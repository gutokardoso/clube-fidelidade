import argparse
import base64
import binascii
import html
import hmac
import io
import json
import os
import re
import smtplib
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from email.message import EmailMessage
from io import BytesIO
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import threading
import time
import secrets

import qrcode

from db import DEFAULT_DB, init_db, ensure_configured_staff, connect, create_session, get_session, audit, insert_id, begin_write, integrity_errors, fetchone_for_update
from security import verify_password, hash_password, random_token, now_ts
from antifraud import validate_stamp, FraudError
from wallet import wallet_status, apple_pass_link, google_wallet_link, build_apple_pkpass, google_save_url, google_update_object, apple_auth_token, apple_push_update
from platform_features import has_permission, session_permissions, active_multiplier, add_point_lot, consume_point_lots, expire_points_once, record_purchase, RATE_LIMITER
from integrations import platform_order

BASE = Path(__file__).resolve().parent
STATIC = BASE / 'static'
DB_PATH = os.environ.get('DATABASE_URL') or os.environ.get('CLUBE_DB_PATH', DEFAULT_DB)
SESSION_COOKIE = 'clube_session'
VERSION='v91'


def jdump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def rowdict(row):
    return dict(row) if row else None

def now_iso():
    return datetime.now(ZoneInfo('America/Sao_Paulo')).isoformat(timespec='seconds')


def current_branch_id(conn, user_id, campaign_id=None):
    if not user_id:
        return None
    if campaign_id:
        row=conn.execute('SELECT branch_id FROM users WHERE id=? AND campaign_id=?',(user_id,campaign_id)).fetchone()
    else:
        row=conn.execute('SELECT branch_id FROM users WHERE id=?',(user_id,)).fetchone()
    return row['branch_id'] if row and row['branch_id'] else None


ECOMMERCE_PLATFORMS={'none','woocommerce','nuvemshop','shopify','tray','vtex','loja_integrada','custom'}

def normalize_ecommerce_platform(value):
    value=str(value or 'none').strip().lower()
    return value if value in ECOMMERCE_PLATFORMS else 'none'

def ecommerce_extract(payload, platform):
    data=payload if isinstance(payload,dict) else {}
    order_id=data.get('order_id') or data.get('id') or data.get('number') or data.get('order_number')
    status=str(data.get('payment_status') or data.get('financial_status') or data.get('status') or '').strip().lower()
    total=data.get('total_cents')
    if total is None:
        total=data.get('total_price', data.get('total', data.get('amount',0)))
        try: total=int(round(float(str(total).replace(',','.'))*100))
        except: total=0
    else:
        try: total=int(total)
        except: total=0
    customer=data.get('customer') if isinstance(data.get('customer'),dict) else {}
    billing=data.get('billing') if isinstance(data.get('billing'),dict) else {}
    billing_address=data.get('billing_address') if isinstance(data.get('billing_address'),dict) else {}
    email=data.get('email') or customer.get('email') or billing.get('email')
    phone=data.get('phone') or customer.get('phone') or billing.get('phone') or billing_address.get('phone')
    cpf=data.get('cpf') or data.get('document') or customer.get('cpf') or customer.get('document')
    if not cpf and isinstance(data.get('meta_data'),list):
        for item in data['meta_data']:
            if isinstance(item,dict) and str(item.get('key','')).lower() in ('cpf','billing_cpf','_billing_cpf'):
                cpf=item.get('value'); break
    return {'order_id':str(order_id or '').strip()[:120],'status':status[:40],'total_cents':max(0,total),
            'email':normalize_email(email),'phone':normalize_phone(phone),'cpf':normalize_cpf(cpf)}

def ecommerce_find_membership(conn,campaign_id,info):
    cpf=info.get('cpf'); email=info.get('email'); phone=info.get('phone')
    if cpf:
        row=conn.execute('SELECT m.*,cu.name customer_name FROM memberships m JOIN customers cu ON cu.id=m.customer_id WHERE m.campaign_id=? AND cu.cpf=? LIMIT 1',(campaign_id,cpf)).fetchone()
        if row:return row
    if email:
        row=conn.execute('SELECT m.*,cu.name customer_name FROM memberships m JOIN customers cu ON cu.id=m.customer_id WHERE m.campaign_id=? AND lower(cu.email)=lower(?) LIMIT 1',(campaign_id,email)).fetchone()
        if row:return row
    if phone:
        row=conn.execute('SELECT m.*,cu.name customer_name FROM memberships m JOIN customers cu ON cu.id=m.customer_id WHERE m.campaign_id=? AND cu.phone=? LIMIT 1',(campaign_id,phone)).fetchone()
        if row:return row
    return None

EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')


def normalize_email(value):
    value = str(value or '').strip().lower()
    return value if len(value) <= 160 and EMAIL_RE.fullmatch(value) else None


def normalize_phone(value):
    digits = re.sub(r'\D', '', str(value or ''))
    if digits.startswith('55') and len(digits) == 13:
        local = digits[2:]
    elif len(digits) == 11:
        local = digits
    else:
        return None
    if len(local) != 11 or local[0] == '0' or local[2] != '9':
        return None
    return '55' + local


def normalize_cpf(value):
    digits = re.sub(r'\D', '', str(value or ''))
    if len(digits) != 11 or digits == digits[0] * 11:
        return None
    nums = [int(x) for x in digits]
    d1 = (sum(nums[i] * (10 - i) for i in range(9)) * 10) % 11
    d1 = 0 if d1 == 10 else d1
    d2 = (sum(nums[i] * (11 - i) for i in range(10)) * 10) % 11
    d2 = 0 if d2 == 10 else d2
    return digits if nums[9] == d1 and nums[10] == d2 else None


def normalize_birth_date(value):
    value = str(value or '').strip()
    try:
        born = date.fromisoformat(value)
    except ValueError:
        return None
    today = datetime.now(ZoneInfo('America/Sao_Paulo')).date()
    if born > today or born.year < 1900:
        return None
    return born.isoformat()





def _secret_box():
    master=os.environ.get('CLUBE_ENCRYPTION_KEY','').strip()
    if not master:
        return None
    key=base64.urlsafe_b64encode(hashlib.sha256(master.encode('utf-8')).digest())
    return Fernet(key)

def encrypt_secret(value):
    value=str(value or '')
    if not value: return None
    box=_secret_box()
    if not box: raise RuntimeError('encryption_key_not_configured')
    return box.encrypt(value.encode('utf-8')).decode('ascii')

def decrypt_secret(value):
    if not value: return ''
    box=_secret_box()
    if not box: return ''
    try: return box.decrypt(str(value).encode('ascii')).decode('utf-8')
    except (InvalidToken,ValueError): return ''

def client_integrations(conn, campaign_id):
    row=conn.execute("""SELECT id,smtp_host,smtp_port,smtp_user,smtp_password_enc,smtp_from,smtp_from_name,smtp_security,email_provider,brevo_api_key_enc,brevo_sender_email,brevo_sender_name,brevo_reply_to,
        whatsapp_phone_number_id,whatsapp_waba_id,whatsapp_access_token_enc,whatsapp_api_version
        FROM campaigns WHERE id=?""",(campaign_id,)).fetchone()
    if not row: return None
    x=rowdict(row)
    x['smtp_password']=decrypt_secret(x.pop('smtp_password_enc',None))
    x['brevo_api_key']=decrypt_secret(x.pop('brevo_api_key_enc',None))
    x['whatsapp_access_token']=decrypt_secret(x.pop('whatsapp_access_token_enc',None))
    return x

def global_smtp_config():
    return {
        'host':os.environ.get('CLUBE_SMTP_HOST','').strip(),
        'port':os.environ.get('CLUBE_SMTP_PORT','587').strip(),
        'user':os.environ.get('CLUBE_SMTP_USER','').strip(),
        'password':os.environ.get('CLUBE_SMTP_PASSWORD',''),
        'from_addr':os.environ.get('CLUBE_SMTP_FROM','').strip(),
        'from_name':os.environ.get('CLUBE_SMTP_FROM_NAME','Clube Fidelidade').strip(),
        'security':os.environ.get('CLUBE_SMTP_SECURITY','starttls').strip().lower(),
        'source':'global'
    }

def smtp_config_for_client(conn=None,campaign_id=None):
    if conn is not None and campaign_id:
        x=client_integrations(conn,campaign_id)
        if x and x.get('smtp_host') and x.get('smtp_from'):
            return {'host':x['smtp_host'],'port':str(x.get('smtp_port') or 587),'user':x.get('smtp_user') or '',
                    'password':x.get('smtp_password') or '','from_addr':x['smtp_from'],'from_name':x.get('smtp_from_name') or '',
                    'security':x.get('smtp_security') or 'starttls','source':'client'}
    return global_smtp_config()

def email_config_for_client(conn=None,campaign_id=None):
    # Integração promocional sempre isolada por cliente, sem fallback global da Taboo.
    if conn is not None and campaign_id:
        x=client_integrations(conn,campaign_id)
        if x:
            provider=(x.get('email_provider') or 'smtp').strip().lower()
            if provider=='brevo':
                return {'provider':'brevo','api_key':x.get('brevo_api_key') or '',
                        'sender_email':x.get('brevo_sender_email') or '',
                        'sender_name':x.get('brevo_sender_name') or '',
                        'reply_to':x.get('brevo_reply_to') or '','source':'client'}
            return {'provider':'smtp','host':x.get('smtp_host') or '',
                    'port':str(x.get('smtp_port') or 587),'user':x.get('smtp_user') or '',
                    'password':x.get('smtp_password') or '','from_addr':x.get('smtp_from') or '',
                    'from_name':x.get('smtp_from_name') or '',
                    'security':x.get('smtp_security') or 'starttls','source':'client'}
    return {'provider':'smtp','host':'','port':'587','user':'','password':'','from_addr':'','from_name':'','security':'starttls','source':'client'}

def smtp_configured(config=None):
    c=config or global_smtp_config()
    return bool(c.get('host') and c.get('from_addr'))


def brevo_api_config():
    return {
        'api_key':os.environ.get('BREVO_API_KEY','').strip(),
        'sender_email':os.environ.get('BREVO_SENDER_EMAIL','').strip(),
        'sender_name':os.environ.get('BREVO_SENDER_NAME','Clube Fidelidade').strip(),
        'reply_to':os.environ.get('BREVO_REPLY_TO','').strip(),
    }

def brevo_api_configured():
    c=brevo_api_config()
    return bool(c.get('api_key') and c.get('sender_email'))

def global_email_config():
    # Conta da Taboo usada apenas para mensagens administrativas da plataforma.
    if brevo_api_configured():
        c=brevo_api_config(); c.update({'provider':'brevo','source':'global'}); return c
    c=global_smtp_config(); c.update({'provider':'smtp','source':'global'}); return c

def email_configured(config=None):
    c=config or {}
    if c.get('provider')=='brevo': return bool(c.get('api_key') and c.get('sender_email'))
    if c.get('provider')=='smtp': return smtp_configured(c)
    return brevo_api_configured() or smtp_configured(c or None)

def _brevo_payload_from_message(msg, cfg=None):
    cfg=cfg or brevo_api_config()
    to=[]
    for addr in msg.get_all('To',[]):
        for item in str(addr).split(','):
            email=item.strip()
            if email: to.append({'email':email})
    if not to:
        raise ValueError('email_recipient_missing')
    text=''; html_content=''; attachments=[]
    if msg.is_multipart():
        for part in msg.walk():
            ctype=part.get_content_type(); disp=part.get_content_disposition()
            if disp=='attachment':
                raw=part.get_payload(decode=True) or b''
                attachments.append({'name':part.get_filename() or 'anexo','content':base64.b64encode(raw).decode('ascii')})
            elif ctype=='text/plain' and not text:
                try: text=part.get_content()
                except Exception: pass
            elif ctype=='text/html' and not html_content:
                try: html_content=part.get_content()
                except Exception: pass
    else:
        ctype=msg.get_content_type()
        try: content=msg.get_content()
        except Exception: content=str(msg.get_payload() or '')
        if ctype=='text/html': html_content=content
        else: text=content
    payload={
        'sender':{'name':cfg.get('sender_name') or 'Clube Fidelidade','email':cfg['sender_email']},
        'to':to,
        'subject':str(msg.get('Subject') or 'Clube Fidelidade'),
    }
    if html_content: payload['htmlContent']=html_content
    else: payload['textContent']=text or 'Clube Fidelidade'
    if attachments: payload['attachment']=attachments
    # Respeita o Reply-To específico da mensagem (ex.: formulário comercial).
    # Só usa o Reply-To global como fallback.
    reply_to=str(msg.get('Reply-To') or cfg.get('reply_to') or '').strip()
    if reply_to: payload['replyTo']={'email':reply_to}
    return payload

def send_email_brevo_api(msg, cfg=None):
    cfg=cfg or brevo_api_config()
    if not (cfg.get('api_key') and cfg.get('sender_email')):
        return {'sent':False,'reason':'brevo_api_not_configured'}
    try:
        payload=_brevo_payload_from_message(msg,cfg)
        req=urllib.request.Request('https://api.brevo.com/v3/smtp/email',data=json.dumps(payload,ensure_ascii=False).encode('utf-8'),method='POST',headers={
            'api-key':cfg['api_key'],'Content-Type':'application/json','Accept':'application/json'
        })
        with urllib.request.urlopen(req,timeout=20) as resp:
            data=json.loads(resp.read().decode('utf-8') or '{}')
        return {'sent':True,'source':'brevo_api','message_id':data.get('messageId')}
    except urllib.error.HTTPError as exc:
        raw=exc.read().decode('utf-8',errors='replace')
        print(f'[EMAIL] BREVO_HTTP_ERROR status={exc.code} body={raw[:500]}')
        reason='brevo_auth_failed' if exc.code in (401,403) else ('brevo_sender_invalid' if exc.code==400 else 'brevo_api_failed')
        return {'sent':False,'reason':reason,'status':exc.code,'source':'brevo_api'}
    except (TimeoutError, socket.timeout):
        print('[EMAIL] BREVO_TIMEOUT')
        return {'sent':False,'reason':'brevo_api_timeout','source':'brevo_api'}
    except urllib.error.URLError as exc:
        print(f'[EMAIL] BREVO_CONNECTION_FAILED error={type(exc.reason).__name__ if getattr(exc,"reason",None) else type(exc).__name__}')
        return {'sent':False,'reason':'brevo_api_connection_failed','source':'brevo_api'}
    except Exception as exc:
        print(f'[EMAIL] BREVO_SEND_FAILED error={type(exc).__name__}')
        return {'sent':False,'reason':'brevo_api_failed','source':'brevo_api'}

def send_email_message(msg, config=None):
    c=config or {}
    if c.get('provider')=='brevo': return send_email_brevo_api(msg,c)
    if c.get('provider')=='smtp': pass
    elif brevo_api_configured(): return send_email_brevo_api(msg)
    c=c or global_smtp_config()
    host=c.get('host','').strip(); from_addr=c.get('from_addr','').strip()
    if not host or not from_addr: return {'sent':False,'reason':'smtp_not_configured'}
    try: port=int(c.get('port') or 587)
    except (ValueError,TypeError): port=587
    user=c.get('user','').strip(); smtp_password=c.get('password','')
    security=(c.get('security') or 'starttls').strip().lower()
    from_name=(c.get('from_name') or '').strip()
    msg['From']=f'{from_name} <{from_addr}>' if from_name else from_addr
    context=ssl.create_default_context()
    try:
        if security=='ssl':
            with smtplib.SMTP_SSL(host,port,timeout=15,context=context) as smtp:
                if user: smtp.login(user,smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host,port,timeout=15) as smtp:
                smtp.ehlo()
                if security!='none':
                    smtp.starttls(context=context); smtp.ehlo()
                if user: smtp.login(user,smtp_password)
                smtp.send_message(msg)
        return {'sent':True,'source':c.get('source','global')}
    except smtplib.SMTPAuthenticationError as exc:
        print(f'[EMAIL] AUTH_FAILED to={msg.get("To","")} code={getattr(exc,"smtp_code","")}')
        return {'sent':False,'reason':'smtp_auth_failed','source':c.get('source','global')}
    except smtplib.SMTPSenderRefused as exc:
        print(f'[EMAIL] SENDER_REFUSED to={msg.get("To","")} code={getattr(exc,"smtp_code","")}')
        return {'sent':False,'reason':'smtp_sender_refused','source':c.get('source','global')}
    except smtplib.SMTPRecipientsRefused as exc:
        print(f'[EMAIL] RECIPIENT_REFUSED to={msg.get("To","")}')
        return {'sent':False,'reason':'smtp_recipient_refused','source':c.get('source','global')}
    except (TimeoutError, socket.timeout) as exc:
        print(f'[EMAIL] TIMEOUT to={msg.get("To","")}')
        return {'sent':False,'reason':'smtp_timeout','source':c.get('source','global')}
    except (ConnectionError, OSError, smtplib.SMTPConnectError) as exc:
        print(f'[EMAIL] CONNECTION_FAILED to={msg.get("To","")} error={type(exc).__name__}')
        return {'sent':False,'reason':'smtp_connection_failed','source':c.get('source','global')}
    except Exception as exc:
        print(f'[EMAIL] SEND_FAILED to={msg.get("To","")} error={type(exc).__name__}')
        return {'sent':False,'reason':'smtp_send_failed','source':c.get('source','global')}

def validate_logo_data(value):
    """Valida e normaliza a logo enviada pelo Painel Taboo.

    Mantém o data URL original para persistência, mas valida MIME, base64,
    tamanho máximo de 500 KB e a assinatura real do arquivo.
    """
    if not value:
        return None
    text=str(value).strip()
    match=re.fullmatch(r'data:(image/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=\s]+)',text)
    if not match:
        raise ValueError('invalid_logo_format')
    try:
        raw=base64.b64decode(re.sub(r'\s+','',match.group(2)),validate=True)
    except (binascii.Error,ValueError):
        raise ValueError('invalid_logo_format')
    if not raw:
        raise ValueError('invalid_logo_format')
    if len(raw)>500_000:
        raise ValueError('logo_too_large')
    mime=match.group(1)
    valid=(
        (mime=='image/png' and raw.startswith(b'\x89PNG\r\n\x1a\n')) or
        (mime=='image/jpeg' and raw.startswith(b'\xff\xd8\xff')) or
        (mime=='image/webp' and len(raw)>=12 and raw[:4]==b'RIFF' and raw[8:12]==b'WEBP')
    )
    if not valid:
        raise ValueError('invalid_logo_format')
    return f'data:{mime};base64,'+base64.b64encode(raw).decode('ascii')


def decode_image_data(value, max_bytes=700_000):
    if not value:
        return None
    text=str(value)
    match=re.fullmatch(r'data:(image/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=\s]+)',text)
    if not match:
        raise ValueError('invalid_image_format')
    try:
        raw=base64.b64decode(match.group(2),validate=True)
    except (binascii.Error,ValueError):
        raise ValueError('invalid_image_format')
    if not raw or len(raw)>max_bytes:
        raise ValueError('image_too_large')
    subtype={'image/png':'png','image/jpeg':'jpeg','image/webp':'webp'}[match.group(1)]
    return raw, subtype


def send_campaign_email(to_email, to_name, message, image_data=None, subject='Mensagem do Clube Fidelidade', smtp_config=None):
    if not email_configured(smtp_config):
        return {'sent':False,'reason':'smtp_not_configured'}
    msg=EmailMessage()
    msg['Subject']=subject
    msg['To']=to_email
    text=(str(message or '').strip() or 'Você recebeu uma nova mensagem do seu Clube Fidelidade.')
    msg.set_content(text)
    if image_data:
        raw,subtype=decode_image_data(image_data)
        msg.add_attachment(raw,maintype='image',subtype=subtype,filename='clube-fidelidade.'+('jpg' if subtype=='jpeg' else subtype))
    return send_email_message(msg, smtp_config)


def send_password_recovery_email(email, reset_token, smtp_config=None):
    if not email_configured(smtp_config):
        return {'sent':False,'reason':'smtp_not_configured'}
    base=(os.environ.get('PUBLIC_BASE_URL') or 'https://clube-fidelidade-production.up.railway.app').rstrip('/')
    reset_url=base+'/reset-password?token='+urllib.parse.quote(reset_token)
    msg=EmailMessage(); msg['Subject']='Redefinição de senha • Fidelizaê!'; msg['To']=email
    msg.set_content('Recebemos uma solicitação para redefinir sua senha no Fidelizaê!.\n\nAbra o link abaixo (válido por 30 minutos):\n'+reset_url+'\n\nSe você não solicitou a alteração, ignore esta mensagem.')
    return send_email_message(msg, smtp_config)


CARD_THEMES={
    'green':('#174f3f','#082b25'),
    'orange':('#d18a1f','#8a4907'),
    'blue':('#183f6d','#091f3b'),
    'red':('#7c2028','#3b0b11'),
    'black':('#292929','#070707'),
}

def card_theme_colors(theme):
    return CARD_THEMES.get(str(theme or 'green').strip().lower(), CARD_THEMES['green'])


def send_customer_welcome_email(name, email, client_name, public_id, campaign, email_config=None):
    """Envia o cartão recém-criado usando exclusivamente a integração do cliente."""
    if not email_configured(email_config):
        return {'sent':False,'reason':'email_provider_not_configured','skipped':True}
    base_url=(os.environ.get('CLUBE_PUBLIC_URL') or 'https://clube-fidelidade-production.up.railway.app').strip().rstrip('/')
    card_url=f'{base_url}/card?id={urllib.parse.quote(public_id)}'
    card_code=f'CLUBE:{public_id}'
    qr_url=f'{base_url}/api/qr?data={urllib.parse.quote(card_code, safe="")}'
    client=html.escape(str(client_name or ''))
    customer=html.escape(str(name or ''))
    safe_card_url=html.escape(card_url, quote=True)
    safe_code=html.escape(card_code)
    goal=int(campaign.get('goal') or 5) if hasattr(campaign,'get') else int(campaign['goal'] or 5)
    icon=(campaign.get('icon') if hasattr(campaign,'get') else campaign['icon']) or '●'
    stamp='●' if icon=='__LOGO__' else html.escape(str(icon))
    cols=3 if goal==3 else (4 if goal==8 else 5)
    theme=(campaign.get('card_theme') if hasattr(campaign,'get') else campaign['card_theme']) or 'green'
    theme_start,theme_end=card_theme_colors(theme)
    cells=[f'<td style="padding:5px"><div style="width:42px;height:42px;border:2px solid #d7c6bb;border-radius:50%;display:flex;align-items:center;justify-content:center;filter:grayscale(1);opacity:.5;font-size:20px">{stamp}</div></td>' for _ in range(goal)]
    rows=['<tr>'+''.join(cells[i:i+cols])+'</tr>' for i in range(0,len(cells),cols)]
    wallet_buttons=[]
    apple=apple_pass_link(public_id)
    google=google_wallet_link(public_id)
    if apple: wallet_buttons.append(f'<a href="{html.escape(base_url+apple,quote=True)}" style="display:inline-block;padding:11px 16px;margin:4px;background:#231a16;color:#fff;text-decoration:none;border-radius:10px;font-weight:700">Apple Wallet</a>')
    if google: wallet_buttons.append(f'<a href="{html.escape(base_url+google,quote=True)}" style="display:inline-block;padding:11px 16px;margin:4px;background:#231a16;color:#fff;text-decoration:none;border-radius:10px;font-weight:700">Google Wallet</a>')
    if not wallet_buttons:
        wallet_buttons.append(f'<a href="{safe_card_url}" style="display:inline-block;padding:11px 16px;margin:4px;background:#231a16;color:#fff;text-decoration:none;border-radius:10px;font-weight:700">Abrir cartão / Wallet</a>')
    text=(f'Agora você faz parte do Clube de Fidelidade {client_name}.\n'
          'Para ter acesso às nossas vantagens, apresente o seu cartão com o QR code aos nossos atendentes toda vez que vier efetuar uma compra.\n\n'
          f'Link de acesso: {card_url}\nCódigo do cartão: {card_code}\n')
    html_body=(
        '<!doctype html><html><body style="margin:0;background:#f7f3ef;font-family:Arial,sans-serif;color:#231a16">'
        '<div style="max-width:620px;margin:0 auto;padding:28px 18px">'
        f'<h2 style="margin:0 0 12px">Agora você faz parte do Clube de Fidelidade {client}.</h2>'
        '<p style="line-height:1.55;margin:0 0 24px">Para ter acesso às nossas vantagens, apresente o seu cartão com o QR code aos nossos atendentes toda vez que vier efetuar uma compra.</p>'
        f'<div style="background:linear-gradient(145deg,{theme_start},{theme_end});color:#fff;border-radius:26px;padding:26px;text-align:center">'
        '<div style="font-weight:900;letter-spacing:.08em;font-size:14px">CLUBE DE FIDELIDADE</div>'
        f'<h2 style="margin:18px 0 6px">{client}</h2><p style="margin:0 0 12px">{customer}</p>'
        f'<table role="presentation" align="center" cellspacing="0" cellpadding="0" style="margin:10px auto 16px">{"".join(rows)}</table>'
        f'<div style="margin:16px auto;padding:10px 12px;border:1px solid rgba(255,255,255,.25);border-radius:12px"><div style="font-size:11px;opacity:.75;text-transform:uppercase">Código do cartão</div><strong>{safe_code}</strong></div>'
        f'<img src="{html.escape(qr_url,quote=True)}" alt="QR code do cartão" width="170" height="170" style="display:block;background:#fff;border-radius:14px;padding:10px;margin:16px auto"></div>'
        f'<div style="text-align:center;margin:18px 0">{"".join(wallet_buttons)}</div>'
        f'<p style="line-height:1.55"><strong>Link de acesso:</strong><br><a href="{safe_card_url}">{html.escape(card_url)}</a></p>'
        f'<p style="line-height:1.55"><strong>Código do cartão:</strong><br>{safe_code}</p></div></body></html>'
    )
    msg=EmailMessage()
    msg['Subject']=f'Bem-vindo ao Clube de Fidelidade {client_name}'
    msg['To']=email
    msg.set_content(text)
    msg.add_alternative(html_body, subtype='html')
    result=send_email_message(msg,email_config)
    if not result.get('sent'):
        print(f'[EMAIL] CUSTOMER_WELCOME_FAILED email={email} campaign={client_name!r} reason={result.get("reason")}')
    return result


def send_attendant_welcome_email(name, email, password, client_name, smtp_config=None):
    if not email_configured(smtp_config):
        return {'sent':False,'reason':'smtp_not_configured'}
    login_url=os.environ.get('CLUBE_LOGIN_URL','https://clube-fidelidade-production.up.railway.app/login').strip()
    msg=EmailMessage()
    msg['Subject']='Acesso ao Clube Fidelidade'
    msg['To']=email
    msg.set_content(
        'Cadastro realizado com sucesso! Agora é só acessar o link abaixo, inserir seu e-mail e senha para ter acesso ao painel do seu Clube Fidelidade.\n\n'
        f'{login_url}\n\n'
        f'E-mail: {email}\n'
        f'Senha: {password}\n'
        f'Cliente: {client_name}\n'
    )
    result=send_email_message(msg, smtp_config)
    if not result.get('sent'):
        print(f'[EMAIL] ATTENDANT_WELCOME_FAILED email={email} reason={result.get("reason")}')
    return result


def whatsapp_link(phone, message):
    return 'https://wa.me/' + str(phone) + '?text=' + urllib.parse.quote(str(message), safe='')


def whatsapp_config_for_client(conn=None,campaign_id=None):
    # WhatsApp sempre isolado por cliente. Vazio = integração não configurada.
    if conn is not None and campaign_id:
        x=client_integrations(conn,campaign_id)
        if x:
            return {'phone_number_id':x.get('whatsapp_phone_number_id') or '',
                    'waba_id':x.get('whatsapp_waba_id') or '',
                    'token':x.get('whatsapp_access_token') or '',
                    'version':x.get('whatsapp_api_version') or 'v24.0','source':'client'}
    return {'phone_number_id':'','waba_id':'','token':'','version':'v24.0','source':'client'}

def whatsapp_cloud_configured(config=None):
    c=config or whatsapp_config_for_client()
    return all(c.get(k,'') for k in ('token','phone_number_id','version'))

def send_whatsapp_cloud(phone, message, config=None):
    c=config or whatsapp_config_for_client()
    version=c.get('version',''); phone_number_id=c.get('phone_number_id',''); token=c.get('token','')
    if not (version and phone_number_id and token): raise RuntimeError('whatsapp_not_configured')
    url=f'https://graph.facebook.com/{urllib.parse.quote(version)}/{urllib.parse.quote(phone_number_id)}/messages'
    body=json.dumps({'messaging_product':'whatsapp','recipient_type':'individual','to':str(phone),'type':'text',
        'text':{'preview_url':False,'body':str(message)}}).encode('utf-8')
    req=urllib.request.Request(url,data=body,method='POST',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=15) as resp: return json.loads(resp.read().decode('utf-8') or '{}')
    except urllib.error.HTTPError as exc:
        raw=exc.read().decode('utf-8',errors='replace')
        try: detail=json.loads(raw)
        except Exception: detail={'error':raw[:500]}
        raise RuntimeError(json.dumps(detail,ensure_ascii=False)) from exc

def meta_public_base_url():
    base=(os.environ.get('PUBLIC_BASE_URL') or '').strip().rstrip('/')
    if not base:
        domain=(os.environ.get('RAILWAY_PUBLIC_DOMAIN') or '').strip().strip('/')
        if domain:
            base='https://'+domain
    return base

def meta_callback_url():
    base=meta_public_base_url()
    return (base+'/auth/meta/callback') if base else ''

def meta_embedded_signup_configured():
    return bool(os.environ.get('META_APP_ID','').strip() and os.environ.get('META_APP_SECRET','').strip() and os.environ.get('META_CONFIG_ID','').strip())

def meta_exchange_code(code):
    app_id=os.environ.get('META_APP_ID','').strip(); secret=os.environ.get('META_APP_SECRET','').strip()
    if not (app_id and secret and code): raise RuntimeError('meta_embedded_signup_not_configured')
    qs=urllib.parse.urlencode({'client_id':app_id,'client_secret':secret,'code':code})
    req=urllib.request.Request('https://graph.facebook.com/v24.0/oauth/access_token?'+qs,method='GET')
    with urllib.request.urlopen(req,timeout=20) as resp: return json.loads(resp.read().decode('utf-8') or '{}')

def meta_phone_details(phone_id,token):
    req=urllib.request.Request(f'https://graph.facebook.com/v24.0/{urllib.parse.quote(str(phone_id))}?fields=id,display_phone_number,verified_name',headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(req,timeout=20) as resp: return json.loads(resp.read().decode('utf-8') or '{}')



def _qr_secret():
    return (os.environ.get('CLUBE_QR_SECRET') or os.environ.get('CLUBE_ENCRYPTION_KEY') or 'development-only-change-me').encode('utf-8')

def make_dynamic_qr(public_id, ttl=60):
    exp=now_ts()+max(30,min(int(ttl),120)); nonce=secrets.token_urlsafe(6)
    body=f'{public_id}.{exp}.{nonce}'
    sig=hmac.new(_qr_secret(),body.encode(),hashlib.sha256).hexdigest()[:32]
    return f'DYN.{body}.{sig}',exp

def resolve_member_token(raw):
    token=str(raw or '').strip()
    if token.startswith('CLUBE:'): token=token[6:]
    if token.startswith('DYN.'):
        parts=token.split('.')
        if len(parts)!=5:return None,'invalid_dynamic_qr'
        _,public_id,exp,nonce,sig=parts
        try:exp=int(exp)
        except ValueError:return None,'invalid_dynamic_qr'
        if exp<now_ts():return None,'qr_expired'
        body=f'{public_id}.{exp}.{nonce}'
        expected=hmac.new(_qr_secret(),body.encode(),hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig,expected):return None,'invalid_dynamic_qr'
        return public_id,None
    return token,None

def enqueue_message(conn, campaign_id, kind, recipient, payload, delay=0):
    return insert_id(conn,"INSERT INTO message_queue(campaign_id,kind,recipient,payload_json,status,attempts,available_at,created_at) VALUES(?,?,?,?,?,?,?,?)",(campaign_id,kind,recipient,json.dumps(payload,ensure_ascii=False),'pending',0,now_ts()+delay,now_ts()))

def _queue_send(item, conn):
    payload=json.loads(item['payload_json'] or '{}'); kind=item['kind']; campaign_id=item['campaign_id']
    if kind=='customer_welcome':
        c=conn.execute('SELECT * FROM campaigns WHERE id=?',(campaign_id,)).fetchone();
        return send_customer_welcome_email(payload['name'],payload['email'],c['name'],payload['public_id'],rowdict(c),email_config_for_client(conn,campaign_id))
    if kind=='campaign_email':
        return send_campaign_email(item['recipient'],payload.get('name',''),payload.get('message',''),payload.get('image_data'),payload.get('subject','Mensagem do Clube Fidelidade'),email_config_for_client(conn,campaign_id))
    if kind=='whatsapp':
        try:
            response=send_whatsapp_cloud(item['recipient'],payload.get('message',''),whatsapp_config_for_client(conn,campaign_id))
            return {'sent':True,'message_id':((response.get('messages') or [{}])[0]).get('id')}
        except Exception as exc:return {'sent':False,'reason':str(exc)[:500]}
    if kind=='attendant_welcome':
        return send_attendant_welcome_email(payload['name'],item['recipient'],payload['password'],payload['client_name'],global_email_config())
    if kind=='password_recovery':
        return send_password_recovery_email(item['recipient'],payload['token'],global_email_config())
    return {'sent':False,'reason':'unknown_queue_kind'}

def process_message_queue_once(limit=15):
    with connect(DB_PATH) as conn:
        # Se o processo caiu enquanto um item estava em 'processing', devolve-o à fila.
        conn.execute("UPDATE message_queue SET status='retry',available_at=? WHERE status='processing' AND available_at<?",(now_ts(),now_ts()-120))
        rows=conn.execute("SELECT * FROM message_queue WHERE status IN ('pending','retry') AND available_at<=? ORDER BY id LIMIT ?",(now_ts(),limit)).fetchall()
        for row in rows:
            item=rowdict(row); conn.execute("UPDATE message_queue SET status='processing',attempts=attempts+1 WHERE id=?",(item['id'],)); conn.commit()
            try: result=_queue_send(item,conn)
            except Exception as exc: result={'sent':False,'reason':type(exc).__name__+':'+str(exc)[:300]}
            if result.get('sent'):
                conn.execute("UPDATE message_queue SET status='sent',sent_at=?,last_error=NULL WHERE id=?",(now_ts(),item['id']))
            else:
                attempts=int(item.get('attempts') or 0)+1; status='failed' if attempts>=4 else 'retry'; delay=min(900,30*(2**max(0,attempts-1)))
                conn.execute("UPDATE message_queue SET status=?,last_error=?,available_at=? WHERE id=?",(status,result.get('reason','failed'),now_ts()+delay,item['id']))
            conn.commit()

def customer_segment(last_activity,created_at,visits,reward_ready,almost_reward,now=None):
    now=now or now_ts(); age=max(0,now-int(last_activity or created_at or now))
    if reward_ready: return 'reward_ready'
    if almost_reward: return 'almost_reward'
    if age>=90*86400: return 'inactive90'
    if age>=60*86400: return 'inactive60'
    if age>=30*86400: return 'at_risk'
    if int(visits or 0)>=12: return 'vip'
    if int(visits or 0)<=1 and now-int(created_at or now)<=30*86400: return 'new'
    return 'active'

def segment_sql(segment,cid,loyalty_type='stamps'):
    now=now_ts(); extra=''; params=[]
    last="COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)"
    visits="(SELECT COUNT(*) FROM transactions t WHERE t.membership_id=m.id AND ((c.loyalty_type='points' AND t.type='adjustment' AND t.value>0) OR (c.loyalty_type='stamps' AND t.type='stamp' AND t.value>0)))"
    if segment=='birthdays': extra=" AND substr(cu.birth_date,6,2)=?"; params=[datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%m')]
    elif segment=='at_risk': extra=f" AND {last}<? AND {last}>=?"; params=[now-30*86400,now-60*86400]
    elif segment=='inactive60': extra=f" AND {last}<? AND {last}>=?"; params=[now-60*86400,now-90*86400]
    elif segment=='inactive90': extra=f" AND {last}<?"; params=[now-90*86400]
    elif segment=='vip': extra=f" AND {visits}>=12"
    elif segment=='new': extra=" AND m.created_at>=?"; params=[now-30*86400]
    elif segment=='reward_ready': extra=" AND (m.rewards_available>0 OR (c.loyalty_type='points' AND m.points_balance>=(SELECT COALESCE(MIN(points_cost),999999999) FROM reward_catalog WHERE campaign_id=m.campaign_id AND active=1)))"
    elif segment=='almost_reward': extra=" AND ((c.loyalty_type='stamps' AND m.progress=c.goal-1) OR (c.loyalty_type='points' AND EXISTS(SELECT 1 FROM reward_catalog r WHERE r.campaign_id=m.campaign_id AND r.active=1 AND r.points_cost>m.points_balance AND r.points_cost-m.points_balance<=GREATEST(1,CAST(r.points_cost*0.15 AS INTEGER)))))" if str(DB_PATH).startswith(('postgres://','postgresql://')) else " AND ((c.loyalty_type='stamps' AND m.progress=c.goal-1) OR (c.loyalty_type='points' AND EXISTS(SELECT 1 FROM reward_catalog r WHERE r.campaign_id=m.campaign_id AND r.active=1 AND r.points_cost>m.points_balance AND r.points_cost-m.points_balance<=MAX(1,CAST(r.points_cost*0.15 AS INTEGER)))))"
    return extra,params

def campaign_recipient_rows(conn,cid,segment):
    extra,params=segment_sql(segment,cid)
    return conn.execute("""SELECT m.id membership_id,m.public_id,cu.id customer_id,cu.name,cu.email,cu.phone,cu.marketing_email,cu.marketing_whatsapp
      FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id
      WHERE m.campaign_id=? AND m.status='active' """+extra+' ORDER BY cu.name',(cid,*params)).fetchall()

def ensure_automation_defaults(conn,campaign_id):
    defaults={
      'birthday':('both','Feliz aniversário, {nome}! O {cliente} deseja um dia especial para você.'),
      'inactive30':('both','Sentimos sua falta, {nome}! Volte ao {cliente} e continue acumulando no seu programa.'),
      'inactive60':('both','Já faz um tempo, {nome}. Temos saudades de você no {cliente}. Volte e continue aproveitando seus benefícios.'),
      'one_to_reward':('both','Falta só 1 selo, {nome}! Sua recompensa no {cliente} está quase lá.'),
      'reward_available':('both','Parabéns, {nome}! Você já tem uma recompensa disponível no {cliente}.')}
    for rule,(channel,msg) in defaults.items():
        # Evita violação UNIQUE no PostgreSQL. Capturar IntegrityError sem
        # rollback deixa toda a transação abortada (InFailedSqlTransaction).
        conn.execute('INSERT INTO automation_rules(campaign_id,rule_type,channel,enabled,message,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(campaign_id,rule_type) DO NOTHING',(campaign_id,rule,channel,0,msg,now_ts()))

def run_automations_once():
    today=datetime.now(ZoneInfo('America/Sao_Paulo')).date(); now=now_ts()
    with connect(DB_PATH) as conn:
        campaigns=conn.execute('SELECT id,name FROM campaigns WHERE active=1').fetchall()
        for c in campaigns: ensure_automation_defaults(conn,c['id'])
        rules=conn.execute('SELECT r.*,c.name client_name FROM automation_rules r JOIN campaigns c ON c.id=r.campaign_id WHERE r.enabled=1 AND c.active=1').fetchall()
        for rule in rules:
            rows=conn.execute('''SELECT m.id membership_id,m.progress,m.rewards_available,m.public_id,m.created_at membership_created,c.goal,cu.id customer_id,cu.name,cu.email,cu.phone,cu.birth_date,cu.marketing_email,cu.marketing_whatsapp,
              COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at) last_activity
              FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND m.status='active' ''',(rule['campaign_id'],)).fetchall()
            for x in rows:
                match=False; period=''
                if rule['rule_type']=='birthday' and x['birth_date'] and x['birth_date'][5:10]==today.isoformat()[5:10]: match=True; period=str(today.year)
                elif rule['rule_type']=='inactive30' and x['last_activity']<=now-30*86400 and x['last_activity']>now-60*86400: match=True; period=today.strftime('%Y-%m')
                elif rule['rule_type']=='inactive60' and x['last_activity']<=now-60*86400: match=True; period=today.strftime('%Y-%m')
                elif rule['rule_type']=='one_to_reward' and x['progress']==x['goal']-1: match=True; period=f"p{x['progress']}-{today.strftime('%Y-%m')}"
                elif rule['rule_type']=='reward_available' and x['rewards_available']>0: match=True; period=f"r{x['rewards_available']}-{today.strftime('%Y-%m')}"
                if not match: continue
                exists=conn.execute('SELECT id FROM automation_runs WHERE rule_id=? AND membership_id=? AND period_key=?',(rule['id'],x['membership_id'],period)).fetchone()
                if exists: continue
                msg=rule['message'].format(nome=x['name'],cliente=rule['client_name'])
                queued=False; channel=rule['channel']
                if channel in ('email','both') and x['email'] and x['marketing_email'] and email_configured(email_config_for_client(conn,rule['campaign_id'])):
                    enqueue_message(conn,rule['campaign_id'],'campaign_email',x['email'],{'name':x['name'],'message':msg,'subject':'Fidelizaê! • '+rule['client_name']}); queued=True
                if channel in ('whatsapp','both') and x['phone'] and x['marketing_whatsapp'] and whatsapp_cloud_configured(whatsapp_config_for_client(conn,rule['campaign_id'])):
                    enqueue_message(conn,rule['campaign_id'],'whatsapp',x['phone'],{'message':msg}); queued=True
                if queued:
                    conn.execute('INSERT INTO automation_runs(rule_id,membership_id,period_key,created_at) VALUES(?,?,?,?) ON CONFLICT(rule_id,membership_id,period_key) DO NOTHING',(rule['id'],x['membership_id'],period,now_ts()))

def background_loop():
    tick=0
    while True:
        try: process_message_queue_once()
        except Exception as exc: print('[QUEUE]',type(exc).__name__,str(exc)[:300])
        tick+=1
        if tick%30==0:
            try:
                with connect(DB_PATH) as _c: expire_points_once(_c,now_ts())
            except Exception as exc: print('[POINTS_EXPIRY]',type(exc).__name__,str(exc)[:300])
            try: run_automations_once()
            except Exception as exc: print('[AUTOMATION]',type(exc).__name__,str(exc)[:300])
        time.sleep(2)

def card_record(conn,public_id):
    row=conn.execute('''SELECT m.public_id,m.progress,m.points_balance,m.rewards_available,m.status,m.created_at,cu.name customer_name,c.name campaign_name,c.code campaign_code,c.reward_name,c.goal,c.icon,c.logo_image,c.card_theme,c.loyalty_type,c.points_spend_cents
      FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.public_id=?''',(public_id,)).fetchone()
    return rowdict(row)

def notify_wallet_updates(conn,public_id):
    card=card_record(conn,public_id)
    if not card:return
    try: google_update_object(card)
    except Exception: pass
    regs=conn.execute('''SELECT wr.push_token FROM wallet_registrations wr JOIN memberships m ON m.id=wr.membership_id WHERE m.public_id=?''',(public_id,)).fetchall()
    for r in regs:
        try: apple_push_update(r['push_token'])
        except Exception: pass

class Handler(BaseHTTPRequestHandler):
    def _need_permission(self,sess,key):
        if has_permission(rowdict(sess),key): return True
        self.send_json({'ok':False,'error':'permission_denied','permission':key},403); return False

    def _rate_ok(self,bucket,limit,window):
        key=f'{bucket}:{self._ip()}'
        if RATE_LIMITER.allow(key,limit,window): return True
        self.send_json({'ok':False,'error':'rate_limited'},429); return False

    server_version = 'Fidelizae/19.0'

    def log_message(self, fmt, *args):
        print(f'[{self.log_date_time_string()}] {self.address_string()} - {fmt % args}')

    def _cookies(self):
        c = cookies.SimpleCookie()
        c.load(self.headers.get('Cookie', ''))
        return c

    def _session_token(self):
        c = self._cookies().get(SESSION_COOKIE)
        return c.value if c else None

    def _session(self, conn):
        return get_session(conn, self._session_token())

    def _body_json(self):
        n = int(self.headers.get('Content-Length', '0') or 0)
        if n > 1_500_000:
            raise ValueError('body_too_large')
        raw = self.rfile.read(n) if n else b'{}'
        return json.loads(raw.decode('utf-8') or '{}')

    def _body_payload(self):
        n = int(self.headers.get('Content-Length', '0') or 0)
        if n > 1_500_000:
            raise ValueError('body_too_large')
        raw = self.rfile.read(n) if n else b''
        ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if ctype == 'application/x-www-form-urlencoded':
            parsed = urllib.parse.parse_qs(raw.decode('utf-8'), keep_blank_values=True)
            return {k: (v[-1] if v else '') for k, v in parsed.items()}, 'form'
        if ctype == 'multipart/form-data':
            raise ValueError('multipart_not_supported')
        return json.loads(raw.decode('utf-8') or '{}'), 'json'

    def send_redirect(self, location, status=303, headers=None):
        self.send_response(status)
        self.send_header('Location', location)
        self.send_header('Cache-Control', 'no-store')
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _ip(self):
        return self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[0].strip()

    def send_json(self, obj, status=200, headers=None):
        data = jdump(obj)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        if headers:
            for k,v in headers.items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)

    def send_text(self, text, status=200, ctype='text/html; charset=utf-8'):
        data = text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.end_headers(); self.wfile.write(data)

    def send_bytes(self, data, ctype='application/octet-stream', status=200, headers=None):
        self.send_response(status); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store')
        if headers:
            for k,v in headers.items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)

    def _require_auth(self, conn, role=None):
        s = self._session(conn)
        if not s:
            self.send_json({'ok':False,'error':'unauthorized'},401); return None
        if role and s['role'] != role:
            self.send_json({'ok':False,'error':'forbidden'},403); return None
        return s

    def _require_csrf(self, session, payload):
        token = self.headers.get('X-CSRF-Token') or payload.get('csrf')
        return bool(token and session and token == session['csrf'])

    def csrf_ok(self):
        token=self.headers.get('X-CSRF-Token')
        if not token:return False
        with connect(DB_PATH) as conn:
            session=self._session(conn)
            return bool(session and token==session['csrf'])

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path = p.path
        qs = urllib.parse.parse_qs(p.query)
        if path == '/': return self.send_text((STATIC/'index.html').read_text(encoding='utf-8').replace('{{VERSION}}',VERSION))
        if path == '/auth/meta/callback':
            code=(qs.get('code') or [''])[0].strip()
            error=(qs.get('error_description') or qs.get('error_message') or qs.get('error') or [''])[0].strip()
            payload=json.dumps({'type':'CLUBE_META_OAUTH_CALLBACK','code':code,'error':error},ensure_ascii=False).replace('</','<\\/')
            page=f'''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Conexão Meta • Clube Fidelidade</title><style>body{{font-family:Arial,sans-serif;background:#f7f4ef;color:#1e1713;display:grid;place-items:center;min-height:100vh;margin:0}}main{{max-width:520px;background:#fff;padding:32px;border-radius:22px;box-shadow:0 16px 50px #0002;text-align:center}}h1{{font-size:24px}}p{{line-height:1.5;color:#655b54}}</style></head><body><main><h1>{'Autorização recebida' if code else 'Não foi possível concluir'}</h1><p>{'Você pode voltar ao Clube Fidelidade. Esta janela será fechada automaticamente.' if code else html.escape(error or 'A Meta não retornou uma autorização válida.')}</p></main><script>(function(){{const data={payload};try{{if(window.opener&&!window.opener.closed)window.opener.postMessage(data,window.location.origin)}}catch(e){{}}setTimeout(function(){{try{{window.close()}}catch(e){{}}}},900)}})();</script></body></html>'''
            return self.send_text(page)
        if path.startswith('/empresa/'):
            code=path.split('/empresa/',1)[1].strip().upper()
            return self.send_redirect('/join?campaign='+urllib.parse.quote(code),302)
        if path == '/privacy':
            code=(qs.get('campaign') or [''])[0].upper().strip(); client='seu estabelecimento'
            if code:
                with connect(DB_PATH) as conn:
                    c=conn.execute('SELECT name FROM campaigns WHERE code=? AND active=1',(code,)).fetchone()
                    if c:client=c['name']
            template=(STATIC/'privacy.html').read_text(encoding='utf-8').replace('{{VERSION}}',VERSION).replace('{{CLIENT_NAME}}',html.escape(str(client)))
            return self.send_text(template)
        if path == '/join':
            code=(qs.get('campaign') or ['CAFE5'])[0].upper().strip()
            with connect(DB_PATH) as conn:
                c=conn.execute('''SELECT c.name,c.reward_name,c.goal,c.logo_image,co.primary_color,co.logo_text FROM campaigns c JOIN companies co ON co.id=c.company_id WHERE c.code=? AND c.active=1''',(code,)).fetchone()
            template=(STATIC/'join.html').read_text(encoding='utf-8').replace('{{VERSION}}',VERSION)
            if c:
                if c['logo_image']:
                    logo_block = '<img class="campaign-logo" src="' + html.escape(str(c['logo_image']), quote=True) + '" alt="Logo do cliente">'
                else:
                    logo_block = '<div class="brand campaign-logo-fallback">' + html.escape(str(c['logo_text'])) + '</div>'
                template=template.replace('{{LOGO_BLOCK}}',logo_block).replace('{{CAMPAIGN_NAME}}',html.escape(str(c['name'])))
                template=template.replace('name="campaign_code" value="CAFE5"',f'name="campaign_code" value="{html.escape(code)}"')
                template=template.replace('href="/privacy"',f'href="/privacy?campaign={urllib.parse.quote(code)}"')
                template=template.replace('</head>',f"<style>:root{{--accent:{html.escape(str(c['primary_color']))}}}</style></head>")
                error_code=(qs.get('error') or [''])[0]
                if error_code:
                    messages={'invalid_name':'Preencha seu nome corretamente.','invalid_email':'Digite um e-mail válido.','invalid_phone':'Digite um celular válido com DDD.','invalid_birth_date':'Digite uma data de nascimento válida.','invalid_cpf':'Digite um CPF válido.','privacy_consent_required':'É necessário aceitar a Política de Privacidade para criar o cartão.','campaign_not_found':'Cliente não encontrado.'}
                    message=messages.get(error_code,'Não foi possível criar o cartão. Confira os dados e tente novamente.')
                    template=template.replace('<div id="msg"></div>','<div id="msg"><div class="notice error">'+html.escape(message)+'</div></div>')
            else:
                template=template.replace('{{LOGO_BLOCK}}','<div class="brand campaign-logo-fallback">CLUBE</div>').replace('{{CAMPAIGN_NAME}}','Cliente não encontrado').replace('<form id="f" class="form" method="post" action="/join">','<form id="f" class="form hidden" method="post" action="/join">')
            return self.send_text(template)
        if path in ['/login','/manager','/attendant','/card','/rewards','/loyalty360']:
            name = path.strip('/') + '.html'
            template=(STATIC/name).read_text(encoding='utf-8').replace('{{VERSION}}',VERSION)
            if path == '/login' and (qs.get('error') or [''])[0]:
                template=template.replace('<div id="msg"></div>','<div id="msg"><div class="notice error">E-mail ou senha inválidos.</div></div>')
            return self.send_text(template)
        if path.startswith('/static/'):
            target = (STATIC / path[len('/static/'):]).resolve()
            if STATIC.resolve() not in target.parents or not target.exists() or not target.is_file():
                return self.send_text('Not found',404,'text/plain')
            import mimetypes
            ctype = mimetypes.guess_type(str(target))[0] or 'application/octet-stream'
            if ctype.startswith('text/') or ctype in ('application/javascript','application/json','image/svg+xml'):
                return self.send_text(target.read_text(encoding='utf-8'),200,ctype + ('; charset=utf-8' if ctype.startswith('text/') or ctype in ('application/javascript','application/json') else ''))
            return self.send_bytes(target.read_bytes(),ctype,200,{'Cache-Control':'public, max-age=3600'})
        if path == '/reset-password':
            target=STATIC/'reset-password.html'; return self.send_text(target.read_text(encoding='utf-8').replace('{{VERSION}}',VERSION),200,'text/html; charset=utf-8')
        if path == '/api/health': return self.send_json({'ok':True,'version':VERSION,'database':'postgresql' if str(DB_PATH).startswith(('postgres://','postgresql://')) else 'sqlite'})
        if path == '/api/session':
            with connect(DB_PATH) as conn:
                s=self._session(conn)
                if not s: return self.send_json({'ok':False,'authenticated':False})
                return self.send_json({'ok':True,'authenticated':True,'user':{'id':s['user_id'],'name':s['name'],'email':s['email'],'role':s['role'],'campaign_id':s['campaign_id'],'client_name':s['client_name'],'client_logo_image':s['client_logo_image'],'is_client_admin':bool(s['is_client_admin']),'permissions':session_permissions(rowdict(s))},'csrf':s['csrf']})
        if path == '/api/wallet/status': return self.send_json({'ok':True,**wallet_status()})
        if path == '/api/campaign/public':
            code=(qs.get('code') or [''])[0].upper().strip()
            with connect(DB_PATH) as conn:
                c=conn.execute('''SELECT c.*,co.name company_name,co.primary_color,co.logo_text FROM campaigns c JOIN companies co ON co.id=c.company_id WHERE c.code=? AND c.active=1''',(code,)).fetchone()
                if not c:
                    return self.send_redirect('/join?campaign='+urllib.parse.quote(code or 'CAFE5')+'&error=1') if path=='/join' else self.send_json({'ok':False,'error':'campaign_not_found'},404)
                return self.send_json({'ok':True,'campaign':rowdict(c)})
        if path == '/api/card':
            public_id=(qs.get('id') or [''])[0]
            with connect(DB_PATH) as conn:
                m=conn.execute('''SELECT m.public_id,m.qr_token,m.progress,m.rewards_available,m.status,m.created_at,
                                  c.name campaign_name,c.reward_name,c.goal,c.icon,c.code,c.logo_image,c.card_theme,c.loyalty_type,c.points_spend_cents,
                                  m.points_balance,m.id membership_id,cu.name customer_name,co.name company_name,co.primary_color,co.logo_text
                                  FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id JOIN companies co ON co.id=c.company_id
                                  WHERE m.public_id=?''',(public_id,)).fetchone()
                if not m: return self.send_json({'ok':False,'error':'card_not_found'},404)
                data=rowdict(m)
                data['card_code']=f'CLUBE:{m["public_id"]}'
                data['qr_value']=data['card_code']
                data['apple_link']=apple_pass_link(public_id)
                data['google_link']=google_wallet_link(public_id)
                data['recent_history']=[rowdict(x) for x in conn.execute('SELECT type,value,note,created_at FROM transactions WHERE membership_id=? ORDER BY created_at DESC LIMIT 5',(m['membership_id'],)).fetchall()]
                data['available_coupons']=[rowdict(x) for x in conn.execute("SELECT name,code,benefit_type,benefit_value,ends_at FROM coupons WHERE campaign_id=(SELECT campaign_id FROM memberships WHERE id=?) AND active=1 AND (starts_at IS NULL OR starts_at<=?) AND (ends_at IS NULL OR ends_at>=?) ORDER BY id DESC LIMIT 5",(m['membership_id'],now_ts(),now_ts())).fetchall()]
                tier=conn.execute('SELECT name,benefit FROM loyalty_tiers WHERE campaign_id=(SELECT campaign_id FROM memberships WHERE id=?) AND active=1 AND min_points<=? ORDER BY min_points DESC LIMIT 1',(m['membership_id'],m['points_balance'] or 0)).fetchone(); data['tier']=rowdict(tier)
                data['nps_due']=not bool(conn.execute('SELECT 1 FROM nps_responses WHERE membership_id=? AND created_at>=? LIMIT 1',(m['membership_id'],now_ts()-90*86400)).fetchone()) and bool(conn.execute('SELECT 1 FROM transactions WHERE membership_id=? LIMIT 1',(m['membership_id'],)).fetchone())
                return self.send_json({'ok':True,'card':data,'wallet':wallet_status()})
        if path == '/api/qr':
            value=(qs.get('data') or [''])[0]
            if not value or len(value)>300: return self.send_text('bad qr data',400,'text/plain')
            img=qrcode.make(value)
            bio=io.BytesIO(); img.save(bio,format='PNG'); data=bio.getvalue()
            self.send_response(200); self.send_header('Content-Type','image/png'); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(data); return
        if path == '/api/card/qr-token':
            public_id=(qs.get('id') or [''])[0].strip()
            with connect(DB_PATH) as conn:
                if not conn.execute('SELECT id FROM memberships WHERE public_id=? AND status=?',(public_id,'active')).fetchone(): return self.send_json({'ok':False,'error':'membership_not_found'},404)
            token,exp=make_dynamic_qr(public_id,60)
            return self.send_json({'ok':True,'token':token,'expires_at':exp})
        if path.startswith('/api/wallet/logo-v62/') or path.startswith('/api/wallet/logo/'):
            if path.startswith('/api/wallet/logo-v62/'):
                # Versioned path is intentionally immutable. Changing the path, not
                # only the query string, forces Google Wallet to fetch the new logo.
                tail=path.split('/api/wallet/logo-v62/',1)[1].strip('/')
                campaign_code=urllib.parse.unquote(tail.split('/',1)[0]).strip().upper()
            else:
                campaign_code=urllib.parse.unquote(path.split('/api/wallet/logo/',1)[1]).strip()
                if campaign_code.lower().endswith('.png'):
                    campaign_code=campaign_code[:-4]
                campaign_code=campaign_code.strip().upper()
            if not campaign_code:return self.send_text('not found',404,'text/plain')
            with connect(DB_PATH) as conn:
                c=conn.execute('SELECT logo_image FROM campaigns WHERE UPPER(code)=UPPER(?) AND active=1',(campaign_code,)).fetchone()
            if not c or not c['logo_image']:return self.send_text('not found',404,'text/plain')
            try:
                # Google Wallet renders programLogo inside a fixed circular slot.
                # Many uploaded logos are square images with a large white/solid
                # background around the real artwork, so simply resizing the whole
                # upload makes the brand mark look tiny. v62 removes the
                # background that is CONNECTED to the image borders, preserving
                # white details that belong to the logo itself.
                raw,_subtype=decode_image_data(c['logo_image'])
                from PIL import Image as PILImage, ImageChops, ImageDraw as PILImageDraw
                src=PILImage.open(io.BytesIO(raw)).convert('RGBA')

                # v62: crop the ACTUAL artwork, not the uploaded square.
                # Google masks programLogo as a circle and recommends a 15% safe
                # margin. We therefore isolate pixels that differ from the edge
                # background, crop tightly, then rebuild a square asset whose
                # artwork fills the whole safe area.
                from PIL import ImageStat
                alpha=src.getchannel('A')
                alpha_bbox=alpha.getbbox()
                if alpha_bbox:
                    src=src.crop(alpha_bbox)

                rgb=src.convert('RGB')
                w,h=rgb.size
                # Robust edge background estimate from many border samples.
                samples=[]
                step=max(1,min(w,h)//64)
                for x in range(0,w,step):
                    samples.append(rgb.getpixel((x,0))); samples.append(rgb.getpixel((x,h-1)))
                for y in range(0,h,step):
                    samples.append(rgb.getpixel((0,y))); samples.append(rgb.getpixel((w-1,y)))
                if samples:
                    bg=tuple(sorted(px[c] for px in samples)[len(samples)//2] for c in range(3))
                else:
                    bg=(255,255,255)

                bg_img=PILImage.new('RGB',rgb.size,bg)
                diff=ImageChops.difference(rgb,bg_img)
                dr,dg,db=diff.split()
                maxdiff=ImageChops.lighter(ImageChops.lighter(dr,dg),db)
                # Anything clearly different from the border is real artwork.
                fg=maxdiff.point(lambda v: 255 if v>24 else 0).convert('L')
                # Include non-transparent pixels when the source already has alpha.
                if src.getchannel('A').getextrema() != (255,255):
                    a=src.getchannel('A').point(lambda v:255 if v>20 else 0)
                    fg=ImageChops.lighter(fg,a)
                art_bbox=fg.getbbox()
                if art_bbox:
                    l,t,r,b=art_bbox
                    # Tiny antialiasing allowance only.
                    pad=max(1,round(max(r-l,b-t)*0.01))
                    art=src.crop((max(0,l-pad),max(0,t-pad),min(src.width,r+pad),min(src.height,b+pad)))
                else:
                    art=src

                size=840
                margin=round(size*0.15)
                safe=size-2*margin
                scale=min(safe/max(1,art.width),safe/max(1,art.height))
                target=(max(1,round(art.width*scale)),max(1,round(art.height*scale)))
                art=art.resize(target,PILImage.Resampling.LANCZOS)
                # Use the detected original edge colour as the full square
                # background, matching Google's logo guidelines.
                canvas=PILImage.new('RGBA',(size,size),(*bg,255))
                # Preserve artwork alpha over the solid background.
                canvas.alpha_composite(art,((size-art.width)//2,(size-art.height)//2))
                out=io.BytesIO(); canvas.save(out,format='PNG',optimize=True)
                return self.send_bytes(out.getvalue(),'image/png',200,{'Cache-Control':'public, max-age=31536000, immutable','X-Content-Type-Options':'nosniff','X-Wallet-Logo-Revision':'v62'})
            except Exception as exc:
                print('[GOOGLE_WALLET] logo render failed:',repr(exc))
                return self.send_text('invalid image',422,'text/plain')
        if path.startswith('/api/wallet/apple/'):
            public_id=urllib.parse.unquote(path.split('/api/wallet/apple/',1)[1])
            with connect(DB_PATH) as conn: card=card_record(conn,public_id)
            if not card:return self.send_json({'ok':False,'error':'membership_not_found'},404)
            try:return self.send_bytes(build_apple_pkpass(card),'application/vnd.apple.pkpass',200,{'Content-Disposition':f'attachment; filename="clube-{public_id}.pkpass"'})
            except Exception as exc:return self.send_json({'ok':False,'error':'apple_wallet_failed','detail':str(exc)[:400]},503)
        if path.startswith('/api/wallet/google/'):
            public_id=urllib.parse.unquote(path.split('/api/wallet/google/',1)[1])
            with connect(DB_PATH) as conn: card=card_record(conn,public_id)
            if not card:return self.send_json({'ok':False,'error':'membership_not_found'},404)
            try:return self.send_redirect(google_save_url(card),302)
            except Exception as exc:return self.send_json({'ok':False,'error':'google_wallet_failed','detail':str(exc)[:400]},503)
        if path.startswith('/api/apple-wallet/v1/passes/'):
            parts=path.split('/'); public_id=urllib.parse.unquote(parts[-1]); auth=(self.headers.get('Authorization') or '').replace('ApplePass ','').strip()
            if not hmac.compare_digest(auth,apple_auth_token(public_id)):return self.send_json({'ok':False,'error':'unauthorized'},401)
            with connect(DB_PATH) as conn: card=card_record(conn,public_id)
            if not card:return self.send_json({'ok':False,'error':'not_found'},404)
            try:return self.send_bytes(build_apple_pkpass(card),'application/vnd.apple.pkpass')
            except Exception as exc:return self.send_json({'ok':False,'error':'apple_wallet_failed','detail':str(exc)[:300]},503)
        if path.startswith('/api/apple-wallet/v1/devices/') and '/registrations/' in path and path.count('/')==7:
            # /api/apple-wallet/v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}
            parts=path.split('/')
            if len(parts)>=8 and parts[4]=='devices' and parts[6]=='registrations':
                device=urllib.parse.unquote(parts[5]); pass_type=urllib.parse.unquote(parts[7])
                try: since=int((qs.get('passesUpdatedSince') or ['0'])[0] or 0)
                except (TypeError,ValueError): since=0
                with connect(DB_PATH) as conn:
                    rows=conn.execute('''SELECT m.public_id FROM wallet_registrations wr JOIN memberships m ON m.id=wr.membership_id WHERE wr.device_library_id=?''',(device,)).fetchall()
                return self.send_json({'serialNumbers':[r['public_id'] for r in rows],'lastUpdated':str(now_ts())})
        if path == '/api/attendant/customer/history':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                try: customer_id=int((qs.get('customer_id') or ['0'])[0])
                except: customer_id=0
                row=conn.execute("SELECT cu.id,cu.name,cu.email,cu.phone,cu.birth_date,cu.cpf,cu.created_at,cu.marketing_email,cu.marketing_whatsapp,m.id membership_id,m.public_id,m.progress,m.points_balance,m.rewards_available,m.status,c.name campaign_name,c.goal,c.reward_name,c.loyalty_type,c.points_spend_cents FROM customers cu JOIN memberships m ON m.customer_id=cu.id JOIN campaigns c ON c.id=m.campaign_id WHERE cu.id=? AND m.campaign_id=?",(customer_id,sess['campaign_id'])).fetchone()
                if not row:return self.send_json({'ok':False,'error':'customer_not_found'},404)
                hist=[rowdict(x) for x in conn.execute("SELECT t.type,t.value,t.previous_progress,t.new_progress,t.rewards_delta,t.note,t.created_at,u.name user_name FROM transactions t LEFT JOIN users u ON u.id=t.user_id WHERE t.membership_id=? ORDER BY t.created_at DESC LIMIT 300",(row['membership_id'],)).fetchall()]
                stats=conn.execute("SELECT COUNT(*) visits,MAX(created_at) last_activity,MIN(created_at) first_activity,COALESCE(SUM(CASE WHEN value>0 THEN value ELSE 0 END),0) total_earned,COALESCE(SUM(CASE WHEN type='redeem' THEN 1 ELSE 0 END),0) total_redeems FROM transactions WHERE membership_id=?",(row['membership_id'],)).fetchone()
                notes=[rowdict(x) for x in conn.execute("SELECT n.note,n.created_at,u.name user_name FROM customer_notes n LEFT JOIN users u ON u.id=n.user_id WHERE n.membership_id=? ORDER BY n.id DESC LIMIT 30",(row['membership_id'],)).fetchall()]
                communications=[rowdict(x) for x in conn.execute("SELECT kind,status,created_at,sent_at FROM message_queue WHERE campaign_id=? AND recipient IN (?,?) ORDER BY created_at DESC LIMIT 30",(sess['campaign_id'],row['email'] or '',row['phone'] or '')).fetchall()]
                coupons=[rowdict(x) for x in conn.execute("SELECT cp.name,cp.code,cr.created_at FROM coupon_redemptions cr JOIN coupons cp ON cp.id=cr.coupon_id WHERE cr.membership_id=? ORDER BY cr.created_at DESC LIMIT 30",(row['membership_id'],)).fetchall()]
                redemptions=[rowdict(x) for x in conn.execute("SELECT COALESCE(rc.name,'Recompensa') name,rr.points_cost,rr.created_at FROM reward_redemptions rr LEFT JOIN reward_catalog rc ON rc.id=rr.reward_id WHERE rr.membership_id=? ORDER BY rr.created_at DESC LIMIT 30",(row['membership_id'],)).fetchall()]
                return self.send_json({'ok':True,'customer':rowdict(row),'stats':rowdict(stats),'notes':notes,'communications':communications,'coupons':coupons,'redemptions':redemptions,'history':hist})
        if path == '/api/admin/report.csv':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                rows=conn.execute("SELECT cu.name,cu.email,cu.phone,cu.birth_date,cu.cpf,m.public_id,m.progress,m.rewards_available,m.status FROM customers cu JOIN memberships m ON m.customer_id=cu.id WHERE m.campaign_id=? ORDER BY cu.name",(sess['campaign_id'],)).fetchall()
                import csv
                b=io.StringIO();w=csv.writer(b);w.writerow(['Nome','E-mail','Celular','Nascimento','CPF','Código','Selos','Recompensas','Status'])
                [w.writerow([r['name'],r['email'],r['phone'],r['birth_date'],r['cpf'],'CLUBE:'+r['public_id'],r['progress'],r['rewards_available'],r['status']]) for r in rows]
                return self.send_bytes(b.getvalue().encode('utf-8-sig'),'text/csv; charset=utf-8',200,{'Content-Disposition':'attachment; filename=relatorio-clientes.csv'})
        if path == '/api/manager/report.csv':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'manager')
                if not sess:return
                rows=conn.execute("SELECT c.name empresa,cu.name cliente,cu.email,cu.phone,m.public_id,m.progress,m.rewards_available,m.status FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE c.company_id=? ORDER BY c.name,cu.name",(sess['company_id'],)).fetchall()
                import csv
                b=io.StringIO();w=csv.writer(b);w.writerow(['Empresa','Cliente','E-mail','Celular','Código','Selos','Recompensas','Status'])
                [w.writerow([r['empresa'],r['cliente'],r['email'],r['phone'],'CLUBE:'+r['public_id'],r['progress'],r['rewards_available'],r['status']]) for r in rows]
                return self.send_bytes(b.getvalue().encode('utf-8-sig'),'text/csv; charset=utf-8',200,{'Content-Disposition':'attachment; filename=relatorio-geral.csv'})
        if path == '/api/manager/join-qr':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'manager')
                if not sess:return
                try: cid=int((qs.get('campaign_id') or ['0'])[0])
                except: cid=0
                c=conn.execute('SELECT code FROM campaigns WHERE id=? AND company_id=?',(cid,sess['company_id'])).fetchone()
                if not c:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                base=(os.environ.get('CLUBE_PUBLIC_URL') or ('https://'+self.headers.get('Host',''))).rstrip('/')
                img=qrcode.make(base+'/join?campaign='+urllib.parse.quote(c['code'])); bio=BytesIO(); img.save(bio,format='PNG')
                return self.send_bytes(bio.getvalue(),'image/png',200,{'Cache-Control':'no-store'})
        if path == '/api/admin/templates':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                return self.send_json({'ok':True,'templates':[rowdict(r) for r in conn.execute('SELECT * FROM message_templates WHERE campaign_id=? ORDER BY name',(sess['campaign_id'],)).fetchall()]})
        if path == '/api/manager/notifications':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'manager')
                if not sess:return
                rows=[]
                failed=conn.execute("SELECT c.id,c.name,COUNT(*) n FROM message_queue q JOIN campaigns c ON c.id=q.campaign_id WHERE c.company_id=? AND q.status='failed' GROUP BY c.id,c.name",(sess['company_id'],)).fetchall()
                for r in failed: rows.append({'kind':'error','campaign_id':r['id'],'title':'Falhas de envio • '+r['name'],'message':str(r['n'])+' mensagem(ns) com falha. Verifique a integração e a fila de comunicação.'})
                camps=conn.execute('SELECT * FROM campaigns WHERE company_id=? AND active=1',(sess['company_id'],)).fetchall(); now=now_ts()
                for c in camps:
                    cid=c['id']; ec=email_configured(email_config_for_client(conn,cid)); wc=whatsapp_cloud_configured(whatsapp_config_for_client(conn,cid))
                    if not ec: rows.append({'kind':'integration','campaign_id':cid,'title':'E-mail não configurado • '+c['name'],'message':'Configure o e-mail para ativar campanhas e automações.'})
                    if not wc: rows.append({'kind':'integration','campaign_id':cid,'title':'WhatsApp não configurado • '+c['name'],'message':'Conecte o WhatsApp para ativar mensagens e recuperação de clientes.'})
                    last=conn.execute("SELECT MAX(t.created_at) ts FROM transactions t JOIN memberships m ON m.id=t.membership_id WHERE m.campaign_id=?",(cid,)).fetchone()['ts']
                    cards=conn.execute("SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND status='active'",(cid,)).fetchone()['n']
                    if cards and (not last or last < now-7*86400): rows.append({'kind':'attention','campaign_id':cid,'title':'Sem movimentação recente • '+c['name'],'message':'Nenhum atendimento foi registrado nos últimos 7 dias. Confira se a equipe está utilizando o Fidelizaê!.'})
                    risk=conn.execute("SELECT COUNT(*) n FROM memberships m WHERE m.campaign_id=? AND m.status='active' AND COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)<? AND COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)>=?",(cid,now-30*86400,now-60*86400)).fetchone()['n']
                    if risk: rows.append({'kind':'opportunity','campaign_id':cid,'title':'Oportunidade de recuperação • '+c['name'],'message':str(risk)+' cliente(s) estão entre 30 e 60 dias sem atividade. Uma campanha de retorno pode ajudar.'})
                    if c['loyalty_type']=='stamps':
                        almost=conn.execute("SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND status='active' AND progress=?",(cid,max(int(c['goal'] or 1)-1,0))).fetchone()['n']
                        if almost: rows.append({'kind':'opportunity','campaign_id':cid,'title':'Clientes quase lá • '+c['name'],'message':str(almost)+' cliente(s) estão a apenas 1 selo da recompensa.'})
                    pending=conn.execute("SELECT COUNT(*) n FROM message_queue WHERE campaign_id=? AND status IN ('pending','retry','processing')",(cid,)).fetchone()['n']
                    if pending>=20: rows.append({'kind':'attention','campaign_id':cid,'title':'Fila de comunicação • '+c['name'],'message':str(pending)+' mensagens aguardam processamento.'})
                order={'error':0,'attention':1,'opportunity':2,'integration':3}; rows.sort(key=lambda x:order.get(x.get('kind'),9))
                for n in rows:
                    fp=hashlib.sha256((n.get('title','')+'|'+n.get('message','')).encode()).hexdigest()[:24]; st=conn.execute('SELECT status,priority FROM alert_states WHERE fingerprint=?',(fp,)).fetchone(); n['fingerprint']=fp; n['status']=(st['status'] if st else 'new'); n['priority']=(st['priority'] if st else ('high' if n.get('kind')=='error' else 'medium')); n['action']='campaign' if 'recupera' in n.get('title','').lower() or 'quase' in n.get('title','').lower() else ('integration' if n.get('kind')=='integration' else 'company')
                return self.send_json({'ok':True,'notifications':[x for x in rows[:40] if x.get('status')!='resolved']})
        if path == '/api/attendant/dashboard':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin'] and not self._need_permission(sess,'view_reports'): return
                cid=sess['campaign_id']; now=now_ts(); month_start=int(datetime.now(ZoneInfo('America/Sao_Paulo')).replace(day=1,hour=0,minute=0,second=0,microsecond=0).timestamp())
                metrics={}
                metrics['active_cards']=conn.execute("SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND status='active'",(cid,)).fetchone()['n']
                metrics['new_month']=conn.execute('SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND created_at>=?',(cid,month_start)).fetchone()['n']
                campaign=conn.execute("SELECT loyalty_type FROM campaigns WHERE id=?",(cid,)).fetchone(); loyalty_type=(campaign['loyalty_type'] if campaign else 'stamps') or 'stamps'; metrics['loyalty_type']=loyalty_type
                metrics['stamps_month']=conn.execute("SELECT COALESCE(SUM(t.value),0) n FROM transactions t JOIN memberships m ON m.id=t.membership_id WHERE m.campaign_id=? AND t.type='stamp' AND t.created_at>=?",(cid,month_start)).fetchone()['n']
                metrics['points_month']=conn.execute("SELECT COALESCE(SUM(CASE WHEN t.type='adjustment' AND t.value>0 THEN t.value ELSE 0 END),0) n FROM transactions t JOIN memberships m ON m.id=t.membership_id WHERE m.campaign_id=? AND t.created_at>=?",(cid,month_start)).fetchone()['n']
                metrics['redeems_month']=conn.execute("SELECT COUNT(*) n FROM transactions t JOIN memberships m ON m.id=t.membership_id WHERE m.campaign_id=? AND t.type='redeem' AND t.created_at>=?",(cid,month_start)).fetchone()['n']
                total=metrics['active_cards'] or 1
                if loyalty_type=='points':
                    cheapest=conn.execute("SELECT MIN(points_cost) n FROM reward_catalog WHERE campaign_id=? AND active=1",(cid,)).fetchone()['n']; completed=conn.execute("SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND points_balance>=?",(cid,int(cheapest or 999999999))).fetchone()['n'] if cheapest else 0
                else: completed=conn.execute('SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND rewards_available>0',(cid,)).fetchone()['n']
                metrics['completion_rate']=round(completed*100/total,1)
                for days in (30,60,90): metrics[f'inactive_{days}']=conn.execute('''SELECT COUNT(*) n FROM memberships m WHERE m.campaign_id=? AND COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)<?''',(cid,now-days*86400)).fetchone()['n']
                pending=conn.execute("SELECT COUNT(*) n FROM message_queue WHERE campaign_id=? AND status IN ('pending','retry','processing')",(cid,)).fetchone()['n']; metrics['messages_pending']=pending
                metrics['birthdays_month']=conn.execute("SELECT COUNT(*) n FROM customers cu JOIN memberships m ON m.customer_id=cu.id WHERE m.campaign_id=? AND substr(cu.birth_date,6,2)=?",(cid,datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%m'))).fetchone()['n']
                returned=conn.execute("SELECT COUNT(*) n FROM memberships m WHERE m.campaign_id=? AND (SELECT COUNT(*) FROM transactions t WHERE t.membership_id=m.id AND ((?='points' AND t.type='adjustment' AND t.value>0) OR (?='stamps' AND t.type='stamp')))>=2",(cid,loyalty_type,loyalty_type)).fetchone()['n']; metrics['return_rate']=round(returned*100/total,1)
                # Retenção e resumo semanal/mensal.
                visit_expr="((c.loyalty_type='points' AND t.type='adjustment' AND t.value>0) OR (c.loyalty_type='stamps' AND t.type='stamp' AND t.value>0))"
                metrics['visits_month']=conn.execute("SELECT COUNT(*) n FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND t.created_at>=? AND "+visit_expr,(cid,month_start)).fetchone()['n']
                metrics['returning_month']=conn.execute("SELECT COUNT(DISTINCT m.id) n FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND EXISTS(SELECT 1 FROM transactions t WHERE t.membership_id=m.id AND t.created_at>=? AND "+visit_expr+") AND EXISTS(SELECT 1 FROM transactions t WHERE t.membership_id=m.id AND t.created_at<? AND "+visit_expr+")",(cid,month_start,month_start)).fetchone()['n']
                metrics['reactivated_month']=conn.execute("SELECT COUNT(DISTINCT m.id) n FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND EXISTS(SELECT 1 FROM transactions t WHERE t.membership_id=m.id AND t.created_at>=? AND "+visit_expr+") AND COALESCE((SELECT MAX(t2.created_at) FROM transactions t2 WHERE t2.membership_id=m.id AND t2.created_at<?),m.created_at)<?",(cid,month_start,month_start,month_start-30*86400)).fetchone()['n']
                week_start=now-7*86400; prev_week=now-14*86400
                week_visits=conn.execute("SELECT COUNT(*) n FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND t.created_at>=? AND "+visit_expr,(cid,week_start)).fetchone()['n']
                prev_visits=conn.execute("SELECT COUNT(*) n FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND t.created_at>=? AND t.created_at<? AND "+visit_expr,(cid,prev_week,week_start)).fetchone()['n']
                metrics['weekly']={'visits':week_visits,'new':conn.execute('SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND created_at>=?',(cid,week_start)).fetchone()['n'],'redeems':conn.execute("SELECT COUNT(*) n FROM transactions t JOIN memberships m ON m.id=t.membership_id WHERE m.campaign_id=? AND t.type='redeem' AND t.created_at>=?",(cid,week_start)).fetchone()['n'],'change_pct':round((week_visits-prev_visits)*100/max(prev_visits,1),1)}
                seg_counts={}
                for seg in ('new','active','vip','at_risk','inactive60','inactive90','almost_reward','reward_ready'):
                    try:
                        rows=campaign_recipient_rows(conn,cid,seg) if seg!='active' else []
                        if seg=='active':
                            raw=conn.execute("""SELECT m.id,m.created_at,COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at) last_activity,
                              (SELECT COUNT(*) FROM transactions t WHERE t.membership_id=m.id AND t.value>0) visits,m.rewards_available,m.progress,c.goal,c.loyalty_type,m.points_balance
                              FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND m.status='active' """,(cid,)).fetchall()
                            n=0
                            for x in raw:
                                rr=bool(x['rewards_available']); ar=(x['loyalty_type']=='stamps' and x['progress']==x['goal']-1)
                                if customer_segment(x['last_activity'],x['created_at'],x['visits'],rr,ar,now)=='active': n+=1
                            seg_counts[seg]=n
                        else: seg_counts[seg]=len(rows)
                    except Exception: seg_counts[seg]=0
                metrics['segments']=seg_counts
                retention=[]
                local_now=datetime.now(ZoneInfo('America/Sao_Paulo'))
                for back in range(5,-1,-1):
                    y=local_now.year; mo=local_now.month-back
                    while mo<=0: mo+=12; y-=1
                    start=datetime(y,mo,1,tzinfo=ZoneInfo('America/Sao_Paulo')); nxt=datetime(y+1,1,1,tzinfo=start.tzinfo) if mo==12 else datetime(y,mo+1,1,tzinfo=start.tzinfo)
                    st,en=int(start.timestamp()),int(nxt.timestamp())
                    active_n=conn.execute("SELECT COUNT(DISTINCT m.id) n FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND EXISTS(SELECT 1 FROM transactions t WHERE t.membership_id=m.id AND t.created_at>=? AND t.created_at<? AND "+visit_expr+")",(cid,st,en)).fetchone()['n']
                    ret_n=conn.execute("SELECT COUNT(DISTINCT m.id) n FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND EXISTS(SELECT 1 FROM transactions t WHERE t.membership_id=m.id AND t.created_at>=? AND t.created_at<? AND "+visit_expr+") AND EXISTS(SELECT 1 FROM transactions t2 WHERE t2.membership_id=m.id AND t2.created_at<? AND "+visit_expr.replace('t.','t2.')+")",(cid,st,en,st)).fetchone()['n']
                    retention.append({'month':f'{mo:02d}/{str(y)[2:]}','rate':round(ret_n*100/max(active_n,1),1)})
                metrics['retention_trend']=retention
                activity=[]
                for d in range(29,-1,-1):
                    day=(datetime.now(ZoneInfo('America/Sao_Paulo'))-timedelta(days=d)).date(); start=int(datetime.combine(day,datetime.min.time(),ZoneInfo('America/Sao_Paulo')).timestamp()); end=start+86400
                    n=conn.execute('SELECT COUNT(*) n FROM transactions t JOIN memberships m ON m.id=t.membership_id WHERE m.campaign_id=? AND t.created_at>=? AND t.created_at<?',(cid,start,end)).fetchone()['n']
                    activity.append({'date':day.isoformat(),'count':n})
                metrics['activity_30d']=activity
                # Financeiro: usa valores de compra registrados tanto em pontos quanto em selos.
                fin=conn.execute('SELECT COALESCE(SUM(pr.amount_cents),0) revenue,COUNT(*) purchases FROM purchase_records pr JOIN memberships m ON m.id=pr.membership_id WHERE m.campaign_id=? AND pr.created_at>=?',(cid,month_start)).fetchone()
                metrics['revenue_month_cents']=int(fin['revenue'] or 0); metrics['purchases_month']=int(fin['purchases'] or 0); metrics['avg_ticket_cents']=round(metrics['revenue_month_cents']/max(metrics['purchases_month'],1))
                metrics['campaign_revenue_cents']=int(conn.execute('SELECT COALESCE(SUM(mcr.attributed_revenue_cents),0) n FROM marketing_campaign_recipients mcr JOIN marketing_campaigns mc ON mc.id=mcr.marketing_campaign_id WHERE mc.campaign_id=? AND mcr.returned_at>=?',(cid,month_start)).fetchone()['n'] or 0)
                finance=[]
                for back in range(5,-1,-1):
                    y=local_now.year; mo=local_now.month-back
                    while mo<=0: mo+=12; y-=1
                    start=datetime(y,mo,1,tzinfo=ZoneInfo('America/Sao_Paulo')); nxt=datetime(y+1,1,1,tzinfo=start.tzinfo) if mo==12 else datetime(y,mo+1,1,tzinfo=start.tzinfo)
                    st,en=int(start.timestamp()),int(nxt.timestamp())
                    rv=conn.execute('SELECT COALESCE(SUM(pr.amount_cents),0) n FROM purchase_records pr JOIN memberships m ON m.id=pr.membership_id WHERE m.campaign_id=? AND pr.created_at>=? AND pr.created_at<?',(cid,st,en)).fetchone()['n']
                    finance.append({'month':f'{mo:02d}/{str(y)[2:]}','revenue_cents':int(rv or 0)})
                metrics['finance_trend']=finance
                return self.send_json({'ok':True,'metrics':metrics})
        if path == '/api/admin/engagement':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                cid=sess['campaign_id']; now=now_ts()
                # Atualiza conversões: uma nova movimentação depois do envio conta como retorno.
                recs=conn.execute("SELECT r.id,r.membership_id,r.sent_at FROM marketing_campaign_recipients r JOIN marketing_campaigns mc ON mc.id=r.marketing_campaign_id WHERE mc.campaign_id=? AND r.returned_at IS NULL",(cid,)).fetchall()
                for r in recs:
                    hit=conn.execute('SELECT MIN(created_at) ts FROM transactions WHERE membership_id=? AND created_at>?',(r['membership_id'],r['sent_at'])).fetchone()['ts']
                    if hit: conn.execute('UPDATE marketing_campaign_recipients SET returned_at=? WHERE id=?',(hit,r['id']))
                campaigns=[]
                for r in conn.execute('SELECT * FROM marketing_campaigns WHERE campaign_id=? ORDER BY id DESC LIMIT 40',(cid,)).fetchall():
                    d=rowdict(r); stats=conn.execute('SELECT COUNT(*) sent,SUM(CASE WHEN returned_at IS NOT NULL THEN 1 ELSE 0 END) returned FROM marketing_campaign_recipients WHERE marketing_campaign_id=?',(d['id'],)).fetchone(); d['sent_count']=stats['sent'] or 0; d['returned_count']=stats['returned'] or 0; d['conversion_rate']=round((d['returned_count'] or 0)*100/max(d['sent_count'] or 0,1),1); d['attributed_revenue_cents']=conn.execute('SELECT COALESCE(SUM(attributed_revenue_cents),0) n FROM marketing_campaign_recipients WHERE marketing_campaign_id=?',(d['id'],)).fetchone()['n'] or 0; campaigns.append(d)
                coupons=[]
                for r in conn.execute('SELECT * FROM coupons WHERE campaign_id=? ORDER BY active DESC,id DESC',(cid,)).fetchall():
                    d=rowdict(r); d['uses']=conn.execute('SELECT COUNT(*) n FROM coupon_redemptions WHERE coupon_id=?',(d['id'],)).fetchone()['n']; coupons.append(d)
                camp=conn.execute('SELECT name,code,logo_image,card_theme,loyalty_type,goal FROM campaigns WHERE id=?',(cid,)).fetchone()
                base=(os.environ.get('PUBLIC_BASE_URL') or '').rstrip('/'); join_url=(base+'/join?campaign='+urllib.parse.quote(camp['code'])) if base else ('/join?campaign='+urllib.parse.quote(camp['code']))
                return self.send_json({'ok':True,'campaigns':campaigns,'coupons':coupons,'promo':{'join_url':join_url,'qr_url':'/api/admin/client-qr','client_name':camp['name'],'theme':camp['card_theme'],'has_logo':bool(camp['logo_image'])}})

        if path == '/api/attendant/automations':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                ensure_automation_defaults(conn,sess['campaign_id']); rows=[rowdict(r) for r in conn.execute('SELECT * FROM automation_rules WHERE campaign_id=? ORDER BY id',(sess['campaign_id'],)).fetchall()]
                return self.send_json({'ok':True,'rules':rows,'can_edit':bool(sess['is_client_admin'])})
        if path == '/api/client-admin/staff':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                rows=[rowdict(r) for r in conn.execute("""SELECT u.id,u.name,u.email,u.active,u.is_client_admin,u.created_at,u.branch_id,b.name branch_name,b.code branch_code
                    FROM users u LEFT JOIN branches b ON b.id=u.branch_id AND b.campaign_id=u.campaign_id
                    WHERE u.campaign_id=? AND u.role='attendant' ORDER BY u.is_client_admin DESC,u.name""",(sess['campaign_id'],)).fetchall()]
                branches=[rowdict(r) for r in conn.execute('SELECT id,name,code FROM branches WHERE campaign_id=? AND active=1 ORDER BY name',(sess['campaign_id'],)).fetchall()]
                return self.send_json({'ok':True,'staff':rows,'branches':branches})

        if path == '/api/attendant/loyalty360-summary':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                cid=sess['campaign_id']; now=now_ts()
                camp=conn.execute("SELECT id,name,loyalty_type,points_spend_cents,cashback_percent,points_expiry_days FROM campaigns WHERE id=? AND company_id=?",(cid,sess['company_id'])).fetchone()
                if not camp:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                tiers=[rowdict(x) for x in conn.execute("SELECT name,min_points,benefit,active FROM loyalty_tiers WHERE campaign_id=? AND active=1 ORDER BY min_points",(cid,)).fetchall()]
                mult=[rowdict(x) for x in conn.execute("SELECT name,factor,weekday,start_hour,end_hour,active FROM point_multipliers WHERE campaign_id=? AND active=1 ORDER BY id DESC",(cid,)).fetchall()]
                rewards_count=conn.execute("SELECT COUNT(*) n FROM reward_catalog WHERE campaign_id=? AND active=1",(cid,)).fetchone()['n']
                metrics={}
                metrics['customers']=conn.execute("SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND status='active'",(cid,)).fetchone()['n']
                metrics['points_circulation']=conn.execute("SELECT COALESCE(SUM(points_balance),0) n FROM memberships WHERE campaign_id=?",(cid,)).fetchone()['n']
                metrics['cashback_cents']=conn.execute("SELECT COALESCE(SUM(cashback_balance_cents),0) n FROM memberships WHERE campaign_id=?",(cid,)).fetchone()['n']
                metrics['inactive30']=conn.execute("SELECT COUNT(*) n FROM memberships m WHERE campaign_id=? AND COALESCE((SELECT MAX(created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)<?",(cid,now-30*86400)).fetchone()['n']
                return self.send_json({'ok':True,'can_edit':bool(sess['is_client_admin']),'program_source':'taboo','campaign':rowdict(camp),'tiers':tiers,'multipliers':mult,'rewards_count':rewards_count,'metrics':metrics})

        if path == '/api/admin/loyalty360':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                cid=sess['campaign_id']; now=now_ts()
                camp=rowdict(conn.execute("SELECT * FROM campaigns WHERE id=?",(cid,)).fetchone())
                tiers=[rowdict(x) for x in conn.execute("SELECT * FROM loyalty_tiers WHERE campaign_id=? ORDER BY min_points",(cid,)).fetchall()]
                mult=[rowdict(x) for x in conn.execute("SELECT * FROM point_multipliers WHERE campaign_id=? ORDER BY id DESC",(cid,)).fetchall()]
                nps=[rowdict(x) for x in conn.execute("SELECT * FROM nps_responses WHERE campaign_id=? ORDER BY id DESC LIMIT 100",(cid,)).fetchall()]
                gifts=[rowdict(x) for x in conn.execute("SELECT * FROM gift_cards WHERE campaign_id=? ORDER BY id DESC LIMIT 100",(cid,)).fetchall()]
                metrics={}
                metrics['customers']=conn.execute("SELECT COUNT(*) n FROM memberships WHERE campaign_id=? AND status='active'",(cid,)).fetchone()['n']
                metrics['points_circulation']=conn.execute("SELECT COALESCE(SUM(points_balance),0) n FROM memberships WHERE campaign_id=?",(cid,)).fetchone()['n']
                metrics['cashback_cents']=conn.execute("SELECT COALESCE(SUM(cashback_balance_cents),0) n FROM memberships WHERE campaign_id=?",(cid,)).fetchone()['n']
                metrics['inactive30']=conn.execute("SELECT COUNT(*) n FROM memberships m WHERE campaign_id=? AND COALESCE((SELECT MAX(created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)<?",(cid,now-30*86400)).fetchone()['n']
                scores=[int(x['score']) for x in nps]
                metrics['nps']=round((sum(1 for x in scores if x>=9)-sum(1 for x in scores if x<=6))*100/len(scores)) if scores else None
                return self.send_json({'ok':True,'program_source':'taboo','campaign':camp,'tiers':tiers,'multipliers':mult,'nps':nps,'gift_cards':gifts,'metrics':metrics})

        if path == '/api/attendant/gift-card':
            code=(qs.get('code') or [''])[0].strip().upper()
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not self._need_permission(sess,'use_gift'): return
                if not code:return self.send_json({'ok':False,'error':'gift_code_required'},400)
                gift=conn.execute("SELECT id,code,value_cents,balance_cents,status,purchaser_name,beneficiary_name,created_at FROM gift_cards WHERE campaign_id=? AND upper(code)=upper(?)",(sess['campaign_id'],code)).fetchone()
                if not gift:return self.send_json({'ok':False,'error':'gift_not_found'},404)
                events=[rowdict(x) for x in conn.execute('SELECT event_type,amount_cents,balance_after_cents,note,created_at FROM gift_card_events WHERE gift_card_id=? ORDER BY id DESC LIMIT 20',(gift['id'],)).fetchall()]; return self.send_json({'ok':True,'gift':rowdict(gift),'events':events,'qr_url':'/api/qr?data='+urllib.parse.quote('GIFT:'+gift['code'])})

        if path == '/api/card/history360':
            public_id=(qs.get('id') or [''])[0].strip()
            with connect(DB_PATH) as conn:
                m=conn.execute("SELECT m.*,c.name campaign_name,c.loyalty_type,c.cashback_percent,c.points_expiry_days FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.public_id=?",(public_id,)).fetchone()
                if not m:return self.send_json({'ok':False,'error':'card_not_found'},404)
                hist=[rowdict(x) for x in conn.execute("SELECT type,value,note,created_at FROM transactions WHERE membership_id=? ORDER BY id DESC LIMIT 100",(m['id'],)).fetchall()]
                tier=conn.execute("SELECT name FROM loyalty_tiers WHERE campaign_id=? AND min_points<=? ORDER BY min_points DESC LIMIT 1",(m['campaign_id'],m['points_balance'])).fetchone()
                return self.send_json({'ok':True,'card':rowdict(m),'history':hist,'tier':tier['name'] if tier else None})
        if path == '/api/manager/meta-config':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'manager')
                if not sess:return
                app_id=os.environ.get('META_APP_ID','').strip()
                config_id=os.environ.get('META_CONFIG_ID','').strip()
                version=(os.environ.get('META_GRAPH_VERSION') or 'v24.0').strip() or 'v24.0'
                callback=meta_callback_url()
                return self.send_json({'ok':True,'configured':meta_embedded_signup_configured(),'app_id':app_id,'config_id':config_id,'graph_version':version,'redirect_uri':callback,'public_base_url':meta_public_base_url()})
        if path == '/api/manager/diagnostics':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'manager')
                if not sess:return
                pending=conn.execute("SELECT COUNT(*) n FROM message_queue WHERE status IN ('pending','retry','processing')").fetchone()['n']; failed=conn.execute("SELECT COUNT(*) n FROM message_queue WHERE status='failed'").fetchone()['n']
                return self.send_json({'ok':True,'version':VERSION,'database':'postgresql' if str(DB_PATH).startswith(('postgres://','postgresql://')) else 'sqlite','wallet':wallet_status(),'queue':{'pending':pending,'failed':failed},'encryption':bool(_secret_box()),'meta':meta_embedded_signup_configured(),'global_email':email_configured(global_email_config()),'public_base_url':os.environ.get('PUBLIC_BASE_URL',''),'environment':os.environ.get('APP_ENV','production'),'backup':'available'})
        if path == '/api/manager/backup':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'manager')
                if not sess:return
                cid=sess['company_id']; payload={'generated_at':now_iso(),'version':VERSION,'company_id':cid}
                payload['campaigns']=[rowdict(r) for r in conn.execute('SELECT id,code,name,reward_name,goal,active,created_at FROM campaigns WHERE company_id=? ORDER BY id',(cid,)).fetchall()]
                payload['staff']=[rowdict(r) for r in conn.execute("SELECT id,name,email,role,active,is_client_admin,campaign_id,created_at FROM users WHERE company_id=? ORDER BY id",(cid,)).fetchall()]
                payload['customers']=[rowdict(r) for r in conn.execute('''SELECT cu.id,cu.name,cu.email,cu.phone,cu.birth_date,cu.cpf,m.public_id,m.progress,m.rewards_available,m.status,m.campaign_id FROM customers cu JOIN memberships m ON m.customer_id=cu.id JOIN campaigns c ON c.id=m.campaign_id WHERE c.company_id=? ORDER BY cu.id''',(cid,)).fetchall()]
                payload['transactions']=[rowdict(r) for r in conn.execute('''SELECT t.id,t.membership_id,t.user_id,t.type,t.value,t.previous_progress,t.new_progress,t.rewards_delta,t.note,t.created_at FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN campaigns c ON c.id=m.campaign_id WHERE c.company_id=? ORDER BY t.id''',(cid,)).fetchall()]
                data=json.dumps(payload,ensure_ascii=False,indent=2).encode('utf-8'); return self.send_bytes(data,'application/json; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="clube-backup-{datetime.now().strftime("%Y%m%d-%H%M")}.json"'})
        if path == '/api/privacy/export':
            public_id=(qs.get('id') or [''])[0].strip(); cpf=normalize_cpf((qs.get('cpf') or [''])[0])
            if not cpf:return self.send_json({'ok':False,'error':'invalid_cpf'},400)
            with connect(DB_PATH) as conn:
                row=conn.execute('''SELECT cu.name,cu.email,cu.phone,cu.birth_date,cu.cpf,cu.privacy_accepted_at,cu.marketing_email,cu.marketing_whatsapp,m.public_id,m.progress,m.rewards_available,c.name client_name FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.public_id=? AND cu.cpf=?''',(public_id,cpf)).fetchone()
                if not row:return self.send_json({'ok':False,'error':'not_found'},404)
                tx=[rowdict(r) for r in conn.execute('SELECT type,value,previous_progress,new_progress,rewards_delta,note,created_at FROM transactions WHERE membership_id=(SELECT id FROM memberships WHERE public_id=?) ORDER BY created_at',(public_id,)).fetchall()]
                return self.send_json({'ok':True,'data':rowdict(row),'history':tx})
        if path == '/api/manager/overview':
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn,'manager');
                if not s: return
                cid=s['company_id']; now=now_ts()
                metrics={}
                metrics['customers']=conn.execute('''SELECT COUNT(DISTINCT m.customer_id) n FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE c.company_id=?''',(cid,)).fetchone()['n']
                metrics['stamps']=conn.execute('''SELECT COALESCE(SUM(t.value),0) n FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN campaigns c ON c.id=m.campaign_id WHERE c.company_id=? AND t.type='stamp' ''',(cid,)).fetchone()['n']
                metrics['redeems']=conn.execute('''SELECT COUNT(*) n FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN campaigns c ON c.id=m.campaign_id WHERE c.company_id=? AND t.type='redeem' ''',(cid,)).fetchone()['n']
                campaigns=[rowdict(r) for r in conn.execute("""SELECT c.*,
                    (SELECT COUNT(*) FROM memberships m WHERE m.campaign_id=c.id) card_count,
                    (SELECT COUNT(*) FROM users ux WHERE ux.campaign_id=c.id AND ux.role='attendant' AND ux.active=1) staff_count,
                    (SELECT COALESCE(SUM(CASE WHEN t.type='stamp' THEN t.value WHEN t.type='adjustment' THEN t.value ELSE 0 END),0)
                       FROM transactions t JOIN memberships m2 ON m2.id=t.membership_id WHERE m2.campaign_id=c.id) stamp_count
                    FROM campaigns c WHERE c.company_id=? ORDER BY c.id DESC""",(cid,)).fetchall()]
                for c in campaigns:
                    c['smtp_configured']=bool(c.get('smtp_host') and c.get('smtp_from'))
                    c['brevo_configured']=bool(c.get('brevo_api_key_enc') and c.get('brevo_sender_email'))
                    c['email_provider']=c.get('email_provider') or 'smtp'
                    c['whatsapp_configured']=bool(c.get('whatsapp_phone_number_id') and c.get('whatsapp_access_token_enc') and c.get('whatsapp_api_version'))
                    c['whatsapp_signup_status']=c.get('whatsapp_signup_status') or ('connected' if c['whatsapp_configured'] else 'not_connected')
                    c['whatsapp_integration_mode']=c.get('whatsapp_integration_mode') or 'manual'
                    c['ecommerce_platform']=normalize_ecommerce_platform(c.get('ecommerce_platform'))
                    c['ecommerce_status']=c.get('ecommerce_status') or ('awaiting_connection' if c['ecommerce_platform']!='none' else 'not_connected')
                    c['ecommerce_configured']=bool(c['ecommerce_platform']!='none' and c.get('ecommerce_webhook_secret'))
                    public_base=os.environ.get('PUBLIC_BASE_URL','').rstrip('/')
                    c['ecommerce_webhook_url']=(public_base+f"/api/integrations/ecommerce/{c['id']}/{c.get('ecommerce_webhook_secret')}") if (public_base and c.get('ecommerce_webhook_secret')) else ''
                    c['email_configured']=bool(c['brevo_configured'] if c['email_provider']=='brevo' else c['smtp_configured']); c['reward_catalog_count']=conn.execute("SELECT COUNT(*) n FROM reward_catalog WHERE campaign_id=? AND active=1",(c['id'],)).fetchone()['n']; c['wallet_google']=wallet_status()['google']['ready']; c['wallet_apple']=wallet_status()['apple']['ready']
                    c['smtp_password_enc']=None
                    c['brevo_api_key_enc']=None
                    c['whatsapp_access_token_enc']=None
                staff=[rowdict(r) for r in conn.execute('''SELECT u.id,u.name,u.email,u.role,u.active,u.is_client_admin,u.created_at,u.campaign_id,c.name client_name FROM users u LEFT JOIN campaigns c ON c.id=u.campaign_id WHERE u.company_id=? ORDER BY u.role,u.name''',(cid,)).fetchall()]
                return self.send_json({'ok':True,'metrics':metrics,'campaigns':campaigns,'staff':staff})
        if path == '/api/attendant/recent':
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn,'attendant')
                if not s: return
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                tx=[rowdict(r) for r in conn.execute('''SELECT t.id,t.type,t.value,t.previous_progress,t.new_progress,t.rewards_delta,t.note,t.created_at,cu.name customer_name,c.name campaign_name,u.name user_name
                   FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id LEFT JOIN users u ON u.id=t.user_id
                   WHERE c.id=? AND c.company_id=? ORDER BY t.id DESC LIMIT 50''',(s['campaign_id'],s['company_id'])).fetchall()]
                return self.send_json({'ok':True,'transactions':tx,'client':{'id':s['campaign_id'],'name':s['client_name']}})
        if path == '/api/attendant/customers':
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn,'attendant')
                if not s: return
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                customers=[rowdict(r) for r in conn.execute('''SELECT cu.id,cu.name,cu.email,cu.phone,cu.birth_date,cu.cpf,cu.created_at,m.id membership_id,m.public_id,m.progress,m.points_balance,m.rewards_available,c.loyalty_type,c.goal,
                    COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at) last_activity,
                    (SELECT COUNT(*) FROM transactions t WHERE t.membership_id=m.id AND ((c.loyalty_type='points' AND t.type='adjustment' AND t.value>0) OR (c.loyalty_type='stamps' AND t.type='stamp' AND t.value>0))) visits,
                    (SELECT COUNT(*) FROM transactions t WHERE t.membership_id=m.id AND t.type='redeem') redeems
                    FROM customers cu JOIN memberships m ON m.customer_id=cu.id JOIN campaigns c ON c.id=m.campaign_id
                    WHERE m.campaign_id=? ORDER BY cu.name''',(s['campaign_id'],)).fetchall()]
                cheapest=conn.execute("SELECT MIN(points_cost) n FROM reward_catalog WHERE campaign_id=? AND active=1",(s['campaign_id'],)).fetchone()['n']
                tiers=[rowdict(r) for r in conn.execute("SELECT name,min_points,benefit FROM loyalty_tiers WHERE campaign_id=? AND active=1 ORDER BY min_points",(s['campaign_id'],)).fetchall()]
                for c in customers:
                    reward_ready=bool(c.get('rewards_available')) or bool(c['loyalty_type']=='points' and cheapest and int(c.get('points_balance') or 0)>=int(cheapest))
                    almost=bool(c['loyalty_type']=='stamps' and int(c.get('progress') or 0)==max(0,int(c.get('goal') or 0)-1)) or bool(c['loyalty_type']=='points' and cheapest and 0<int(cheapest)-int(c.get('points_balance') or 0)<=max(1,int(int(cheapest)*.15)))
                    c['segment']=customer_segment(c.get('last_activity'),c.get('created_at'),c.get('visits'),reward_ready,almost)
                    if tiers and c['loyalty_type']=='points':
                        eligible=[t for t in tiers if int(c.get('points_balance') or 0)>=int(t.get('min_points') or 0)]; c['level']=(eligible[-1]['name'] if eligible else 'Inicial')
                    else: c['level']='VIP' if int(c.get('visits') or 0)>=12 else ('Frequente' if int(c.get('visits') or 0)>=5 else 'Inicial')
                    if c['loyalty_type']=='points': c['to_reward']=max(0,int(cheapest or 0)-int(c.get('points_balance') or 0)) if cheapest else None
                    else: c['to_reward']=max(0,int(c.get('goal') or 0)-int(c.get('progress') or 0))
                month=datetime.now(ZoneInfo('America/Sao_Paulo')).month
                birthdays=[c for c in customers if c.get('birth_date') and len(c['birth_date'])>=10 and int(c['birth_date'][5:7])==month]
                birthdays.sort(key=lambda c: (int(c['birth_date'][8:10]), c['name'].lower()))
                return self.send_json({'ok':True,'customers':customers,'birthdays':birthdays,'month':month,'whatsapp_cloud':whatsapp_cloud_configured(whatsapp_config_for_client(conn,s['campaign_id'])),'whatsapp_configured':whatsapp_cloud_configured(whatsapp_config_for_client(conn,s['campaign_id'])),'email_configured':email_configured(email_config_for_client(conn,s['campaign_id']))})

        if path == '/api/card/rewards':
            public_id=(qs.get('id') or [''])[0].strip()
            with connect(DB_PATH) as conn:
                m=conn.execute("SELECT m.id,m.public_id,m.points_balance,c.id campaign_id,c.name campaign_name,c.loyalty_type FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.public_id=?",(public_id,)).fetchone()
                if not m:return self.send_json({'ok':False,'error':'card_not_found'},404)
                rewards=[rowdict(r) for r in conn.execute("SELECT id,name,description,points_cost,image_data,active,stock,starts_at,ends_at FROM reward_catalog WHERE campaign_id=? AND active=1 ORDER BY points_cost,name",(m['campaign_id'],)).fetchall()]
                return self.send_json({'ok':True,'loyalty_type':m['loyalty_type'],'points_balance':m['points_balance'],'campaign_name':m['campaign_name'],'rewards':rewards})
        if path == '/api/attendant/rewards':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                c=conn.execute("SELECT id,name,loyalty_type,points_spend_cents FROM campaigns WHERE id=? AND company_id=?",(sess['campaign_id'],sess['company_id'])).fetchone()
                if not c:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                rewards=[rowdict(r) for r in conn.execute("SELECT id,name,description,points_cost,image_data,active,stock,starts_at,ends_at FROM reward_catalog WHERE campaign_id=? AND active=1 ORDER BY points_cost,name",(sess['campaign_id'],)).fetchall()]
                return self.send_json({'ok':True,'campaign':rowdict(c),'rewards':rewards})
        if path == '/api/admin/rewards':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                rewards=[rowdict(r) for r in conn.execute("SELECT id,name,description,points_cost,image_data,active,stock,starts_at,ends_at,created_at,updated_at FROM reward_catalog WHERE campaign_id=? ORDER BY active DESC,points_cost,name",(sess['campaign_id'],)).fetchall()]
                c=conn.execute("SELECT loyalty_type,points_spend_cents FROM campaigns WHERE id=?",(sess['campaign_id'],)).fetchone()
                return self.send_json({'ok':True,'campaign':rowdict(c) if c else {},'rewards':rewards})

        if path == '/api/attendant/messages':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['campaign_id']:return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                rows=[rowdict(r) for r in conn.execute("SELECT id,kind,recipient,status,attempts,last_error,created_at,sent_at,available_at FROM message_queue WHERE campaign_id=? ORDER BY id DESC LIMIT 30",(sess['campaign_id'],)).fetchall()]
                return self.send_json({'ok':True,'messages':rows})
        if path == '/api/admin/branches':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                rows=[rowdict(r) for r in conn.execute("""SELECT b.id,b.name,b.code,b.active,b.created_at,
                    (SELECT COUNT(*) FROM users u WHERE u.branch_id=b.id AND u.campaign_id=b.campaign_id AND u.role='attendant' AND u.active=1) staff_count,
                    (SELECT COUNT(*) FROM transactions t JOIN memberships m ON m.id=t.membership_id LEFT JOIN users ux ON ux.id=t.user_id WHERE m.campaign_id=b.campaign_id AND COALESCE(t.branch_id,ux.branch_id)=b.id) operations_count
                    FROM branches b WHERE b.campaign_id=? ORDER BY b.active DESC,b.name""",(sess['campaign_id'],)).fetchall()]
                me=conn.execute('SELECT branch_id FROM users WHERE id=?',(sess['user_id'],)).fetchone()
                return self.send_json({'ok':True,'branches':rows,'current_branch_id':me['branch_id'] if me else None})
        if path == '/api/admin/audit-center':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                action=(qs.get('action') or [''])[0].strip(); user_id=(qs.get('user_id') or [''])[0].strip(); branch_id=(qs.get('branch_id') or [''])[0].strip()
                params=[sess['company_id']]; where=['a.company_id=?']
                if action: where.append('a.action=?'); params.append(action)
                if user_id:
                    try: uid=int(user_id)
                    except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_user'},400)
                    where.append('a.user_id=?'); params.append(uid)
                if branch_id:
                    try: bid=int(branch_id)
                    except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_branch'},400)
                    owned=conn.execute('SELECT id FROM branches WHERE id=? AND campaign_id=?',(bid,sess['campaign_id'])).fetchone()
                    if not owned:return self.send_json({'ok':False,'error':'branch_not_found'},404)
                    where.append('COALESCE(a.branch_id,u.branch_id)=?'); params.append(bid)
                rows=[rowdict(r) for r in conn.execute('SELECT a.*,u.name user_name,COALESCE(b.name,\'Sem unidade\') branch_name,b.code branch_code FROM audit_log a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN branches b ON b.id=COALESCE(a.branch_id,u.branch_id) WHERE '+ ' AND '.join(where)+' ORDER BY a.id DESC LIMIT 250',tuple(params)).fetchall()]
                users=[rowdict(r) for r in conn.execute("SELECT u.id,u.name,u.email,u.branch_id,b.name branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id WHERE u.company_id=? AND u.active=1 AND (u.campaign_id=? OR u.id=?) ORDER BY u.name,u.email",(sess['company_id'],sess['campaign_id'],sess['user_id'])).fetchall()]
                actions=[r['action'] for r in conn.execute('SELECT DISTINCT action FROM audit_log WHERE company_id=? ORDER BY action',(sess['company_id'],)).fetchall()]
                branches=[rowdict(r) for r in conn.execute('SELECT id,name,code FROM branches WHERE campaign_id=? AND active=1 ORDER BY name',(sess['campaign_id'],)).fetchall()]
                return self.send_json({'ok':True,'audit':rows,'users':users,'actions':actions,'branches':branches})
        if path == '/api/admin/commercial-report':
            with connect(DB_PATH) as conn:
                sess=self._require_auth(conn,'attendant')
                if not sess:return
                if not sess['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                cid=sess['campaign_id']
                top_rewards=[rowdict(r) for r in conn.execute("SELECT COALESCE(rc.name,'Recompensa') name,COUNT(*) total FROM reward_redemptions rr LEFT JOIN reward_catalog rc ON rc.id=rr.reward_id JOIN memberships m ON m.id=rr.membership_id WHERE m.campaign_id=? GROUP BY rc.name ORDER BY total DESC LIMIT 10",(cid,)).fetchall()]
                by_staff=[rowdict(r) for r in conn.execute("""SELECT COALESCE(u.name,'Sistema') name,COALESCE(b.name,'Sem unidade') branch_name,COUNT(*) operations
                    FROM transactions t JOIN memberships m ON m.id=t.membership_id LEFT JOIN users u ON u.id=t.user_id LEFT JOIN branches b ON b.id=COALESCE(t.branch_id,u.branch_id)
                    WHERE m.campaign_id=? GROUP BY u.name,b.name ORDER BY operations DESC LIMIT 30""",(cid,)).fetchall()]
                by_branch=[rowdict(r) for r in conn.execute("""SELECT COALESCE(b.name,'Sem unidade') name,COALESCE(b.code,'—') code,COUNT(*) operations,COUNT(DISTINCT t.user_id) staff_count,COUNT(DISTINCT t.membership_id) customers
                    FROM transactions t JOIN memberships m ON m.id=t.membership_id LEFT JOIN users u ON u.id=t.user_id LEFT JOIN branches b ON b.id=COALESCE(t.branch_id,u.branch_id)
                    WHERE m.campaign_id=? GROUP BY b.id,b.name,b.code ORDER BY operations DESC""",(cid,)).fetchall()]
                return self.send_json({'ok':True,'top_rewards':top_rewards,'by_staff':by_staff,'by_branch':by_branch})
        if path == '/api/attendant/lookup':
            token,token_error=resolve_member_token((qs.get('token') or [''])[0])
            if token_error:return self.send_json({'ok':False,'error':token_error},410 if token_error=='qr_expired' else 400)
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn,'attendant')
                if not s: return
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                m=conn.execute('''SELECT m.*,cu.name customer_name,c.name campaign_name,c.reward_name,c.goal,c.icon,c.logo_image,c.company_id,c.loyalty_type,c.points_spend_cents
                  FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?''',(token,token,s['company_id'],s['campaign_id'])).fetchone()
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                return self.send_json({'ok':True,'membership':rowdict(m)})
        return self.send_text('Not found',404,'text/plain')

    def do_DELETE(self):
        p=urllib.parse.urlparse(self.path); path=p.path
        if path.startswith('/api/apple-wallet/v1/devices/') and '/registrations/' in path:
            parts=path.split('/'); device=parts[5] if len(parts)>5 else ''; public_id=urllib.parse.unquote(parts[-1]); auth=(self.headers.get('Authorization') or '').replace('ApplePass ','').strip()
            if not hmac.compare_digest(auth,apple_auth_token(public_id)):return self.send_json({'ok':False,'error':'unauthorized'},401)
            with connect(DB_PATH) as conn:
                m=conn.execute('SELECT id FROM memberships WHERE public_id=?',(public_id,)).fetchone()
                if m:conn.execute('DELETE FROM wallet_registrations WHERE membership_id=? AND device_library_id=?',(m['id'],device))
            return self.send_json({'ok':True})
        return self.send_json({'ok':False,'error':'not_found'},404)

    def do_POST(self):
        p=urllib.parse.urlparse(self.path); path=p.path
        print(f'[FORM] POST {path} ip={self._ip()} content_type={self.headers.get("Content-Type", "")}')
        try: payload, payload_kind=self._body_payload()
        except Exception:
            if path in ['/login','/join']:
                return self.send_redirect('/login?error=1' if path == '/login' else '/join?error=1')
            return self.send_json({'ok':False,'error':'invalid_json'},400)
        if path=='/api/public/contact':
            # Formulário comercial público da landing page. O campo `website` é
            # um honeypot simples para bots; para visitantes reais fica vazio.
            if str(payload.get('website') or '').strip():
                return self.send_json({'ok':True})
            name=str(payload.get('name') or '').strip()[:120]
            company=str(payload.get('company') or '').strip()[:160]
            email=str(payload.get('email') or '').strip().lower()[:180]
            phone=str(payload.get('phone') or '').strip()[:40]
            segment=str(payload.get('segment') or '').strip()[:100]
            interest=str(payload.get('interest') or '').strip()[:80]
            message=str(payload.get('message') or '').strip()[:3000]
            consent=bool(payload.get('consent'))
            if not name or not company or not email or not phone or not segment or not interest or not consent:
                return self.send_json({'ok':False,'error':'required_fields'},400)
            if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email):
                return self.send_json({'ok':False,'error':'invalid_email'},400)
            cfg=global_email_config()
            print(f'[CONTACT] EMAIL_CONFIG provider={cfg.get("provider") or "auto"} source={cfg.get("source") or "unknown"} configured={email_configured(cfg)} sender={bool(cfg.get("sender_email") or cfg.get("from_addr"))}')
            if not email_configured(cfg):
                print('[CONTACT] EMAIL_NOT_CONFIGURED')
                return self.send_json({'ok':False,'error':'email_not_configured'},503)
            msg=EmailMessage()
            msg['Subject']=f'Novo contato Fidelizaê! • {company}'
            msg['To']='gustavo@agenciataboo.com.br'
            msg['Reply-To']=email
            msg.set_content(
                'Novo contato recebido pelo site do Fidelizaê!\n\n'
                f'Nome: {name}\nEmpresa: {company}\nE-mail: {email}\nWhatsApp/Celular: {phone}\n'
                f'Segmento: {segment}\nInteresse: {interest}\n\nMensagem:\n{message or "Não informada."}\n'
            )
            result=send_email_message(msg,cfg)
            if not result.get('sent'):
                print(f'[CONTACT] SEND_FAILED email={email} reason={result.get("reason")} status={result.get("status")} source={result.get("source")}')
                return self.send_json({'ok':False,'error':'send_failed'},502)
            print(f'[CONTACT] SENT company={company!r} email={email}')
            return self.send_json({'ok':True})
        mweb=re.fullmatch(r'/api/integrations/ecommerce/(\d+)/([^/]+)',path)
        if mweb:
            campaign_id=int(mweb.group(1)); supplied_secret=mweb.group(2)
            with connect(DB_PATH) as conn:
                c=rowdict(conn.execute('SELECT * FROM campaigns WHERE id=? AND active=1',(campaign_id,)).fetchone())
                if not c or normalize_ecommerce_platform(c.get('ecommerce_platform'))=='none':return self.send_json({'ok':False,'error':'ecommerce_not_configured'},404)
                expected=str(c.get('ecommerce_webhook_secret') or '')
                if not expected or not hmac.compare_digest(expected,supplied_secret):return self.send_json({'ok':False,'error':'invalid_webhook_secret'},403)
                platform=normalize_ecommerce_platform(c.get('ecommerce_platform')); adapted=platform_order(payload,platform); info=ecommerce_extract(adapted,platform)
                if not info['order_id']:return self.send_json({'ok':False,'error':'order_id_required'},400)
                paid_states={'paid','approved','completed','processing','authorized'}
                reversed_states={'refunded','cancelled','canceled','voided','reversed','chargeback'}
                if info['status'] not in paid_states|reversed_states:return self.send_json({'ok':True,'ignored':True,'reason':'status_not_final','status':info['status']})
                existing=rowdict(conn.execute('SELECT * FROM ecommerce_orders WHERE campaign_id=? AND platform=? AND order_id=?',(campaign_id,platform,info['order_id'])).fetchone())
                if info['status'] in paid_states:
                    if existing and existing.get('processed_at') and not existing.get('reversed_at'):
                        return self.send_json({'ok':True,'duplicate':True,'order_id':info['order_id']})
                    member=ecommerce_find_membership(conn,campaign_id,info)
                    customer_ref=info.get('cpf') or info.get('email') or info.get('phone') or ''
                    if not member:
                        if existing: conn.execute('UPDATE ecommerce_orders SET order_status=?,customer_ref=?,total_cents=?,updated_at=? WHERE id=?',(info['status'],customer_ref,info['total_cents'],now_ts(),existing['id']))
                        else: conn.execute('INSERT INTO ecommerce_orders(campaign_id,platform,order_id,order_status,customer_ref,total_cents,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(campaign_id,platform,info['order_id'],info['status'],customer_ref,info['total_cents'],now_ts(),now_ts()))
                        audit(conn,c['company_id'],None,'ecommerce_customer_not_found','campaign',campaign_id,details=f'{platform};pedido={info["order_id"]};cliente={customer_ref}',ip_address=self._ip())
                        return self.send_json({'ok':False,'error':'customer_not_found','message':'O pedido foi recebido, mas o cliente ainda não possui cartão neste programa.'},409)
                    event_ts=now_ts()
                    if c['loyalty_type']=='points':
                        rate=max(1,int(c['points_spend_cents'] or 200)); base_reward=info['total_cents']//rate; factor=active_multiplier(conn,campaign_id,event_ts); reward=int(base_reward*factor)
                        if reward<1:return self.send_json({'ok':True,'ignored':True,'reason':'purchase_below_point_rule'})
                        prev=int(member['points_balance'] or 0); new=prev+reward
                        tx_id=insert_id(conn,"INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(member['id'],None,None,'adjustment',reward,prev,new,0,f'ecom:{campaign_id}:{platform}:{info["order_id"]}',self._ip(),f'{platform} • Pedido {info["order_id"]} • R$ {info["total_cents"]/100:.2f} • {factor:g}x',event_ts))
                        conn.execute('UPDATE memberships SET points_balance=? WHERE id=?',(new,member['id']))
                        add_point_lot(conn,member['id'],tx_id,reward,int(c.get('points_expiry_days') or 180),event_ts)
                    else:
                        reward=1; prev=int(member['progress'] or 0); goal=max(1,int(c['goal'] or 5)); new=prev+1; rewards_delta=0
                        if new>=goal:new=0;rewards_delta=1
                        tx_id=insert_id(conn,"INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(member['id'],None,None,'stamp',1,prev,new,rewards_delta,f'ecom:{campaign_id}:{platform}:{info["order_id"]}',self._ip(),f'{platform} • Pedido {info["order_id"]} • R$ {info["total_cents"]/100:.2f}',event_ts))
                        conn.execute('UPDATE memberships SET progress=?,rewards_available=rewards_available+? WHERE id=?',(new,rewards_delta,member['id']))
                    record_purchase(conn,member['id'],tx_id,info['total_cents'],platform,event_ts)
                    if existing: conn.execute('UPDATE ecommerce_orders SET order_status=?,customer_ref=?,total_cents=?,reward_value=?,transaction_id=?,processed_at=?,reversed_at=NULL,reversal_transaction_id=NULL,updated_at=? WHERE id=?',(info['status'],customer_ref,info['total_cents'],reward,tx_id,now_ts(),now_ts(),existing['id']))
                    else: conn.execute('INSERT INTO ecommerce_orders(campaign_id,platform,order_id,order_status,customer_ref,total_cents,reward_value,transaction_id,processed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(campaign_id,platform,info['order_id'],info['status'],customer_ref,info['total_cents'],reward,tx_id,now_ts(),now_ts(),now_ts()))
                    conn.execute("UPDATE campaigns SET ecommerce_status='connected',ecommerce_connected_at=COALESCE(ecommerce_connected_at,?) WHERE id=?",(now_iso(),campaign_id))
                    audit(conn,c['company_id'],None,'ecommerce_reward','membership',member['public_id'],details=f'{platform};pedido={info["order_id"]};valor={info["total_cents"]};recompensa={reward}',ip_address=self._ip()); notify_wallet_updates(conn,member['public_id'])
                    return self.send_json({'ok':True,'order_id':info['order_id'],'customer_name':member['customer_name'],'reward':reward,'loyalty_type':c['loyalty_type']})
                if not existing or not existing.get('processed_at') or existing.get('reversed_at'): return self.send_json({'ok':True,'ignored':True,'reason':'nothing_to_reverse'})
                tx=conn.execute('SELECT * FROM transactions WHERE id=?',(existing['transaction_id'],)).fetchone()
                if not tx:return self.send_json({'ok':False,'error':'original_transaction_not_found'},409)
                member=fetchone_for_update(conn,'SELECT * FROM memberships WHERE id=?',(tx['membership_id'],)); reward=max(0,int(existing['reward_value'] or 0))
                if c['loyalty_type']=='points':
                    prev=int(member['points_balance'] or 0); reversed_points=min(prev,reward); new=max(0,prev-reversed_points)
                    consume_point_lots(conn,member['id'],reversed_points)
                    rtx=insert_id(conn,"INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(member['id'],None,None,'adjustment',-reversed_points,prev,new,0,f'ecom-refund:{campaign_id}:{platform}:{info["order_id"]}',self._ip(),f'Estorno {platform} • Pedido {info["order_id"]}',now_ts()))
                    conn.execute('UPDATE memberships SET points_balance=? WHERE id=?',(new,member['id']))
                else:
                    prev=int(member['progress'] or 0); goal=max(1,int(c['goal'] or 5)); rewards_available=int(member['rewards_available'] or 0); new=prev-1; rd=0
                    if new<0:
                        new=goal-1
                        if rewards_available>0: rd=-1
                    rtx=insert_id(conn,"INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(member['id'],None,None,'adjustment',-1,prev,new,rd,f'ecom-refund:{campaign_id}:{platform}:{info["order_id"]}',self._ip(),f'Estorno {platform} • Pedido {info["order_id"]}',now_ts()))
                    new_rewards=max(0,rewards_available+rd); conn.execute('UPDATE memberships SET progress=?,rewards_available=? WHERE id=?',(new,new_rewards,member['id']))
                conn.execute('UPDATE ecommerce_orders SET order_status=?,reversal_transaction_id=?,reversed_at=?,updated_at=? WHERE id=?',(info['status'],rtx,now_ts(),now_ts(),existing['id']))
                audit(conn,c['company_id'],None,'ecommerce_reward_reversed','membership',member['public_id'],details=f'{platform};pedido={info["order_id"]};recompensa=-{reward}',ip_address=self._ip()); notify_wallet_updates(conn,member['public_id'])
                return self.send_json({'ok':True,'reversed':True,'order_id':info['order_id'],'reward_reversed':reward,'loyalty_type':c['loyalty_type']})

        if path in ['/api/login','/login']:
            if not self._rate_ok('login',10,300): return
            email=str(payload.get('email','')).lower().strip(); password=str(payload.get('password','')).strip()
            with connect(DB_PATH) as conn:
                u=conn.execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
                password_ok = bool(u) and verify_password(password,u['password_hash'])
                # O administrador configurado no Railway é a identidade reservada do Painel Taboo.
                # Se a senha digitada coincidir com CLUBE_ADMIN_PASSWORD, o perfil é restaurado para
                # manager mesmo que o banco tenha ficado legado/inconsistente como attendant.
                admin_email=os.environ.get('CLUBE_ADMIN_EMAIL','').strip().lower()
                admin_password=os.environ.get('CLUBE_ADMIN_PASSWORD','').strip()
                admin_login = bool(u and admin_email and admin_password and email == admin_email and hmac.compare_digest(password,admin_password))
                if admin_login:
                    needs_repair = (u['role'] != 'manager') or (not password_ok) or (u['campaign_id'] is not None)
                    if needs_repair:
                        conn.execute("UPDATE users SET password_hash=?,role='manager',campaign_id=NULL,active=1 WHERE id=?",(hash_password(admin_password),u['id']))
                        u=conn.execute('SELECT * FROM users WHERE id=?',(u['id'],)).fetchone()
                        print(f'[AUTH] ADMIN_LOGIN_REPAIRED email={email} previous_role_repaired=True')
                    password_ok=True
                if not u or not password_ok:
                    print(f'[AUTH] LOGIN_FAILED email={email} user_found={bool(u)} password_length={len(password)}')
                    audit(conn,u['company_id'] if u else None,u['id'] if u else None,'login_failed',details=email,ip_address=self._ip())
                    if path == '/login':
                        return self.send_redirect('/login?error=1')
                    return self.send_json({'ok':False,'error':'invalid_credentials'},401)
                token,csrf=create_session(conn,u['id']); audit(conn,u['company_id'],u['id'],'login_success',ip_address=self._ip())
                print(f'[AUTH] LOGIN_SUCCESS email={email} role={u["role"]}')
                cookie=f'{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800'
                if os.environ.get('CLUBE_SECURE_COOKIE', '1' if str(DB_PATH).startswith(('postgres://','postgresql://')) else '0')=='1': cookie+='; Secure'
                if path == '/login':
                    return self.send_redirect('/manager' if u['role']=='manager' else '/attendant',303,{'Set-Cookie':cookie})
                return self.send_json({'ok':True,'role':u['role'],'csrf':csrf},200,{'Set-Cookie':cookie})
        if path == '/api/logout':
            with connect(DB_PATH) as conn:
                token=self._session_token(); s=self._session(conn)
                if token: conn.execute('DELETE FROM sessions WHERE token=?',(token,))
                if s: audit(conn,s['company_id'],s['user_id'],'logout',ip_address=self._ip())
            return self.send_json({'ok':True},200,{'Set-Cookie':f'{SESSION_COOKIE}=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Strict'})
        if path in ['/api/join','/join']:
            if not RATE_LIMITER.allow(f'join:{self._ip()}',12,600):
                return self.send_redirect('/join?campaign='+urllib.parse.quote(str(payload.get('campaign_code','') or 'CAFE5'))+'&error=rate_limited') if path=='/join' else self.send_json({'ok':False,'error':'rate_limited'},429)
            code=str(payload.get('campaign_code','')).upper().strip()
            name=str(payload.get('name','')).strip()[:80]
            email=normalize_email(payload.get('email'))
            phone=normalize_phone(payload.get('phone'))
            birth_date=normalize_birth_date(payload.get('birth_date'))
            cpf=normalize_cpf(payload.get('cpf')); privacy_ok=str(payload.get('privacy_consent','')).lower() in ('1','true','on','yes'); marketing_email=str(payload.get('marketing_email','')).lower() in ('1','true','on','yes'); marketing_whatsapp=str(payload.get('marketing_whatsapp','')).lower() in ('1','true','on','yes')
            if len(name)<2 or not email or not phone or not birth_date or not cpf or not privacy_ok:
                error='invalid_customer_data'
                if len(name)<2: error='invalid_name'
                elif not email: error='invalid_email'
                elif not phone: error='invalid_phone'
                elif not birth_date: error='invalid_birth_date'
                elif not cpf: error='invalid_cpf'
                elif not privacy_ok: error='privacy_consent_required'
                return self.send_redirect('/join?campaign='+urllib.parse.quote(code or 'CAFE5')+'&error='+urllib.parse.quote(error)) if path=='/join' else self.send_json({'ok':False,'error':error},400)
            with connect(DB_PATH) as conn:
                c=conn.execute('SELECT * FROM campaigns WHERE code=? AND active=1',(code,)).fetchone()
                if not c:
                    return self.send_redirect('/join?campaign='+urllib.parse.quote(code or 'CAFE5')+'&error=campaign_not_found') if path=='/join' else self.send_json({'ok':False,'error':'campaign_not_found'},404)
                existing_customer=conn.execute('''SELECT cu.id FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                    WHERE m.campaign_id=? AND cu.cpf=? LIMIT 1''',(c['id'],cpf)).fetchone()
                customer_id=existing_customer['id'] if existing_customer else None
                duplicate_contact=conn.execute('''SELECT cu.id,cu.cpf FROM customers cu JOIN memberships m ON m.customer_id=cu.id WHERE m.campaign_id=? AND (lower(cu.email)=lower(?) OR cu.phone=?) AND cu.cpf<>? LIMIT 1''',(c['id'],email,phone,cpf)).fetchone()
                if duplicate_contact:
                    return self.send_redirect('/join?campaign='+urllib.parse.quote(code)+'&error=duplicate_contact') if path=='/join' else self.send_json({'ok':False,'error':'duplicate_contact'},409)
                if customer_id is None:
                    customer_id=insert_id(conn,'INSERT INTO customers(name,contact,email,phone,birth_date,cpf,privacy_accepted_at,marketing_email,marketing_whatsapp,marketing_accepted_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                        (name,email,email,phone,birth_date,cpf,now_ts(),1 if marketing_email else 0,1 if marketing_whatsapp else 0,now_ts() if (marketing_email or marketing_whatsapp) else None,now_ts()))
                else:
                    conn.execute('UPDATE customers SET name=?,contact=?,email=?,phone=?,birth_date=?,cpf=?,privacy_accepted_at=COALESCE(privacy_accepted_at,?),marketing_email=?,marketing_whatsapp=?,marketing_accepted_at=? WHERE id=?',
                        (name,email,email,phone,birth_date,cpf,now_ts(),1 if marketing_email else 0,1 if marketing_whatsapp else 0,now_ts() if (marketing_email or marketing_whatsapp) else None,customer_id))
                existing=conn.execute('SELECT public_id FROM memberships WHERE customer_id=? AND campaign_id=?',(customer_id,c['id'])).fetchone()
                if existing:
                    return self.send_redirect('/card?id='+urllib.parse.quote(existing['public_id'])) if path=='/join' else self.send_json({'ok':True,'public_id':existing['public_id'],'existing':True})
                public_id='mem_'+random_token(10); qr_token=random_token(24)
                conn.execute('INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)',(customer_id,c['id'],public_id,qr_token,now_ts()))
                print(f'[JOIN] CREATED public_id={public_id} campaign={code} name={name!r}')
                audit(conn,c['company_id'],None,'customer_join','membership',public_id,details=name,ip_address=self._ip())
                welcome_result={'queued':False,'skipped':True,'reason':'email_provider_not_configured'}
                if email_configured(email_config_for_client(conn,c['id'])):
                    qid=enqueue_message(conn,c['id'],'customer_welcome',email,{'name':name,'email':email,'public_id':public_id}); welcome_result={'queued':True,'queue_id':qid}
                    audit(conn,c['company_id'],None,'customer_welcome_queued','membership',public_id,details=email,ip_address=self._ip())
                return self.send_redirect('/card?id='+urllib.parse.quote(public_id)) if path=='/join' else self.send_json({'ok':True,'public_id':public_id,'existing':False,'welcome_email':welcome_result})
        if path == '/api/forgot-password':
            if not self._rate_ok('forgot-password',5,900): return
            email=normalize_email(payload.get('email'))
            if not email:
                return self.send_json({'ok':False,'error':'invalid_email'},400)
            with connect(DB_PATH) as conn:
                u=conn.execute("SELECT id,company_id,email,role,active,campaign_id FROM users WHERE email=? AND active=1",(email,)).fetchone()
                # Não revelamos se o endereço existe. A redefinição usa token único de 30 minutos.
                if u and u['role']=='attendant':
                    raw=random_token(32); token_hash=hashlib.sha256(raw.encode()).hexdigest(); ts=now_ts()
                    smtp_cfg=global_email_config()
                    if not email_configured(smtp_cfg): return self.send_json({'ok':False,'error':'email_provider_not_configured'},503)
                    conn.execute('DELETE FROM password_reset_tokens WHERE user_id=? OR expires_at<?',(u['id'],ts))
                    conn.execute('INSERT INTO password_reset_tokens(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)',(token_hash,u['id'],ts+1800,ts))
                    qid=enqueue_message(conn,None,'password_recovery',email,{'token':raw,'user_id':u['id']})
                    audit(conn,u['company_id'],u['id'],'password_recovery_queued','user',u['id'],details=f'queue={qid}',ip_address=self._ip())
                return self.send_json({'ok':True,'message':'Se o e-mail estiver cadastrado, enviaremos um link de redefinição.'})

        if path == '/api/reset-password':
            if not self._rate_ok('reset-password',6,900): return
            token=str(payload.get('token') or ''); password=str(payload.get('password') or '').strip()
            if len(password)<10:return self.send_json({'ok':False,'error':'invalid_new_password'},400)
            th=hashlib.sha256(token.encode()).hexdigest()
            with connect(DB_PATH) as conn:
                r=conn.execute('SELECT * FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>=?',(th,now_ts())).fetchone()
                if not r:return self.send_json({'ok':False,'error':'reset_token_invalid'},400)
                conn.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(password),r['user_id'])); conn.execute('UPDATE password_reset_tokens SET used_at=? WHERE token_hash=?',(now_ts(),th)); conn.execute('DELETE FROM sessions WHERE user_id=?',(r['user_id'],)); u=conn.execute('SELECT company_id FROM users WHERE id=?',(r['user_id'],)).fetchone(); audit(conn,u['company_id'] if u else None,r['user_id'],'password_change','user',r['user_id'],details='reset_token',ip_address=self._ip())
            return self.send_json({'ok':True})

        if path == '/api/privacy/delete':
            if not self._rate_ok('privacy-delete',5,900): return
            public_id=str(payload.get('id','')).strip(); cpf=normalize_cpf(payload.get('cpf'))
            if not cpf:return self.send_json({'ok':False,'error':'invalid_cpf'},400)
            with connect(DB_PATH) as conn:
                row=conn.execute('''SELECT m.id membership_id,m.customer_id,c.company_id FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.public_id=? AND cu.cpf=?''',(public_id,cpf)).fetchone()
                if not row:return self.send_json({'ok':False,'error':'not_found'},404)
                audit(conn,row['company_id'],None,'lgpd_delete','customer',row['customer_id'],details=public_id,ip_address=self._ip())
                conn.execute('DELETE FROM memberships WHERE id=?',(row['membership_id'],))
                conn.execute('DELETE FROM customers WHERE id=? AND id NOT IN (SELECT customer_id FROM memberships)',(row['customer_id'],))
            return self.send_json({'ok':True})
        if path == '/api/privacy/preferences':
            if not self._rate_ok('privacy-preferences',20,900): return
            public_id=str(payload.get('id','')).strip(); cpf=normalize_cpf(payload.get('cpf'))
            if not cpf:return self.send_json({'ok':False,'error':'invalid_cpf'},400)
            marketing_email=1 if str(payload.get('marketing_email','')).lower() in ('1','true','on','yes') else 0
            marketing_whatsapp=1 if str(payload.get('marketing_whatsapp','')).lower() in ('1','true','on','yes') else 0
            with connect(DB_PATH) as conn:
                row=conn.execute('''SELECT m.customer_id,c.company_id FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.public_id=? AND cu.cpf=?''',(public_id,cpf)).fetchone()
                if not row:return self.send_json({'ok':False,'error':'not_found'},404)
                conn.execute('UPDATE customers SET marketing_email=?,marketing_whatsapp=?,marketing_accepted_at=? WHERE id=?',(marketing_email,marketing_whatsapp,now_ts() if (marketing_email or marketing_whatsapp) else None,row['customer_id']))
                audit(conn,row['company_id'],None,'privacy_preferences','customer',row['customer_id'],details=f'email={marketing_email};whatsapp={marketing_whatsapp}',ip_address=self._ip())
            return self.send_json({'ok':True,'marketing_email':bool(marketing_email),'marketing_whatsapp':bool(marketing_whatsapp)})
        if path == '/api/card/nps':
            if not self._rate_ok('card-nps',8,900): return
            public_id=str(payload.get('id') or '').strip()
            try: score=int(payload.get('score'))
            except (TypeError,ValueError): score=-1
            comment=str(payload.get('comment') or '').strip()[:500]
            if score<0 or score>10:return self.send_json({'ok':False,'error':'invalid_score'},400)
            with connect(DB_PATH) as conn:
                m=conn.execute("SELECT id,campaign_id FROM memberships WHERE public_id=? AND status='active'",(public_id,)).fetchone()
                if not m:return self.send_json({'ok':False,'error':'card_not_found'},404)
                # Só aceita NPS após existir alguma interação real no programa.
                if not conn.execute('SELECT 1 FROM transactions WHERE membership_id=? LIMIT 1',(m['id'],)).fetchone():
                    return self.send_json({'ok':False,'error':'nps_not_due'},409)
                recent=conn.execute('SELECT 1 FROM nps_responses WHERE membership_id=? AND created_at>=? LIMIT 1',(m['id'],now_ts()-90*86400)).fetchone()
                if recent:return self.send_json({'ok':False,'error':'nps_already_answered'},409)
                insert_id(conn,"INSERT INTO nps_responses(campaign_id,membership_id,score,comment,created_at) VALUES(?,?,?,?,?)",(m['campaign_id'],m['id'],score,comment,now_ts()))
            return self.send_json({'ok':True})

        if path == '/api/apple-wallet/v1/log':
            # Apple may post diagnostic messages from Wallet; do not require app session/CSRF.
            return self.send_json({'ok':True})
        if path.startswith('/api/apple-wallet/v1/devices/') and '/registrations/' in path:
            parts=path.split('/'); device=urllib.parse.unquote(parts[5]) if len(parts)>5 else ''; public_id=urllib.parse.unquote(parts[-1])
            auth=(self.headers.get('Authorization') or '').replace('ApplePass ','').strip()
            if not hmac.compare_digest(auth,apple_auth_token(public_id)):return self.send_json({'ok':False,'error':'unauthorized'},401)
            push=str(payload.get('pushToken','')).strip()
            if not device or not push:return self.send_json({'ok':False,'error':'invalid_registration'},400)
            with connect(DB_PATH) as conn:
                m=conn.execute('SELECT id FROM memberships WHERE public_id=?',(public_id,)).fetchone()
                if not m:return self.send_json({'ok':False,'error':'invalid_registration'},400)
                try: conn.execute('INSERT INTO wallet_registrations(membership_id,device_library_id,push_token,created_at) VALUES(?,?,?,?)',(m['id'],device,push,now_ts()))
                except integrity_errors(): conn.execute('UPDATE wallet_registrations SET push_token=?,created_at=? WHERE membership_id=? AND device_library_id=?',(push,now_ts(),m['id'],device))
            return self.send_json({'ok':True},201)

        with connect(DB_PATH) as conn:
            s=self._require_auth(conn)
            if not s: return
            if not self._require_csrf(s,payload): return self.send_json({'ok':False,'error':'csrf_failed'},403)
            if path == '/api/admin/loyalty360/settings':
                s=self._require_auth(conn,'attendant')
                if not s:return
                if not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                campaign=conn.execute("SELECT loyalty_type FROM campaigns WHERE id=? AND company_id=?",(s['campaign_id'],s['company_id'])).fetchone()
                if not campaign:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                # O tipo principal é definido exclusivamente no Painel Taboo.
                # O administrador da empresa configura apenas recursos avançados do mesmo programa.
                if campaign['loyalty_type']=='points':
                    expiry=int(payload.get('points_expiry_days') or 180)
                    if expiry not in tuple(i*30 for i in range(1,13)): return self.send_json({'ok':False,'error':'invalid_points_expiry'},400)
                    conn.execute("UPDATE campaigns SET points_expiry_days=? WHERE id=?",(expiry,s['campaign_id']))
                return self.send_json({'ok':True,'loyalty_type':campaign['loyalty_type']})
            if path == '/api/admin/loyalty360/tier':
                s=self._require_auth(conn,'attendant');
                if not s:return
                if not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                campaign=conn.execute("SELECT loyalty_type FROM campaigns WHERE id=?",(s['campaign_id'],)).fetchone()
                if not campaign or campaign['loyalty_type']!='points':return self.send_json({'ok':False,'error':'points_program_required'},409)
                name=str(payload.get('name') or '').strip()[:60]; mp=max(0,int(payload.get('min_points') or 0)); benefit=str(payload.get('benefit') or '').strip()[:200]
                if not name:return self.send_json({'ok':False,'error':'invalid_tier'},400)
                insert_id(conn,"INSERT INTO loyalty_tiers(campaign_id,name,min_points,benefit,active,created_at) VALUES(?,?,?,?,1,?)",(s['campaign_id'],name,mp,benefit,now_ts())); return self.send_json({'ok':True})
            if path == '/api/admin/loyalty360/multiplier':
                s=self._require_auth(conn,'attendant');
                if not s:return
                if not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                campaign=conn.execute("SELECT loyalty_type FROM campaigns WHERE id=?",(s['campaign_id'],)).fetchone()
                if not campaign or campaign['loyalty_type']!='points':return self.send_json({'ok':False,'error':'points_program_required'},409)
                name=str(payload.get('name') or '').strip()[:80]; factor=max(1,min(10,float(payload.get('factor') or 1))); weekday=str(payload.get('weekday') or 'all')[:20]
                insert_id(conn,"INSERT INTO point_multipliers(campaign_id,name,factor,weekday,start_hour,end_hour,active,created_at) VALUES(?,?,?,?,?,?,1,?)",(s['campaign_id'],name,factor,weekday,str(payload.get('start_hour') or ''),str(payload.get('end_hour') or ''),now_ts())); return self.send_json({'ok':True})
            if path == '/api/admin/gift-card':
                s=self._require_auth(conn,'attendant');
                if not s:return
                if not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                value=max(100,int(payload.get('value_cents') or 0)); code='VALE-'+secrets.token_hex(4).upper(); purchaser=str(payload.get('purchaser_name') or '').strip()[:100]; beneficiary=str(payload.get('beneficiary_name') or '').strip()[:100]; gid=insert_id(conn,"INSERT INTO gift_cards(campaign_id,code,value_cents,balance_cents,status,purchaser_name,beneficiary_name,created_at) VALUES(?,?,?,?,?,?,?,?)",(s['campaign_id'],code,value,value,'active',purchaser,beneficiary,now_ts())); conn.execute('INSERT INTO gift_card_events(gift_card_id,user_id,event_type,amount_cents,balance_after_cents,note,created_at) VALUES(?,?,?,?,?,?,?)',(gid,s['user_id'],'created',value,value,'Vale criado',now_ts())); return self.send_json({'ok':True,'code':code,'qr_url':'/api/qr?data='+urllib.parse.quote('GIFT:'+code)})

            if path == '/api/admin/gift-card/delete':
                s=self._require_auth(conn,'attendant');
                if not s:return
                if not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                code=str(payload.get('code') or '').strip().upper()
                if not code:return self.send_json({'ok':False,'error':'gift_code_required'},400)
                gift=conn.execute("SELECT id,code FROM gift_cards WHERE campaign_id=? AND upper(code)=upper(?)",(s['campaign_id'],code)).fetchone()
                if not gift:return self.send_json({'ok':False,'error':'gift_not_found'},404)
                conn.execute("DELETE FROM gift_cards WHERE id=? AND campaign_id=?",(gift['id'],s['campaign_id']))
                audit(conn,s['company_id'],s['user_id'],'gift_card_delete','gift_card',gift['id'],details=gift['code'],ip_address=self._ip())
                return self.send_json({'ok':True,'code':gift['code']})

            if path == '/api/attendant/gift-card/redeem':
                if s['role']=='attendant' and not self._need_permission(s,'use_gift'): return
                if s['role']!='attendant' or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                code=str(payload.get('code') or '').strip().upper()
                try: amount=int(payload.get('amount_cents') or 0)
                except: amount=0
                if not code or amount<1:return self.send_json({'ok':False,'error':'invalid_gift_redeem'},400)
                with connect(DB_PATH) as conn2:
                    gift=fetchone_for_update(conn2,"SELECT * FROM gift_cards WHERE campaign_id=? AND upper(code)=upper(?)",(s['campaign_id'],code))
                    if not gift:return self.send_json({'ok':False,'error':'gift_not_found'},404)
                    if gift['status']!='active':return self.send_json({'ok':False,'error':'gift_inactive'},409)
                    balance=int(gift['balance_cents'] or 0)
                    if amount>balance:return self.send_json({'ok':False,'error':'insufficient_gift_balance','balance_cents':balance},409)
                    new_balance=balance-amount; new_status='used' if new_balance==0 else 'active'
                    conn2.execute("UPDATE gift_cards SET balance_cents=?,status=? WHERE id=?",(new_balance,new_status,gift['id'])); conn2.execute('INSERT INTO gift_card_events(gift_card_id,user_id,event_type,amount_cents,balance_after_cents,note,created_at) VALUES(?,?,?,?,?,?,?)',(gift['id'],s['user_id'],'redeem',amount,new_balance,'Uso do vale',now_ts()))
                    audit(conn2,s['company_id'],s['user_id'],'gift_card_redeem','gift_card',gift['id'],details=f'{code};R${amount/100:.2f};saldo=R${new_balance/100:.2f}',ip_address=self._ip())
                return self.send_json({'ok':True,'code':code,'amount_cents':amount,'balance_cents':new_balance,'status':new_status})

            if path == '/api/admin/marketing-campaign/save':
                if s['role']!='attendant' or not s['is_client_admin'] or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:100]; segment=str(payload.get('segment','all')); channel=str(payload.get('channel','both')); message=str(payload.get('message','')).strip()[:4096]
                if len(name)<2 or not message or segment not in ('all','new','active','vip','at_risk','inactive60','inactive90','almost_reward','reward_ready','birthdays') or channel not in ('email','whatsapp','both'):return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                mid=insert_id(conn,'INSERT INTO marketing_campaigns(campaign_id,name,segment,channel,message,status,created_at) VALUES(?,?,?,?,?,?,?)',(s['campaign_id'],name,segment,channel,message,'draft',now_ts()))
                audit(conn,s['company_id'],s['user_id'],'marketing_campaign_create','marketing_campaign',mid,details=name,ip_address=self._ip())
                return self.send_json({'ok':True,'id':mid})
            if path == '/api/admin/marketing-campaign/send':
                if s['role']!='attendant' or not s['is_client_admin'] or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                mid=int(payload.get('id') or 0); mc=conn.execute('SELECT * FROM marketing_campaigns WHERE id=? AND campaign_id=?',(mid,s['campaign_id'])).fetchone()
                if not mc:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                if mc['status']=='sent':return self.send_json({'ok':False,'error':'already_sent'},409)
                rows=campaign_recipient_rows(conn,s['campaign_id'],mc['segment']); queued=0; sent_at=now_ts()
                for r in rows:
                    q=False
                    if mc['channel'] in ('email','both') and r['email'] and r['marketing_email'] and email_configured(email_config_for_client(conn,s['campaign_id'])):
                        enqueue_message(conn,s['campaign_id'],'campaign_email',r['email'],{'name':r['name'],'message':mc['message'],'subject':'Fidelizaê! • '+mc['name']}); q=True
                    if mc['channel'] in ('whatsapp','both') and r['phone'] and r['marketing_whatsapp'] and whatsapp_cloud_configured(whatsapp_config_for_client(conn,s['campaign_id'])):
                        enqueue_message(conn,s['campaign_id'],'whatsapp',r['phone'],{'message':mc['message']}); q=True
                    if q:
                        cur=conn.execute('INSERT INTO marketing_campaign_recipients(marketing_campaign_id,membership_id,sent_at) VALUES(?,?,?) ON CONFLICT(marketing_campaign_id,membership_id) DO NOTHING',(mid,r['membership_id'],sent_at))
                        # O contador representa destinatários efetivamente novos.
                        if getattr(cur,'rowcount',0)>0: queued+=1
                conn.execute("UPDATE marketing_campaigns SET status='sent',sent_at=? WHERE id=?",(sent_at,mid)); audit(conn,s['company_id'],s['user_id'],'marketing_campaign_send','marketing_campaign',mid,details=f'queued={queued}',ip_address=self._ip())
                return self.send_json({'ok':True,'queued':queued})
            if path == '/api/admin/coupon/save':
                if s['role']!='attendant' or not s['is_client_admin'] or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:100]; code=re.sub(r'[^A-Z0-9_-]','',str(payload.get('code','')).upper())[:30]; typ=str(payload.get('benefit_type','percent')); segment=str(payload.get('segment','all'))
                try: val=int(payload.get('benefit_value') or 0); limit=int(payload.get('usage_limit') or 0); starts=int(payload.get('starts_at') or 0) or None; ends=int(payload.get('ends_at') or 0) or None
                except: return self.send_json({'ok':False,'error':'invalid_coupon'},400)
                if len(name)<2 or len(code)<3 or typ not in ('percent','fixed','bonus_points','bonus_stamps') or val<=0:return self.send_json({'ok':False,'error':'invalid_coupon'},400)
                try: cid=insert_id(conn,'INSERT INTO coupons(campaign_id,name,code,benefit_type,benefit_value,segment,starts_at,ends_at,usage_limit,active,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(s['campaign_id'],name,code,typ,val,segment,starts,ends,limit,1,now_ts()))
                except integrity_errors():return self.send_json({'ok':False,'error':'coupon_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'coupon_create','coupon',cid,details=code,ip_address=self._ip());return self.send_json({'ok':True,'id':cid})
            if path == '/api/admin/coupon/toggle':
                if s['role']!='attendant' or not s['is_client_admin'] or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                conn.execute('UPDATE coupons SET active=? WHERE id=? AND campaign_id=?',(1 if payload.get('active') else 0,int(payload.get('id') or 0),s['campaign_id']));return self.send_json({'ok':True})
            if path == '/api/attendant/coupon/apply':
                if s['role']!='attendant' or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                code=str(payload.get('code','')).strip().upper(); public_id=str(payload.get('public_id','')).strip(); now=now_ts(); purchase_cents=max(0,int(payload.get('purchase_cents') or 0))
                m=conn.execute('SELECT m.*,c.loyalty_type,c.goal FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.public_id=? AND m.campaign_id=?',(public_id,s['campaign_id'])).fetchone(); cup=conn.execute('SELECT * FROM coupons WHERE campaign_id=? AND upper(code)=upper(?) AND active=1',(s['campaign_id'],code)).fetchone()
                if not m or not cup:return self.send_json({'ok':False,'error':'coupon_not_found'},404)
                if (cup['starts_at'] and now<cup['starts_at']) or (cup['ends_at'] and now>cup['ends_at']):return self.send_json({'ok':False,'error':'coupon_not_available'},409)
                if conn.execute('SELECT 1 FROM coupon_redemptions WHERE coupon_id=? AND membership_id=?',(cup['id'],m['id'])).fetchone():return self.send_json({'ok':False,'error':'coupon_already_used'},409)
                if cup['usage_limit'] and conn.execute('SELECT COUNT(*) n FROM coupon_redemptions WHERE coupon_id=?',(cup['id'],)).fetchone()['n']>=cup['usage_limit']:return self.send_json({'ok':False,'error':'coupon_limit_reached'},409)
                benefit={'type':cup['benefit_type'],'value':cup['benefit_value']}
                if cup['benefit_type']=='bonus_points':
                    prev=int(m['points_balance'] or 0); new=prev+int(cup['benefit_value']); conn.execute('UPDATE memberships SET points_balance=? WHERE id=?',(new,m['id'])); tx_coupon=insert_id(conn,'INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(m['id'],s['user_id'],current_branch_id(conn,s['user_id']),'adjustment',cup['benefit_value'],prev,new,0,self._ip(),'Cupom '+cup['code'],now)); exp=conn.execute('SELECT points_expiry_days FROM campaigns WHERE id=?',(s['campaign_id'],)).fetchone(); add_point_lot(conn,m['id'],tx_coupon,int(cup['benefit_value']),int(exp['points_expiry_days'] or 180),now)
                elif cup['benefit_type']=='bonus_stamps':
                    prev=int(m['progress'] or 0); total=prev+int(cup['benefit_value']); rewards=total//int(m['goal']); new=total%int(m['goal']); conn.execute('UPDATE memberships SET progress=?,rewards_available=rewards_available+? WHERE id=?',(new,rewards,m['id'])); conn.execute('INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(m['id'],s['user_id'],current_branch_id(conn,s['user_id']),'stamp',cup['benefit_value'],prev,new,rewards,self._ip(),'Cupom '+cup['code'],now))
                discount_cents=0
                if cup['benefit_type']=='percent' and purchase_cents>0: discount_cents=min(purchase_cents,round(purchase_cents*int(cup['benefit_value'])/100))
                elif cup['benefit_type']=='fixed' and purchase_cents>0: discount_cents=min(purchase_cents,int(cup['benefit_value']))
                benefit['discount_cents']=discount_cents; benefit['purchase_cents']=purchase_cents
                conn.execute('INSERT INTO coupon_redemptions(coupon_id,membership_id,user_id,purchase_cents,discount_cents,created_at) VALUES(?,?,?,?,?,?)',(cup['id'],m['id'],s['user_id'],purchase_cents,discount_cents,now)); audit(conn,s['company_id'],s['user_id'],'coupon_redeem','coupon',cup['id'],details=f"{cup['code']};membership={m['public_id']}",ip_address=self._ip()); notify_wallet_updates(conn,m['public_id'])
                return self.send_json({'ok':True,'coupon':cup['name'],'benefit':benefit})

            if path == '/api/manager/notification/state':
                if s['role']!='manager':return self.send_json({'ok':False,'error':'forbidden'},403)
                fp=str(payload.get('fingerprint') or '')[:40]; status=str(payload.get('status') or 'seen'); priority=str(payload.get('priority') or 'medium')
                if status not in ('new','seen','resolved') or priority not in ('low','medium','high'):return self.send_json({'ok':False,'error':'invalid_state'},400)
                try: conn.execute('INSERT INTO alert_states(fingerprint,status,priority,updated_at) VALUES(?,?,?,?)',(fp,status,priority,now_ts()))
                except integrity_errors(): conn.execute('UPDATE alert_states SET status=?,priority=?,updated_at=? WHERE fingerprint=?',(status,priority,now_ts(),fp))
                return self.send_json({'ok':True})

            if path == '/api/attendant/customer/note':
                if s['role']!='attendant' or not s['campaign_id']: return self.send_json({'ok':False,'error':'forbidden'},403)
                note=str(payload.get('note') or '').strip()[:800]
                try: customer_id=int(payload.get('customer_id') or 0)
                except: customer_id=0
                if not note:return self.send_json({'ok':False,'error':'note_required'},400)
                m=conn.execute('SELECT m.id FROM memberships m WHERE m.customer_id=? AND m.campaign_id=?',(customer_id,s['campaign_id'])).fetchone()
                if not m:return self.send_json({'ok':False,'error':'customer_not_found'},404)
                insert_id(conn,'INSERT INTO customer_notes(membership_id,user_id,note,created_at) VALUES(?,?,?,?)',(m['id'],s['user_id'],note,now_ts())); audit(conn,s['company_id'],s['user_id'],'customer_note_create','membership',m['id'],details=note[:120],ip_address=self._ip()); return self.send_json({'ok':True})

            if path == '/api/attendant/password':
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                current_password=str(payload.get('current_password',''))
                new_password=str(payload.get('new_password','')).strip()
                if len(new_password)<10: return self.send_json({'ok':False,'error':'invalid_new_password'},400)
                u=conn.execute('SELECT id,password_hash FROM users WHERE id=? AND role=\'attendant\' AND active=1',(s['user_id'],)).fetchone()
                if not u or not verify_password(current_password,u['password_hash']): return self.send_json({'ok':False,'error':'invalid_current_password'},401)
                if verify_password(new_password,u['password_hash']): return self.send_json({'ok':False,'error':'same_password'},409)
                conn.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(new_password),s['user_id']))
                audit(conn,s['company_id'],s['user_id'],'password_change','user',s['user_id'],ip_address=self._ip())
                print(f'[AUTH] ATTENDANT_PASSWORD_CHANGED user_id={s["user_id"]}')
                return self.send_json({'ok':True})
            if path == '/api/attendant/customer/update':
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                try: customer_id=int(payload.get('customer_id',0))
                except (TypeError,ValueError): customer_id=0
                name=str(payload.get('name','')).strip()[:80]
                email=normalize_email(payload.get('email'))
                phone=normalize_phone(payload.get('phone'))
                birth_date=normalize_birth_date(payload.get('birth_date'))
                cpf=normalize_cpf(payload.get('cpf'))
                if customer_id<1 or len(name)<2 or not email or not phone or not birth_date or not cpf:
                    return self.send_json({'ok':False,'error':'invalid_customer_data'},400)
                member=conn.execute("""SELECT m.id,m.public_id FROM memberships m JOIN campaigns c ON c.id=m.campaign_id
                    WHERE m.customer_id=? AND m.campaign_id=? AND c.company_id=?""",(customer_id,s['campaign_id'],s['company_id'])).fetchone()
                if not member: return self.send_json({'ok':False,'error':'customer_not_found'},404)
                duplicate=conn.execute("""SELECT cu.id FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                    WHERE m.campaign_id=? AND cu.cpf=? AND cu.id<>? LIMIT 1""",(s['campaign_id'],cpf,customer_id)).fetchone()
                if duplicate: return self.send_json({'ok':False,'error':'cpf_exists'},409)
                conn.execute('UPDATE customers SET name=?,contact=?,email=?,phone=?,birth_date=?,cpf=? WHERE id=?',
                    (name,email,email,phone,birth_date,cpf,customer_id))
                audit(conn,s['company_id'],s['user_id'],'customer_update','customer',customer_id,details=member['public_id'],ip_address=self._ip())
                return self.send_json({'ok':True,'customer_id':customer_id})
            if path == '/api/attendant/customer/delete':
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                try: customer_id=int(payload.get('customer_id',0))
                except (TypeError,ValueError): customer_id=0
                member=conn.execute("""SELECT m.id,m.public_id FROM memberships m JOIN campaigns c ON c.id=m.campaign_id
                    WHERE m.customer_id=? AND m.campaign_id=? AND c.company_id=?""",(customer_id,s['campaign_id'],s['company_id'])).fetchone()
                if not member: return self.send_json({'ok':False,'error':'customer_not_found'},404)
                audit(conn,s['company_id'],s['user_id'],'customer_delete','membership',member['public_id'],details=f'customer_id={customer_id}',ip_address=self._ip())
                conn.execute('DELETE FROM memberships WHERE id=?',(member['id'],))
                remaining=conn.execute('SELECT COUNT(*) n FROM memberships WHERE customer_id=?',(customer_id,)).fetchone()['n']
                if remaining==0: conn.execute('DELETE FROM customers WHERE id=?',(customer_id,))
                return self.send_json({'ok':True,'deleted_customer_id':customer_id,'deleted_membership':member['public_id']})
            if path == '/api/attendant/whatsapp':
                if s['role']=='attendant' and not self._need_permission(s,'send_messages'): return
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                recipient=str(payload.get('recipient','')).strip()
                message=str(payload.get('message','')).strip()
                if not message or len(message)>4096: return self.send_json({'ok':False,'error':'invalid_message'},400)
                if recipient == 'all' or recipient.startswith('segment:'):
                    extra=''; args=[s['campaign_id'],'']
                    if recipient=='segment:birthdays': extra=" AND substr(cu.birth_date,6,2)=?"; args.append(datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%m'))
                    elif recipient=='segment:inactive30': extra=" AND COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)<?"; args.append(now_ts()-30*86400)
                    elif recipient=='segment:reward_ready': extra=" AND (m.rewards_available>0 OR m.points_balance>=(SELECT COALESCE(MIN(points_cost),999999999) FROM reward_catalog WHERE campaign_id=m.campaign_id AND active=1))"
                    rows=conn.execute('SELECT DISTINCT cu.id,cu.name,cu.phone FROM customers cu JOIN memberships m ON m.customer_id=cu.id WHERE m.campaign_id=? AND cu.marketing_whatsapp=1 AND cu.phone IS NOT NULL AND cu.phone<>?'+extra+' ORDER BY cu.name',tuple(args)).fetchall()
                else:
                    try: customer_id=int(recipient)
                    except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_recipient'},400)
                    rows=conn.execute('''SELECT DISTINCT cu.id,cu.name,cu.phone FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                        WHERE m.campaign_id=? AND cu.id=? AND cu.marketing_whatsapp=1 AND cu.phone IS NOT NULL AND cu.phone<>?''',(s['campaign_id'],customer_id,'')).fetchall()
                if not rows: return self.send_json({'ok':False,'error':'no_recipients'},404)
                wa_cfg=whatsapp_config_for_client(conn,s['campaign_id'])
                cloud=whatsapp_cloud_configured(wa_cfg)
                if not cloud:return self.send_json({'ok':False,'error':'whatsapp_not_configured'},503)
                results=[]
                for r in rows:
                    qid=enqueue_message(conn,s['campaign_id'],'whatsapp',r['phone'],{'message':message})
                    results.append({'customer_id':r['id'],'name':r['name'],'phone':r['phone'],'queued':True,'queue_id':qid})
                    audit(conn,s['company_id'],s['user_id'],'whatsapp_queued','customer',r['id'],details=f'queue={qid}',ip_address=self._ip())
                return self.send_json({'ok':True,'queued_count':len(results),'results':results})
            if path == '/api/attendant/email':
                if s['role']=='attendant' and not self._need_permission(s,'send_messages'): return
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                smtp_cfg=email_config_for_client(conn,s['campaign_id'])
                if not email_configured(smtp_cfg): return self.send_json({'ok':False,'error':'email_provider_not_configured'},503)
                recipient=str(payload.get('recipient','')).strip()
                message=str(payload.get('message','')).strip()
                image_data=payload.get('image_data')
                if not message and not image_data: return self.send_json({'ok':False,'error':'message_or_image_required'},400)
                if len(message)>10000: return self.send_json({'ok':False,'error':'invalid_message'},400)
                try:
                    if image_data: decode_image_data(image_data)
                except ValueError as exc:
                    return self.send_json({'ok':False,'error':str(exc)},400)
                if recipient == 'all' or recipient.startswith('segment:'):
                    extra=''; args=[s['campaign_id'],'']
                    if recipient=='segment:birthdays': extra=" AND substr(cu.birth_date,6,2)=?"; args.append(datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%m'))
                    elif recipient=='segment:inactive30': extra=" AND COALESCE((SELECT MAX(t.created_at) FROM transactions t WHERE t.membership_id=m.id),m.created_at)<?"; args.append(now_ts()-30*86400)
                    elif recipient=='segment:reward_ready': extra=" AND (m.rewards_available>0 OR m.points_balance>=(SELECT COALESCE(MIN(points_cost),999999999) FROM reward_catalog WHERE campaign_id=m.campaign_id AND active=1))"
                    rows=conn.execute('SELECT DISTINCT cu.id,cu.name,cu.email FROM customers cu JOIN memberships m ON m.customer_id=cu.id WHERE m.campaign_id=? AND cu.marketing_email=1 AND cu.email IS NOT NULL AND cu.email<>?'+extra+' ORDER BY cu.name',tuple(args)).fetchall()
                else:
                    try: customer_id=int(recipient)
                    except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_recipient'},400)
                    rows=conn.execute('''SELECT DISTINCT cu.id,cu.name,cu.email FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                        WHERE m.campaign_id=? AND cu.id=? AND cu.marketing_email=1 AND cu.email IS NOT NULL AND cu.email<>?''',(s['campaign_id'],customer_id,'')).fetchall()
                if not rows: return self.send_json({'ok':False,'error':'no_recipients'},404)
                results=[]
                for r in rows:
                    qid=enqueue_message(conn,s['campaign_id'],'campaign_email',r['email'],{'name':r['name'],'message':message,'image_data':image_data,'subject':f'Clube Fidelidade • {s["client_name"] or "Mensagem"}'})
                    results.append({'customer_id':r['id'],'name':r['name'],'email':r['email'],'queued':True,'queue_id':qid})
                    audit(conn,s['company_id'],s['user_id'],'email_queued','customer',r['id'],details=f'queue={qid}',ip_address=self._ip())
                return self.send_json({'ok':True,'results':results,'queued_count':len(results)})
            if path == '/api/admin/template/save':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80];channel=str(payload.get('channel','both'));subject=str(payload.get('subject','')).strip()[:150];body=str(payload.get('body','')).strip()[:4000]
                if not name or not body or channel not in ('email','whatsapp','both'):return self.send_json({'ok':False,'error':'invalid_template'},400)
                tid=insert_id(conn,'INSERT INTO message_templates(campaign_id,name,channel,subject,body,created_at) VALUES(?,?,?,?,?,?)',(s['campaign_id'],name,channel,subject,body,now_ts()))
                return self.send_json({'ok':True,'template_id':tid})
            if path == '/api/admin/template/delete':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                conn.execute('DELETE FROM message_templates WHERE id=? AND campaign_id=?',(int(payload.get('template_id') or 0),s['campaign_id']));return self.send_json({'ok':True})

            if path == '/api/admin/reward/save':
                if s['role']!='attendant' or not s['is_client_admin'] or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                if not self.csrf_ok():return self.send_json({'ok':False,'error':'csrf_failed'},403)
                name=str(payload.get('name','')).strip()[:100]; description=str(payload.get('description','')).strip()[:300]
                try: points_cost=int(payload.get('points_cost') or 0)
                except: points_cost=0
                image_data=str(payload.get('image_data','') or '')
                try: stock=int(payload.get('stock',-1)); starts_at=int(payload.get('starts_at') or 0) or None; ends_at=int(payload.get('ends_at') or 0) or None
                except: stock=-1; starts_at=None; ends_at=None
                if stock < -1: stock=-1
                if not name or points_cost<1:return self.send_json({'ok':False,'error':'invalid_reward'},400)
                if image_data and (len(image_data)>900000 or not image_data.startswith(('data:image/png;base64,','data:image/jpeg;base64,','data:image/webp;base64,'))):return self.send_json({'ok':False,'error':'invalid_reward_image'},400)
                with connect(DB_PATH) as conn:
                    c=conn.execute("SELECT loyalty_type FROM campaigns WHERE id=? AND company_id=?",(s['campaign_id'],s['company_id'])).fetchone()
                    if not c or c['loyalty_type']!='points':return self.send_json({'ok':False,'error':'points_program_required'},409)
                    rid=insert_id(conn,"INSERT INTO reward_catalog(campaign_id,name,description,points_cost,image_data,active,stock,starts_at,ends_at,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?,?,?,?)",(s['campaign_id'],name,description,points_cost,image_data or None,stock,starts_at,ends_at,now_ts(),now_ts()))
                    audit(conn,s['company_id'],s['user_id'],'reward_catalog_create','reward',rid,details=f'{name};{points_cost} pontos',ip_address=self._ip())
                return self.send_json({'ok':True,'reward_id':rid})
            if path == '/api/admin/reward/update':
                if s['role']!='attendant' or not s['is_client_admin'] or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                if not self.csrf_ok():return self.send_json({'ok':False,'error':'csrf_failed'},403)
                try: rid=int(payload.get('reward_id') or 0); points_cost=int(payload.get('points_cost') or 0)
                except: rid=0; points_cost=0
                name=str(payload.get('name','')).strip()[:100]; description=str(payload.get('description','')).strip()[:300]; image_data=payload.get('image_data',None)
                try: stock=int(payload.get('stock',-1)); starts_at=int(payload.get('starts_at') or 0) or None; ends_at=int(payload.get('ends_at') or 0) or None
                except: stock=-1; starts_at=None; ends_at=None
                if stock < -1: stock=-1
                if rid<1 or not name or points_cost<1:return self.send_json({'ok':False,'error':'invalid_reward'},400)
                with connect(DB_PATH) as conn:
                    r=conn.execute("SELECT id FROM reward_catalog WHERE id=? AND campaign_id=?",(rid,s['campaign_id'])).fetchone()
                    if not r:return self.send_json({'ok':False,'error':'reward_not_found'},404)
                    if image_data is None: conn.execute("UPDATE reward_catalog SET name=?,description=?,points_cost=?,stock=?,starts_at=?,ends_at=?,updated_at=? WHERE id=?",(name,description,points_cost,stock,starts_at,ends_at,now_ts(),rid))
                    else:
                        image_data=str(image_data or '')
                        if image_data and (len(image_data)>900000 or not image_data.startswith(('data:image/png;base64,','data:image/jpeg;base64,','data:image/webp;base64,'))):return self.send_json({'ok':False,'error':'invalid_reward_image'},400)
                        conn.execute("UPDATE reward_catalog SET name=?,description=?,points_cost=?,image_data=?,stock=?,starts_at=?,ends_at=?,updated_at=? WHERE id=?",(name,description,points_cost,image_data or None,stock,starts_at,ends_at,now_ts(),rid))
                    audit(conn,s['company_id'],s['user_id'],'reward_catalog_update','reward',rid,details=f'{name};{points_cost} pontos',ip_address=self._ip())
                return self.send_json({'ok':True})
            if path == '/api/admin/reward/toggle':
                if s['role']!='attendant' or not s['is_client_admin'] or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                if not self.csrf_ok():return self.send_json({'ok':False,'error':'csrf_failed'},403)
                try: rid=int(payload.get('reward_id') or 0)
                except: rid=0
                active=1 if payload.get('active') else 0
                with connect(DB_PATH) as conn:
                    r=conn.execute("SELECT id FROM reward_catalog WHERE id=? AND campaign_id=?",(rid,s['campaign_id'])).fetchone()
                    if not r:return self.send_json({'ok':False,'error':'reward_not_found'},404)
                    conn.execute("UPDATE reward_catalog SET active=?,updated_at=? WHERE id=?",(active,now_ts(),rid)); audit(conn,s['company_id'],s['user_id'],'reward_catalog_toggle','reward',rid,details=f'active={active}',ip_address=self._ip())
                return self.send_json({'ok':True})
            if path == '/api/attendant/points/earn':
                if s['role']=='attendant' and not self._need_permission(s,'add_balance'): return
                if s['role']!='attendant' or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                if not self.csrf_ok():return self.send_json({'ok':False,'error':'csrf_failed'},403)
                token,token_error=resolve_member_token(str(payload.get('token','')))
                if token_error:return self.send_json({'ok':False,'error':token_error},410 if token_error=='qr_expired' else 400)
                try: purchase_cents=int(payload.get('purchase_cents') or 0)
                except: purchase_cents=0
                idem=str(payload.get('idempotency_key','')).strip()
                if purchase_cents<1 or not idem:return self.send_json({'ok':False,'error':'invalid_purchase'},400)
                with connect(DB_PATH) as conn:
                    m=fetchone_for_update(conn,"SELECT m.*,c.company_id,c.name campaign_name,c.loyalty_type,c.points_spend_cents,cu.name customer_name FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?",(token,token,s['company_id'],s['campaign_id']))
                    if not m:return self.send_json({'ok':False,'error':'membership_not_found'},404)
                    if m['loyalty_type']!='points':return self.send_json({'ok':False,'error':'points_program_required'},409)
                    rate=max(1,int(m['points_spend_cents'] or 200)); base_earned=purchase_cents//rate; factor=active_multiplier(conn,s['campaign_id']); earned=int(base_earned*factor)
                    if earned<1:return self.send_json({'ok':False,'error':'purchase_below_point_rule','message':'O valor da compra não gera nenhum ponto nesta regra.'},409)
                    prev=int(m['points_balance'] or 0); new=prev+earned; ts=now_ts()
                    tx_id=insert_id(conn,"INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,device_id,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(m['id'],s['user_id'],current_branch_id(conn,s['user_id'],s['campaign_id']),'adjustment',earned,prev,new,0,idem,str(payload.get('device_id',''))[:120],self._ip(),f'Pontos por compra de R$ {purchase_cents/100:.2f} • {factor:g}x',ts))
                    conn.execute("UPDATE memberships SET points_balance=? WHERE id=?",(new,m['id'])); camp_exp=conn.execute('SELECT points_expiry_days FROM campaigns WHERE id=?',(s['campaign_id'],)).fetchone(); add_point_lot(conn,m['id'],tx_id,earned,int(camp_exp['points_expiry_days'] or 180),ts); record_purchase(conn,m['id'],tx_id,purchase_cents,'in_store',ts); audit(conn,s['company_id'],s['user_id'],'points_earn','membership',m['public_id'],details=f'R${purchase_cents/100:.2f};+{earned} pontos;{factor:g}x',ip_address=self._ip()); notify_wallet_updates(conn,m['public_id'])
                return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name'],'points_earned':earned,'points_balance':new})
            if path == '/api/attendant/points/redeem':
                if s['role']=='attendant' and not self._need_permission(s,'redeem_reward'): return
                if s['role']!='attendant' or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                if not self.csrf_ok():return self.send_json({'ok':False,'error':'csrf_failed'},403)
                token,token_error=resolve_member_token(str(payload.get('token','')))
                if token_error:return self.send_json({'ok':False,'error':token_error},410 if token_error=='qr_expired' else 400)
                try: reward_id=int(payload.get('reward_id') or 0)
                except: reward_id=0
                idem=str(payload.get('idempotency_key','')).strip()
                if reward_id<1 or not idem:return self.send_json({'ok':False,'error':'invalid_reward'},400)
                with connect(DB_PATH) as conn:
                    m=fetchone_for_update(conn,"SELECT m.*,c.company_id,c.loyalty_type,cu.name customer_name FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?",(token,token,s['company_id'],s['campaign_id']))
                    if not m:return self.send_json({'ok':False,'error':'membership_not_found'},404)
                    if m['loyalty_type']!='points':return self.send_json({'ok':False,'error':'points_program_required'},409)
                    r=conn.execute("SELECT * FROM reward_catalog WHERE id=? AND campaign_id=? AND active=1",(reward_id,s['campaign_id'])).fetchone()
                    if not r:return self.send_json({'ok':False,'error':'reward_not_found'},404)
                    prev=int(m['points_balance'] or 0); cost=int(r['points_cost'])
                    if prev<cost:return self.send_json({'ok':False,'error':'insufficient_points','message':'Saldo de pontos insuficiente para esta recompensa.'},409)
                    new=prev-cost
                    tx_id=insert_id(conn,"INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(m['id'],s['user_id'],current_branch_id(conn,s['user_id'],s['campaign_id']),'redeem',-cost,prev,new,0,idem,self._ip(),f'Resgate: {r["name"]} ({cost} pontos)',now_ts()))
                    consume_point_lots(conn,m['id'],cost); conn.execute("UPDATE memberships SET points_balance=? WHERE id=?",(new,m['id'])); conn.execute("INSERT INTO reward_redemptions(membership_id,reward_id,user_id,points_cost,created_at) VALUES(?,?,?,?,?)",(m['id'],r['id'],s['user_id'],cost,now_ts())); conn.execute("UPDATE reward_catalog SET stock=CASE WHEN stock>0 THEN stock-1 ELSE stock END,updated_at=? WHERE id=?",(now_ts(),r['id'])); audit(conn,s['company_id'],s['user_id'],'points_redeem','membership',m['public_id'],details=f'{r["name"]};-{cost} pontos',ip_address=self._ip()); notify_wallet_updates(conn,m['public_id'])
                return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name'],'reward_name':r['name'],'points_spent':cost,'points_balance':new})

            if path in ('/api/attendant/stamp','/api/attendant/stamp/remove','/api/attendant/redeem'):
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
            if path == '/api/attendant/stamp':
                if not self._need_permission(s,'add_balance'): return
                token,token_error=resolve_member_token(payload.get('token'));
                if token_error:return self.send_json({'ok':False,'error':token_error},410 if token_error=='qr_expired' else 400)
                qty=int(payload.get('quantity',1)); idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12); device=str(payload.get('device_id',''))[:100]
                try:
                    begin_write(conn)
                    dupe=conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone()
                    if dupe: return self.send_json({'ok':True,'duplicate':True,'transaction_id':dupe['id']})
                    m=fetchone_for_update(conn,'''SELECT m.*,c.goal,c.min_stamp_interval_sec,c.max_stamps_per_hour,c.max_stamps_per_attendant_day,c.company_id,c.name campaign_name,c.loyalty_type,cu.name customer_name
                      FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?''',(token,token,s['company_id'],s['campaign_id']))
                    if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                    if m['loyalty_type']!='stamps': return self.send_json({'ok':False,'error':'stamps_program_required'},409)
                    validate_stamp(conn,m,m,s,qty)
                    prev=m['progress']; rewards=0; new=prev
                    for _ in range(qty):
                        new += 1
                        if new >= m['goal']:
                            rewards += 1; new = 0
                    tx_id=insert_id(conn,'''INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,device_id,ip_address,created_at)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],current_branch_id(conn,s['user_id'],s['campaign_id']),'stamp',qty,prev,new,rewards,idem,device,self._ip(),now_ts()))
                    conn.execute('UPDATE memberships SET progress=?, rewards_available=rewards_available+? WHERE id=?',(new,rewards,m['id']))
                    purchase_cents=max(0,int(payload.get('purchase_cents') or 0))
                    if purchase_cents: record_purchase(conn,m['id'],tx_id,purchase_cents,'in_store',now_ts())
                    audit(conn,s['company_id'],s['user_id'],'stamp','membership',m['public_id'],details=f'qty={qty};reward+={rewards};valor={purchase_cents}',ip_address=self._ip()); notify_wallet_updates(conn,m['public_id'])
                    return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name'],'previous_progress':prev,'progress':new,'reward_added':rewards})
                except FraudError as e:
                    audit(conn,s['company_id'],s['user_id'],'stamp_blocked','membership',token,details=e.code,ip_address=self._ip())
                    return self.send_json({'ok':False,'error':e.code,'message':e.message,'requires_manager':e.requires_manager},409)
                except integrity_errors():
                    return self.send_json({'ok':False,'error':'duplicate_request'},409)
            if path == '/api/attendant/stamp/remove':
                if not self._need_permission(s,'remove_balance'): return
                reason=str(payload.get('reason','')).strip()[:300]
                if len(reason)<3:return self.send_json({'ok':False,'error':'removal_reason_required'},400)
                token,token_error=resolve_member_token(payload.get('token'));
                if token_error:return self.send_json({'ok':False,'error':token_error},410 if token_error=='qr_expired' else 400)
                idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12)
                begin_write(conn)
                dupe=conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone()
                if dupe: return self.send_json({'ok':True,'duplicate':True,'transaction_id':dupe['id']})
                m=fetchone_for_update(conn,'''SELECT m.*,c.goal,c.company_id,cu.name customer_name
                  FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id
                  WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?''',(token,token,s['company_id'],s['campaign_id']))
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                if m['status']!='active': return self.send_json({'ok':False,'error':'membership_blocked'},409)
                prev=m['progress']; reward_delta=0
                if prev>0:
                    new=prev-1
                elif m['rewards_available']>0:
                    # Desfaz o selo que fechou o ciclo: restaura goal-1 e remove a recompensa gerada.
                    new=max(0,m['goal']-1); reward_delta=-1
                else:
                    return self.send_json({'ok':False,'error':'no_stamp_to_remove','message':'Este cartão não possui selo para remover.'},409)
                tx_id=insert_id(conn,'''INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],current_branch_id(conn,s['user_id'],s['campaign_id']),'adjustment',-1,prev,new,reward_delta,idem,self._ip(),reason,now_ts()))
                conn.execute('UPDATE memberships SET progress=?, rewards_available=rewards_available+? WHERE id=?',(new,reward_delta,m['id']))
                audit(conn,s['company_id'],s['user_id'],'stamp_remove','membership',m['public_id'],details=f'progress={prev}->{new};reward={reward_delta};reason={reason}',ip_address=self._ip()); notify_wallet_updates(conn,m['public_id'])
                return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name'],'previous_progress':prev,'progress':new,'reward_removed':1 if reward_delta<0 else 0})
            if path == '/api/attendant/redeem':
                if not self._need_permission(s,'redeem_reward'): return
                token,token_error=resolve_member_token(payload.get('token'));
                if token_error:return self.send_json({'ok':False,'error':token_error},410 if token_error=='qr_expired' else 400); idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12)
                begin_write(conn)
                if conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone(): return self.send_json({'ok':True,'duplicate':True})
                m=fetchone_for_update(conn,'''SELECT m.*,c.company_id,cu.name customer_name FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?''',(token,token,s['company_id'],s['campaign_id']))
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                if m['status']!='active': return self.send_json({'ok':False,'error':'membership_blocked'},409)
                if m['rewards_available']<1: return self.send_json({'ok':False,'error':'no_reward_available'},409)
                tx_id=insert_id(conn,'''INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],current_branch_id(conn,s['user_id'],s['campaign_id']),'redeem',1,m['progress'],m['progress'],-1,idem,self._ip(),now_ts()))
                conn.execute('UPDATE memberships SET rewards_available=rewards_available-1 WHERE id=?',(m['id'],))
                audit(conn,s['company_id'],s['user_id'],'reward_redeem','membership',m['public_id'],details='Recompensa resgatada; novo ciclo permanece ativo.',ip_address=self._ip()); notify_wallet_updates(conn,m['public_id'])
                return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name']})
            if path == '/api/attendant/messages/retry':
                if s['role']!='attendant' or not s['campaign_id']:return self.send_json({'ok':False,'error':'forbidden'},403)
                try: message_id=int(payload.get('message_id',0))
                except (TypeError,ValueError):message_id=0
                row=conn.execute("SELECT id,status FROM message_queue WHERE id=? AND campaign_id=?",(message_id,s['campaign_id'])).fetchone()
                if not row:return self.send_json({'ok':False,'error':'message_not_found'},404)
                if row['status'] not in ('failed','retry'):return self.send_json({'ok':False,'error':'message_not_retryable'},409)
                conn.execute("UPDATE message_queue SET status='pending',attempts=0,last_error=NULL,available_at=? WHERE id=?",(now_ts(),message_id))
                audit(conn,s['company_id'],s['user_id'],'message_retry','message_queue',message_id,ip_address=self._ip())
                return self.send_json({'ok':True})
            if path == '/api/attendant/automations/update':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                try: rule_id=int(payload.get('rule_id',0))
                except: rule_id=0
                channel=str(payload.get('channel','email')); enabled=1 if payload.get('enabled') else 0; message=str(payload.get('message','')).strip()[:1000]
                if channel not in ('email','whatsapp','both') or not message:return self.send_json({'ok':False,'error':'invalid_rule'},400)
                r=conn.execute('SELECT id FROM automation_rules WHERE id=? AND campaign_id=?',(rule_id,s['campaign_id'])).fetchone()
                if not r:return self.send_json({'ok':False,'error':'rule_not_found'},404)
                conn.execute('UPDATE automation_rules SET channel=?,enabled=?,message=? WHERE id=?',(channel,enabled,message,rule_id)); audit(conn,s['company_id'],s['user_id'],'automation_update','automation',rule_id,details=f'{channel}:{enabled}',ip_address=self._ip())
                return self.send_json({'ok':True})
            if path == '/api/admin/branch/update':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                bid=int(payload.get('branch_id') or 0); name=str(payload.get('name') or '').strip()[:100]; code=re.sub(r'[^A-Z0-9_-]','',str(payload.get('code') or '').upper())[:30]
                if not bid or not name or not code:return self.send_json({'ok':False,'error':'invalid_branch'},400)
                conn.execute('UPDATE branches SET name=?,code=? WHERE id=? AND campaign_id=?',(name,code,bid,s['campaign_id'])); audit(conn,s['company_id'],s['user_id'],'branch_update','branch',bid,details=name,ip_address=self._ip()); return self.send_json({'ok':True})
            if path == '/api/admin/branch/toggle':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                bid=int(payload.get('branch_id') or 0); active=1 if payload.get('active') else 0
                conn.execute('UPDATE branches SET active=? WHERE id=? AND campaign_id=?',(active,bid,s['campaign_id'])); audit(conn,s['company_id'],s['user_id'],'branch_toggle','branch',bid,details='ativo' if active else 'inativo',ip_address=self._ip()); return self.send_json({'ok':True})

            if path == '/api/admin/branch/save':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; code=str(payload.get('code','')).strip().upper()[:30]
                if not name or not code:return self.send_json({'ok':False,'error':'invalid_branch'},400)
                try: bid=insert_id(conn,'INSERT INTO branches(campaign_id,name,code,active,created_at) VALUES(?,?,?,?,?)',(s['campaign_id'],name,code,1,now_ts()))
                except integrity_errors():return self.send_json({'ok':False,'error':'branch_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'branch_create','branch',bid,details=f'{name} ({code})',ip_address=self._ip());return self.send_json({'ok':True,'branch_id':bid})
            if path == '/api/admin/current-branch':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                branch_raw=payload.get('branch_id')
                try: branch_id=int(branch_raw) if branch_raw not in (None,'',0,'0') else None
                except (TypeError,ValueError):return self.send_json({'ok':False,'error':'invalid_branch'},400)
                if branch_id and not conn.execute('SELECT id FROM branches WHERE id=? AND campaign_id=? AND active=1',(branch_id,s['campaign_id'])).fetchone():return self.send_json({'ok':False,'error':'branch_not_found'},404)
                conn.execute('UPDATE users SET branch_id=? WHERE id=? AND campaign_id=? AND role=\'attendant\'',(branch_id,s['user_id'],s['campaign_id']))
                audit(conn,s['company_id'],s['user_id'],'current_branch_update','user',s['user_id'],details=f'branch_id={branch_id or "none"}',ip_address=self._ip(),branch_id=branch_id)
                return self.send_json({'ok':True,'branch_id':branch_id})
            if path == '/api/admin/staff/access':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                uid=int(payload.get('user_id') or 0); branch_id=payload.get('branch_id'); perms=payload.get('permissions') or {}
                allowed={k:bool(perms.get(k)) for k in ('add_balance','remove_balance','redeem_reward','use_gift','view_reports','send_messages')}
                conn.execute("UPDATE users SET permissions_json=?,branch_id=? WHERE id=? AND campaign_id=? AND role='attendant'",(json.dumps(allowed,ensure_ascii=False),int(branch_id) if branch_id else None,uid,s['campaign_id']))
                audit(conn,s['company_id'],s['user_id'],'staff_access_update','user',uid,details=json.dumps(allowed),ip_address=self._ip());return self.send_json({'ok':True})
            if path == '/api/client-admin/staff/create':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; email=normalize_email(payload.get('email')); password=str(payload.get('password','')).strip(); branch_raw=payload.get('branch_id')
                try: branch_id=int(branch_raw) if branch_raw not in (None,'',0,'0') else None
                except (TypeError,ValueError):return self.send_json({'ok':False,'error':'invalid_branch'},400)
                if branch_id and not conn.execute('SELECT id FROM branches WHERE id=? AND campaign_id=? AND active=1',(branch_id,s['campaign_id'])).fetchone():return self.send_json({'ok':False,'error':'branch_not_found'},404)
                if conn.execute('SELECT COUNT(*) n FROM branches WHERE campaign_id=? AND active=1',(s['campaign_id'],)).fetchone()['n'] and not branch_id:return self.send_json({'ok':False,'error':'branch_required'},400)
                if len(name)<2 or not email or len(password)<10:return self.send_json({'ok':False,'error':'invalid_staff'},400)
                try:new_id=insert_id(conn,'INSERT INTO users(company_id,name,email,password_hash,role,campaign_id,is_client_admin,branch_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(s['company_id'],name,email,hash_password(password),'attendant',s['campaign_id'],0,branch_id,now_ts()))
                except integrity_errors():return self.send_json({'ok':False,'error':'email_exists'},409)
                c=conn.execute('SELECT name FROM campaigns WHERE id=?',(s['campaign_id'],)).fetchone(); q=None
                if email_configured(global_email_config()):q=enqueue_message(conn,None,'attendant_welcome',email,{'name':name,'password':password,'client_name':c['name']})
                audit(conn,s['company_id'],s['user_id'],'client_admin_staff_create','user',new_id,details=f'{email};branch_id={branch_id or "none"}',ip_address=self._ip()); return self.send_json({'ok':True,'user_id':new_id,'queue_id':q})
            if path == '/api/client-admin/staff/update':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                if not self.csrf_ok():return self.send_json({'ok':False,'error':'csrf_failed'},403)
                uid=int(payload.get('user_id') or 0); name=str(payload.get('name','')).strip()[:80]; email=normalize_email(payload.get('email')); password=str(payload.get('password','')); branch_raw=payload.get('branch_id')
                try: branch_id=int(branch_raw) if branch_raw not in (None,'',0,'0') else None
                except (TypeError,ValueError):return self.send_json({'ok':False,'error':'invalid_branch'},400)
                if uid==int(s['user_id']):return self.send_json({'ok':False,'error':'cannot_edit_self'},400)
                if not name or not email or (password and len(password)<10):return self.send_json({'ok':False,'error':'invalid_staff'},400)
                if branch_id and not conn.execute('SELECT id FROM branches WHERE id=? AND campaign_id=? AND active=1',(branch_id,s['campaign_id'])).fetchone():return self.send_json({'ok':False,'error':'branch_not_found'},404)
                if conn.execute('SELECT COUNT(*) n FROM branches WHERE campaign_id=? AND active=1',(s['campaign_id'],)).fetchone()['n'] and not branch_id:return self.send_json({'ok':False,'error':'branch_required'},400)
                u=conn.execute("SELECT id FROM users WHERE id=? AND campaign_id=? AND role='attendant'",(uid,s['campaign_id'])).fetchone()
                if not u:return self.send_json({'ok':False,'error':'staff_not_found'},404)
                duplicate=conn.execute("SELECT id FROM users WHERE lower(email)=lower(?) AND id<>?",(email,uid)).fetchone()
                if duplicate:return self.send_json({'ok':False,'error':'email_exists'},409)
                if password: conn.execute("UPDATE users SET name=?,email=?,password_hash=?,branch_id=? WHERE id=?",(name,email,hash_password(password),branch_id,uid))
                else: conn.execute("UPDATE users SET name=?,email=?,branch_id=? WHERE id=?",(name,email,branch_id,uid))
                audit(conn,s['company_id'],s['user_id'],'client_admin_staff_update','user',uid,details=f'{email};branch_id={branch_id or "none"}',ip_address=self._ip())
                return self.send_json({'ok':True})
            if path == '/api/client-admin/staff/delete':
                if s['role']!='attendant' or not s['is_client_admin']:return self.send_json({'ok':False,'error':'forbidden'},403)
                try: uid=int(payload.get('user_id',0))
                except:uid=0
                if uid==s['user_id']:return self.send_json({'ok':False,'error':'cannot_delete_self'},409)
                u=conn.execute("SELECT id FROM users WHERE id=? AND campaign_id=? AND role='attendant' AND is_client_admin=0",(uid,s['campaign_id'])).fetchone()
                if not u:return self.send_json({'ok':False,'error':'user_not_found'},404)
                conn.execute('DELETE FROM users WHERE id=?',(uid,)); audit(conn,s['company_id'],s['user_id'],'client_admin_staff_delete','user',uid,ip_address=self._ip());return self.send_json({'ok':True})
            if path == '/api/manager/campaign':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; reward=str(payload.get('reward_name','')).strip()[:100] or 'Catálogo de recompensas'; code=re.sub(r'[^A-Z0-9_-]','',str(payload.get('code','')).upper())[:24]
                loyalty_type=str(payload.get('loyalty_type','stamps')).strip().lower()
                try: points_spend_cents=int(payload.get('points_spend_cents') or 200)
                except: points_spend_cents=200
                icon=str(payload.get('icon','☕'))[:8]; goal=int(payload.get('goal',5))
                card_theme=str(payload.get('card_theme','green')).strip().lower()
                if card_theme not in CARD_THEMES: card_theme='green'
                if not name or not code or loyalty_type not in ('stamps','points') or (loyalty_type=='stamps' and (not reward or goal not in (3,5,8,10,15))) or (loyalty_type=='points' and points_spend_cents not in (200,300,500,1000)): return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                try:
                    logo_image=validate_logo_data(payload.get('logo_image'))
                    if not logo_image:
                        return self.send_json({'ok':False,'error':'logo_required'},400)
                except ValueError as exc:
                    return self.send_json({'ok':False,'error':str(exc)},400)
                # Integrações opcionais do próprio cliente podem ser cadastradas agora ou depois.
                email_provider=str(payload.get('email_provider','smtp')).strip().lower()
                if email_provider not in ('smtp','brevo'): email_provider='smtp'
                smtp_host=str(payload.get('smtp_host','')).strip()[:200]
                smtp_port=str(payload.get('smtp_port','587')).strip()[:8] or '587'
                smtp_user=str(payload.get('smtp_user','')).strip()[:200]
                smtp_from=str(payload.get('smtp_from','')).strip()[:200]
                smtp_from_name=str(payload.get('smtp_from_name','')).strip()[:100]
                smtp_security=str(payload.get('smtp_security','starttls')).strip().lower()
                if smtp_security not in ('starttls','ssl','none'): smtp_security='starttls'
                brevo_sender_email=str(payload.get('brevo_sender_email','')).strip()[:200]
                brevo_sender_name=str(payload.get('brevo_sender_name','')).strip()[:100]
                brevo_reply_to=str(payload.get('brevo_reply_to','')).strip()[:200]
                wa_phone_id=str(payload.get('whatsapp_phone_number_id','')).strip()[:100]
                wa_waba_id=str(payload.get('whatsapp_waba_id','')).strip()[:100]
                wa_version=str(payload.get('whatsapp_api_version','v24.0')).strip()[:20] or 'v24.0'
                wa_mode=str(payload.get('whatsapp_integration_mode','none')).strip().lower()
                if wa_mode not in ('embedded','manual','none'): wa_mode='none'
                ecommerce_platform=normalize_ecommerce_platform(payload.get('ecommerce_platform'))
                ecommerce_store_url=str(payload.get('ecommerce_store_url','')).strip()[:300]
                ecommerce_secret=secrets.token_urlsafe(24) if ecommerce_platform!='none' else None
                ecommerce_status='awaiting_connection' if ecommerce_platform!='none' else 'not_connected'
                try:
                    smtp_password_enc=encrypt_secret(payload.get('smtp_password')) if payload.get('smtp_password') else None
                    brevo_api_key_enc=encrypt_secret(payload.get('brevo_api_key')) if payload.get('brevo_api_key') else None
                    wa_token_enc=encrypt_secret(payload.get('whatsapp_access_token')) if payload.get('whatsapp_access_token') else None
                except RuntimeError as exc:
                    return self.send_json({'ok':False,'error':str(exc)},503)
                wa_status='connected' if (wa_phone_id and wa_token_enc) else ('awaiting_connection' if wa_mode=='embedded' else 'not_connected')
                try:
                    new_id=insert_id(conn,'''INSERT INTO campaigns(company_id,code,name,reward_name,goal,icon,logo_image,card_theme,loyalty_type,points_spend_cents,min_stamp_interval_sec,max_stamps_per_hour,max_stamps_per_attendant_day,
                        smtp_host,smtp_port,smtp_user,smtp_password_enc,smtp_from,smtp_from_name,smtp_security,email_provider,brevo_api_key_enc,brevo_sender_email,brevo_sender_name,brevo_reply_to,
                        whatsapp_phone_number_id,whatsapp_waba_id,whatsapp_access_token_enc,whatsapp_api_version,whatsapp_integration_mode,whatsapp_signup_status,
                        ecommerce_platform,ecommerce_store_url,ecommerce_webhook_secret,ecommerce_status,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(
                        s['company_id'],code,name,reward,goal,icon,logo_image,card_theme,loyalty_type,points_spend_cents,int(payload.get('min_interval',0)),int(payload.get('max_hour',0)),int(payload.get('max_day',500)),
                        smtp_host,smtp_port,smtp_user,smtp_password_enc,smtp_from,smtp_from_name,smtp_security,email_provider,brevo_api_key_enc,brevo_sender_email,brevo_sender_name,brevo_reply_to,
                        wa_phone_id,wa_waba_id,wa_token_enc,wa_version,wa_mode,wa_status,
                        ecommerce_platform,ecommerce_store_url,ecommerce_secret,ecommerce_status,now_ts()))
                except integrity_errors(): return self.send_json({'ok':False,'error':'campaign_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'campaign_create','campaign',new_id,details=code,ip_address=self._ip())
                return self.send_json({'ok':True,'campaign_id':new_id})
            if path == '/api/manager/campaign/update':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                name=str(payload.get('name','')).strip()[:80]; reward=str(payload.get('reward_name','')).strip()[:100] or 'Catálogo de recompensas'; code=re.sub(r'[^A-Z0-9_-]','',str(payload.get('code','')).upper())[:24]
                loyalty_type=str(payload.get('loyalty_type','stamps')).strip().lower()
                try: points_spend_cents=int(payload.get('points_spend_cents') or 200)
                except: points_spend_cents=200
                icon=str(payload.get('icon','☕'))[:8]
                try: goal=int(payload.get('goal',5)); min_interval=int(payload.get('min_interval',0)); max_hour=int(payload.get('max_hour',0)); max_day=int(payload.get('max_day',500))
                except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                if campaign_id<1 or not name or not code or loyalty_type not in ('stamps','points') or (loyalty_type=='stamps' and (not reward or goal not in (3,5,8,10,15))) or (loyalty_type=='points' and points_spend_cents not in (200,300,500,1000)) or min_interval<0 or max_hour<0 or max_day<1:
                    return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                c=rowdict(conn.execute('SELECT * FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone())
                card_theme=str(payload.get('card_theme',c.get('card_theme') or 'green')).strip().lower()
                if card_theme not in CARD_THEMES: card_theme='green'
                if not c: return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                logo_image=c['logo_image']
                if payload.get('logo_image'):
                    try: logo_image=validate_logo_data(payload.get('logo_image'))
                    except ValueError as exc: return self.send_json({'ok':False,'error':str(exc)},400)
                # Integrações por cliente. Segredos vazios preservam os valores já salvos.
                smtp_host=str(payload.get('smtp_host','')).strip()[:200]
                smtp_port=str(payload.get('smtp_port','587')).strip()[:8] or '587'
                smtp_user=str(payload.get('smtp_user','')).strip()[:200]
                smtp_from=str(payload.get('smtp_from','')).strip()[:200]
                smtp_from_name=str(payload.get('smtp_from_name','')).strip()[:100]
                smtp_security=str(payload.get('smtp_security','starttls')).strip().lower()
                email_provider=str(payload.get('email_provider',c.get('email_provider') or 'smtp')).strip().lower()
                if email_provider not in ('smtp','brevo'): email_provider='smtp'
                brevo_sender_email=str(payload.get('brevo_sender_email','')).strip()[:200]
                brevo_sender_name=str(payload.get('brevo_sender_name','')).strip()[:100]
                brevo_reply_to=str(payload.get('brevo_reply_to','')).strip()[:200]
                wa_phone_id=str(payload.get('whatsapp_phone_number_id','')).strip()[:100]
                wa_waba_id=str(payload.get('whatsapp_waba_id','')).strip()[:100]
                wa_version=str(payload.get('whatsapp_api_version','v24.0')).strip()[:20]
                wa_mode=str(payload.get('whatsapp_integration_mode',c.get('whatsapp_integration_mode') or 'manual')).strip().lower()
                if wa_mode not in ('embedded','manual','none'): wa_mode='manual'
                ecommerce_platform=normalize_ecommerce_platform(payload.get('ecommerce_platform',c.get('ecommerce_platform') or 'none'))
                ecommerce_store_url=str(payload.get('ecommerce_store_url',c.get('ecommerce_store_url') or '')).strip()[:300]
                old_platform=normalize_ecommerce_platform(c.get('ecommerce_platform'))
                ecommerce_secret=c.get('ecommerce_webhook_secret')
                if ecommerce_platform!='none' and not ecommerce_secret: ecommerce_secret=secrets.token_urlsafe(24)
                if ecommerce_platform=='none': ecommerce_secret=None
                ecommerce_status=('awaiting_connection' if ecommerce_platform!='none' else 'not_connected') if ecommerce_platform!=old_platform else (c.get('ecommerce_status') or ('awaiting_connection' if ecommerce_platform!='none' else 'not_connected'))
                smtp_password_enc=c['smtp_password_enc']
                brevo_api_key_enc=c.get('brevo_api_key_enc')
                wa_token_enc=c['whatsapp_access_token_enc']
                try:
                    if payload.get('smtp_password'): smtp_password_enc=encrypt_secret(payload.get('smtp_password'))
                    if payload.get('brevo_api_key'): brevo_api_key_enc=encrypt_secret(payload.get('brevo_api_key'))
                    if payload.get('whatsapp_access_token'): wa_token_enc=encrypt_secret(payload.get('whatsapp_access_token'))
                except RuntimeError as exc:
                    return self.send_json({'ok':False,'error':str(exc)},503)
                try:
                    conn.execute('''UPDATE campaigns SET code=?,name=?,reward_name=?,goal=?,icon=?,logo_image=?,card_theme=?,loyalty_type=?,points_spend_cents=?,min_stamp_interval_sec=?,max_stamps_per_hour=?,max_stamps_per_attendant_day=?,
                        smtp_host=?,smtp_port=?,smtp_user=?,smtp_password_enc=?,smtp_from=?,smtp_from_name=?,smtp_security=?,email_provider=?,brevo_api_key_enc=?,brevo_sender_email=?,brevo_sender_name=?,brevo_reply_to=?,
                        whatsapp_phone_number_id=?,whatsapp_waba_id=?,whatsapp_access_token_enc=?,whatsapp_api_version=?,whatsapp_integration_mode=?,whatsapp_signup_status=?,
                        ecommerce_platform=?,ecommerce_store_url=?,ecommerce_webhook_secret=?,ecommerce_status=?
                        WHERE id=? AND company_id=?''',(code,name,reward,goal,icon,logo_image,card_theme,loyalty_type,points_spend_cents,min_interval,max_hour,max_day,
                        smtp_host,smtp_port,smtp_user,smtp_password_enc,smtp_from,smtp_from_name,smtp_security,email_provider,brevo_api_key_enc,brevo_sender_email,brevo_sender_name,brevo_reply_to,
                        wa_phone_id,wa_waba_id,wa_token_enc,wa_version,wa_mode,'connected' if (wa_phone_id and wa_token_enc) else ('awaiting_connection' if wa_mode=='embedded' else 'not_connected'),
                        ecommerce_platform,ecommerce_store_url,ecommerce_secret,ecommerce_status,campaign_id,s['company_id']))
                except integrity_errors(): return self.send_json({'ok':False,'error':'campaign_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'campaign_update','campaign',campaign_id,details=code,ip_address=self._ip())
                return self.send_json({'ok':True,'campaign_id':campaign_id})
            if path == '/api/manager/integration/ecommerce/rotate-secret':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except: campaign_id=0
                c=rowdict(conn.execute('SELECT ecommerce_platform FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone())
                if not c:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                platform=normalize_ecommerce_platform(c.get('ecommerce_platform'))
                if platform=='none':return self.send_json({'ok':False,'error':'ecommerce_not_configured'},409)
                secret=secrets.token_urlsafe(24)
                conn.execute("UPDATE campaigns SET ecommerce_webhook_secret=?,ecommerce_status='awaiting_connection' WHERE id=?",(secret,campaign_id))
                audit(conn,s['company_id'],s['user_id'],'ecommerce_secret_rotated','campaign',campaign_id,ip_address=self._ip())
                public_base=os.environ.get('PUBLIC_BASE_URL','').rstrip('/')
                return self.send_json({'ok':True,'webhook_url':(public_base+f'/api/integrations/ecommerce/{campaign_id}/{secret}') if public_base else '', 'secret':secret})

            if path == '/api/manager/integration/test-email':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                cfg=email_config_for_client(conn,campaign_id)
                target=normalize_email(payload.get('email') or s['email'])
                if not target or not email_configured(cfg): return self.send_json({'ok':False,'error':'email_provider_not_configured'},503)
                msg=EmailMessage(); msg['Subject']='Teste de e-mail • Clube Fidelidade'; msg['To']=target; msg.set_content('Configuração SMTP testada com sucesso.')
                result=send_email_message(msg,cfg)
                return self.send_json({'ok':bool(result.get('sent')),'result':result},200 if result.get('sent') else 502)
            if path == '/api/manager/integration/whatsapp/embedded-complete':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                code=str(payload.get('code','')).strip(); phone_id=str(payload.get('phone_number_id','')).strip(); waba_id=str(payload.get('waba_id','')).strip()
                if not (campaign_id and code and phone_id and waba_id): return self.send_json({'ok':False,'error':'embedded_signup_incomplete'},400)
                c=conn.execute('SELECT id FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone()
                if not c: return self.send_json({'ok':False,'error':'client_not_found'},404)
                try:
                    exchanged=meta_exchange_code(code); token=str(exchanged.get('access_token','')).strip()
                    if not token: raise RuntimeError('meta_token_missing')
                    details=meta_phone_details(phone_id,token); token_enc=encrypt_secret(token)
                    conn.execute("""UPDATE campaigns SET whatsapp_integration_mode='embedded',whatsapp_signup_status='connected',whatsapp_phone_number_id=?,whatsapp_waba_id=?,whatsapp_access_token_enc=?,whatsapp_api_version=?,whatsapp_connected_at=? WHERE id=? AND company_id=?""",(phone_id,waba_id,token_enc,os.environ.get('META_GRAPH_VERSION','v24.0'),now_iso(),campaign_id,s['company_id']))
                    conn.commit()
                    return self.send_json({'ok':True,'status':'connected','display_phone_number':details.get('display_phone_number'),'verified_name':details.get('verified_name')})
                except Exception as exc: return self.send_json({'ok':False,'error':'embedded_signup_failed','detail':str(exc)[:700]},502)
            if path == '/api/manager/integration/test-whatsapp':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                phone=normalize_phone(payload.get('phone'))
                cfg=whatsapp_config_for_client(conn,campaign_id)
                if not phone or not whatsapp_cloud_configured(cfg): return self.send_json({'ok':False,'error':'whatsapp_not_configured'},503)
                try: response=send_whatsapp_cloud(phone,'Teste de integração • Clube Fidelidade',cfg)
                except Exception as exc: return self.send_json({'ok':False,'error':'whatsapp_test_failed','detail':str(exc)[:500]},502)
                return self.send_json({'ok':True,'message_id':((response.get('messages') or [{}])[0]).get('id')})
            if path == '/api/manager/staff/check-email':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                email=normalize_email(payload.get('email'))
                if not email or '@' not in email:
                    return self.send_json({'ok':False,'available':False,'error':'invalid_email','message':'Informe um e-mail válido.'},400)
                configured_admin=normalize_email(os.environ.get('CLUBE_ADMIN_EMAIL',''))
                if configured_admin and email == configured_admin:
                    return self.send_json({
                        'ok':True,'available':False,'error':'admin_email_reserved',
                        'message':'Este e-mail pertence ao administrador geral da plataforma. Utilize outro e-mail para cadastrar um usuário da empresa.'
                    })
                existing=conn.execute('SELECT id,name,active,is_client_admin,campaign_id FROM users WHERE lower(email)=lower(?) LIMIT 1',(email,)).fetchone()
                if existing:
                    return self.send_json({
                        'ok':True,'available':False,'error':'email_exists',
                        'message':'Este e-mail já está cadastrado no sistema. Cada usuário deve possuir um e-mail próprio.'
                    })
                return self.send_json({'ok':True,'available':True,'message':'E-mail disponível para cadastro.'})

            if path == '/api/manager/staff':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]
                email=normalize_email(payload.get('email'))
                password=str(payload.get('password','')).strip()
                is_client_admin=1 if payload.get('is_client_admin') else 0
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                if len(name)<2 or not email or '@' not in email or len(password)<10 or campaign_id<1:
                    return self.send_json({'ok':False,'error':'invalid_staff','message':'Preencha nome, e-mail, cliente, perfil e uma senha com pelo menos 10 caracteres.'},400)
                configured_admin=normalize_email(os.environ.get('CLUBE_ADMIN_EMAIL',''))
                if configured_admin and email == configured_admin:
                    return self.send_json({
                        'ok':False,'error':'admin_email_reserved',
                        'message':'Este e-mail pertence ao administrador geral da plataforma. Utilize outro e-mail para cadastrar um usuário da empresa.'
                    },409)
                existing=conn.execute('SELECT id FROM users WHERE lower(email)=lower(?) LIMIT 1',(email,)).fetchone()
                if existing:
                    return self.send_json({
                        'ok':False,'error':'email_exists',
                        'message':'Este e-mail já está cadastrado no sistema. Cada usuário deve possuir um e-mail próprio.'
                    },409)
                client=conn.execute('SELECT id,name FROM campaigns WHERE id=? AND company_id=? AND active=1',(campaign_id,s['company_id'])).fetchone()
                if not client:
                    return self.send_json({'ok':False,'error':'client_not_found','message':'A empresa selecionada não foi encontrada ou está arquivada.'},404)
                try:
                    new_id=insert_id(conn,'INSERT INTO users(company_id,name,email,password_hash,role,campaign_id,is_client_admin,created_at) VALUES(?,?,?,?,?,?,?,?)',(s['company_id'],name,email,hash_password(password),'attendant',campaign_id,is_client_admin,now_ts()))
                except integrity_errors():
                    return self.send_json({'ok':False,'error':'email_exists','message':'Este e-mail já está cadastrado no sistema. Cada usuário deve possuir um e-mail próprio.'},409)
                audit(conn,s['company_id'],s['user_id'],'staff_create','user',new_id,details=f'{email}:attendant:client={campaign_id}',ip_address=self._ip())
                smtp_cfg=global_email_config(); email_result={'queued':False,'reason':'email_provider_not_configured'}
                if email_configured(smtp_cfg):
                    qid=enqueue_message(conn,None,'attendant_welcome',email,{'name':name,'password':password,'client_name':client['name']}); email_result={'queued':True,'queue_id':qid}
                    audit(conn,s['company_id'],s['user_id'],'staff_welcome_queued','user',new_id,details=f'queue={qid}',ip_address=self._ip())
                return self.send_json({'ok':True,'user_id':new_id,'client_name':client['name'],'welcome_email':email_result})
            if path == '/api/manager/campaign/delete':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                c=conn.execute('SELECT id,name,code FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone()
                if not c:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                conn.execute('UPDATE campaigns SET active=0 WHERE id=? AND company_id=?',(campaign_id,s['company_id']))
                audit(conn,s['company_id'],s['user_id'],'client_archive','campaign',campaign_id,details=c['code'],ip_address=self._ip())
                return self.send_json({'ok':True,'archived_campaign_id':campaign_id})
            if path == '/api/manager/campaign/restore':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                c=conn.execute('SELECT id,code FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone()
                if not c:return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                conn.execute('UPDATE campaigns SET active=1 WHERE id=? AND company_id=?',(campaign_id,s['company_id']))
                audit(conn,s['company_id'],s['user_id'],'client_restore','campaign',campaign_id,details=c['code'],ip_address=self._ip())
                return self.send_json({'ok':True})
            if path == '/api/manager/staff/delete':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: user_id=int(payload.get('user_id',0))
                except (TypeError,ValueError): user_id=0
                if user_id == s['user_id']: return self.send_json({'ok':False,'error':'cannot_delete_self'},409)
                u=conn.execute('SELECT id,name,email,role FROM users WHERE id=? AND company_id=?',(user_id,s['company_id'])).fetchone()
                if not u: return self.send_json({'ok':False,'error':'user_not_found'},404)
                configured_admin=os.environ.get('CLUBE_ADMIN_EMAIL','').strip().lower()
                if configured_admin and u['email'].lower()==configured_admin:
                    return self.send_json({'ok':False,'error':'configured_admin_protected'},409)
                if u['role']=='manager':
                    managers=conn.execute("SELECT COUNT(*) n FROM users WHERE company_id=? AND role='manager' AND active=1",(s['company_id'],)).fetchone()['n']
                    if managers <= 1: return self.send_json({'ok':False,'error':'last_manager_protected'},409)
                audit(conn,s['company_id'],s['user_id'],'staff_delete','user',user_id,details=f"{u['email']}:{u['role']}",ip_address=self._ip())
                conn.execute('DELETE FROM users WHERE id=? AND company_id=?',(user_id,s['company_id']))
                return self.send_json({'ok':True,'deleted_user_id':user_id})
            if path == '/api/manager/block':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                token,token_error=resolve_member_token(payload.get('token'));
                if token_error:return self.send_json({'ok':False,'error':token_error},410 if token_error=='qr_expired' else 400); status='blocked' if payload.get('blocked',True) else 'active'
                m=conn.execute('''SELECT m.* FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=?''',(token,token,s['company_id'])).fetchone()
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                conn.execute('UPDATE memberships SET status=? WHERE id=?',(status,m['id']))
                ttype='block' if status=='blocked' else 'unblock'
                conn.execute('''INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],current_branch_id(conn,s['user_id']),ttype,0,m['progress'],m['progress'],0,self._ip(),'manager action',now_ts()))
                audit(conn,s['company_id'],s['user_id'],ttype,'membership',m['public_id'],ip_address=self._ip())
                return self.send_json({'ok':True,'status':status})
            return self.send_json({'ok':False,'error':'not_found'},404)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--host',default=os.environ.get('HOST','0.0.0.0')); parser.add_argument('--port',type=int,default=int(os.environ.get('PORT','8000'))); parser.add_argument('--init-only',action='store_true'); args=parser.parse_args()
    init_db(DB_PATH,seed=True)
    ensure_configured_staff(DB_PATH)
    if args.init_only:
        print(f'Database initialized: {DB_PATH}'); return
    threading.Thread(target=background_loop,daemon=True,name='clube-worker').start()
    srv=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f'Fidelizaê! {VERSION} em http://{args.host}:{args.port}')
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally: srv.server_close()

if __name__=='__main__': main()
