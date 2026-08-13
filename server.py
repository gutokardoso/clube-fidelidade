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
from datetime import date, datetime
from zoneinfo import ZoneInfo
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from email.message import EmailMessage
from cryptography.fernet import Fernet, InvalidToken
import hashlib

import qrcode

from db import DEFAULT_DB, init_db, ensure_configured_staff, connect, create_session, get_session, audit, insert_id, begin_write, integrity_errors, fetchone_for_update
from security import verify_password, hash_password, random_token, now_ts
from antifraud import validate_stamp, FraudError
from wallet import wallet_status, apple_pass_link, google_wallet_link

BASE = Path(__file__).resolve().parent
STATIC = BASE / 'static'
DB_PATH = os.environ.get('DATABASE_URL') or os.environ.get('CLUBE_DB_PATH', DEFAULT_DB)
SESSION_COOKIE = 'clube_session'


def jdump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def rowdict(row):
    return dict(row) if row else None



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
    if cfg.get('reply_to'): payload['replyTo']={'email':cfg['reply_to']}
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


def send_password_recovery_email(email, temporary_password, smtp_config=None):
    if not email_configured(smtp_config):
        return {'sent':False,'reason':'smtp_not_configured'}
    login_url=os.environ.get('CLUBE_LOGIN_URL','https://clube-fidelidade-production.up.railway.app/login').strip()
    msg=EmailMessage()
    msg['Subject']='Recuperação de senha • Clube Fidelidade'
    msg['To']=email
    msg.set_content(
        'Recebemos uma solicitação de recuperação de senha para o seu acesso ao Clube Fidelidade.\n\n'
        f'Nova senha temporária: {temporary_password}\n\n'
        f'Acesse: {login_url}\n\n'
        'Depois de entrar, altere a senha no painel.'
    )
    return send_email_message(msg, smtp_config)


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
        '<div style="background:linear-gradient(145deg,#57301d,#2e1b12);color:#fff;border-radius:26px;padding:26px;text-align:center">'
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


class Handler(BaseHTTPRequestHandler):
    server_version = 'ClubeFidelidade/18.0'

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

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path = p.path
        qs = urllib.parse.parse_qs(p.query)
        if path == '/': return self.send_text((STATIC/'index.html').read_text(encoding='utf-8'))
        if path == '/join':
            code=(qs.get('campaign') or ['CAFE5'])[0].upper().strip()
            with connect(DB_PATH) as conn:
                c=conn.execute('''SELECT c.name,c.reward_name,c.goal,c.logo_image,co.primary_color,co.logo_text FROM campaigns c JOIN companies co ON co.id=c.company_id WHERE c.code=? AND c.active=1''',(code,)).fetchone()
            template=(STATIC/'join.html').read_text(encoding='utf-8')
            if c:
                if c['logo_image']:
                    logo_block = '<img class="campaign-logo" src="' + html.escape(str(c['logo_image']), quote=True) + '" alt="Logo do cliente">'
                else:
                    logo_block = '<div class="brand campaign-logo-fallback">' + html.escape(str(c['logo_text'])) + '</div>'
                template=template.replace('{{LOGO_BLOCK}}',logo_block).replace('{{CAMPAIGN_NAME}}',html.escape(str(c['name'])))
                template=template.replace('name="campaign_code" value="CAFE5"',f'name="campaign_code" value="{html.escape(code)}"')
                template=template.replace('</head>',f"<style>:root{{--accent:{html.escape(str(c['primary_color']))}}}</style></head>")
                error_code=(qs.get('error') or [''])[0]
                if error_code:
                    messages={'invalid_name':'Preencha seu nome corretamente.','invalid_email':'Digite um e-mail válido.','invalid_phone':'Digite um celular válido com DDD.','invalid_birth_date':'Digite uma data de nascimento válida.','invalid_cpf':'Digite um CPF válido.','campaign_not_found':'Cliente não encontrado.'}
                    message=messages.get(error_code,'Não foi possível criar o cartão. Confira os dados e tente novamente.')
                    template=template.replace('<div id="msg"></div>','<div id="msg"><div class="notice error">'+html.escape(message)+'</div></div>')
            else:
                template=template.replace('{{LOGO_BLOCK}}','<div class="brand campaign-logo-fallback">CLUBE</div>').replace('{{CAMPAIGN_NAME}}','Cliente não encontrado').replace('<form id="f" class="form" method="post" action="/join">','<form id="f" class="form hidden" method="post" action="/join">')
            return self.send_text(template)
        if path in ['/login','/manager','/attendant','/card']:
            name = path.strip('/') + '.html'
            template=(STATIC/name).read_text(encoding='utf-8')
            if path == '/login' and (qs.get('error') or [''])[0]:
                template=template.replace('<div id="msg"></div>','<div id="msg"><div class="notice error">E-mail ou senha inválidos.</div></div>')
            return self.send_text(template)
        if path.startswith('/static/'):
            target = STATIC / path[len('/static/'):]
            if not target.exists() or not target.is_file(): return self.send_text('Not found',404,'text/plain')
            ctype='text/plain; charset=utf-8'
            if target.suffix=='.css': ctype='text/css; charset=utf-8'
            elif target.suffix=='.js': ctype='application/javascript; charset=utf-8'
            elif target.suffix=='.svg': ctype='image/svg+xml'
            return self.send_text(target.read_text(encoding='utf-8'),200,ctype)
        if path == '/api/health': return self.send_json({'ok':True,'version':'v19','database':'postgresql' if str(DB_PATH).startswith(('postgres://','postgresql://')) else 'sqlite'})
        if path == '/api/session':
            with connect(DB_PATH) as conn:
                s=self._session(conn)
                if not s: return self.send_json({'ok':False,'authenticated':False})
                return self.send_json({'ok':True,'authenticated':True,'user':{'id':s['user_id'],'name':s['name'],'email':s['email'],'role':s['role'],'campaign_id':s['campaign_id'],'client_name':s['client_name'],'client_logo_image':s['client_logo_image']},'csrf':s['csrf']})
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
                                  c.name campaign_name,c.reward_name,c.goal,c.icon,c.code,c.logo_image,
                                  cu.name customer_name,co.name company_name,co.primary_color,co.logo_text
                                  FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id JOIN companies co ON co.id=c.company_id
                                  WHERE m.public_id=?''',(public_id,)).fetchone()
                if not m: return self.send_json({'ok':False,'error':'card_not_found'},404)
                data=rowdict(m)
                data['card_code']=f'CLUBE:{m["public_id"]}'
                data['qr_value']=data['card_code']
                data['apple_link']=apple_pass_link(public_id)
                data['google_link']=google_wallet_link(public_id)
                return self.send_json({'ok':True,'card':data,'wallet':wallet_status()})
        if path == '/api/qr':
            value=(qs.get('data') or [''])[0]
            if not value or len(value)>300: return self.send_text('bad qr data',400,'text/plain')
            img=qrcode.make(value)
            bio=io.BytesIO(); img.save(bio,format='PNG'); data=bio.getvalue()
            self.send_response(200); self.send_header('Content-Type','image/png'); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(data); return
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
                    c['smtp_password_enc']=None
                    c['brevo_api_key_enc']=None
                    c['whatsapp_access_token_enc']=None
                staff=[rowdict(r) for r in conn.execute('''SELECT u.id,u.name,u.email,u.role,u.active,u.created_at,u.campaign_id,c.name client_name FROM users u LEFT JOIN campaigns c ON c.id=u.campaign_id WHERE u.company_id=? ORDER BY u.role,u.name''',(cid,)).fetchall()]
                return self.send_json({'ok':True,'metrics':metrics,'campaigns':campaigns,'staff':staff})
        if path == '/api/attendant/recent':
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn,'attendant')
                if not s: return
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                tx=[rowdict(r) for r in conn.execute('''SELECT t.id,t.type,t.value,t.previous_progress,t.new_progress,t.rewards_delta,t.created_at,cu.name customer_name,c.name campaign_name,u.name user_name
                   FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id LEFT JOIN users u ON u.id=t.user_id
                   WHERE c.id=? AND c.company_id=? ORDER BY t.id DESC LIMIT 50''',(s['campaign_id'],s['company_id'])).fetchall()]
                return self.send_json({'ok':True,'transactions':tx,'client':{'id':s['campaign_id'],'name':s['client_name']}})
        if path == '/api/attendant/customers':
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn,'attendant')
                if not s: return
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                customers=[rowdict(r) for r in conn.execute('''SELECT cu.id,cu.name,cu.email,cu.phone,cu.birth_date,cu.cpf,cu.created_at,m.public_id,m.progress,m.rewards_available
                    FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                    WHERE m.campaign_id=? ORDER BY cu.name''',(s['campaign_id'],)).fetchall()]
                month=datetime.now(ZoneInfo('America/Sao_Paulo')).month
                birthdays=[c for c in customers if c.get('birth_date') and len(c['birth_date'])>=10 and int(c['birth_date'][5:7])==month]
                birthdays.sort(key=lambda c: (int(c['birth_date'][8:10]), c['name'].lower()))
                return self.send_json({'ok':True,'customers':customers,'birthdays':birthdays,'month':month,'whatsapp_cloud':whatsapp_cloud_configured(whatsapp_config_for_client(conn,s['campaign_id'])),'whatsapp_configured':whatsapp_cloud_configured(whatsapp_config_for_client(conn,s['campaign_id'])),'email_configured':email_configured(email_config_for_client(conn,s['campaign_id']))})
        if path == '/api/attendant/lookup':
            token=(qs.get('token') or [''])[0].strip()
            if token.startswith('CLUBE:'): token=token[6:]
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn,'attendant')
                if not s: return
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                m=conn.execute('''SELECT m.*,cu.name customer_name,c.name campaign_name,c.reward_name,c.goal,c.icon,c.logo_image,c.company_id
                  FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?''',(token,token,s['company_id'],s['campaign_id'])).fetchone()
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                return self.send_json({'ok':True,'membership':rowdict(m)})
        return self.send_text('Not found',404,'text/plain')

    def do_POST(self):
        p=urllib.parse.urlparse(self.path); path=p.path
        print(f'[FORM] POST {path} ip={self._ip()} content_type={self.headers.get("Content-Type", "")}')
        try: payload, payload_kind=self._body_payload()
        except Exception:
            if path in ['/login','/join']:
                return self.send_redirect('/login?error=1' if path == '/login' else '/join?error=1')
            return self.send_json({'ok':False,'error':'invalid_json'},400)
        if path in ['/api/login','/login']:
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
            code=str(payload.get('campaign_code','')).upper().strip()
            name=str(payload.get('name','')).strip()[:80]
            email=normalize_email(payload.get('email'))
            phone=normalize_phone(payload.get('phone'))
            birth_date=normalize_birth_date(payload.get('birth_date'))
            cpf=normalize_cpf(payload.get('cpf'))
            if len(name)<2 or not email or not phone or not birth_date or not cpf:
                error='invalid_customer_data'
                if len(name)<2: error='invalid_name'
                elif not email: error='invalid_email'
                elif not phone: error='invalid_phone'
                elif not birth_date: error='invalid_birth_date'
                elif not cpf: error='invalid_cpf'
                return self.send_redirect('/join?campaign='+urllib.parse.quote(code or 'CAFE5')+'&error='+urllib.parse.quote(error)) if path=='/join' else self.send_json({'ok':False,'error':error},400)
            with connect(DB_PATH) as conn:
                c=conn.execute('SELECT * FROM campaigns WHERE code=? AND active=1',(code,)).fetchone()
                if not c:
                    return self.send_redirect('/join?campaign='+urllib.parse.quote(code or 'CAFE5')+'&error=campaign_not_found') if path=='/join' else self.send_json({'ok':False,'error':'campaign_not_found'},404)
                existing_customer=conn.execute('''SELECT cu.id FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                    WHERE m.campaign_id=? AND cu.cpf=? LIMIT 1''',(c['id'],cpf)).fetchone()
                customer_id=existing_customer['id'] if existing_customer else None
                if customer_id is None:
                    customer_id=insert_id(conn,'INSERT INTO customers(name,contact,email,phone,birth_date,cpf,created_at) VALUES(?,?,?,?,?,?,?)',
                        (name,email,email,phone,birth_date,cpf,now_ts()))
                else:
                    conn.execute('UPDATE customers SET name=?,contact=?,email=?,phone=?,birth_date=?,cpf=? WHERE id=?',
                        (name,email,email,phone,birth_date,cpf,customer_id))
                existing=conn.execute('SELECT public_id FROM memberships WHERE customer_id=? AND campaign_id=?',(customer_id,c['id'])).fetchone()
                if existing:
                    return self.send_redirect('/card?id='+urllib.parse.quote(existing['public_id'])) if path=='/join' else self.send_json({'ok':True,'public_id':existing['public_id'],'existing':True})
                public_id='mem_'+random_token(10); qr_token=random_token(24)
                conn.execute('INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)',(customer_id,c['id'],public_id,qr_token,now_ts()))
                print(f'[JOIN] CREATED public_id={public_id} campaign={code} name={name!r}')
                audit(conn,c['company_id'],None,'customer_join','membership',public_id,details=name,ip_address=self._ip())
                welcome_cfg=email_config_for_client(conn,c['id'])
                welcome_result=send_customer_welcome_email(name,email,c['name'],public_id,c,welcome_cfg)
                if welcome_result.get('sent'):
                    audit(conn,c['company_id'],None,'customer_welcome_email','membership',public_id,details=email,ip_address=self._ip())
                elif not welcome_result.get('skipped'):
                    print(f'[EMAIL] CUSTOMER_WELCOME_NOT_SENT public_id={public_id} reason={welcome_result.get("reason")}')
                return self.send_redirect('/card?id='+urllib.parse.quote(public_id)) if path=='/join' else self.send_json({'ok':True,'public_id':public_id,'existing':False,'welcome_email':welcome_result})
        if path == '/api/forgot-password':
            email=normalize_email(payload.get('email'))
            if not email:
                return self.send_json({'ok':False,'error':'invalid_email'},400)
            with connect(DB_PATH) as conn:
                u=conn.execute("SELECT id,company_id,email,role,active,campaign_id FROM users WHERE email=? AND active=1",(email,)).fetchone()
                # Não revelamos se o endereço existe. Para atendentes cadastrados, geramos uma senha temporária
                # e só substituímos o hash depois que o e-mail foi aceito pelo provedor de e-mail.
                if u and u['role']=='attendant':
                    temporary='Clube-'+random_token(9)[:12]
                    smtp_cfg=global_email_config()
                    result=send_password_recovery_email(email,temporary,smtp_cfg)
                    if not result.get('sent'):
                        return self.send_json({'ok':False,'error':result.get('reason','email_send_failed')},503)
                    conn.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(temporary),u['id']))
                    conn.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
                    audit(conn,u['company_id'],u['id'],'password_recovery','user',u['id'],details='temporary_password_emailed',ip_address=self._ip())
                return self.send_json({'ok':True,'message':'Enviamos sua senha para o e-mail cadastrado'})

        with connect(DB_PATH) as conn:
            s=self._require_auth(conn)
            if not s: return
            if not self._require_csrf(s,payload): return self.send_json({'ok':False,'error':'csrf_failed'},403)
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
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
                recipient=str(payload.get('recipient','')).strip()
                message=str(payload.get('message','')).strip()
                if not message or len(message)>4096: return self.send_json({'ok':False,'error':'invalid_message'},400)
                if recipient == 'all':
                    rows=conn.execute('''SELECT DISTINCT cu.id,cu.name,cu.phone FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                        WHERE m.campaign_id=? AND cu.phone IS NOT NULL AND cu.phone<>? ORDER BY cu.name''',(s['campaign_id'],'')).fetchall()
                else:
                    try: customer_id=int(recipient)
                    except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_recipient'},400)
                    rows=conn.execute('''SELECT DISTINCT cu.id,cu.name,cu.phone FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                        WHERE m.campaign_id=? AND cu.id=? AND cu.phone IS NOT NULL AND cu.phone<>?''',(s['campaign_id'],customer_id,'')).fetchall()
                if not rows: return self.send_json({'ok':False,'error':'no_recipients'},404)
                wa_cfg=whatsapp_config_for_client(conn,s['campaign_id'])
                cloud=whatsapp_cloud_configured(wa_cfg)
                results=[]
                for r in rows:
                    item={'customer_id':r['id'],'name':r['name'],'phone':r['phone'],'manual_url':whatsapp_link(r['phone'],message)}
                    if cloud:
                        try:
                            response=send_whatsapp_cloud(r['phone'],message,wa_cfg)
                            item['sent']=True
                            item['message_id']=((response.get('messages') or [{}])[0]).get('id')
                            audit(conn,s['company_id'],s['user_id'],'whatsapp_send','customer',r['id'],details='cloud_api',ip_address=self._ip())
                        except Exception as exc:
                            item['sent']=False
                            item['error']=str(exc)[:800]
                    else:
                        item['sent']=False
                        item['manual']=True
                    results.append(item)
                return self.send_json({'ok':True,'cloud_api':cloud,'integration_source':wa_cfg.get('source'),'results':results,'sent_count':sum(1 for x in results if x.get('sent'))})
            if path == '/api/attendant/email':
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
                if recipient == 'all':
                    rows=conn.execute('''SELECT DISTINCT cu.id,cu.name,cu.email FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                        WHERE m.campaign_id=? AND cu.email IS NOT NULL AND cu.email<>? ORDER BY cu.name''',(s['campaign_id'],'')).fetchall()
                else:
                    try: customer_id=int(recipient)
                    except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_recipient'},400)
                    rows=conn.execute('''SELECT DISTINCT cu.id,cu.name,cu.email FROM customers cu JOIN memberships m ON m.customer_id=cu.id
                        WHERE m.campaign_id=? AND cu.id=? AND cu.email IS NOT NULL AND cu.email<>?''',(s['campaign_id'],customer_id,'')).fetchall()
                if not rows: return self.send_json({'ok':False,'error':'no_recipients'},404)
                results=[]
                for r in rows:
                    result=send_campaign_email(r['email'],r['name'],message,image_data,subject=f'Clube Fidelidade • {s["client_name"] or "Mensagem"}',smtp_config=smtp_cfg)
                    results.append({'customer_id':r['id'],'name':r['name'],'email':r['email'],'sent':bool(result.get('sent')),'error':result.get('reason')})
                    audit(conn,s['company_id'],s['user_id'],'email_send','customer',r['id'],details='sent' if result.get('sent') else result.get('reason','failed'),ip_address=self._ip())
                return self.send_json({'ok':True,'results':results,'sent_count':sum(1 for x in results if x.get('sent'))})
            if path in ('/api/attendant/stamp','/api/attendant/stamp/remove','/api/attendant/redeem'):
                if s['role']!='attendant': return self.send_json({'ok':False,'error':'forbidden'},403)
                if not s['campaign_id']: return self.send_json({'ok':False,'error':'attendant_without_client'},403)
            if path == '/api/attendant/stamp':
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token
                qty=int(payload.get('quantity',1)); idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12); device=str(payload.get('device_id',''))[:100]
                try:
                    begin_write(conn)
                    dupe=conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone()
                    if dupe: return self.send_json({'ok':True,'duplicate':True,'transaction_id':dupe['id']})
                    m=fetchone_for_update(conn,'''SELECT m.*,c.goal,c.min_stamp_interval_sec,c.max_stamps_per_hour,c.max_stamps_per_attendant_day,c.company_id,c.name campaign_name,cu.name customer_name
                      FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?''',(token,token,s['company_id'],s['campaign_id']))
                    if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                    validate_stamp(conn,m,m,s,qty)
                    prev=m['progress']; rewards=0; new=prev
                    for _ in range(qty):
                        new += 1
                        if new >= m['goal']:
                            rewards += 1; new = 0
                    tx_id=insert_id(conn,'''INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,device_id,ip_address,created_at)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],'stamp',qty,prev,new,rewards,idem,device,self._ip(),now_ts()))
                    conn.execute('UPDATE memberships SET progress=?, rewards_available=rewards_available+? WHERE id=?',(new,rewards,m['id']))
                    audit(conn,s['company_id'],s['user_id'],'stamp','membership',m['public_id'],details=f'qty={qty};reward+={rewards}',ip_address=self._ip())
                    return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name'],'previous_progress':prev,'progress':new,'reward_added':rewards})
                except FraudError as e:
                    audit(conn,s['company_id'],s['user_id'],'stamp_blocked','membership',token,details=e.code,ip_address=self._ip())
                    return self.send_json({'ok':False,'error':e.code,'message':e.message,'requires_manager':e.requires_manager},409)
                except integrity_errors():
                    return self.send_json({'ok':False,'error':'duplicate_request'},409)
            if path == '/api/attendant/stamp/remove':
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token
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
                tx_id=insert_id(conn,'''INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],'adjustment',-1,prev,new,reward_delta,idem,self._ip(),'remoção manual de selo',now_ts()))
                conn.execute('UPDATE memberships SET progress=?, rewards_available=rewards_available+? WHERE id=?',(new,reward_delta,m['id']))
                audit(conn,s['company_id'],s['user_id'],'stamp_remove','membership',m['public_id'],details=f'progress={prev}->{new};reward={reward_delta}',ip_address=self._ip())
                return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name'],'previous_progress':prev,'progress':new,'reward_removed':1 if reward_delta<0 else 0})
            if path == '/api/attendant/redeem':
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token; idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12)
                begin_write(conn)
                if conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone(): return self.send_json({'ok':True,'duplicate':True})
                m=fetchone_for_update(conn,'''SELECT m.*,c.company_id,cu.name customer_name FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=? AND c.id=?''',(token,token,s['company_id'],s['campaign_id']))
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                if m['status']!='active': return self.send_json({'ok':False,'error':'membership_blocked'},409)
                if m['rewards_available']<1: return self.send_json({'ok':False,'error':'no_reward_available'},409)
                tx_id=insert_id(conn,'''INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],'redeem',1,m['progress'],m['progress'],-1,idem,self._ip(),now_ts()))
                conn.execute('UPDATE memberships SET rewards_available=rewards_available-1 WHERE id=?',(m['id'],))
                audit(conn,s['company_id'],s['user_id'],'reward_redeem','membership',m['public_id'],ip_address=self._ip())
                return self.send_json({'ok':True,'transaction_id':tx_id,'customer_name':m['customer_name']})
            if path == '/api/manager/campaign':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; reward=str(payload.get('reward_name','')).strip()[:100]; code=re.sub(r'[^A-Z0-9_-]','',str(payload.get('code','')).upper())[:24]
                icon=str(payload.get('icon','☕'))[:8]; goal=int(payload.get('goal',5))
                if not name or not reward or not code or goal not in (3,5,8,10,15): return self.send_json({'ok':False,'error':'invalid_campaign'},400)
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
                try:
                    smtp_password_enc=encrypt_secret(payload.get('smtp_password')) if payload.get('smtp_password') else None
                    brevo_api_key_enc=encrypt_secret(payload.get('brevo_api_key')) if payload.get('brevo_api_key') else None
                    wa_token_enc=encrypt_secret(payload.get('whatsapp_access_token')) if payload.get('whatsapp_access_token') else None
                except RuntimeError as exc:
                    return self.send_json({'ok':False,'error':str(exc)},503)
                wa_status='connected' if (wa_phone_id and wa_token_enc) else ('awaiting_connection' if wa_mode=='embedded' else 'not_connected')
                try:
                    new_id=insert_id(conn,'''INSERT INTO campaigns(company_id,code,name,reward_name,goal,icon,logo_image,min_stamp_interval_sec,max_stamps_per_hour,max_stamps_per_attendant_day,
                        smtp_host,smtp_port,smtp_user,smtp_password_enc,smtp_from,smtp_from_name,smtp_security,email_provider,brevo_api_key_enc,brevo_sender_email,brevo_sender_name,brevo_reply_to,
                        whatsapp_phone_number_id,whatsapp_waba_id,whatsapp_access_token_enc,whatsapp_api_version,whatsapp_integration_mode,whatsapp_signup_status,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(
                        s['company_id'],code,name,reward,goal,icon,logo_image,int(payload.get('min_interval',60)),int(payload.get('max_hour',6)),int(payload.get('max_day',500)),
                        smtp_host,smtp_port,smtp_user,smtp_password_enc,smtp_from,smtp_from_name,smtp_security,email_provider,brevo_api_key_enc,brevo_sender_email,brevo_sender_name,brevo_reply_to,
                        wa_phone_id,wa_waba_id,wa_token_enc,wa_version,wa_mode,wa_status,now_ts()))
                except integrity_errors(): return self.send_json({'ok':False,'error':'campaign_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'campaign_create','campaign',new_id,details=code,ip_address=self._ip())
                return self.send_json({'ok':True,'campaign_id':new_id})
            if path == '/api/manager/campaign/update':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                name=str(payload.get('name','')).strip()[:80]; reward=str(payload.get('reward_name','')).strip()[:100]; code=re.sub(r'[^A-Z0-9_-]','',str(payload.get('code','')).upper())[:24]
                icon=str(payload.get('icon','☕'))[:8]
                try: goal=int(payload.get('goal',5)); min_interval=int(payload.get('min_interval',60)); max_hour=int(payload.get('max_hour',6)); max_day=int(payload.get('max_day',500))
                except (TypeError,ValueError): return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                if campaign_id<1 or not name or not reward or not code or goal not in (3,5,8,10,15) or min_interval<0 or max_hour<1 or max_day<1:
                    return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                c=conn.execute('SELECT * FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone()
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
                    conn.execute('''UPDATE campaigns SET code=?,name=?,reward_name=?,goal=?,icon=?,logo_image=?,min_stamp_interval_sec=?,max_stamps_per_hour=?,max_stamps_per_attendant_day=?,
                        smtp_host=?,smtp_port=?,smtp_user=?,smtp_password_enc=?,smtp_from=?,smtp_from_name=?,smtp_security=?,email_provider=?,brevo_api_key_enc=?,brevo_sender_email=?,brevo_sender_name=?,brevo_reply_to=?,
                        whatsapp_phone_number_id=?,whatsapp_waba_id=?,whatsapp_access_token_enc=?,whatsapp_api_version=?,whatsapp_integration_mode=?,whatsapp_signup_status=?
                        WHERE id=? AND company_id=?''',(code,name,reward,goal,icon,logo_image,min_interval,max_hour,max_day,
                        smtp_host,smtp_port,smtp_user,smtp_password_enc,smtp_from,smtp_from_name,smtp_security,email_provider,brevo_api_key_enc,brevo_sender_email,brevo_sender_name,brevo_reply_to,
                        wa_phone_id,wa_waba_id,wa_token_enc,wa_version,wa_mode,'connected' if (wa_phone_id and wa_token_enc) else ('awaiting_connection' if wa_mode=='embedded' else 'not_connected'),campaign_id,s['company_id']))
                except integrity_errors(): return self.send_json({'ok':False,'error':'campaign_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'campaign_update','campaign',campaign_id,details=code,ip_address=self._ip())
                return self.send_json({'ok':True,'campaign_id':campaign_id})
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
            if path == '/api/manager/staff':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; email=str(payload.get('email','')).lower().strip()[:120]; password=str(payload.get('password','')).strip()
                configured_admin=os.environ.get('CLUBE_ADMIN_EMAIL','').strip().lower()
                if configured_admin and email == configured_admin:
                    return self.send_json({'ok':False,'error':'admin_email_reserved'},409)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                if len(name)<2 or '@' not in email or len(password)<10 or campaign_id<1: return self.send_json({'ok':False,'error':'invalid_staff'},400)
                client=conn.execute('SELECT id,name FROM campaigns WHERE id=? AND company_id=? AND active=1',(campaign_id,s['company_id'])).fetchone()
                if not client: return self.send_json({'ok':False,'error':'client_not_found'},404)
                try:
                    new_id=insert_id(conn,'INSERT INTO users(company_id,name,email,password_hash,role,campaign_id,created_at) VALUES(?,?,?,?,?,?,?)',(s['company_id'],name,email,hash_password(password),'attendant',campaign_id,now_ts()))
                except integrity_errors(): return self.send_json({'ok':False,'error':'email_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'staff_create','user',new_id,details=f'{email}:attendant:client={campaign_id}',ip_address=self._ip())
                smtp_cfg=global_email_config()
                email_result=send_attendant_welcome_email(name,email,password,client['name'],smtp_cfg)
                audit(conn,s['company_id'],s['user_id'],'staff_welcome_email','user',new_id,details='sent' if email_result.get('sent') else email_result.get('reason','failed'),ip_address=self._ip())
                return self.send_json({'ok':True,'user_id':new_id,'client_name':client['name'],'welcome_email':email_result})
            if path == '/api/manager/campaign/delete':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                c=conn.execute('SELECT id,name,code FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone()
                if not c: return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                linked_staff=conn.execute("SELECT COUNT(*) n FROM users WHERE campaign_id=? AND role='attendant'",(campaign_id,)).fetchone()['n']
                if linked_staff: return self.send_json({'ok':False,'error':'client_has_attendants','linked_attendants':linked_staff},409)
                members=conn.execute('SELECT COUNT(*) n FROM memberships WHERE campaign_id=?',(campaign_id,)).fetchone()['n']
                audit(conn,s['company_id'],s['user_id'],'client_delete','campaign',campaign_id,details=f"{c['code']};members={members}",ip_address=self._ip())
                conn.execute('DELETE FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id']))
                # Remove clientes que ficaram sem nenhum cartão após a exclusão do cliente.
                conn.execute('DELETE FROM customers WHERE id NOT IN (SELECT DISTINCT customer_id FROM memberships)')
                return self.send_json({'ok':True,'deleted_campaign_id':campaign_id,'deleted_memberships':members})
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
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token; status='blocked' if payload.get('blocked',True) else 'active'
                m=conn.execute('''SELECT m.* FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=?''',(token,token,s['company_id'])).fetchone()
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                conn.execute('UPDATE memberships SET status=? WHERE id=?',(status,m['id']))
                ttype='block' if status=='blocked' else 'unblock'
                conn.execute('''INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],ttype,0,m['progress'],m['progress'],0,self._ip(),'manager action',now_ts()))
                audit(conn,s['company_id'],s['user_id'],ttype,'membership',m['public_id'],ip_address=self._ip())
                return self.send_json({'ok':True,'status':status})
            return self.send_json({'ok':False,'error':'not_found'},404)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--host',default=os.environ.get('HOST','0.0.0.0')); parser.add_argument('--port',type=int,default=int(os.environ.get('PORT','8000'))); parser.add_argument('--init-only',action='store_true'); args=parser.parse_args()
    init_db(DB_PATH,seed=True)
    ensure_configured_staff(DB_PATH)
    if args.init_only:
        print(f'Database initialized: {DB_PATH}'); return
    srv=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f'Clube Fidelidade v30 em http://{args.host}:{args.port}')
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally: srv.server_close()

if __name__=='__main__': main()
