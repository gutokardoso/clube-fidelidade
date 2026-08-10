import argparse
import base64
import binascii
import html
import hmac
import io
import json
import os
import re
import urllib.parse
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

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


def validate_logo_data(value):
    """Aceita apenas PNG/JPEG/WEBP em data URL, até 500 KB decodificados."""
    value = str(value or '').strip()
    if not value:
        return None
    m = re.fullmatch(r'data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=\r\n]+)', value, re.I)
    if not m:
        raise ValueError('invalid_logo_format')
    try:
        raw = base64.b64decode(m.group(2), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('invalid_logo_format')
    if len(raw) > 500_000:
        raise ValueError('logo_too_large')
    mime = m.group(1).lower()
    # Assinaturas mínimas para impedir conteúdo arbitrário disfarçado de imagem.
    valid = (mime == 'png' and raw.startswith(b'\x89PNG\r\n\x1a\n')) or \
            (mime == 'jpeg' and raw.startswith(b'\xff\xd8\xff')) or \
            (mime == 'webp' and raw.startswith(b'RIFF') and raw[8:12] == b'WEBP')
    if not valid:
        raise ValueError('invalid_logo_format')
    return f'data:image/{mime};base64,' + base64.b64encode(raw).decode('ascii')


class Handler(BaseHTTPRequestHandler):
    server_version = 'ClubeFidelidade/9.0'

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
                    logo_block = '<img class="campaign-logo" src="' + html.escape(str(c['logo_image']), quote=True) + '" alt="Logo da campanha">'
                else:
                    logo_block = '<div class="brand campaign-logo-fallback">' + html.escape(str(c['logo_text'])) + '</div>'
                template=template.replace('{{LOGO_BLOCK}}',logo_block).replace('{{CAMPAIGN_NAME}}',html.escape(str(c['name']))).replace('{{CAMPAIGN_DESC}}',html.escape(f"Complete {c['goal']} selos e ganhe {c['reward_name']}."))
                template=template.replace('name="campaign_code" value="CAFE5"',f'name="campaign_code" value="{html.escape(code)}"')
                template=template.replace('</head>',f"<style>:root{{--accent:{html.escape(str(c['primary_color']))}}}</style></head>")
                if (qs.get('error') or [''])[0]:
                    template=template.replace('<div id="msg"></div>','<div id="msg"><div class="notice error">Não foi possível criar o cartão. Confira os dados e tente novamente.</div></div>')
            else:
                template=template.replace('{{LOGO_BLOCK}}','<div class="brand campaign-logo-fallback">CLUBE</div>').replace('{{CAMPAIGN_NAME}}','Campanha não encontrada').replace('{{CAMPAIGN_DESC}}','Confira o QR Code ou fale com o estabelecimento.').replace('<form id="f" class="form">','<form id="f" class="form hidden">')
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
        if path == '/api/health': return self.send_json({'ok':True,'version':'v9','database':'postgresql' if str(DB_PATH).startswith(('postgres://','postgresql://')) else 'sqlite'})
        if path == '/api/session':
            with connect(DB_PATH) as conn:
                s=self._session(conn)
                if not s: return self.send_json({'ok':False,'authenticated':False})
                return self.send_json({'ok':True,'authenticated':True,'user':{'id':s['user_id'],'name':s['name'],'email':s['email'],'role':s['role']},'csrf':s['csrf']})
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
                                  c.name campaign_name,c.reward_name,c.goal,c.icon,c.code,
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
                campaigns=[rowdict(r) for r in conn.execute('SELECT * FROM campaigns WHERE company_id=? ORDER BY id DESC',(cid,)).fetchall()]
                staff=[rowdict(r) for r in conn.execute('SELECT id,name,email,role,active,created_at FROM users WHERE company_id=? ORDER BY role,name',(cid,)).fetchall()]
                tx=[rowdict(r) for r in conn.execute('''SELECT t.id,t.type,t.value,t.previous_progress,t.new_progress,t.rewards_delta,t.note,t.created_at,u.name user_name,cu.name customer_name,c.name campaign_name
                   FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id LEFT JOIN users u ON u.id=t.user_id
                   WHERE c.company_id=? ORDER BY t.id DESC LIMIT 30''',(cid,)).fetchall()]
                return self.send_json({'ok':True,'metrics':metrics,'campaigns':campaigns,'staff':staff,'transactions':tx})
        if path == '/api/attendant/recent':
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn)
                if not s: return
                tx=[rowdict(r) for r in conn.execute('''SELECT t.id,t.type,t.value,t.created_at,cu.name customer_name,c.name campaign_name
                   FROM transactions t JOIN memberships m ON m.id=t.membership_id JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id
                   WHERE t.user_id=? ORDER BY t.id DESC LIMIT 15''',(s['user_id'],)).fetchall()]
                return self.send_json({'ok':True,'transactions':tx})
        if path == '/api/attendant/lookup':
            token=(qs.get('token') or [''])[0].strip()
            if token.startswith('CLUBE:'): token=token[6:]
            with connect(DB_PATH) as conn:
                s=self._require_auth(conn)
                if not s: return
                m=conn.execute('''SELECT m.*,cu.name customer_name,c.name campaign_name,c.reward_name,c.goal,c.icon,c.company_id
                  FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=?''',(token,token,s['company_id'])).fetchone()
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
                # Em produção, as credenciais do Railway são a fonte de verdade para os perfis bootstrap.
                # Se o hash persistido estiver defasado, uma senha que bate exatamente com a variável
                # de ambiente repara o hash no primeiro login, sem expor a senha nos logs.
                if u and not password_ok:
                    configured = []
                    admin_email=os.environ.get('CLUBE_ADMIN_EMAIL','').strip().lower()
                    admin_password=os.environ.get('CLUBE_ADMIN_PASSWORD','').strip()
                    attendant_email=os.environ.get('CLUBE_ATTENDANT_EMAIL','').strip().lower()
                    attendant_password=os.environ.get('CLUBE_ATTENDANT_PASSWORD','').strip()
                    if admin_email and admin_password: configured.append((admin_email,admin_password,'manager','ADMIN'))
                    if attendant_email and attendant_password: configured.append((attendant_email,attendant_password,'attendant','ATTENDANT'))
                    for cfg_email,cfg_password,cfg_role,cfg_label in configured:
                        if email == cfg_email and hmac.compare_digest(password,cfg_password):
                            conn.execute('UPDATE users SET password_hash=?,role=?,active=1 WHERE id=?',(hash_password(cfg_password),cfg_role,u['id']))
                            u=conn.execute('SELECT * FROM users WHERE id=?',(u['id'],)).fetchone()
                            password_ok=True
                            print(f'[AUTH] {cfg_label}_LOGIN_REPAIRED email={email} password_length={len(cfg_password)}')
                            break
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
            code=str(payload.get('campaign_code','')).upper().strip(); name=str(payload.get('name','')).strip()[:80]; contact=str(payload.get('contact','')).strip()[:120]
            if len(name)<2:
                return self.send_redirect('/join?campaign='+urllib.parse.quote(code or 'CAFE5')+'&error=1') if path=='/join' else self.send_json({'ok':False,'error':'invalid_name'},400)
            with connect(DB_PATH) as conn:
                c=conn.execute('SELECT * FROM campaigns WHERE code=? AND active=1',(code,)).fetchone()
                if not c:
                    return self.send_redirect('/join?campaign='+urllib.parse.quote(code or 'CAFE5')+'&error=1') if path=='/join' else self.send_json({'ok':False,'error':'campaign_not_found'},404)
                customer_id=None
                if contact:
                    existing=conn.execute('''SELECT cu.id FROM customers cu JOIN memberships m ON m.customer_id=cu.id WHERE m.campaign_id=? AND cu.contact=?''',(c['id'],contact)).fetchone()
                    if existing: customer_id=existing['id']
                if customer_id is None:
                    customer_id=insert_id(conn,'INSERT INTO customers(name,contact,created_at) VALUES(?,?,?)',(name,contact or None,now_ts()))
                existing=conn.execute('SELECT public_id FROM memberships WHERE customer_id=? AND campaign_id=?',(customer_id,c['id'])).fetchone()
                if existing:
                    return self.send_redirect('/card?id='+urllib.parse.quote(existing['public_id'])) if path=='/join' else self.send_json({'ok':True,'public_id':existing['public_id'],'existing':True})
                public_id='mem_'+random_token(10); qr_token=random_token(24)
                conn.execute('INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)',(customer_id,c['id'],public_id,qr_token,now_ts()))
                print(f'[JOIN] CREATED public_id={public_id} campaign={code} name={name!r}')
                audit(conn,c['company_id'],None,'customer_join','membership',public_id,details=name,ip_address=self._ip())
                return self.send_redirect('/card?id='+urllib.parse.quote(public_id)) if path=='/join' else self.send_json({'ok':True,'public_id':public_id,'existing':False})
        with connect(DB_PATH) as conn:
            s=self._require_auth(conn)
            if not s: return
            if not self._require_csrf(s,payload): return self.send_json({'ok':False,'error':'csrf_failed'},403)
            if path == '/api/attendant/stamp':
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token
                qty=int(payload.get('quantity',1)); idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12); device=str(payload.get('device_id',''))[:100]
                try:
                    begin_write(conn)
                    dupe=conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone()
                    if dupe: return self.send_json({'ok':True,'duplicate':True,'transaction_id':dupe['id']})
                    m=fetchone_for_update(conn,'''SELECT m.*,c.goal,c.min_stamp_interval_sec,c.max_stamps_per_hour,c.max_stamps_per_attendant_day,c.company_id,c.name campaign_name,cu.name customer_name
                      FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=?''',(token,token,s['company_id']))
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
            if path == '/api/attendant/redeem':
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token; idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12)
                begin_write(conn)
                if conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone(): return self.send_json({'ok':True,'duplicate':True})
                m=fetchone_for_update(conn,'''SELECT m.*,c.company_id,cu.name customer_name FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE (m.public_id=? OR m.qr_token=?) AND c.company_id=?''',(token,token,s['company_id']))
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
                if not name or not reward or not code or goal<1 or goal>50: return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                try:
                    logo_image=validate_logo_data(payload.get('logo_image'))
                    if not logo_image:
                        return self.send_json({'ok':False,'error':'logo_required'},400)
                except ValueError as exc:
                    return self.send_json({'ok':False,'error':str(exc)},400)
                try:
                    new_id=insert_id(conn,'''INSERT INTO campaigns(company_id,code,name,reward_name,goal,icon,logo_image,min_stamp_interval_sec,max_stamps_per_hour,max_stamps_per_attendant_day,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(s['company_id'],code,name,reward,goal,icon,logo_image,int(payload.get('min_interval',60)),int(payload.get('max_hour',6)),int(payload.get('max_day',500)),now_ts()))
                except integrity_errors(): return self.send_json({'ok':False,'error':'campaign_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'campaign_create','campaign',new_id,details=code,ip_address=self._ip())
                return self.send_json({'ok':True,'campaign_id':new_id})
            if path == '/api/manager/staff':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; email=str(payload.get('email','')).lower().strip()[:120]; password=str(payload.get('password','')).strip(); role=str(payload.get('role','attendant'))
                if role not in ('manager','attendant') or len(name)<2 or '@' not in email or len(password)<10: return self.send_json({'ok':False,'error':'invalid_staff'},400)
                try:
                    new_id=insert_id(conn,'INSERT INTO users(company_id,name,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)',(s['company_id'],name,email,hash_password(password),role,now_ts()))
                except integrity_errors(): return self.send_json({'ok':False,'error':'email_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'staff_create','user',new_id,details=f'{email}:{role}',ip_address=self._ip())
                return self.send_json({'ok':True,'user_id':new_id})
            if path == '/api/manager/campaign/delete':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                try: campaign_id=int(payload.get('campaign_id',0))
                except (TypeError,ValueError): campaign_id=0
                c=conn.execute('SELECT id,name,code FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id'])).fetchone()
                if not c: return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                members=conn.execute('SELECT COUNT(*) n FROM memberships WHERE campaign_id=?',(campaign_id,)).fetchone()['n']
                audit(conn,s['company_id'],s['user_id'],'campaign_delete','campaign',campaign_id,details=f"{c['code']};members={members}",ip_address=self._ip())
                conn.execute('DELETE FROM campaigns WHERE id=? AND company_id=?',(campaign_id,s['company_id']))
                # Remove clientes que ficaram sem nenhum cartão após a exclusão da campanha.
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
    print(f'Clube Fidelidade v9 em http://{args.host}:{args.port}')
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally: srv.server_close()

if __name__=='__main__': main()
