import argparse
import html
import io
import json
import os
import re
import sqlite3
import urllib.parse
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import qrcode

from db import DEFAULT_DB, init_db, connect, create_session, get_session, audit
from security import verify_password, hash_password, random_token, now_ts
from antifraud import validate_stamp, FraudError
from wallet import wallet_status, apple_pass_link, google_wallet_link

BASE = Path(__file__).resolve().parent
STATIC = BASE / 'static'
DB_PATH = os.environ.get('CLUBE_DB_PATH', DEFAULT_DB)
SESSION_COOKIE = 'clube_session'


def jdump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def rowdict(row):
    return dict(row) if row else None


class Handler(BaseHTTPRequestHandler):
    server_version = 'ClubeFidelidade/1.0'

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
        if n > 1_000_000:
            raise ValueError('body_too_large')
        raw = self.rfile.read(n) if n else b'{}'
        return json.loads(raw.decode('utf-8') or '{}')

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
        if path in ['/login','/manager','/attendant','/join','/card']:
            name = path.strip('/') + '.html'
            return self.send_text((STATIC/name).read_text(encoding='utf-8'))
        if path.startswith('/static/'):
            target = STATIC / path[len('/static/'):]
            if not target.exists() or not target.is_file(): return self.send_text('Not found',404,'text/plain')
            ctype='text/plain; charset=utf-8'
            if target.suffix=='.css': ctype='text/css; charset=utf-8'
            elif target.suffix=='.js': ctype='application/javascript; charset=utf-8'
            elif target.suffix=='.svg': ctype='image/svg+xml'
            return self.send_text(target.read_text(encoding='utf-8'),200,ctype)
        if path == '/api/health': return self.send_json({'ok':True,'version':'v1'})
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
                if not c: return self.send_json({'ok':False,'error':'campaign_not_found'},404)
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
                data['qr_value']=f'CLUBE:{m["qr_token"]}'
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
                  FROM memberships m JOIN customers cu ON cu.id=m.customer_id JOIN campaigns c ON c.id=m.campaign_id WHERE m.qr_token=? AND c.company_id=?''',(token,s['company_id'])).fetchone()
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                return self.send_json({'ok':True,'membership':rowdict(m)})
        return self.send_text('Not found',404,'text/plain')

    def do_POST(self):
        p=urllib.parse.urlparse(self.path); path=p.path
        try: payload=self._body_json()
        except Exception: return self.send_json({'ok':False,'error':'invalid_json'},400)
        if path == '/api/login':
            email=str(payload.get('email','')).lower().strip(); password=str(payload.get('password',''))
            with connect(DB_PATH) as conn:
                u=conn.execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
                if not u or not verify_password(password,u['password_hash']):
                    audit(conn,u['company_id'] if u else None,u['id'] if u else None,'login_failed',details=email,ip_address=self._ip())
                    return self.send_json({'ok':False,'error':'invalid_credentials'},401)
                token,csrf=create_session(conn,u['id']); audit(conn,u['company_id'],u['id'],'login_success',ip_address=self._ip())
                cookie=f'{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800'
                if os.environ.get('CLUBE_SECURE_COOKIE','0')=='1': cookie+='; Secure'
                return self.send_json({'ok':True,'role':u['role'],'csrf':csrf},200,{'Set-Cookie':cookie})
        if path == '/api/logout':
            with connect(DB_PATH) as conn:
                token=self._session_token(); s=self._session(conn)
                if token: conn.execute('DELETE FROM sessions WHERE token=?',(token,))
                if s: audit(conn,s['company_id'],s['user_id'],'logout',ip_address=self._ip())
            return self.send_json({'ok':True},200,{'Set-Cookie':f'{SESSION_COOKIE}=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Strict'})
        if path == '/api/join':
            code=str(payload.get('campaign_code','')).upper().strip(); name=str(payload.get('name','')).strip()[:80]; contact=str(payload.get('contact','')).strip()[:120]
            if len(name)<2: return self.send_json({'ok':False,'error':'invalid_name'},400)
            with connect(DB_PATH) as conn:
                c=conn.execute('SELECT * FROM campaigns WHERE code=? AND active=1',(code,)).fetchone()
                if not c: return self.send_json({'ok':False,'error':'campaign_not_found'},404)
                customer_id=None
                if contact:
                    existing=conn.execute('''SELECT cu.id FROM customers cu JOIN memberships m ON m.customer_id=cu.id WHERE m.campaign_id=? AND cu.contact=?''',(c['id'],contact)).fetchone()
                    if existing: customer_id=existing['id']
                if customer_id is None:
                    customer_id=conn.execute('INSERT INTO customers(name,contact,created_at) VALUES(?,?,?)',(name,contact or None,now_ts())).lastrowid
                existing=conn.execute('SELECT public_id FROM memberships WHERE customer_id=? AND campaign_id=?',(customer_id,c['id'])).fetchone()
                if existing: return self.send_json({'ok':True,'public_id':existing['public_id'],'existing':True})
                public_id='mem_'+random_token(10); qr_token=random_token(24)
                conn.execute('INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)',(customer_id,c['id'],public_id,qr_token,now_ts()))
                audit(conn,c['company_id'],None,'customer_join','membership',public_id,details=name,ip_address=self._ip())
                return self.send_json({'ok':True,'public_id':public_id,'existing':False})
        with connect(DB_PATH) as conn:
            s=self._require_auth(conn)
            if not s: return
            if not self._require_csrf(s,payload): return self.send_json({'ok':False,'error':'csrf_failed'},403)
            if path == '/api/attendant/stamp':
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token
                qty=int(payload.get('quantity',1)); idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12); device=str(payload.get('device_id',''))[:100]
                try:
                    conn.execute('BEGIN IMMEDIATE')
                    dupe=conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone()
                    if dupe: return self.send_json({'ok':True,'duplicate':True,'transaction_id':dupe['id']})
                    m=conn.execute('''SELECT m.*,c.goal,c.min_stamp_interval_sec,c.max_stamps_per_hour,c.max_stamps_per_attendant_day,c.company_id,c.name campaign_name,cu.name customer_name
                      FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE m.qr_token=? AND c.company_id=?''',(token,s['company_id'])).fetchone()
                    if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                    validate_stamp(conn,m,m,s,qty)
                    prev=m['progress']; rewards=0; new=prev
                    for _ in range(qty):
                        new += 1
                        if new >= m['goal']:
                            rewards += 1; new = 0
                    cur=conn.execute('''INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,device_id,ip_address,created_at)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],'stamp',qty,prev,new,rewards,idem,device,self._ip(),now_ts()))
                    conn.execute('UPDATE memberships SET progress=?, rewards_available=rewards_available+? WHERE id=?',(new,rewards,m['id']))
                    audit(conn,s['company_id'],s['user_id'],'stamp','membership',m['public_id'],details=f'qty={qty};reward+={rewards}',ip_address=self._ip())
                    return self.send_json({'ok':True,'transaction_id':cur.lastrowid,'customer_name':m['customer_name'],'previous_progress':prev,'progress':new,'reward_added':rewards})
                except FraudError as e:
                    audit(conn,s['company_id'],s['user_id'],'stamp_blocked','membership',token,details=e.code,ip_address=self._ip())
                    return self.send_json({'ok':False,'error':e.code,'message':e.message,'requires_manager':e.requires_manager},409)
                except sqlite3.IntegrityError:
                    return self.send_json({'ok':False,'error':'duplicate_request'},409)
            if path == '/api/attendant/redeem':
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token; idem=str(payload.get('idempotency_key','')).strip()[:100] or random_token(12)
                conn.execute('BEGIN IMMEDIATE')
                if conn.execute('SELECT id FROM transactions WHERE idempotency_key=?',(idem,)).fetchone(): return self.send_json({'ok':True,'duplicate':True})
                m=conn.execute('''SELECT m.*,c.company_id,cu.name customer_name FROM memberships m JOIN campaigns c ON c.id=m.campaign_id JOIN customers cu ON cu.id=m.customer_id WHERE m.qr_token=? AND c.company_id=?''',(token,s['company_id'])).fetchone()
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                if m['status']!='active': return self.send_json({'ok':False,'error':'membership_blocked'},409)
                if m['rewards_available']<1: return self.send_json({'ok':False,'error':'no_reward_available'},409)
                cur=conn.execute('''INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],'redeem',1,m['progress'],m['progress'],-1,idem,self._ip(),now_ts()))
                conn.execute('UPDATE memberships SET rewards_available=rewards_available-1 WHERE id=?',(m['id'],))
                audit(conn,s['company_id'],s['user_id'],'reward_redeem','membership',m['public_id'],ip_address=self._ip())
                return self.send_json({'ok':True,'transaction_id':cur.lastrowid,'customer_name':m['customer_name']})
            if path == '/api/manager/campaign':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; reward=str(payload.get('reward_name','')).strip()[:100]; code=re.sub(r'[^A-Z0-9_-]','',str(payload.get('code','')).upper())[:24]
                icon=str(payload.get('icon','☕'))[:8]; goal=int(payload.get('goal',5))
                if not name or not reward or not code or goal<1 or goal>50: return self.send_json({'ok':False,'error':'invalid_campaign'},400)
                try:
                    cur=conn.execute('''INSERT INTO campaigns(company_id,code,name,reward_name,goal,icon,min_stamp_interval_sec,max_stamps_per_hour,max_stamps_per_attendant_day,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?)''',(s['company_id'],code,name,reward,goal,icon,int(payload.get('min_interval',60)),int(payload.get('max_hour',6)),int(payload.get('max_day',500)),now_ts()))
                except sqlite3.IntegrityError: return self.send_json({'ok':False,'error':'campaign_code_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'campaign_create','campaign',cur.lastrowid,details=code,ip_address=self._ip())
                return self.send_json({'ok':True,'campaign_id':cur.lastrowid})
            if path == '/api/manager/staff':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                name=str(payload.get('name','')).strip()[:80]; email=str(payload.get('email','')).lower().strip()[:120]; password=str(payload.get('password','')); role=str(payload.get('role','attendant'))
                if role not in ('manager','attendant') or len(name)<2 or '@' not in email or len(password)<10: return self.send_json({'ok':False,'error':'invalid_staff'},400)
                try:
                    cur=conn.execute('INSERT INTO users(company_id,name,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)',(s['company_id'],name,email,hash_password(password),role,now_ts()))
                except sqlite3.IntegrityError: return self.send_json({'ok':False,'error':'email_exists'},409)
                audit(conn,s['company_id'],s['user_id'],'staff_create','user',cur.lastrowid,details=f'{email}:{role}',ip_address=self._ip())
                return self.send_json({'ok':True,'user_id':cur.lastrowid})
            if path == '/api/manager/block':
                if s['role']!='manager': return self.send_json({'ok':False,'error':'forbidden'},403)
                token=str(payload.get('token','')).strip(); token=token[6:] if token.startswith('CLUBE:') else token; status='blocked' if payload.get('blocked',True) else 'active'
                m=conn.execute('''SELECT m.* FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.qr_token=? AND c.company_id=?''',(token,s['company_id'])).fetchone()
                if not m: return self.send_json({'ok':False,'error':'membership_not_found'},404)
                conn.execute('UPDATE memberships SET status=? WHERE id=?',(status,m['id']))
                ttype='block' if status=='blocked' else 'unblock'
                conn.execute('''INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)''',(m['id'],s['user_id'],ttype,0,m['progress'],m['progress'],0,self._ip(),'manager action',now_ts()))
                audit(conn,s['company_id'],s['user_id'],ttype,'membership',m['public_id'],ip_address=self._ip())
                return self.send_json({'ok':True,'status':status})
            return self.send_json({'ok':False,'error':'not_found'},404)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--host',default='127.0.0.1'); parser.add_argument('--port',type=int,default=8000); parser.add_argument('--init-only',action='store_true'); args=parser.parse_args()
    init_db(DB_PATH,seed=True)
    if args.init_only:
        print(f'Database initialized: {DB_PATH}'); return
    srv=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f'Clube Fidelidade v1 em http://{args.host}:{args.port}')
    print('Gerente demo: gerente@demo.local / Gerente123!')
    print('Atendente demo: atendente@demo.local / Atendente123!')
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally: srv.server_close()

if __name__=='__main__': main()
