import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from db import init_db, connect, ensure_configured_staff
from security import verify_password
from antifraud import validate_stamp, FraudError
from server import normalize_email, normalize_phone, normalize_cpf, normalize_birth_date, send_attendant_welcome_email, send_campaign_email, send_password_recovery_email

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.NamedTemporaryFile(suffix='.sqlite3',delete=False); self.tmp.close(); self.db=self.tmp.name
        init_db(self.db,seed=True)
    def tearDown(self):
        try: os.unlink(self.db)
        except OSError: pass
    def test_seed_login_users(self):
        with connect(self.db) as c:
            u=c.execute("SELECT * FROM users WHERE email='gerente@demo.local'").fetchone()
            self.assertEqual(u['role'],'manager'); self.assertTrue(verify_password('Gerente123!',u['password_hash']))
    def test_campaign_goal(self):
        with connect(self.db) as c:
            camp=c.execute("SELECT * FROM campaigns WHERE code='CAFE5'").fetchone(); self.assertEqual(camp['goal'],5)
    def test_attendant_is_bound_to_client(self):
        with connect(self.db) as c:
            u=c.execute("SELECT * FROM users WHERE role='attendant'").fetchone()
            camp=c.execute("SELECT * FROM campaigns WHERE code='CAFE5'").fetchone()
            self.assertEqual(u['campaign_id'], camp['id'])

    def test_manager_has_global_scope(self):
        with connect(self.db) as c:
            u=c.execute("SELECT * FROM users WHERE role='manager'").fetchone()
            self.assertIsNone(u['campaign_id'])

    def test_antifraud_blocks_fast_second_stamp(self):
        import time
        with connect(self.db) as c:
            customer=c.execute("INSERT INTO customers(name,created_at) VALUES('Teste',?)",(int(time.time()),)).lastrowid
            camp=c.execute("SELECT * FROM campaigns WHERE code='CAFE5'").fetchone()
            mid=c.execute("INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)",(customer,camp['id'],'mem-test','tok-test',int(time.time()))).lastrowid
            m=c.execute('SELECT * FROM memberships WHERE id=?',(mid,)).fetchone()
            user0=c.execute("SELECT * FROM users WHERE role='attendant'").fetchone(); user=dict(user0); user['user_id']=user0['id']
            c.execute("INSERT INTO transactions(membership_id,user_id,type,value,previous_progress,new_progress,rewards_delta,created_at) VALUES(?,?,?,?,?,?,?,?)",(mid,user0['id'],'stamp',1,0,1,0,int(time.time())))
            with self.assertRaises(FraudError) as ctx: validate_stamp(c,m,camp,user,1)
            self.assertEqual(ctx.exception.code,'too_fast')

    def test_configured_manager_password_is_resynced(self):
        old_email=os.environ.get('CLUBE_ADMIN_EMAIL'); old_password=os.environ.get('CLUBE_ADMIN_PASSWORD'); old_name=os.environ.get('CLUBE_ADMIN_NAME')
        try:
            os.environ['CLUBE_ADMIN_EMAIL']='gerente@demo.local'
            os.environ['CLUBE_ADMIN_PASSWORD']='NovaSenhaGerente123!'
            os.environ['CLUBE_ADMIN_NAME']='Gerente Atualizado'
            ensure_configured_staff(self.db)
            with connect(self.db) as c:
                u=c.execute("SELECT * FROM users WHERE email='gerente@demo.local'").fetchone()
                self.assertEqual(u['role'],'manager')
                self.assertTrue(verify_password('NovaSenhaGerente123!',u['password_hash']))
                self.assertFalse(verify_password('Gerente123!',u['password_hash']))
        finally:
            for key,val in [('CLUBE_ADMIN_EMAIL',old_email),('CLUBE_ADMIN_PASSWORD',old_password),('CLUBE_ADMIN_NAME',old_name)]:
                if val is None: os.environ.pop(key,None)
                else: os.environ[key]=val

    def test_admin_role_cannot_be_demoted_by_bootstrap_collision(self):
        keys=['CLUBE_ADMIN_EMAIL','CLUBE_ADMIN_PASSWORD','CLUBE_ADMIN_NAME','CLUBE_ATTENDANT_EMAIL','CLUBE_ATTENDANT_PASSWORD','CLUBE_ATTENDANT_NAME']
        old={k:os.environ.get(k) for k in keys}
        try:
            # Simula banco legado em que o gerente foi indevidamente salvo como atendente.
            with connect(self.db) as c:
                camp=c.execute("SELECT id FROM campaigns WHERE code='CAFE5'").fetchone()
                c.execute("UPDATE users SET role='attendant',campaign_id=? WHERE email='gerente@demo.local'",(camp['id'],))
            os.environ['CLUBE_ADMIN_EMAIL']='gerente@demo.local'
            os.environ['CLUBE_ADMIN_PASSWORD']='SenhaGerenteCorreta123!'
            os.environ['CLUBE_ADMIN_NAME']='Administrador Taboo'
            # Mesmo se o bootstrap de atendente tiver sido configurado por engano com o mesmo e-mail,
            # o perfil administrativo deve prevalecer.
            os.environ['CLUBE_ATTENDANT_EMAIL']='gerente@demo.local'
            os.environ['CLUBE_ATTENDANT_PASSWORD']='SenhaAtendente123!'
            os.environ['CLUBE_ATTENDANT_NAME']='Atendente Incorreto'
            ensure_configured_staff(self.db)
            with connect(self.db) as c:
                u=c.execute("SELECT * FROM users WHERE email='gerente@demo.local'").fetchone()
                self.assertEqual(u['role'],'manager')
                self.assertIsNone(u['campaign_id'])
                self.assertTrue(verify_password('SenhaGerenteCorreta123!',u['password_hash']))
        finally:
            for k,v in old.items():
                if v is None: os.environ.pop(k,None)
                else: os.environ[k]=v

    def test_customer_registration_validators(self):
        self.assertEqual(normalize_email(' Pessoa@Exemplo.COM '), 'pessoa@exemplo.com')
        self.assertIsNone(normalize_email('email-invalido'))
        self.assertEqual(normalize_phone('(11) 99999-9999'), '5511999999999')
        self.assertIsNone(normalize_phone('(11) 3333-4444'))
        self.assertEqual(normalize_cpf('529.982.247-25'), '52998224725')
        self.assertIsNone(normalize_cpf('111.111.111-11'))
        self.assertEqual(normalize_birth_date('1990-08-12'), '1990-08-12')
        self.assertIsNone(normalize_birth_date('2999-01-01'))

    def test_customer_schema_v19_fields(self):
        with connect(self.db) as c:
            cols={r['name'] for r in c.execute('PRAGMA table_info(customers)').fetchall()}
            for name in ('email','phone','birth_date','cpf'):
                self.assertIn(name, cols)


    def test_attendant_welcome_email_content(self):
        from unittest.mock import patch
        old={k:os.environ.get(k) for k in ('CLUBE_SMTP_HOST','CLUBE_SMTP_PORT','CLUBE_SMTP_FROM','CLUBE_SMTP_SECURITY','CLUBE_LOGIN_URL')}
        sent=[]
        class FakeSMTP:
            def __init__(self,*a,**k): pass
            def __enter__(self): return self
            def __exit__(self,*a): return False
            def ehlo(self): pass
            def starttls(self,context=None): pass
            def login(self,*a): pass
            def send_message(self,msg): sent.append(msg)
        try:
            os.environ['CLUBE_SMTP_HOST']='smtp.test.local'
            os.environ['CLUBE_SMTP_PORT']='587'
            os.environ['CLUBE_SMTP_FROM']='taboo@example.com'
            os.environ['CLUBE_SMTP_SECURITY']='starttls'
            os.environ['CLUBE_LOGIN_URL']='https://clube-fidelidade-production.up.railway.app/login'
            with patch('server.smtplib.SMTP',FakeSMTP):
                result=send_attendant_welcome_email('Atendente','atendente@example.com','SenhaInicial123!','Cliente Teste')
            self.assertTrue(result['sent']); self.assertEqual(len(sent),1)
            body=sent[0].get_content()
            self.assertIn('Cadastro realizado com sucesso!',body)
            self.assertIn('https://clube-fidelidade-production.up.railway.app/login',body)
            self.assertIn('E-mail: atendente@example.com',body)
            self.assertIn('Senha: SenhaInicial123!',body)
        finally:
            for k,v in old.items():
                if v is None: os.environ.pop(k,None)
                else: os.environ[k]=v

    def test_attendant_welcome_email_without_smtp(self):
        old_host=os.environ.pop('CLUBE_SMTP_HOST',None); old_from=os.environ.pop('CLUBE_SMTP_FROM',None)
        try:
            result=send_attendant_welcome_email('A','a@example.com','Senha123456!','Cliente')
            self.assertFalse(result['sent']); self.assertEqual(result['reason'],'smtp_not_configured')
        finally:
            if old_host is not None: os.environ['CLUBE_SMTP_HOST']=old_host
            if old_from is not None: os.environ['CLUBE_SMTP_FROM']=old_from

    def test_campaign_email_with_image(self):
        from unittest.mock import patch
        import base64
        old={k:os.environ.get(k) for k in ('CLUBE_SMTP_HOST','CLUBE_SMTP_PORT','CLUBE_SMTP_FROM','CLUBE_SMTP_SECURITY')}
        sent=[]
        class FakeSMTP:
            def __init__(self,*a,**k): pass
            def __enter__(self): return self
            def __exit__(self,*a): return False
            def ehlo(self): pass
            def starttls(self,context=None): pass
            def login(self,*a): pass
            def send_message(self,msg): sent.append(msg)
        try:
            os.environ['CLUBE_SMTP_HOST']='smtp.test.local'; os.environ['CLUBE_SMTP_PORT']='587'; os.environ['CLUBE_SMTP_FROM']='taboo@example.com'; os.environ['CLUBE_SMTP_SECURITY']='starttls'
            tiny='data:image/png;base64,'+base64.b64encode(b'fakepng').decode()
            with patch('server.smtplib.SMTP',FakeSMTP): result=send_campaign_email('cliente@example.com','Cliente','Promoção teste',tiny)
            self.assertTrue(result['sent']); self.assertEqual(len(sent),1); self.assertTrue(sent[0].is_multipart())
        finally:
            for k,v in old.items():
                if v is None: os.environ.pop(k,None)
                else: os.environ[k]=v

    def test_password_recovery_email_content(self):
        from unittest.mock import patch
        old={k:os.environ.get(k) for k in ('CLUBE_SMTP_HOST','CLUBE_SMTP_PORT','CLUBE_SMTP_FROM','CLUBE_SMTP_SECURITY')}
        sent=[]
        class FakeSMTP:
            def __init__(self,*a,**k): pass
            def __enter__(self): return self
            def __exit__(self,*a): return False
            def ehlo(self): pass
            def starttls(self,context=None): pass
            def login(self,*a): pass
            def send_message(self,msg): sent.append(msg)
        try:
            os.environ['CLUBE_SMTP_HOST']='smtp.test.local'; os.environ['CLUBE_SMTP_PORT']='587'; os.environ['CLUBE_SMTP_FROM']='taboo@example.com'; os.environ['CLUBE_SMTP_SECURITY']='starttls'
            with patch('server.smtplib.SMTP',FakeSMTP): result=send_password_recovery_email('atendente@example.com','Clube-Temp123')
            self.assertTrue(result['sent']); self.assertIn('Clube-Temp123',sent[0].get_content())
        finally:
            for k,v in old.items():
                if v is None: os.environ.pop(k,None)
                else: os.environ[k]=v

    def test_brevo_api_email_send(self):
        from unittest.mock import patch
        import io, json
        old={k:os.environ.get(k) for k in ('BREVO_API_KEY','BREVO_SENDER_EMAIL','BREVO_SENDER_NAME','CLUBE_SMTP_HOST','CLUBE_SMTP_FROM')}
        captured={}
        class FakeResp:
            def __enter__(self): return self
            def __exit__(self,*a): return False
            def read(self): return b'{"messageId":"msg-test-123"}'
        def fake_urlopen(req,timeout=20):
            captured['url']=req.full_url; captured['headers']=dict(req.header_items()); captured['body']=json.loads(req.data.decode('utf-8')); return FakeResp()
        try:
            os.environ['BREVO_API_KEY']='xkeysib-test'
            os.environ['BREVO_SENDER_EMAIL']='clube@example.com'
            os.environ['BREVO_SENDER_NAME']='Clube Fidelidade'
            os.environ.pop('CLUBE_SMTP_HOST',None); os.environ.pop('CLUBE_SMTP_FROM',None)
            with patch('server.urllib.request.urlopen',fake_urlopen):
                result=send_attendant_welcome_email('Atendente','destino@example.com','SenhaInicial123!','Cliente Teste')
            self.assertTrue(result['sent']); self.assertEqual(result['source'],'brevo_api')
            self.assertEqual(captured['url'],'https://api.brevo.com/v3/smtp/email')
            self.assertEqual(captured['body']['sender']['email'],'clube@example.com')
            self.assertEqual(captured['body']['to'][0]['email'],'destino@example.com')
            self.assertIn('Senha: SenhaInicial123!',captured['body']['textContent'])
        finally:
            for k,v in old.items():
                if v is None: os.environ.pop(k,None)
                else: os.environ[k]=v

if __name__=='__main__': unittest.main()
