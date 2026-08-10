import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from db import init_db, connect, ensure_configured_staff
from security import verify_password
from antifraud import validate_stamp, FraudError

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

if __name__=='__main__': unittest.main()
