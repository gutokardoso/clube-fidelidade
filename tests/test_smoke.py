import os, tempfile, unittest

class PlatformRegression(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix='.sqlite3'); os.close(fd)
        import db
        db.init_db(self.path,seed=True)
        self.db=db

    def tearDown(self):
        try: os.remove(self.path)
        except OSError: pass

    def test_version_and_latest_migration(self):
        import server
        self.assertEqual(server.VERSION,'v179')
        with self.db.connect(self.path) as c:
            self.assertIsNotNone(c.execute("SELECT version FROM schema_migrations WHERE version='v179'").fetchone())

    def test_performance_indexes_exist(self):
        with self.db.connect(self.path) as c:
            names={r['name'] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
        for name in ('idx_memberships_campaign_status','idx_transactions_membership_type_time','idx_purchase_records_membership_time','idx_customers_phone_hash','idx_customers_cpf_hash'):
            self.assertIn(name,names)

    def test_seed_auth_passwords_are_hashed_and_verify(self):
        from security import verify_password
        with self.db.connect(self.path) as c:
            manager=c.execute("SELECT * FROM users WHERE email='gerente@demo.local'").fetchone()
            attendant=c.execute("SELECT * FROM users WHERE email='atendente@demo.local'").fetchone()
        self.assertTrue(verify_password('Gerente123!',manager['password_hash']))
        self.assertTrue(verify_password('Atendente123!',attendant['password_hash']))
        self.assertNotEqual(manager['password_hash'],'Gerente123!')

    def test_tenant_memberships_are_isolated_by_campaign(self):
        with self.db.connect(self.path) as c:
            campaign=c.execute('SELECT id FROM campaigns ORDER BY id LIMIT 1').fetchone()['id']
            self.assertEqual(c.execute('SELECT COUNT(*) n FROM memberships WHERE campaign_id=?',(campaign,)).fetchone()['n'],0)
            self.assertEqual(c.execute('SELECT COUNT(*) n FROM memberships WHERE campaign_id=?',(999999,)).fetchone()['n'],0)

    def test_bulk_intelligence_returns_all_requested_members(self):
        from intelligence import customer_intelligence_bulk
        from db import insert_id, now_ts
        with self.db.connect(self.path) as c:
            cid=c.execute('SELECT id FROM campaigns ORDER BY id LIMIT 1').fetchone()['id']; ts=now_ts()
            customer=insert_id(c,"INSERT INTO customers(name,email,created_at) VALUES(?,?,?)",('Teste','teste@example.com',ts))
            mid=insert_id(c,"INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)",(customer,cid,'mem_test','qr_test',ts))
            out=customer_intelligence_bulk(c,[{'id':mid,'created_at':ts,'progress':0,'points_balance':0,'rewards_available':0,'goal':5}],{'id':cid,'loyalty_type':'stamps'})
            self.assertIn(mid,out); self.assertIn('segment',out[mid]); self.assertIn('days_since_last',out[mid])

    def test_worker_entrypoint_is_available(self):
        import worker
        self.assertTrue(callable(worker.main))

if __name__=='__main__': unittest.main()
