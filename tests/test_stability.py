import http.client
import json
import os
import re
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PlatformStability(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix='.sqlite3')
        os.close(fd)
        import db
        db.init_db(self.path, seed=True)
        self.db = db

    def tearDown(self):
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_expected_core_tables_and_foreign_keys(self):
        expected = {
            'companies', 'users', 'campaigns', 'customers', 'memberships',
            'transactions', 'sessions', 'audit_log', 'message_queue',
            'schema_migrations', 'auth_challenges'
        }
        with self.db.connect(self.path) as conn:
            tables = {r['name'] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            self.assertTrue(expected.issubset(tables), expected - tables)
            self.assertEqual(conn.execute('PRAGMA foreign_keys').fetchone()[0], 1)

    def test_seed_users_have_valid_roles_and_unique_emails(self):
        with self.db.connect(self.path) as conn:
            users = conn.execute('SELECT email,role,password_hash FROM users').fetchall()
        self.assertGreaterEqual(len(users), 2)
        self.assertEqual(len({u['email'].lower() for u in users}), len(users))
        self.assertTrue(all(u['role'] in ('manager','attendant') for u in users))
        self.assertTrue(all(u['password_hash'] and '$' in u['password_hash'] for u in users))

    def test_public_static_references_exist(self):
        missing = []
        for html_path in (ROOT / 'static').glob('*.html'):
            text = html_path.read_text(encoding='utf-8')
            for value in re.findall(r'''(?:href|src)=["']([^"']+)["']''', text):
                clean = value.split('?', 1)[0].split('#', 1)[0]
                if clean.startswith('/static/'):
                    target = ROOT / clean.lstrip('/')
                    if not target.exists():
                        missing.append((html_path.name, clean))
        self.assertEqual(missing, [])

    def test_critical_public_pages_are_routed(self):
        source = (ROOT / 'server.py').read_text(encoding='utf-8')
        for path in ('/login','/manager','/attendant','/card','/rewards','/help','/privacy','/terms','/security'):
            self.assertIn(path, source)

    def _serve(self):
        import server
        server.DB_PATH = self.path
        server.persistent_rate_reset('unused')
        srv = server.SentryHTTPServer(('127.0.0.1', 0), server.Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        return server, srv, thread

    def test_2fa_api_without_challenge_returns_401_instead_of_dropping_connection(self):
        server, srv, thread = self._serve()
        try:
            conn = http.client.HTTPConnection('127.0.0.1', srv.server_port, timeout=5)
            body = json.dumps({'code':'123456'})
            conn.request('POST','/api/login/2fa',body=body,headers={'Content-Type':'application/json','Content-Length':str(len(body))})
            response = conn.getresponse()
            payload = json.loads(response.read().decode('utf-8'))
            self.assertEqual(response.status, 401)
            self.assertEqual(payload.get('error'), 'two_factor_challenge_invalid')
            conn.close()
        finally:
            srv.shutdown(); srv.server_close(); thread.join(timeout=3)

    def test_2fa_html_without_challenge_redirects_to_login(self):
        server, srv, thread = self._serve()
        try:
            conn = http.client.HTTPConnection('127.0.0.1', srv.server_port, timeout=5)
            body = 'code=123456'
            conn.request('POST','/login/2fa',body=body,headers={'Content-Type':'application/x-www-form-urlencoded','Content-Length':str(len(body))})
            response = conn.getresponse(); response.read()
            self.assertEqual(response.status, 303)
            self.assertEqual(response.getheader('Location'), '/login?error=2fa_expired')
            conn.close()
        finally:
            srv.shutdown(); srv.server_close(); thread.join(timeout=3)

    def test_direct_2fa_page_without_challenge_redirects_to_login(self):
        server, srv, thread = self._serve()
        try:
            conn = http.client.HTTPConnection('127.0.0.1', srv.server_port, timeout=5)
            conn.request('GET','/login/2fa')
            response = conn.getresponse(); response.read()
            self.assertEqual(response.status, 303)
            self.assertEqual(response.getheader('Location'), '/login?error=2fa_expired')
            conn.close()
        finally:
            srv.shutdown(); srv.server_close(); thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
