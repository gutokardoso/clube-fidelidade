import os,tempfile,unittest
class Smoke(unittest.TestCase):
 def test_db_init_and_version(self):
  fd,path=tempfile.mkstemp(suffix='.sqlite3');os.close(fd)
  try:
   import db; db.init_db(path,seed=False)
   with db.connect(path) as c:
    self.assertIsNotNone(c.execute("SELECT version FROM schema_migrations WHERE version='v178'").fetchone())
   import server; self.assertEqual(server.VERSION,'v178')
  finally:
   try:os.remove(path)
   except OSError:pass
if __name__=='__main__':unittest.main()
