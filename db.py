import os
import sqlite3
from contextlib import contextmanager
from security import hash_password, random_token, now_ts

DEFAULT_DB = os.environ.get('CLUBE_DB_PATH', os.path.join(os.path.dirname(__file__), 'data.sqlite3'))

SCHEMA = '''
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS companies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  primary_color TEXT NOT NULL DEFAULT '#4A2B1B',
  logo_text TEXT NOT NULL DEFAULT 'CLUBE CAFÉ',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('manager','attendant')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  reward_name TEXT NOT NULL,
  goal INTEGER NOT NULL CHECK(goal BETWEEN 1 AND 50),
  icon TEXT NOT NULL DEFAULT '☕',
  active INTEGER NOT NULL DEFAULT 1,
  min_stamp_interval_sec INTEGER NOT NULL DEFAULT 60,
  max_stamps_per_hour INTEGER NOT NULL DEFAULT 6,
  max_stamps_per_attendant_day INTEGER NOT NULL DEFAULT 500,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  contact TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  public_id TEXT NOT NULL UNIQUE,
  qr_token TEXT NOT NULL UNIQUE,
  progress INTEGER NOT NULL DEFAULT 0,
  rewards_available INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked')),
  created_at INTEGER NOT NULL,
  UNIQUE(customer_id, campaign_id)
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  type TEXT NOT NULL CHECK(type IN ('stamp','redeem','adjustment','block','unblock')),
  value INTEGER NOT NULL,
  previous_progress INTEGER NOT NULL,
  new_progress INTEGER NOT NULL,
  rewards_delta INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT UNIQUE,
  device_id TEXT,
  ip_address TEXT,
  note TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER,
  user_id INTEGER,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  details TEXT,
  ip_address TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tx_membership_time ON transactions(membership_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memberships_campaign ON memberships(campaign_id);
'''

@contextmanager
def connect(db_path=DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path=DEFAULT_DB, seed=True):
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        if seed:
            count = conn.execute('SELECT COUNT(*) c FROM companies').fetchone()['c']
            if count == 0:
                ts = now_ts()
                cur = conn.execute('INSERT INTO companies(name,slug,primary_color,logo_text,created_at) VALUES(?,?,?,?,?)',
                                   ('Café Taboo','cafe-taboo','#5A321F','CLUBE CAFÉ',ts))
                company_id = cur.lastrowid
                conn.execute('INSERT INTO users(company_id,name,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)',
                             (company_id,'Gerente Demo','gerente@demo.local',hash_password('Gerente123!'),'manager',ts))
                conn.execute('INSERT INTO users(company_id,name,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)',
                             (company_id,'Atendente Demo','atendente@demo.local',hash_password('Atendente123!'),'attendant',ts))
                conn.execute('''INSERT INTO campaigns(company_id,code,name,reward_name,goal,icon,min_stamp_interval_sec,max_stamps_per_hour,max_stamps_per_attendant_day,created_at)
                                VALUES(?,?,?,?,?,?,?,?,?,?)''',
                             (company_id,'CAFE5','Clube Café','1 café grátis',5,'☕',60,6,500,ts))


def create_session(conn, user_id: int, ttl=8*60*60):
    token = random_token(32)
    csrf = random_token(24)
    ts = now_ts()
    conn.execute('INSERT INTO sessions(token,user_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?)',
                 (token,user_id,csrf,ts+ttl,ts))
    return token, csrf


def get_session(conn, token: str):
    if not token:
        return None
    row = conn.execute('''SELECT s.token,s.csrf,s.expires_at,u.id user_id,u.company_id,u.name,u.email,u.role,u.active
                          FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?''',(token,)).fetchone()
    if not row or row['expires_at'] < now_ts() or not row['active']:
        return None
    return row


def audit(conn, company_id, user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None):
    conn.execute('''INSERT INTO audit_log(company_id,user_id,action,entity_type,entity_id,details,ip_address,created_at)
                    VALUES(?,?,?,?,?,?,?,?)''',
                 (company_id,user_id,action,entity_type,str(entity_id) if entity_id is not None else None,details,ip_address,now_ts()))
