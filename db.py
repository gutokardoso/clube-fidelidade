import os
import sqlite3
from contextlib import contextmanager
from security import hash_password, verify_password, random_token, now_ts

DEFAULT_DB = os.environ.get('CLUBE_DB_PATH', os.path.join(os.path.dirname(__file__), 'data.sqlite3'))
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()

SQLITE_SCHEMA = '''
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
  is_client_admin INTEGER NOT NULL DEFAULT 0,
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
  logo_image TEXT,
  card_theme TEXT NOT NULL DEFAULT 'green',
  loyalty_type TEXT NOT NULL DEFAULT 'stamps',
  points_spend_cents INTEGER NOT NULL DEFAULT 200,
  cashback_percent REAL NOT NULL DEFAULT 0,
  points_expiry_days INTEGER NOT NULL DEFAULT 0,
  referral_bonus_points INTEGER NOT NULL DEFAULT 0,
  referee_bonus_points INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  min_stamp_interval_sec INTEGER NOT NULL DEFAULT 0,
  max_stamps_per_hour INTEGER NOT NULL DEFAULT 0,
  max_stamps_per_attendant_day INTEGER NOT NULL DEFAULT 500,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  contact TEXT,
  email TEXT,
  phone TEXT,
  birth_date TEXT,
  cpf TEXT,
  privacy_accepted_at INTEGER,
  marketing_email INTEGER NOT NULL DEFAULT 0,
  marketing_whatsapp INTEGER NOT NULL DEFAULT 0,
  marketing_accepted_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  public_id TEXT NOT NULL UNIQUE,
  qr_token TEXT NOT NULL UNIQUE,
  progress INTEGER NOT NULL DEFAULT 0,
  points_balance INTEGER NOT NULL DEFAULT 0,
  cashback_balance_cents INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS message_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER REFERENCES campaigns(id) ON DELETE CASCADE, kind TEXT NOT NULL, recipient TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, available_at INTEGER NOT NULL, created_at INTEGER NOT NULL, sent_at INTEGER
);
CREATE TABLE IF NOT EXISTS automation_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, rule_type TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'email', enabled INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(campaign_id,rule_type)
);
CREATE TABLE IF NOT EXISTS automation_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL REFERENCES automation_rules(id) ON DELETE CASCADE, membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, period_key TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(rule_id,membership_id,period_key)
);
CREATE TABLE IF NOT EXISTS wallet_registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, device_library_id TEXT NOT NULL, push_token TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(membership_id,device_library_id)
);
CREATE INDEX IF NOT EXISTS idx_tx_membership_time ON transactions(membership_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memberships_campaign ON memberships(campaign_id);
CREATE TABLE IF NOT EXISTS reward_catalog (
  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT, points_cost INTEGER NOT NULL, image_data TEXT, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reward_catalog_campaign ON reward_catalog(campaign_id, active, points_cost);
'''

POSTGRES_SCHEMA = '''
CREATE TABLE IF NOT EXISTS companies (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  primary_color TEXT NOT NULL DEFAULT '#4A2B1B',
  logo_text TEXT NOT NULL DEFAULT 'CLUBE CAFÉ',
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('manager','attendant')),
  active INTEGER NOT NULL DEFAULT 1,
  is_client_admin INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  reward_name TEXT NOT NULL,
  goal INTEGER NOT NULL CHECK(goal BETWEEN 1 AND 50),
  icon TEXT NOT NULL DEFAULT '☕',
  logo_image TEXT,
  card_theme TEXT NOT NULL DEFAULT 'green',
  loyalty_type TEXT NOT NULL DEFAULT 'stamps',
  points_spend_cents INTEGER NOT NULL DEFAULT 200,
  cashback_percent REAL NOT NULL DEFAULT 0,
  points_expiry_days INTEGER NOT NULL DEFAULT 0,
  referral_bonus_points INTEGER NOT NULL DEFAULT 0,
  referee_bonus_points INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  min_stamp_interval_sec INTEGER NOT NULL DEFAULT 0,
  max_stamps_per_hour INTEGER NOT NULL DEFAULT 0,
  max_stamps_per_attendant_day INTEGER NOT NULL DEFAULT 500,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  contact TEXT,
  email TEXT,
  phone TEXT,
  birth_date TEXT,
  cpf TEXT,
  privacy_accepted_at BIGINT,
  marketing_email INTEGER NOT NULL DEFAULT 0,
  marketing_whatsapp INTEGER NOT NULL DEFAULT 0,
  marketing_accepted_at BIGINT,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  id BIGSERIAL PRIMARY KEY,
  customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  public_id TEXT NOT NULL UNIQUE,
  qr_token TEXT NOT NULL UNIQUE,
  progress INTEGER NOT NULL DEFAULT 0,
  points_balance INTEGER NOT NULL DEFAULT 0,
  cashback_balance_cents INTEGER NOT NULL DEFAULT 0,
  rewards_available INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked')),
  created_at BIGINT NOT NULL,
  UNIQUE(customer_id, campaign_id)
);
CREATE TABLE IF NOT EXISTS transactions (
  id BIGSERIAL PRIMARY KEY,
  membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  type TEXT NOT NULL CHECK(type IN ('stamp','redeem','adjustment','block','unblock')),
  value INTEGER NOT NULL,
  previous_progress INTEGER NOT NULL,
  new_progress INTEGER NOT NULL,
  rewards_delta INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT UNIQUE,
  device_id TEXT,
  ip_address TEXT,
  note TEXT,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT,
  user_id BIGINT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  details TEXT,
  ip_address TEXT,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS message_queue (
  id BIGSERIAL PRIMARY KEY, campaign_id BIGINT REFERENCES campaigns(id) ON DELETE CASCADE, kind TEXT NOT NULL, recipient TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, available_at BIGINT NOT NULL, created_at BIGINT NOT NULL, sent_at BIGINT
);
CREATE TABLE IF NOT EXISTS automation_rules (
  id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, rule_type TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'email', enabled INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(campaign_id,rule_type)
);
CREATE TABLE IF NOT EXISTS automation_runs (
  id BIGSERIAL PRIMARY KEY, rule_id BIGINT NOT NULL REFERENCES automation_rules(id) ON DELETE CASCADE, membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, period_key TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(rule_id,membership_id,period_key)
);
CREATE TABLE IF NOT EXISTS wallet_registrations (
  id BIGSERIAL PRIMARY KEY, membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, device_library_id TEXT NOT NULL, push_token TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(membership_id,device_library_id)
);
CREATE INDEX IF NOT EXISTS idx_tx_membership_time ON transactions(membership_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memberships_campaign ON memberships(campaign_id);
CREATE TABLE IF NOT EXISTS reward_catalog (
  id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT, points_cost INTEGER NOT NULL, image_data TEXT, active INTEGER NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reward_catalog_campaign ON reward_catalog(campaign_id, active, points_cost);
'''


def _is_postgres(db_path=None):
    target = (db_path or DATABASE_URL or '').lower()
    return target.startswith('postgres://') or target.startswith('postgresql://')


def using_postgres(db_path=None):
    return _is_postgres(db_path)


class PgConnection:
    def __init__(self, conn):
        self._conn = conn

    @staticmethod
    def _sql(sql):
        # O projeto usa placeholders DB-API '?'. PostgreSQL/psycopg usa '%s'.
        return sql.replace('?', '%s')

    def execute(self, sql, params=()):
        return self._conn.execute(self._sql(sql), params)

    def executescript(self, script):
        for statement in script.split(';'):
            if statement.strip():
                self._conn.execute(statement)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


@contextmanager
def connect(db_path=None):
    target = db_path or DATABASE_URL or DEFAULT_DB
    if _is_postgres(target):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError('PostgreSQL configurado, mas psycopg não está instalado. Execute pip install -r requirements.txt.') from exc
        raw = psycopg.connect(target, row_factory=dict_row)
        conn = PgConnection(raw)
    else:
        raw = sqlite3.connect(target)
        raw.row_factory = sqlite3.Row
        raw.execute('PRAGMA foreign_keys = ON')
        conn = raw
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def integrity_errors():
    errors = [sqlite3.IntegrityError]
    try:
        import psycopg
        errors.append(psycopg.IntegrityError)
    except ImportError:
        pass
    return tuple(errors)


def insert_id(conn, sql, params=()):
    if isinstance(conn, PgConnection):
        cur = conn.execute(sql.rstrip().rstrip(';') + ' RETURNING id', params)
        return cur.fetchone()['id']
    cur = conn.execute(sql, params)
    return cur.lastrowid


def begin_write(conn):
    # SQLite ganha lock de escrita cedo; PostgreSQL já abre transação implicitamente.
    if isinstance(conn, PgConnection):
        return
    conn.execute('BEGIN IMMEDIATE')


def fetchone_for_update(conn, sql, params=()):
    # Em PostgreSQL bloqueia o registro até commit/rollback para impedir dois caixas
    # de creditarem/resgatarem simultaneamente o mesmo cartão.
    if isinstance(conn, PgConnection):
        sql = sql.rstrip().rstrip(';') + ' FOR UPDATE'
    return conn.execute(sql, params).fetchone()


def init_db(db_path=None, seed=True):
    target = db_path or DATABASE_URL or DEFAULT_DB
    with connect(target) as conn:
        conn.executescript(POSTGRES_SCHEMA if _is_postgres(target) else SQLITE_SCHEMA)
        # Migração v9: campanhas existentes ganham campo opcional de logo.
        if _is_postgres(target):
            conn.execute('ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS logo_image TEXT')
        else:
            cols = [r['name'] for r in conn.execute('PRAGMA table_info(campaigns)').fetchall()]
            if 'logo_image' not in cols:
                conn.execute('ALTER TABLE campaigns ADD COLUMN logo_image TEXT')
        # Migração v18: cadastro completo do cliente final.
        if _is_postgres(target):
            conn.execute('ALTER TABLE customers ADD COLUMN IF NOT EXISTS email TEXT')
            conn.execute('ALTER TABLE customers ADD COLUMN IF NOT EXISTS phone TEXT')
            conn.execute('ALTER TABLE customers ADD COLUMN IF NOT EXISTS birth_date TEXT')
            conn.execute('ALTER TABLE customers ADD COLUMN IF NOT EXISTS cpf TEXT')
        else:
            customer_cols = [r['name'] for r in conn.execute('PRAGMA table_info(customers)').fetchall()]
            for col in ('email','phone','birth_date','cpf'):
                if col not in customer_cols:
                    conn.execute(f'ALTER TABLE customers ADD COLUMN {col} TEXT')

        # Migração v42: permissões por cliente, LGPD, fila, automações e Wallet.
        if _is_postgres(target):
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_client_admin INTEGER NOT NULL DEFAULT 0")
            for col,typ,default in [('privacy_accepted_at','BIGINT','NULL'),('marketing_email','INTEGER','0'),('marketing_whatsapp','INTEGER','0'),('marketing_accepted_at','BIGINT','NULL')]:
                conn.execute(f"ALTER TABLE customers ADD COLUMN IF NOT EXISTS {col} {typ} DEFAULT {default}")
        else:
            ucols={r['name'] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
            if 'is_client_admin' not in ucols: conn.execute("ALTER TABLE users ADD COLUMN is_client_admin INTEGER NOT NULL DEFAULT 0")
            ccols={r['name'] for r in conn.execute("PRAGMA table_info(customers)").fetchall()}
            for col,typ,default in [('privacy_accepted_at','INTEGER','NULL'),('marketing_email','INTEGER','0'),('marketing_whatsapp','INTEGER','0'),('marketing_accepted_at','INTEGER','NULL')]:
                if col not in ccols: conn.execute(f"ALTER TABLE customers ADD COLUMN {col} {typ} DEFAULT {default}")
        conn.executescript("CREATE TABLE IF NOT EXISTS message_queue (\n  id BIGSERIAL PRIMARY KEY, campaign_id BIGINT REFERENCES campaigns(id) ON DELETE CASCADE, kind TEXT NOT NULL, recipient TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, available_at BIGINT NOT NULL, created_at BIGINT NOT NULL, sent_at BIGINT\n);\nCREATE TABLE IF NOT EXISTS automation_rules (\n  id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, rule_type TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'email', enabled INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(campaign_id,rule_type)\n);\nCREATE TABLE IF NOT EXISTS automation_runs (\n  id BIGSERIAL PRIMARY KEY, rule_id BIGINT NOT NULL REFERENCES automation_rules(id) ON DELETE CASCADE, membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, period_key TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(rule_id,membership_id,period_key)\n);\nCREATE TABLE IF NOT EXISTS wallet_registrations (\n  id BIGSERIAL PRIMARY KEY, membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, device_library_id TEXT NOT NULL, push_token TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(membership_id,device_library_id)\n);\n" if _is_postgres(target) else "CREATE TABLE IF NOT EXISTS message_queue (\n  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER REFERENCES campaigns(id) ON DELETE CASCADE, kind TEXT NOT NULL, recipient TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, available_at INTEGER NOT NULL, created_at INTEGER NOT NULL, sent_at INTEGER\n);\nCREATE TABLE IF NOT EXISTS automation_rules (\n  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, rule_type TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'email', enabled INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(campaign_id,rule_type)\n);\nCREATE TABLE IF NOT EXISTS automation_runs (\n  id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL REFERENCES automation_rules(id) ON DELETE CASCADE, membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, period_key TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(rule_id,membership_id,period_key)\n);\nCREATE TABLE IF NOT EXISTS wallet_registrations (\n  id INTEGER PRIMARY KEY AUTOINCREMENT, membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, device_library_id TEXT NOT NULL, push_token TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(membership_id,device_library_id)\n);\n")

        # Migração v42b: templates de comunicação e notificações.
        conn.executescript(("CREATE TABLE IF NOT EXISTS message_templates (id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, name TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'both', subject TEXT, body TEXT NOT NULL, created_at BIGINT NOT NULL); CREATE TABLE IF NOT EXISTS notifications (id BIGSERIAL PRIMARY KEY, company_id BIGINT, campaign_id BIGINT, kind TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, created_at BIGINT NOT NULL);" if _is_postgres(target) else "CREATE TABLE IF NOT EXISTS message_templates (id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, name TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'both', subject TEXT, body TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, campaign_id INTEGER, kind TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL);"))

        # Migração v42: tema de cor individual do cartão por cliente.
        if _is_postgres(target):
            conn.execute("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS card_theme TEXT NOT NULL DEFAULT 'green'")
        else:
            campaign_cols={r['name'] for r in conn.execute("PRAGMA table_info(campaigns)").fetchall()}
            if 'card_theme' not in campaign_cols:
                conn.execute("ALTER TABLE campaigns ADD COLUMN card_theme TEXT NOT NULL DEFAULT 'green'")

        # Migração v22: onboarding WhatsApp via Meta Embedded Signup.
        wa_signup_cols=[('whatsapp_integration_mode','TEXT'),('whatsapp_signup_status','TEXT'),('whatsapp_business_id','TEXT'),('whatsapp_connected_at','TEXT')]
        if _is_postgres(target):
            for col,typ in wa_signup_cols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS {col} {typ}')
        else:
            campaign_cols={r['name'] for r in conn.execute("PRAGMA table_info(campaigns)").fetchall()}
            for col,typ in wa_signup_cols:
                if col not in campaign_cols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN {col} {typ}')

        # Migração v21: integrações SMTP e WhatsApp isoladas por cliente.
        integration_cols = [
            ('smtp_host','TEXT'),('smtp_port','TEXT'),('smtp_user','TEXT'),('smtp_password_enc','TEXT'),
            ('smtp_from','TEXT'),('smtp_from_name','TEXT'),('smtp_security','TEXT'),
            ('email_provider','TEXT'),('brevo_api_key_enc','TEXT'),('brevo_sender_email','TEXT'),('brevo_sender_name','TEXT'),('brevo_reply_to','TEXT'),
            ('whatsapp_phone_number_id','TEXT'),('whatsapp_waba_id','TEXT'),('whatsapp_access_token_enc','TEXT'),
            ('whatsapp_api_version','TEXT')
        ]
        if _is_postgres(target):
            for col,typ in integration_cols:
                conn.execute(f'ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS {col} {typ}')
        else:
            campaign_cols={r['name'] for r in conn.execute("PRAGMA table_info(campaigns)").fetchall()}
            for col,typ in integration_cols:
                if col not in campaign_cols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN {col} {typ}')


        # Migração v74: integração de e-commerce por empresa e histórico idempotente de pedidos.
        ecommerce_cols=[
            ('ecommerce_platform',"TEXT NOT NULL DEFAULT 'none'"),('ecommerce_store_url','TEXT'),
            ('ecommerce_webhook_secret','TEXT'),('ecommerce_status',"TEXT NOT NULL DEFAULT 'not_connected'"),
            ('ecommerce_connected_at','TEXT')
        ]
        if _is_postgres(target):
            for col,typ in ecommerce_cols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS {col} {typ}')
            conn.executescript("""CREATE TABLE IF NOT EXISTS ecommerce_orders (
              id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
              platform TEXT NOT NULL, order_id TEXT NOT NULL, order_status TEXT NOT NULL, customer_ref TEXT,
              total_cents INTEGER NOT NULL DEFAULT 0, reward_value INTEGER NOT NULL DEFAULT 0, transaction_id BIGINT,
              reversal_transaction_id BIGINT, processed_at BIGINT, reversed_at BIGINT, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
              UNIQUE(campaign_id,platform,order_id)
            ); CREATE INDEX IF NOT EXISTS idx_ecommerce_orders_campaign ON ecommerce_orders(campaign_id,created_at DESC);""")
        else:
            ccols={r['name'] for r in conn.execute("PRAGMA table_info(campaigns)").fetchall()}
            for col,typ in ecommerce_cols:
                if col not in ccols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN {col} {typ}')
            conn.executescript("""CREATE TABLE IF NOT EXISTS ecommerce_orders (
              id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
              platform TEXT NOT NULL, order_id TEXT NOT NULL, order_status TEXT NOT NULL, customer_ref TEXT,
              total_cents INTEGER NOT NULL DEFAULT 0, reward_value INTEGER NOT NULL DEFAULT 0, transaction_id INTEGER,
              reversal_transaction_id INTEGER, processed_at INTEGER, reversed_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
              UNIQUE(campaign_id,platform,order_id)
            ); CREATE INDEX IF NOT EXISTS idx_ecommerce_orders_campaign ON ecommerce_orders(campaign_id,created_at DESC);""")

        # Migração v42: programas por selos ou pontos + catálogo de recompensas.
        loyalty_cols=[('loyalty_type',"TEXT NOT NULL DEFAULT 'stamps'"),('points_spend_cents',"INTEGER NOT NULL DEFAULT 200")]
        if _is_postgres(target):
            for col,typ in loyalty_cols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS {col} {typ}')
            conn.execute("ALTER TABLE memberships ADD COLUMN IF NOT EXISTS points_balance INTEGER NOT NULL DEFAULT 0")
        else:
            ccols={r['name'] for r in conn.execute("PRAGMA table_info(campaigns)").fetchall()}
            for col,typ in loyalty_cols:
                if col not in ccols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN {col} {typ}')
            mcols={r['name'] for r in conn.execute("PRAGMA table_info(memberships)").fetchall()}
            if 'points_balance' not in mcols: conn.execute("ALTER TABLE memberships ADD COLUMN points_balance INTEGER NOT NULL DEFAULT 0")
        conn.executescript(("CREATE TABLE IF NOT EXISTS reward_catalog (id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT, points_cost INTEGER NOT NULL, image_data TEXT, active INTEGER NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL); CREATE INDEX IF NOT EXISTS idx_reward_catalog_campaign ON reward_catalog(campaign_id, active, points_cost);" if _is_postgres(target) else "CREATE TABLE IF NOT EXISTS reward_catalog (id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT, points_cost INTEGER NOT NULL, image_data TEXT, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_reward_catalog_campaign ON reward_catalog(campaign_id, active, points_cost);"))

        # Migração v50: fidelidade 360.
        campaign360=[('cashback_percent','REAL NOT NULL DEFAULT 0'),('points_expiry_days','INTEGER NOT NULL DEFAULT 0'),('referral_bonus_points','INTEGER NOT NULL DEFAULT 0'),('referee_bonus_points','INTEGER NOT NULL DEFAULT 0')]
        if _is_postgres(target):
            for col,typ in campaign360: conn.execute(f'ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS {col} {typ}')
            conn.execute('ALTER TABLE memberships ADD COLUMN IF NOT EXISTS cashback_balance_cents INTEGER NOT NULL DEFAULT 0')
        else:
            ccols={r['name'] for r in conn.execute('PRAGMA table_info(campaigns)').fetchall()}; mcols={r['name'] for r in conn.execute('PRAGMA table_info(memberships)').fetchall()}
            for col,typ in campaign360:
                if col not in ccols: conn.execute(f'ALTER TABLE campaigns ADD COLUMN {col} {typ}')
            if 'cashback_balance_cents' not in mcols: conn.execute('ALTER TABLE memberships ADD COLUMN cashback_balance_cents INTEGER NOT NULL DEFAULT 0')
        if _is_postgres(target):
            conn.executescript("CREATE TABLE IF NOT EXISTS loyalty_tiers (id BIGSERIAL PRIMARY KEY,campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,name TEXT NOT NULL,min_points INTEGER NOT NULL DEFAULT 0,benefit TEXT,active INTEGER NOT NULL DEFAULT 1,created_at BIGINT NOT NULL); CREATE TABLE IF NOT EXISTS point_multipliers (id BIGSERIAL PRIMARY KEY,campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,name TEXT,factor REAL NOT NULL DEFAULT 1,weekday TEXT DEFAULT 'all',start_hour TEXT,end_hour TEXT,active INTEGER NOT NULL DEFAULT 1,created_at BIGINT NOT NULL); CREATE TABLE IF NOT EXISTS referrals (id BIGSERIAL PRIMARY KEY,campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,referrer_membership_id BIGINT REFERENCES memberships(id),referred_membership_id BIGINT REFERENCES memberships(id),code TEXT,status TEXT NOT NULL DEFAULT 'pending',created_at BIGINT NOT NULL,rewarded_at BIGINT); CREATE TABLE IF NOT EXISTS nps_responses (id BIGSERIAL PRIMARY KEY,campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,membership_id BIGINT REFERENCES memberships(id),score INTEGER NOT NULL,comment TEXT,created_at BIGINT NOT NULL); CREATE TABLE IF NOT EXISTS gift_cards (id BIGSERIAL PRIMARY KEY,campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,code TEXT NOT NULL UNIQUE,value_cents INTEGER NOT NULL,balance_cents INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'active',created_at BIGINT NOT NULL);")
        else:
            conn.executescript("CREATE TABLE IF NOT EXISTS loyalty_tiers (id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,name TEXT NOT NULL,min_points INTEGER NOT NULL DEFAULT 0,benefit TEXT,active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS point_multipliers (id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,name TEXT,factor REAL NOT NULL DEFAULT 1,weekday TEXT DEFAULT 'all',start_hour TEXT,end_hour TEXT,active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS referrals (id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,referrer_membership_id INTEGER REFERENCES memberships(id),referred_membership_id INTEGER REFERENCES memberships(id),code TEXT,status TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL,rewarded_at INTEGER); CREATE TABLE IF NOT EXISTS nps_responses (id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,membership_id INTEGER REFERENCES memberships(id),score INTEGER NOT NULL,comment TEXT,created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS gift_cards (id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,code TEXT NOT NULL UNIQUE,value_cents INTEGER NOT NULL,balance_cents INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'active',created_at INTEGER NOT NULL);")

        # Migração v68: consolidação operacional/comercial.
        # Recompensas: estoque e janela de disponibilidade; vales: validade; estrutura multiunidade e permissões.
        if _is_postgres(target):
            for col,typ in [('stock','INTEGER NOT NULL DEFAULT -1'),('starts_at','BIGINT'),('ends_at','BIGINT')]: conn.execute(f'ALTER TABLE reward_catalog ADD COLUMN IF NOT EXISTS {col} {typ}')
            conn.execute('ALTER TABLE gift_cards ADD COLUMN IF NOT EXISTS expires_at BIGINT')
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions_json TEXT NOT NULL DEFAULT '{}' ")
            conn.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS branch_id BIGINT')
            conn.execute('ALTER TABLE memberships ADD COLUMN IF NOT EXISTS branch_id BIGINT')
            conn.executescript("CREATE TABLE IF NOT EXISTS branches (id BIGSERIAL PRIMARY KEY,campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,name TEXT NOT NULL,code TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at BIGINT NOT NULL,UNIQUE(campaign_id,code)); CREATE TABLE IF NOT EXISTS customer_notes (id BIGSERIAL PRIMARY KEY,membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,note TEXT NOT NULL,created_at BIGINT NOT NULL); CREATE TABLE IF NOT EXISTS reward_redemptions (id BIGSERIAL PRIMARY KEY,membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,reward_id BIGINT REFERENCES reward_catalog(id) ON DELETE SET NULL,user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,points_cost INTEGER NOT NULL,created_at BIGINT NOT NULL);")
        else:
            rcols={r['name'] for r in conn.execute('PRAGMA table_info(reward_catalog)').fetchall()}
            for col,typ in [('stock','INTEGER NOT NULL DEFAULT -1'),('starts_at','INTEGER'),('ends_at','INTEGER')]:
                if col not in rcols: conn.execute(f'ALTER TABLE reward_catalog ADD COLUMN {col} {typ}')
            gcols={r['name'] for r in conn.execute('PRAGMA table_info(gift_cards)').fetchall()}
            if 'expires_at' not in gcols: conn.execute('ALTER TABLE gift_cards ADD COLUMN expires_at INTEGER')
            ucols={r['name'] for r in conn.execute('PRAGMA table_info(users)').fetchall()}
            if 'permissions_json' not in ucols: conn.execute("ALTER TABLE users ADD COLUMN permissions_json TEXT NOT NULL DEFAULT '{}'")
            if 'branch_id' not in ucols: conn.execute('ALTER TABLE users ADD COLUMN branch_id INTEGER')
            mcols={r['name'] for r in conn.execute('PRAGMA table_info(memberships)').fetchall()}
            if 'branch_id' not in mcols: conn.execute('ALTER TABLE memberships ADD COLUMN branch_id INTEGER')
            conn.executescript("CREATE TABLE IF NOT EXISTS branches (id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,name TEXT NOT NULL,code TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,UNIQUE(campaign_id,code)); CREATE TABLE IF NOT EXISTS customer_notes (id INTEGER PRIMARY KEY AUTOINCREMENT,membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,note TEXT NOT NULL,created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS reward_redemptions (id INTEGER PRIMARY KEY AUTOINCREMENT,membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,reward_id INTEGER REFERENCES reward_catalog(id) ON DELETE SET NULL,user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,points_cost INTEGER NOT NULL,created_at INTEGER NOT NULL);")

        # Migração v73: multiunidade operacional.
        # Guarda a unidade no momento da operação/auditoria para manter o histórico correto
        # mesmo se um atendente for transferido de filial posteriormente.
        if _is_postgres(target):
            conn.execute('ALTER TABLE transactions ADD COLUMN IF NOT EXISTS branch_id BIGINT')
            conn.execute('ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS branch_id BIGINT')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_transactions_branch_time ON transactions(branch_id,created_at DESC)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_branch_time ON audit_log(branch_id,created_at DESC)')
        else:
            txcols={r['name'] for r in conn.execute('PRAGMA table_info(transactions)').fetchall()}
            if 'branch_id' not in txcols: conn.execute('ALTER TABLE transactions ADD COLUMN branch_id INTEGER')
            acols={r['name'] for r in conn.execute('PRAGMA table_info(audit_log)').fetchall()}
            if 'branch_id' not in acols: conn.execute('ALTER TABLE audit_log ADD COLUMN branch_id INTEGER')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_transactions_branch_time ON transactions(branch_id,created_at DESC)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_branch_time ON audit_log(branch_id,created_at DESC)')

        # Migração v76: retenção, campanhas, cupons e acompanhamento de conversão.
        if _is_postgres(target):
            conn.executescript("""CREATE TABLE IF NOT EXISTS marketing_campaigns (
              id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
              name TEXT NOT NULL, segment TEXT NOT NULL DEFAULT 'all', channel TEXT NOT NULL DEFAULT 'both',
              message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', created_at BIGINT NOT NULL, sent_at BIGINT
            );
            CREATE TABLE IF NOT EXISTS marketing_campaign_recipients (
              id BIGSERIAL PRIMARY KEY, marketing_campaign_id BIGINT NOT NULL REFERENCES marketing_campaigns(id) ON DELETE CASCADE,
              membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, sent_at BIGINT NOT NULL, returned_at BIGINT,
              UNIQUE(marketing_campaign_id,membership_id)
            );
            CREATE TABLE IF NOT EXISTS coupons (
              id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
              name TEXT NOT NULL, code TEXT NOT NULL, benefit_type TEXT NOT NULL DEFAULT 'percent', benefit_value INTEGER NOT NULL DEFAULT 0,
              segment TEXT NOT NULL DEFAULT 'all', starts_at BIGINT, ends_at BIGINT, usage_limit INTEGER NOT NULL DEFAULT 0,
              active INTEGER NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, UNIQUE(campaign_id,code)
            );
            CREATE TABLE IF NOT EXISTS coupon_redemptions (
              id BIGSERIAL PRIMARY KEY, coupon_id BIGINT NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
              membership_id BIGINT NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
              created_at BIGINT NOT NULL, UNIQUE(coupon_id,membership_id)
            );
            CREATE INDEX IF NOT EXISTS idx_marketing_campaigns_client ON marketing_campaigns(campaign_id,created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_coupon_client ON coupons(campaign_id,active);
            """)
        else:
            conn.executescript("""CREATE TABLE IF NOT EXISTS marketing_campaigns (
              id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
              name TEXT NOT NULL, segment TEXT NOT NULL DEFAULT 'all', channel TEXT NOT NULL DEFAULT 'both',
              message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', created_at INTEGER NOT NULL, sent_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS marketing_campaign_recipients (
              id INTEGER PRIMARY KEY AUTOINCREMENT, marketing_campaign_id INTEGER NOT NULL REFERENCES marketing_campaigns(id) ON DELETE CASCADE,
              membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, sent_at INTEGER NOT NULL, returned_at INTEGER,
              UNIQUE(marketing_campaign_id,membership_id)
            );
            CREATE TABLE IF NOT EXISTS coupons (
              id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
              name TEXT NOT NULL, code TEXT NOT NULL, benefit_type TEXT NOT NULL DEFAULT 'percent', benefit_value INTEGER NOT NULL DEFAULT 0,
              segment TEXT NOT NULL DEFAULT 'all', starts_at INTEGER, ends_at INTEGER, usage_limit INTEGER NOT NULL DEFAULT 0,
              active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, UNIQUE(campaign_id,code)
            );
            CREATE TABLE IF NOT EXISTS coupon_redemptions (
              id INTEGER PRIMARY KEY AUTOINCREMENT, coupon_id INTEGER NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
              membership_id INTEGER NOT NULL REFERENCES memberships(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
              created_at INTEGER NOT NULL, UNIQUE(coupon_id,membership_id)
            );
            CREATE INDEX IF NOT EXISTS idx_marketing_campaigns_client ON marketing_campaigns(campaign_id,created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_coupon_client ON coupons(campaign_id,active);
            """)

        # Migração v10: todo atendente pode ser vinculado a um cliente (campaign_id).
        if _is_postgres(target):
            conn.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS campaign_id BIGINT REFERENCES campaigns(id) ON DELETE SET NULL')
        else:
            user_cols = [r['name'] for r in conn.execute('PRAGMA table_info(users)').fetchall()]
            if 'campaign_id' not in user_cols:
                conn.execute('ALTER TABLE users ADD COLUMN campaign_id INTEGER REFERENCES campaigns(id) ON DELETE SET NULL')
        # Compatibilidade: atendentes antigos são associados ao primeiro cliente ativo.
        first_client = conn.execute('SELECT id FROM campaigns WHERE active=1 ORDER BY id LIMIT 1').fetchone()
        if first_client:
            conn.execute("UPDATE users SET campaign_id=? WHERE role='attendant' AND campaign_id IS NULL", (first_client['id'],))
        if not seed:
            return
        count = conn.execute('SELECT COUNT(*) c FROM companies').fetchone()['c']
        if count != 0:
            return

        ts = now_ts()
        production = _is_postgres(target)
        demo_enabled = os.environ.get('CLUBE_SEED_DEMO', '0' if production else '1') == '1'

        if demo_enabled:
            company_name = 'Café Taboo'
            company_slug = 'cafe-taboo'
            manager_name = 'Gerente Demo'
            manager_email = 'gerente@demo.local'
            manager_password = 'Gerente123!'
            attendant_name = 'Atendente Demo'
            attendant_email = 'atendente@demo.local'
            attendant_password = 'Atendente123!'
        else:
            company_name = os.environ.get('CLUBE_COMPANY_NAME', 'Clube Fidelidade').strip()
            company_slug = os.environ.get('CLUBE_COMPANY_SLUG', 'clube-fidelidade').strip()
            manager_name = os.environ.get('CLUBE_ADMIN_NAME', 'Administrador').strip()
            manager_email = os.environ.get('CLUBE_ADMIN_EMAIL', '').strip().lower()
            manager_password = os.environ.get('CLUBE_ADMIN_PASSWORD', '')
            attendant_name = attendant_email = attendant_password = None
            if '@' not in manager_email or len(manager_password) < 12:
                raise RuntimeError(
                    'Banco de produção vazio. Configure CLUBE_ADMIN_EMAIL e CLUBE_ADMIN_PASSWORD '
                    '(mínimo 12 caracteres) nas variáveis do serviço antes do primeiro deploy.'
                )

        company_id = insert_id(conn,
            'INSERT INTO companies(name,slug,primary_color,logo_text,created_at) VALUES(?,?,?,?,?)',
            (company_name, company_slug, '#5A321F', 'CLUBE CAFÉ', ts))
        conn.execute('INSERT INTO users(company_id,name,email,password_hash,role,campaign_id,created_at) VALUES(?,?,?,?,?,?,?)',
                     (company_id, manager_name, manager_email, hash_password(manager_password), 'manager', None, ts))
        default_campaign_id = insert_id(conn, '''INSERT INTO campaigns(company_id,code,name,reward_name,goal,icon,min_stamp_interval_sec,max_stamps_per_hour,max_stamps_per_attendant_day,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?)''',
                     (company_id,'CAFE5','Clube Café','1 café grátis',5,'☕',60,6,500,ts))
        if attendant_email:
            conn.execute('INSERT INTO users(company_id,name,email,password_hash,role,campaign_id,created_at) VALUES(?,?,?,?,?,?,?)',
                         (company_id, attendant_name, attendant_email, hash_password(attendant_password), 'attendant', default_campaign_id, ts))



def ensure_configured_staff(db_path=None):
    """Sincroniza credenciais configuradas por variáveis de ambiente.

    Em produção isto permite trocar a senha no Railway sem precisar apagar o banco.
    Se o usuário já existe, nome/senha/role são atualizados; se não existe, ele é criado.
    """
    target = db_path or DATABASE_URL or DEFAULT_DB
    admin_email = os.environ.get('CLUBE_ADMIN_EMAIL', '').strip().lower()
    admin_password = os.environ.get('CLUBE_ADMIN_PASSWORD', '').strip()
    admin_name = os.environ.get('CLUBE_ADMIN_NAME', 'Administrador').strip() or 'Administrador'
    attendant_email = os.environ.get('CLUBE_ATTENDANT_EMAIL', '').strip().lower()
    attendant_password = os.environ.get('CLUBE_ATTENDANT_PASSWORD', '').strip()
    attendant_name = os.environ.get('CLUBE_ATTENDANT_NAME', 'Atendente').strip() or 'Atendente'

    # O e-mail administrativo é reservado ao Painel Taboo e nunca pode ser
    # rebaixado para atendente, mesmo que as variáveis bootstrap sejam
    # configuradas por engano com o mesmo endereço.
    if admin_email and attendant_email and admin_email == attendant_email:
        print(f'[AUTH] ATTENDANT_BOOTSTRAP_SKIPPED admin_email_collision={admin_email}')
        attendant_email = ''
        attendant_password = ''

    configured = []
    # Sincroniza primeiro o bootstrap de atendente e por último o administrador.
    # Assim, mesmo diante de dados legados inconsistentes, o perfil Taboo sempre prevalece.
    if attendant_email or attendant_password:
        if '@' not in attendant_email or len(attendant_password) < 10:
            raise RuntimeError('CLUBE_ATTENDANT_EMAIL inválido ou CLUBE_ATTENDANT_PASSWORD com menos de 10 caracteres.')
        configured.append((attendant_name, attendant_email, attendant_password, 'attendant'))
    if admin_email or admin_password:
        if '@' not in admin_email or len(admin_password) < 12:
            raise RuntimeError('CLUBE_ADMIN_EMAIL inválido ou CLUBE_ADMIN_PASSWORD com menos de 12 caracteres.')
        configured.append((admin_name, admin_email, admin_password, 'manager'))
    if not configured:
        return

    with connect(target) as conn:
        company = conn.execute('SELECT id FROM companies ORDER BY id LIMIT 1').fetchone()
        if not company:
            return
        for name, email, password, role in configured:
            existing = conn.execute('SELECT id,campaign_id FROM users WHERE email=?', (email,)).fetchone()
            pwd_hash = hash_password(password)
            if existing:
                campaign_id = existing['campaign_id'] if role == 'attendant' else None
                if role == 'attendant' and campaign_id is None:
                    first_client = conn.execute('SELECT id FROM campaigns WHERE active=1 ORDER BY id LIMIT 1').fetchone()
                    campaign_id = first_client['id'] if first_client else None
                if role == 'attendant':
                    # A senha do atendente pode ser alterada por ele próprio e não deve
                    # ser redefinida pelo Railway em deploys futuros.
                    conn.execute('UPDATE users SET name=?, role=?, campaign_id=?, active=1 WHERE id=?',
                                 (name, role, campaign_id, existing['id']))
                else:
                    conn.execute('UPDATE users SET name=?, password_hash=?, role=?, campaign_id=?, active=1 WHERE id=?',
                                 (name, pwd_hash, role, campaign_id, existing['id']))
                user_id = existing['id']
            else:
                campaign_id = None
                if role == 'attendant':
                    first_client = conn.execute('SELECT id FROM campaigns WHERE active=1 ORDER BY id LIMIT 1').fetchone()
                    campaign_id = first_client['id'] if first_client else None
                user_id = insert_id(conn,
                    'INSERT INTO users(company_id,name,email,password_hash,role,campaign_id,created_at) VALUES(?,?,?,?,?,?,?)',
                    (company['id'], name, email, pwd_hash, role, campaign_id, now_ts()))
            check = conn.execute('SELECT password_hash,role,active FROM users WHERE id=?', (user_id,)).fetchone()
            password_synced = verify_password(password, check['password_hash']) if check and (role == 'manager' or not existing) else True
            if not check or not password_synced or check['role'] != role or int(check['active']) != 1:
                raise RuntimeError(f'Falha ao sincronizar credenciais de {role}: {email}')
            label = 'ADMIN' if role == 'manager' else 'ATTENDANT'
            print(f'[AUTH] {label}_SYNC_OK email={email} password_length={len(password)} preserved={bool(role == "attendant" and existing)}')


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
    row = conn.execute('''SELECT s.token,s.csrf,s.expires_at,u.id user_id,u.company_id,u.campaign_id,u.name,u.email,u.role,u.active,u.is_client_admin,c.name client_name,c.logo_image client_logo_image
                          FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN campaigns c ON c.id=u.campaign_id WHERE s.token=?''',(token,)).fetchone()
    if not row or row['expires_at'] < now_ts() or not row['active']:
        return None
    return row


def audit(conn, company_id, user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None, branch_id=None):
    # A unidade é registrada junto ao evento. Se o chamador não informar, usamos
    # a unidade atualmente vinculada ao usuário. Isso preserva o contexto da filial
    # no histórico mesmo que o usuário seja transferido depois.
    if branch_id is None and user_id is not None:
        try:
            u=conn.execute('SELECT branch_id FROM users WHERE id=?',(user_id,)).fetchone()
            branch_id=u['branch_id'] if u else None
        except Exception:
            branch_id=None
    try:
        conn.execute('''INSERT INTO audit_log(company_id,user_id,branch_id,action,entity_type,entity_id,details,ip_address,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?)''',
                     (company_id,user_id,branch_id,action,entity_type,str(entity_id) if entity_id is not None else None,details,ip_address,now_ts()))
    except Exception:
        # Compatibilidade defensiva durante deploys em que a migração ainda não tenha sido aplicada.
        conn.execute('''INSERT INTO audit_log(company_id,user_id,action,entity_type,entity_id,details,ip_address,created_at)
                        VALUES(?,?,?,?,?,?,?,?)''',
                     (company_id,user_id,action,entity_type,str(entity_id) if entity_id is not None else None,details,ip_address,now_ts()))
