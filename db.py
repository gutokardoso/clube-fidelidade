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
  active INTEGER NOT NULL DEFAULT 1,
  min_stamp_interval_sec INTEGER NOT NULL DEFAULT 60,
  max_stamps_per_hour INTEGER NOT NULL DEFAULT 6,
  max_stamps_per_attendant_day INTEGER NOT NULL DEFAULT 500,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  contact TEXT,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  id BIGSERIAL PRIMARY KEY,
  customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  public_id TEXT NOT NULL UNIQUE,
  qr_token TEXT NOT NULL UNIQUE,
  progress INTEGER NOT NULL DEFAULT 0,
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
CREATE INDEX IF NOT EXISTS idx_tx_membership_time ON transactions(membership_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memberships_campaign ON memberships(campaign_id);
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
    row = conn.execute('''SELECT s.token,s.csrf,s.expires_at,u.id user_id,u.company_id,u.campaign_id,u.name,u.email,u.role,u.active,c.name client_name,c.logo_image client_logo_image
                          FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN campaigns c ON c.id=u.campaign_id WHERE s.token=?''',(token,)).fetchone()
    if not row or row['expires_at'] < now_ts() or not row['active']:
        return None
    return row


def audit(conn, company_id, user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None):
    conn.execute('''INSERT INTO audit_log(company_id,user_id,action,entity_type,entity_id,details,ip_address,created_at)
                    VALUES(?,?,?,?,?,?,?,?)''',
                 (company_id,user_id,action,entity_type,str(entity_id) if entity_id is not None else None,details,ip_address,now_ts()))
