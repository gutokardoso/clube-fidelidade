import os
import tempfile

fd, db_path = tempfile.mkstemp(prefix='clube-v42-', suffix='.sqlite3')
os.close(fd)
os.unlink(db_path)
os.environ['CLUBE_DB_PATH'] = db_path
os.environ.setdefault('CLUBE_QR_SECRET','smoke-qr-secret-1234567890')
os.environ.setdefault('CLUBE_ENCRYPTION_KEY','12345678901234567890123456789012')

from db import init_db, connect
import server

init_db(db_path, seed=True)
assert server.VERSION == 'v43'
with connect(db_path) as conn:
    tables = {r['name'] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {'message_queue','automation_rules','automation_runs','wallet_registrations'} <= tables
    customer_cols={r['name'] for r in conn.execute('PRAGMA table_info(customers)').fetchall()}
    assert {'privacy_accepted_at','marketing_email','marketing_whatsapp'} <= customer_cols
    user_cols={r['name'] for r in conn.execute('PRAGMA table_info(users)').fetchall()}
    assert 'is_client_admin' in user_cols

token, exp = server.make_dynamic_qr('mem_smoke', 60)
resolved, error = server.resolve_member_token(token)
assert error is None and resolved == 'mem_smoke' and exp > server.now_ts()

print('smoke_test: ok')

# Fila: um item pendente precisa chegar a 'sent' quando o provedor confirma envio.
with connect(db_path) as conn:
    qid=server.enqueue_message(conn,1,'campaign_email','smoke@example.com',{'name':'Smoke','message':'Oi'})
original_queue_send=server._queue_send
server._queue_send=lambda item,conn:{'sent':True,'message_id':'smoke'}
server.process_message_queue_once()
server._queue_send=original_queue_send
with connect(db_path) as conn:
    assert conn.execute('SELECT status FROM message_queue WHERE id=?',(qid,)).fetchone()['status']=='sent'

# Automação: aniversário com consentimento deve gerar uma mensagem na fila.
from datetime import datetime
from zoneinfo import ZoneInfo
today=datetime.now(ZoneInfo('America/Sao_Paulo')).date()
with connect(db_path) as conn:
    customer_id=server.insert_id(conn,'INSERT INTO customers(name,contact,email,phone,birth_date,cpf,privacy_accepted_at,marketing_email,marketing_whatsapp,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',('Aniversariante','birthday@example.com','birthday@example.com','5511999999999',today.isoformat(),'52998224725',server.now_ts(),1,0,server.now_ts()))
    membership_id=server.insert_id(conn,'INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)',(customer_id,1,'mem_birthday_smoke','qr_birthday_smoke',server.now_ts()))
    server.ensure_automation_defaults(conn,1)
    conn.execute("UPDATE automation_rules SET enabled=1,channel='email' WHERE campaign_id=1 AND rule_type='birthday'")
original_email_cfg=server.email_config_for_client
server.email_config_for_client=lambda conn,campaign_id:{'provider':'brevo','api_key':'smoke','sender_email':'sender@example.com'}
server.run_automations_once()
server.email_config_for_client=original_email_cfg
with connect(db_path) as conn:
    assert conn.execute("SELECT COUNT(*) n FROM message_queue WHERE campaign_id=1 AND recipient='birthday@example.com'").fetchone()['n']==1

print('smoke_test_extended: ok')
for page in ('index.html','login.html','manager.html','attendant.html','join.html','card.html','privacy.html'):
    html=(server.STATIC/page).read_text(encoding='utf-8')
    assert '<div class="build-marker">{{VERSION}}</div>' in html

print('version_source: ok')

try: os.unlink(db_path)
except FileNotFoundError: pass
