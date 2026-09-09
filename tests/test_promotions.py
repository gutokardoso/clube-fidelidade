import os, tempfile
from unittest import mock
import db, server
from security import now_ts

def make_db():
    fd,path=tempfile.mkstemp(suffix='.db'); os.close(fd); db.init_db(path); return path

def add_promo(conn, company_id, limit=100):
    return db.insert_id(conn,"INSERT INTO platform_promotions(company_id,name,target_plan,benefit_type,benefit_value,billing_option,usage_limit,require_card,auto_apply,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(company_id,'100 primeiros no PRO','pro','trial_days',30,'monthly',limit,1,1,'active',now_ts(),now_ts()))

def test_promotion_schema_and_migration():
    path=make_db()
    try:
        with db.connect(path) as c:
            assert c.execute("SELECT 1 FROM schema_migrations WHERE version='v191'").fetchone()
            assert c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='platform_promotions'").fetchone()
            cols={r[1] for r in c.execute('PRAGMA table_info(subscription_signups)').fetchall()}
            assert {'promotion_id','trial_days'} <= cols
    finally: os.unlink(path)

def test_active_promotion_and_limit():
    path=make_db()
    try:
        with db.connect(path) as c:
            company=c.execute('SELECT id FROM companies ORDER BY id LIMIT 1').fetchone(); assert company
            pid=add_promo(c,company['id'],1)
            p=server.active_signup_promotion(c,'pro','monthly'); assert p and p['id']==pid
            c.execute("INSERT INTO promotion_redemptions(promotion_id,signup_id,campaign_id,identity_hash,redeemed_at) VALUES(?,?,?,?,?)",(pid,999,None,'x',now_ts()))
            assert server.active_signup_promotion(c,'pro','monthly') is None
    finally: os.unlink(path)

def test_trial_is_sent_to_mercado_pago_preapproval():
    captured={}
    def fake(method,path,payload=None,extra_headers=None):
        captured.update(payload or {}); return {'id':'sub-test','status':'pending','init_point':'https://example.invalid'}
    with mock.patch.object(server,'mp_request',side_effect=fake):
        result=server.create_mp_subscription('buyer@example.com','pro','signup:test',billing_option='monthly',trial_days=30)
    assert result['id']=='sub-test'
    assert captured['auto_recurring']['transaction_amount']==99.90
    assert captured['auto_recurring']['free_trial']=={'frequency':30,'frequency_type':'days'}

def test_manager_and_signup_ui_expose_promotions():
    manager=open('static/manager.html',encoding='utf-8').read(); signup=open('static/signup.html',encoding='utf-8').read()
    assert 'Criar promoção' in manager and 'openPromotionManager' in manager
    assert '/api/public/promotions/active' in signup and 'promotion_id' in signup
