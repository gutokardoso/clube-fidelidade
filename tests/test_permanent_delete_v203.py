import os, tempfile
from unittest import mock
import db, server
from security import now_ts, hash_password


def make_db():
    fd,path=tempfile.mkstemp(suffix='.db'); os.close(fd); db.init_db(path,seed=True); return path


def prepare_paid_campaign(path):
    with db.connect(path) as c:
        camp=c.execute('SELECT * FROM campaigns ORDER BY id LIMIT 1').fetchone()
        cid=int(camp['id']); company_id=int(camp['company_id']); ts=now_ts()
        c.execute("UPDATE campaigns SET subscription_provider='mercadopago',subscription_id='sub-main',pending_subscription_id='sub-pending',previous_subscription_id='sub-old',subscription_status='active',active=1 WHERE id=?",(cid,))
        admin=db.insert_id(c,"INSERT INTO users(company_id,name,email,password_hash,role,active,is_client_admin,campaign_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(company_id,'Admin Empresa','admin-v203@example.com',hash_password('SenhaForte123!'),'attendant',1,1,cid,ts))
        staff=db.insert_id(c,"INSERT INTO users(company_id,name,email,password_hash,role,active,is_client_admin,campaign_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(company_id,'Atendente','staff-v203@example.com',hash_password('SenhaForte123!'),'attendant',1,0,cid,ts))
        customer=db.insert_id(c,"INSERT INTO customers(name,email,created_at) VALUES(?,?,?)",('Cliente exclusivo','cliente-v203@example.com',ts))
        membership=db.insert_id(c,"INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)",(customer,cid,'member-v203','qr-v203',ts))
        c.execute("INSERT INTO sessions(token,user_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?)",('sess-v203',admin,'csrf',ts+3600,ts))
        c.execute("INSERT INTO message_queue(campaign_id,kind,recipient,payload_json,status,available_at,created_at) VALUES(?,?,?,?,?,?,?)",(cid,'test','x@example.com','{}','pending',ts,ts))
        return cid,admin,staff,customer,membership


def test_verified_cancel_requires_remote_confirmation():
    calls=[]
    def fake(method,path,payload=None,extra_headers=None):
        calls.append((method,path,payload))
        if method=='GET' and len(calls)==1:return {'id':'sub','status':'authorized'}
        if method=='PUT':return {'id':'sub','status':'cancelled'}
        return {'id':'sub','status':'cancelled'}
    with mock.patch.object(server,'mp_request',side_effect=fake):
        assert server._cancel_subscription_verified('sub') is True
    assert [x[0] for x in calls]==['GET','PUT','GET']


def test_permanent_delete_cancels_all_subscriptions_and_removes_company_data():
    path=make_db()
    try:
        cid,admin,staff,customer,membership=prepare_paid_campaign(path)
        def fake(method,path,payload=None,extra_headers=None):
            return {'id':path.rsplit('/',1)[-1],'status':'cancelled' if method!='GET' else 'authorized'} if method=='PUT' else {'id':path.rsplit('/',1)[-1],'status':'cancelled'}
        with db.connect(path) as c, mock.patch.object(server,'mp_request',side_effect=fake):
            camp=c.execute('SELECT * FROM campaigns WHERE id=?',(cid,)).fetchone()
            result=server._permanently_delete_campaign(c,camp)
            assert result['deleted_users']>=2
            assert result['cancelled_subscriptions']==3
        with db.connect(path) as c:
            assert c.execute('SELECT 1 FROM campaigns WHERE id=?',(cid,)).fetchone() is None
            assert c.execute('SELECT 1 FROM users WHERE id IN (?,?)',(admin,staff)).fetchone() is None
            assert c.execute('SELECT 1 FROM sessions WHERE user_id=?',(admin,)).fetchone() is None
            assert c.execute('SELECT 1 FROM memberships WHERE id=?',(membership,)).fetchone() is None
            assert c.execute('SELECT 1 FROM customers WHERE id=?',(customer,)).fetchone() is None
            assert c.execute('SELECT 1 FROM message_queue WHERE campaign_id=?',(cid,)).fetchone() is None
    finally:
        os.unlink(path)


def test_failed_billing_confirmation_blocks_access_but_preserves_data_for_retry():
    path=make_db()
    try:
        cid,admin,staff,customer,membership=prepare_paid_campaign(path)
        try:
            with db.connect(path) as c, mock.patch.object(server,'_cancel_subscription_verified',return_value=False):
                camp=c.execute('SELECT * FROM campaigns WHERE id=?',(cid,)).fetchone()
                server._permanently_delete_campaign(c,camp)
        except RuntimeError as exc:
            assert str(exc)=='billing_cancel_failed'
        with db.connect(path) as c:
            camp=c.execute('SELECT active,subscription_status FROM campaigns WHERE id=?',(cid,)).fetchone()
            assert camp is not None and int(camp['active'])==0 and camp['subscription_status']=='cancelling'
            assert c.execute('SELECT 1 FROM users WHERE id=?',(admin,)).fetchone() is not None
            assert c.execute('SELECT 1 FROM sessions WHERE user_id=?',(admin,)).fetchone() is None
            assert c.execute('SELECT 1 FROM memberships WHERE id=?',(membership,)).fetchone() is not None
    finally:
        os.unlink(path)


def test_shared_customer_is_preserved_when_it_belongs_to_another_campaign():
    path=make_db()
    try:
        with db.connect(path) as c:
            base=c.execute('SELECT * FROM campaigns ORDER BY id LIMIT 1').fetchone(); cid=int(base['id']); company_id=int(base['company_id']); ts=now_ts()
            other=db.insert_id(c,"INSERT INTO campaigns(company_id,code,name,reward_name,goal,icon,card_theme,plan,loyalty_type,points_spend_cents,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(company_id,'OTHER203','Outra empresa','R',5,'X','orange','beginner','stamps',200,ts))
            customer=db.insert_id(c,"INSERT INTO customers(name,email,created_at) VALUES(?,?,?)",('Compartilhado','share-v203@example.com',ts))
            c.execute("INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)",(customer,cid,'share-a','share-qa',ts))
            c.execute("INSERT INTO memberships(customer_id,campaign_id,public_id,qr_token,created_at) VALUES(?,?,?,?,?)",(customer,other,'share-b','share-qb',ts))
            camp=c.execute('SELECT * FROM campaigns WHERE id=?',(cid,)).fetchone()
            server._permanently_delete_campaign(c,camp)
        with db.connect(path) as c:
            assert c.execute('SELECT 1 FROM customers WHERE id=?',(customer,)).fetchone() is not None
            assert c.execute('SELECT 1 FROM memberships WHERE customer_id=? AND campaign_id=?',(customer,other)).fetchone() is not None
    finally:
        os.unlink(path)

def test_queue_send_refuses_inactive_campaign_before_delivery():
    path=make_db()
    try:
        with db.connect(path) as c:
            camp=c.execute('SELECT id FROM campaigns ORDER BY id LIMIT 1').fetchone(); cid=int(camp['id']); ts=now_ts()
            c.execute('UPDATE campaigns SET active=0 WHERE id=?',(cid,))
            item={'payload_json':'{}','kind':'campaign_email','campaign_id':cid,'recipient':'x@example.com'}
            with mock.patch.object(server,'send_campaign_email') as send:
                result=server._queue_send(item,c)
            assert result=={'sent':False,'reason':'campaign_inactive'}
            send.assert_not_called()
    finally:
        os.unlink(path)
