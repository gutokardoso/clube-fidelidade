import os, tempfile, unittest, time, io, urllib.error
from pathlib import Path
from email.message import EmailMessage
from unittest.mock import patch
from db import init_db, connect
from platform_features import (
    session_permissions, has_permission, active_multiplier, add_point_lot,
    consume_point_lots, expire_points_once, record_purchase, RateLimiter,
)
from integrations import platform_order
from server import _brevo_blocked_ip_details, send_email_brevo_api

ROOT=Path(__file__).resolve().parents[1]

class FeatureTests(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix='.sqlite3'); os.close(fd); os.unlink(self.path)
        init_db(self.path,seed=True)
    def tearDown(self):
        try: os.remove(self.path)
        except OSError: pass

    def _campaign(self,c):
        return c.execute('SELECT id,company_id FROM campaigns ORDER BY id LIMIT 1').fetchone()

    def _membership(self,c,points_balance=0):
        camp=self._campaign(c); now=int(time.time())
        cur=c.execute("INSERT INTO customers(name,email,phone,birth_date,cpf,created_at) VALUES(?,?,?,?,?,?)",('Teste','teste-%s@example.com'%now,'11999999999','1990-01-01',str(now)[-11:].zfill(11),now))
        cust=cur.lastrowid
        cur=c.execute("INSERT INTO memberships(campaign_id,customer_id,public_id,qr_token,status,progress,rewards_available,points_balance,cashback_balance_cents,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(camp['id'],cust,'pub'+str(now),'qr'+str(now),'active',0,0,points_balance,0,now))
        return camp,cur.lastrowid

    def test_legacy_permissions_and_explicit_permissions(self):
        self.assertTrue(session_permissions({'is_client_admin':0,'permissions_json':'{}'})['add_balance'])
        p=session_permissions({'is_client_admin':0,'permissions_json':'{"add_balance":true,"remove_balance":false}'})
        self.assertTrue(p['add_balance']); self.assertFalse(p['remove_balance'])
        self.assertFalse(has_permission({'is_client_admin':0,'permissions_json':'{"send_messages":false}'},'send_messages'))

    def test_client_admin_has_all_permissions(self):
        p=session_permissions({'is_client_admin':1,'permissions_json':'{}'})
        self.assertTrue(all(p.values()))

    def test_default_point_expiry_180_days(self):
        with connect(self.path) as c:
            c.execute("UPDATE campaigns SET loyalty_type='points',points_expiry_days=180 WHERE id=(SELECT id FROM campaigns ORDER BY id LIMIT 1)")
            row=c.execute("SELECT points_expiry_days FROM campaigns WHERE loyalty_type='points' LIMIT 1").fetchone()
            self.assertEqual(int(row['points_expiry_days']),180)

    def test_expiry_selector_has_1_to_12_months(self):
        html=(ROOT/'static/loyalty360.html').read_text(encoding='utf-8')
        for month,days in enumerate(range(30,361,30),1):
            self.assertIn(f'value="{days}"',html)
            self.assertIn(f'>{month} mês' if month==1 else f'>{month} meses',html)
        self.assertIn('value="180" selected',html)

    def test_point_lot_fifo_and_expiry(self):
        with connect(self.path) as c:
            camp,mid=self._membership(c,100); now=int(time.time())
            add_point_lot(c,mid,None,40,180,now); add_point_lot(c,mid,None,60,180,now+1)
            self.assertEqual(consume_point_lots(c,mid,50),50)
            rem=[r['remaining_points'] for r in c.execute('SELECT remaining_points FROM point_lots WHERE membership_id=? ORDER BY id',(mid,)).fetchall()]
            self.assertEqual(rem,[0,50])
            c.execute('UPDATE point_lots SET expires_at=? WHERE membership_id=?',(now-1,mid)); expired=expire_points_once(c,now)
            self.assertEqual(expired,50)
            bal=c.execute('SELECT points_balance FROM memberships WHERE id=?',(mid,)).fetchone()['points_balance']; self.assertEqual(bal,50)
            tx=c.execute("SELECT note FROM transactions WHERE membership_id=? AND note='Expiração automática de pontos'",(mid,)).fetchone(); self.assertIsNotNone(tx)

    def test_multiplier_uses_largest_active_factor(self):
        with connect(self.path) as c:
            camp=self._campaign(c); now=int(time.time())
            c.execute("INSERT INTO point_multipliers(campaign_id,name,factor,weekday,start_hour,end_hour,active,created_at) VALUES(?,?,?,?,?,?,?,?)",(camp['id'],'Dobro',2.0,'all','','',1,now))
            c.execute("INSERT INTO point_multipliers(campaign_id,name,factor,weekday,start_hour,end_hour,active,created_at) VALUES(?,?,?,?,?,?,?,?)",(camp['id'],'Triplo',3.0,'all','','',1,now))
            self.assertEqual(active_multiplier(c,camp['id'],now),3.0)

    def test_inactive_multiplier_is_ignored(self):
        with connect(self.path) as c:
            camp=self._campaign(c); now=int(time.time())
            c.execute("INSERT INTO point_multipliers(campaign_id,name,factor,weekday,start_hour,end_hour,active,created_at) VALUES(?,?,?,?,?,?,?,?)",(camp['id'],'Inativo',5.0,'all','','',0,now))
            self.assertEqual(active_multiplier(c,camp['id'],now),1.0)

    def test_purchase_record_attributes_recent_campaign(self):
        with connect(self.path) as c:
            camp,mid=self._membership(c,0); now=int(time.time())
            mc=c.execute("INSERT INTO marketing_campaigns(campaign_id,name,segment,channel,message,status,created_at) VALUES(?,?,?,?,?,?,?)",(camp['id'],'Volte','all','email','Oi','sent',now-100)).lastrowid
            rec=c.execute("INSERT INTO marketing_campaign_recipients(marketing_campaign_id,membership_id,sent_at) VALUES(?,?,?)",(mc,mid,now-90)).lastrowid
            record_purchase(c,mid,None,12550,'in_store',now)
            row=c.execute('SELECT returned_at,attributed_revenue_cents FROM marketing_campaign_recipients WHERE id=?',(rec,)).fetchone()
            self.assertEqual(int(row['attributed_revenue_cents']),12550); self.assertEqual(int(row['returned_at']),now)

    def test_purchase_record_without_campaign_still_records(self):
        with connect(self.path) as c:
            camp,mid=self._membership(c,0); now=int(time.time())
            record_purchase(c,mid,None,5000,'in_store',now)
            row=c.execute('SELECT amount_cents,channel FROM purchase_records WHERE membership_id=?',(mid,)).fetchone()
            self.assertEqual(row['amount_cents'],5000); self.assertEqual(row['channel'],'in_store')

    def test_rate_limiter(self):
        r=RateLimiter()
        self.assertTrue(r.allow('x',2,60)); self.assertTrue(r.allow('x',2,60)); self.assertFalse(r.allow('x',2,60))

    def test_ecommerce_adapters(self):
        samples={
            'woocommerce':({'id':123,'status':'completed','total':'49.90','billing':{'email':'a@b.com','phone':'1199'},'meta_data':[{'key':'cpf','value':'123'}]},'123','a@b.com'),
            'shopify':({'id':'gid://shopify/Order/4','financial_status':'paid','total_price':'20.00','email':'x@y.com'},'gid://shopify/Order/4','x@y.com'),
            'nuvemshop':({'id':99,'payment_status':'paid','total':'30','customer':{'email':'n@n.com','phone':'22'}},'99','n@n.com'),
            'tray':({'order_id':'T1','status':'paid','total':'12','customer':{'email':'t@t.com'}},'T1','t@t.com'),
            'vtex':({'orderId':'V1','status':'paid','value':'22','client':{'email':'v@v.com'}},'V1','v@v.com'),
            'loja_integrada':({'id':'L1','status':'paid','total_price':'9','customer':{'email':'l@l.com'}},'L1','l@l.com'),
            'custom':({'order_id':'C1','payment_status':'paid','total_cents':1234,'customer':{'email':'c@c.com'}},'C1','c@c.com'),
        }
        for platform,(payload,oid,email) in samples.items():
            with self.subTest(platform=platform):
                o=platform_order(payload,platform); self.assertEqual(str(o.get('id')),oid); self.assertEqual(o.get('email'),email)

    def test_nps_ui_exists_on_customer_card(self):
        html=(ROOT/'static/card.html').read_text(encoding='utf-8')
        self.assertIn('De 0 a 10, quanto você recomendaria este estabelecimento?',html)
        self.assertIn("/api/card/nps",html)

    def test_financial_dashboard_is_line_chart(self):
        html=(ROOT/'static/attendant.html').read_text(encoding='utf-8')
        self.assertIn('Dashboard financeiro',html)
        self.assertIn('<polyline points=',html)
        self.assertIn('Receita atribuída a campanhas',html)


    def test_brevo_ip_block_detection(self):
        raw='{"message":"We have detected you are using an unrecognised IP address: 162.220.232.73"}'
        blocked,ip=_brevo_blocked_ip_details(raw)
        self.assertTrue(blocked); self.assertEqual(ip,'162.220.232.73')
        blocked,ip=_brevo_blocked_ip_details('{"message":"Key not found"}')
        self.assertFalse(blocked); self.assertEqual(ip,'')
        html=(ROOT/'static/index.html').read_text(encoding='utf-8')
        self.assertIn('email_provider_ip_blocked',html)

    def test_brevo_http_error_returns_ip_block_reason(self):
        msg=EmailMessage(); msg['To']='lead@example.com'; msg['Subject']='Teste'; msg.set_content('Olá')
        body=b'{"message":"We have detected you are using an unrecognised IP address: 162.220.232.73"}'
        err=urllib.error.HTTPError('https://api.brevo.com/v3/smtp/email',401,'Unauthorized',{},io.BytesIO(body))
        with patch('urllib.request.urlopen',side_effect=err):
            result=send_email_brevo_api(msg,{'api_key':'fake','sender_email':'sender@example.com','sender_name':'Fidelizae'})
        self.assertFalse(result['sent'])
        self.assertEqual(result['reason'],'brevo_ip_blocked')
        self.assertEqual(result['blocked_ip'],'162.220.232.73')

    def test_gift_card_ui_has_owner_qr_and_history(self):
        html=(ROOT/'static/loyalty360.html').read_text(encoding='utf-8')
        self.assertIn('Comprador (opcional)',html); self.assertIn('Beneficiário (opcional)',html)
        self.assertIn('Histórico do vale',html); self.assertIn('QR Code do vale-presente',html)

if __name__=='__main__': unittest.main()
