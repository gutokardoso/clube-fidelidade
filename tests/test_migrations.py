import os,tempfile,unittest
from pathlib import Path
from db import init_db,connect
ROOT=Path(__file__).resolve().parents[1]

class MigrationTests(unittest.TestCase):
    def setUp(self):
        fd,self.p=tempfile.mkstemp(suffix='.sqlite3');os.close(fd);os.unlink(self.p);init_db(self.p,seed=True)
    def tearDown(self):
        try:os.remove(self.p)
        except OSError:pass

    def test_v87_schema_and_no_referrals(self):
        with connect(self.p) as c:
            names={r['name'] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            for t in ('schema_migrations','point_lots','purchase_records','alert_states','password_reset_tokens','gift_card_events','nps_responses','customer_notes'):
                self.assertIn(t,names)
            self.assertNotIn('referrals',names)
            self.assertIsNotNone(c.execute("SELECT 1 FROM schema_migrations WHERE version='v87'").fetchone())

    def test_fresh_campaign_schema_has_no_referral_columns(self):
        with connect(self.p) as c:
            cols={r['name'] for r in c.execute('PRAGMA table_info(campaigns)').fetchall()}
            self.assertNotIn('referral_bonus_points',cols); self.assertNotIn('referee_bonus_points',cols)
            self.assertIn('cashback_percent',cols)  # reservado para evolução futura
            self.assertIn('points_expiry_days',cols)

    def test_v87_added_finance_coupon_and_gift_columns(self):
        with connect(self.p) as c:
            mcr={r['name'] for r in c.execute('PRAGMA table_info(marketing_campaign_recipients)').fetchall()}
            coupons={r['name'] for r in c.execute('PRAGMA table_info(coupon_redemptions)').fetchall()}
            gifts={r['name'] for r in c.execute('PRAGMA table_info(gift_cards)').fetchall()}
            self.assertTrue({'returned_transaction_id','attributed_revenue_cents'}<=mcr)
            self.assertTrue({'purchase_cents','discount_cents'}<=coupons)
            self.assertTrue({'purchaser_name','beneficiary_name'}<=gifts)

    def test_password_reset_page_and_tokens_exist(self):
        self.assertTrue((ROOT/'static/reset-password.html').exists())
        with connect(self.p) as c:
            cols={r['name'] for r in c.execute('PRAGMA table_info(password_reset_tokens)').fetchall()}
            self.assertTrue({'token_hash','user_id','expires_at','used_at','created_at'}<=cols)

if __name__=='__main__':unittest.main()
