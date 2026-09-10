import json
from unittest.mock import patch

import server
import wallet


def _card(loyalty_type='points'):
    return {
        'public_id':'abc123', 'campaign_name':'Loja Teste', 'campaign_code':'loja',
        'loyalty_type':loyalty_type, 'points_balance':480, 'progress':4, 'goal':10,
        'reward_name':'Brinde', 'card_theme':'orange', 'customer_name':'Cliente',
        'latest_purchase_points':180,
    }


def test_purchase_messages_match_product_copy():
    assert server.wallet_purchase_message(_card('points'), 180) == 'Sua compra foi registrada. Você ganhou 180 pontos.'
    assert server.wallet_purchase_message(_card('stamps')) == 'Seu cartão foi atualizado. Agora você tem 4 de 10 selos.'


def test_apple_pass_has_change_messages_for_stamps_and_points():
    source=open('wallet.py', encoding='utf-8').read()
    assert "'changeMessage':(" in source
    assert 'Seu cartão foi atualizado. Agora você tem %@ selos.' in source
    assert 'Sua compra foi registrada. Você ganhou {int(card.get(\'latest_purchase_points\') or 0)} pontos.' in source


def test_google_notification_uses_text_and_notify(monkeypatch):
    monkeypatch.setenv('GOOGLE_WALLET_ISSUER_ID','issuer')
    monkeypatch.setenv('GOOGLE_SERVICE_ACCOUNT_EMAIL','x@example.com')
    monkeypatch.setenv('GOOGLE_PRIVATE_KEY','dummy')
    captured={}
    class Resp:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def read(self): return b'{}'
    def fake_urlopen(req, timeout=15):
        captured['url']=req.full_url
        captured['body']=json.loads(req.data.decode('utf-8'))
        return Resp()
    with patch.object(wallet, '_google_access_token', return_value='token'), patch.object(wallet.urllib.request, 'urlopen', side_effect=fake_urlopen):
        ok=wallet.google_add_update_notification(_card('points'),'Sua compra foi registrada. Você ganhou 180 pontos.',123)
    assert ok is True
    assert captured['url'].endswith('/loyaltyObject/issuer.abc123_v62/addMessage')
    msg=captured['body']['message']
    assert msg['header']=='Fidelizaê!'
    assert msg['body']=='Sua compra foi registrada. Você ganhou 180 pontos.'
    assert msg['messageType']=='TEXT_AND_NOTIFY'
    assert msg['id']=='purchase_123'


def test_purchase_endpoints_request_wallet_notification():
    source=open('server.py',encoding='utf-8').read()
    assert "notify_wallet_updates(conn,m['public_id'],purchase=True,earned_points=earned,transaction_id=tx_id)" in source
    assert "notify_wallet_updates(conn,m['public_id'],purchase=True,transaction_id=tx_id)" in source
