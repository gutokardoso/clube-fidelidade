import os


def wallet_status():
    apple_ready = all(os.environ.get(k) for k in ['APPLE_PASS_TYPE_ID','APPLE_TEAM_ID','APPLE_CERT_PATH','APPLE_KEY_PATH'])
    google_ready = all(os.environ.get(k) for k in ['GOOGLE_WALLET_ISSUER_ID','GOOGLE_SERVICE_ACCOUNT_EMAIL','GOOGLE_PRIVATE_KEY'])
    return {
        'apple': {'ready': apple_ready, 'mode': 'live' if apple_ready else 'configuration_required'},
        'google': {'ready': google_ready, 'mode': 'live' if google_ready else 'configuration_required'},
    }


def apple_pass_link(public_id: str):
    # Hook de integração. Em produção, este endpoint deve gerar e assinar um .pkpass
    # usando os certificados oficiais do Apple Developer Program.
    if not wallet_status()['apple']['ready']:
        return None
    return f'/api/wallet/apple/{public_id}'


def google_wallet_link(public_id: str):
    # Hook de integração. Em produção, este endpoint deve assinar o JWT "Save to Google Wallet"
    # com a service account autorizada no Google Wallet Issuer.
    if not wallet_status()['google']['ready']:
        return None
    return f'/api/wallet/google/{public_id}'
