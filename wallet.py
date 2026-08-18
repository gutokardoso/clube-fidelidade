import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
import zipfile
from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image, ImageDraw


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _json_b64(obj) -> str:
    return _b64url(json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))


def _sign_rs256(header, payload, private_key_pem):
    signing_input=(_json_b64(header)+'.'+_json_b64(payload)).encode('ascii')
    key=serialization.load_pem_private_key(private_key_pem.encode('utf-8'),password=None)
    sig=key.sign(signing_input,padding.PKCS1v15(),hashes.SHA256())
    return signing_input.decode('ascii')+'.'+_b64url(sig)


def _has_env_material(path_key, pem_key):
    return bool(os.environ.get(path_key,'').strip() or os.environ.get(pem_key,'').strip())


def _material_path(temp_dir, path_key, pem_key, filename):
    path=os.environ.get(path_key,'').strip()
    if path:
        return path
    pem=os.environ.get(pem_key,'').replace('\\n','\n').strip()
    if not pem:
        return ''
    target=Path(temp_dir)/filename
    target.write_text(pem+'\n',encoding='utf-8')
    return str(target)

def wallet_status():
    apple_ready=bool(os.environ.get('APPLE_PASS_TYPE_ID','').strip() and os.environ.get('APPLE_TEAM_ID','').strip() and os.environ.get('CLUBE_PUBLIC_URL','').strip() and _has_env_material('APPLE_CERT_PATH','APPLE_CERT_PEM') and _has_env_material('APPLE_KEY_PATH','APPLE_KEY_PEM') and _has_env_material('APPLE_WWDR_CERT_PATH','APPLE_WWDR_CERT_PEM'))
    google_keys=['GOOGLE_WALLET_ISSUER_ID','GOOGLE_SERVICE_ACCOUNT_EMAIL','GOOGLE_PRIVATE_KEY']
    google_ready=all(os.environ.get(k,'').strip() for k in google_keys)
    return {
        'apple':{'ready':apple_ready,'mode':'live' if apple_ready else 'configuration_required'},
        'google':{'ready':google_ready,'mode':'live' if google_ready else 'configuration_required'},
    }


def apple_pass_link(public_id):
    return f'/api/wallet/apple/{urllib.parse.quote(public_id)}' if wallet_status()['apple']['ready'] else None


def google_wallet_link(public_id):
    return f'/api/wallet/google/{urllib.parse.quote(public_id)}' if wallet_status()['google']['ready'] else None


def apple_auth_token(public_id):
    secret=(os.environ.get('APPLE_PASS_AUTH_SECRET') or os.environ.get('CLUBE_ENCRYPTION_KEY') or '').encode('utf-8')
    if not secret:return ''
    import hmac
    return hmac.new(secret,public_id.encode('utf-8'),hashlib.sha256).hexdigest()


def _theme_rgb(theme):
    return {'green':(23,79,63),'orange':(209,138,31),'blue':(24,63,109),'red':(124,32,40),'black':(25,25,25)}.get(theme,(23,79,63))


def _theme_hex(theme):
    r,g,b=_theme_rgb(theme)
    return f'#{r:02x}{g:02x}{b:02x}'


def _google_public_url():
    # Prefer an explicitly configured public URL, but Railway already exposes
    # the production hostname automatically.  Without this fallback the
    # per-client LoyaltyClass was created without programLogo and Google
    # rejected it with: "LoyaltyClass cannot be created without a program logo."
    explicit=(os.environ.get('CLUBE_PUBLIC_URL') or os.environ.get('PUBLIC_BASE_URL') or '').strip().rstrip('/')
    if explicit:
        return explicit
    railway=(os.environ.get('RAILWAY_PUBLIC_DOMAIN') or '').strip().strip('/')
    if railway:
        return railway if railway.startswith(('http://','https://')) else 'https://'+railway
    return ''


def _google_class_id(card):
    issuer=os.environ['GOOGLE_WALLET_ISSUER_ID'].strip()
    configured=(os.environ.get('GOOGLE_WALLET_CLASS_ID') or 'clube_fidelidade').strip()
    # Railway may contain either a suffix (clube_fidelidade) or a complete ID.
    base=configured.split('.',1)[1] if configured.startswith(issuer+'.') else configured
    base=re.sub(r'[^A-Za-z0-9_.-]','_',base or 'clube_fidelidade')
    campaign=re.sub(r'[^A-Za-z0-9_.-]','_',str(card.get('campaign_code') or 'cliente').lower())
    # One class per company/campaign is required for independent logo/color branding.
    suffix=base if base.endswith('_'+campaign) else f'{base}_{campaign}'
    return f'{issuer}.{suffix}'


def _google_logo_url(card):
    base=_google_public_url()
    code=str(card.get('campaign_code') or '').strip()
    
    if not (base and code and card.get('logo_image')):
        return ''
    # Cache-bust the image URL whenever the stored logo changes. Google Wallet
    # caches remote image assets aggressively, so reusing the same URL can keep
    # an older processed logo even after the class is patched. The renderer revision
    # suffix MUST change whenever the server-side crop/resize algorithm changes.
    digest=hashlib.sha256(str(card.get('logo_image')).encode('utf-8')).hexdigest()[:12]
    return f"{base}/api/wallet/logo/{urllib.parse.quote(code)}.png?v={digest}-r57"


def _google_class_object(card):
    class_id=_google_class_id(card)
    logo=_google_logo_url(card)
    klass={
      'id':class_id,
      'issuerName':card.get('campaign_name') or 'Clube Fidelidade',
      'programName':'Clube de Fidelidade',
      'reviewStatus':'UNDER_REVIEW',
      'hexBackgroundColor':_theme_hex(card.get('card_theme')),
      'accountNameLabel':'Cliente',
      'accountIdLabel':'Código do cartão',
      'classTemplateInfo':{
        'cardTemplateOverride':{
          'cardRowTemplateInfos':[
            {'twoItems':{
              'startItem':{'firstValue':{'fields':[{'fieldPath':'object.loyaltyPoints.balance'}]}},
              'endItem':{'firstValue':{'fields':[{'fieldPath':"object.textModulesData['reward']"}]}}
            }},
            {'oneItem':{'item':{'firstValue':{'fields':[{'fieldPath':'object.accountName'}]}}}}
          ]
        },
        'listTemplateOverride':{
          'firstRowOption':{'fieldOption':{'fields':[{'fieldPath':'object.loyaltyPoints.balance'}]}},
          'secondRowOption':{'fields':[{'fieldPath':"object.textModulesData['reward']"}]}
        }
      }
    }
    if logo:
        klass['programLogo']={'sourceUri':{'uri':logo,'description':'Logo '+str(card.get('campaign_name') or 'Clube Fidelidade')}}
    origin=_google_public_url()
    if origin:
        klass['homepageUri']={'uri':origin,'description':'Acessar cartão'}
    return klass


def _google_object(card):
    issuer=os.environ['GOOGLE_WALLET_ISSUER_ID'].strip()
    obj_suffix=re.sub(r'[^A-Za-z0-9_.-]','_',card['public_id'])
    points=card.get('loyalty_type')=='points'
    balance=str(card.get('points_balance',0)) if points else f"{card.get('progress',0)} de {card.get('goal',0)}"
    reward='Consulte o catálogo de recompensas' if points else (card.get('reward_name') or 'Recompensa do programa')
    body={
      'id':f'{issuer}.{obj_suffix}',
      'classId':_google_class_id(card),
      'state':'ACTIVE',
      'accountId':'CLUBE:'+card['public_id'],
      'accountName':card.get('customer_name') or '',
      'loyaltyPoints':{'label':'Pontos' if points else 'Selos','balance':{'string':balance}},
      'barcode':{'type':'QR_CODE','value':'CLUBE:'+card['public_id'],'alternateText':'CLUBE:'+card['public_id']},
      'textModulesData':[
        {'id':'reward','header':'Próxima recompensa' if not points else 'Recompensas','body':reward},
        {'id':'status','header':'Seu saldo','body':(str(card.get('points_balance',0))+' pontos') if points else (str(card.get('progress',0))+' de '+str(card.get('goal',0))+' selos')},
        {'id':'member','header':'Cliente','body':card.get('customer_name') or ''}
      ]
    }
    origin=_google_public_url()
    if origin:
        body['linksModuleData']={'uris':[{'uri':origin+'/card?id='+urllib.parse.quote(card['public_id']),'description':'Abrir cartão digital'}]}
    return body


def _icon_png(size, theme='green', logo_data=None):
    if logo_data and str(logo_data).startswith('data:image/'):
        try:
            raw=base64.b64decode(str(logo_data).split(',',1)[1])
            im=Image.open(BytesIO(raw)).convert('RGBA')
            im.thumbnail((size,size),Image.Resampling.LANCZOS)
            canvas=Image.new('RGBA',(size,size),(255,255,255,0)); canvas.alpha_composite(im,((size-im.width)//2,(size-im.height)//2))
            out=BytesIO(); canvas.save(out,'PNG'); return out.getvalue()
        except Exception: pass
    im=Image.new('RGB',(size,size),_theme_rgb(theme)); d=ImageDraw.Draw(im); d.ellipse((size*.18,size*.18,size*.82,size*.82),fill='white')
    out=BytesIO(); im.save(out,'PNG'); return out.getvalue()


def build_apple_pkpass(card):
    if not wallet_status()['apple']['ready']: raise RuntimeError('apple_wallet_not_configured')
    public_url=os.environ['CLUBE_PUBLIC_URL'].rstrip('/')
    pass_json={
      'formatVersion':1,
      'passTypeIdentifier':os.environ['APPLE_PASS_TYPE_ID'],
      'serialNumber':card['public_id'],
      'teamIdentifier':os.environ['APPLE_TEAM_ID'],
      'organizationName':card.get('campaign_name') or 'Clube Fidelidade',
      'description':'Cartão de fidelidade',
      'logoText':card.get('campaign_name') or 'Clube Fidelidade',
      'foregroundColor':'rgb(255,255,255)',
      'backgroundColor':'rgb(%d,%d,%d)'%_theme_rgb(card.get('card_theme')),
      'labelColor':'rgb(235,235,235)',
      'webServiceURL':public_url+'/api/apple-wallet/v1',
      'authenticationToken':apple_auth_token(card['public_id']),
      'generic':{
        'primaryFields':[{'key':'balance','label':'PONTOS' if card.get('loyalty_type')=='points' else 'SELOS','value':str(card.get('points_balance',0)) if card.get('loyalty_type')=='points' else f"{card.get('progress',0)} de {card.get('goal',0)}"}],
        'secondaryFields':[{'key':'reward','label':'RECOMPENSAS' if card.get('loyalty_type')=='points' else 'RECOMPENSA','value':'Consulte o catálogo no cartão' if card.get('loyalty_type')=='points' else (card.get('reward_name') or '')}],
        'auxiliaryFields':[{'key':'code','label':'CÓDIGO','value':'CLUBE:'+card['public_id']}]
      },
      'barcodes':[{'format':'PKBarcodeFormatQR','message':'CLUBE:'+card['public_id'],'messageEncoding':'iso-8859-1'}],
      'barcode':{'format':'PKBarcodeFormatQR','message':'CLUBE:'+card['public_id'],'messageEncoding':'iso-8859-1'}
    }
    files={'pass.json':json.dumps(pass_json,ensure_ascii=False,separators=(',',':')).encode('utf-8')}
    for name,size in [('icon.png',29),('icon@2x.png',58),('logo.png',160),('logo@2x.png',320)]:
        files[name]=_icon_png(size,card.get('card_theme'),card.get('logo_image'))
    manifest={name:hashlib.sha1(data).hexdigest() for name,data in files.items()}
    files['manifest.json']=json.dumps(manifest,separators=(',',':')).encode('utf-8')
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        for name,data in files.items():(td/name).write_bytes(data)
        cert=_material_path(td,'APPLE_CERT_PATH','APPLE_CERT_PEM','pass-cert.pem')
        key=_material_path(td,'APPLE_KEY_PATH','APPLE_KEY_PEM','pass-key.pem')
        wwdr=_material_path(td,'APPLE_WWDR_CERT_PATH','APPLE_WWDR_CERT_PEM','wwdr.pem')
        cmd=['openssl','smime','-binary','-sign','-certfile',wwdr,'-signer',cert,'-inkey',key,'-in',str(td/'manifest.json'),'-out',str(td/'signature'),'-outform','DER']
        if os.environ.get('APPLE_KEY_PASSWORD'): cmd += ['-passin','env:APPLE_KEY_PASSWORD']
        env=os.environ.copy()
        res=subprocess.run(cmd,capture_output=True,env=env,timeout=20)
        if res.returncode!=0: raise RuntimeError('apple_pass_sign_failed:'+res.stderr.decode('utf-8','ignore')[:300])
        out=BytesIO()
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
            for name in list(files.keys())+['signature']:
                pass_file=td/name
                z.writestr(name,pass_file.read_bytes())
        return out.getvalue()


def google_wallet_jwt(card, include_class=True):
    if not wallet_status()['google']['ready']: raise RuntimeError('google_wallet_not_configured')
    email=os.environ['GOOGLE_SERVICE_ACCOUNT_EMAIL'].strip()
    private_key=os.environ['GOOGLE_PRIVATE_KEY'].replace('\\n','\n')
    class_obj=_google_class_object(card)
    object_obj=_google_object(card)
    wallet_payload={'loyaltyObjects':[object_obj]}
    if include_class:
        wallet_payload['loyaltyClasses']=[class_obj]
    payload={'iss':email,'aud':'google','typ':'savetowallet','iat':int(time.time()),'payload':wallet_payload}
    origin=_google_public_url()
    if origin: payload['origins']=[origin]
    return _sign_rs256({'alg':'RS256','typ':'JWT'},payload,private_key),object_obj['id']

def google_save_url(card):
    # Ensure the company-specific class really exists before creating the Save URL.
    # Previous versions only PATCHed it; a new per-company class returned 404 and
    # therefore never persisted its programLogo/branding in Google Wallet.
    class_ready=google_ensure_class(card)
    token,_=google_wallet_jwt(card, include_class=not class_ready)
    return 'https://pay.google.com/gp/v/save/'+token


def _google_access_token():
    email=os.environ['GOOGLE_SERVICE_ACCOUNT_EMAIL'].strip(); private_key=os.environ['GOOGLE_PRIVATE_KEY'].replace('\\n','\n')
    now=int(time.time())
    assertion=_sign_rs256({'alg':'RS256','typ':'JWT'},{'iss':email,'scope':'https://www.googleapis.com/auth/wallet_object.issuer','aud':'https://oauth2.googleapis.com/token','iat':now,'exp':now+3600},private_key)
    data=urllib.parse.urlencode({'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer','assertion':assertion}).encode()
    req=urllib.request.Request('https://oauth2.googleapis.com/token',data=data,method='POST',headers={'Content-Type':'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req,timeout=15) as r:return json.loads(r.read().decode())['access_token']


def _google_patch(resource, resource_id, body):
    req=urllib.request.Request(
        'https://walletobjects.googleapis.com/walletobjects/v1/'+resource+'/'+urllib.parse.quote(resource_id,safe='.'),
        data=json.dumps(body,ensure_ascii=False,separators=(',',':')).encode('utf-8'),method='PATCH',
        headers={'Authorization':'Bearer '+_google_access_token(),'Content-Type':'application/json'}
    )
    with urllib.request.urlopen(req,timeout=15) as r:r.read()

def _google_insert(resource, body):
    req=urllib.request.Request(
        'https://walletobjects.googleapis.com/walletobjects/v1/'+resource,
        data=json.dumps(body,ensure_ascii=False,separators=(',',':')).encode('utf-8'),method='POST',
        headers={'Authorization':'Bearer '+_google_access_token(),'Content-Type':'application/json'}
    )
    with urllib.request.urlopen(req,timeout=15) as r:
        return json.loads(r.read().decode('utf-8') or '{}')

def google_ensure_class(card):
    if not wallet_status()['google']['ready']: return False
    klass=_google_class_object(card)
    body={k:v for k,v in klass.items() if k not in ('id','reviewStatus')}
    try:
        _google_patch('loyaltyClass',klass['id'],body)
        print('[GOOGLE_WALLET] class updated:', klass['id'], 'logo=', bool(klass.get('programLogo')))
        return True
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            detail=exc.read().decode('utf-8','ignore')[:500]
            print('[GOOGLE_WALLET] class update failed:', exc.code, detail)
            return False
    try:
        _google_insert('loyaltyClass',klass)
        print('[GOOGLE_WALLET] class created:', klass['id'], 'logo=', bool(klass.get('programLogo')))
        return True
    except urllib.error.HTTPError as exc:
        detail=exc.read().decode('utf-8','ignore')[:500]
        # A concurrent request may have created it after our 404; patch once more.
        if exc.code == 409:
            try:
                _google_patch('loyaltyClass',klass['id'],body)
                print('[GOOGLE_WALLET] class updated after conflict:', klass['id'])
                return True
            except Exception as patch_exc:
                print('[GOOGLE_WALLET] class patch after conflict failed:', repr(patch_exc))
        print('[GOOGLE_WALLET] class create failed:', exc.code, detail)
        return False
    except Exception as exc:
        print('[GOOGLE_WALLET] class create failed:', repr(exc))
        return False

def google_update_class(card):
    return google_ensure_class(card)


def google_update_object(card):
    if not wallet_status()['google']['ready']: return False
    obj=_google_object(card)
    body={k:v for k,v in obj.items() if k not in ('id','classId','state')}
    try:
        google_update_class(card)
        _google_patch('loyaltyObject',obj['id'],body)
        return True
    except Exception:
        return False

def apple_push_update(push_token):
    if not wallet_status()['apple']['ready'] or not push_token:return False
    topic=os.environ.get('APPLE_PASS_TYPE_ID','')
    host='https://api.push.apple.com/3/device/'+push_token
    try:
        with tempfile.TemporaryDirectory() as td:
            cert=_material_path(td,'APPLE_PUSH_CERT_PATH','APPLE_CERT_PEM','push-cert.pem') or _material_path(td,'APPLE_CERT_PATH','APPLE_CERT_PEM','push-cert.pem')
            key=_material_path(td,'APPLE_PUSH_KEY_PATH','APPLE_KEY_PEM','push-key.pem') or _material_path(td,'APPLE_KEY_PATH','APPLE_KEY_PEM','push-key.pem')
            cmd=['curl','-sS','--http2','--max-time','12','--cert',cert,'--key',key,'-H','apns-topic: '+topic,'-H','content-type: application/json','-d','{}',host]
            if os.environ.get('APPLE_KEY_PASSWORD'): cmd += ['--pass',os.environ['APPLE_KEY_PASSWORD']]
            r=subprocess.run(cmd,capture_output=True,timeout=15)
            return r.returncode==0
    except Exception:return False
