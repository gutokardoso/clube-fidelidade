"""Normalizadores de payloads de e-commerce.

Cada adaptador reduz o payload nativo a um contrato pequeno que o servidor
converte para o formato interno do Fidelizaê!. A conexão/autorização oficial
continua sendo configurada por plataforma no painel da empresa.
"""
import re

def digits(v): return re.sub(r'\D','',str(v or ''))

def _first_meta(items, keys):
    keys={str(k).lower() for k in keys}
    for x in items or []:
        if isinstance(x,dict) and str(x.get('key') or x.get('name') or '').lower() in keys:
            return x.get('value')
    return None

def platform_order(payload,platform):
    d=payload if isinstance(payload,dict) else {}
    p=(platform or 'custom').lower()
    if p=='woocommerce':
        billing=d.get('billing') or {}
        cpf=_first_meta(d.get('meta_data'),('cpf','billing_cpf','_billing_cpf','billing_cpfcnpj')) or billing.get('cpf')
        return {'id':d.get('id'),'status':d.get('status'),'total':d.get('total',0),'email':billing.get('email'),'phone':billing.get('phone'),'cpf':cpf}
    if p=='shopify':
        cust=d.get('customer') or {}; addr=d.get('billing_address') or {}
        cpf=d.get('cpf') or _first_meta(d.get('note_attributes'),('cpf','document','documento')) or cust.get('cpf')
        return {'id':d.get('id') or d.get('order_number'),'status':d.get('financial_status') or d.get('status'),'total':d.get('current_total_price') or d.get('total_price'),'email':d.get('email') or cust.get('email'),'phone':d.get('phone') or addr.get('phone') or cust.get('phone'),'cpf':cpf}
    if p=='nuvemshop':
        cust=d.get('customer') or {}
        ident=cust.get('identification')
        if isinstance(ident,dict): ident=ident.get('number') or ident.get('value')
        return {'id':d.get('id'),'status':d.get('payment_status') or d.get('status'),'total':d.get('total'),'email':cust.get('email') or d.get('contact_email'),'phone':cust.get('phone') or d.get('contact_phone'),'cpf':ident or cust.get('cpf')}
    if p in ('tray','vtex','loja_integrada'):
        cust=d.get('customer') or d.get('client') or {}
        return {'id':d.get('order_id') or d.get('id') or d.get('orderId'),'status':d.get('payment_status') or d.get('status'),'total':d.get('total') or d.get('value') or d.get('total_price'),'email':d.get('email') or cust.get('email'),'phone':d.get('phone') or cust.get('phone'),'cpf':d.get('cpf') or cust.get('cpf') or cust.get('document')}
    # API personalizada preserva centavos quando o integrador já os envia assim.
    out={'id':d.get('order_id') or d.get('id'),'status':d.get('payment_status') or d.get('status'),'email':d.get('email') or (d.get('customer') or {}).get('email'),'phone':d.get('phone') or (d.get('customer') or {}).get('phone'),'cpf':d.get('cpf') or (d.get('customer') or {}).get('cpf')}
    if d.get('total_cents') is not None: out['total_cents']=d.get('total_cents')
    else: out['total']=d.get('total')
    return out
