import json, threading, time
from datetime import datetime
from zoneinfo import ZoneInfo

PERMISSIONS=('add_balance','remove_balance','redeem_reward','use_gift','view_reports','send_messages')

def session_permissions(sess):
    if not sess: return {}
    if sess.get('is_client_admin'): return {k:True for k in PERMISSIONS}
    raw=sess.get('permissions_json')
    try: data=json.loads(raw or '{}') if isinstance(raw,str) else (raw or {})
    except Exception: data={}
    # Compatibilidade com atendentes antigos: sem configuração explícita = permissões operacionais liberadas.
    if not data: return {k:True for k in PERMISSIONS}
    return {k:bool(data.get(k)) for k in PERMISSIONS}

def has_permission(sess, key):
    return bool(session_permissions(sess).get(key, False))

def active_multiplier(conn,campaign_id,ts=None):
    ts=ts or int(time.time())
    dt=datetime.fromtimestamp(ts,ZoneInfo('America/Sao_Paulo'))
    # UI usa 0=domingo,1=segunda,...6=sábado
    wd=str((dt.weekday()+1)%7); hh=dt.strftime('%H:%M')
    rows=conn.execute("SELECT factor,weekday,start_hour,end_hour FROM point_multipliers WHERE campaign_id=? AND active=1",(campaign_id,)).fetchall()
    factor=1.0
    for r in rows:
        if str(r['weekday'] or 'all') not in ('all',wd): continue
        start=str(r['start_hour'] or '').strip(); end=str(r['end_hour'] or '').strip()
        if start and hh<start: continue
        if end and hh>end: continue
        factor=max(factor,float(r['factor'] or 1))
    return factor

def add_point_lot(conn,membership_id,transaction_id,points,expiry_days,created_at):
    points=int(points or 0)
    if points<=0:return
    expiry_days=int(expiry_days or 180)
    expires_at=created_at+expiry_days*86400 if expiry_days>0 else None
    conn.execute("INSERT INTO point_lots(membership_id,transaction_id,points,remaining_points,expires_at,created_at) VALUES(?,?,?,?,?,?)",(membership_id,transaction_id,points,points,expires_at,created_at))

def consume_point_lots(conn,membership_id,points):
    remaining=max(0,int(points or 0))
    if not remaining:return 0
    rows=conn.execute("SELECT id,remaining_points FROM point_lots WHERE membership_id=? AND remaining_points>0 ORDER BY COALESCE(expires_at,9223372036854775807),id",(membership_id,)).fetchall()
    consumed=0
    for r in rows:
        if remaining<=0:break
        take=min(remaining,int(r['remaining_points'] or 0))
        conn.execute("UPDATE point_lots SET remaining_points=remaining_points-? WHERE id=?",(take,r['id']))
        remaining-=take; consumed+=take
    return consumed

def expire_points_once(conn,now_ts):
    rows=conn.execute("SELECT pl.id,pl.membership_id,pl.remaining_points,m.points_balance FROM point_lots pl JOIN memberships m ON m.id=pl.membership_id WHERE pl.remaining_points>0 AND pl.expires_at IS NOT NULL AND pl.expires_at<=? ORDER BY pl.expires_at,pl.id",(now_ts,)).fetchall()
    expired=0
    for r in rows:
        pts=min(int(r['remaining_points'] or 0),int(r['points_balance'] or 0))
        conn.execute("UPDATE point_lots SET remaining_points=0 WHERE id=?",(r['id'],))
        if pts<=0:continue
        prev=int(r['points_balance'] or 0); new=max(0,prev-pts)
        try:
            conn.execute("INSERT INTO transactions(membership_id,user_id,branch_id,type,value,previous_progress,new_progress,rewards_delta,idempotency_key,ip_address,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(r['membership_id'],None,None,'adjustment',-pts,prev,new,0,f'points-expiry:{r["id"]}',None,'Expiração automática de pontos',now_ts))
        except Exception:
            pass
        conn.execute("UPDATE memberships SET points_balance=? WHERE id=?",(new,r['membership_id']))
        expired+=pts
    return expired

def record_purchase(conn,membership_id,transaction_id,amount_cents,channel='in_store',created_at=None):
    amount=max(0,int(amount_cents or 0))
    if amount<=0:return
    created_at=created_at or int(time.time())
    try: conn.execute("INSERT INTO purchase_records(membership_id,transaction_id,amount_cents,channel,created_at) VALUES(?,?,?,?,?)",(membership_id,transaction_id,amount,channel,created_at))
    except Exception: pass
    # atribui retorno à campanha mais recente ainda não convertida, em janela de 30 dias
    rec=conn.execute("SELECT mcr.id FROM marketing_campaign_recipients mcr WHERE mcr.membership_id=? AND mcr.returned_at IS NULL AND mcr.sent_at<=? AND mcr.sent_at>=? ORDER BY mcr.sent_at DESC LIMIT 1",(membership_id,created_at,created_at-30*86400)).fetchone()
    if rec:
        try: conn.execute("UPDATE marketing_campaign_recipients SET returned_at=?,returned_transaction_id=?,attributed_revenue_cents=? WHERE id=?",(created_at,transaction_id,amount,rec['id']))
        except Exception: pass

class RateLimiter:
    def __init__(self):
        self.lock=threading.Lock(); self.events={}
    def allow(self,key,limit,window):
        now=time.time()
        with self.lock:
            arr=[x for x in self.events.get(key,[]) if x>now-window]
            if len(arr)>=limit:
                self.events[key]=arr; return False
            arr.append(now); self.events[key]=arr; return True
RATE_LIMITER=RateLimiter()
