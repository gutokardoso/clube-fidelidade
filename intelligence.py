from statistics import median
from security import now_ts

DAY=86400


def _purchase_times(conn,membership_id):
    rows=conn.execute('SELECT created_at FROM purchase_records WHERE membership_id=? ORDER BY created_at',(membership_id,)).fetchall()
    if rows:
        return [int(r['created_at']) for r in rows]
    rows=conn.execute("SELECT created_at FROM transactions WHERE membership_id=? AND value>0 AND type IN ('stamp','adjustment') AND COALESCE(note,'')<>'Saldo inicial importado' ORDER BY created_at",(membership_id,)).fetchall()
    return [int(r['created_at']) for r in rows]


def customer_intelligence(conn,membership,campaign=None,now=None):
    now=int(now or now_ts()); mid=int(membership['id'])
    times=_purchase_times(conn,mid)
    first=int(membership['created_at'] or (times[0] if times else now))
    last=times[-1] if times else first
    days_since=max(0,(now-last)//DAY)
    intervals=[max(1,(b-a)//DAY) for a,b in zip(times,times[1:]) if b>a]
    freq_days=round(sum(intervals)/len(intervals),1) if intervals else None
    med_days=round(median(intervals),1) if intervals else None
    purchase=conn.execute('SELECT COUNT(*) purchases,COALESCE(SUM(amount_cents),0) revenue FROM purchase_records WHERE membership_id=?',(mid,)).fetchone()
    purchases=int(purchase['purchases'] or len(times) or 0); revenue=int(purchase['revenue'] or 0)
    ticket=round(revenue/max(int(purchase['purchases'] or 0),1)) if revenue else 0
    redeems=int(conn.execute("SELECT COUNT(*) n FROM transactions WHERE membership_id=? AND type='redeem'",(mid,)).fetchone()['n'] or 0)
    age_days=max(1,(now-first)//DAY)
    monthly_value=round(revenue/max(age_days/30,1)) if revenue else 0
    ltv=max(revenue, round(monthly_value*12)) if revenue else 0
    reward_ready=bool(int(membership.get('rewards_available',0) if isinstance(membership,dict) else membership['rewards_available'] or 0))
    loyalty=(campaign or {}).get('loyalty_type') if isinstance(campaign,dict) else None
    if not loyalty:
        try: loyalty=membership['loyalty_type']
        except Exception: loyalty='stamps'
    if loyalty=='points':
        try:
            campaign_id=membership.get('campaign_id') if isinstance(membership,dict) else membership['campaign_id']
            cheapest_ready=conn.execute('SELECT MIN(points_cost) n FROM reward_catalog WHERE campaign_id=? AND active=1',(campaign_id,)).fetchone()['n']
            balance_ready=int(membership.get('points_balance',0) if isinstance(membership,dict) else membership['points_balance'] or 0)
            if cheapest_ready and balance_ready>=int(cheapest_ready): reward_ready=True
        except Exception:
            pass
    almost=False
    try:
        if loyalty=='stamps': almost=int(membership['progress'] or 0)==max(0,int(membership['goal'] or 0)-1)
        else:
            cheapest=conn.execute('SELECT MIN(points_cost) n FROM reward_catalog WHERE campaign_id=? AND active=1',(membership['campaign_id'],)).fetchone()['n']
            bal=int(membership['points_balance'] or 0); almost=bool(cheapest and 0<int(cheapest)-bal<=max(1,int(int(cheapest)*.15)))
    except Exception: pass
    if reward_ready: status='reward_ready'
    elif almost: status='almost_reward'
    elif purchases<=1 and age_days<=30: status='new'
    else:
        expected=med_days or freq_days
        if expected and len(times)>=3:
            ratio=days_since/max(expected,1)
            if days_since>=90 or ratio>=3: status='inactive'
            elif days_since>=30 or ratio>=1.8: status='at_risk'
            elif purchases>=12 and (revenue>=100000 or age_days>=90): status='vip'
            elif purchases>=3: status='recurrent'
            else: status='active'
        else:
            if days_since>=90: status='inactive'
            elif days_since>=45: status='at_risk'
            elif purchases>=12: status='vip'
            elif purchases>=3: status='recurrent'
            else: status='active'
    next_expected=(last+round((med_days or freq_days or 0)*DAY)) if (med_days or freq_days) else None
    return {'segment':status,'purchases':purchases,'revenue_cents':revenue,'avg_ticket_cents':ticket,'frequency_days':freq_days,'median_frequency_days':med_days,'days_since_last':days_since,'last_purchase_at':last,'first_purchase_at':times[0] if times else None,'redeems':redeems,'ltv_estimated_cents':ltv,'next_expected_at':next_expected}


def campaign_intelligence(conn,campaign_id):
    rows=conn.execute('''SELECT m.*,c.goal,c.loyalty_type FROM memberships m JOIN campaigns c ON c.id=m.campaign_id WHERE m.campaign_id=? AND m.status='active' ''',(campaign_id,)).fetchall()
    data=[]
    for r in rows:
        d=dict(r); d.update(customer_intelligence(conn,d,d)); data.append(d)
    counts={k:0 for k in ('new','active','recurrent','vip','at_risk','inactive','almost_reward','reward_ready')}
    for d in data: counts[d['segment']]=counts.get(d['segment'],0)+1
    total=len(data); recurrent=sum(1 for d in data if d['purchases']>=2)
    rev=sum(d['revenue_cents'] for d in data); purchases=sum(d['purchases'] for d in data)
    freqs=[d['frequency_days'] for d in data if d['frequency_days']]
    ltv=[d['ltv_estimated_cents'] for d in data if d['ltv_estimated_cents']]
    return {'segments':counts,'return_rate':round(recurrent*100/max(total,1),1),'avg_ticket_cents':round(rev/max(purchases,1)) if rev else 0,'avg_frequency_days':round(sum(freqs)/len(freqs),1) if freqs else None,'avg_ltv_cents':round(sum(ltv)/len(ltv)) if ltv else 0,'customers':data}
