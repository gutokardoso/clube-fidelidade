#!/usr/bin/env python3
import argparse, hashlib, hmac, json, re, sqlite3, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from db import init_db
BACKUP_FORMAT='fidelizae-platform-backup-v1'

def validate_payload(payload):
    if not isinstance(payload,dict) or payload.get('format')!=BACKUP_FORMAT or not isinstance(payload.get('tables'),dict): return False,'invalid_backup_format'
    expected=str(payload.get('sha256') or '')
    unsigned=dict(payload); unsigned.pop('sha256',None)
    raw=json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    if not expected or not hmac.compare_digest(expected,hashlib.sha256(raw).hexdigest()): return False,'backup_checksum_invalid'
    counts=payload.get('counts') or {}
    for table,rows in payload['tables'].items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',table): return False,'invalid_table_name'
        if not isinstance(rows,list) or int(counts.get(table,-1))!=len(rows): return False,'backup_count_mismatch'
    return True,'ok'

def load_backup(path):
    payload=json.loads(Path(path).read_text(encoding='utf-8')); ok,reason=validate_payload(payload)
    if not ok: raise RuntimeError(reason)
    return payload

def restore_sqlite(payload,target):
    target=Path(target)
    if target.exists(): raise RuntimeError('target_exists')
    init_db(str(target))
    conn=sqlite3.connect(str(target)); conn.row_factory=sqlite3.Row
    try:
        conn.execute('PRAGMA foreign_keys=OFF')
        existing={r['name'] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        tables={k:v for k,v in payload['tables'].items() if k in existing}
        for table in tables: conn.execute(f'DELETE FROM "{table}"')
        for table,rows in tables.items():
            cols={r['name'] for r in conn.execute(f'PRAGMA table_info("{table}")')}
            for row in rows:
                keys=[k for k in row if k in cols]
                if not keys: continue
                sql=f'INSERT INTO "{table}" ('+','.join('"'+k+'"' for k in keys)+') VALUES ('+','.join('?' for _ in keys)+')'
                conn.execute(sql,[row[k] for k in keys])
        conn.commit(); conn.execute('PRAGMA foreign_keys=ON')
        integrity=conn.execute('PRAGMA integrity_check').fetchone()[0]; fk=list(conn.execute('PRAGMA foreign_key_check'))
        if integrity!='ok': raise RuntimeError('sqlite_integrity_failed:'+str(integrity))
        if fk: raise RuntimeError('foreign_key_check_failed:'+str(len(fk)))
        restored={t:conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables}
        for t,count in payload.get('counts',{}).items():
            if t in restored and restored[t]!=int(count): raise RuntimeError('restore_count_mismatch:'+t)
        return {'tables':len(restored),'rows':sum(restored.values()),'integrity':'ok'}
    finally: conn.close()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('command',choices=['validate','restore-sqlite']); ap.add_argument('backup'); ap.add_argument('target',nargs='?'); a=ap.parse_args()
    payload=load_backup(a.backup)
    if a.command=='validate': print(json.dumps({'ok':True,'tables':len(payload['tables']),'rows':sum(payload['counts'].values()),'sha256':payload['sha256']},ensure_ascii=False)); return
    if not a.target: ap.error('restore-sqlite exige destino')
    print(json.dumps({'ok':True,**restore_sqlite(payload,a.target)},ensure_ascii=False))
if __name__=='__main__': main()
