"""Worker separado opcional para filas/automações/backups em produção."""
import time
from db import init_db
from server import DB_PATH, process_message_queue_once, run_automations_once, run_meta_template_sync_once, run_scheduled_r2_backup_once

def main():
    init_db(DB_PATH,seed=False); tick=299
    while True:
        try: process_message_queue_once(limit=30)
        except Exception as exc: print('[QUEUE]',type(exc).__name__,str(exc)[:300])
        tick+=1
        if tick%30==0:
            try: run_automations_once()
            except Exception as exc: print('[AUTOMATION]',type(exc).__name__,str(exc)[:300])
        if tick%300==0:
            try: run_meta_template_sync_once()
            except Exception as exc: print('[META_TEMPLATES]',type(exc).__name__,str(exc)[:300])
            try: run_scheduled_r2_backup_once()
            except Exception as exc: print('[R2_BACKUP]',type(exc).__name__,str(exc)[:300])
        time.sleep(2)
if __name__=='__main__':main()
