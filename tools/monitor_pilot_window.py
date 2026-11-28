"""Read-only by default. Set the pilot window only with --apply while monitoring is off."""
import argparse
from datetime import timedelta
import json
import os
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import job_store
from account_store import now


def run(days=28,apply=False):
    if not 1<=days<=28:raise ValueError('Pilot duration must be 1..28 days')
    if apply and os.getenv('MONITOR_ENABLED','false').lower()=='true':raise ValueError('Disable monitoring before changing the pilot window')
    with job_store.connect() as db:
        row=db.execute('SELECT ends_at FROM privetek_monitor_pilot WHERE id=1'+(' FOR UPDATE' if apply else '')).fetchone()
        if not row:raise ValueError('Monitoring migrations are missing')
        current=now();outcome=dict(expired=row['ends_at']<=current,ends_at=row['ends_at'].isoformat(),applied=False)
        if apply:
            # Do not silently pause, resume, enroll, or rewrite any user's monitor.
            if db.execute("SELECT 1 FROM privetek_monitors WHERE state='active' LIMIT 1").fetchone():raise ValueError('Active subscriptions require separate review')
            end=current+timedelta(days=days)
            db.execute('UPDATE privetek_monitor_pilot SET ends_at=%s,day=CURRENT_DATE,scans=0,mails=0 WHERE id=1',(end,))
            outcome.update(applied=True,ends_at=end.isoformat(),expired=False)
    return outcome

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--days',type=int,default=28);p.add_argument('--apply',action='store_true');a=p.parse_args()
    try:print(json.dumps(run(a.days,a.apply)))
    except Exception as e:print(json.dumps({'error_type':type(e).__name__,'changed':False}));raise SystemExit(1)
