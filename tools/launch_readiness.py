"""Read-only readiness inventory. Never sends SMS, mail, HIBP queries, or a monitor tick."""
import argparse,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import sms_provider


def report(database=False):
    env=os.environ
    out=dict(sms=dict(enabled=env.get('SMS_AUTH_ENABLED','false').lower()=='true',live_send_enabled=env.get('SMS_LIVE_SEND_ENABLED','false').lower()=='true',provider=env.get('SMS_PROVIDER','not_selected'),api_key_present=bool(env.get('SMS_RU_API_ID')),pilot_allowlist_present=bool(env.get('SMS_PILOT_PHONE_HASHES')),ready=sms_provider.configured()),
      hibp=dict(key_present=bool(env.get('HIBP_API_KEY','').strip()),explicitly_disabled=env.get('HIBP_ENABLED','').lower()=='false',interval_seconds=env.get('HIBP_MIN_INTERVAL_SECONDS','6.5')),
      monitoring=dict(enabled=env.get('MONITOR_ENABLED','false').lower()=='true',runner_token_present=len(env.get('MONITOR_RUNNER_TOKEN',''))>=32,scheduler_external_verification_required=True),
      email=dict(provider=env.get('MAIL_PROVIDER','not_configured'),brevo_key_present=bool(env.get('BREVO_API_KEY')),sender_present=bool(env.get('MAIL_FROM'))),
      accounts=dict(enabled=env.get('ACCOUNTS_ENABLED','false').lower()=='true',database_present=bool(env.get('DATABASE_URL')),secret_present=len(env.get('ACCOUNT_SECRET',''))>=32,report_key_present=bool(env.get('ACCOUNT_REPORT_KEY'))),
      no_provider_calls=True,database_checked=False)
    if database:
        try:
            import job_store
            with job_store.connect() as db:
                row=db.execute('SELECT ends_at,ends_at<=now() AS expired FROM privetek_monitor_pilot WHERE id=1').fetchone()
                migrations=db.execute('SELECT version FROM privetek_schema_migrations ORDER BY version').fetchall()
            out['database_checked']=True
            out['monitoring'].update(pilot_expired=row['expired'],pilot_ends_at=row['ends_at'].isoformat())
            out['phone_schema_ready']=any(x['version']=='014_phone_auth.sql' for x in migrations)
        except Exception as e:out['database_error_type']=type(e).__name__
    return out

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--database',action='store_true');a=p.parse_args();print(json.dumps(report(a.database),indent=2))
