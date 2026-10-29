"""Encrypted opt-in monitoring and durable scan/mail claims. No production inputs in logs."""
import json
from datetime import timedelta
from uuid import uuid4
from account_crypto import report_cipher
from account_store import now
import job_store
from search_inputs import normalize_username


def encode(value):return report_cipher().encrypt(json.dumps(value,ensure_ascii=False).encode())
def decode(value):return json.loads(report_cipher().decrypt(bytes(value))) if value else None


def pilot(db):
    return db.execute('SELECT * FROM privetek_monitor_pilot WHERE id=1 FOR UPDATE').fetchone()


def settings(user_id):
    with job_store.connect() as db:
        row=db.execute('SELECT * FROM privetek_monitors WHERE user_id=%s',(user_id,)).fetchone()
        end=db.execute('SELECT ends_at FROM privetek_monitor_pilot WHERE id=1').fetchone()['ends_at']
        count=db.execute('SELECT count(*) AS n FROM privetek_monitors').fetchone()['n']
    result=dict(state='off',username='',pilot_ends_at=end,pilot_capacity=10,pilot_used=count,exclusions=[])
    if row:
        config=decode(row['config'])
        result.update(state=row['state'] if end>now() else 'paused',username=config['username'],
            use_profile_reviews=config.get('use_profile_reviews',True),next_run_at=row['next_run_at'],
            last_checked_at=row['last_checked_at'],last_status=row['last_status'],
            included=config.get('included',[]),exclusions=[dict(value,id=item_id) for item_id,value in config.get('excluded',{}).items()])
    return result


def change(user_id,action,username='',consent=False,use_reviews=True):
    with job_store.connect() as db:
        control=pilot(db)
        row=db.execute('SELECT * FROM privetek_monitors WHERE user_id=%s FOR UPDATE',(user_id,)).fetchone()
        if action=='delete':
            db.execute('DELETE FROM privetek_monitors WHERE user_id=%s',(user_id,));return
        if action=='pause':
            if row:
                db.execute("UPDATE privetek_monitors SET state='paused',version=version+1,lease=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE user_id=%s",(user_id,))
                db.execute("UPDATE privetek_monitor_runs SET mail_state='cancelled' WHERE user_id=%s AND mail_state='pending'",(user_id,))
            return
        if action not in ('enable','resume'):raise ValueError('Unknown monitoring action')
        if control['ends_at']<=now():raise RuntimeError('pilot_ended')
        if action=='resume':
            if not row:raise ValueError('No monitoring to resume')
            db.execute("UPDATE privetek_monitors SET state='active',next_run_at=CURRENT_TIMESTAMP,version=version+1,lease=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE user_id=%s",(user_id,));return
        if consent is not True:raise ValueError('Consent required')
        username=normalize_username(username)
        if not row and db.execute('SELECT count(*) AS n FROM privetek_monitors').fetchone()['n']>=10:raise RuntimeError('pilot_full')
        config=encode(dict(username=username,use_profile_reviews=use_reviews,excluded={},included=[]))
        db.execute('''INSERT INTO privetek_monitors(user_id,state,config) VALUES (%s,'active',%s)
            ON CONFLICT(user_id) DO UPDATE SET state='active',config=EXCLUDED.config,baseline=NULL,
            version=privetek_monitors.version+1,next_run_at=CURRENT_TIMESTAMP,lease=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP''',(user_id,config))
        db.execute("UPDATE privetek_monitor_runs SET mail_state='cancelled' WHERE user_id=%s AND mail_state='pending'",(user_id,))


def history(user_id,offset=0,limit=15):
    with job_store.connect() as db:
        rows=db.execute('''SELECT id,state,started_at,finished_at,changes,new_count,mail_state FROM privetek_monitor_runs
            WHERE user_id=%s AND started_at>CURRENT_TIMESTAMP-INTERVAL '90 days' ORDER BY started_at DESC,id DESC LIMIT %s OFFSET %s''',(user_id,limit,offset)).fetchall()
    return [dict(row,changes=decode(row['changes'])) for row in rows]


def exclude(user_id,item_id,action):
    if action not in ('exclude','restore'):raise ValueError('Unknown exclusion action')
    with job_store.connect() as db:
        row=db.execute('SELECT config FROM privetek_monitors WHERE user_id=%s FOR UPDATE',(user_id,)).fetchone()
        if not row:return False
        config=decode(row['config']);found=None
        for run in db.execute("SELECT changes FROM privetek_monitor_runs WHERE user_id=%s AND changes IS NOT NULL AND started_at>CURRENT_TIMESTAMP-INTERVAL '90 days' ORDER BY started_at DESC LIMIT 15",(user_id,)):
            details=decode(run['changes'])
            found=next((item for item in details.get('items',[])+details.get('baseline_items',[]) if item['id']==item_id),None)
            if found:break
        if action=='restore' and item_id in config['excluded']:found=config['excluded'][item_id]
        if not found:return False
        if action=='exclude':
            if len(config['excluded'])>=200 and item_id not in config['excluded']:raise ValueError('Exclusion limit')
            config['excluded'][item_id]={k:found.get(k) for k in ('source','kind','profile_url','breach_name')}
            config['included']=[i for i in config.get('included',[]) if i!=item_id]
        else:
            config['excluded'].pop(item_id,None)
            config['included']=list(set(config.get('included',[])+[item_id]))[-200:]
        db.execute('UPDATE privetek_monitors SET config=%s,updated_at=CURRENT_TIMESTAMP WHERE user_id=%s',(encode(config),user_id))
    return True


def cleanup():
    with job_store.connect() as db:
        db.execute("UPDATE privetek_monitors SET state='paused',version=version+1,lease=NULL,lease_until=NULL WHERE state='active' AND (SELECT ends_at FROM privetek_monitor_pilot WHERE id=1)<=CURRENT_TIMESTAMP")
        db.execute("DELETE FROM privetek_monitors WHERE state='paused' AND GREATEST(updated_at,COALESCE(last_checked_at,updated_at))<=CURRENT_TIMESTAMP-INTERVAL '90 days'")
        db.execute("DELETE FROM privetek_monitor_runs WHERE started_at<=CURRENT_TIMESTAMP-INTERVAL '90 days'")
        db.execute("UPDATE privetek_monitor_runs SET mail_state='cancelled' WHERE mail_state='pending' AND NOT EXISTS (SELECT 1 FROM privetek_monitors m WHERE m.user_id=privetek_monitor_runs.user_id AND m.state='active' AND m.version=privetek_monitor_runs.version)")
        db.execute("UPDATE privetek_monitor_runs SET mail_state='delivery_unknown' WHERE mail_state='sending' AND mail_started_at<CURRENT_TIMESTAMP-INTERVAL '15 minutes'")


def claim_scan():
    with job_store.connect() as db:
        control=pilot(db)
        if control['ends_at']<=now():return None
        if control['day']!=now().date():
            db.execute('UPDATE privetek_monitor_pilot SET day=CURRENT_DATE,scans=0,mails=0 WHERE id=1');control['scans']=0
        if control['scans']>=10:return None
        if db.execute('SELECT user_id FROM privetek_monitors WHERE lease_until>CURRENT_TIMESTAMP LIMIT 1').fetchone():return None
        row=db.execute("""SELECT m.*,u.email,u.email_key FROM privetek_monitors m JOIN privetek_users u ON u.id=m.user_id
            WHERE m.state='active' AND m.next_run_at<=CURRENT_TIMESTAMP AND (m.lease_until IS NULL OR m.lease_until<=CURRENT_TIMESTAMP)
            ORDER BY m.next_run_at,m.user_id FOR UPDATE OF m SKIP LOCKED LIMIT 1""").fetchone()
        if not row:return None
        run_id=uuid4().hex
        db.execute("UPDATE privetek_monitor_runs SET state='interrupted',finished_at=CURRENT_TIMESTAMP WHERE user_id=%s AND state='running'",(row['user_id'],))
        db.execute("INSERT INTO privetek_monitor_runs(id,user_id,version,state) VALUES (%s,%s,%s,'running')",(run_id,row['user_id'],row['version']))
        db.execute("UPDATE privetek_monitors SET lease=%s,lease_until=CURRENT_TIMESTAMP+INTERVAL '15 minutes' WHERE user_id=%s",(run_id,row['user_id']))
        db.execute('UPDATE privetek_monitor_pilot SET scans=scans+1 WHERE id=1')
        return dict(row,run_id=run_id,config=decode(row['config']),baseline=decode(row['baseline']))


def profile_reviews(owner_key,username,connection=None):
    """Only exact public profiles, not provider-wide breach claims, may suppress alerts."""
    if not username:return set()
    if connection is None:
        with job_store.connect() as db:return profile_reviews(owner_key,username,db)
    rows=connection.execute('''SELECT r.identity_ciphertext FROM privetek_account_reports r
            JOIN privetek_job_owners o ON o.job_id=r.job_id JOIN privetek_jobs j ON j.id=r.job_id
            WHERE o.email_key=%s AND r.expires_at>CURRENT_TIMESTAMP AND r.identity_ciphertext IS NOT NULL
            ORDER BY j.created_at DESC LIMIT 20''',(owner_key,)).fetchall()
    reviewed={}
    for row in rows:
        snapshot=decode(row['identity_ciphertext'])
        if not any(i['id']=='identifier-username' and i['title']==username for i in snapshot['identifiers']):continue
        for item in snapshot['findings']:
            if item['kind']=='username' and item['decision'] in ('mine','not_mine') and item['id'] not in reviewed:
                reviewed[item['id']]=item['decision']
    return {i for i,decision in reviewed.items() if decision=='not_mine'}


def complete_scan(claim,result=None):
    with job_store.connect() as db:
        row=db.execute('SELECT * FROM privetek_monitors WHERE user_id=%s FOR UPDATE',(claim['user_id'],)).fetchone()
        if not row or row['state']!='active' or row['version']!=claim['version'] or row['lease']!=claim['run_id']:
            db.execute("UPDATE privetek_monitor_runs SET state='cancelled',finished_at=CURRENT_TIMESTAMP WHERE id=%s AND state='running'",(claim['run_id'],));return False
        success=result is not None and result['details']['checked_sources']>0
        status=('partial' if result['details']['unavailable'] else 'completed') if success else 'unavailable'
        if success:
            # Recheck explicit exclusions after the scan; settings could have changed in flight.
            config=decode(row['config']);blocked=set(config['excluded'])
            for item in result['details']['items']:
                if item['id'] in config.get('included',[]):item['excluded']=False
                elif item['id'] in blocked:item['excluded']=True
            count=sum(not i['excluded'] for i in result['details']['items'])
            details=encode(result['details']);baseline=encode(result['baseline'])
            if len(baseline)>512*1024 or len(details)>256*1024:raise ValueError('Monitor snapshot too large')
            db.execute('UPDATE privetek_monitor_runs SET state=%s,changes=%s,new_count=%s,mail_state=%s,finished_at=CURRENT_TIMESTAMP WHERE id=%s',
                (status,details,count,'pending' if count else 'none',claim['run_id']))
            db.execute("UPDATE privetek_monitors SET baseline=%s,last_checked_at=CURRENT_TIMESTAMP,last_status=%s,next_run_at=CURRENT_TIMESTAMP+INTERVAL '7 days',lease=NULL,lease_until=NULL WHERE user_id=%s",(baseline,status,claim['user_id']))
        else:
            db.execute("UPDATE privetek_monitor_runs SET state='unavailable',finished_at=CURRENT_TIMESTAMP WHERE id=%s",(claim['run_id'],))
            db.execute("UPDATE privetek_monitors SET last_checked_at=CURRENT_TIMESTAMP,last_status='unavailable',next_run_at=CURRENT_TIMESTAMP+INTERVAL '1 day',lease=NULL,lease_until=NULL WHERE user_id=%s",(claim['user_id'],))
    return True


def claim_mail():
    with job_store.connect() as db:
        control=pilot(db)
        if control['day']!=now().date():
            db.execute('UPDATE privetek_monitor_pilot SET day=CURRENT_DATE,scans=0,mails=0 WHERE id=1');control['mails']=0
        if control['mails']>=10 or control['ends_at']<=now():return None
        candidate=db.execute("SELECT id,user_id FROM privetek_monitor_runs WHERE mail_state='pending' ORDER BY started_at LIMIT 1").fetchone()
        if not candidate:return None
        monitor=db.execute("SELECT m.state,m.version,m.config,u.email,u.email_key FROM privetek_monitors m JOIN privetek_users u ON u.id=m.user_id WHERE m.user_id=%s FOR UPDATE OF m",(candidate['user_id'],)).fetchone()
        row=db.execute("SELECT id,user_id,version,changes FROM privetek_monitor_runs WHERE id=%s AND mail_state='pending' FOR UPDATE",(candidate['id'],)).fetchone()
        if not row:return None
        if not monitor or monitor['state']!='active' or monitor['version']!=row['version']:
            db.execute("UPDATE privetek_monitor_runs SET mail_state='cancelled' WHERE id=%s",(row['id'],));return {'skip':True}
        row=dict(row,config=monitor['config'],email=monitor['email'])
        details=decode(row['changes']);config=decode(row['config'])
        reviewed=profile_reviews(monitor['email_key'],config['username'],db) if config.get('use_profile_reviews',True) else set()
        relevant=[item for item in details['items'] if not item['excluded'] and item['id'] not in config['excluded'] and (item['link_id'] not in reviewed or item['id'] in config.get('included',[]))]
        db.execute('UPDATE privetek_monitor_runs SET mail_state=%s,mail_started_at=CURRENT_TIMESTAMP WHERE id=%s',('sending' if relevant else 'cancelled',row['id']))
        if not relevant:return {'skip':True}
        db.execute('UPDATE privetek_monitor_pilot SET mails=mails+1 WHERE id=1')
        return dict(row,changes=None,config=None)


def finish_mail(run_id,accepted):
    with job_store.connect() as db:db.execute("UPDATE privetek_monitor_runs SET mail_state=%s WHERE id=%s AND mail_state='sending'",('provider_accepted' if accepted else 'delivery_unknown',run_id))
