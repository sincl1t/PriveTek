import os
from datetime import datetime,timedelta,timezone
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock
import pytest
import httpx
import monitoring as m
import monitor_store as store
import monitor_worker
import account_store
import job_store
import server
import email_sender
from test_accounts import settings,db,client,register,login

NOW=datetime(2026,10,29,tzinfo=timezone.utc)


def sample(handle='alpha',status='found',source='GitHub'):
    return {'checks':[dict(source=source,kind='username',status=status,profile_url='https://github.com/'+handle if source=='GitHub' else 'https://scratch.mit.edu/users/'+handle+'/')], 'email_breach':[]}


def test_initial_baseline_quiet_then_new_then_no_repeat():
    baseline=m.compare(None,m.observe(sample()),NOW)
    assert baseline['new_count']==0 and len(baseline['details']['baseline_items'])==1
    raw=sample();raw['checks'].append(sample('beta')['checks'][0])
    new=m.compare(baseline['baseline'],m.observe(raw),NOW+timedelta(days=7))
    assert new['new_count']==1 and new['details']['items'][0]['profile_url'].endswith('/beta')
    assert m.compare(new['baseline'],m.observe(raw),NOW+timedelta(days=14))['new_count']==0


def test_failure_and_newly_available_source_not_fake_new():
    baseline=m.compare(None,m.observe(sample()),NOW)['baseline']
    failed=m.compare(baseline,m.observe(sample(status='unavailable')),NOW+timedelta(days=7))
    assert failed['new_count']==0 and failed['baseline']['seen']==baseline['seen']
    assert m.compare(failed['baseline'],m.observe(sample()),NOW+timedelta(days=14))['new_count']==0
    new_source=m.compare(baseline,m.observe(sample('mres',source='Scratch')),NOW+timedelta(days=7))
    assert new_source['new_count']==0 and new_source['details']['baseline_items']


def test_exclusion_does_not_repeat_and_retention_rebaselines():
    baseline=m.compare(None,m.observe(sample(status='not_found')),NOW)['baseline']
    obs=m.observe(sample());item_id=next(iter(obs['items']))
    excluded=m.compare(baseline,obs,NOW+timedelta(days=7),{item_id})
    assert excluded['new_count']==0 and excluded['details']['items'][0]['excluded']
    assert m.compare(excluded['baseline'],obs,NOW+timedelta(days=14))['new_count']==0
    reset=m.compare(excluded['baseline'],obs,NOW+timedelta(days=100))
    assert reset['new_count']==0 and reset['details']['baseline_items']


def test_breach_date_correction_not_new_and_unknown_not_absence():
    raw={'checks':[dict(source='LeakCheck',kind='breach',status='found')],'email_breach':[dict(source='LeakCheck',name='Synthetic',date='2020')]}
    base=m.compare(None,m.observe(raw),NOW)['baseline']
    raw['email_breach'][0]['date']='2021'
    assert m.compare(base,m.observe(raw),NOW+timedelta(days=7))['new_count']==0
    assert not m.observe(sample(status='unknown'))['initialized']


def test_no_phone_or_untrusted_profile_and_item_limit():
    raw=sample();raw['checks'][0]['profile_url']='https://foreign.invalid/name'
    raw['checks'].append(dict(source='Amazon',kind='phone',status='possible'))
    assert m.observe(raw)['items']=={}
    raw={'checks':[sample(str(i))['checks'][0] for i in range(201)]}
    with pytest.raises(ValueError):m.observe(raw)


def test_monitor_routes_auth_origin_and_disabled_runner(settings,monkeypatch):
    c=client()
    assert c.get('/api/account/monitor').status_code==401
    assert c.post('/api/account/monitor',json={}).status_code==401
    assert c.post('/api/account/monitor',json={},headers={'Origin':'https://foreign.invalid'}).status_code==403
    assert c.post('/api/internal/monitor/tick',json={}).status_code==403
    monkeypatch.setattr(job_store,'connect',MagicMock(side_effect=AssertionError('No DB')))
    assert c.post('/api/internal/monitor/tick',headers={'Authorization':'Bearer wrong'}).status_code==403


@pytest.fixture
def monitor_db(db,monkeypatch):
    monkeypatch.setenv('MONITOR_ENABLED','true');monkeypatch.setenv('MONITOR_RUNNER_TOKEN','test-monitor-runner-'+'x'*40)
    with job_store.connect() as conn:conn.execute("UPDATE privetek_monitor_pilot SET ends_at=CURRENT_TIMESTAMP+INTERVAL '28 days',day=CURRENT_DATE,scans=0,mails=0")
    return db


def enrolled(sent):
    c=client();register(c,sent);csrf=login(c)
    response=c.post('/api/account/monitor',json={'action':'enable','consent':True,'username':'alpha'},headers={'X-CSRF-Token':csrf})
    assert response.status_code==200,response.text
    with job_store.connect() as conn:user=conn.execute('SELECT id FROM privetek_users WHERE email=%s',('owner@example.com',)).fetchone()['id']
    return c,csrf,user


def due(user):
    with job_store.connect() as conn:conn.execute("UPDATE privetek_monitors SET next_run_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE user_id=%s",(user,))


def test_db_consent_ciphertext_scope_and_pause(monitor_db):
    c=client();register(c,monitor_db);csrf=login(c);path='/api/account/monitor'
    assert c.post(path,json={'action':'enable','consent':True}).status_code==403
    assert c.post(path,json={'action':'enable'},headers={'X-CSRF-Token':csrf}).status_code==422
    assert c.post(path,json={'action':'enable','consent':True,'username':'@alpha'},headers={'X-CSRF-Token':csrf}).status_code==200
    data=c.get(path).json();assert data['settings']['username']=='alpha' and data['history']==[]
    with job_store.connect() as conn:assert b'alpha' not in bytes(conn.execute('SELECT config FROM privetek_monitors').fetchone()['config'])
    other=client();register(other,monitor_db,'other@example.com');login(other,'other@example.com')
    assert other.get(path).json()['settings']['state']=='off' and other.get(path).json()['history']==[]
    assert c.post(path,json={'action':'pause'},headers={'X-CSRF-Token':csrf}).json()['settings']['state']=='paused'
    assert store.claim_scan() is None


def test_db_baseline_new_mail_and_never_retry_unknown(monitor_db,monkeypatch):
    c,csrf,user=enrolled(monitor_db);current=sample()
    def search(**kwargs):
        assert kwargs=={'email':'owner@example.com','username':'alpha','phone':None}
        return current
    monkeypatch.setattr('osint.search',search)
    mail=MagicMock();monkeypatch.setattr(email_sender,'send_monitor_notice',mail)
    assert monitor_worker.tick()['operation']=='scan'
    assert monitor_worker.tick()['operation']=='idle';mail.assert_not_called()
    due(user);current['checks'].append(sample('beta')['checks'][0])
    assert monitor_worker.tick()['operation']=='scan'
    result=c.get('/api/account/monitor').json();assert result['history'][0]['new_count']==1
    assert result['history'][0]['mail_state']=='pending'
    mail.side_effect=RuntimeError('uncertain provider outcome')
    assert monitor_worker.tick()['status']=='delivery_unknown'
    assert monitor_worker.tick()['operation']=='idle';assert mail.call_count==1
    assert c.get('/api/account/monitor').json()['history'][0]['mail_state']=='delivery_unknown'


def test_db_pause_during_scan_cancels_completion_and_delete_cascades(monitor_db,monkeypatch):
    c,csrf,user=enrolled(monitor_db)
    claim=store.claim_scan();assert claim
    store.change(user,'pause')
    result=m.compare(None,m.observe(sample()),account_store.now())
    assert store.complete_scan(claim,result) is False
    assert not store.claim_mail()
    assert c.post('/api/account/monitor',json={'action':'delete'},headers={'X-CSRF-Token':csrf}).status_code==200
    with job_store.connect() as conn:
        assert conn.execute('SELECT count(*) AS n FROM privetek_monitor_runs').fetchone()['n']==0
        assert conn.execute('SELECT count(*) AS n FROM privetek_monitors').fetchone()['n']==0


def test_db_exclusions_block_pending_notice_and_restore(monitor_db,monkeypatch):
    c,csrf,user=enrolled(monitor_db);current=sample(status='not_found')
    monkeypatch.setattr('osint.search',lambda **kwargs:current)
    monitor_worker.tick();due(user);current=sample();monitor_worker.tick()
    run=c.get('/api/account/monitor').json()['history'][0];item_id=run['changes']['items'][0]['id']
    route='/api/account/monitor/exclusions';headers={'X-CSRF-Token':csrf}
    assert c.post(route,json={'item_id':'f'*24,'action':'exclude'},headers=headers).status_code==404
    assert c.post(route,json={'item_id':item_id,'action':'exclude'},headers=headers).status_code==200
    assert store.claim_mail()=={'skip':True}
    assert c.post(route,json={'item_id':item_id,'action':'restore'},headers=headers).status_code==200
    assert c.get('/api/account/monitor').json()['settings']['exclusions']==[]


def test_db_expiry_retry_and_daily_limits(monitor_db,monkeypatch):
    _,_,user=enrolled(monitor_db)
    monkeypatch.setattr('osint.search',lambda **kwargs:sample(status='unavailable'))
    assert monitor_worker.tick()['status']=='recorded'
    assert store.history(user)[0]['state']=='unavailable'
    assert store.claim_scan() is None
    due(user)
    with job_store.connect() as conn:conn.execute('UPDATE privetek_monitor_pilot SET scans=10')
    assert store.claim_scan() is None
    with job_store.connect() as conn:conn.execute("UPDATE privetek_monitor_pilot SET scans=0,ends_at=CURRENT_TIMESTAMP-INTERVAL '1 second'")
    with pytest.raises(RuntimeError):store.change(user,'resume')
    store.cleanup();assert store.settings(user)['state']=='paused'


def test_db_pilot_capacity_and_history_retention(monitor_db):
    _,_,user=enrolled(monitor_db)
    with job_store.connect() as conn:
        for i in range(9):
            uid='test-'+str(i)
            conn.execute("INSERT INTO privetek_users(id,email,email_key,password_hash) VALUES (%s,%s,%s,'test')",(uid,uid+'@example.com',uid),prepare=False)
            conn.execute("INSERT INTO privetek_monitors(user_id,state,config) VALUES (%s,'paused',%s)",(uid,store.encode({'username':'','excluded':{}})),prepare=False)
        conn.execute("INSERT INTO privetek_users(id,email,email_key,password_hash) VALUES ('extra','extra@example.com','extra','test')")
    with pytest.raises(RuntimeError):store.change('extra','enable','',True)
    claim=store.claim_scan();store.complete_scan(claim,m.compare(None,m.observe(sample()),account_store.now()))
    with job_store.connect() as conn:conn.execute("UPDATE privetek_monitor_runs SET started_at=CURRENT_TIMESTAMP-INTERVAL '91 days'")
    store.cleanup();assert store.history(user)==[]


@pytest.mark.skipif(os.getenv('ACCOUNTS_NATIVE_POSTGRES_TESTS')!='1',reason='Native row locks required')
def test_db_concurrent_ticks_only_one_claim(monitor_db):
    enrolled(monitor_db)
    with ThreadPoolExecutor(max_workers=2) as pool:claims=list(pool.map(lambda _:store.claim_scan(),range(2)))
    assert sum(item is not None for item in claims)==1


def test_runner_correct_token_and_busy_does_not_scan(settings,monkeypatch):
    monkeypatch.setenv('MONITOR_ENABLED','true');monkeypatch.setenv('MONITOR_RUNNER_TOKEN','x'*48)
    monkeypatch.setattr(account_store,'quota',lambda items:True)
    monkeypatch.setattr(server.slots,'acquire',lambda **kwargs:False)
    assert client().post('/api/internal/monitor/tick',headers={'Authorization':'Bearer '+'x'*48}).json()=={'operation':'busy'}


def test_brevo_notice_is_generic_and_acceptance_not_delivery(monkeypatch):
    monkeypatch.setenv('MAIL_PROVIDER','brevo');monkeypatch.setenv('BREVO_API_KEY','test-key');monkeypatch.setenv('MAIL_FROM','sender@example.com')
    monkeypatch.setattr(email_sender,'validate_settings',lambda:'brevo')
    seen=[]
    def send(url,**kwargs):seen.append(kwargs);return httpx.Response(201,json={'messageId':'accepted-test'})
    monkeypatch.setattr(email_sender.httpx,'post',send)
    email_sender.send_monitor_notice('owner@example.com')
    text=seen[0]['json']['textContent']
    assert 'впервые обнаружил' in text and 'включили мониторинг' in text
    assert 'attachment' not in seen[0]['json'] and seen[0]['follow_redirects'] is False
    monkeypatch.setattr(email_sender.httpx,'post',lambda *args,**kwargs:httpx.Response(201,json={}))
    with pytest.raises(email_sender.DeliveryError):email_sender.send_monitor_notice('owner@example.com')


def test_status_strengthening_is_history_update_not_new_notice():
    raw={'checks':[dict(source='Spotify',kind='email',status='possible')]}
    baseline=m.compare(None,m.observe(raw),NOW)['baseline']
    raw['checks'][0]['status']='found'
    result=m.compare(baseline,m.observe(raw),NOW+timedelta(days=7))
    assert result['new_count']==0 and len(result['details']['status_updates'])==1


def test_db_profile_review_exclusion_and_no_ai(monitor_db,monkeypatch,tmp_path):
    import identity_resolution
    c,csrf,user=enrolled(monitor_db)
    current=sample(status='not_found');monkeypatch.setattr('osint.search',lambda **kwargs:current)
    monkeypatch.setattr('ai_summary.select',MagicMock(side_effect=AssertionError('No AI')))
    monitor_worker.tick()
    current=sample();snap=identity_resolution.build(current,'owner@example.com',username='alpha')
    snap=identity_resolution.decide(snap,snap['findings'][0]['id'],'not_mine')
    job='e'*32;job_store.record(job,'accepted','owner@example.com');pdf=tmp_path/'fixture.pdf';pdf.write_bytes(b'%PDF-test');account_store.save_report(job,pdf,snap)
    due(user);monitor_worker.tick()
    run=c.get('/api/account/monitor').json()['history'][0]
    assert run['new_count']==0 and run['changes']['items'][0]['excluded'] is True


def test_db_mail_acceptance_once_and_history_pagination(monitor_db,monkeypatch):
    c,csrf,user=enrolled(monitor_db);current=sample(status='not_found')
    monkeypatch.setattr('osint.search',lambda **kwargs:current)
    monitor_worker.tick();current=sample();due(user);monitor_worker.tick()
    sent=MagicMock();monkeypatch.setattr(email_sender,'send_monitor_notice',sent)
    assert monitor_worker.tick()['status']=='provider_accepted'
    assert monitor_worker.tick()['operation']=='idle';sent.assert_called_once_with('owner@example.com')
    assert c.get('/api/account/monitor?offset=1').json()['history'][0]['new_count']==0
    assert c.get('/api/account/monitor?offset=-1').status_code==422


@pytest.mark.skipif(os.getenv('ACCOUNTS_NATIVE_POSTGRES_TESTS')!='1',reason='Native row locks required')
def test_db_pilot_capacity_race_cannot_exceed_ten(monitor_db):
    enrolled(monitor_db)
    with job_store.connect() as conn:
        for i in range(10):
            uid='race-'+str(i)
            conn.execute("INSERT INTO privetek_users(id,email,email_key,password_hash) VALUES (%s,%s,%s,'test')",(uid,uid+'@example.com',uid),prepare=False)
            if i<8:conn.execute("INSERT INTO privetek_monitors(user_id,state,config) VALUES (%s,'paused',%s)",(uid,store.encode({'username':'','excluded':{}})),prepare=False)
    def enable(uid):
        try:store.change(uid,'enable','',True);return True
        except RuntimeError:return False
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(enable,['race-8','race-9']))
    assert results.count(True)==1
    with job_store.connect() as conn:assert conn.execute('SELECT count(*) AS n FROM privetek_monitors').fetchone()['n']==10


def test_conflicting_observations_are_unavailable_not_new():
    raw=sample();raw['checks'].append(sample(status='not_found')['checks'][0])
    observed=m.observe(raw)
    assert not observed['items'] and not observed['initialized']
    assert observed['unavailable']==['GitHub:username']
