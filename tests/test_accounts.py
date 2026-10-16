"""HTTP/security tests plus optional PostgreSQL/PGlite integration on a disposable DB."""
import os
import json
import secrets
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet
import server
import account_crypto as crypto
import account_store as store
import account_routes as routes
import job_store

ORIGIN = 'https://privetek.test'
PASSWORD = 'a long unique test password 2026'

@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv('ACCOUNTS_ENABLED','true')
    monkeypatch.setenv('ACCOUNT_SECRET','test-only-account-secret-'+'x'*32)
    monkeypatch.setenv('ACCOUNT_REPORT_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('ACCOUNT_ORIGIN',ORIGIN)
    monkeypatch.setenv('DATABASE_URL','unused-test-setting')


def client():
    return TestClient(server.app,base_url=ORIGIN,headers={'Origin':ORIGIN})


def test_disabled_feature_is_closed(monkeypatch):
    monkeypatch.setenv('ACCOUNTS_ENABLED','false')
    c=client()
    assert c.get('/account').status_code==404
    assert c.get('/api/account/me').status_code==404
    assert c.post('/api/account/auth/login',json={}).status_code==404


def test_settings_require_https_keys_and_database(settings,monkeypatch):
    crypto.validate_settings()
    for name,bad in [('ACCOUNT_ORIGIN','http://privetek.test'),('ACCOUNT_SECRET','short'),('ACCOUNT_REPORT_KEY','bad'),('DATABASE_URL','')]:
        with monkeypatch.context() as m:
            m.setenv(name,bad)
            with pytest.raises((ValueError,KeyError)):crypto.validate_settings()


def test_password_hashes_salted_and_not_reversible():
    first=crypto.password_hash(PASSWORD); second=crypto.password_hash(PASSWORD)
    assert first!=second and first.startswith('$argon2id$') and PASSWORD not in first
    assert crypto.password_matches(first,PASSWORD)
    assert not crypto.password_matches(first,'different password')
    assert not crypto.password_matches(None,PASSWORD)
    for value in ['short','x'*129,None]:
        with pytest.raises(ValueError): crypto.password_hash(value)


@pytest.mark.parametrize('path',['auth/register','auth/login','auth/forgot-password','auth/verify','jobs'])
def test_mutations_reject_foreign_origin_before_work(settings,path,monkeypatch):
    storecall=MagicMock();monkeypatch.setattr(store,'quota',storecall)
    c=client()
    assert c.post('/api/account/'+path,json={},headers={'Origin':'https://evil.test'}).status_code==403
    storecall.assert_not_called()


def test_bounded_body_and_sensitive_errors(settings,monkeypatch):
    c=client()
    assert c.post('/api/account/auth/login',content='x'*5000,headers={'Content-Type':'application/json'}).status_code==413
    assert c.post('/api/account/auth/login',json=[]).status_code==400
    assert c.post('/api/account/auth/login',data={'email':'x'}).status_code==415
    monkeypatch.setattr(store,'cleanup',lambda:None)
    monkeypatch.setattr(store,'quota',lambda items:True)
    monkeypatch.setattr(store,'login',MagicMock(side_effect=RuntimeError('SECRET DB PASSWORD')))
    r=c.post('/api/account/auth/login',json={'email':'a@example.com','password':PASSWORD})
    assert r.status_code==503 and 'SECRET' not in r.text
    assert r.headers['Cache-Control']=='no-store'


def test_anonymous_cannot_list_or_download_or_submit(settings):
    c=client()
    assert c.get('/api/account/me').status_code==401
    assert c.get('/api/account/jobs').status_code==401
    assert c.get('/api/account/jobs/'+'a'*32+'/report').status_code==401
    assert c.post('/api/account/jobs',json={'consent':True}).status_code==401


def test_get_database_errors_are_sanitized(settings,monkeypatch):
    c=client();c.cookies.set(routes.COOKIE,secrets.token_urlsafe(32))
    monkeypatch.setattr(store,'session',MagicMock(side_effect=RuntimeError('private connection credentials')))
    r=c.get('/api/account/me')
    assert r.status_code==503 and 'credentials' not in r.text


def test_csrf_checked_after_session(settings,monkeypatch):
    token=secrets.token_urlsafe(32); c=client();c.cookies.set(routes.COOKIE,token)
    monkeypatch.setattr(store,'session',lambda token_hash:dict(id='user',email='a@example.com',email_key='owner'))
    assert c.delete('/api/account/jobs/'+'a'*32+'/report').status_code==403
    assert c.post('/api/account/jobs',json={'consent':True}).status_code==403


def test_owner_sql_filters_both_download_and_delete(settings,monkeypatch):
    ctx=MagicMock();db=ctx.__enter__.return_value;db.execute.return_value.fetchone.return_value=None
    monkeypatch.setattr(job_store,'connect',lambda:ctx)
    assert store.report('owner-A','job-B') is None
    assert db.execute.call_args.args[1]==('job-B','owner-A')
    assert 'o.email_key = %s' in db.execute.call_args.args[0]
    store.delete_report('owner-A','job-B')
    assert 'o.email_key = %s' in db.execute.call_args.args[0]
    assert db.execute.call_args.args[1]==('job-B','owner-A')


@pytest.fixture
def db(settings,monkeypatch):
    dsn=os.getenv('ACCOUNTS_TEST_DATABASE_URL')
    if not dsn:pytest.skip('Set ACCOUNTS_TEST_DATABASE_URL to a disposable PostgreSQL/PGlite database')
    if os.getenv('PRIVETEK_TEST_ALLOW_RESET')!='1':pytest.fail('Disposable DB reset requires PRIVETEK_TEST_ALLOW_RESET=1')
    monkeypatch.setenv('DATABASE_URL',dsn)
    job_store.initialize()
    with job_store.connect() as connection:
        connection.execute('TRUNCATE privetek_users,privetek_account_codes,privetek_sessions,privetek_account_limits,privetek_jobs,privetek_job_owners,privetek_job_events,privetek_account_reports CASCADE')
    sent=[]
    monkeypatch.setattr(server.email_sender,'validate_settings',lambda:None)
    monkeypatch.setattr(server.email_sender,'send_account_code',lambda email,code,purpose:sent.append((email,code,purpose)))
    return sent


def register(c,sent,email='owner@example.com'):
    r=c.post('/api/account/auth/register',json={'email':email,'password':PASSWORD})
    assert r.status_code==200,r.text
    challenge=r.json()['challenge_id'];code=sent[-1][1]
    r=c.post('/api/account/auth/verify',json={'challenge_id':challenge,'code':code})
    assert r.status_code==200,r.text
    return challenge,code


def login(c,email='owner@example.com',password=PASSWORD):
    r=c.post('/api/account/auth/login',json={'email':email,'password':password})
    assert r.status_code==200,r.text
    return c.get('/api/account/me').json()['csrf_token']


def test_db_registration_verification_cookie_logout(db):
    c=client()
    # Pending registration alone must not create a user able to log in.
    r=c.post('/api/account/auth/register',json={'email':'owner@example.com','password':PASSWORD})
    challenge=r.json()['challenge_id']
    assert c.post('/api/account/auth/login',json={'email':'owner@example.com','password':PASSWORD}).status_code==401
    code=db[-1][1]
    assert c.post('/api/account/auth/verify',json={'challenge_id':challenge,'code':code}).status_code==200
    assert c.post('/api/account/auth/verify',json={'challenge_id':challenge,'code':code}).status_code==400
    r=c.post('/api/account/auth/login',json={'email':'owner@example.com','password':PASSWORD})
    assert r.status_code==200
    cookie=r.headers['set-cookie'];assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=strict' in cookie
    me=c.get('/api/account/me');assert me.json()['email']=='owner@example.com'
    assert c.post('/api/account/auth/logout',json={},headers={'X-CSRF-Token':me.json()['csrf_token']}).status_code==200
    assert c.get('/api/account/me').status_code==401


def test_db_wrong_expired_and_rate_limited_codes(db):
    c=client();r=c.post('/api/account/auth/register',json={'email':'owner@example.com','password':PASSWORD});challenge=r.json()['challenge_id'];code=db[-1][1]
    bad='00000000' if code!='00000000' else '11111111'
    for _ in range(5):assert c.post('/api/account/auth/verify',json={'challenge_id':challenge,'code':bad}).status_code==400
    assert c.post('/api/account/auth/verify',json={'challenge_id':challenge,'code':code}).status_code==400
    r=c.post('/api/account/auth/register',json={'email':'owner@example.com','password':PASSWORD});challenge=r.json()['challenge_id'];code=db[-1][1]
    with job_store.connect() as connection:
        connection.execute("UPDATE privetek_account_codes SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE id=%s",(challenge,))
    assert c.post('/api/account/auth/verify',json={'challenge_id':challenge,'code':code}).status_code==400


def test_db_reports_are_encrypted_tenant_isolated_and_expire(db,tmp_path):
    a=client();register(a,db);csrf=login(a)
    b=client();register(b,db,'other@example.com');login(b,'other@example.com')
    job='a'*32;job_store.record(job,'accepted','owner@example.com')
    pdf=tmp_path/'report.pdf';pdf.write_bytes(b'%PDF-test-private-content')
    store.save_report(job,pdf)
    items=a.get('/api/account/jobs').json()['items'];assert len(items)==1 and items[0]['report_available']
    assert b.get('/api/account/jobs').json()['items']==[]
    path='/api/account/jobs/'+job+'/report'
    assert a.get(path).content==pdf.read_bytes()
    assert b.get(path).status_code==404
    with job_store.connect() as connection:
        encrypted=connection.execute('SELECT ciphertext FROM privetek_account_reports WHERE job_id=%s',(job,)).fetchone()['ciphertext']
        assert pdf.read_bytes() not in bytes(encrypted)
    # Another owner cannot delete a report by guessing its id.
    bcsrf=b.get('/api/account/me').json()['csrf_token'];assert b.delete(path,headers={'X-CSRF-Token':bcsrf}).status_code==200
    assert a.get(path).status_code==200
    with job_store.connect() as connection:
        connection.execute("UPDATE privetek_account_reports SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE job_id=%s",(job,))
    assert a.get(path).status_code==404
    assert not a.get('/api/account/jobs').json()['items'][0]['report_available']
    store.cleanup()
    with job_store.connect() as connection:
        assert connection.execute('SELECT job_id FROM privetek_account_reports WHERE job_id=%s',(job,)).fetchone() is None


def test_db_password_reset_revokes_existing_sessions(db):
    c=client();register(c,db);login(c)
    r=c.post('/api/account/auth/forgot-password',json={'email':'owner@example.com'});challenge=r.json()['challenge_id'];code=db[-1][1]
    new='another unique long password 2026'
    r=c.post('/api/account/auth/reset-password',json={'challenge_id':challenge,'code':code,'password':new})
    assert r.status_code==200,r.text
    assert c.get('/api/account/me').status_code==401
    assert c.post('/api/account/auth/login',json={'email':'owner@example.com','password':PASSWORD}).status_code==401
    login(c,password=new)
    assert c.post('/api/account/auth/reset-password',json={'challenge_id':challenge,'code':code,'password':PASSWORD}).status_code==400


def test_db_registration_never_overwrites_verified_password(db):
    c=client();register(c,db)
    r=c.post('/api/account/auth/register',json={'email':'owner@example.com','password':'attacker chosen long password'})
    assert r.status_code==200 and len(db)==1
    login(c)


def test_db_login_quota_is_durable_and_generic(db):
    c=client()
    for _ in range(10):assert c.post('/api/account/auth/login',json={'email':'absent@example.com','password':PASSWORD}).status_code==401
    assert c.post('/api/account/auth/login',json={'email':'absent@example.com','password':PASSWORD}).status_code==429


def test_db_account_submission_ignores_forged_email_and_owner(db,monkeypatch):
    c=client();register(c,db);csrf=login(c)
    monkeypatch.setattr(server.threading,'Thread',MagicMock())
    monkeypatch.setattr(server,'slots',MagicMock())
    r=c.post('/api/account/jobs',json={'Email':'victim@example.com','owner':'evil','username':'mytest','consent':True},headers={'X-CSRF-Token':csrf})
    assert r.status_code==202,r.text
    job=r.json()['job_id'];assert c.get('/api/account/jobs').json()['items'][0]['id']==job
    thread=server.threading.Thread.call_args
    assert str(thread.kwargs['args'][0].Email)=='owner@example.com'
    assert thread.kwargs['args'][0].Username=='mytest'


def test_db_owner_report_delete_keeps_job_history(db,tmp_path):
    c=client();register(c,db);csrf=login(c);job='b'*32
    job_store.record(job,'accepted','owner@example.com');pdf=tmp_path/'report.pdf';pdf.write_bytes(b'%PDF-test');store.save_report(job,pdf)
    path='/api/account/jobs/'+job+'/report'
    assert c.delete(path,headers={'X-CSRF-Token':csrf}).status_code==200
    assert c.get(path).status_code==404
    assert len(c.get('/api/account/jobs').json()['items'])==1


def test_db_session_hash_and_expiry(db):
    c=client();register(c,db);login(c)
    raw=c.cookies.get(routes.COOKIE)
    with job_store.connect() as connection:
        row=connection.execute('SELECT token_hash FROM privetek_sessions').fetchone()
        assert row['token_hash']!=raw and row['token_hash']==crypto.digest('session',raw)
        connection.execute("UPDATE privetek_sessions SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'")
    assert c.get('/api/account/me').status_code==401


def test_db_history_pagination_and_owner_filter(db):
    c=client();register(c,db);login(c)
    for i in range(21):job_store.record(f'{i:032x}','accepted','owner@example.com')
    job_store.record('f'*32,'accepted','other@example.com')
    first=c.get('/api/account/jobs').json();second=c.get('/api/account/jobs?offset=20').json()
    assert len(first['items'])==20 and first['has_more']
    assert len(second['items'])==1 and not second['has_more']
    assert not ({x['id'] for x in first['items']} & {x['id'] for x in second['items']})
    assert 'f'*32 not in {x['id'] for x in first['items']+second['items']}


def test_archive_failure_does_not_break_existing_mail_delivery(settings,monkeypatch,tmp_path):
    import osint
    pdf=tmp_path/'report.pdf';pdf.write_bytes(b'%PDF-test')
    monkeypatch.setattr(osint,'search',lambda **kwargs:{})
    monkeypatch.setattr(server.pdf_gen,'create_report',lambda results:str(pdf))
    monkeypatch.setattr(store,'save_report',MagicMock(side_effect=RuntimeError('private storage failure')))
    monkeypatch.setattr(job_store,'record',MagicMock())
    mail=MagicMock();monkeypatch.setattr(server.email_sender,'send_report',mail)
    monkeypatch.setattr(server,'slots',MagicMock())
    server.background_task(server.Submission(Email='owner@example.com'),'c'*32)
    mail.assert_called_once()
    assert not pdf.exists()
    assert job_store.record.call_args.args==('c'*32,'provider_accepted')


@pytest.mark.skipif(os.getenv('ACCOUNTS_NATIVE_POSTGRES_TESTS') != '1', reason='Native PostgreSQL concurrency check; PGlite has a different connection model')
def test_db_concurrent_report_workers_and_history(db,tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    email='owner@example.com'
    c=client();register(c,db);login(c)
    jobs=[f'{i+100:032x}' for i in range(4)]
    paths=[]
    for job in jobs:
        job_store.record(job,'accepted',email)
        path=tmp_path/(job+'.pdf');path.write_bytes(b'%PDF-concurrent-test');paths.append(path)
    def worker(pair):
        job,path=pair
        for status in ['searching','generating_report']:
            job_store.record(job,status)
        store.save_report(job,path)
        job_store.record(job,'sending')
        job_store.record(job,'provider_accepted')
    def reader(_):
        for attempt in range(10):
            history=store.list_jobs(crypto.email_key(email))['items']
            assert len(history)==4
            assert all(item['id'] in jobs for item in history)
    with ThreadPoolExecutor(max_workers=8) as pool:
        tasks=[pool.submit(worker,pair) for pair in zip(jobs,paths)]
        tasks += [pool.submit(reader,i) for i in range(4)]
        for task in tasks:task.result(timeout=30)
    for job in jobs:
        assert job_store.get(job)['status']=='provider_accepted'
        assert store.report(crypto.email_key(email),job)==b'%PDF-concurrent-test'


@pytest.mark.skipif(os.getenv('ACCOUNTS_NATIVE_POSTGRES_TESTS') != '1', reason='Native PostgreSQL row-lock concurrency check')
def test_db_concurrent_code_redemption_only_one_succeeds(db):
    from concurrent.futures import ThreadPoolExecutor
    c=client();r=c.post('/api/account/auth/register',json={'email':'owner@example.com','password':PASSWORD})
    challenge=r.json()['challenge_id'];code=db[-1][1]
    supplied=crypto.digest('code',challenge+':'+code)
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes=list(pool.map(lambda _:store.redeem(challenge,supplied,'register'),range(4)))
    assert outcomes.count(True)==1
    assert outcomes.count(False)==3
    login(c)
