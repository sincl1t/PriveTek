"""MFA regression tests: session gating, replay, recovery, CSRF and password-reset bypass."""
import os
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
import pyotp
import account_mfa as mfa
import account_crypto as crypto
import account_store as store
import job_store
from test_accounts import settings, db, client, register, login, PASSWORD


def post(c, action, payload, csrf):
    return c.post('/api/account/security/'+action,json=payload,headers={'X-CSRF-Token':csrf})


def enroll(c, sent):
    register(c,sent);csrf=login(c)
    r=post(c,'setup',{'password':PASSWORD},csrf);assert r.status_code==200,r.text
    secret=r.json()['secret'];code=pyotp.TOTP(secret).now()
    r=post(c,'confirm',{'code':code},csrf);assert r.status_code==200,r.text
    return csrf,secret,r.json()['recovery_codes']


def challenge(c):
    r=c.post('/api/account/auth/login',json={'email':'owner@example.com','password':PASSWORD})
    assert r.status_code==200 and r.json()['mfa_required'] is True
    assert 'set-cookie' not in r.headers
    assert c.get('/api/account/me').status_code==401
    assert c.get('/api/account/jobs').status_code==401
    return r.json()['challenge_id']


def finish(c, token, code):
    return c.post('/api/account/auth/mfa-verify',json={'challenge_id':token,'code':code})


def test_totp_rfc6238_vectors_and_replay(monkeypatch):
    import base64
    from datetime import datetime,timezone
    secret=base64.b32encode(b'12345678901234567890').decode()
    for instant,expected in [(59,'287082'),(1111111109,'081804'),(1234567890,'005924'),(2000000000,'279037')]:
        monkeypatch.setattr(mfa,'now',lambda:datetime.fromtimestamp(instant,timezone.utc))
        step=instant//30
        assert mfa.matching_step(secret,expected)==step
        assert mfa.matching_step(secret,expected,step) is None
    assert mfa.matching_step(secret,'1234567') is None


def test_mfa_endpoints_reject_anonymous_and_foreign_origin(settings):
    c=client()
    assert c.get('/api/account/security').status_code==401
    for name in ['setup','confirm','disable','recovery']:
        assert c.post('/api/account/security/'+name,json={}).status_code==401
        assert c.post('/api/account/security/'+name,json={},headers={'Origin':'https://evil.test'}).status_code==403
    assert c.post('/api/account/auth/mfa-verify',json={},headers={'Origin':'https://evil.test'}).status_code==403


def test_db_mfa_enrollment_gates_login_and_recovers_once(db,monkeypatch):
    c=client();csrf,secret,codes=enroll(c,db)
    assert len(codes)==10 and len(set(codes))==10
    assert c.get('/api/account/security').json()=={'enabled':True,'recovery_codes_remaining':10}
    with job_store.connect() as conn:
        u=conn.execute('SELECT * FROM privetek_users').fetchone()
        assert secret.encode() not in bytes(u['mfa_secret'])
        hashes=[r['code_hash'] for r in conn.execute('SELECT code_hash FROM privetek_mfa_recovery')]
        assert not any(code in h for code in codes for h in hashes)
    other=client();token=challenge(other)
    assert finish(other,token,pyotp.TOTP(secret).now()).status_code==400  # enrollment consumed current TOTP
    assert finish(other,token,codes[0]).status_code==200
    assert other.get('/api/account/me').status_code==200
    assert finish(client(),token,codes[1]).status_code==400  # challenge consumed
    new=client();token2=challenge(new)
    assert finish(new,token2,codes[0]).status_code==400  # recovery consumed
    future=mfa.now()+timedelta(seconds=30)
    monkeypatch.setattr(mfa,'now',lambda:future)
    assert finish(new,token2,pyotp.TOTP(secret).at(future)).status_code==200
    next_client=client();token3=challenge(next_client)
    assert finish(next_client,token3,pyotp.TOTP(secret).at(future)).status_code==400


def test_db_mfa_setup_password_csrf_expiry_and_session_binding(db):
    c=client();register(c,db);csrf=login(c)
    assert c.post('/api/account/security/setup',json={'password':PASSWORD}).status_code==403
    assert post(c,'setup',{'password':'wrong'},csrf).status_code==400
    other=client();othercsrf=login(other)
    r=post(c,'setup',{'password':PASSWORD},csrf);secret=r.json()['secret']
    assert post(other,'confirm',{'code':pyotp.TOTP(secret).now()},othercsrf).status_code==400
    with job_store.connect() as conn:conn.execute("UPDATE privetek_mfa_setup SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'")
    assert post(c,'confirm',{'code':pyotp.TOTP(secret).now()},csrf).status_code==400
    assert c.get('/api/account/security').json()['enabled'] is False


def test_db_mfa_challenge_attempts_expiry_and_password_reset(db):
    c=client();csrf,secret,codes=enroll(c,db)
    new=client();token=challenge(new)
    for _ in range(5):assert finish(new,token,'invalid').status_code==400
    assert finish(new,token,codes[0]).status_code==400
    fresh=client();exp=challenge(fresh)
    with job_store.connect() as conn:conn.execute("UPDATE privetek_mfa_challenges SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'")
    assert finish(fresh,exp,codes[0]).status_code==400
    reset=c.post('/api/account/auth/forgot-password',json={'email':'owner@example.com'}).json()
    assert c.post('/api/account/auth/reset-password',json={'challenge_id':reset['challenge_id'],'code':db[-1][1],'password':PASSWORD+'new'}).status_code==200
    assert c.get('/api/account/me').status_code==401
    r=client().post('/api/account/auth/login',json={'email':'owner@example.com','password':PASSWORD+'new'})
    assert r.json()['mfa_required'] and 'set-cookie' not in r.headers
    assert finish(client(),token,codes[0]).status_code==400


def test_db_mfa_enable_revokes_old_sessions_and_disable_requires_factor(db):
    c=client();register(c,db);csrf=login(c)
    old=client();login(old)
    pending=post(c,'setup',{'password':PASSWORD},csrf).json()
    confirmed=post(c,'confirm',{'code':pyotp.TOTP(pending['secret']).now()},csrf)
    assert confirmed.status_code==200
    assert old.get('/api/account/me').status_code==401
    assert post(c,'disable',{'password':PASSWORD,'code':'invalid'},csrf).status_code==400
    code=confirmed.json()['recovery_codes'][0]
    assert post(c,'disable',{'password':'wrong','code':code},csrf).status_code==400
    assert post(c,'disable',{'password':PASSWORD,'code':code},csrf).json()['enabled'] is False
    assert client().post('/api/account/auth/login',json={'email':'owner@example.com','password':PASSWORD}).json().get('mfa_required') is None


def test_db_mfa_new_recovery_invalidates_old_codes_and_pending_logins(db):
    c=client();csrf,_,codes=enroll(c,db)
    other=client();token=challenge(other)
    r=post(c,'recovery',{'password':PASSWORD,'code':codes[0]},csrf)
    assert r.status_code==200 and len(r.json()['recovery_codes'])==10
    assert finish(other,token,codes[1]).status_code==400
    new=client();token2=challenge(new)
    assert finish(new,token2,codes[1]).status_code==400
    assert finish(new,token2,r.json()['recovery_codes'][0]).status_code==200


@pytest.mark.skipif(os.getenv('ACCOUNTS_NATIVE_POSTGRES_TESTS')!='1',reason='Native row locking required')
def test_db_mfa_concurrent_recovery_and_totp_redeemed_once(db,monkeypatch):
    c=client();_,secret,codes=enroll(c,db)
    for factor in [codes[0],pyotp.TOTP(secret).at(mfa.now()+timedelta(seconds=30))]:
        future=mfa.now()+timedelta(seconds=30)
        monkeypatch.setattr(mfa,'now',lambda f=future:f)
        clients=[client(),client()];tokens=[challenge(x) for x in clients]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda pair:mfa.finish_login(pair[0],factor,crypto.digest('session',pair[1])),zip(tokens,['a'*43,'b'*43])))
        assert results.count(True)==1 and results.count(False)==1
