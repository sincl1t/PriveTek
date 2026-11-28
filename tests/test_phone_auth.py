from unittest.mock import MagicMock
import pytest
import phone_auth as phone
import sms_provider
import account_crypto
import account_store
import job_store
from test_accounts import settings,db,client,register,login,PASSWORD  # noqa: F401
from account_routes import COOKIE


def enable(monkeypatch):
    monkeypatch.setattr(sms_provider,'configured',lambda:True)
    monkeypatch.setenv('SMS_PILOT_PHONE_HASHES',phone.phone_key('+12025550123'))
    sent=[];monkeypatch.setattr(sms_provider,'send_code',lambda number,code:sent.append((number,code)))
    return sent


def test_disabled_sms_routes_are_closed_without_db(settings,monkeypatch):
    monkeypatch.setattr(sms_provider,'configured',lambda:False)
    c=client();assert c.get('/api/account/auth/capabilities').json()=={'sms_login':False}
    assert c.post('/api/account/auth/sms-start',json={'phone':'+12025550123'}).status_code==404
    assert c.post('/api/account/auth/sms-verify',json={}).status_code==404
    monkeypatch.setattr(account_store,'session',lambda _:dict(id='owner',email='owner@example.com'))
    c.cookies.set(COOKIE,'x'*43)
    assert c.get('/api/account/phone').json()['available'] is False
    assert c.post('/api/account/phone/start',json={}).status_code==403


def test_phone_binding_login_and_replay_protection(db,monkeypatch):
    c=client();register(c,db);csrf=login(c);sent=enable(monkeypatch)
    headers={'X-CSRF-Token':csrf}
    assert c.post('/api/account/phone/start',json={'phone':'+12025550123','password':'wrong','consent':True},headers=headers).status_code==400
    r=c.post('/api/account/phone/start',json={'phone':'+12025550123','password':PASSWORD,'consent':True},headers=headers)
    assert r.status_code==200,r.text
    challenge=r.json()['challenge_id'];code=sent[-1][1]
    with job_store.connect() as conn:
        row=conn.execute('SELECT * FROM privetek_phone_codes WHERE id=%s',(challenge,)).fetchone()
        assert code not in row['code_hash'] and b'12025550123' not in bytes(row['ciphertext'])
    assert c.post('/api/account/phone/verify',json={'challenge_id':challenge,'code':code},headers=headers).status_code==200
    assert c.get('/api/account/phone').json()['linked'] is True
    c.post('/api/account/auth/logout',json={},headers=headers)
    r=c.post('/api/account/auth/sms-start',json={'phone':'+12025550123'})
    # Binding just sent a code: the one-minute cooldown applies to login too.
    if r.status_code==429:
        with job_store.connect() as conn:conn.execute("UPDATE privetek_phone_codes SET expires_at=now()-interval '1 second'")
        r=c.post('/api/account/auth/sms-start',json={'phone':'+12025550123'})
    assert r.status_code==200,r.text
    challenge=r.json()['challenge_id'];code=sent[-1][1]
    assert c.post('/api/account/auth/sms-verify',json={'challenge_id':challenge,'code':code}).status_code==200
    assert c.get('/api/account/me').json()['email']=='owner@example.com'
    assert c.post('/api/account/auth/sms-verify',json={'challenge_id':challenge,'code':code}).status_code==400


def test_unknown_phone_never_sends(db,monkeypatch):
    sent=enable(monkeypatch);challenge=phone.issue('+12025550123','login')
    assert not sent and phone.redeem(challenge,'12345678','login',session_hash='x') is False


def test_mfa_is_not_bypassed_and_wrong_codes_are_bounded(db,monkeypatch):
    c=client();register(c,db);sent=enable(monkeypatch)
    with job_store.connect() as conn:
        user=conn.execute('SELECT id FROM privetek_users').fetchone()['id']
    challenge=phone.issue('+12025550123','bind',user);assert phone.redeem(challenge,sent[-1][1],'bind',user_id=user)
    with job_store.connect() as conn:conn.execute('UPDATE privetek_users SET mfa_enabled=TRUE WHERE id=%s',(user,))
    challenge=phone.issue('+12025550123','login');code=sent[-1][1]
    outcome=phone.redeem(challenge,code,'login',session_hash='must-not-create')
    assert isinstance(outcome,tuple)
    with job_store.connect() as conn:assert not conn.execute("SELECT 1 FROM privetek_sessions WHERE token_hash='must-not-create'").fetchone()
    challenge=phone.issue('+12025550123','login');code=sent[-1][1]
    wrong='00000000' if code!='00000000' else '11111111'
    for _ in range(5):assert not phone.redeem(challenge,wrong,'login',session_hash='x')
    assert not phone.redeem(challenge,code,'login',session_hash='x')


def test_expiry_budget_and_unlink_revoke_login(db,monkeypatch):
    c=client();register(c,db);csrf=login(c);sent=enable(monkeypatch)
    with job_store.connect() as conn:
        conn.execute('TRUNCATE privetek_sms_budget')
        user=conn.execute('SELECT id FROM privetek_users').fetchone()['id']
    challenge=phone.issue('+12025550123','bind',user)
    assert phone.redeem(challenge,sent[-1][1],'bind',user_id=user)
    monkeypatch.setenv('SMS_MAX_SENDS_PER_DAY','1')
    challenge=phone.issue('+12025550123','login')
    assert len(sent)==1  # Daily cap includes the binding message.
    assert not phone.redeem(challenge,sent[-1][1],'login',session_hash='capped')
    with job_store.connect() as conn:
        conn.execute('TRUNCATE privetek_sms_budget')
        conn.execute('DELETE FROM privetek_phone_codes')
    challenge=phone.issue('+12025550123','login');code=sent[-1][1]
    with job_store.connect() as conn:conn.execute("UPDATE privetek_phone_codes SET expires_at=now()-interval '1 second' WHERE id=%s",(challenge,))
    assert not phone.redeem(challenge,code,'login',session_hash='expired')
    with job_store.connect() as conn:conn.execute('TRUNCATE privetek_sms_budget')
    challenge=phone.issue('+12025550123','login');code=sent[-1][1]
    assert c.post('/api/account/phone/delete',json={'password':PASSWORD},headers={'X-CSRF-Token':csrf}).status_code==200
    assert not phone.redeem(challenge,code,'login',session_hash='unlinked')
    assert c.get('/api/account/phone').json()['linked'] is False
    assert c.get('/api/account/me').json()['email']=='owner@example.com'


def test_binding_challenge_cannot_be_used_by_another_account(db,monkeypatch):
    c=client();register(c,db);sent=enable(monkeypatch)
    with job_store.connect() as conn:
        conn.execute('TRUNCATE privetek_sms_budget')
        user=conn.execute('SELECT id FROM privetek_users').fetchone()['id']
    challenge=phone.issue('+12025550123','bind',user);code=sent[-1][1]
    assert not phone.redeem(challenge,code,'bind',user_id='another-user')
    assert phone.redeem(challenge,code,'bind',user_id=user)
