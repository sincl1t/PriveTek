"""A saved draft is neither verified contact nor permission to start a search."""
import html
import json
import time
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
import server
import guest_order as guest
import account_store
import account_crypto as crypto
import job_store
from test_accounts import settings,db,client,register,login

FIELDS={'Name':'Synthetic Person','Email':'owner@example.com','Phone':'+1 (202) 555-0123','Username':'@One','AdditionalUsername1':'Two'}


def test_pages_and_cross_origin_rejection(settings,monkeypatch):
    c=client();quota=MagicMock();monkeypatch.setattr(account_store,'quota',quota)
    for path in ['/account/login','/account/register','/account/start']:assert c.get(path).status_code==200
    assert c.post('/account/start',data=FIELDS,headers={'Origin':'https://evil.test'}).status_code==403
    quota.assert_not_called()
    assert c.post('/account/start',json=FIELDS).status_code==415
    assert c.post('/account/start',content='x'*5000,headers={'Content-Type':'application/x-www-form-urlencoded'}).status_code==413


def test_invalid_form_keeps_escaped_fields_without_sending_mail(settings,monkeypatch):
    quota=MagicMock();monkeypatch.setattr(account_store,'quota',quota)
    name='<script>alert("private")</script>'
    r=client().post('/account/start',data={**FIELDS,'Name':name,'Phone':'bad'},follow_redirects=False)
    assert r.status_code==422 and html.escape(name,quote=True) in r.text
    assert name not in r.text and 'owner@example.com' in r.text and '@One' in r.text
    assert guest.COOKIE not in r.cookies
    quota.assert_not_called()


def test_draft_cookie_is_encrypted_tamper_proof_and_expiring(settings,monkeypatch):
    monkeypatch.setattr(account_store,'quota',lambda items:True)
    c=client();r=c.post('/account/start',data=FIELDS,follow_redirects=False)
    assert r.status_code==303 and r.headers['location']=='/account/register'
    value=c.cookies.get(guest.COOKIE)
    assert all(part not in value for part in ['owner@example.com','Synthetic Person','2025550123'])
    assert all(flag in r.headers['set-cookie'].lower() for flag in ['httponly','secure','samesite=lax','max-age=3600','path=/'])
    restored=c.get('/api/account/draft').json()['draft']
    assert restored['phone']=='+12025550123' and restored['username']=='One' and restored['additional_usernames']==['Two']
    assert c.get('/api/account/me').status_code==401
    for token in [value[:-2]+'xx',crypto.report_cipher().encrypt_at_time(json.dumps({'purpose':'guest-order-v1','id':'a'*32}).encode(),int(time.time())-3601).decode()]:
        bad=client();bad.cookies.set(guest.COOKIE,token)
        assert bad.get('/api/account/draft').json()['draft'] is None
    assert c.delete('/api/account/draft',headers={'Origin':'https://evil.test'}).status_code==403
    assert c.delete('/api/account/draft').status_code==200
    assert c.get('/api/account/draft').json()['draft'] is None


def test_legacy_webhook_cannot_bypass_verification_when_accounts_enabled(settings,monkeypatch):
    reserve=MagicMock();monkeypatch.setattr(server.guard,'reserve',reserve)
    c=client();headers={'X-Webhook-Secret':'test-webhook-key'}
    assert c.post('/webhook',data=FIELDS,headers=headers).status_code==409
    assert c.post('/webhook',data={'test':'test'},headers=headers).status_code==200
    reserve.assert_not_called()


def test_db_draft_survives_verification_login_and_requires_explicit_order(db,monkeypatch):
    c=client();r=c.post('/account/start',data=FIELDS,headers={'Origin':'https://privetek.ru'},follow_redirects=False)
    assert r.status_code==303 and db==[]
    draft=c.get('/api/account/draft').json()['draft']
    with job_store.connect() as connection:
        assert connection.execute('SELECT count(*) AS n FROM privetek_jobs').fetchone()['n']==0
        assert connection.execute('SELECT count(*) AS n FROM privetek_users').fetchone()['n']==0
    assert c.post('/api/account/jobs',json={'draft_id':draft['id'],'consent':True}).status_code==401
    register(c,db);csrf=login(c)
    assert c.get('/api/account/draft').json()['draft']==draft
    with job_store.connect() as connection:
        assert connection.execute('SELECT count(*) AS n FROM privetek_jobs').fetchone()['n']==0
    thread=MagicMock();monkeypatch.setattr(server.threading,'Thread',thread);monkeypatch.setattr(server,'slots',MagicMock())
    payload={'draft_id':draft['id'],'username':draft['username'],'phone':draft['phone'],'additional_usernames':draft['additional_usernames']}
    headers={'X-CSRF-Token':csrf}
    assert c.post('/api/account/jobs',json={**payload,'consent':False},headers=headers).status_code==422
    thread.assert_not_called()
    response=c.post('/api/account/jobs',json={**payload,'consent':True},headers=headers)
    assert response.status_code==202 and thread.call_count==1
    assert thread.call_args.kwargs['args'][0].Name=='Synthetic Person'
    assert c.get('/api/account/draft').json()['draft'] is None


def test_db_wrong_verified_account_cannot_launch_another_contact_draft(db,monkeypatch):
    c=client();c.post('/account/start',data=FIELDS,follow_redirects=False)
    draft=c.get('/api/account/draft').json()['draft']
    register(c,db,'other@example.com');csrf=login(c,'other@example.com')
    reserve=MagicMock();monkeypatch.setattr(server.guard,'reserve',reserve)
    for draft_id in [draft['id'],'wrong','💥']:
        r=c.post('/api/account/jobs',json={'draft_id':draft_id,'consent':True},headers={'X-CSRF-Token':csrf})
        assert r.status_code==409
    reserve.assert_not_called()
    assert c.get('/api/account/draft').json()['draft']==draft
