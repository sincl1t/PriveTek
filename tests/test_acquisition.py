"""Acquisition trust boundaries and real disposable-DB conversion accounting."""
from unittest.mock import MagicMock
import pytest
from starlette.requests import Request
from fastapi.testclient import TestClient
import acquisition as a
import server
import job_store
from test_accounts import settings, db, client, register, login


def request(cookie='', query='', headers=()):
    return Request({'type':'http','method':'GET','path':'/account','query_string':query.encode(),
                    'headers':[(b'cookie',(a.COOKIE+'='+cookie).encode()),*headers]})


def test_labels_never_store_free_text():
    assert a.attribution({}) == ('direct','unknown','none')
    assert a.attribution({'utm_source':'VK','utm_medium':'social','utm_campaign':'c12'}) == ('vk','social','c12')
    assert a.attribution({'utm_source':'private@example.com','utm_medium':'secret','utm_campaign':'+79990000000'}) == ('unknown','unknown','none')


def test_cookie_is_authenticated_expires_and_respects_opt_out(settings,monkeypatch):
    monkeypatch.setattr(a.time,'time',lambda:1800000000)
    value=a.token(); assert len(a.visitor(request(value))) == 32
    assert a.visitor(request(value[:-1]+('0' if value[-1]!='0' else '1'))) is None
    monkeypatch.setattr(a.time,'time',lambda:1800000000+31*86400)
    assert a.visitor(request(value)) is None
    for name in [b'dnt',b'sec-gpc']:
        assert a.visitor(request(value,headers=[(name,b'1')])) is None


def test_public_cannot_submit_success_or_private_properties(settings,monkeypatch):
    c=client(); quota=MagicMock();monkeypatch.setattr(server.account_crypto,'enabled',lambda:True)
    import account_store
    monkeypatch.setattr(account_store,'quota',quota)
    for payload in [{'event':'registered'}, {'event':'form_open','email':'private@example.com'}, {'event':[]}]:
        assert c.post('/api/account/analytics/event',json=payload).status_code==422
    quota.assert_not_called()
    assert c.post('/api/account/analytics/event',json={'event':'form_open'},headers={'Origin':'https://evil.test'}).status_code==403
    assert c.get('/api/internal/analytics/summary').status_code in (403,503)


def test_analytics_failure_does_not_break_account_page(settings,monkeypatch):
    monkeypatch.setattr(a,'visit',MagicMock(side_effect=RuntimeError('PRIVATE_DB_ERROR_MARKER')))
    r=client().get('/account')
    assert r.status_code==200 and 'PRIVATE_DB_ERROR_MARKER' not in r.text
    assert a.COOKIE not in r.cookies


def test_summary_requires_team_key_and_valid_period(settings,monkeypatch):
    monkeypatch.setenv('STATUS_API_KEY','synthetic-team-key')
    c=client()
    assert c.get('/api/internal/analytics/summary').status_code==403
    assert c.get('/api/internal/analytics/summary?days=91',headers={'Authorization':'Bearer synthetic-team-key'}).status_code==422


def test_db_first_touch_registration_jobs_ready_and_download(db,monkeypatch,tmp_path):
    import account_store
    c=client()
    r=c.get('/account?utm_source=vk&utm_medium=social&utm_campaign=c12')
    assert a.COOKIE in r.cookies
    first=c.cookies.get(a.COOKIE)
    assert c.get('/account?utm_source=telegram').status_code==200
    assert c.cookies.get(a.COOKIE)==first
    for _ in range(2):
        assert c.post('/api/account/analytics/event',json={'event':'registration_start'}).status_code==200
    register(c,db);login(c)
    with job_store.connect() as connection:
        user=connection.execute('SELECT id,email_key FROM privetek_users').fetchone()
    for job in ['a'*32,'b'*32]:
        job_store.record(job,'accepted','owner@example.com')
        a.associate_job(request(first),job)
    pdf=tmp_path/'synthetic.pdf';pdf.write_bytes(b'%PDF-1.3\nsynthetic')
    account_store.save_report('a'*32,pdf)
    for _ in range(2):
        assert c.get('/api/account/jobs/'+'a'*32+'/report').status_code==200
    assert c.get('/api/account/jobs/'+'b'*32+'/report').status_code==404
    result=a.summary(30)
    counts={row['kind']:row['events'] for row in result['channels'] if row['source']=='vk'}
    assert counts=={'visit':1,'landing':2,'registration_start':1,'contact_verified':1,'registered':1,'report_ordered':2,'report_ready':1,'report_response':1}
    assert result['accounts']==[{'account_id':user['id'],'ordered':2,'ordered_total':2,'ready_observed':1,'report_responses_observed':1}]
    assert c.post('/api/account/auth/verify',json={'challenge_id':'a'*48,'code':'12345678'}).status_code==400
    assert any(row['kind']=='error_verification' for row in a.summary(30)['channels'])
    with job_store.connect() as connection:
        connection.execute("UPDATE privetek_analytics_events SET created_at=CURRENT_TIMESTAMP-INTERVAL '91 days'")
        connection.execute("UPDATE privetek_analytics_visitors SET created_at=CURRENT_TIMESTAMP-INTERVAL '91 days'")
    a.cleanup()
    assert a.summary(30)['channels']==[]


def test_db_redirect_is_constant_and_utm_is_bounded(db):
    c=client()
    r=c.get('/go?utm_source=telegram&utm_medium=social&utm_campaign=c1&next=https://evil.test',follow_redirects=False)
    assert r.status_code==302 and r.headers['location']=='https://privetek.ru/'
    assert a.COOKIE in r.cookies
    assert a.summary(30)['channels'][0]['source']=='telegram'
    c2=client();r=c2.get('/account',headers={'DNT':'1'})
    assert a.COOKIE not in r.cookies
