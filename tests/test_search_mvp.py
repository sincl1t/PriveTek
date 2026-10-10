import httpx
import pytest
import trio
from pypdf import PdfReader
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

import osint
import server
from search_inputs import normalize_phone, normalize_username
from source_checks import github_username, amazon_phone
from report_data import prepare
from pdf_gen import create_report
from submission_guard import SubmissionGuard


@pytest.mark.parametrize('value,expected', [(' @Octocat ', 'octocat'), ('a','a'), ('some-user','some-user'), ('','')])
def test_username_input(value, expected):
    assert normalize_username(value) == expected


@pytest.mark.parametrize('value', ['../admin','https://github.com/a','a/b','a--b','a_1','a'*40,'-a','a-'])
def test_bad_username_rejected(value):
    with pytest.raises(ValueError):
        normalize_username(value)


@pytest.mark.parametrize('code,payload,expected', [
    (200, {'login':'Octocat','id':1,'type':'User','html_url':'https://github.com/Octocat'}, 'found'),
    (404, {'message':'Not Found'}, 'not_found'),
    (200, {'login':'other','id':1,'type':'User','html_url':'https://github.com/other'}, 'unavailable'),
    (200, {'login':'octocat','id':1,'type':'Organization','html_url':'https://github.com/octocat'}, 'unavailable'),
    (429, {'message':'Not Found'}, 'unavailable'),
    (503, {}, 'unavailable'),
    (200, {}, 'unavailable'),
])
def test_github_adapter_validates_evidence(code,payload,expected):
    async def run():
        def handler(request):
            assert request.url == 'https://api.github.com/users/octocat'
            return httpx.Response(code,json=payload)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            out=[]
            await github_username('octocat',client,out)
            assert out[0]['status'] == expected
    trio.run(run)


def test_github_transport_failure():
    async def run():
        def handler(request):
            raise httpx.ConnectError('private username',request=request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            out=[]
            await github_username('octocat',client,out)
            assert out[0]['status'] == 'unavailable'
            assert 'private username' not in out[0]['reason']
    trio.run(run)


@pytest.mark.parametrize('action', ['/ap/signin', '/ax/claim'])
def test_phone_source_posts_country_code_and_number(action):
    async def run():
        requests=[]
        def handler(request):
            requests.append(request)
            if request.method == 'GET':
                return httpx.Response(200,text=f'<form method="post" action="{action}"><input name="email"><input type="hidden" name="token" value="abc"></form>')
            assert b'email=12025550123' in request.content
            return httpx.Response(200,text='<form><input name="password" type="password"></form>')
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            out=[]
            await amazon_phone('2025550123','1',client,out)
            assert out[0]['exists'] is True
            assert len(requests)==2
    trio.run(run)


def test_search_combines_three_kinds_and_normalizes(monkeypatch):
    calls=[]
    def fake(function,checks,args):
        calls.append(args)
        if checks[0][0]=='GitHub':
            return [dict(name='GitHub',status='found',profile_url='https://github.com/octocat',reason='Exact handle',checked_at='2026-10-10T12:00:00+00:00')]
        if checks[0][0]=='Gravatar':
            return [dict(name='Gravatar',status='not_found')]
        return [dict(name=label,exists=True,rateLimit=False) for label,_ in checks]
    monkeypatch.setattr(osint.trio,'run',fake)
    monkeypatch.setattr(osint.hibp_client,'lookup',lambda email:([],dict(source='HIBP',kind='breach',status='not_found',reason='No match')))
    result=osint.search('reader@example.com','+1 (202) 555-0123','@Octocat')
    assert ('2025550123','1') in calls
    assert ('octocat',) in calls
    assert result['schema_version']==1
    assert {c['kind'] for c in result['checks']} >= {'email','phone','username'}
    assert all({'source','source_url','kind','status','reason','checked_at','profile_url'} <= c.keys() for c in result['checks'])
    assert result['username_profiles'][0]['profile_url']=='https://github.com/octocat'
    assert prepare(result)==result


def test_username_changes_duplicate_identity():
    guard=SubmissionGuard(per_email=5)
    one,_=guard.reserve('reader@example.com','','octocat')
    same,duplicate=guard.reserve('reader@example.com','','OCTOCAT')
    other,duplicate_other=guard.reserve('reader@example.com','','other')
    assert same==one and duplicate
    assert other!=one and not duplicate_other


def test_webhook_passes_username_to_pipeline(monkeypatch):
    monkeypatch.setattr(server.email_sender,'validate_settings',lambda:None)
    thread=MagicMock()
    monkeypatch.setattr(server.threading,'Thread',thread)
    response=TestClient(server.app).post('/webhook',headers={'X-Webhook-Secret':'test-webhook-key'},data={'Email':'reader@example.com','Username':'@Octocat'})
    assert response.status_code==200
    assert thread.call_args.kwargs['args'][0].Username=='octocat'
    server.slots.release()


def test_username_report_contains_profile(tmp_path):
    data={'checks':[dict(source='GitHub',kind='username',status='found',reason='Точное имя, личность не подтверждена.',profile_url='https://github.com/octocat',checked_at='2026-10-10T12:00:00+00:00')]}
    text=''.join(p.extract_text() for p in PdfReader(create_report(data,tmp_path)).pages)
    assert 'Публичные профили по username' in text
    assert 'https://github.com/octocat' in text
    assert 'личность не подтверждена' in text


@pytest.mark.parametrize('location,expected_requests', [('/ax/claim?step=2',3),('https://example.com/collect',2),('/ap/register',2)])
def test_amazon_redirect_is_bounded_and_same_origin(location,expected_requests):
    async def run():
        requests=[]
        def handler(request):
            requests.append(request)
            if len(requests)==1:
                return httpx.Response(200,text='<form method="post" action="/ax/claim"><input name="email"></form>')
            if request.method=='POST':
                return httpx.Response(302,headers={'Location':location})
            return httpx.Response(200,text='<form><input name="password" type="password"></form>')
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            out=[]
            await amazon_phone('2025550123','1',client,out)
            assert len(requests)==expected_requests
            assert out[0]['exists'] is (True if expected_requests==3 else None)
    trio.run(run)
