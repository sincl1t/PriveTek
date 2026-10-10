import hashlib
import httpx
import pytest
import trio
from fastapi.testclient import TestClient
import leakcheck_client
import public_sources as sources
import source_health
import server

PAYLOADS = {
 'GitHub': {'id':1,'login':'octocat','type':'User'},
 'GitLab': [{'id':1,'username':'sytses'}],
 'Codeberg': {'id':1,'login':'earl-warren'},
 'Hugging Face': {'_id':'abc','user':'julien-c','type':'user'},
 'DEV': {'id':1,'username':'ben'},
 'Hacker News': {'created':123,'id':'pg'},
 'Keybase': {'status':{'code':0},'them':[{'id':'abc','basics':{'username':'chris'}}]},
 'Lichess': {'createdAt':123,'username':'thibault'},
 'Chess.com': {'player_id':1,'username':'hikaru'},
 'Wikipedia': {'query':{'users':[{'userid':1,'name':'Jimbo Wales'}]}},
 'Discourse Meta': {'user':{'id':1,'username':'codinghorror'}},
}
MISSES = {
 'GitHub': (404,{'message':'Not Found'}),
 'GitLab': (200,[]),
 'Codeberg': (404,{'message':'user does not exist'}),
 'Hugging Face': (404,{'error':'User not found'}),
 'DEV': (404,{'status':404,'error':'Not Found'}),
 'Hacker News': (200,None),
 'Keybase': (200,{'status':{'code':0},'them':[None]}),
 'Lichess': (404,{'error':'Not found'}),
 'Chess.com': (404,{'code':0,'message':'User not found'}),
 'Wikipedia': (200,{'query':{'users':[{'name':'absent','missing':''}]}}),
 'Discourse Meta': (404,{'error_type':'not_found'}),
}


def invoke(source, code, body=None, text=None, username=None):
    async def run():
        def handler(request):
            assert request.method == 'GET'
            expected, params = sources.endpoint(source[0], username or source[3])
            assert str(request.url.copy_with(query=None)) == expected
            return httpx.Response(code, text='null') if body is None and text is None else (httpx.Response(code, json=body) if text is None else httpx.Response(code, text=text))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await sources.check_profile(source, username or source[3], client)
    return trio.run(run)


@pytest.mark.parametrize('source', sources.SOURCES, ids=lambda s:s[0])
def test_public_profile_exact_match(source):
    result=invoke(source,200,PAYLOADS[source[0]])
    assert result['status']=='found'
    assert result['profile_url'].startswith(source[1])
    assert result['checked_at']
    assert 'Принадлежность' in result['reason']


@pytest.mark.parametrize('source', sources.SOURCES, ids=lambda s:s[0])
def test_public_profile_recognised_miss(source):
    result=invoke(source,*MISSES[source[0]])
    assert result['status']=='not_found'
    assert result['profile_url'] is None


@pytest.mark.parametrize('source', sources.SOURCES, ids=lambda s:s[0])
@pytest.mark.parametrize('code',[200,404,429,503])
def test_challenge_html_never_means_no_account(source,code):
    assert invoke(source,code,text='<html>Challenge</html>')['status']=='unavailable'


@pytest.mark.parametrize('source', sources.SOURCES, ids=lambda s:s[0])
def test_wrong_account_never_becomes_match(source):
    assert invoke(source,200,PAYLOADS[source[0]],username='other123')['status']=='unavailable'


def test_case_sensitive_hn_and_wikipedia():
    assert not sources.matches('Hacker News','pg','PG')
    assert sources.matches('Wikipedia','Jimbo Wales','Jimbo_Wales')
    assert not sources.matches('Wikipedia','Jimbo Wales','JIMBO_WALES')
    assert sources.matches('GitHub','Octocat','octocat')


def test_platform_specific_invalid_handle_skips_without_network():
    async def run():
        def forbidden(request):
            raise AssertionError('Network must not run')
        async with httpx.AsyncClient(transport=httpx.MockTransport(forbidden)) as client:
            result=await sources.check_profile(sources.SOURCES[0],'a_b',client)
            assert result['status']=='skipped' and result['checked_at'] is None
    trio.run(run)


@pytest.mark.parametrize('code,body,status', [
 (200,{'success':True,'found':0},'not_found'),
 (200,{'success':False,'error':'Not found'},'not_found'),
 (429,{'success':False,'error':'Not found'},'unavailable'),
 (200,{'success':True,'found':1,'fields':['password'],'sources':[{'name':'Example','date':'2020-01','password':'never-copy'}]},'found'),
 (200,{'success':True,'found':1,'fields':['password'],'sources':[]},'unavailable'),
 (200,{'success':True,'found':True},'unavailable'),
 (200,{'success':False,'error':'private details'},'unavailable'),
 (429,{'success':True,'found':0},'unavailable'),
])
def test_leakcheck_hash_only_and_metadata(monkeypatch,code,body,status):
    monkeypatch.setattr(leakcheck_client,'_last_request',0)
    def fake(url,**kwargs):
        assert url=='https://leakcheck.io/api/public'
        assert kwargs['params']=={'check':hashlib.sha256(b'reader@example.com').hexdigest()[:24]}
        return httpx.Response(code,json=body)
    monkeypatch.setattr(leakcheck_client.httpx,'get',fake)
    rows,check=leakcheck_client.lookup(' Reader@Example.com ')
    assert check['status']==status
    assert 'private details' not in check['reason']
    if rows:
        assert 'password' not in rows[0]
        assert rows[0]['classes_scope']=='all_matching_breaches'


def test_probe_auth_and_cache(monkeypatch):
    monkeypatch.setenv('STATUS_API_KEY','team-key')
    monkeypatch.setattr(source_health,'_cached',None)
    calls=[]
    def fake(*args):
        calls.append(args)
        return [dict(source='GitHub',kind='username',status='found' if args[-1] is True else 'not_found')]
    monkeypatch.setattr(source_health.trio,'run',fake)
    monkeypatch.setattr(source_health.leakcheck_client,'lookup',lambda email:([],dict(source='LeakCheck',kind='breach',status='not_found')))
    client=TestClient(server.app)
    assert client.get('/api/sources').status_code==403
    assert client.post('/api/sources/check').status_code==403
    headers={'Authorization':'Bearer team-key'}
    registry=client.get('/api/sources',headers=headers)
    assert registry.status_code==200 and len(registry.json()['sources'])==17
    first=client.post('/api/sources/check',headers=headers)
    second=client.post('/api/sources/check',headers=headers)
    assert first.json()['verified_sources']==2
    assert second.json()['cached'] is True and len(calls)==2
    assert first.headers['cache-control']=='no-store'


def test_leakcheck_enforces_request_spacing(monkeypatch):
    sleeps=[]
    monkeypatch.setattr(leakcheck_client,'_last_request',10.0)
    monkeypatch.setattr(leakcheck_client.time,'monotonic',lambda:10.2)
    monkeypatch.setattr(leakcheck_client.time,'sleep',sleeps.append)
    monkeypatch.setattr(leakcheck_client.httpx,'get',lambda *a,**kw:httpx.Response(200,json={'success':False,'error':'Not found'}))
    leakcheck_client.lookup('reader@example.com')
    assert sleeps == [pytest.approx(.85)]


def test_leakcheck_pdf_labels_provider_and_global_categories(tmp_path):
    from pypdf import PdfReader
    from pdf_gen import create_report
    data={'checks':[dict(source='LeakCheck',kind='breach',status='found',reason='Метаданные')],
          'email_breach':[dict(source='LeakCheck',name='Example',date='2020-01',data_classes=['password'],classes_scope='all_matching_breaches')]}
    text=''.join(page.extract_text() for page in PdfReader(create_report(data,tmp_path)).pages)
    assert 'Источник сведений: LeakCheck.' in text
    assert 'Категории во всех совпавших утечках: пароли' in text
    assert 'Powered by LeakCheck' in text
    assert 'Источник сведений: HIBP.' not in text
