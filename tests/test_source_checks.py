import httpx
import trio
import pytest
import source_checks as sources
import osint


def run(fn, replies):
    requests=[]
    def handler(request):
        requests.append(request)
        return replies[len(requests)-1]
    async def check():
        out=[]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
            await fn('test@example.invalid',client,out)
        return out
    return trio.run(check),requests


@pytest.mark.parametrize('code',[403,404,429,500])
@pytest.mark.parametrize('fn',[sources.amazon_email,sources.instagram])
def test_http_failure(fn,code):
    out,requests=run(fn,[httpx.Response(code)])
    assert out[0]['exists'] is None
    assert str(code) in out[0]['reason']
    assert len(requests)==1
    checks=[]
    assert osint.collect(out,[],checks) is None
    assert checks[0]['status']=='unavailable'


def test_captcha_stops_before_submission():
    out,requests=run(sources.amazon_email,[httpx.Response(200,text='<form action="/errors_page/validateCaptcha"></form>')])
    assert 'CAPTCHA' in out[0]['reason']
    assert len(requests)==1


@pytest.mark.parametrize('action',['https://evil.example/ap/signin','/ap/register','http://www.amazon.com/ap/signin'])
def test_unexpected_action_never_receives_email(action):
    out,requests=run(sources.amazon_email,[httpx.Response(200,text=f'<form method="post" action="{action}"><input name="email"></form>')])
    assert out[0]['exists'] is None
    assert len(requests)==1


@pytest.mark.parametrize('body,expected',[
    ('<div id="auth-password-missing-alert" hidden></div>',None),
    ('<form><input name="password" type="password"></form>',True)])
def test_amazon_result(body,expected):
    out,requests=run(sources.amazon_email,[httpx.Response(200,text='<form method="post" action="/ap/signin"><input name="email"><input type="hidden" name="token" value="x"></form>'),httpx.Response(200,text=body)])
    assert requests[1].url.path=='/ap/signin'
    assert out[0]['exists'] is expected


@pytest.mark.parametrize('payload,expected',[
    ({'status':'ok','errors':{'email':[{'code':'email_is_taken'}]}},True),
    ({'status':'ok','errors':{}},None),
    ({'status':'fail','errors':{}},None),
    ({'status':'ok','errors':{'email':[{'code':'email_sharing_limit'}]}},None),
    ([],None)])
def test_instagram_cookie_and_schema(payload,expected):
    out,requests=run(sources.instagram,[httpx.Response(200,headers={'set-cookie':'csrftoken=test; Domain=.instagram.com; Path=/'},text='<html></html>'),httpx.Response(200,json=payload)])
    assert requests[1].url.path=='/api/v1/web/accounts/web_create_ajax/attempt/'
    assert requests[1].headers['x-csrftoken']=='test'
    assert out[0]['exists'] is expected


@pytest.mark.parametrize('payload,expected',[
    ({'status':20},True), ({'status':1},False), ({'status':True},None),
    ({'status':'20'},None), ({'status':429},None), ({'error':'blocked'},None), ([],None)])
def test_spotify_validation_only(payload,expected):
    out,requests=run(sources.spotify,[httpx.Response(200,json=payload)])
    assert len(requests)==1
    request=requests[0]
    assert request.method=='GET'
    assert request.url.host=='spclient.wg.spotify.com'
    assert request.url.params['validate']=='1'
    assert not request.content
    assert out[0]['exists'] is expected
    checks=[]
    osint.collect(out,[],checks)
    assert checks[0]['status']==('possible' if expected is True else 'unknown' if expected is False else 'unavailable')


@pytest.mark.parametrize('code',[301,403,404,429,500])
def test_spotify_http_errors_never_negative(code):
    out,requests=run(sources.spotify,[httpx.Response(code,headers={'location':'https://example.invalid/'},json={'status':20})])
    assert out[0]['exists'] is None
    assert len(requests)==1


def test_spotify_html_is_unavailable():
    out,requests=run(sources.spotify,[httpx.Response(200,text='<html>CAPTCHA</html>')])
    assert out[0]['exists'] is None


def test_spotify_integrates_with_report(tmp_path,monkeypatch):
    from pypdf import PdfReader
    import pdf_gen
    async def fake(email,client,out):
        out.append({'name':'Spotify','exists':True,'rateLimit':False,'reason':'Email уже используется.'})
    monkeypatch.setattr(osint,'spotify',fake)
    async def unavailable(email,client,out):
        out.append({'name':'Other','rateLimit':True})
    monkeypatch.setattr(osint,'instagram',unavailable)
    monkeypatch.setattr(osint,'holehe_amazon',unavailable)
    monkeypatch.setattr(osint,'gravatar',unavailable)
    monkeypatch.setattr(osint.hibp_client,'lookup',lambda email:(None,{'source':'HIBP','kind':'breach','status':'skipped','reason':'Нет ключа.'}))
    monkeypatch.setattr(osint.leakcheck_client,'lookup',lambda email:(None,{'source':'LeakCheck','kind':'breach','status':'unavailable','reason':'Offline test.'}))
    result=osint.search('test@example.invalid')
    assert any(c['source']=='Spotify' and c['status']=='possible' for c in result['checks'])
    text=''.join(p.extract_text() for p in PdfReader(pdf_gen.create_report(result,tmp_path)).pages)
    assert 'Spotify' in text
    assert 'Email уже используется.' in text


def test_spotify_skipped_without_email():
    result=osint.search()
    assert any(c['source']=='Spotify' and c['status']=='skipped' for c in result['checks'])


@pytest.mark.parametrize('code,mime,status', [
    (200, 'image/png', 'found'), (404, 'text/html', 'not_found'),
    (200, 'text/html', 'unavailable'), (429, 'text/html', 'unavailable'),
    (302, 'image/png', 'unavailable'), (500, 'image/png', 'unavailable')])
def test_gravatar_is_only_a_public_avatar_lookup(code, mime, status):
    import hashlib
    out, requests = run(sources.gravatar, [httpx.Response(code, headers={'content-type': mime})])
    assert out[0]['status'] == status
    assert out[0]['kind'] == 'avatar'
    assert requests[0].method == 'HEAD'
    assert requests[0].url.params['d'] == '404'
    assert requests[0].url.path.endswith(hashlib.sha256(b'test@example.invalid').hexdigest())
    assert 'test@example.invalid' not in str(requests[0].url)


def test_avatar_is_not_reported_as_breach(tmp_path):
    from report_insights import insights
    from pypdf import PdfReader
    import pdf_gen
    data = {'checks': [{'source': 'Gravatar', 'kind': 'avatar', 'status': 'found',
                         'reason': 'Публичный аватар; не утечка.'}], 'email_breach': None}
    summary, actions = insights(data)
    assert 'Найден публичный аватар' in summary[0]
    assert not any('замените' in line.lower() for line in actions)
    text = ''.join(p.extract_text() for p in PdfReader(pdf_gen.create_report(data, tmp_path)).pages)
    assert 'Публичные аватары по email' in text
    assert 'Gravatar: Найдены сведения' in text
