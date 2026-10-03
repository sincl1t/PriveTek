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
