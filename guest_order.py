"""One-hour encrypted draft; never an authentication or job-creation token."""
import html
import json
import secrets
import re
from uuid import uuid4
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool
import account_crypto as crypto
import account_store
from account_routes import HEADERS, ready, origin, result

router=APIRouter()
COOKIE='__Host-privetek_draft'
TTL=3600
ASSETS=Path(__file__).parent/'account_ui'


def read(request):
    value=request.cookies.get(COOKIE,'')
    if not value or len(value)>3500:return None
    try:
        data=json.loads(crypto.report_cipher().decrypt(value.encode('ascii'),ttl=TTL))
        if data.get('purpose')!='guest-order-v1' or not isinstance(data.get('id'),str) or not re.fullmatch('[0-9a-f]{32}',data['id']):return None
        return data
    except Exception:
        return None


def clear(response):
    response.delete_cookie(COOKIE,secure=True,httponly=True,samesite='lax',path='/')


def render(values=None,error='',status=200,restore=True):
    values=values or {};content=(ASSETS/'start.html').read_text()
    for field in ['Name','Email','Phone','Username','AdditionalUsername1','AdditionalUsername2']:
        value=values.get(field,'')
        content=content.replace('{{'+field+'}}',html.escape(str(value)[:300],quote=True))
    content=content.replace('{{error}}',html.escape(error)).replace('{{restore}}','yes' if restore else 'no')
    return HTMLResponse(content,status_code=status,headers=HEADERS)


@router.get('/account/start',include_in_schema=False)
def start_page():
    ready();return render()


async def fields(request):
    if request.headers.get('content-type','').split(';')[0] != 'application/x-www-form-urlencoded':
        raise HTTPException(415,'Ожидается форма')
    content=bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content)>4096:raise HTTPException(413,'Слишком большая заявка')
    async def receive():return {'type':'http.request','body':bytes(content),'more_body':False}
    form=await Request(request.scope,receive).form(max_files=0,max_fields=10)
    if any(len(form.getlist(key))>1 for key in form):raise HTTPException(422,'Повторяющееся поле')
    return dict(form)


def save(values,request):
    from server import Submission
    from search_inputs import normalize_usernames
    from email_sender import mailbox
    from pydantic import ValidationError
    try:
        extras=[values.get('AdditionalUsername1',''),values.get('AdditionalUsername2','')]
        submission=Submission(Name=values.get('Name',''),Email=values.get('Email',''),Phone=values.get('Phone',''),Username=values.get('Username',''),AdditionalUsernames=extras)
        names=normalize_usernames(submission.Username,submission.AdditionalUsernames)
        email=mailbox(str(submission.Email)).casefold()
    except (ValueError,TypeError,ValidationError):
        return render(values,'Проверьте email, номер с кодом страны и username без ссылок. Данные остались в форме.',422,False)
    ip=request.client.host if request.client else 'unknown'
    if not account_store.quota([('draft:ip',ip,100),('draft:email',email,10),('draft:global','all',1000)]):
        return render(values,'Слишком много попыток. Повторите позже.',429,False)
    data=dict(purpose='guest-order-v1',id=uuid4().hex,name=submission.Name,email=email,
              phone=submission.Phone,username=names[0] if names else '',additional_usernames=names[1:])
    value=crypto.report_cipher().encrypt(json.dumps(data,ensure_ascii=False).encode()).decode()
    response=RedirectResponse('/account/register',status_code=303,headers=HEADERS)
    response.set_cookie(COOKIE,value,max_age=TTL,secure=True,httponly=True,samesite='lax',path='/')
    return response


@router.post('/account/start',include_in_schema=False)
async def start(request:Request):
    import os
    ready()
    if request.headers.get('origin') not in {'https://privetek.ru',os.getenv('ACCOUNT_ORIGIN')}:
        raise HTTPException(403,'Откройте форму на сайте PriveTek')
    values=await fields(request)
    return await run_in_threadpool(save,values,request)


@router.get('/api/account/draft')
def draft(request:Request):
    ready();data=read(request)
    response=result({'draft':{key:value for key,value in data.items() if key!='purpose'} if data else None})
    if not data and request.cookies.get(COOKIE):clear(response)
    return response


@router.delete('/api/account/draft')
def discard(request:Request):
    ready();origin(request)
    response=result({'message':'Заявка удалена из этого браузера'});clear(response);return response


def for_order(request,data,user):
    if 'draft_id' not in data:return None
    draft=read(request);supplied=data.get('draft_id')
    if not draft or not isinstance(supplied,str) or not re.fullmatch('[0-9a-f]{32}',supplied) or not secrets.compare_digest(supplied,draft['id']):
        raise HTTPException(409,'Заявка истекла или была изменена. Заполните её снова.')
    if crypto.email_key(user['email'])!=crypto.email_key(draft['email']):
        raise HTTPException(409,'Для этой заявки войдите с указанным в ней email или исправьте email заявки.')
    return draft
