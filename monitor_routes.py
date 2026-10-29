"""Session-owned monitor settings and history; machine tick lives separately in server."""
import os
import re
from fastapi import APIRouter,HTTPException,Request
from starlette.concurrency import run_in_threadpool
from account_routes import ready,origin,body,identify,result,quota
import monitor_store as store

router=APIRouter()


def available():return os.getenv('MONITOR_ENABLED','false').lower()=='true' and len(os.getenv('MONITOR_RUNNER_TOKEN',''))>=32


@router.get('/api/account/monitor')
def read(request:Request,offset:int=0):
    ready();user,_=identify(request)
    if not 0<=offset<=1000:raise HTTPException(422,'Неверная страница истории')
    rows=store.history(user['id'],offset,16)
    return result(dict(available=available(),settings=store.settings(user['id']),history=rows[:15],has_more=len(rows)>15))


def update(data,request):
    user,_=identify(request,mutation=True)
    action=data.get('action')
    if action not in ('enable','pause','resume','delete'):raise HTTPException(422,'Выберите действие мониторинга')
    if action in ('enable','resume') and not available():raise HTTPException(503,'Мониторинг пока не подключён')
    username=data.get('username','');use_reviews=data.get('use_profile_reviews',True)
    if not isinstance(username,str) or len(username)>65 or type(use_reviews) is not bool:raise HTTPException(422,'Проверьте username и настройки')
    quota(request,user['email'],'monitor-settings',20)
    try:store.change(user['id'],action,username,data.get('consent') is True,use_reviews)
    except ValueError:raise HTTPException(422,'Подтвердите согласие и проверьте username') from None
    except RuntimeError as error:
        raise HTTPException(409,'Пилот завершён' if str(error)=='pilot_ended' else 'Все 10 мест пилота заняты') from None
    return result(dict(settings=store.settings(user['id'])))


@router.post('/api/account/monitor')
async def change(request:Request):
    ready();origin(request);data=await body(request)
    try:return await run_in_threadpool(update,data,request)
    except HTTPException:raise
    except Exception:raise HTTPException(503,'Не удалось изменить мониторинг. Попробуйте позже') from None


@router.post('/api/account/monitor/exclusions')
async def exclusions(request:Request):
    ready();origin(request);data=await body(request)
    def execute():
        user,_=identify(request,mutation=True)
        item_id=data.get('item_id');action=data.get('action')
        if not isinstance(item_id,str) or not re.fullmatch('[0-9a-f]{24}',item_id) or action not in ('exclude','restore'):raise HTTPException(422,'Неверная отметка')
        quota(request,user['email'],'monitor-review',50)
        try:found=store.exclude(user['id'],item_id,action)
        except ValueError:raise HTTPException(422,'Достигнут лимит исключений') from None
        if not found:raise HTTPException(404,'Находка недоступна')
        return result(dict(settings=store.settings(user['id'])))
    try:return await run_in_threadpool(execute)
    except HTTPException:raise
    except Exception:raise HTTPException(503,'Не удалось сохранить отметку') from None
