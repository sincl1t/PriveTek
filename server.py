"""Tilda webhook. Run one worker; background jobs are not a durable queue."""
import logging
import asyncio
import os
import re
import threading
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from search_inputs import normalize_phone, normalize_username
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.encoders import jsonable_encoder
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError, field_validator

import email_sender
import pdf_gen
import job_store
import account_crypto
import discovery
from account_routes import router as account_router
from monitor_routes import router as monitor_router
from submission_guard import SubmissionGuard, Limited
from privacy_logging import configure_logging

load_dotenv(Path(__file__).resolve().parent / '.env')
configure_logging()
logger = logging.getLogger('privetek')
@asynccontextmanager
async def lifespan(app):
    account_crypto.validate_settings()
    await run_in_threadpool(job_store.initialize)
    if os.getenv('RENDER') == 'true':
        threading.Thread(target=discovery.startup_probe, daemon=True, name='discovery-probe').start()
    cleanup_task = None
    if account_crypto.enabled():
        cleanup_task = asyncio.create_task(account_cleanup_loop())
    try:
        yield
    finally:
        if cleanup_task:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass


async def account_cleanup_loop():
    import account_store
    while True:
        try:
            await run_in_threadpool(account_store.cleanup)
        except Exception as error:
            logger.error('account_cleanup_failed=%s', type(error).__name__)
        await asyncio.sleep(3600)

app = FastAPI(lifespan=lifespan)
app.include_router(account_router)
app.include_router(monitor_router)


@app.middleware("http")
async def protect_account_responses(request, call_next):
    private = request.url.path.startswith("/api/account/") or request.url.path.startswith("/account")
    try:
        response = await call_next(request)
    except Exception:
        if not private:
            raise
        response = JSONResponse({"detail": "Кабинет временно недоступен. Попробуйте позже"}, status_code=503)
    if private:
        from account_routes import HEADERS
        response.headers.update(HEADERS)
    return response

slots = threading.BoundedSemaphore(4)
guard = SubmissionGuard()


class Submission(BaseModel):
    model_config = ConfigDict(extra='ignore', str_strip_whitespace=True)
    Name: str = Field(default='', max_length=120)
    Email: EmailStr = Field(max_length=254)
    Phone: str = Field(default='', max_length=40)
    Username: str = Field(default='', max_length=65)

    @field_validator('Email')
    @classmethod
    def validate_mailbox(cls, value):
        return email_sender.mailbox(str(value))

    @field_validator('Phone')
    @classmethod
    def validate_phone(cls, value):
        return normalize_phone(value)

    @field_validator('Username')
    @classmethod
    def validate_username(cls, value):
        return normalize_username(value)


@app.get('/', response_class=PlainTextResponse)
def health():
    try:
        job_store.health()
    except Exception:
        raise HTTPException(503, 'Хранилище временно недоступно') from None
    return 'ok'


def require_team(request):
    key = os.getenv('STATUS_API_KEY', '')
    if not key:
        raise HTTPException(503, 'Доступ к статусам ещё не настроен')
    supplied = request.headers.get('authorization', '')
    if not secrets.compare_digest(supplied.encode(), ('Bearer ' + key).encode()):
        raise HTTPException(403, 'Доступ запрещён')


@app.get('/api/sources')
def source_registry(request: Request):
    require_team(request)
    from source_health import registry
    return JSONResponse(registry(), headers={'Cache-Control': 'no-store'})


@app.post('/api/sources/check')
def source_check(request: Request):
    require_team(request)
    from source_health import verify
    return JSONResponse(verify(), headers={'Cache-Control': 'no-store'})


@app.get('/api/jobs/{job_id}')
def job_status(job_id: str, request: Request):
    require_team(request)
    if not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise HTTPException(404, 'Задание не найдено')
    try:
        job = job_store.get(job_id)
    except Exception:
        raise HTTPException(503, 'Хранилище временно недоступно') from None
    if job is None:
        raise HTTPException(404, 'Задание не найдено')
    return JSONResponse(jsonable_encoder(job), headers={"Cache-Control": "no-store"})


@app.post('/webhook', response_class=PlainTextResponse)
@app.post('/', response_class=PlainTextResponse)
async def receive(request: Request):
    content_type = request.headers.get('content-type', '').split(';')[0].lower()
    if content_type not in ('application/x-www-form-urlencoded', 'multipart/form-data'):
        raise HTTPException(415, 'Ожидаются поля формы Name, Email, Phone, Username')
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 16384:
            raise HTTPException(413, 'Слишком большая заявка')
        body.extend(chunk)
    async def bounded_body():
        return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
    try:
        form = await Request(request.scope, bounded_body).form(max_files=0, max_fields=50)
    except Exception:
        raise HTTPException(400, 'Не удалось прочитать форму')
    webhook_secret = os.getenv('WEBHOOK_SECRET', '')
    if not webhook_secret:
        raise HTTPException(503, 'Защита формы ещё не настроена')
    supplied = request.headers.get('x-webhook-secret')
    if supplied is None:
        tokens = request.query_params.getlist('token')
        supplied = tokens[0] if len(tokens) == 1 else ''
    if not secrets.compare_digest(supplied.encode(), webhook_secret.encode()):
        raise HTTPException(403, 'Неверный ключ формы')
    # Authenticate the Tilda probe too; it must never start a job or consume quota.
    if list(form.multi_items()) == [('test', 'test')]:
        return PlainTextResponse('ok')
    try:
        submission = Submission.model_validate(dict(form))
    except ValidationError as error:
        details = [{'field': '.'.join(map(str, item['loc'])), 'message': item['msg']}
                   for item in error.errors()]
        raise HTTPException(422, details)
    return await start_submission(submission)


async def start_submission(submission):
    try:
        email_sender.validate_settings()
    except (ValueError, TypeError):
        raise HTTPException(503, 'Отправка почты ещё не настроена')
    try:
        job_id, duplicate = guard.reserve(str(submission.Email), submission.Phone, submission.Username)
    except Limited as limit:
        raise HTTPException(429, 'Лимит заявок. Повторите позже',
                            headers={'Retry-After': str(limit.retry_after)})
    if duplicate:
        return PlainTextResponse('ok', headers={'X-Request-ID': job_id, 'X-Duplicate': 'true'})
    if not slots.acquire(blocking=False):
        guard.cancel(job_id)
        raise HTTPException(503, 'Сервер занят. Повторите позже')
    accepted = False
    try:
        if account_crypto.enabled():
            await run_in_threadpool(job_store.record, job_id, 'accepted', str(submission.Email))
        else:
            await run_in_threadpool(job_store.record, job_id, 'accepted')
        accepted = True
        threading.Thread(target=background_task,
                         args=(submission, job_id), daemon=False).start()
    except Exception as error:
        if accepted:
            try:
                await run_in_threadpool(job_store.record, job_id, 'failed')
            except Exception:
                logger.error('job=%s status_store_failed', job_id)
        guard.cancel(job_id)
        slots.release()
        logger.error('job=%s stage=start failed=%s', job_id, type(error).__name__)
        raise HTTPException(503, 'Не удалось запустить обработку') from None
    logger.info('job=%s accepted', job_id)
    return PlainTextResponse('ok', headers={'X-Request-ID': job_id})


def background_task(submission, job_id):
    stage = 'search'
    pdf_path = None
    try:
        job_store.record(job_id, 'searching')
        import osint
        results = osint.search(email=str(submission.Email), phone=submission.Phone or None,
                               username=submission.Username or None)
        import analysis_layer, ai_summary
        results['analysis_selection'] = ai_summary.select(analysis_layer.analyze(results))
        if results.get('identity_resolution'):
            results['identity_resolution']['analysis_selection'] = results['analysis_selection']
        stage = 'pdf'
        job_store.record(job_id, 'generating_report')
        pdf_path = pdf_gen.create_report(results)
        if account_crypto.enabled():
            try:
                import account_store
                account_store.save_report(job_id, pdf_path, results.get('identity_resolution'))
            except Exception as error:
                logger.error('job=%s account_report_failed=%s', job_id, type(error).__name__)
        stage = 'mail'
        job_store.record(job_id, 'sending')
        email_sender.send_report(str(submission.Email), pdf_path)
        job_store.record(job_id, 'provider_accepted')
        logger.info('job=%s submitted_to_mail_provider', job_id)
    except Exception as error:
        try:
            job_store.record(job_id, 'delivery_unknown' if stage == 'mail' else 'failed')
        except Exception:
            logger.error('job=%s status_store_failed', job_id)
        # SMTP exceptions may contain addresses; do not log their message or traceback.
        logger.error('job=%s stage=%s failed=%s', job_id, stage, type(error).__name__)
    finally:
        if pdf_path:
            try:
                Path(pdf_path).unlink(missing_ok=True)
            except OSError:
                logger.error('job=%s report_cleanup_failed', job_id)
        guard.finish(job_id)
        slots.release()


@app.post('/api/account/jobs')
async def account_submit(request: Request):
    from account_routes import ready, origin, body, identify, result
    ready()
    origin(request)
    data = await body(request)
    user, _ = await run_in_threadpool(identify, request, True)
    if data.get('consent') is not True:
        raise HTTPException(422, 'Подтвердите согласие на проверку своих данных')
    try:
        submission = Submission(Email=user['email'], Phone=data.get('phone', ''), Username=data.get('username', ''))
    except (ValidationError, TypeError):
        raise HTTPException(422, 'Проверьте формат телефона и username') from None
    response = await start_submission(submission)
    return result(dict(job_id=response.headers['X-Request-ID'], duplicate=response.headers.get('X-Duplicate') == 'true'), 202)


def monitor_authorize(request):
    from monitor_routes import available
    token=os.getenv('MONITOR_RUNNER_TOKEN','')
    supplied=request.headers.get('authorization','')
    if not available() or not secrets.compare_digest(supplied,'Bearer '+token):
        raise HTTPException(403,'Forbidden')


@app.get('/api/internal/monitor/status')
async def monitor_status(request: Request):
    monitor_authorize(request)
    import monitor_store
    status=await run_in_threadpool(monitor_store.scheduler_status)
    return JSONResponse(jsonable_encoder(status),headers={'Cache-Control':'no-store'})


@app.post('/api/internal/monitor/tick')
async def monitor_tick(request: Request):
    monitor_authorize(request)
    from account_store import quota
    if not await run_in_threadpool(quota,[('monitor-runner:global','all',50)]):
        raise HTTPException(429,'Runner limit')
    if not slots.acquire(blocking=False):
        return JSONResponse({'operation':'busy'})
    try:
        from monitor_worker import tick
        outcome=await run_in_threadpool(tick)
        return JSONResponse(outcome,headers={'Cache-Control':'no-store'})
    finally:
        slots.release()


if __name__ == '__main__':
    uvicorn.run(app, host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '8000')),
                access_log=False, log_config=None)
