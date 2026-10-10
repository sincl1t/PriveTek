"""Tilda webhook. Run one worker; background jobs are not a durable queue."""
import logging
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
from submission_guard import SubmissionGuard, Limited
from privacy_logging import configure_logging

load_dotenv(Path(__file__).resolve().parent / '.env')
configure_logging()
logger = logging.getLogger('privetek')
@asynccontextmanager
async def lifespan(app):
    await run_in_threadpool(job_store.initialize)
    yield

app = FastAPI(lifespan=lifespan)
slots = threading.BoundedSemaphore(4)
guard = SubmissionGuard()


class Submission(BaseModel):
    model_config = ConfigDict(extra='ignore', str_strip_whitespace=True)
    Name: str = Field(default='', max_length=120)
    Email: EmailStr = Field(max_length=254)
    Phone: str = Field(default='', max_length=40)
    Username: str = Field(default='', max_length=40)

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


@app.get('/api/jobs/{job_id}')
def job_status(job_id: str, request: Request):
    key = os.getenv('STATUS_API_KEY', '')
    if not key:
        raise HTTPException(503, 'Доступ к статусам ещё не настроен')
    supplied = request.headers.get('authorization', '')
    if not secrets.compare_digest(supplied.encode(), ('Bearer ' + key).encode()):
        raise HTTPException(403, 'Доступ запрещён')
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
        stage = 'pdf'
        job_store.record(job_id, 'generating_report')
        pdf_path = pdf_gen.create_report(results)
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


if __name__ == '__main__':
    uvicorn.run(app, host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '8000')),
                access_log=False, log_config=None)
