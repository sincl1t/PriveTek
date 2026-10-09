"""Tilda webhook. Run one worker; background jobs are not a durable queue."""
import logging
import os
import re
import threading
from pathlib import Path

import phonenumbers
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError, field_validator

import email_sender
import pdf_gen
from submission_guard import SubmissionGuard, Limited

load_dotenv(Path(__file__).resolve().parent / '.env')
logger = logging.getLogger('privetek')
app = FastAPI()
slots = threading.BoundedSemaphore(4)
guard = SubmissionGuard()


class Submission(BaseModel):
    model_config = ConfigDict(extra='ignore', str_strip_whitespace=True)
    Name: str = Field(default='', max_length=120)
    Email: EmailStr = Field(max_length=254)
    Phone: str = Field(default='', max_length=40)

    @field_validator('Email')
    @classmethod
    def validate_mailbox(cls, value):
        return email_sender.mailbox(str(value))

    @field_validator('Phone')
    @classmethod
    def validate_phone(cls, value):
        if not value:
            return ''
        if not re.fullmatch(r'\+[0-9\s().-]+', value):
            raise ValueError('Телефон укажите с кодом страны, например +7 или +36')
        try:
            number = phonenumbers.parse(value, None)
        except phonenumbers.NumberParseException:
            raise ValueError('Не удалось распознать телефон')
        if not phonenumbers.is_possible_number(number):
            raise ValueError('Неверная длина или код страны телефона')
        return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


@app.get('/', response_class=PlainTextResponse)
def health():
    return 'ok'


@app.post('/', response_class=PlainTextResponse)
async def receive(request: Request):
    content_type = request.headers.get('content-type', '').split(';')[0].lower()
    if content_type not in ('application/x-www-form-urlencoded', 'multipart/form-data'):
        raise HTTPException(415, 'Ожидаются поля формы Name, Email, Phone')
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
    # Tilda validates a new webhook with POST test=test (no personal data).
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
        job_id, duplicate = guard.reserve(str(submission.Email), submission.Phone)
    except Limited as limit:
        raise HTTPException(429, 'Лимит заявок. Повторите позже',
                            headers={'Retry-After': str(limit.retry_after)})
    if duplicate:
        return PlainTextResponse('ok', headers={'X-Request-ID': job_id, 'X-Duplicate': 'true'})
    if not slots.acquire(blocking=False):
        guard.cancel(job_id)
        raise HTTPException(503, 'Сервер занят. Повторите позже')
    try:
        threading.Thread(target=background_task,
                         args=(submission, job_id), daemon=False).start()
    except Exception:
        guard.cancel(job_id)
        slots.release()
        raise HTTPException(503, 'Не удалось запустить обработку')
    logger.info('job=%s accepted', job_id)
    return PlainTextResponse('ok', headers={'X-Request-ID': job_id})


def background_task(submission, job_id):
    stage = 'search'
    try:
        import osint
        results = osint.search(email=str(submission.Email), phone=submission.Phone or None)
        stage = 'pdf'
        pdf_path = pdf_gen.create_report(results)
        stage = 'mail'
        email_sender.send_report(str(submission.Email), pdf_path)
        logger.info('job=%s submitted_to_mail_provider', job_id)
    except Exception as error:
        # SMTP exceptions may contain addresses; do not log their message or traceback.
        logger.error('job=%s stage=%s failed=%s', job_id, stage, type(error).__name__)
    finally:
        guard.finish(job_id)
        slots.release()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    uvicorn.run(app, host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '8000')))
