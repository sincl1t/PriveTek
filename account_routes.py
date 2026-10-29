"""Same-origin account API. Never accepts caller-supplied job owners or file paths."""
import json
import os
import re
import secrets
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.encoders import jsonable_encoder
from starlette.concurrency import run_in_threadpool
import account_crypto as crypto
import account_store as store
import email_sender

router = APIRouter()
COOKIE = '__Host-privetek_session'
ASSETS = Path(__file__).parent / 'account_ui'
HEADERS = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
           'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
           'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"}


def ready():
    if not crypto.enabled():
        raise HTTPException(404, 'Личный кабинет пока не подключён')
    try:
        crypto.validate_settings()
    except Exception:
        raise HTTPException(503, 'Личный кабинет ещё не настроен') from None


def origin(request):
    if request.headers.get('origin') != os.getenv('ACCOUNT_ORIGIN') or request.headers.get('sec-fetch-site') == 'cross-site':
        raise HTTPException(403, 'Откройте личный кабинет на сайте PriveTek')


def result(data, status=200):
    return JSONResponse(jsonable_encoder(data), status_code=status, headers=HEADERS)


async def body(request):
    if request.headers.get('content-type', '').split(';')[0] != 'application/json':
        raise HTTPException(415, 'Ожидается JSON')
    content = bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content) > 4096:
            raise HTTPException(413, 'Слишком большой запрос')
    try:
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise HTTPException(400, 'Не удалось прочитать запрос') from None


def address(data):
    try:
        value = data.get('email')
        if not isinstance(value, str) or len(value) > 254:
            raise ValueError()
        return email_sender.mailbox(value.strip()).casefold()
    except Exception:
        raise HTTPException(422, 'Введите корректный email') from None


def quota(request, email, action, per_email=5):
    # Never trust client-supplied X-Forwarded-For. Configure trusted proxy at uvicorn.
    ip = request.client.host if request.client else 'unknown'
    if not store.quota([(action + ':email', email, per_email),
                        (action + ':ip', ip, 30), ('account:global', 'all', 300)]):
        raise HTTPException(429, 'Слишком много попыток. Повторите через час', headers={'Retry-After': '3600'})


def issue(data, request, purpose):
    email = address(data)
    quota(request, email, 'code', 3)
    pending_hash = None
    if purpose == 'register':
        try:
            pending_hash = crypto.password_hash(data.get('password'))
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
    email_sender.validate_settings()
    challenge = secrets.token_hex(24)
    code = ''.join(secrets.choice('0123456789') for _ in range(8))
    if store.put_code(challenge, email, purpose, crypto.digest('code', challenge + ':' + code), pending_hash):
        try:
            email_sender.send_account_code(email, code, purpose)
        except Exception:
            store.cancel_code(challenge)
            raise HTTPException(503, 'Не удалось отправить код. Попробуйте позже') from None
    # Uniform HTTP response even when the account exists / does not exist.
    return result(dict(challenge_id=challenge, expires_in=600,
                       message='Если действие доступно для этого адреса, код придёт на почту. Проверьте также папку «Спам».'))


def identify(request, mutation=False):
    token = request.cookies.get(COOKIE, '')
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
        raise HTTPException(401, 'Войдите в личный кабинет')
    user = store.session(crypto.digest('session', token))
    if not user:
        raise HTTPException(401, 'Сессия завершилась. Войдите снова')
    if mutation:
        supplied = request.headers.get('x-csrf-token', '')
        if not secrets.compare_digest(supplied.encode(), crypto.digest('csrf', token).encode()):
            raise HTTPException(403, 'Обновите страницу и повторите действие')
    return user, token


def session_response(request, token):
    previous = request.cookies.get(COOKIE)
    if previous:
        store.logout(crypto.digest('session', previous))
    response = result(dict(message='Вы вошли'))
    response.set_cookie(COOKIE, token, max_age=7 * 86400, secure=True, httponly=True, samesite='strict', path='/')
    return response


def action(data, request, name):
    ready()
    store.cleanup()
    if name in ('register', 'forgot-password'):
        return issue(data, request, 'register' if name == 'register' else 'reset')
    if name in ('verify', 'reset-password'):
        challenge, code = data.get('challenge_id', ''), data.get('code', '')
        if not isinstance(challenge, str) or not re.fullmatch(r'[0-9a-f]{48}', challenge) or not isinstance(code, str) or not re.fullmatch(r'[0-9]{8}', code):
            raise HTTPException(422, 'Введите восьмизначный код из письма')
        # In addition to the persistent five-attempt challenge bound, cap verification work.
        quota(request, challenge, 'verify', 10)
        new_hash = None
        if name == 'reset-password':
            try:
                new_hash = crypto.password_hash(data.get('password'))
            except ValueError as error:
                raise HTTPException(422, str(error)) from None
        if not store.redeem(challenge, crypto.digest('code', challenge + ':' + code),
                            'register' if name == 'verify' else 'reset', new_hash):
            raise HTTPException(400, 'Код неверен, истёк или уже использован. Запросите новый')
        return result(dict(message='Email подтверждён. Теперь можно войти.' if name == 'verify' else 'Пароль изменён. Войдите с новым паролем.'))
    if name == 'login':
        email = address(data)
        quota(request, email, 'login', 10)
        password = data.get('password')
        if not isinstance(password, str) or not 1 <= len(password) <= 128:
            raise HTTPException(401, 'Неверный email или пароль')
        token = secrets.token_urlsafe(32)
        outcome = store.login(email, password, crypto.digest('session', token))
        if not outcome:
            raise HTTPException(401, 'Неверный email или пароль; email должен быть подтверждён')
        if isinstance(outcome, str):
            return result(dict(mfa_required=True, challenge_id=outcome, expires_in=300))
        return session_response(request, token)
    if name == 'mfa-verify':
        import account_mfa
        challenge, code = data.get('challenge_id'), data.get('code')
        if not isinstance(challenge, str) or not re.fullmatch(r'[0-9a-f]{48}', challenge) or not isinstance(code, str) or len(code) > 64:
            raise HTTPException(422, 'Введите код приложения или резервный код')
        quota(request, challenge, 'mfa-login', 10)
        token = secrets.token_urlsafe(32)
        if not account_mfa.finish_login(challenge, code.strip(), crypto.digest('session', token)):
            raise HTTPException(400, 'Код неверен, уже использован или вход истёк. Для нового кода дождитесь его смены в приложении')
        return session_response(request, token)
    if name == 'logout':
        _, token = identify(request, mutation=True)
        store.logout(crypto.digest('session', token))
        response = result(dict(message='Вы вышли'))
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite='strict', path='/')
        return response
    raise HTTPException(404, 'Действие не найдено')


@router.post('/api/account/auth/{name}')
async def auth(name: str, request: Request):
    ready()
    origin(request)
    data = await body(request)
    try:
        return await run_in_threadpool(action, data, request, name)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, 'Сервис временно недоступен. Попробуйте позже') from None


@router.get('/api/account/me')
def me(request: Request):
    ready()
    user, token = identify(request)
    return result(dict(email=user['email'], csrf_token=crypto.digest('csrf', token)))


@router.get('/api/account/security')
def security_status(request: Request):
    import account_mfa
    ready()
    user, _ = identify(request)
    return result(account_mfa.status(user['id']))


def security_action(data, request, name):
    import account_mfa
    ready()
    user, token = identify(request, mutation=True)
    quota(request, user['email'], 'mfa-manage', 10)
    session_hash = crypto.digest('session', token)
    if name == 'setup':
        secret = account_mfa.setup(user['id'], data.get('password'), session_hash)
        if secret is None:
            raise HTTPException(400, 'Проверьте пароль; 2FA уже может быть включена')
        import base64
        import pyotp
        import qrcode
        import qrcode.image.svg
        uri = pyotp.TOTP(secret).provisioning_uri(name=user['email'], issuer_name='PriveTek')
        qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathFillImage).to_string()
        return result(dict(secret=secret, qr_data='data:image/svg+xml;base64,' + base64.b64encode(qr).decode(), expires_in=600))
    code = data.get('code')
    if not isinstance(code, str) or len(code) > 64:
        raise HTTPException(422, 'Введите код подтверждения')
    if name == 'confirm':
        codes = account_mfa.confirm(user['id'], session_hash, code.strip())
    elif name in ('disable', 'recovery'):
        codes = account_mfa.manage(user['id'], data.get('password'), code.strip(), session_hash, disable=name == 'disable')
    else:
        raise HTTPException(404, 'Действие не найдено')
    if codes is None:
        raise HTTPException(400, 'Проверьте пароль и новый код приложения или неиспользованный резервный код')
    return result(dict(enabled=name != 'disable', recovery_codes=codes))


@router.post('/api/account/security/{name}')
async def security_change(name: str, request: Request):
    ready()
    origin(request)
    data = await body(request)
    try:
        return await run_in_threadpool(security_action, data, request, name)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, 'Не удалось изменить настройки защиты. Попробуйте позже') from None


@router.get('/api/account/jobs')
def jobs(request: Request, offset: int = 0):
    ready()
    user, _ = identify(request)
    if not 0 <= offset <= 10000:
        raise HTTPException(422, 'Неверная страница')
    return result(store.list_jobs(user['email_key'], offset=offset))


@router.get('/api/account/jobs/{job_id}/report')
def download(job_id: str, request: Request):
    ready()
    user, _ = identify(request)
    if not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise HTTPException(404, 'Отчёт не найден')
    content = store.report(user['email_key'], job_id)
    if content is None:
        raise HTTPException(404, 'Отчёт не найден или срок хранения истёк')
    return Response(content, media_type='application/pdf', headers={**HEADERS,
                    'Content-Disposition': 'attachment; filename="PriveTek-report.pdf"'})


@router.delete('/api/account/jobs/{job_id}/report')
def remove_report(job_id: str, request: Request):
    ready()
    origin(request)
    user, _ = identify(request, mutation=True)
    if not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise HTTPException(404, 'Отчёт не найден')
    store.delete_report(user['email_key'], job_id)
    return result(dict(message='Копия отчёта удалена из кабинета'))


@router.get('/account', include_in_schema=False)
def page():
    if not crypto.enabled():
        raise HTTPException(404, 'Личный кабинет пока не подключён')
    return FileResponse(ASSETS / 'index.html', headers=HEADERS)


@router.get('/account/assets/{name}', include_in_schema=False)
def asset(name: str):
    allowed = {'account.css': 'text/css', 'account.js': 'application/javascript',
               'brand-logo.png': 'image/png', 'brand-background.jpg': 'image/jpeg',
               'tildasans.woff2': 'font/woff2'}
    if name not in allowed:
        raise HTTPException(404)
    return FileResponse(ASSETS / name, media_type=allowed[name], headers=HEADERS)


def identity_job(job_id):
    if not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise HTTPException(404, 'Карточка не найдена')


@router.get('/api/account/jobs/{job_id}/identity')
def identity_read(job_id: str, request: Request):
    ready()
    user, _ = identify(request)
    identity_job(job_id)
    snapshot = store.identity_snapshot(user['email_key'], job_id)
    if snapshot is None:
        raise HTTPException(404, 'Карточка недоступна: старая проверка, истёк срок или отчёт удалён')
    return result(snapshot)


def identity_update(data, request, job_id):
    user, _ = identify(request, mutation=True)
    identity_job(job_id)
    revision, item_id, decision = data.get('revision'), data.get('item_id'), data.get('decision')
    from identity_resolution import DECISIONS
    if type(revision) is not int or revision < 1 or not isinstance(item_id, str) or len(item_id) > 64 or not isinstance(decision, str) or decision not in DECISIONS:
        raise HTTPException(422, 'Неверная отметка или версия карточки')
    quota(request, user['email'], 'identity-review', 100)
    try:
        snapshot = store.identity_decision(user['email_key'], job_id, revision, item_id, decision)
    except ValueError:
        raise HTTPException(422, 'Находка не относится к этой карточке') from None
    except RuntimeError:
        raise HTTPException(409, 'Карточка изменена в другой вкладке. Откройте её снова') from None
    if snapshot is None:
        raise HTTPException(404, 'Карточка не найдена')
    return result(snapshot)


@router.put('/api/account/jobs/{job_id}/identity')
async def identity_write(job_id: str, request: Request):
    ready()
    origin(request)
    data = await body(request)
    try:
        return await run_in_threadpool(identity_update, data, request, job_id)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, 'Не удалось сохранить отметку. Попробуйте позже') from None


@router.get('/api/account/jobs/{job_id}/identity/report')
def identity_pdf(job_id: str, request: Request):
    ready()
    user, _ = identify(request)
    identity_job(job_id)
    snapshot = store.identity_snapshot(user['email_key'], job_id)
    if snapshot is None:
        raise HTTPException(404, 'Карточка не найдена')
    quota(request, user['email'], 'identity-pdf', 10)
    import tempfile
    import pdf_gen
    with tempfile.TemporaryDirectory(prefix='privetek-identity-') as directory:
        path = pdf_gen.create_report({'identity_resolution': snapshot, 'identity_only': True}, directory)
        content = Path(path).read_bytes()
    return Response(content, media_type='application/pdf', headers={**HEADERS,
        'Content-Disposition': 'attachment; filename="PriveTek-identity.pdf"'})
