"""Exact public-account discovery, including username-to-ID resolution for SPAs.

Only fixed public read endpoints; no sign-in, recovery, arbitrary URLs or browser bypass.
"""
import json
import logging
import re
import threading
import time
from urllib.parse import quote
import httpx
import trio
from report_data import utc_now

SOURCES = [
    ('Roblox', 'https://www.roblox.com/', 'https://create.roblox.com/docs/cloud/reference/domains/users', 'builderman', r'[A-Za-z0-9_]{3,20}'),
    ('Scratch', 'https://scratch.mit.edu/', 'https://github.com/scratchfoundation/scratch-rest-api/wiki/Users', 'mres', r'[A-Za-z0-9_-]{3,20}'),
    ('Codewars', 'https://www.codewars.com/', 'https://dev.codewars.com/', 'g964', r'[A-Za-z0-9_.-]{1,64}'),
]
NEGATIVE = 'pvtkz8q4n2x7r9'
MAX_BYTES = 256 * 1024
_lock = threading.Lock()
_next_request = {}
_latest_probe = None


def reserve(name):
    with _lock:
        current = time.monotonic()
        if current < _next_request.get(name, 0):
            return False
        _next_request[name] = current + 1.0
        return True


def backoff(name, value):
    try:
        delay = max(60, min(3600, int(value)))
    except (TypeError, ValueError):
        delay = 60
    with _lock:
        _next_request[name] = max(_next_request.get(name, 0), time.monotonic() + delay)


def request_spec(name, username):
    handle = quote(username, safe='')
    if name == 'Roblox':
        return 'POST', 'https://users.roblox.com/v1/usernames/users', {'json': {'usernames': [username], 'excludeBannedUsers': False}}
    if name == 'Scratch':
        return 'GET', 'https://api.scratch.mit.edu/users/' + handle, {}
    if name == 'Codewars':
        return 'GET', 'https://www.codewars.com/api/v1/users/' + handle, {}
    raise ValueError('Unknown discovery source')


def classify(name, username, status, body):
    """Never classify a generic HTTP miss, challenge, fuzzy name or display name."""
    if not isinstance(body, dict):
        return 'unavailable', None
    if status == 404:
        if name == 'Scratch' and body.get('code') == 'NotFound':
            return 'not_found', None
        if name == 'Codewars' and body.get('success') is False and body.get('reason') == 'not found':
            return 'not_found', None
    if status != 200 or 'errors' in body or 'error' in body:
        return 'unavailable', None
    if name == 'Roblox':
        rows = body.get('data')
        if rows == []:
            return 'not_found', None
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            return 'unavailable', None
        row = rows[0]
        if not isinstance(row.get('requestedUsername'), str) or row['requestedUsername'].casefold() != username.casefold():
            return 'unavailable', None
        actual, account_id = row.get('name'), row.get('id')
        valid_id = type(account_id) is int and account_id > 0
        url = f'https://www.roblox.com/users/{account_id}/profile' if valid_id else None
    else:
        actual, account_id = body.get('username'), body.get('id')
        valid_id = (type(account_id) is int and account_id > 0) if name == 'Scratch' else isinstance(account_id, str) and bool(re.fullmatch(r'[0-9a-f]{24}', account_id))
        url = ('https://scratch.mit.edu/users/' + quote(actual, safe='') + '/' if name == 'Scratch' else 'https://www.codewars.com/users/' + quote(actual, safe='')) if isinstance(actual, str) else None
    if valid_id and isinstance(actual, str) and actual.casefold() == username.casefold():
        return 'found', url
    return 'unavailable', None


async def check(source, username, client):
    name, home, docs, fixture, pattern = source
    result = dict(source=name, kind='username', source_url=home, profile_url=None,
                  checked_at=None, status='unavailable', method='public_account_lookup',
                  reason='Источник не дал пригодного ответа; наличие аккаунта неизвестно.')
    if not isinstance(username, str) or not re.fullmatch(pattern, username):
        result.update(status='skipped', reason='Username не соответствует формату этого сайта.')
        return result
    if not reserve(name):
        result['reason'] = 'Локальный лимит или пауза источника; проверка не выполнена.'
        return result
    result['checked_at'] = utc_now()
    method, url, kwargs = request_spec(name, username)
    try:
        # Explicitly disable redirects, even when supplied client enables them.
        with trio.fail_after(15):
            async with client.stream(method, url, follow_redirects=False, **kwargs) as response:
                if response.status_code == 429:
                    backoff(name, response.headers.get('retry-after'))
                    result['reason'] = 'Источник ограничил запросы; повторная проверка временно приостановлена.'
                    return result
                if response.status_code not in (200, 404) or response.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                    return result
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_BYTES:
                        return result
                state, profile = classify(name, username, response.status_code, json.loads(content))
        result.update(status=state, profile_url=profile)
        if state == 'found':
            result['reason'] = 'Найден публичный аккаунт с точным username. Совпадение имени не подтверждает принадлежность человеку.'
        elif state == 'not_found':
            result['reason'] = 'Публичный метод источника не нашёл этот username. Это не исключает переименованный, скрытый или другой аккаунт.'
    except (httpx.HTTPError, ValueError, TypeError, KeyError, trio.TooSlowError):
        pass
    return result


async def run(username=None, fixtures=False):
    # Sequential, bounded work; no fan-out to unapproved hosts and no retries.
    async with httpx.AsyncClient(timeout=12, follow_redirects=False, headers={
        'User-Agent': 'PriveTek/3.0 (+https://github.com/sincl1t/PriveTek)', 'Accept': 'application/json'}) as client:
        return [await check(source, source[3] if fixtures else username, client) for source in SOURCES]


async def probe():
    positives = await run(fixtures=True)
    await trio.sleep(1.05)
    negatives = await run(NEGATIVE)
    rows = [dict(source=p['source'], positive_status=p['status'], negative_status=n['status'],
                 verified=p['status'] == 'found' and n['status'] == 'not_found') for p, n in zip(positives, negatives)]
    return dict(checked_at=utc_now(), sources=rows, verified_sources=sum(r['verified'] for r in rows), total_sources=len(SOURCES))


def startup_probe():
    """Six fixed public fixture queries per process start; no user input or stored payloads."""
    global _latest_probe
    try:
        outcome = trio.run(probe)
        with _lock:
            _latest_probe = outcome
        logging.getLogger('privetek').info('discovery_probe=%s', json.dumps(outcome, separators=(',', ':')))
    except Exception as error:
        logging.getLogger('privetek').warning('discovery_probe_failed=%s', type(error).__name__)


def latest_probe():
    with _lock:
        return json.loads(json.dumps(_latest_probe))
