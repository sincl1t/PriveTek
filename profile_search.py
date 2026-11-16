"""Opt-in public username search from PriveTek and Maigret."""
import asyncio
import json
import logging
import os
import re
from uuid import uuid4

from bs4 import BeautifulSoup
import httpx
import trio
from fastapi import HTTPException

import account_crypto
import discovery
import job_store
import public_sources

EXTRA_SOURCES = (
    ('Bluesky', 'https://bsky.app/profile/{username}.bsky.social', r'[A-Za-z0-9][A-Za-z0-9-]{0,62}'),
    ('OpenStreetMap', 'https://www.openstreetmap.org/user/{username}', r'[A-Za-z0-9_][A-Za-z0-9_-]{0,63}'),
    ('RubyGems', 'https://rubygems.org/profiles/{username}', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}'),
)
logger = logging.getLogger('privetek.profile_search')


def enabled():
    return os.getenv('PROFILE_SEARCH_ENABLED', '').lower() == 'true'


async def public_page(site, username, client):
    name, template, pattern = site
    if not re.fullmatch(pattern, username) or (name == 'GitHub' and '--' in username):
        return dict(status='skipped')
    url = template.format(username=username)
    try:
        if name == 'Bluesky':
            handle = username.lower() + '.bsky.social'
            response = await client.get('https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile',
                                        params={'actor': handle})
            if response.status_code in (200, 400):
                data = response.json()
                if isinstance(data, dict):
                    if response.status_code == 200 and data.get('handle') == handle and data.get('did'):
                        return dict(status='found', profile_url='https://bsky.app/profile/' + handle)
                    if response.status_code == 400 and data.get('error') == 'InvalidRequest' and data.get('message') == 'Profile not found':
                        return dict(status='not_found')
        else:
            response = await client.get(url)
            if response.status_code == 404:
                return dict(status='not_found')
            if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                page = BeautifulSoup(response.content, 'html.parser')
                title = page.title.get_text(strip=True) if page.title else ''
                if name == 'GitHub':
                    login = page.find('meta', attrs={'name': 'octolytics-dimension-user_login'})
                    canonical = page.find('meta', property='og:url')
                    if login and canonical and login.get('content', '').casefold() == username.casefold():
                        href = 'https://github.com/' + login['content']
                        if canonical.get('content') == href:
                            return dict(status='found', profile_url=href)
                elif name == 'OpenStreetMap' and title == username + ' | OpenStreetMap':
                    return dict(status='found', profile_url=url)
                elif name == 'RubyGems' and title.split(' | ', 1)[0].casefold() == ('Profile of ' + username).casefold():
                    return dict(status='found', profile_url=url)
        logger.info('profile_source_unavailable source=%s http=%s', name, response.status_code)
    except (httpx.HTTPError, ValueError) as error:
        logger.info('profile_source_unavailable source=%s reason=%s', name, type(error).__name__)
    return dict(status='unavailable')


async def search_sources(username):
    checks = []
    for source in public_sources.SOURCES:
        if source[0] == 'GitHub':
            checks.append((('GitHub', 'https://github.com/{username}', source[-1]), public_page))
        else:
            checks.append((source, public_sources.check_profile))
    checks.extend((source, discovery.check) for source in discovery.SOURCES)
    checks.extend((source, public_page) for source in EXTRA_SOURCES)
    results = [dict(site=source[0], status='unavailable', url=None) for source, _ in checks]
    limiter = trio.CapacityLimiter(5)

    async with httpx.AsyncClient(timeout=6, follow_redirects=False, headers={
        'User-Agent': public_sources.USER_AGENT, 'Accept': 'application/json, text/html'
    }) as client:
        async def run_one(index, source, adapter):
            async with limiter:
                try:
                    row = await adapter(source, username, client)
                    status = row['status']
                    results[index] = dict(site=source[0], status=status,
                                          url=row.get('profile_url') if status == 'found' else None)
                except Exception as error:
                    logger.info('profile_source_unavailable source=%s reason=%s', source[0], type(error).__name__)

        with trio.move_on_after(20):
            async with trio.open_nursery() as nursery:
                for index, (source, adapter) in enumerate(checks):
                    nursery.start_soon(run_one, index, source, adapter)
    return results


async def search(username):
    return await asyncio.to_thread(trio.run, search_sources, username)


def state(user_id):
    with job_store.connect() as db:
        row = db.execute('''SELECT free_used, access_until > now() AS subscribed,
            lease_until > now() AS busy, CASE WHEN result_until > now() THEN ciphertext END AS result
            FROM privetek_profile_search WHERE user_id=%s''', (user_id,)).fetchone()
    if not row:
        return dict(free_available=True, subscribed=False, busy=False, results=[])
    return dict(free_available=not row['free_used'], subscribed=bool(row['subscribed']), busy=bool(row['busy']),
                results=json.loads(account_crypto.report_cipher().decrypt(bytes(row['result']))) if row['result'] else [])


def submit(user_id, username):
    token = uuid4().hex
    with job_store.connect() as db:
        db.execute('INSERT INTO privetek_profile_search(user_id) VALUES (%s) ON CONFLICT DO NOTHING', (user_id,))
        row = db.execute('''SELECT free_used, access_until > now() AS subscribed, lease_until > now() AS busy
            FROM privetek_profile_search WHERE user_id=%s FOR UPDATE''', (user_id,)).fetchone()
        if row['busy']:
            raise HTTPException(409, 'Один поиск уже выполняется.')
        if row['free_used'] and not row['subscribed']:
            raise HTTPException(402, 'Бесплатный запрос уже использован. Для новых запросов нужна подписка.')
        db.execute("UPDATE privetek_profile_search SET lease_token=%s, lease_until=now()+interval '60 seconds' WHERE user_id=%s",
                   (token, user_id))
    payload = None
    try:
        results = asyncio.run(asyncio.wait_for(search(username), timeout=25))
        if not any(item['status'] in ('found', 'not_found') for item in results):
            raise HTTPException(503, 'Источники не дали ответа. Можно попробовать снова.')
        payload = account_crypto.report_cipher().encrypt(json.dumps(results, ensure_ascii=False).encode())
    finally:
        with job_store.connect() as db:
            if payload is None:
                db.execute('UPDATE privetek_profile_search SET lease_token=NULL,lease_until=NULL WHERE user_id=%s AND lease_token=%s',
                           (user_id, token))
            else:
                saved = db.execute('''UPDATE privetek_profile_search SET free_used=true, lease_token=NULL,
                    lease_until=NULL, ciphertext=%s, result_until=now()+interval '24 hours'
                    WHERE user_id=%s AND lease_token=%s AND lease_until>now() RETURNING user_id''',
                                   (payload, user_id, token)).fetchone()
                if not saved:
                    raise HTTPException(409, 'Срок запроса истёк. Попробуйте снова.')
    return state(user_id)


def grant_retest_access():
    target = os.getenv('PROFILE_SEARCH_RETEST_ACCOUNT_SHA256', '')
    if not enabled() or not re.fullmatch(r'[a-f0-9]{64}', target):
        return
    try:
        with job_store.connect() as db:
            rows = db.execute("""
                UPDATE privetek_profile_search p SET access_until=now()+interval '20 minutes'
                FROM privetek_users u
                WHERE u.id=p.user_id AND u.verified_at IS NOT NULL AND p.free_used
                  AND encode(sha256(convert_to(u.email, 'UTF8')), 'hex')=%s
                  AND p.access_until < now()
                  AND p.access_until < TIMESTAMPTZ '2026-11-16 15:20:00+00'
                RETURNING p.user_id
            """, (target,)).fetchall()
            if len(rows) > 1:
                raise ValueError('Ambiguous retest account')
        logger.info('profile_search_retest_granted=%d', len(rows))
    except Exception as error:
        logger.error('profile_search_retest_failed=%s', type(error).__name__)
