"""Opt-in public username search powered by Maigret."""
import asyncio
import json
import logging
import os
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException

import account_crypto
import job_store

SITES = ('Bluesky', 'OpenStreetMap', 'RubyGems')
logger = logging.getLogger('privetek.profile_search')
logger.propagate = False
logger.addHandler(logging.NullHandler())


def enabled():
    return os.getenv('PROFILE_SEARCH_ENABLED', '').lower() == 'true'


async def search(username):
    import maigret as package
    from maigret.checking import maigret
    from maigret.sites import MaigretDatabase

    db = MaigretDatabase()
    db.load_from_path(str(Path(package.__file__).parent / 'resources' / 'data.json'))
    rows = await maigret(username, {site: db.sites_dict[site] for site in SITES}, logger,
                         timeout=8, max_connections=3, no_progressbar=True, retries=0,
                         is_parsing_enabled=False, is_enrich_enabled=False, check_domains=False)
    output = []
    for site in SITES:
        result = rows.get(site) or {}
        status = result.get('status')
        name = status.status.name if status else None
        code = result.get('http_status')
        expected_url = db.sites_dict[site].url.format(username=username)
        found = name == 'CLAIMED' and code == 200 and result.get('url_user') == expected_url
        absent = name == 'AVAILABLE' and code == (400 if site == 'Bluesky' else 404)
        output.append(dict(site=site, status='found' if found else 'not_found' if absent else 'unavailable',
                           url=expected_url if found else None))
    return output


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
