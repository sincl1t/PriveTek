"""Refresh public breach metadata without sending account identifiers."""
from datetime import datetime, timezone

import httpx
import psycopg

import job_store
from tools.breach_index import SOURCE, LICENSE, TTL, fetch, valid_name

MAX_NAMES = 3


def lookup(client, name):
    key = name.lower()
    with job_store.connect() as db:
        row = db.execute('''SELECT title,breach_date,refreshed_at FROM privetek_breach_catalogue
            WHERE name_key=%s AND refreshed_at > now()-%s''', (key, TTL)).fetchone()
    if row:
        return dict(status='available', title=row['title'], breach_date=row['breach_date'],
                    refreshed_at=row['refreshed_at'].isoformat())
    fresh = fetch(client, name)
    if fresh is None:
        with job_store.connect() as db:
            db.execute('DELETE FROM privetek_breach_catalogue WHERE name_key=%s AND refreshed_at <= now()-%s', (key, TTL))
        return dict(status='not_found')
    refreshed = datetime.now(timezone.utc)
    with job_store.connect() as db:
        db.execute('''INSERT INTO privetek_breach_catalogue (name_key,title,breach_date,refreshed_at)
            VALUES (%s,%s,%s,%s) ON CONFLICT (name_key) DO UPDATE SET title=excluded.title,
            breach_date=excluded.breach_date, refreshed_at=excluded.refreshed_at
            WHERE privetek_breach_catalogue.refreshed_at < excluded.refreshed_at''',
                   (key, fresh['title'], fresh['breach_date'], refreshed))
    return dict(status='available', title=fresh['title'], breach_date=fresh['breach_date'],
                refreshed_at=refreshed.isoformat())


def decorate(snapshot):
    with httpx.Client(timeout=2, follow_redirects=False,
                      headers={'User-Agent': 'PriveTek-Catalogue/1.0 (+https://privetek.ru/)'}) as client:
        for item in snapshot.get('findings', []):
            if item.get('source') != 'HIBP' or item.get('kind') != 'breach':
                continue
            names = [name for name in item.get('breach_names', []) if valid_name(name)]
            for name in names[:MAX_NAMES]:
                try:
                    result = lookup(client, name)
                except (httpx.HTTPError, ValueError, psycopg.Error, job_store.StoreNotConfigured):
                    result = dict(status='unavailable')
                item.setdefault('catalogue', []).append(dict(name=name, source='Have I Been Pwned',
                    source_url=SOURCE, license_url=LICENSE, **result))
            item['catalogue_omitted'] = max(0, len(names) - MAX_NAMES)
    return snapshot
