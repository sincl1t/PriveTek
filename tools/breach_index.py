"""Local pilot for public Have I Been Pwned breach metadata."""
import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sqlite3
from time import perf_counter
from urllib.parse import quote

import httpx

SOURCE = 'https://haveibeenpwned.com/'
LICENSE = 'https://creativecommons.org/licenses/by/4.0/'
TTL = timedelta(hours=24)
SAMPLE = ('Adobe', 'Dropbox', 'LinkedIn')


def valid_name(name):
    return isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,99}', name) is not None


def fetch(client, name):
    url = SOURCE + 'api/v3/breach/' + quote(name, safe='')
    response = client.get(url)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    row = response.json()
    if not isinstance(row, dict) or not isinstance(row.get('Name'), str) or row['Name'].lower() != name.lower():
        raise ValueError('Unexpected record from the catalogue')
    if row.get('IsRetired') is True:
        return None
    if not isinstance(row.get('Title'), str) or not isinstance(row.get('BreachDate'), str):
        raise ValueError('Incomplete breach metadata')
    return {
        'name': row['Name'],
        'title': row['Title'],
        'breach_date': date.fromisoformat(row['BreachDate']).isoformat(),
    }


def lookup(db, client, name, now=None):
    if not valid_name(name):
        raise ValueError('Specify a catalogue Name, for example Adobe')
    now = now or datetime.now(timezone.utc)
    key = name.lower()
    started = perf_counter()
    db.execute('''CREATE TABLE IF NOT EXISTS public_breaches (
        name_key TEXT PRIMARY KEY, refreshed_at TEXT NOT NULL, metadata TEXT NOT NULL
    )''')
    cached = db.execute('SELECT refreshed_at, metadata FROM public_breaches WHERE name_key=?', (key,)).fetchone()
    age = now - datetime.fromisoformat(cached[0]) if cached else None
    origin = 'api'
    refreshed = None
    if age is not None and timedelta(0) <= age < TTL:
        origin = 'index'
        refreshed, payload = cached[0], json.loads(cached[1])
    else:
        payload = fetch(client, name)
        with db:
            if payload is None:
                db.execute('DELETE FROM public_breaches WHERE name_key=?', (key,))
            else:
                refreshed = now.isoformat()
                db.execute('''INSERT INTO public_breaches VALUES (?,?,?)
                    ON CONFLICT (name_key) DO UPDATE SET refreshed_at=excluded.refreshed_at,
                    metadata=excluded.metadata''', (key, refreshed, json.dumps(payload)))
    return {
        'source': 'Have I Been Pwned',
        'source_url': SOURCE,
        'license': LICENSE,
        'route': origin,
        'index_state': 'fresh' if origin == 'index' else 'expired' if cached else 'miss',
        'refreshed_at': refreshed,
        'elapsed_ms': round((perf_counter() - started) * 1000, 3),
        'breach': payload,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True, type=Path, help='Path to a local SQLite database')
    parser.add_argument('names', nargs='*', help='Exact catalogue names, defaults to three sample records')
    args = parser.parse_args()
    with sqlite3.connect(args.db) as db, httpx.Client(
        headers={'User-Agent': 'PriveTek-Catalogue-Pilot/1.0 (+https://privetek.ru/)'},
        timeout=10, follow_redirects=False,
    ) as client:
        for name in args.names or SAMPLE:
            try:
                print(json.dumps(lookup(db, client, name), ensure_ascii=False))
            except (httpx.HTTPError, ValueError) as error:
                parser.exit(1, f'Catalogue lookup failed: {type(error).__name__}\n')


if __name__ == '__main__':
    main()
