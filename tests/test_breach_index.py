import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from tools.breach_index import lookup, TTL


def test_cold_warm_expired_and_removed():
    start = datetime(2026, 11, 15, tzinfo=timezone.utc)
    replies = iter([
        httpx.Response(200, json={'Name':'Adobe', 'Title':'Adobe', 'BreachDate':'2013-10-04', 'Description':'Excluded'}),
        httpx.Response(200, json={'Name':'Adobe', 'Title':'Updated Adobe', 'BreachDate':'2013-10-04'}),
        httpx.Response(404),
    ])
    calls = []

    def send(request):
        calls.append(request.url.path)
        return next(replies)

    with sqlite3.connect(':memory:') as db, httpx.Client(transport=httpx.MockTransport(send)) as client:
        cold = lookup(db, client, 'Adobe', now=start)
        warm = lookup(db, client, 'adobe', now=start + timedelta(hours=1))
        assert cold['route'] == 'api' and warm['route'] == 'index'
        assert warm['breach'] == cold['breach'] and set(warm['breach']) == {'name', 'title', 'breach_date'}
        assert warm['refreshed_at'] == cold['refreshed_at'] and len(calls) == 1
        refreshed = lookup(db, client, 'Adobe', now=start + TTL)
        assert refreshed['index_state'] == 'expired' and refreshed['breach']['title'] == 'Updated Adobe'
        gone = lookup(db, client, 'Adobe', now=start + 2 * TTL)
        assert gone['breach'] is None and len(calls) == 3
        assert db.execute('SELECT count(*) FROM public_breaches').fetchone() == (0,)


def test_error_or_personal_identifier_does_not_create_record():
    with sqlite3.connect(':memory:') as db, httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(429)),
    ) as client:
        with pytest.raises(ValueError):
            lookup(db, client, 'someone@example.com')
        with pytest.raises(httpx.HTTPStatusError):
            lookup(db, client, 'Adobe')
        assert db.execute('SELECT count(*) FROM public_breaches').fetchone() == (0,)
