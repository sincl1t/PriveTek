"""Isolated PostgreSQL validation. The load test uses synthetic orders and mail."""
import multiprocessing
import os
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import httpx
import pytest

import job_store
import osint
import search_queue
import search_worker
import server
import source_limits
from test_accounts import db, settings  # noqa: F401


@pytest.fixture
def queue(db, monkeypatch):
    if os.getenv('ACCOUNTS_NATIVE_POSTGRES_TESTS') != '1':
        pytest.skip('Requires disposable native PostgreSQL for concurrent sessions')
    monkeypatch.setenv('SEARCH_QUEUE_ENABLED', 'true')
    with job_store.connect() as conn:
        conn.execute('TRUNCATE privetek_source_limits')
    return db


def order(number):
    return server.Submission(Email=f'test{number}@example.com', Phone='+12025550123', Username='synthetic')


def test_atomic_admission_and_recovery(queue):
    with ThreadPoolExecutor(8) as pool:
        barrier = Barrier(8)

        def enqueue(_):
            barrier.wait()
            return search_queue.enqueue(order(1), ['synthetic'])

        admitted = list(pool.map(enqueue, range(8)))
    assert len({job_id for job_id, _ in admitted}) == 1
    assert sum(not duplicate for _, duplicate in admitted) == 1
    first = search_queue.claim()
    assert job_store.get(first['job_id'])['status'] == 'accepted'
    assert b'test1@example.com' not in bytes(first['payload'])
    assert search_queue.claim() is None
    with job_store.connect() as conn:
        conn.execute("UPDATE privetek_search_queue SET lease_until=clock_timestamp()-interval '1 second'")
    second = search_queue.claim()
    assert second['job_id'] == first['job_id']
    with pytest.raises(search_queue.LeaseLost):
        search_queue.record(first['job_id'], first['lease_token'], 'sending')
    search_queue.record(second['job_id'], second['lease_token'], 'sending')
    with job_store.connect() as conn:
        conn.execute("UPDATE privetek_search_queue SET lease_until=clock_timestamp()-interval '1 second'")
    assert search_queue.claim() is None
    assert job_store.get(first['job_id'])['status'] == 'delivery_unknown'
    with job_store.connect() as conn:
        assert conn.execute('SELECT payload FROM privetek_search_queue').fetchone()['payload'] is None


def test_cross_worker_source_budget(queue):
    with ThreadPoolExecutor(16) as pool:
        barrier = Barrier(16)

        def acquire(_):
            barrier.wait()
            return source_limits.try_acquire('github.com')

        batch = list(pool.map(acquire, range(16)))
    assert sum(batch) == 1
    assert source_limits.try_acquire('gitlab.com')
    with pytest.raises(httpx.RequestError, match='not registered'):
        source_limits.wait_for_slot(httpx.URL('https://example.invalid/'))
    time.sleep(source_limits.INTERVAL)
    assert source_limits.try_acquire('github.com')


def drain_queue(_):
    handled = 0
    while search_worker.run_one():
        handled += 1
    return handled


def test_parallel_worker_load(queue, monkeypatch, tmp_path, capsys):
    count = 1000
    deliveries = tmp_path / 'mail'
    deliveries.mkdir()
    # Simulate data sources, disk rendering, and the mail provider without traffic.
    monkeypatch.setattr(osint, 'search', lambda **_: {'checks': []})
    def create_report(_):
        pdf = tmp_path / (uuid4().hex + '.pdf')
        pdf.write_bytes(b'%PDF-synthetic')
        return pdf

    monkeypatch.setattr(server.pdf_gen, 'create_report', create_report)
    def deliver(email, _):
        # Exclusive creation makes duplicate sends visible across processes.
        (deliveries / email).touch(exist_ok=False)

    monkeypatch.setattr(server.email_sender, 'send_report', deliver)

    started = time.monotonic()
    with ThreadPoolExecutor(12) as pool:
        accepted = list(pool.map(lambda n: search_queue.enqueue(order(n), ['synthetic'], hourly_limit=count), range(count)))
    admitted_seconds = time.monotonic() - started
    assert len(set(accepted)) == count and all(not duplicate for _, duplicate in accepted)

    started = time.monotonic()
    # Each worker holds its own database sessions and inherits the synthetic adapters.
    with ProcessPoolExecutor(8, mp_context=multiprocessing.get_context('fork')) as pool:
        handled = list(pool.map(drain_queue, range(8)))
    drained_seconds = time.monotonic() - started

    assert sum(handled) == count and sum(n > 0 for n in handled) > 1
    assert len(list(deliveries.iterdir())) == count
    with job_store.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM privetek_jobs WHERE status='provider_accepted'").fetchone()['n'] == count
        assert conn.execute('SELECT count(*) AS n FROM privetek_search_queue WHERE payload IS NOT NULL').fetchone()['n'] == 0
    with capsys.disabled():
        print(f'Queue load: {count} orders; 12 producers {admitted_seconds:.2f}s; 8 consumers {drained_seconds:.2f}s; per-consumer={handled}; duplicates=0; outstanding=0')


def test_chat_uses_shared_source_pacing(monkeypatch):
    import profile_search
    import trio

    monkeypatch.setenv('SEARCH_QUEUE_ENABLED', 'true')
    monkeypatch.setattr(profile_search.public_sources, 'SOURCES', [])
    monkeypatch.setattr(profile_search.discovery, 'SOURCES', [])
    monkeypatch.setattr(profile_search, 'EXTRA_SOURCES', profile_search.EXTRA_SOURCES[:1])
    acquired = []
    monkeypatch.setattr(source_limits, 'wait_for_slot', lambda url: acquired.append(url.host))
    real_client = httpx.AsyncClient
    monkeypatch.setattr(profile_search.httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(lambda request: httpx.Response(
            400, json={'error': 'InvalidRequest', 'message': 'Profile not found'})),
        **kwargs))
    result = trio.run(profile_search.search_sources, 'synthetic')
    assert result[0]['status'] == 'not_found'
    assert acquired == ['public.api.bsky.app']


@pytest.mark.parametrize('host', ['public.api.bsky.app', 'www.openstreetmap.org', 'rubygems.org'])
def test_current_chat_domains_have_shared_limits(monkeypatch, host):
    calls = []
    monkeypatch.setattr(source_limits, 'try_acquire', lambda source: calls.append(source) or True)
    source_limits.wait_for_slot(httpx.URL('https://' + host + '/'))
    assert len(calls) == 1
