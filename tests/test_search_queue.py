"""Isolated PostgreSQL validation. The load test uses synthetic orders and mail."""
import os
import time
from concurrent.futures import ThreadPoolExecutor
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


def test_parallel_worker_load(queue, monkeypatch, tmp_path, capsys):
    count = 1000
    processed = []
    # Simulate data sources, disk rendering, and the mail provider without traffic.
    monkeypatch.setattr(osint, 'search', lambda **_: {'checks': []})
    def create_report(_):
        pdf = tmp_path / (uuid4().hex + '.pdf')
        pdf.write_bytes(b'%PDF-synthetic')
        return pdf

    monkeypatch.setattr(server.pdf_gen, 'create_report', create_report)
    monkeypatch.setattr(server.email_sender, 'send_report', lambda email, _: processed.append(email))

    started = time.monotonic()
    with ThreadPoolExecutor(12) as pool:
        accepted = list(pool.map(lambda n: search_queue.enqueue(order(n), ['synthetic'], hourly_limit=count), range(count)))
    admitted_seconds = time.monotonic() - started
    assert len(set(accepted)) == count and all(not duplicate for _, duplicate in accepted)

    started = time.monotonic()
    def drain(_):
        handled = 0
        while search_worker.run_one():
            handled += 1
        return handled

    with ThreadPoolExecutor(8) as pool:
        handled = list(pool.map(drain, range(8)))
    drained_seconds = time.monotonic() - started

    assert sum(handled) == count and sum(n > 0 for n in handled) > 1
    assert len(processed) == len(set(processed)) == count
    with job_store.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM privetek_jobs WHERE status='provider_accepted'").fetchone()['n'] == count
        assert conn.execute('SELECT count(*) AS n FROM privetek_search_queue WHERE payload IS NOT NULL').fetchone()['n'] == 0
    with capsys.disabled():
        print(f'Queue load: {count} orders; 12 producers {admitted_seconds:.2f}s; 8 consumers {drained_seconds:.2f}s; per-consumer={handled}; duplicates=0; outstanding=0')
