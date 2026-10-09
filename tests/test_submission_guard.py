from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import server
from submission_guard import Limited, SubmissionGuard


def test_concurrent_duplicates_reserve_one_job():
    guard = SubmissionGuard()
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: guard.reserve('reader@example.com', ''), range(40)))
    assert len({job for job, _ in results}) == 1
    assert sum(not duplicate for _, duplicate in results) == 1
    assert 'reader@example.com' not in repr(guard.entries)


def test_active_job_and_completed_cooldown():
    now = [0]
    guard = SubmissionGuard(clock=lambda: now[0])
    job, _ = guard.reserve('reader@example.com', '')
    now[0] = 7200
    assert guard.reserve('READER@example.com', '') == (job, True)
    guard.finish(job)
    now[0] += 599
    assert guard.reserve('reader@example.com', '') == (job, True)
    now[0] += 2
    assert guard.reserve('reader@example.com', '')[1] is False


def test_recipient_quota_cannot_be_evaded_by_phone():
    guard = SubmissionGuard()
    guard.reserve('reader@example.com', '+36201234567')
    guard.reserve('reader@example.com', '+36201234568')
    with pytest.raises(Limited) as error:
        guard.reserve('READER@example.com', '+36201234569')
    assert 1 <= error.value.retry_after <= 3601


def test_global_quota_expires_and_cancel_releases():
    now = [0]
    guard = SubmissionGuard(clock=lambda: now[0], total=1)
    job, _ = guard.reserve('one@example.com', '')
    with pytest.raises(Limited):
        guard.reserve('two@example.com', '')
    guard.cancel(job)
    job, _ = guard.reserve('two@example.com', '')
    guard.finish(job)
    now[0] = 3600
    assert guard.reserve('three@example.com', '')[1] is False


@pytest.fixture
def webhook(monkeypatch):
    monkeypatch.setattr(server.email_sender, 'validate_settings', lambda: None)
    thread = MagicMock()
    slots = MagicMock()
    monkeypatch.setattr(server.threading, 'Thread', thread)
    monkeypatch.setattr(server, 'slots', slots)
    return TestClient(server.app), thread, slots


def test_duplicate_webhook_does_not_send_or_acquire_slot(webhook):
    client, thread, slots = webhook
    first = client.post('/', data={'Email': 'reader@example.com'})
    second = client.post('/', data={'Email': 'reader@example.com', 'Name': 'Another name'})
    assert first.status_code == second.status_code == 200
    assert first.headers['X-Request-ID'] == second.headers['X-Request-ID']
    assert second.headers['X-Duplicate'] == 'true'
    thread.return_value.start.assert_called_once()
    slots.acquire.assert_called_once()


def test_failed_start_can_be_retried(webhook):
    client, thread, slots = webhook
    thread.return_value.start.side_effect = RuntimeError()
    assert client.post('/', data={'Email': 'reader@example.com'}).status_code == 503
    thread.return_value.start.side_effect = None
    assert client.post('/', data={'Email': 'reader@example.com'}).status_code == 200
    slots.release.assert_called_once()


def test_busy_does_not_consume_quota(webhook):
    client, thread, slots = webhook
    slots.acquire.return_value = False
    for _ in range(5):
        assert client.post('/', data={'Email': 'reader@example.com'}).status_code == 503
    slots.acquire.return_value = True
    assert client.post('/', data={'Email': 'reader@example.com'}).status_code == 200


def test_oversized_body_with_false_length_rejected(webhook):
    client, thread, _ = webhook
    response = client.post('/', content=b'Name=' + b'x' * 17000,
                           headers={'Content-Type': 'application/x-www-form-urlencoded',
                                    'Content-Length': '1'})
    assert response.status_code == 413
    thread.assert_not_called()


def test_quota_response_and_tilda_probe(webhook, monkeypatch):
    client, thread, _ = webhook
    monkeypatch.setattr(server, 'guard', SubmissionGuard(total=1))
    assert client.post('/', data={'Email': 'one@example.com'}).status_code == 200
    limited = client.post('/', data={'Email': 'two@example.com'})
    assert limited.status_code == 429
    assert int(limited.headers['Retry-After']) > 0
    assert client.post('/', data={'test': 'test'}).status_code == 200
    thread.return_value.start.assert_called_once()
