import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import server
from privacy_logging import PrivacyFilter


@pytest.mark.parametrize('headers,query', [({}, ''), ({'X-Webhook-Secret': 'wrong'}, ''),
    ({}, '?token=wrong'), ({}, '?token=test-webhook-key&token=test-webhook-key')])
def test_webhook_rejects_unauthorized_probe(headers, query, monkeypatch):
    thread = MagicMock()
    monkeypatch.setattr(server.threading, 'Thread', thread)
    response = TestClient(server.app).post('/webhook' + query, data={'test': 'test'}, headers=headers)
    assert response.status_code == 403
    thread.assert_not_called()


def test_webhook_missing_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv('WEBHOOK_SECRET')
    assert TestClient(server.app).post('/', data={'test': 'test'}).status_code == 503


@pytest.mark.parametrize('path,headers', [('/webhook?token=test-webhook-key', {}),
    ('/', {'X-Webhook-Secret': 'test-webhook-key'})])
def test_authenticated_tilda_probe_does_not_start_job(path, headers, monkeypatch):
    thread = MagicMock()
    monkeypatch.setattr(server.threading, 'Thread', thread)
    response = TestClient(server.app).post(path, data={'test': 'test'}, headers=headers)
    assert response.status_code == 200 and response.text == 'ok'
    thread.assert_not_called()
    assert not server.guard.accepted


def test_tilda_url_form_starts_one_job_and_suppresses_retry(monkeypatch):
    monkeypatch.setattr(server.email_sender, 'validate_settings', lambda: None)
    thread = MagicMock()
    monkeypatch.setattr(server.threading, 'Thread', thread)
    monkeypatch.setattr(server, 'slots', MagicMock())
    client = TestClient(server.app)
    path = '/webhook?token=test-webhook-key'
    data = {'Email': 'reader@example.com', 'Phone': '+36 20 123 4567', 'tranid': '467251:8442970'}
    first = client.post(path, data=data)
    second = client.post(path, data=data)
    assert first.status_code == second.status_code == 200
    assert first.headers['X-Request-ID'] == second.headers['X-Request-ID']
    assert second.headers['X-Duplicate'] == 'true'
    thread.return_value.start.assert_called_once()


def test_status_api_separate_authorization_and_errors(monkeypatch):
    monkeypatch.setenv('STATUS_API_KEY', 'team-key')
    store = MagicMock(return_value={'id': 'a'*32, 'status': 'searching', 'history': []})
    monkeypatch.setattr(server.job_store, 'get', store)
    client = TestClient(server.app)
    path = '/api/jobs/' + 'a'*32
    assert client.get(path).status_code == 403
    assert client.get(path, headers={'Authorization': 'Bearer test-webhook-key'}).status_code == 403
    store.assert_not_called()
    headers = {'Authorization': 'Bearer team-key'}
    assert client.get(path, headers=headers).json()['status'] == 'searching'
    assert client.get('/api/jobs/invalid', headers=headers).status_code == 404
    store.return_value = None
    assert client.get(path, headers=headers).status_code == 404
    store.side_effect = RuntimeError('private database credentials')
    failed = client.get(path, headers=headers)
    assert failed.status_code == 503
    assert 'credentials' not in failed.text
    monkeypatch.delenv('STATUS_API_KEY')
    assert client.get(path, headers=headers).status_code == 503


def test_privacy_filter_redacts_url_email_exception():
    try:
        raise RuntimeError('secret reader@example.com')
    except RuntimeError:
        import sys
        record = logging.LogRecord('test', logging.ERROR, '', 0,
            'request https://example.com/webhook?token=secret reader@example.com', (), sys.exc_info())
    PrivacyFilter().filter(record)
    assert 'secret' not in record.getMessage()
    assert 'reader@example.com' not in record.getMessage()
    assert 'RuntimeError' in record.getMessage()
    assert record.exc_info is None


def test_failed_mail_also_removes_pdf(tmp_path, monkeypatch):
    import osint
    path = tmp_path / 'report.pdf'
    path.write_bytes(b'%PDF-test')
    monkeypatch.setattr(osint, 'search', lambda **kw: {})
    monkeypatch.setattr(server.pdf_gen, 'create_report', lambda data: str(path))
    monkeypatch.setattr(server.email_sender, 'send_report', MagicMock(side_effect=RuntimeError()))
    store = MagicMock()
    monkeypatch.setattr(server.job_store, 'record', store)
    slots = MagicMock()
    monkeypatch.setattr(server, 'slots', slots)
    server.background_task(server.Submission(Email='reader@example.com'), 'a'*32)
    assert not path.exists()
    assert store.call_args.args == ('a'*32, 'delivery_unknown')
    slots.release.assert_called_once()


@pytest.mark.parametrize('failure', ['database', 'thread'])
def test_start_failure_does_not_leave_quota_or_inaccurate_status(monkeypatch, failure):
    monkeypatch.setattr(server.email_sender, 'validate_settings', lambda: None)
    store = MagicMock()
    thread = MagicMock()
    if failure == 'database':
        store.side_effect = RuntimeError('private credentials')
    else:
        thread.return_value.start.side_effect = RuntimeError()
    monkeypatch.setattr(server.job_store, 'record', store)
    monkeypatch.setattr(server.threading, 'Thread', thread)
    slots = MagicMock()
    monkeypatch.setattr(server, 'slots', slots)
    response = TestClient(server.app).post('/', data={'Email': 'reader@example.com'},
        headers={'X-Webhook-Secret': 'test-webhook-key'})
    assert response.status_code == 503
    assert 'credentials' not in response.text
    assert not server.guard.accepted and not server.guard.entries
    slots.release.assert_called_once()
    if failure == 'thread':
        assert [c.args[1] for c in store.call_args_list] == ['accepted', 'failed']
    else:
        thread.assert_not_called()
