import smtplib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

import email_sender
import osint
import pdf_gen
import server
from demo_report import SAMPLE


@pytest.fixture
def smtp_env(monkeypatch):
    for key, value in {'SMTP_HOST': 'smtp.example.com', 'SMTP_PORT': '587',
                       'SMTP_USERNAME': 'demo', 'SMTP_PASSWORD': 'test-secret',
                       'SMTP_FROM': 'sender@example.com', 'SMTP_SECURITY': 'starttls'}.items():
        monkeypatch.setenv(key, value)


def test_pdf_unicode_and_parallel_names(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        paths = list(pool.map(lambda _: pdf_gen.create_report(SAMPLE, tmp_path), range(8)))
    assert len(set(paths)) == 8
    for path in paths:
        text = ''.join(p.extract_text() for p in PdfReader(path).pages)
        assert 'Отчёт о цифровом следе' in text
        assert 'ДЕМОНСТРАЦИОННЫЙ' in text
        assert 'Instagram' in text


def test_long_report(tmp_path):
    data = dict(SAMPLE, email_registrations=[{'site': 'Длинное название ' * 15}] * 30)
    path = pdf_gen.create_report(data, tmp_path)
    assert len(PdfReader(path).pages) > 1


@pytest.mark.parametrize('security,constructor', [('starttls', 'SMTP'), ('ssl', 'SMTP_SSL')])
def test_mail_attachment_and_tls(tmp_path, monkeypatch, smtp_env, security, constructor):
    monkeypatch.setenv('SMTP_SECURITY', security)
    pdf = Path(pdf_gen.create_report(SAMPLE, tmp_path))
    connection = MagicMock()
    smtp = connection.return_value.__enter__.return_value
    smtp.send_message.return_value = {}
    monkeypatch.setattr(email_sender.smtplib, constructor, connection)
    identifier = email_sender.send_report('reader@example.com', str(pdf))
    message = smtp.send_message.call_args.args[0]
    assert identifier == message['Message-ID']
    assert message['To'] == 'reader@example.com'
    attachment = list(message.iter_attachments())[0]
    assert attachment.get_content_type() == 'application/pdf'
    assert attachment.get_payload(decode=True) == pdf.read_bytes()
    smtp.login.assert_called_once_with('demo', 'test-secret')
    assert smtp.starttls.called == (security == 'starttls')


def test_smtp_failure_is_not_success(tmp_path, monkeypatch, smtp_env):
    connection = MagicMock()
    connection.return_value.__enter__.return_value.send_message.side_effect = smtplib.SMTPException('test')
    monkeypatch.setattr(email_sender.smtplib, 'SMTP', connection)
    with pytest.raises(smtplib.SMTPException):
        email_sender.send_report('reader@example.com', pdf_gen.create_report(SAMPLE, tmp_path))


@pytest.mark.parametrize('data', [{}, {'Email': 'wrong'}, {'Email': 'reader@example.com', 'Phone': 'abc'},
                                  {'Email': 'reader@example.com', 'Phone': '+123'}])
def test_invalid_submission(data):
    response = TestClient(server.app).post('/', data=data or {'Name': ''})
    assert response.status_code == 422


def test_form_acceptance(monkeypatch, smtp_env):
    thread = MagicMock()
    monkeypatch.setattr(server.threading, 'Thread', thread)
    # Isolate the acquired slot because this fake thread will not run its finally block.
    monkeypatch.setattr(server, 'slots', MagicMock())
    response = TestClient(server.app).post('/', data={'Name': 'Тест', 'Email': 'reader@example.com', 'Phone': '+36 20 123 4567'})
    assert response.status_code == 200 and response.text == 'ok'
    submission, job = thread.call_args.kwargs['args']
    assert submission.Phone == '+36201234567'
    assert job == response.headers['X-Request-ID']
    thread.return_value.start.assert_called_once()


def test_missing_mail_settings(monkeypatch):
    monkeypatch.delenv('SMTP_HOST', raising=False)
    assert TestClient(server.app).post('/', data={'Email': 'reader@example.com'}).status_code == 503


def test_json_rejected():
    assert TestClient(server.app).post('/', json={'Email': 'reader@example.com'}).status_code == 415


def test_busy(monkeypatch, smtp_env):
    slots = MagicMock()
    slots.acquire.return_value = False
    monkeypatch.setattr(server, 'slots', slots)
    assert TestClient(server.app).post('/', data={'Email': 'reader@example.com'}).status_code == 503


def test_pipeline(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(osint, 'search', lambda **kwargs: SAMPLE)
    create = pdf_gen.create_report
    monkeypatch.setattr(pdf_gen, 'create_report', lambda data: create(data, tmp_path))
    send = MagicMock()
    monkeypatch.setattr(email_sender, 'send_report', send)
    slots = MagicMock()
    monkeypatch.setattr(server, 'slots', slots)
    server.background_task(server.Submission(Email='reader@example.com'), 'demo-job')
    assert Path(send.call_args.args[1]).is_file()
    slots.release.assert_called_once()
    assert 'reader@example.com' not in caplog.text


def test_pipeline_failure_releases_slot(monkeypatch, caplog):
    monkeypatch.setattr(osint, 'search', MagicMock(side_effect=RuntimeError('private@example.com')))
    slots = MagicMock()
    monkeypatch.setattr(server, 'slots', slots)
    server.background_task(server.Submission(Email='reader@example.com'), 'demo-job')
    slots.release.assert_called_once()
    assert 'stage=search' in caplog.text
    assert 'private@example.com' not in caplog.text


def test_hibp_and_phone_arguments(monkeypatch):
    monkeypatch.setenv('HIBP_API_KEY', 'test-key')
    request = httpx.Request('GET', 'https://example.com')
    monkeypatch.setattr(osint.httpx, 'get', lambda *a, **kw: httpx.Response(200, request=request, json=[{'Name': 'Demo', 'BreachDate': '2024-01-01'}]))
    run = MagicMock(return_value=[{'name': 'Demo', 'exists': True, 'rateLimit': False}])
    monkeypatch.setattr(osint.trio, 'run', run)
    result = osint.search('reader@example.com', '+36201234567')
    assert result['email_breach'][0]['name'] == 'Demo'
    assert run.call_args.args[2] == ('201234567', '36')


def test_unavailable_source_is_not_negative_result():
    errors = []
    assert osint.collect([{'name': 'Demo', 'rateLimit': True}], errors) is None
    assert errors


@pytest.fixture
def brevo_env(monkeypatch):
    monkeypatch.setenv('MAIL_PROVIDER', 'brevo')
    monkeypatch.setenv('MAIL_FROM', 'sender@example.com')
    monkeypatch.setenv('BREVO_API_KEY', 'dummy-secret')


def test_brevo_pdf_attachment(tmp_path, monkeypatch, brevo_env):
    import base64
    pdf = Path(pdf_gen.create_report(SAMPLE, tmp_path))
    post = MagicMock(return_value=httpx.Response(201, json={'messageId': 'test-id'}))
    monkeypatch.setattr(email_sender.httpx, 'post', post)
    assert email_sender.send_report('reader@example.com', str(pdf)) == 'test-id'
    assert post.call_args.args[0] == 'https://api.brevo.com/v3/smtp/email'
    payload = post.call_args.kwargs['json']
    assert payload['to'] == [{'email': 'reader@example.com'}]
    assert payload['sender']['email'] == 'sender@example.com'
    assert base64.b64decode(payload['attachment'][0]['content']) == pdf.read_bytes()


@pytest.mark.parametrize('status', [400, 401, 403, 429, 500])
def test_brevo_failures_do_not_leak_or_retry(tmp_path, monkeypatch, brevo_env, status):
    post = MagicMock(return_value=httpx.Response(status, text='dummy-secret reader@example.com'))
    monkeypatch.setattr(email_sender.httpx, 'post', post)
    with pytest.raises(email_sender.DeliveryError) as error:
        email_sender.send_report('reader@example.com', pdf_gen.create_report(SAMPLE, tmp_path))
    assert str(status) in str(error.value)
    assert 'dummy-secret' not in str(error.value)
    assert 'reader@example.com' not in str(error.value)
    post.assert_called_once()


def test_brevo_missing_key(monkeypatch, brevo_env):
    monkeypatch.delenv('BREVO_API_KEY')
    assert TestClient(server.app).post('/', data={'Email': 'reader@example.com'}).status_code == 503


def test_brevo_timeout(tmp_path, monkeypatch, brevo_env):
    post = MagicMock(side_effect=httpx.ReadTimeout('private'))
    monkeypatch.setattr(email_sender.httpx, 'post', post)
    with pytest.raises(email_sender.DeliveryError):
        email_sender.send_report('reader@example.com', pdf_gen.create_report(SAMPLE, tmp_path))
    post.assert_called_once()
