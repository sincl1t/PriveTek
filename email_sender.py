"""SMTP or Brevo HTTPS delivery; credentials are never logged."""
import os
import base64
import httpx
import ssl
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from email_validator import validate_email


def mailbox(value):
    return validate_email(value, check_deliverability=False, allow_smtputf8=False).normalized


@dataclass(frozen=True)
class SMTPSettings:
    host: str
    port: int
    username: str
    password: str
    sender: str
    security: str

    @classmethod
    def from_env(cls):
        required = ('SMTP_HOST', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'SMTP_FROM')
        missing = [key for key in required if not os.getenv(key)]
        if missing:
            raise ValueError('Не заполнены настройки: ' + ', '.join(missing))
        security = os.getenv('SMTP_SECURITY', 'starttls').lower()
        if security not in ('starttls', 'ssl'):
            raise ValueError('SMTP_SECURITY должен быть starttls или ssl')
        port = int(os.getenv('SMTP_PORT', '465' if security == 'ssl' else '587'))
        if not 1 <= port <= 65535:
            raise ValueError('Неверный SMTP_PORT')
        return cls(os.environ['SMTP_HOST'], port, os.environ['SMTP_USERNAME'],
                   os.environ['SMTP_PASSWORD'], mailbox(os.environ['SMTP_FROM']), security)


def send_smtp_report(to_email: str, pdf_path: str):
    settings = SMTPSettings.from_env()
    recipient = mailbox(to_email)
    content = Path(pdf_path).read_bytes()
    if not content.startswith(b'%PDF-'):
        raise ValueError('Вложение должно быть PDF')
    message = EmailMessage()
    message['Subject'] = 'PriveTek: ваш отчёт о цифровом следе'
    message['From'] = settings.sender
    message['To'] = recipient
    message['Date'] = formatdate(localtime=False)
    message['Message-ID'] = make_msgid()
    message.set_content('Здравствуйте!\n\nВаш отчёт о цифровом следе находится во вложении.\n'
                        'Результаты относятся только к перечисленным в отчёте проверкам.\n\nКоманда PriveTek')
    message.add_attachment(content, maintype='application', subtype='pdf', filename='PriveTek-report.pdf')
    context = ssl.create_default_context()
    if settings.security == 'ssl':
        connection = smtplib.SMTP_SSL(settings.host, settings.port, timeout=30, context=context)
    else:
        connection = smtplib.SMTP(settings.host, settings.port, timeout=30)
    with connection as smtp:
        smtp.ehlo()
        if settings.security == 'starttls':
            smtp.starttls(context=context)
            smtp.ehlo()
        smtp.login(settings.username, settings.password)
        refused = smtp.send_message(message, from_addr=settings.sender, to_addrs=[recipient])
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)
    return message['Message-ID']


@dataclass(frozen=True)
class BrevoSettings:
    api_key: str
    sender: str

    @classmethod
    def from_env(cls):
        key = os.getenv('BREVO_API_KEY', '').strip()
        sender = os.getenv('MAIL_FROM', '').strip()
        if not key or not sender:
            raise ValueError('Заполните BREVO_API_KEY и MAIL_FROM')
        return cls(key, mailbox(sender))


def validate_settings():
    provider = os.getenv('MAIL_PROVIDER', 'smtp').lower()
    if provider == 'brevo':
        BrevoSettings.from_env()
    elif provider == 'smtp':
        SMTPSettings.from_env()
    else:
        raise ValueError('MAIL_PROVIDER должен быть brevo или smtp')
    return provider


class DeliveryError(RuntimeError):
    """Safe error message: no addresses, API keys or provider response body."""


def send_brevo_report(to_email, pdf_path):
    settings = BrevoSettings.from_env()
    recipient = mailbox(to_email)
    content = Path(pdf_path).read_bytes()
    if not content.startswith(b'%PDF-'):
        raise ValueError('Вложение должно быть PDF')
    payload = {
        'sender': {'name': 'PriveTek', 'email': settings.sender},
        'replyTo': {'name': 'PriveTek', 'email': settings.sender},
        'to': [{'email': recipient}],
        'subject': 'PriveTek: ваш отчёт о цифровом следе',
        'textContent': 'Здравствуйте! Ваш отчёт о цифровом следе во вложении. '
                       'Результаты относятся только к перечисленным проверкам. Команда PriveTek.',
        'attachment': [{'name': 'PriveTek-report.pdf',
                        'content': base64.b64encode(content).decode('ascii')}],
    }
    # No automatic retry: a timed-out response may follow a successful send.
    try:
        response = httpx.post('https://api.brevo.com/v3/smtp/email',
                              headers={'api-key': settings.api_key, 'accept': 'application/json'},
                              json=payload, timeout=30, follow_redirects=False)
    except httpx.RequestError:
        raise DeliveryError('Нет ответа Brevo; проверьте журнал отправок перед повтором') from None
    if response.status_code != 201:
        raise DeliveryError(f'Brevo не подтвердил отправку (HTTP {response.status_code})')
    try:
        message_id = response.json()['messageId']
        if not isinstance(message_id, str) or not message_id:
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise DeliveryError('Ответ Brevo без идентификатора; проверьте журнал отправок') from None
    return message_id


def send_report(to_email: str, pdf_path: str):
    if validate_settings() == 'brevo':
        return send_brevo_report(to_email, pdf_path)
    return send_smtp_report(to_email, pdf_path)
