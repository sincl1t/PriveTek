"""Account secrets and password hashing. No credentials in logs or URLs."""
import hashlib
import hmac
import os
import secrets
import threading
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from cryptography.fernet import Fernet

HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))
HASH_SLOTS = threading.BoundedSemaphore(2)


def enabled():
    return os.getenv('ACCOUNTS_ENABLED', 'false').lower() == 'true'


def validate_settings():
    from urllib.parse import urlsplit
    if not enabled():
        return
    secret = os.getenv('ACCOUNT_SECRET', '')
    origin = urlsplit(os.getenv('ACCOUNT_ORIGIN', ''))
    if len(secret) < 32 or origin.scheme != 'https' or not origin.netloc or origin.path or origin.query or origin.fragment or origin.username:
        raise ValueError('Account secret or HTTPS origin is not configured')
    if not os.getenv('DATABASE_URL'):
        raise ValueError('Accounts require PostgreSQL')
    report_cipher()


def digest(context, value):
    key = os.environ['ACCOUNT_SECRET'].encode()
    return hmac.new(key, (context + '\0' + value).encode(), hashlib.sha256).hexdigest()


def email_key(email):
    return digest('email', email.casefold())


def password_hash(password):
    if not isinstance(password, str) or not 15 <= len(password) <= 128:
        raise ValueError('Пароль должен содержать от 15 до 128 символов')
    with HASH_SLOTS:
        return HASHER.hash(password)


def password_matches(stored, supplied):
    if not isinstance(supplied, str) or not 1 <= len(supplied) <= 128:
        return False
    try:
        with HASH_SLOTS:
            return HASHER.verify(stored or DUMMY_HASH, supplied)
    except (VerificationError, InvalidHashError, ValueError):
        return False


def report_cipher():
    return Fernet(os.environ['ACCOUNT_REPORT_KEY'].encode())
