"""TOTP enrollment and verification; secrets encrypted, recovery codes HMAC-only."""
import base64
import hashlib
import hmac
import os
import re
import secrets
from datetime import timedelta
import pyotp
from cryptography.fernet import Fernet
import job_store
import account_crypto as crypto
from account_store import now


def cipher():
    key = hmac.new(os.environ['ACCOUNT_SECRET'].encode(), b'privetek:mfa-encryption:v1', hashlib.sha256).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def matching_step(secret, code, previous=-1):
    if not isinstance(code, str) or not re.fullmatch(r'[0-9]{6}', code):
        return None
    step = int(now().timestamp()) // 30
    totp = pyotp.TOTP(secret)
    for counter in (step - 1, step, step + 1):
        if counter > previous and secrets.compare_digest(totp.at(counter * 30), code):
            return counter
    return None


def recovery_hash(user_id, code):
    normalized = code.replace('-', '').replace(' ', '').lower() if isinstance(code, str) else ''
    if not re.fullmatch(r'[0-9a-f]{20}', normalized):
        return None
    return crypto.digest('mfa-recovery', user_id + ':' + normalized)


def new_recovery(db, user_id):
    codes = ['-'.join(re.findall('.{4}', secrets.token_hex(10))) for _ in range(10)]
    db.execute('DELETE FROM privetek_mfa_recovery WHERE user_id=%s', (user_id,))
    for code in codes:
        db.execute('INSERT INTO privetek_mfa_recovery (user_id,code_hash) VALUES (%s,%s)',
                   (user_id, recovery_hash(user_id, code)), prepare=False)
    return codes


def consume_factor(db, user, code):
    if not user['mfa_enabled'] or not user['mfa_secret']:
        return False
    secret = cipher().decrypt(bytes(user['mfa_secret'])).decode()
    step = matching_step(secret, code, user['mfa_last_step'])
    if step is not None:
        db.execute('UPDATE privetek_users SET mfa_last_step=%s WHERE id=%s', (step, user['id']))
        return True
    hashed = recovery_hash(user['id'], code)
    if hashed:
        return bool(db.execute('DELETE FROM privetek_mfa_recovery WHERE user_id=%s AND code_hash=%s RETURNING code_hash',
                               (user['id'], hashed)).fetchone())
    return False


def login_challenge(db, user):
    token = secrets.token_hex(24)
    db.execute('INSERT INTO privetek_mfa_challenges (token_hash,user_id,version,expires_at) VALUES (%s,%s,%s,%s)',
               (crypto.digest('mfa-login', token), user['id'], user['mfa_version'], now() + timedelta(minutes=5)))
    return token


def finish_login(challenge, code, session_hash):
    key = crypto.digest('mfa-login', challenge)
    with job_store.connect() as db:
        found = db.execute('SELECT user_id FROM privetek_mfa_challenges WHERE token_hash=%s', (key,)).fetchone()
        if not found:
            return False
        # All MFA operations lock user first; challenges and recovery codes follow.
        user = db.execute('SELECT * FROM privetek_users WHERE id=%s FOR UPDATE', (found['user_id'],)).fetchone()
        row = db.execute('SELECT * FROM privetek_mfa_challenges WHERE token_hash=%s FOR UPDATE', (key,)).fetchone()
        if not user or not row or row['expires_at'] <= now() or row['attempts'] >= 5 or row['version'] != user['mfa_version']:
            return False
        db.execute('UPDATE privetek_mfa_challenges SET attempts=attempts+1 WHERE token_hash=%s', (key,))
        if not consume_factor(db, user, code):
            return False
        db.execute('DELETE FROM privetek_mfa_challenges WHERE token_hash=%s', (key,))
        db.execute('INSERT INTO privetek_sessions (token_hash,user_id,expires_at) VALUES (%s,%s,%s)',
                   (session_hash, user['id'], now() + timedelta(days=7)))
    return True


def status(user_id):
    with job_store.connect() as db:
        user = db.execute('SELECT mfa_enabled FROM privetek_users WHERE id=%s', (user_id,)).fetchone()
        count = db.execute('SELECT count(*) AS n FROM privetek_mfa_recovery WHERE user_id=%s', (user_id,)).fetchone()['n']
    return {'enabled': bool(user and user['mfa_enabled']), 'recovery_codes_remaining': count}


def setup(user_id, password, session_hash):
    with job_store.connect() as db:
        user = db.execute('SELECT * FROM privetek_users WHERE id=%s FOR UPDATE', (user_id,)).fetchone()
        if not user or user['mfa_enabled'] or not crypto.password_matches(user['password_hash'], password):
            return None
        secret = pyotp.random_base32()
        db.execute('''INSERT INTO privetek_mfa_setup (user_id,session_hash,secret,expires_at) VALUES (%s,%s,%s,%s)
            ON CONFLICT (user_id) DO UPDATE SET session_hash=EXCLUDED.session_hash,secret=EXCLUDED.secret,expires_at=EXCLUDED.expires_at''',
                   (user_id, session_hash, cipher().encrypt(secret.encode()), now() + timedelta(minutes=10)))
    return secret


def confirm(user_id, session_hash, code):
    with job_store.connect() as db:
        user = db.execute('SELECT * FROM privetek_users WHERE id=%s FOR UPDATE', (user_id,)).fetchone()
        pending = db.execute('SELECT * FROM privetek_mfa_setup WHERE user_id=%s FOR UPDATE', (user_id,)).fetchone()
        if not user or user['mfa_enabled'] or not pending or pending['session_hash'] != session_hash or pending['expires_at'] <= now():
            return None
        secret = cipher().decrypt(bytes(pending['secret'])).decode()
        step = matching_step(secret, code)
        if step is None:
            return None
        db.execute('UPDATE privetek_users SET mfa_enabled=TRUE,mfa_secret=%s,mfa_last_step=%s,mfa_version=mfa_version+1 WHERE id=%s',
                   (pending['secret'], step, user_id))
        codes = new_recovery(db, user_id)
        db.execute('DELETE FROM privetek_mfa_setup WHERE user_id=%s', (user_id,))
        db.execute('DELETE FROM privetek_mfa_challenges WHERE user_id=%s', (user_id,))
        db.execute('DELETE FROM privetek_sessions WHERE user_id=%s AND token_hash<>%s', (user_id, session_hash))
    return codes


def manage(user_id, password, code, session_hash, disable=False):
    with job_store.connect() as db:
        user = db.execute('SELECT * FROM privetek_users WHERE id=%s FOR UPDATE', (user_id,)).fetchone()
        if not user or not crypto.password_matches(user['password_hash'], password) or not consume_factor(db, user, code):
            return None
        if disable:
            db.execute('UPDATE privetek_users SET mfa_enabled=FALSE,mfa_secret=NULL,mfa_last_step=-1,mfa_version=mfa_version+1 WHERE id=%s', (user_id,))
            db.execute('DELETE FROM privetek_mfa_recovery WHERE user_id=%s', (user_id,))
            codes = []
        else:
            codes = new_recovery(db, user_id)
            db.execute('UPDATE privetek_users SET mfa_version=mfa_version+1 WHERE id=%s', (user_id,))
        db.execute('DELETE FROM privetek_mfa_setup WHERE user_id=%s', (user_id,))
        db.execute('DELETE FROM privetek_mfa_challenges WHERE user_id=%s', (user_id,))
        db.execute('DELETE FROM privetek_sessions WHERE user_id=%s AND token_hash<>%s', (user_id, session_hash))
    return codes
