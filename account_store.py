"""Transactional PostgreSQL account store. All tenant reads require a verified owner."""
import secrets
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import job_store
from account_crypto import digest, email_key, password_matches, report_cipher


def now():
    return datetime.now(timezone.utc)


def quota(items):
    """Independent committed counters: failures also consume quota across workers."""
    allowed = True
    with job_store.connect() as db:
        for name, value, limit in sorted(items):
            key = digest('quota:' + name, value)
            row = db.execute('''INSERT INTO privetek_account_limits (key) VALUES (%s)
                ON CONFLICT (key) DO UPDATE SET
                requests = CASE WHEN privetek_account_limits.window_start < CURRENT_TIMESTAMP - INTERVAL '1 hour'
                    THEN 1 ELSE privetek_account_limits.requests + 1 END,
                window_start = CASE WHEN privetek_account_limits.window_start < CURRENT_TIMESTAMP - INTERVAL '1 hour'
                    THEN CURRENT_TIMESTAMP ELSE privetek_account_limits.window_start END
                RETURNING requests''', (key,)).fetchone()
            allowed = allowed and row['requests'] <= limit
    return allowed


def put_code(challenge, email, purpose, code_hash, pending_hash):
    key = email_key(email)
    with job_store.connect() as db:
        # Serialize issuance with registration/reset and avoid multiple active challenges.
        db.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))', (key,))
        if purpose == 'register':
            existing = db.execute('SELECT id FROM privetek_users WHERE email_key = %s', (key,)).fetchone()
            if existing:
                return False
        elif not db.execute('SELECT id FROM privetek_users WHERE email_key = %s', (key,)).fetchone():
            return False
        db.execute('DELETE FROM privetek_account_codes WHERE email_key = %s AND purpose = %s', (key, purpose))
        db.execute('''INSERT INTO privetek_account_codes
            (id,email,email_key,purpose,code_hash,pending_password_hash,expires_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s)''',
            (challenge, email, key, purpose, code_hash, pending_hash, now() + timedelta(minutes=10)))
    return True


def cancel_code(challenge):
    with job_store.connect() as db:
        db.execute('DELETE FROM privetek_account_codes WHERE id = %s', (challenge,))


def redeem(challenge, supplied_hash, purpose, new_hash=None):
    with job_store.connect() as db:
        row = db.execute('SELECT * FROM privetek_account_codes WHERE id = %s FOR UPDATE', (challenge,)).fetchone()
        if not row or row['purpose'] != purpose or row['used_at'] or row['attempts'] >= 5 or row['expires_at'] <= now():
            return False
        if not secrets.compare_digest(row['code_hash'], supplied_hash):
            db.execute('UPDATE privetek_account_codes SET attempts = attempts + 1 WHERE id = %s', (challenge,))
            return False
        if purpose == 'register':
            db.execute('''INSERT INTO privetek_users (id,email,email_key,password_hash)
                VALUES (%s,%s,%s,%s) ON CONFLICT (email_key) DO NOTHING''',
                (uuid4().hex, row['email'], row['email_key'], row['pending_password_hash']))
        else:
            user = db.execute('SELECT id FROM privetek_users WHERE email_key = %s FOR UPDATE', (row['email_key'],)).fetchone()
            if not user or not new_hash:
                return False
            db.execute('UPDATE privetek_users SET password_hash = %s WHERE id = %s', (new_hash, user['id']))
            db.execute('DELETE FROM privetek_sessions WHERE user_id = %s', (user['id'],))
            db.execute('DELETE FROM privetek_mfa_challenges WHERE user_id = %s', (user['id'],))
            db.execute('DELETE FROM privetek_mfa_setup WHERE user_id = %s', (user['id'],))
        db.execute('UPDATE privetek_account_codes SET used_at = CURRENT_TIMESTAMP, pending_password_hash = NULL WHERE id = %s', (challenge,))
    return True


def login(email, password, token_hash):
    with job_store.connect() as db:
        user = db.execute('SELECT * FROM privetek_users WHERE email_key = %s FOR UPDATE', (email_key(email),)).fetchone()
        valid = password_matches(user['password_hash'] if user else None, password)
        if not user or not valid:
            return False
        if user['mfa_enabled']:
            from account_mfa import login_challenge
            return login_challenge(db, user)
        db.execute('INSERT INTO privetek_sessions (token_hash,user_id,expires_at) VALUES (%s,%s,%s)',
                   (token_hash, user['id'], now() + timedelta(days=7)))
    return True


def session(token_hash):
    with job_store.connect() as db:
        return db.execute('''SELECT u.id,u.email,u.email_key FROM privetek_sessions s
            JOIN privetek_users u ON u.id = s.user_id
            WHERE s.token_hash = %s AND s.expires_at > CURRENT_TIMESTAMP''', (token_hash,)).fetchone()


def logout(token_hash):
    with job_store.connect() as db:
        db.execute('DELETE FROM privetek_sessions WHERE token_hash = %s', (token_hash,))


def list_jobs(owner_key, limit=20, offset=0):
    with job_store.connect() as db:
        rows = db.execute('''SELECT j.id,j.status,j.created_at,j.updated_at,
            (r.job_id IS NOT NULL AND r.expires_at > CURRENT_TIMESTAMP) AS report_available,
            r.expires_at AS report_expires_at,
            (r.identity_ciphertext IS NOT NULL AND r.expires_at > CURRENT_TIMESTAMP) AS identity_available
            FROM privetek_jobs j JOIN privetek_job_owners o ON o.job_id = j.id
            LEFT JOIN privetek_account_reports r ON r.job_id = j.id
            WHERE o.email_key = %s ORDER BY j.created_at DESC,j.id DESC LIMIT %s OFFSET %s''',
            (owner_key, limit + 1, offset)).fetchall()
        return dict(items=rows[:limit], has_more=len(rows) > limit, offset=offset)


def save_report(job_id, pdf_path, identity=None):
    path = Path(pdf_path)
    if path.stat().st_size > 5 * 1024 * 1024:
        raise ValueError('Report too large')
    content = path.read_bytes()
    if not content.startswith(b'%PDF-') or len(content) > 5 * 1024 * 1024:
        raise ValueError('Report invalid or too large')
    ciphertext = report_cipher().encrypt(content)
    identity_ciphertext = None
    if identity is not None:
        payload = json.dumps(identity, ensure_ascii=False).encode()
        if len(payload) > 256 * 1024:
            raise ValueError('Identity snapshot too large')
        identity_ciphertext = report_cipher().encrypt(payload)
    with job_store.connect() as db:
        db.execute('''INSERT INTO privetek_account_reports (job_id,ciphertext,expires_at,identity_ciphertext,identity_revision)
            SELECT %s,%s,%s,%s,%s WHERE EXISTS (SELECT 1 FROM privetek_job_owners WHERE job_id = %s)
            ON CONFLICT (job_id) DO NOTHING''', (job_id, ciphertext, now() + timedelta(days=30), identity_ciphertext, 1 if identity is not None else 0, job_id))


def report(owner_key, job_id):
    with job_store.connect() as db:
        row = db.execute('''SELECT r.ciphertext FROM privetek_account_reports r
            JOIN privetek_job_owners o ON o.job_id = r.job_id
            WHERE r.job_id = %s AND o.email_key = %s AND r.expires_at > CURRENT_TIMESTAMP''',
            (job_id, owner_key)).fetchone()
    return report_cipher().decrypt(bytes(row['ciphertext'])) if row else None


def delete_report(owner_key, job_id):
    with job_store.connect() as db:
        db.execute('''DELETE FROM privetek_account_reports r USING privetek_job_owners o
            WHERE r.job_id = o.job_id AND r.job_id = %s AND o.email_key = %s''', (job_id, owner_key))


def cleanup():
    """Run daily and on account requests; bounded data lifetimes, not only hidden UI."""
    with job_store.connect() as db:
        db.execute('DELETE FROM privetek_account_reports WHERE expires_at <= CURRENT_TIMESTAMP')
        db.execute('DELETE FROM privetek_sessions WHERE expires_at <= CURRENT_TIMESTAMP')
        db.execute('DELETE FROM privetek_account_codes WHERE expires_at <= CURRENT_TIMESTAMP')
        db.execute('DELETE FROM privetek_mfa_setup WHERE expires_at <= CURRENT_TIMESTAMP')
        db.execute('DELETE FROM privetek_mfa_challenges WHERE expires_at <= CURRENT_TIMESTAMP')
        db.execute("DELETE FROM privetek_account_limits WHERE window_start < CURRENT_TIMESTAMP - INTERVAL '2 hours'")


def identity_snapshot(owner_key, job_id):
    with job_store.connect() as db:
        row = db.execute("""SELECT r.identity_ciphertext FROM privetek_account_reports r
            JOIN privetek_job_owners o ON o.job_id=r.job_id
            WHERE r.job_id=%s AND o.email_key=%s AND r.expires_at>CURRENT_TIMESTAMP""", (job_id, owner_key)).fetchone()
    return json.loads(report_cipher().decrypt(bytes(row['identity_ciphertext']))) if row and row['identity_ciphertext'] else None


def identity_decision(owner_key, job_id, revision, item_id, decision):
    from identity_resolution import decide
    with job_store.connect() as db:
        row = db.execute("""SELECT r.identity_ciphertext,r.identity_revision FROM privetek_account_reports r
            JOIN privetek_job_owners o ON o.job_id=r.job_id
            WHERE r.job_id=%s AND o.email_key=%s AND r.expires_at>CURRENT_TIMESTAMP FOR UPDATE OF r""", (job_id, owner_key)).fetchone()
        if not row or not row['identity_ciphertext']:
            return None
        if row['identity_revision'] != revision:
            raise RuntimeError('Identity revision conflict')
        snapshot = json.loads(report_cipher().decrypt(bytes(row['identity_ciphertext'])))
        updated = decide(snapshot, item_id, decision)
        ciphertext = report_cipher().encrypt(json.dumps(updated, ensure_ascii=False).encode())
        db.execute('UPDATE privetek_account_reports SET identity_ciphertext=%s,identity_revision=%s WHERE job_id=%s',
                   (ciphertext, updated['revision'], job_id))
    return updated
