"""Durable report orders and fenced worker leases."""
import os
from uuid import uuid4

import account_crypto
import job_store
from submission_guard import Limited


class QueueFull(Exception):
    pass


class LeaseLost(Exception):
    pass


def enabled():
    return os.getenv('SEARCH_QUEUE_ENABLED', 'false').lower() == 'true'


def validate_settings():
    if not job_store.enabled() or len(os.getenv('ACCOUNT_SECRET', '')) < 32:
        raise ValueError('Search queue requires PostgreSQL and ACCOUNT_SECRET')
    account_crypto.report_cipher()


def enqueue(submission, aliases, *, hourly_limit=20):
    email = str(submission.Email)
    key = account_crypto.digest('queue-recipient', email.casefold())
    fingerprint = account_crypto.digest('queue-order', '\0'.join((email.casefold(), submission.Phone, *sorted(aliases))))
    payload = account_crypto.report_cipher().encrypt(submission.model_dump_json().encode())
    job_id = uuid4().hex
    with job_store.connect() as db:
        # Serialize admissions so quotas and duplicate detection hold across web replicas.
        db.execute('SELECT pg_advisory_xact_lock(741920262)')
        previous = db.execute("""
            SELECT job_id FROM privetek_search_queue WHERE fingerprint=%s
              AND (finished_at IS NULL OR finished_at > clock_timestamp()-interval '10 minutes')
            ORDER BY created_at DESC LIMIT 1
        """, (fingerprint,)).fetchone()
        if previous:
            return previous['job_id'], True
        counts = db.execute("""
            SELECT count(*) AS total, count(*) FILTER (WHERE recipient_key=%s) AS recipient
            FROM privetek_search_queue WHERE created_at > clock_timestamp()-interval '1 hour'
        """, (key,)).fetchone()
        if counts['total'] >= hourly_limit or counts['recipient'] >= 2:
            raise Limited(3599)
        if db.execute('SELECT count(*) AS n FROM privetek_search_queue WHERE finished_at IS NULL').fetchone()['n'] >= 5000:
            raise QueueFull()
        job_store.record_in(db, job_id, 'accepted', email if account_crypto.enabled() else None)
        db.execute('INSERT INTO privetek_search_queue (job_id,recipient_key,fingerprint,payload) VALUES (%s,%s,%s,%s)',
                   (job_id, key, fingerprint, payload))
    return job_id, False


def claim():
    token = uuid4().hex
    with job_store.connect() as db:
        db.execute("DELETE FROM privetek_search_queue WHERE finished_at < clock_timestamp()-interval '2 hours'")
        expired = db.execute("""
            UPDATE privetek_search_queue SET finished_at=clock_timestamp(),payload=NULL,lease_token=NULL
            WHERE job_id IN (
                SELECT job_id FROM privetek_search_queue WHERE finished_at IS NULL
                  AND (lease_until IS NULL OR lease_until <= clock_timestamp())
                  AND (sending OR attempts >= 3 OR created_at <= clock_timestamp()-interval '24 hours')
                ORDER BY created_at LIMIT 40 FOR UPDATE SKIP LOCKED
            ) RETURNING job_id,sending
        """).fetchall()
        for row in expired:
            job_store.record_in(db, row['job_id'], 'delivery_unknown' if row['sending'] else 'failed')
        return db.execute("""
            UPDATE privetek_search_queue SET lease_token=%s,lease_until=clock_timestamp()+interval '15 minutes',
                attempts=attempts+1
            WHERE job_id = (
                SELECT job_id FROM privetek_search_queue WHERE finished_at IS NULL AND NOT sending AND attempts < 3
                  AND created_at > clock_timestamp()-interval '24 hours'
                  AND (lease_until IS NULL OR lease_until <= clock_timestamp())
                ORDER BY created_at,job_id LIMIT 1 FOR UPDATE SKIP LOCKED
            ) RETURNING job_id,lease_token,payload
        """, (token,)).fetchone()


def record(job_id, token, status):
    terminal = status in ('provider_accepted', 'delivery_unknown', 'failed')
    with job_store.connect() as db:
        row = db.execute("""
            UPDATE privetek_search_queue SET
                sending=sending OR %s,
                finished_at=CASE WHEN %s THEN clock_timestamp() ELSE NULL END,
                payload=CASE WHEN %s THEN NULL ELSE payload END,
                lease_token=CASE WHEN %s THEN NULL ELSE lease_token END,
                lease_until=clock_timestamp()+interval '15 minutes'
            WHERE job_id=%s AND lease_token=%s AND finished_at IS NULL AND lease_until > clock_timestamp()
            RETURNING job_id
        """, (status == 'sending', terminal, terminal, terminal, job_id, token)).fetchone()
        if not row:
            raise LeaseLost()
        if status != 'saving_report':
            job_store.record_in(db, job_id, status)
