"""PostgreSQL job metadata and history; no recipient or report content."""
import os
from pathlib import Path
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row


class StoreNotConfigured(RuntimeError):
    pass


def enabled():
    if os.getenv('DATABASE_URL'):
        return True
    if os.getenv('REQUIRE_DATABASE', 'false').lower() == 'true':
        raise StoreNotConfigured('Database is required')
    return False


@contextmanager
def connect():
    if not os.getenv('DATABASE_URL'):
        raise StoreNotConfigured('Database is not configured')
    # Neon/PgBouncer rejects timeout parameters in the startup package.
    # SET LOCAL keeps them within this transaction and works with pooling.
    with psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=2,
                         row_factory=dict_row) as connection:
        connection.execute("SET LOCAL statement_timeout = '2s'")
        connection.execute("SET LOCAL lock_timeout = '2s'")
        yield connection


def initialize():
    if not enabled():
        return
    with connect() as connection:
        # Serialize migrations across application starts in the same database.
        connection.execute('SELECT pg_advisory_xact_lock(741920261)')
        connection.execute('''CREATE TABLE IF NOT EXISTS privetek_schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
        for migration in sorted((Path(__file__).parent / 'migrations').glob('*.sql')):
            existing = connection.execute(
                'SELECT version FROM privetek_schema_migrations WHERE version = %s',
                (migration.name,)).fetchone()
            if existing:
                continue
            connection.execute(migration.read_text(encoding='utf-8'))
            connection.execute('INSERT INTO privetek_schema_migrations (version) VALUES (%s)',
                               (migration.name,))


def record(job_id, status):
    if not enabled():
        return
    with connect() as connection:
        connection.execute('''INSERT INTO privetek_jobs (id, status) VALUES (%s, %s)
            ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status,
            updated_at = CURRENT_TIMESTAMP''', (job_id, status))
        connection.execute('INSERT INTO privetek_job_events (job_id, status) VALUES (%s, %s)',
                           (job_id, status))


def get(job_id):
    with connect() as connection:
        job = connection.execute('''SELECT id, status, created_at, updated_at
            FROM privetek_jobs WHERE id = %s''', (job_id,)).fetchone()
        if job is None:
            return None
        job['history'] = connection.execute('''SELECT status, created_at
            FROM privetek_job_events WHERE job_id = %s ORDER BY id''', (job_id,)).fetchall()
        return job


def health():
    if enabled():
        with connect() as connection:
            connection.execute('SELECT 1 FROM privetek_jobs LIMIT 1').fetchone()
