"""Persistent processing metadata; never store recipient data or report content."""
import os
import psycopg


SCHEMA = '''CREATE TABLE IF NOT EXISTS privetek_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
)'''


def connect():
    return psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=15)


def initialize():
    if not os.getenv('DATABASE_URL'):
        return
    with connect() as connection:
        connection.execute(SCHEMA)


def record(job_id, status):
    if not os.getenv('DATABASE_URL'):
        return
    with connect() as connection:
        connection.execute('''INSERT INTO privetek_jobs (id, status) VALUES (%s, %s)
            ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status,
            updated_at = CURRENT_TIMESTAMP''', (job_id, status))


def health():
    if os.getenv('DATABASE_URL'):
        with connect() as connection:
            connection.execute('SELECT 1').fetchone()
