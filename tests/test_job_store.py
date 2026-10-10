from unittest.mock import MagicMock

import pytest
import job_store


def test_required_database_cannot_silently_disable(monkeypatch):
    monkeypatch.setenv('REQUIRE_DATABASE', 'true')
    for action in (job_store.initialize, job_store.health, lambda: job_store.record('job', 'accepted')):
        with pytest.raises(job_store.StoreNotConfigured):
            action()


def test_migrations_are_versioned_and_skip_applied(monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'test')
    connection = MagicMock()
    connection.__enter__.return_value.execute.return_value.fetchone.return_value = None
    monkeypatch.setattr(job_store, 'connect', lambda: connection)
    job_store.initialize()
    statements = connection.__enter__.return_value.execute.call_args_list
    assert sum('CREATE TABLE IF NOT EXISTS privetek_jobs' in c.args[0] for c in statements) == 1
    assert sum('INSERT INTO privetek_schema_migrations' in c.args[0] for c in statements) == 2
    connection.__enter__.return_value.execute.reset_mock()
    connection.__enter__.return_value.execute.return_value.fetchone.return_value = {'version': 'already applied'}
    job_store.initialize()
    assert not any('INSERT INTO privetek_schema_migrations' in c.args[0]
                   for c in connection.__enter__.return_value.execute.call_args_list)


def test_status_and_history_written_in_same_transaction(monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'test')
    connection = MagicMock()
    monkeypatch.setattr(job_store, 'connect', lambda: connection)
    job_store.record("job'", 'accepted')
    calls = connection.__enter__.return_value.execute.call_args_list
    assert len(calls) == 2
    assert all(c.args[1] == ("job'", 'accepted') for c in calls)
    assert all("job'" not in c.args[0] for c in calls)
    connection.__exit__.assert_called_once_with(None, None, None)


def test_status_and_history_read_from_database(monkeypatch):
    connection = MagicMock()
    db = connection.__enter__.return_value
    db.execute.return_value.fetchone.return_value = {'id': 'a'*32, 'status': 'sending'}
    db.execute.return_value.fetchall.return_value = [{'status': 'accepted'}]
    monkeypatch.setattr(job_store, 'connect', lambda: connection)
    result = job_store.get('a'*32)
    assert result['status'] == 'sending'
    assert result['history'] == [{'status': 'accepted'}]


def test_pooled_connection_uses_transaction_local_timeouts(monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'postgresql://test-pooler/db')
    constructor = MagicMock()
    monkeypatch.setattr(job_store.psycopg, 'connect', constructor)
    with job_store.connect() as connection:
        connection.execute('SELECT 1')
    assert 'options' not in constructor.call_args.kwargs
    assert constructor.call_args.kwargs['connect_timeout'] == 2
    db = constructor.return_value.__enter__.return_value
    assert [c.args[0] for c in db.execute.call_args_list] == [
        "SET LOCAL statement_timeout = '2s'", "SET LOCAL lock_timeout = '2s'", 'SELECT 1']
    constructor.return_value.__exit__.assert_called_once_with(None, None, None)
