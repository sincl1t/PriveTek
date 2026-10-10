import pytest
import server
from submission_guard import SubmissionGuard

@pytest.fixture(autouse=True)
def fresh_guard(monkeypatch):
    monkeypatch.setattr(server, 'guard', SubmissionGuard())
    monkeypatch.setenv('WEBHOOK_SECRET', 'test-webhook-key')
    monkeypatch.delenv('DATABASE_URL', raising=False)
