import pytest
import server
from submission_guard import SubmissionGuard

@pytest.fixture(autouse=True)
def fresh_guard(monkeypatch):
    monkeypatch.setattr(server, 'guard', SubmissionGuard())
