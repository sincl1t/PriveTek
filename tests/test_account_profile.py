from unittest.mock import MagicMock
import pytest
import account_profile
import account_store
import job_store
from test_accounts import client, db, login, register, settings  # noqa: F401


@pytest.mark.parametrize('data', [
    {'display_name':'x'*81,'avatar_theme':'sky'},
    {'display_name':'hello\nworld','avatar_theme':'sky'},
    {'display_name':'name','avatar_theme':'https://external.example/avatar'},
    {'display_name':'name','avatar_theme':[]},
    {'display_name':None,'avatar_theme':'sky'},
    {'display_name':'name','avatar_theme':'sky','user_id':'someone-else'},
    {'display_name':'name','avatar_theme':'sky','email':'other@example.com'},
    {'display_name':'name','avatar_theme':'sky','subscribed':True},
])
def test_profile_rejects_invalid_or_privileged_fields(data):
    with pytest.raises(ValueError):
        account_profile.normalize(data)


def test_profile_only_normalizes_presentation_fields():
    assert account_profile.normalize({'display_name':'  Лиза   Гр  ','avatar_theme':'mint'}) == {
        'display_name':'Лиза Гр', 'avatar_theme':'mint'}


def test_profile_api_requires_authenticated_owner_and_csrf(settings, monkeypatch):
    c = client()
    assert c.get('/api/account/profile').status_code == 401
    assert c.put('/api/account/profile', json={}).status_code == 401
    monkeypatch.setattr(account_store, 'session', lambda token:dict(id='owner',email='owner@example.com'))
    from account_routes import COOKIE
    c.cookies.set(COOKIE, 'x'*43)
    write = MagicMock()
    monkeypatch.setattr(account_profile, 'save', write)
    assert c.put('/api/account/profile', json={}).status_code == 403
    assert c.put('/api/account/profile', json={}, headers={'Origin':'https://evil.test'}).status_code == 403
    write.assert_not_called()


def test_profile_errors_do_not_expose_private_storage_details(settings, monkeypatch):
    c = client()
    from account_routes import COOKIE
    c.cookies.set(COOKIE, 'x'*43)
    monkeypatch.setattr(account_store, 'session', lambda token:dict(id='owner',email='owner@example.com'))
    monkeypatch.setattr(account_profile, 'read', MagicMock(side_effect=RuntimeError('PRIVATE KEY CONTENT')))
    r = c.get('/api/account/profile')
    assert r.status_code == 503 and 'PRIVATE' not in r.text
    assert r.headers['cache-control'] == 'no-store'


def test_db_profile_persists_encrypted_and_never_changes_another_owner_or_access(db):
    a, b = client(), client()
    register(a, db); register(b, db, 'other@example.com')
    csrf = login(a); login(b, 'other@example.com')
    initial = a.get('/api/account/profile').json()
    assert initial['display_name'] == '' and initial['avatar_theme'] == 'sky'
    assert initial['email_verified'] is True
    assert initial['access']['subscription_required'] is False
    payload = {'display_name':'Лиза Тест','avatar_theme':'violet'}
    response = a.put('/api/account/profile', json=payload, headers={'X-CSRF-Token':csrf})
    assert response.status_code == 200 and response.json() == payload
    assert a.get('/api/account/profile').json()['display_name'] == payload['display_name']
    assert b.get('/api/account/profile').json()['display_name'] == ''
    with job_store.connect() as conn:
        row = conn.execute('SELECT ciphertext FROM privetek_account_profiles').fetchone()
        assert payload['display_name'].encode() not in bytes(row['ciphertext'])
        assert b'violet' not in bytes(row['ciphertext'])
        assert conn.execute('SELECT count(*) AS n FROM privetek_profile_search').fetchone()['n'] == 0
    for extra in ({'email':'other@example.com'},{'user_id':'other'},{'subscribed':True}):
        assert a.put('/api/account/profile', json={**payload,**extra}, headers={'X-CSRF-Token':csrf}).status_code == 422
    new = client(); login(new)
    assert new.get('/api/account/profile').json()['avatar_theme'] == 'violet'
    # Presentation settings can be removed without changing account identity.
    assert new.put('/api/account/profile', json={'display_name':'','avatar_theme':'sky'},
                   headers={'X-CSRF-Token':new.get('/api/account/me').json()['csrf_token']}).status_code == 200
    assert new.get('/api/account/me').json()['email'] == 'owner@example.com'
