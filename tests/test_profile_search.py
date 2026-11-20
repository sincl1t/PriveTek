import pytest

import job_store
import profile_search
from test_accounts import client, db, login, register, settings  # noqa: F401


def test_profile_search_disabled_by_default(settings, monkeypatch):
    monkeypatch.delenv('PROFILE_SEARCH_ENABLED', raising=False)
    assert client().get('/api/account/profile-search').status_code == 404


def test_db_profile_search_repeat_without_subscription(db, monkeypatch):
    monkeypatch.setenv('PROFILE_SEARCH_ENABLED', 'true')
    c = client()
    register(c, db)
    csrf = login(c)
    url = '/api/account/profile-search'
    headers = {'X-CSRF-Token': csrf}
    body = {'username': 'blue', 'consent': True}
    calls = []

    async def search(username):
        calls.append(username)
        status = 'unavailable' if len(calls) == 1 else 'found'
        return [{'site': 'RubyGems', 'status': status,
                 'url': 'https://rubygems.org/profiles/blue' if status == 'found' else None}]

    monkeypatch.setattr(profile_search, 'search', search)
    assert c.get(url).json()['free_available']
    assert client().get(url).status_code == 401
    assert c.post(url, json=body).status_code == 403
    assert c.post(url, json={**body, 'consent': False}, headers=headers).status_code == 422
    assert c.post(url, json=body, headers=headers).status_code == 503
    assert c.get(url).json()['free_available']
    response = c.post(url, json=body, headers=headers)
    assert response.status_code == 200
    assert not response.json()['free_available']
    assert response.json() == c.get(url).json()
    assert c.post(url, json=body, headers=headers).status_code == 200
    assert len(calls) == 3
    with job_store.connect() as conn:
        saved = conn.execute('SELECT ciphertext FROM privetek_profile_search').fetchone()
        assert b'rubygems.org' not in bytes(saved['ciphertext'])
        conn.execute("UPDATE privetek_profile_search SET access_until=now()+interval '1 day'")
    assert c.post(url, json=body, headers=headers).status_code == 200
    with job_store.connect() as conn:
        conn.execute("UPDATE privetek_profile_search SET access_until=now()-interval '1 minute'")
    assert c.post(url, json=body, headers=headers).status_code == 200


def test_search_uses_all_username_sources_and_preserves_unavailable(monkeypatch):
    import asyncio

    async def check(source, username, _client):
        assert username == 'octocat'
        if source[0] == 'GitHub':
            return {'status': 'found', 'profile_url': 'https://github.com/octocat'}
        if source[0] == 'Roblox':
            raise RuntimeError('test outage')
        return {'status': 'skipped'}

    async def direct(source, username, _client):
        assert username == 'octocat'
        if source[0] == 'GitHub':
            return {'status': 'found', 'profile_url': 'https://github.com/octocat'}
        return {'status': 'not_found'}

    monkeypatch.setattr(profile_search.public_sources, 'check_profile', check)
    monkeypatch.setattr(profile_search.discovery, 'check', check)
    monkeypatch.setattr(profile_search, 'public_page', direct)
    rows = asyncio.run(profile_search.search('octocat'))
    assert len(rows) == len({row['site'] for row in rows}) == 17
    assert rows[0] == {'site': 'GitHub', 'status': 'found', 'url': 'https://github.com/octocat'}
    assert {row['site']: row['status'] for row in rows}['Roblox'] == 'unavailable'
    assert rows[-1] == {'site': 'RubyGems', 'status': 'not_found', 'url': None}



@pytest.mark.parametrize(('site', 'response', 'expected'), [
    (('GitHub', 'https://github.com/{username}', '[a-z0-9]+'),
     (200, '<meta name="octolytics-dimension-user_login" content="octocat"><meta property="og:url" content="https://github.com/octocat">'), 'found'),
    (('GitHub', 'https://github.com/{username}', '[a-z0-9]+'), (403, 'blocked'), 'unavailable'),
    (profile_search.EXTRA_SOURCES[1], (200, '<title>octocat | OpenStreetMap</title>'), 'found'),
    (profile_search.EXTRA_SOURCES[2], (200, '<title>Profile of octocat | RubyGems.org</title>'), 'found'),
    (profile_search.EXTRA_SOURCES[2], (200, '<title>Just a moment</title>'), 'unavailable'),
    (profile_search.EXTRA_SOURCES[1], (404, ''), 'not_found'),
    (profile_search.EXTRA_SOURCES[0], (400, '{"error":"InvalidRequest","message":"Profile not found"}'), 'not_found'),
    (profile_search.EXTRA_SOURCES[0], (400, '{"error":"InvalidRequest","message":"Invalid actor"}'), 'unavailable'),
])
def test_chat_public_source_rejects_unrecognized_responses(site, response, expected):
    import httpx
    import trio

    async def check():
        code, content = response
        def respond(request):
            assert request.headers.get('accept') == ('*/*' if site[0] == 'Bluesky' else 'text/html')
            return httpx.Response(code, text=content, headers={'content-type': 'text/html'})

        mock = httpx.MockTransport(respond)
        async with httpx.AsyncClient(transport=mock) as client:
            return await profile_search.public_page(site, 'octocat', client)

    result = trio.run(check)
    assert result['status'] == expected
    assert bool(result.get('profile_url')) == (expected == 'found')
