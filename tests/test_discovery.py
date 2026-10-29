import json
import httpx
import pytest
import trio
import discovery as d
import osint
from report_data import prepare

BODIES = {
    'Roblox': {'data': [{'requestedUsername': 'builderman', 'name': 'builderman', 'id': 156, 'displayName': 'ignored'}]},
    'Scratch': {'id': 167, 'username': 'mres', 'profile': {'bio': 'must-not-persist'}},
    'Codewars': {'id': '545207bac8e60b30fc000942', 'username': 'g964', 'name': 'must-not-persist'},
}
MISSES = {'Roblox': (200, {'data': []}), 'Scratch': (404, {'code': 'NotFound', 'message': ''}), 'Codewars': (404, {'success': False, 'reason': 'not found'})}


@pytest.fixture(autouse=True)
def limits(monkeypatch):
    monkeypatch.setattr(d, '_next_request', {})


def invoke(source, status=200, payload=None, raw=None, headers=None, username=None):
    seen = []
    async def runner():
        def handler(request):
            method, url, kwargs = d.request_spec(source[0], username or source[3])
            assert request.method == method and str(request.url) == url
            assert 'cookie' not in request.headers and 'authorization' not in request.headers
            if method == 'POST':
                assert json.loads(request.content) == kwargs['json']
            seen.append(request)
            return httpx.Response(status, json=payload, headers=headers) if raw is None else httpx.Response(status, content=raw, headers=headers)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
            return await d.check(source, username or source[3], client)
    return trio.run(runner), seen


@pytest.mark.parametrize('source', d.SOURCES, ids=lambda s: s[0])
def test_exact_profile_minimal_result(source):
    result, requests = invoke(source, payload=BODIES[source[0]])
    assert result['status'] == 'found' and len(requests) == 1
    assert result['profile_url'].startswith(source[1])
    assert 'must-not-persist' not in json.dumps(result)
    assert result['method'] == 'public_account_lookup' and result['checked_at']
    assert 'не подтверждает' in result['reason']
    check = prepare({'checks': [result]})['checks'][0]
    assert check['source_url'] == source[1]


@pytest.mark.parametrize('source', d.SOURCES, ids=lambda s: s[0])
def test_recognized_negative(source):
    code, body = MISSES[source[0]]
    result, _ = invoke(source, code, body)
    assert result['status'] == 'not_found' and result['profile_url'] is None


@pytest.mark.parametrize('source', d.SOURCES, ids=lambda s: s[0])
@pytest.mark.parametrize('status', [200, 404, 403, 429, 503])
def test_challenge_never_means_absence(source, status):
    result, _ = invoke(source, status, raw=b'<html>CAPTCHA</html>', headers={'Content-Type': 'text/html'})
    assert result['status'] == 'unavailable'


@pytest.mark.parametrize('source', d.SOURCES, ids=lambda s: s[0])
@pytest.mark.parametrize('payload', [{}, [], None, {'errors': []}, {'id': True, 'username': 'mres'}])
def test_bad_schemas_never_found(source, payload):
    assert invoke(source, payload=payload)[0]['status'] == 'unavailable'


@pytest.mark.parametrize('source', d.SOURCES, ids=lambda s: s[0])
def test_wrong_username_not_found_as_match(source):
    assert invoke(source, payload=BODIES[source[0]], username='other123')[0]['status'] == 'unavailable'


def test_roblox_requested_name_and_display_name_are_not_identity():
    source = d.SOURCES[0]
    for row in [dict(id=156, name='other', requestedUsername='builderman', displayName='builderman'),
                dict(id=156, name='builderman', requestedUsername='other'),
                dict(id=True, name='builderman', requestedUsername='builderman')]:
        d._next_request.clear()
        assert invoke(source, payload={'data': [row]})[0]['status'] == 'unavailable'


@pytest.mark.parametrize('source', d.SOURCES, ids=lambda s: s[0])
def test_invalid_handle_never_requests(source):
    result, seen = invoke(source, username='https://evil.example/a')
    assert result['status'] == 'skipped' and not seen
    assert result['checked_at'] is None


@pytest.mark.parametrize('source', d.SOURCES, ids=lambda s: s[0])
def test_redirect_is_not_followed(source):
    result, seen = invoke(source, 302, raw=b'', headers={'Location': 'https://evil.example/'})
    assert result['status'] == 'unavailable' and len(seen) == 1


def test_size_bound_and_json_content_type():
    assert invoke(d.SOURCES[0], raw=b' ' * (d.MAX_BYTES + 1), headers={'Content-Type': 'application/json'})[0]['status'] == 'unavailable'
    d._next_request.clear()
    assert invoke(d.SOURCES[0], raw=b'{bad}', headers={'Content-Type': 'application/json'})[0]['status'] == 'unavailable'


def test_per_source_rate_and_backoff(monkeypatch):
    monkeypatch.setattr(d.time, 'monotonic', lambda: 100)
    assert d.reserve('Roblox') and not d.reserve('Roblox')
    assert d.reserve('Scratch')
    d.backoff('Roblox', '120')
    monkeypatch.setattr(d.time, 'monotonic', lambda: 102)
    assert not d.reserve('Roblox') and d.reserve('Scratch')
    monkeypatch.setattr(d.time, 'monotonic', lambda: 221)
    assert d.reserve('Roblox')


def test_429_sets_pause_without_retry():
    result, seen = invoke(d.SOURCES[0], 429, raw=b'', headers={'Retry-After': '120'})
    assert result['status'] == 'unavailable' and len(seen) == 1
    assert not d.reserve('Roblox')


def test_search_includes_discovery_and_pdf_metadata(monkeypatch):
    def fake_run(function, *args):
        if function is osint.run_profiles:
            return []
        assert function is d.run
        return [dict(source='Roblox', kind='username', status='found', profile_url='https://www.roblox.com/users/156/profile')]
    monkeypatch.setattr(osint.trio, 'run', fake_run)
    result = osint.search(username='builderman')
    assert result['username_profiles'] == [{'site': 'Roblox', 'profile_url': 'https://www.roblox.com/users/156/profile'}]
    assert result['checks'][-1]['source_url'] == 'https://www.roblox.com/'


def test_missing_username_marks_discovery_skipped():
    result = osint.search()
    for source in d.SOURCES:
        assert any(c['source'] == source[0] and c['status'] == 'skipped' for c in result['checks'])


def test_probe_only_confirms_positive_and_negative(monkeypatch):
    async def fake(username=None, fixtures=False):
        return [dict(source=s[0], status='found' if fixtures else ('unavailable' if s[0] == 'Scratch' else 'not_found')) for s in d.SOURCES]
    async def no_sleep(seconds): pass
    monkeypatch.setattr(d, 'run', fake)
    monkeypatch.setattr(d.trio, 'sleep', no_sleep)
    result = trio.run(d.probe)
    assert result['verified_sources'] == 2 and result['total_sources'] == 3
    assert result['sources'][1]['verified'] is False


def test_pdf_contains_all_discovery_sources_and_profile_links(tmp_path):
    from pypdf import PdfReader
    from pdf_gen import create_report
    checks=[]
    for source in d.SOURCES:
        state, url = d.classify(source[0], source[3], 200, BODIES[source[0]])
        checks.append(dict(source=source[0],kind='username',status=state,profile_url=url,reason='Точное имя; личность не подтверждена.'))
    text=''.join(page.extract_text() for page in PdfReader(create_report(prepare({'checks':checks}),tmp_path)).pages)
    for source in d.SOURCES:
        assert source[0] in text
    assert 'https://www.roblox.com/users/156/profile' in text
    assert 'https://scratch.mit.edu/users/mres/' in text


def test_timeout_is_unavailable_and_does_not_leak_error():
    async def runner():
        def handler(request):
            raise httpx.ReadTimeout('private-username request detail', request=request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await d.check(d.SOURCES[0], 'builderman', client)
    result=trio.run(runner)
    assert result['status']=='unavailable' and 'private-username' not in json.dumps(result)


def test_rate_reservation_is_atomic():
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:d.reserve('Roblox'), range(8)))
    assert results.count(True)==1
