import httpx
import pytest

import counterparty


@pytest.mark.parametrize(('identifier', 'expected'), [
    ('7719402047', 'inn'), ('1157746078984', 'ogrn'),
    ('7719402048', None), ('1157746078985', None),
    ('500100732259', None), ('304500116000157', None),
])
def test_company_identifiers(identifier, expected):
    if expected is None:
        with pytest.raises(ValueError):
            counterparty.company_identifier(identifier)
    else:
        assert counterparty.company_identifier(identifier) == (expected, identifier)


@pytest.mark.parametrize(('suggestions', 'status_code', 'outcome'), [
    ([], 200, 'not_found'),
    ([], 429, 'unavailable'),
    ([{'data': {'inn': '7719402047', 'type': 'INDIVIDUAL', 'branch_type': 'MAIN'}}], 200, 'unavailable'),
    ([{'data': {'inn': '7719402048', 'type': 'LEGAL', 'branch_type': 'MAIN'}}], 200, 'unavailable'),
])
def test_counterparty_coverage(monkeypatch, suggestions, status_code, outcome):
    def respond(url, **kwargs):
        return httpx.Response(status_code, request=httpx.Request('POST', url),
                              json={'suggestions': suggestions})
    monkeypatch.setattr(counterparty.httpx, 'post', respond)
    assert counterparty.assess('inn', '7719402047', 'test')['outcome'] == outcome


def test_counterparty_discards_personal_fields(monkeypatch):
    def respond(url, **kwargs):
        assert kwargs['json'] == {'query': '7719402047', 'type': 'LEGAL', 'branch_type': 'MAIN'}
        return httpx.Response(200, request=httpx.Request('POST', url), json={'suggestions': [{
            'value': 'Test name',
            'data': {'inn': '7719402047', 'type': 'LEGAL', 'branch_type': 'MAIN',
                     'state': {'status': 'LIQUIDATING'}, 'management': {'name': 'Test person'},
                     'phones': ['Test phone'], 'address': 'Test address'},
        }]})
    monkeypatch.setattr(counterparty.httpx, 'post', respond)
    result = counterparty.assess('inn', '7719402047', 'test')
    assert set(result) == {'outcome', 'status', 'signals', 'source', 'source_url', 'checked_at'}
    assert result['outcome'] == 'found'
    assert result['signals']
    assert 'Test' not in str(result)
