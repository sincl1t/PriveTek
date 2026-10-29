import json
from unittest.mock import MagicMock
import pytest
import httpx
import ai_summary as ai
import analysis_layer as a
from test_analysis_layer import data


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv('AI_SUMMARY_ENABLED','true');monkeypatch.setenv('AI_DATA_TRANSFER_APPROVED','true')
    monkeypatch.setenv('OPENAI_API_KEY','test-key-never-send');monkeypatch.setenv('AI_SUMMARY_MODEL','test-model')
    monkeypatch.setenv('AI_MAX_CALLS_PER_HOUR','2')
    import account_store
    monkeypatch.setattr(account_store,'quota',lambda items:True)


def test_disabled_never_reads_database_or_calls_provider(monkeypatch):
    monkeypatch.delenv('AI_SUMMARY_ENABLED',raising=False)
    call=MagicMock(side_effect=AssertionError('No network'));monkeypatch.setattr(ai.httpx,'Client',call)
    assert ai.select(a.analyze(data()))=={'status':'disabled'}
    call.assert_not_called()


@pytest.mark.parametrize('name,value',[('AI_DATA_TRANSFER_APPROVED','false'),('AI_SUMMARY_MODEL',''),('OPENAI_API_KEY',''),('AI_MAX_CALLS_PER_HOUR','0'),('AI_MAX_CALLS_PER_HOUR','bad')])
def test_configuration_fail_closed(enabled,monkeypatch,name,value):
    monkeypatch.setenv(name,value)
    monkeypatch.setattr(ai.httpx,'Client',MagicMock(side_effect=AssertionError('No network')))
    assert ai.select(a.analyze(data()))['status']=='not_configured'


@pytest.mark.parametrize('value',[{'fact_ids':['made-up']},{'fact_ids':['F1','F1']},{'fact_ids':[]},{'fact_ids':['F1'],'summary':'You were hacked'},{'fact_ids':[True]},[]])
def test_unknown_hallucinated_or_freeform_output_rejected(value):
    assert not ai.validate_selection(value,a.analyze(data(classes=['Passwords'])))


def test_request_contains_only_sanitized_facts_and_strict_format():
    analysis=a.analyze(data(classes=['Passwords']))
    payload=ai.request_body(analysis,'test-model')
    assert payload['store'] is False and payload['max_output_tokens']==512
    assert payload['text']['format']['strict'] is True
    assert 'private@example.com' not in payload['input'] and 'github.com' not in payload['input']
    assert set(json.loads(payload['input'])['findings'][0])=={'fact_id','category','evidence','ownership','priority','reason_code','classes_scope','record_count','classes'}


def test_success_and_invalid_json_have_safe_fallback(enabled,monkeypatch):
    real_client=httpx.Client
    analysis=a.analyze(data(classes=['Passwords']))
    output={'status':'completed','output':[{'type':'message','role':'assistant','content':[{'type':'output_text','text':json.dumps({'fact_ids':['F1']})}]}]}
    def handler(request):
        assert str(request.url)==ai.ENDPOINT and request.method=='POST'
        assert request.headers['authorization']=='Bearer test-key-never-send'
        return httpx.Response(200,json=output)
    monkeypatch.setattr(ai.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(handler),**kwargs))
    result=ai.select(analysis)
    assert result=={'status':'selected','fact_ids':['F1']} and ai.display_ids(result,analysis)==['F1']
    output['status']='incomplete'
    assert ai.select(analysis)['status']=='rejected'


def test_quota_prevents_provider_call(enabled,monkeypatch):
    import account_store
    monkeypatch.setattr(account_store,'quota',lambda items:False)
    monkeypatch.setattr(ai.httpx,'Client',MagicMock(side_effect=AssertionError('No network')))
    assert ai.select(a.analyze(data(classes=['Passwords'])))['status']=='rate_limited'


def test_saved_selection_invalidated_after_user_exclusion():
    raw=data(classes=['Passwords']);analysis=a.analyze(raw)
    stored={'status':'selected','fact_ids':['F1']}
    assert ai.display_ids(stored,analysis)==['F1']
    raw['identity_resolution']['findings'][0]['decision']='not_mine'
    assert ai.display_ids(stored,a.analyze(raw)) is None


def test_high_priority_cannot_be_omitted():
    analysis=a.analyze(data(classes=['Passwords']))
    other=dict(analysis['items'][0],fact_id='F2',priority='informational');analysis['items'].append(other)
    assert not ai.validate_selection({'fact_ids':['F2']},analysis)
    assert ai.validate_selection({'fact_ids':['F1','F2']},analysis)


@pytest.mark.parametrize('status',[302,401,429,500])
def test_provider_errors_fall_back_without_retry(enabled,monkeypatch,status):
    real_client=httpx.Client;seen=[]
    def handler(request):
        seen.append(request)
        return httpx.Response(status,headers={'Location':'https://foreign.invalid/'},json={'error':'private provider detail'})
    monkeypatch.setattr(ai.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(handler),**kwargs))
    result=ai.select(a.analyze(data(classes=['Passwords'])))
    assert result=={'status':'unavailable'} and len(seen)==1


def test_timeout_does_not_break_rule_report(enabled,monkeypatch):
    real_client=httpx.Client
    def handler(request):raise httpx.ReadTimeout('private API key',request=request)
    monkeypatch.setattr(ai.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(handler),**kwargs))
    analysis=a.analyze(data(classes=['Passwords']))
    assert ai.select(analysis)=={'status':'unavailable'}
    assert a.lines(analysis) and analysis['priorities']['high']==1
