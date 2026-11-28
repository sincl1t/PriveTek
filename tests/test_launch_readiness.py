import importlib.util
from pathlib import Path
from unittest.mock import MagicMock
import httpx
import pytest
import hibp_client as hibp
import sms_provider
from test_accounts import settings, db  # noqa: F401


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


@pytest.mark.parametrize('status,payload,expected',[(200,[{'Name':'Synthetic','DataClasses':['Passwords']}],'found'),(404,None,'not_found'),(401,None,'unavailable'),(403,None,'unavailable'),(429,None,'unavailable'),(503,None,'unavailable'),(200,{},'unavailable'),(200,[],'unavailable')])
def test_hibp_statuses_never_treat_failure_as_absence(monkeypatch,status,payload,expected):
    monkeypatch.setattr(hibp,'_next_request',0)
    monkeypatch.setattr(hibp.httpx,'get',lambda *a,**k:httpx.Response(status,json=payload))
    rows,check=hibp.lookup('account-exists@hibp-integration-tests.com',api_key='0'*32)
    assert check['status']==expected
    if expected=='unavailable':assert rows is None


def test_hibp_disabled_and_cooldown_do_not_call_provider(monkeypatch):
    monkeypatch.setenv('HIBP_ENABLED','false');call=MagicMock();monkeypatch.setattr(hibp.httpx,'get',call)
    assert hibp.lookup('private@example.com')[1]['status']=='skipped';call.assert_not_called()
    monkeypatch.setattr(hibp,'_next_request',0)
    call.return_value=httpx.Response(429,headers={'retry-after':'30'})
    assert hibp.lookup('account-exists@hibp-integration-tests.com',api_key='0'*32)[1]['status']=='unavailable'
    assert hibp.lookup('account-exists@hibp-integration-tests.com',api_key='0'*32)[1]['status']=='unavailable'
    assert call.call_count==1


def test_sms_cannot_send_with_only_one_flag(monkeypatch):
    monkeypatch.setenv('SMS_AUTH_ENABLED','true');monkeypatch.setenv('SMS_LIVE_SEND_ENABLED','false')
    call=MagicMock();monkeypatch.setattr(sms_provider.httpx,'post',call)
    with pytest.raises(sms_provider.SmsUnavailable):sms_provider.send_code('+12025550123','12345678')
    call.assert_not_called()


def test_sms_provider_posts_no_secret_in_url_and_never_retries(monkeypatch):
    monkeypatch.setattr(sms_provider,'configured',lambda:True);monkeypatch.setenv('SMS_RU_API_ID','private-key')
    call=MagicMock(return_value=httpx.Response(200,json={'status':'OK','sms':{'12025550123':{'status':'OK','status_code':100}}}))
    monkeypatch.setattr(sms_provider.httpx,'post',call);sms_provider.send_code('+12025550123','12345678')
    args=call.call_args;assert args.args==('https://sms.ru/sms/send',) and args.kwargs['follow_redirects'] is False
    assert args.kwargs['data']['to']=='12025550123'
    call.reset_mock();call.return_value=httpx.Response(503,text='private response')
    with pytest.raises(sms_provider.SmsUnavailable) as error:sms_provider.send_code('+12025550123','12345678')
    assert 'private' not in str(error.value) and call.call_count==1


def test_readiness_default_never_uses_provider_or_database(monkeypatch):
    import job_store
    call=MagicMock(side_effect=AssertionError('No DB'))
    monkeypatch.setattr(job_store,'connect',call)
    r=load('readiness','tools/launch_readiness.py').report()
    assert r['no_provider_calls'] and not r['database_checked'];call.assert_not_called()


def test_monitor_preflight_only_reads_status(monkeypatch,capsys):
    r=load('monitor_preflight','tools/run_monitor.py');monkeypatch.setenv('MONITOR_RUNNER_TOKEN','test-'+'x'*40)
    response=MagicMock();response.__enter__.return_value=response;response.read.return_value=b'{"ready":true}'
    opener=MagicMock();opener.open.return_value=response;monkeypatch.setattr(r.urllib.request,'build_opener',lambda *a:opener)
    r.main(check=True);request=opener.open.call_args.args[0]
    assert request.get_method()=='GET' and request.full_url.endswith('/monitor/status')
    assert 'test-' not in capsys.readouterr().out


def test_pilot_window_is_read_only_by_default_and_refuses_active_monitoring(db,monkeypatch):
    import job_store
    window=load('pilot_window','tools/monitor_pilot_window.py')
    monkeypatch.setenv('MONITOR_ENABLED','false')
    with job_store.connect() as conn:
        conn.execute('DELETE FROM privetek_monitors')
        before=conn.execute('SELECT ends_at FROM privetek_monitor_pilot WHERE id=1').fetchone()['ends_at']
    assert not window.run()['applied']
    with job_store.connect() as conn:assert conn.execute('SELECT ends_at FROM privetek_monitor_pilot WHERE id=1').fetchone()['ends_at']==before
    assert window.run(days=7,apply=True)['applied']
    monkeypatch.setenv('MONITOR_ENABLED','true')
    with pytest.raises(ValueError):window.run(apply=True)
