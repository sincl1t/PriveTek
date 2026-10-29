import importlib.util
from pathlib import Path
from unittest.mock import MagicMock
import pytest

spec=importlib.util.spec_from_file_location('monitor_runner',Path(__file__).resolve().parents[1]/'tools/run_monitor.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


def test_missing_credential_never_calls_network(monkeypatch):
    monkeypatch.delenv('MONITOR_RUNNER_TOKEN',raising=False)
    call=MagicMock(side_effect=AssertionError('No network'));monkeypatch.setattr(r.urllib.request,'build_opener',call)
    with pytest.raises(RuntimeError):r.main()
    call.assert_not_called()


def test_runner_fixed_endpoint_and_stops_when_idle(monkeypatch,capsys):
    monkeypatch.setenv('MONITOR_RUNNER_TOKEN','test-only-'+'x'*40)
    monkeypatch.setattr(r.signal,'signal',lambda *args:None);alarms=[];monkeypatch.setattr(r.signal,'alarm',alarms.append)
    response=MagicMock();response.__enter__.return_value=response;response.read.return_value=b'{"operation":"idle"}'
    opener=MagicMock();opener.open.return_value=response;monkeypatch.setattr(r.urllib.request,'build_opener',lambda *args:opener)
    r.main();request=opener.open.call_args.args[0]
    assert request.full_url==r.URL and request.method=='POST' and request.data==b'{}'
    assert request.get_header('Authorization').startswith('Bearer test-only-')
    assert opener.open.call_count==1 and alarms==[600,0]
    assert 'test-only-' not in capsys.readouterr().out
