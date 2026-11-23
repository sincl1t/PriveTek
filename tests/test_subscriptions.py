from copy import deepcopy
from unittest.mock import MagicMock
import os
import shutil
import subprocess
from pathlib import Path
import pytest
import subscription_store as subs
import account_store
import account_crypto
import job_store
from account_routes import COOKIE
from test_accounts import client, settings, db, register, login  # noqa: F401


def sample():
    return dict(revision=0,items=[dict(id='sample',merchant='Demo',amount='499.00',currency='RUB',period='monthly',last_date='2026-01-31',status='review')])


@pytest.mark.parametrize('change',[
    {'amount':'NaN'},{'amount':'-1'},{'amount':'10000001'},{'amount':'1e3'},
    {'merchant':'x'*101},{'merchant':'private\ntext'},{'currency':'ZZZ'},
    {'period':'daily'},{'status':'verified_by_bank'},{'last_date':'2026-02-30'},
    {'raw_transactions':['must not store']},{'user_id':'another-owner'},
])
def test_reject_unexpected_or_invalid_metadata(change):
    data=sample();data['items'][0].update(change)
    with pytest.raises(ValueError):subs.normalize(data)


def test_owner_bound_cipher(settings):
    row=dict(revision=1,ciphertext=account_crypto.report_cipher().encrypt(b'{"user_id":"owner","items":[]}'))
    assert subs.decode('owner',row)==dict(revision=1,items=[])
    with pytest.raises(ValueError):subs.decode('other-owner',row)


def test_api_security_and_validation(settings,monkeypatch):
    c=client();assert c.get('/api/account/subscriptions').status_code==401
    assert c.put('/api/account/subscriptions',json=sample()).status_code==401
    monkeypatch.setattr(account_store,'session',lambda _:dict(id='owner',email='owner@example.com'))
    c.cookies.set(COOKIE,'x'*43);save=MagicMock();monkeypatch.setattr(subs,'save',save)
    assert c.put('/api/account/subscriptions',json=sample()).status_code==403
    headers={'x-csrf-token':account_crypto.digest('csrf','x'*43)}
    assert c.put('/api/account/subscriptions',json=sample(),headers={**headers,'Origin':'https://evil.test'}).status_code==403
    bad=sample();bad['items'][0]['raw_transactions']=[]
    assert c.put('/api/account/subscriptions',json=bad,headers=headers).status_code==422
    save.assert_not_called()
    monkeypatch.setattr(subs,'save',MagicMock(side_effect=subs.Conflict()))
    assert c.put('/api/account/subscriptions',json=sample(),headers=headers).status_code==409
    monkeypatch.setattr(subs,'read',MagicMock(side_effect=RuntimeError('SECRET DATA')))
    result=c.get('/api/account/subscriptions');assert result.status_code==503 and 'SECRET' not in result.text


def test_native_encrypted_persistence_and_conflict(db,settings):
    c=client();register(c,db);register(client(),db,'other@example.com')
    with job_store.connect() as connection:
        owner=connection.execute("SELECT id FROM privetek_users WHERE email='owner@example.com'").fetchone()['id']
        other=connection.execute("SELECT id FROM privetek_users WHERE email='other@example.com'").fetchone()['id']
    assert subs.read(owner)==dict(items=[],revision=0)
    saved=subs.save(owner,sample());assert saved['revision']==1
    assert subs.read(owner)==saved and subs.read(other)['items']==[]
    with job_store.connect() as connection:
        raw=bytes(connection.execute('SELECT ciphertext FROM privetek_subscription_lists WHERE user_id=%s',(owner,)).fetchone()['ciphertext'])
        assert b'Demo' not in raw and b'499' not in raw
    with pytest.raises(subs.Conflict):subs.save(owner,sample())
    empty=subs.save(owner,dict(revision=1,items=[]));assert empty==dict(revision=2,items=[])
    csrf=login(c);response=c.put('/api/account/subscriptions',json=dict(revision=2,items=sample()['items']),headers={'x-csrf-token':csrf})
    assert response.status_code==200 and c.get('/api/account/subscriptions').json()['items'][0]['merchant']=='Demo'


def test_local_csv_analyzer():
    node=os.getenv('SUBSCRIPTIONS_TEST_NODE') or shutil.which('node')
    if not node:pytest.skip('Node.js needed for local CSV checks')
    run=subprocess.run([node,str(Path(__file__).parent/'js/subscriptions.test.cjs')],capture_output=True,text=True,timeout=15)
    assert run.returncode==0,run.stdout+run.stderr


def test_subscription_api_accepts_bounded_list_larger_than_auth_payload(settings,monkeypatch):
    c=client();c.cookies.set(COOKIE,'x'*43)
    monkeypatch.setattr(account_store,'session',lambda _:dict(id='owner',email='owner@example.com'))
    monkeypatch.setattr(subs,'save',lambda owner,data:dict(data,revision=1))
    data=sample();data['items']=[dict(data['items'][0],id=str(i)) for i in range(40)]
    headers={'x-csrf-token':account_crypto.digest('csrf','x'*43)}
    assert c.put('/api/account/subscriptions',json=data,headers=headers).status_code==200
    assert c.put('/api/account/subscriptions',content='x'*65537,headers={**headers,'Content-Type':'application/json'}).status_code==413
