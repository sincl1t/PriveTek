"""Multiple usernames are bounded, searched once and never merged as one person."""
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pypdf import PdfReader
import osint
import server
import account_routes
import acquisition
from search_inputs import normalize_usernames
from identity_resolution import build
from pdf_gen import create_report
from test_accounts import settings, db, client, register, login


def test_username_list_is_bounded_and_deduplicated_without_dropping_case_sensitive_handles():
    assert normalize_usernames(' @Example ',['Example','Other']) == ['Example','Other']
    assert normalize_usernames('Name',['name']) == ['Name','name']
    assert normalize_usernames('', ['Other','@Third']) == ['Other','Third']
    for extras in ['abc', ['a','b','c'], [123], ['https://example.com'], ['a b']]:
        with pytest.raises(ValueError): normalize_usernames('first',extras)


@pytest.mark.parametrize('payload', [
    {'AdditionalUsernames':['one','two','three']}, {'AdditionalUsernames':'one'},
    {'AdditionalUsernames':['../bad']}, {'Phone':'12345'}, {'Email':'not-an-email'},
])
def test_model_rejects_invalid_identifiers(payload):
    values={'Email':'fixture@example.com',**payload}
    with pytest.raises(ValidationError): server.Submission(**values)


def test_pipeline_searches_unique_handles_and_preserves_query_links(monkeypatch):
    calls=[]
    def fake_run(runner,handle):
        calls.append((runner,handle))
        if runner is osint.discovery.run:
            if handle=='Other':raise RuntimeError('private response')
            return []
        return [dict(source='GitHub',kind='username',status='found',profile_url='https://github.com/'+handle,reason='Exact handle')]
    monkeypatch.setattr(osint.trio,'run',fake_run)
    result=osint.search(username='@Example',additional_usernames=['Example','Other'])
    assert [handle for runner,handle in calls if runner is osint.run_profiles]==['Example','Other']
    checks=[row for row in result['checks'] if row['kind']=='username']
    assert {row['query_username'] for row in checks}=={'Example','Other'}
    assert any(row['status']=='unavailable' and row['query_username']=='Other' for row in checks)
    assert 'private response' not in str(result)
    snapshot=result['identity_resolution']
    assert len(snapshot['identifiers'])==2
    assert {row['identifier_id'] for row in snapshot['findings']}=={'identifier-username','identifier-username-2'}
    assert snapshot['automatic_person_merges']==0
    assert snapshot['coverage']['counts']['completed']==2
    assert snapshot['coverage']['counts']['unavailable']==len(osint.discovery.SOURCES)


def test_same_profile_from_two_queries_does_not_merge_query_edges():
    checks=[dict(source='GitHub',kind='username',status='found',profile_url='https://github.com/Canonical',query_username=name) for name in ['One','Two']]
    snapshot=build({'checks':checks},username='One',additional_usernames=['Two'])
    assert len(snapshot['findings'])==2
    assert len({row['identifier_id'] for row in snapshot['findings']})==2
    assert snapshot['owner_group']==[]


def test_report_labels_username_and_unavailable_status(tmp_path):
    data={'checks':[dict(source='GitHub',kind='username',status='found',query_username='AliasOne',profile_url='https://github.com/AliasOne',reason='Exact handle'),
                    dict(source='Scratch',kind='username',status='unavailable',query_username='AliasTwo',reason='Source unavailable')]}
    text=''.join(page.extract_text() for page in PdfReader(create_report(data,tmp_path)).pages)
    assert 'Проверялся username: AliasOne' in text
    assert 'Проверялся username: AliasTwo' in text
    assert 'Проверка недоступна' in text


def test_account_submission_passes_aliases_and_deduplicates_order(settings,monkeypatch):
    monkeypatch.setattr(acquisition,'enabled',lambda:False)
    monkeypatch.setattr(account_routes,'identify',lambda request,mutation=False:({'email':'fixture@example.com','id':'fixture','email_key':'fixture'},'token'))
    monkeypatch.setattr(server.email_sender,'validate_settings',lambda:None)
    monkeypatch.setattr(server.job_store,'record',lambda *args:None)
    thread=MagicMock();monkeypatch.setattr(server.threading,'Thread',thread)
    c=TestClient(server.app,base_url='https://privetek.test',headers={'Origin':'https://privetek.test'})
    try:
        first=c.post('/api/account/jobs',json={'username':'One','additional_usernames':['Two','@One'],'consent':True})
        assert first.status_code==202
        assert thread.call_args.kwargs['args'][0].AdditionalUsernames==['Two','One']
        duplicate=c.post('/api/account/jobs',json={'username':'Two','additional_usernames':['One'],'consent':True})
        assert duplicate.status_code==202 and duplicate.json()['duplicate'] is True
        assert duplicate.json()['job_id']==first.json()['job_id']
        assert thread.call_count==1
        bad=c.post('/api/account/jobs',json={'additional_usernames':['a','b','c'],'consent':True})
        assert bad.status_code==422 and thread.call_count==1
        no_consent=c.post('/api/account/jobs',json={'additional_usernames':['a'],'consent':False})
        assert no_consent.status_code==422
    finally:
        if thread.call_count:server.slots.release()


def test_db_coverage_is_encrypted_owner_scoped_and_survives_review(db,tmp_path):
    import account_store,job_store
    owner=client();register(owner,db);csrf=login(owner)
    job='c'*32;job_store.record(job,'accepted','owner@example.com')
    snapshot=build({'checks':[dict(source='GitHub',kind='username',status='found',query_username='Two',profile_url='https://github.com/Two',reason='Exact handle')]},username='One',additional_usernames=['Two'])
    pdf=tmp_path/'fixture.pdf';pdf.write_bytes(b'%PDF-1.3\nsynthetic')
    account_store.save_report(job,pdf,snapshot)
    path='/api/account/jobs/'+job+'/identity'
    saved=owner.get(path);assert saved.status_code==200
    assert saved.json()['coverage']['entries'][0]['query_username']=='Two'
    changed=owner.put(path,json={'revision':1,'item_id':snapshot['findings'][0]['id'],'decision':'mine'},headers={'X-CSRF-Token':csrf})
    assert changed.status_code==200 and changed.json()['coverage']==snapshot['coverage']
    assert client().get(path).status_code==401
    other=client();register(other,db,'other@example.com');login(other,'other@example.com')
    assert other.get(path).status_code==404
    with job_store.connect() as connection:
        row=connection.execute('SELECT identity_ciphertext FROM privetek_account_reports WHERE job_id=%s',(job,)).fetchone()
        assert b'Exact handle' not in bytes(row['identity_ciphertext'])
