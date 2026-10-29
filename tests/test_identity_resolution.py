from copy import deepcopy
import json
from concurrent.futures import ThreadPoolExecutor
import os
import pytest
from pypdf import PdfReader
import identity_resolution as identity
import account_store as store
import account_crypto as crypto
import job_store
from test_accounts import settings, db, client, register, login, PASSWORD


def snapshot():
    rows=[dict(source='GitHub',kind='username',status='found',profile_url='https://github.com/Example',reason='Exact username'),
          dict(source='Amazon',kind='email',status='possible'),
          dict(source='Amazon',kind='phone',status='possible'),
          dict(source='LeakCheck',kind='breach',status='found'),
          dict(source='Scratch',kind='username',status='unavailable')]
    return identity.build({'checks':rows}, 'Owner@Example.com', '+1 (202) 555-0123', '@Example')


def test_queries_are_not_person_unions():
    result=snapshot()
    assert len(result['identifiers'])==3 and len(result['findings'])==4
    assert result['owner_group']==[] and result['automatic_person_merges']==0
    assert result['summary']=={'mine':0,'not_mine':0,'unreviewed':7}
    assert all(edge['relation']=='matched_query_only' for edge in result['edges'])
    amazon=[x for x in result['findings'] if x['source']=='Amazon']
    assert len(amazon)==2 and amazon[0]['id']!=amazon[1]['id']
    assert 'Owner@Example.com' not in json.dumps(result) and '+12025550123' not in json.dumps(result)


def test_user_decisions_are_explicit_reversible_and_no_propagation():
    before=snapshot();original=deepcopy(before)
    marked=identity.decide(before,'identifier-username','mine')
    assert marked['owner_group']==['identifier-username'] and marked['revision']==2
    assert all(item['decision']=='unreviewed' for item in marked['findings'])
    node=marked['findings'][0]['id'];marked=identity.decide(marked,node,'not_mine')
    assert node not in marked['owner_group'] and marked['summary']['not_mine']==1
    cleared=identity.decide(marked,'identifier-username','unreviewed')
    assert cleared['owner_group']==[] and before==original


@pytest.mark.parametrize('item,decision',[('unknown','mine'),('identifier-email','verified'),('identifier-email',None)])
def test_unknown_item_or_claim_rejected(item,decision):
    with pytest.raises(ValueError):identity.decide(snapshot(),item,decision)


def test_same_account_dedup_keeps_distinct_observations_and_other_profiles():
    row=dict(source='GitHub',kind='username',status='found',profile_url='https://github.com/example/',reason='First',checked_at='2026-10-29T12:00:00Z')
    rows=[row,dict(row),dict(row,profile_url='https://github.com/example#bio',reason='Second'),dict(row,profile_url='https://github.com/another')]
    result=identity.build({'checks':rows},username='example')
    assert len(result['findings'])==2
    assert len(result['findings'][0]['observations'])==2
    assert result['owner_group']==[]


@pytest.mark.parametrize('url',['http://github.com/example','https://evil.example/example','https://github.com@evil.example/example','https://github.com:444/example','javascript:alert(1)',None])
def test_untrusted_profile_urls_not_linked(url):
    result=identity.build({'checks':[dict(source='GitHub',kind='username',status='found',profile_url=url)]},username='example')
    assert not result['findings']


def test_unavailable_and_negative_are_not_candidates():
    for status in ['not_found','unavailable','unknown','skipped','disabled']:
        result=identity.build({'checks':[dict(source='Amazon',kind='email',status=status)]},email='owner@example.com')
        assert not result['findings']


def test_empty_inputs_and_bounded_graph():
    assert identity.build({})['identifiers']==[]
    rows=[dict(source='Site'+str(i),kind='email',status='possible') for i in range(identity.MAX_ITEMS+5)]
    result=identity.build({'checks':rows},email='owner@example.com')
    assert len(result['findings'])==identity.MAX_ITEMS and result['omitted']==5


def test_pdf_original_and_updated_card_labels(tmp_path):
    from pdf_gen import create_report
    before=snapshot();after=identity.decide(before,before['findings'][0]['id'],'mine')
    text=''.join(page.extract_text() for page in PdfReader(create_report({'identity_resolution':after,'identity_only':True},tmp_path)).pages)
    assert 'Связи и принадлежность' in text
    assert 'Моё — отмечено пользователем' in text
    assert 'Общий владелец не доказан' in text
    assert 'https://github.com/Example' in text
    assert 'Проверок в отчёте: 0' not in text


def test_identity_endpoints_require_auth_origin_and_bounded_json(settings):
    c=client();path='/api/account/jobs/'+'a'*32+'/identity'
    assert c.get(path).status_code==401
    assert c.get(path+'/report').status_code==401
    assert c.put(path,json={}).status_code==401
    assert c.put(path,json={},headers={'Origin':'https://evil.test'}).status_code==403
    assert c.put(path,content='x'*5000,headers={'Content-Type':'application/json'}).status_code==413


def create_private(c,sent,tmp_path,job='a'*32,owner='owner@example.com'):
    register(c,sent);csrf=login(c)
    job_store.record(job,'accepted',owner)
    path=tmp_path/'report.pdf';path.write_bytes(b'%PDF-test')
    store.save_report(job,path,snapshot())
    return csrf,job


def test_db_private_snapshot_review_ciphertext_and_idor(db,tmp_path):
    c=client();csrf,job=create_private(c,db,tmp_path)
    route='/api/account/jobs/'+job+'/identity'
    before=c.get(route).json();assert before['revision']==1
    item=before['findings'][0]['id']
    body=dict(revision=1,item_id=item,decision='mine')
    assert c.put(route,json=body).status_code==403
    r=c.put(route,json=body,headers={'X-CSRF-Token':csrf})
    assert r.status_code==200 and r.json()['owner_group']==[item]
    assert c.put(route,json=body,headers={'X-CSRF-Token':csrf}).status_code==409
    assert c.get(route).json()['revision']==2
    foreign='b'*32;job_store.record(foreign,'accepted','other@example.com')
    pdf=tmp_path/'other.pdf';pdf.write_bytes(b'%PDF-test');store.save_report(foreign,pdf,snapshot())
    other='/api/account/jobs/'+foreign+'/identity'
    assert c.get(other).status_code==404
    assert c.get(other+'/report').status_code==404
    assert c.put(other,json=body,headers={'X-CSRF-Token':csrf}).status_code==404
    with job_store.connect() as conn:
        row=conn.execute('SELECT identity_ciphertext,identity_revision FROM privetek_account_reports WHERE job_id=%s',(job,)).fetchone()
        assert b'github.com' not in bytes(row['identity_ciphertext']) and row['identity_revision']==2
    report=c.get(route+'/report');assert report.status_code==200 and report.content.startswith(b'%PDF-')
    assert report.headers['Cache-Control']=='no-store'


def test_db_invalid_decisions_and_expiry_delete_together(db,tmp_path):
    c=client();csrf,job=create_private(c,db,tmp_path)
    route='/api/account/jobs/'+job+'/identity';headers={'X-CSRF-Token':csrf}
    for update in [dict(revision=True,item_id='identifier-email',decision='mine'),dict(revision=1,item_id='unknown',decision='mine'),dict(revision=1,item_id='identifier-email',decision=[])]:
        assert c.put(route,json=update,headers=headers).status_code==422
    assert c.get('/api/account/jobs').json()['items'][0]['identity_available'] is True
    with job_store.connect() as conn:conn.execute("UPDATE privetek_account_reports SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'")
    assert c.get(route).status_code==404 and c.get(route+'/report').status_code==404
    store.cleanup()
    with job_store.connect() as conn:assert conn.execute('SELECT count(*) AS n FROM privetek_account_reports').fetchone()['n']==0


def test_db_legacy_and_delete_hide_identity(db,tmp_path):
    c=client();csrf,job=create_private(c,db,tmp_path)
    old='c'*32;job_store.record(old,'accepted','owner@example.com')
    pdf=tmp_path/'legacy.pdf';pdf.write_bytes(b'%PDF-test');store.save_report(old,pdf)
    assert c.get('/api/account/jobs/'+old+'/identity').status_code==404
    assert c.delete('/api/account/jobs/'+job+'/report',headers={'X-CSRF-Token':csrf}).status_code==200
    assert c.get('/api/account/jobs/'+job+'/identity').status_code==404


@pytest.mark.skipif(os.getenv('ACCOUNTS_NATIVE_POSTGRES_TESTS')!='1',reason='Native row locks required')
def test_db_concurrent_reviews_conflict_instead_of_overwrite(db,tmp_path):
    c=client();_,job=create_private(c,db,tmp_path)
    def update(decision):
        try:return store.identity_decision(crypto.email_key('owner@example.com'),job,1,'identifier-email',decision)['revision']
        except RuntimeError:return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(update,['mine','not_mine']))
    assert results.count(2)==1 and results.count('conflict')==1
