"""Report failures must be visible without leaking other accounts' job metadata."""
import os
from pathlib import Path
import shutil
import subprocess
from unittest.mock import MagicMock
import pytest
import account_store
import job_store
from account_routes import COOKIE
from test_accounts import settings, db, client, register, login  # noqa: F401


def test_account_job_status_requires_session_and_sanitizes_db_errors(settings,monkeypatch):
    c=client();job='a'*32
    assert c.get('/api/account/jobs/'+job+'/status').status_code==401
    monkeypatch.setattr(account_store,'session',lambda _:dict(id='owner',email_key='owner-key'))
    c.cookies.set(COOKIE,'x'*43)
    assert c.get('/api/account/jobs/invalid/status').status_code==404
    monkeypatch.setattr(job_store,'connect',MagicMock(side_effect=RuntimeError('private database credentials')))
    response=c.get('/api/account/jobs/'+job+'/status')
    assert response.status_code==503 and 'private' not in response.text
    assert response.headers['Cache-Control']=='no-store'


def test_db_job_status_is_owner_scoped_and_does_not_claim_pdf_before_storage(db,tmp_path):
    a=client();b=client();register(a,db);register(b,db,'other@example.com');login(a);login(b,'other@example.com')
    job='a'*32;route='/api/account/jobs/'+job+'/status'
    job_store.record(job,'accepted','owner@example.com')
    assert a.get(route).json()=={'status':'accepted','report_available':False}
    assert b.get(route).status_code==404
    job_store.record(job,'failed')
    assert a.get(route).json()=={'status':'failed','report_available':False}
    pdf=tmp_path/'report.pdf';pdf.write_bytes(b'%PDF-test');account_store.save_report(job,pdf)
    assert a.get(route).json()=={'status':'failed','report_available':True}
    assert b.get(route).status_code==404


def test_report_chat_terminal_states_and_manual_retry():
    node=os.getenv('SUBSCRIPTIONS_TEST_NODE') or shutil.which('node')
    if not node:pytest.skip('Node.js needed for report chat checks')
    run=subprocess.run([node,str(Path(__file__).parent/'js/report-chat.test.cjs')],capture_output=True,text=True,timeout=15)
    assert run.returncode==0,run.stdout+run.stderr


def test_db_new_user_draft_to_real_pdf_with_mocked_sources(db,monkeypatch,tmp_path):
    """Actual account/PDF storage pipeline; only sources and mail transport are replaced."""
    from io import BytesIO
    from types import SimpleNamespace
    from pypdf import PdfReader
    import server,osint,identity_resolution,report_data
    from submission_guard import SubmissionGuard
    c=client()
    response=c.post('/account/start',data={'Email':'owner@example.com','Phone':'+12025550123','Username':'Example'},headers={'Origin':'https://privetek.ru'},follow_redirects=False)
    assert response.status_code==303 and response.headers['location']=='/account/register'
    draft=c.get('/api/account/draft').json()['draft']
    assert not db  # The site draft alone sends no mail or search.
    register(c,db);csrf=login(c)
    assert c.get('/api/account/draft').json()['draft']['id']==draft['id']
    sources=MagicMock()
    def search(**kwargs):
        sources(**kwargs)
        result=report_data.prepare({'email':kwargs['email'],'username':kwargs['username'],'checks':[
            {'source':'GitHub','kind':'username','status':'found','profile_url':'https://github.com/Example','reason':'Synthetic control finding'},
            {'source':'HIBP','kind':'breach','status':'skipped','reason':'Проверка HIBP отключена командой сервиса.'},
            {'source':'Scratch','kind':'username','status':'unavailable','reason':'Synthetic source outage'}]})
        result['identity_resolution']=identity_resolution.build(result,kwargs['email'],kwargs['phone'],kwargs['username'])
        return result
    monkeypatch.setattr(osint,'search',search)
    monkeypatch.setenv('AI_SUMMARY_ENABLED','false')
    sent=[]
    monkeypatch.setattr(server.email_sender,'send_report',lambda email,path:sent.append((email,Path(path).read_bytes())))
    monkeypatch.setattr(server,'guard',SubmissionGuard())
    queued=[]
    monkeypatch.setattr(server,'threading',SimpleNamespace(Thread=lambda **kw:SimpleNamespace(start=lambda:queued.append(kw))))
    payload={'draft_id':draft['id'],'phone':draft['phone'],'username':draft['username']}
    headers={'X-CSRF-Token':csrf}
    assert c.post('/api/account/jobs',json={**payload,'consent':False},headers=headers).status_code==422
    sources.assert_not_called()
    response=c.post('/api/account/jobs',json={**payload,'consent':True},headers=headers)
    assert response.status_code==202 and len(queued)==1
    job=response.json()['job_id'];queued[0]['target'](*queued[0]['args'])
    assert sources.call_count==1 and len(sent)==1
    status=c.get('/api/account/jobs/'+job+'/status').json()
    assert status=={'status':'provider_accepted','report_available':True}
    pdf=c.get('/api/account/jobs/'+job+'/report')
    assert pdf.status_code==200 and pdf.content==sent[0][1]
    reader=PdfReader(BytesIO(pdf.content));first=reader.pages[0].extract_text()
    assert all(title in first for title in ('Что нашли','Что не удалось проверить','Что делать дальше'))
    full_text=''.join(page.extract_text() for page in reader.pages)
    assert all(source in full_text for source in ('GitHub','HIBP','Scratch'))
    (tmp_path/'new-user-report.pdf').write_bytes(pdf.content)
    assert reader.pages[0].get('/Annots')
    assert c.get('/api/account/jobs/'+job+'/identity').status_code==200
    assert c.get('/api/account/draft').json()['draft'] is None
