"""One private synthetic report, expires in 24 hours. No network calls or mail."""
from uuid import UUID, uuid5
from tempfile import TemporaryDirectory
from pathlib import Path
import account_crypto
import job_store
import pdf_gen


def install():
    with job_store.connect() as db:
        owner = db.execute("SELECT id,email_key FROM privetek_users WHERE email=%s AND verified_at IS NOT NULL", ('lis.gr@bk.ru',)).fetchone()
        if owner is None:
            raise RuntimeError('Verified test account missing')
        job_id = uuid5(UUID('fa53e903-bfa7-42cc-bceb-e0e217dc9b75'), str(owner['id'])).hex
        if db.execute('SELECT id FROM privetek_jobs WHERE id=%s', (job_id,)).fetchone():
            return
        data = dict(demo=True, checks=[dict(source='LeakCheck',kind='breach',status='found',
            reason='Синтетический тест: реальные данные пользователя не проверялись.',
            breach_summary=dict(match_count=7,source_count=3,
                data_classes=['password','email','city','company_name','dob','ip','ip1','unknown_a','unknown_b']))],
            email_breach=[dict(source='LeakCheck',name='СИНТЕТИЧЕСКИЙ '+name,date=date)
                for name,date in [('Alpha','2020-01'),('Beta','2021-02'),('Gamma','2022-03')]])
        with TemporaryDirectory() as directory:
            content = Path(pdf_gen.create_report(data,directory)).read_bytes()
        encrypted = account_crypto.report_cipher().encrypt(content)
        db.execute("INSERT INTO privetek_jobs (id,status) VALUES (%s,'synthetic_fixture')", (job_id,))
        db.execute('INSERT INTO privetek_job_owners (job_id,email_key) VALUES (%s,%s)', (job_id,owner['email_key']))
        db.execute("INSERT INTO privetek_account_reports (job_id,ciphertext,expires_at) VALUES (%s,%s,now()+interval '24 hours')",(job_id,encrypted))
