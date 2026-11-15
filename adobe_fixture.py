"""Prepare or add a single private, short-lived Adobe fixture. Run from the repo."""
import json
from pathlib import Path
import tempfile
from uuid import UUID, uuid5

import account_crypto
import identity_resolution
import job_store
import pdf_gen

NAMESPACE = UUID('e491f9ee-9d35-4ec8-a1e4-a341de96ad34')


def build_fixture(directory):
    data = {
        'checks': [{'source': 'HIBP', 'kind': 'breach', 'status': 'found',
                    'reason': 'Тестовая находка. Поиск по адресу аккаунта не выполнялся.'}],
        'email_breach': [{'source': 'HIBP', 'name': 'Adobe', 'date': '2013-10-04'}],
    }
    card = identity_resolution.build(data, 'account-exists@hibp-integration-tests.com')
    card['findings'][0]['title'] = 'Тестовая находка Adobe (синтетические данные)'
    card['identifiers'][0]['title'] = 'Синтетический адрес HIBP'
    path = pdf_gen.create_report({'identity_resolution': card, 'identity_only': True}, directory)
    return card, Path(path).read_bytes()


def apply(email, card, pdf):
    cipher = account_crypto.report_cipher()
    with job_store.connect() as db:
        owner = db.execute('SELECT id,email_key FROM privetek_users WHERE email=%s AND verified_at IS NOT NULL',
                           (email,)).fetchone()
        if owner is None:
            return 'account_not_found'
        job_id = uuid5(NAMESPACE, owner['id']).hex
        existing = db.execute('SELECT email_key FROM privetek_job_owners WHERE job_id=%s', (job_id,)).fetchone()
        if existing:
            if existing['email_key'] != owner['email_key']:
                raise ValueError('Existing fixture owner does not match')
            return 'already_present'
        db.execute("INSERT INTO privetek_jobs (id,status) VALUES (%s,'synthetic_fixture')", (job_id,))
        db.execute('INSERT INTO privetek_job_owners (job_id,email_key) VALUES (%s,%s)', (job_id, owner['email_key']))
        db.execute("""INSERT INTO privetek_account_reports
                   (job_id,ciphertext,expires_at,identity_ciphertext,identity_revision)
                   VALUES (%s,%s,now()+interval '24 hours',%s,1)""",
                   (job_id, cipher.encrypt(pdf), cipher.encrypt(json.dumps(card, ensure_ascii=False).encode())))
    return 'created'


def seed():
    with tempfile.TemporaryDirectory() as directory:
        card, pdf = build_fixture(directory)
    if not pdf.startswith(b'%PDF-') or card['findings'][0]['breach_names'] != ['Adobe']:
        raise ValueError('Invalid synthetic report')
    return apply('privetekmail@gmail.com', card, pdf)
