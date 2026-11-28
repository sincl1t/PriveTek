"""Opt-in linked phone pilot. Email identity and existing MFA are preserved."""
from datetime import timedelta
import os
import secrets
import re
import account_crypto as crypto
from account_store import now
import job_store
from search_inputs import normalize_phone
import sms_provider


def phone_key(phone):return crypto.digest('login-phone',phone)


def status(user_id):
    with job_store.connect() as db:
        row=db.execute('SELECT ciphertext FROM privetek_account_phones WHERE user_id=%s',(user_id,)).fetchone()
    if not row:return dict(linked=False,masked_phone=None)
    phone=crypto.report_cipher().decrypt(bytes(row['ciphertext'])).decode()
    return dict(linked=True,masked_phone=phone[:2]+'•'*(len(phone)-6)+phone[-4:])


def issue(phone,purpose,user_id=None):
    if not sms_provider.configured():raise sms_provider.SmsUnavailable('SMS отключены')
    phone=normalize_phone(phone)
    if not phone:raise ValueError('Укажите номер с кодом страны')
    key=phone_key(phone);challenge=secrets.token_hex(24)
    code=''.join(secrets.choice('0123456789') for _ in range(8))
    allowed=key in os.getenv('SMS_PILOT_PHONE_HASHES','').split(',')
    with job_store.connect() as db:
        db.execute("DELETE FROM privetek_phone_codes WHERE expires_at<now()-interval '1 day'")
        db.execute("DELETE FROM privetek_sms_budget WHERE day<CURRENT_DATE-90")
        db.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(key,))
        if db.execute("SELECT id FROM privetek_phone_codes WHERE phone_key=%s AND expires_at>now()+interval '4 minutes'",(key,)).fetchone():
            raise ValueError('Повторите запрос через минуту')
        linked=db.execute('SELECT user_id FROM privetek_account_phones WHERE phone_key=%s',(key,)).fetchone()
        owner=user_id if purpose=='bind' else linked['user_id'] if linked else None
        can_send=allowed and bool(owner) and (purpose!='bind' or not linked or linked['user_id']==owner)
        if can_send:
            row=db.execute('INSERT INTO privetek_sms_budget(day,used) VALUES (CURRENT_DATE,1) ON CONFLICT(day) DO UPDATE SET used=privetek_sms_budget.used+1 WHERE privetek_sms_budget.used<%s RETURNING used',
                           (max(1,min(100,int(os.getenv('SMS_MAX_SENDS_PER_DAY','10')))),)).fetchone()
            can_send=bool(row)
        # Latest issuance invalidates prior codes, including uncertain sends.
        db.execute('DELETE FROM privetek_phone_codes WHERE phone_key=%s AND purpose=%s',(key,purpose))
        db.execute('INSERT INTO privetek_phone_codes(id,user_id,purpose,phone_key,ciphertext,code_hash,expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)',
            (challenge,owner if can_send else None,purpose,key,crypto.report_cipher().encrypt(phone.encode()),crypto.digest('sms-code',challenge+':'+code),now()+timedelta(minutes=5)))
    if can_send:
        try:sms_provider.send_code(phone,code)
        except sms_provider.SmsUnavailable:return challenge
        with job_store.connect() as db:db.execute('UPDATE privetek_phone_codes SET accepted=TRUE WHERE id=%s',(challenge,))
    return challenge


def redeem(challenge,code,purpose,user_id=None,session_hash=None):
    if not sms_provider.configured():raise sms_provider.SmsUnavailable('SMS отключены')
    if not isinstance(challenge,str) or not re.fullmatch('[0-9a-f]{48}',challenge) or not isinstance(code,str) or not re.fullmatch('[0-9]{8}',code):return False
    with job_store.connect() as db:
        initial=db.execute('SELECT user_id FROM privetek_phone_codes WHERE id=%s',(challenge,)).fetchone()
        if not initial or not initial['user_id']:return False
        # Same lock order as existing MFA: user before challenge.
        user=db.execute('SELECT * FROM privetek_users WHERE id=%s FOR UPDATE',(initial['user_id'],)).fetchone()
        row=db.execute('SELECT * FROM privetek_phone_codes WHERE id=%s FOR UPDATE',(challenge,)).fetchone()
        if not user or not row or not row['accepted'] or row['purpose']!=purpose or row['expires_at']<=now() or row['attempts']>=5 or (purpose=='bind' and row['user_id']!=user_id):return False
        db.execute('UPDATE privetek_phone_codes SET attempts=attempts+1 WHERE id=%s',(challenge,))
        if not secrets.compare_digest(row['code_hash'],crypto.digest('sms-code',challenge+':'+code)):return False
        if purpose=='bind':
            linked=db.execute('SELECT user_id FROM privetek_account_phones WHERE phone_key=%s',(row['phone_key'],)).fetchone()
            if linked and linked['user_id']!=user_id:return False
            db.execute('INSERT INTO privetek_account_phones(user_id,phone_key,ciphertext) VALUES (%s,%s,%s) ON CONFLICT(user_id) DO UPDATE SET phone_key=EXCLUDED.phone_key,ciphertext=EXCLUDED.ciphertext,verified_at=now()',
                       (user_id,row['phone_key'],row['ciphertext']))
            # Rebinding revokes outstanding SMS login challenges for this account.
            db.execute("DELETE FROM privetek_phone_codes WHERE user_id=%s AND purpose='login'",(user_id,))
            outcome=True
        else:
            linked=db.execute('SELECT phone_key FROM privetek_account_phones WHERE user_id=%s',(user['id'],)).fetchone()
            if not linked or linked['phone_key']!=row['phone_key']:return False
            if user['mfa_enabled']:
                from account_mfa import login_challenge
                outcome=login_challenge(db,user)
            else:
                db.execute('INSERT INTO privetek_sessions(token_hash,user_id,expires_at) VALUES (%s,%s,%s)',(session_hash,user['id'],now()+timedelta(days=7)))
                outcome=True
        db.execute('DELETE FROM privetek_phone_codes WHERE id=%s',(challenge,))
    return outcome
