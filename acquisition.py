"""Bounded, first-party acquisition measurements. No arbitrary labels or PII."""
import logging
import re
import secrets
import time
from datetime import datetime, timezone
import account_crypto as crypto
import job_store

COOKIE = '__Host-privetek_visit'
SOURCES = {'telegram', 'vk', 'interview', 'ads', 'newsletter', 'partner', 'organic'}
MEDIUMS = {'social', 'cpc', 'email', 'referral', 'interview', 'organic'}
CLIENT_EVENTS = {'form_open', 'registration_start', 'report_form_open'}
logger = logging.getLogger('privetek')


def enabled():
    return crypto.enabled() and job_store.enabled()


def attribution(params):
    # Campaigns are deliberately numbered: no names, phones, email or free text.
    tagged = any(key in params for key in ('utm_source', 'utm_medium', 'utm_campaign'))
    source = params.get('utm_source', '').lower()
    medium = params.get('utm_medium', '').lower()
    campaign = params.get('utm_campaign', '')
    return (source if source in SOURCES else 'unknown' if tagged else 'direct',
            medium if medium in MEDIUMS else 'unknown',
            campaign if re.fullmatch(r'c[0-9]{1,6}', campaign) else 'none')


def token():
    value = secrets.token_hex(16) + '.' + str(int(time.time()))
    return value + '.' + crypto.digest('analytics-cookie', value)


def visitor(request):
    if request.headers.get('dnt') == '1' or request.headers.get('sec-gpc') == '1':
        return None
    value = request.cookies.get(COOKIE, '')
    if not re.fullmatch(r'[0-9a-f]{32}\.[0-9]{10}\.[0-9a-f]{64}', value):
        return None
    key, stamp, signature = value.split('.')
    age = time.time() - int(stamp)
    if not 0 <= age <= 30 * 86400 or not secrets.compare_digest(signature, crypto.digest('analytics-cookie', key + '.' + stamp)):
        return None
    return key


def safe(call, *args):
    if not enabled():
        return None
    try:
        return call(*args)
    except Exception:
        # Analytics never blocks sign-in, reporting or downloads; no payload logs.
        logger.warning('analytics_write_unavailable')
        return None


def transaction_event(db, call, *args):
    try:
        with db.transaction():
            call(db, *args)
    except Exception:
        logger.warning('analytics_write_unavailable')


def event(db, kind, key, visitor_id=None, user_id=None, job_id=None, error_code=None):
    db.execute('''INSERT INTO privetek_analytics_events
        (dedup_key,kind,visitor_id,user_id,job_id,error_code) VALUES (%s,%s,%s,%s,%s,%s)
        ON CONFLICT (dedup_key) DO NOTHING''', (key, kind, visitor_id, user_id, job_id, error_code))


def visit(request):
    if request.headers.get('dnt') == '1' or request.headers.get('sec-gpc') == '1':
        return None
    existing = visitor(request)
    with job_store.connect() as db:
        import account_store
        ip = request.client.host if request.client else 'unknown'
        if not account_store.quota([('analytics-visit:ip', ip, 300), ('analytics-visit:global', 'all', 10000)]):
            return None
        if existing and db.execute('SELECT id FROM privetek_analytics_visitors WHERE id=%s', (existing,)).fetchone():
            event(db, 'landing', 'landing:' + secrets.token_hex(16), existing)
            return None
        value = token(); key = value.split('.')[0]
        db.execute('INSERT INTO privetek_analytics_visitors (id,source,medium,campaign) VALUES (%s,%s,%s,%s)', (key, *attribution(request.query_params)))
        event(db, 'visit', 'visit:' + key, key)
        event(db, 'landing', 'landing:' + secrets.token_hex(16), key)
        return value


def client_event(request, kind):
    key = visitor(request)
    if not key:
        return
    with job_store.connect() as db:
        if not db.execute('SELECT id FROM privetek_analytics_visitors WHERE id=%s', (key,)).fetchone():
            return
        day = datetime.now(timezone.utc).date().isoformat()
        event(db, kind, kind + ':' + key + ':' + day, key)


def bind_challenge(request, challenge):
    key = visitor(request)
    if not key:
        return
    with job_store.connect() as db:
        db.execute('''INSERT INTO privetek_analytics_challenges (challenge_id,visitor_id)
            SELECT %s,id FROM privetek_analytics_visitors WHERE id=%s
            ON CONFLICT DO NOTHING''', (challenge, key))


def registered(db, challenge, user_id):
    row = db.execute('SELECT visitor_id FROM privetek_analytics_challenges WHERE challenge_id=%s', (challenge,)).fetchone()
    key = row['visitor_id'] if row else None
    event(db, 'contact_verified', 'verified:' + user_id, key, user_id)
    event(db, 'registered', 'registered:' + user_id, key, user_id)


def job_event(db, job_id, kind):
    row = db.execute('''SELECT u.id FROM privetek_job_owners o JOIN privetek_users u ON u.email_key=o.email_key WHERE o.job_id=%s''', (job_id,)).fetchone()
    event(db, kind, kind + ':' + job_id, user_id=row['id'] if row else None, job_id=job_id)


def associate_job(request, job_id):
    key = visitor(request)
    if not key:
        return
    with job_store.connect() as db:
        db.execute('''UPDATE privetek_analytics_events SET visitor_id=v.id FROM privetek_analytics_visitors v
            WHERE dedup_key=%s AND visitor_id IS NULL AND v.id=%s''', ('report_ordered:' + job_id, key))


def download(user, job_id):
    with job_store.connect() as db:
        event(db, 'report_response', 'report_response:' + job_id + ':' + user['id'], user_id=user['id'], job_id=job_id)


def error(request, stage, status):
    key = visitor(request)
    if not key:
        return
    with job_store.connect() as db:
        if db.execute('SELECT id FROM privetek_analytics_visitors WHERE id=%s', (key,)).fetchone():
            day = datetime.now(timezone.utc).date().isoformat()
            event(db, 'error_' + stage, 'error:' + stage + ':' + str(status) + ':' + key + ':' + day, key, error_code=status)


def cleanup():
    with job_store.connect() as db:
        db.execute("DELETE FROM privetek_analytics_events WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days'")
        db.execute("DELETE FROM privetek_analytics_challenges WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 day'")
        db.execute("DELETE FROM privetek_analytics_visitors WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days'")


def summary(days):
    with job_store.connect() as db:
        channels = db.execute('''SELECT COALESCE(v.source,'unknown') AS source,
            COALESCE(v.medium,'unknown') AS medium, COALESCE(v.campaign,'none') AS campaign,
            e.kind, e.error_code, count(*) AS events,
            count(DISTINCT e.visitor_id) AS visitors, count(DISTINCT e.user_id) AS users,
            count(DISTINCT e.job_id) AS reports
            FROM privetek_analytics_events e
            LEFT JOIN privetek_analytics_events ordered ON ordered.dedup_key='report_ordered:'||e.job_id
            LEFT JOIN privetek_analytics_events registration ON registration.dedup_key='registered:'||e.user_id
            LEFT JOIN privetek_analytics_visitors v ON v.id=COALESCE(registration.visitor_id,e.visitor_id,ordered.visitor_id)
            WHERE e.created_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')
            GROUP BY v.source,v.medium,v.campaign,e.kind,e.error_code ORDER BY 1,2,3,4''', (days,)).fetchall()
        accounts = db.execute('''SELECT u.id AS account_id, count(DISTINCT o.job_id) FILTER (WHERE o.created_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')) AS ordered,
            count(DISTINCT o.job_id) AS ordered_total,
            count(DISTINCT ready.job_id) AS ready_observed,
            count(DISTINCT downloaded.job_id) AS report_responses_observed
            FROM privetek_users u LEFT JOIN privetek_job_owners o ON o.email_key=u.email_key
            LEFT JOIN privetek_analytics_events ready ON ready.dedup_key='report_ready:'||o.job_id
            LEFT JOIN privetek_analytics_events downloaded ON downloaded.dedup_key='report_response:'||o.job_id||':'||u.id
            GROUP BY u.id ORDER BY ordered DESC,u.id LIMIT 1001''', (days,)).fetchall()
        since = db.execute("SELECT applied_at FROM privetek_schema_migrations WHERE version='007_acquisition_analytics.sql'").fetchone()
    return dict(days=days, tracking_since=since['applied_at'] if since else None, channels=channels,
                accounts=accounts[:1000], accounts_truncated=len(accounts)>1000,
                definitions={'landing':'observed GET /go or /account, including repeat loads and bots; not proof Tilda loaded',
                             'visit':'unique 30-day browser identifier; not a person or every page view',
                             'ui_events':'one event per browser, kind and UTC day; untrusted client observations',
                             'error':'one observation per browser, stage, HTTP status and UTC day; not every attempt',
                             'report_response':'authorized PDF response initiated; does not prove saved or read',
                             'attribution':'first touch, registration cohort preferred; unknown stays unknown',
                             'accounts':'orders in period include existing jobs; ready/responses only since tracking began',
                             'retention_days':90, 'funnel':'independent stage counts, not a strictly ordered cohort conversion'})
