"""LeakCheck Public: hash-only email queries; breach metadata, never secret values."""
import hashlib
import threading
import time
import httpx
from report_data import utc_now
from public_sources import USER_AGENT

_lock = threading.Lock()
_last_request = 0.0


def lookup(email):
    global _last_request
    check = dict(source='LeakCheck', kind='breach', status='unavailable', checked_at=utc_now(),
                 reason='LeakCheck не дал пригодного ответа; ошибка связи, лимит или неизвестный формат.')
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:24]
    try:
        # Serialize across worker threads; one Render worker is required.
        with _lock:
            delay = 1.05 - (time.monotonic() - _last_request)
            if delay > 0:
                time.sleep(delay)
            _last_request = time.monotonic()
            response = httpx.get('https://leakcheck.io/api/public', params={'check': digest},
                                 headers={'User-Agent': USER_AGENT}, timeout=15, follow_redirects=False)
        body = response.json()
        if response.status_code == 200 and isinstance(body, dict) and body.get('success') is False and body.get('error') == 'Not found':
            check.update(status='not_found', reason='LeakCheck не нашёл утечек по хешу email. Полнота базы не гарантируется.')
            return [], check
        if response.status_code != 200 or not isinstance(body, dict) or body.get('success') is not True:
            return None, check
        found, fields, sources = body.get('found'), body.get('fields'), body.get('sources')
        if not isinstance(found, int) or isinstance(found, bool) or found < 0:
            return None, check
        if found == 0:
            check.update(status='not_found', reason='LeakCheck не нашёл утечек по хешу email. Полнота базы не гарантируется.')
            return [], check
        if not isinstance(fields, list) or not all(isinstance(v, str) for v in fields) or not isinstance(sources, list) or not sources:
            return None, check
        rows = []
        for source in sources:
            if not isinstance(source, dict) or not isinstance(source.get('name'), str) or not source['name']:
                return None, check
            date = source.get('date') or 'дата неизвестна'
            if not isinstance(date, str):
                return None, check
            rows.append(dict(source='LeakCheck', name=source['name'], date=date,
                             data_classes=fields, classes_scope='all_matching_breaches'))
        check.update(status='found', reason='Найдены названия утечек. Категории данных относятся ко всем совпадениям вместе; значения данных API не раскрывает.')
        return rows, check
    except (httpx.HTTPError, ValueError, TypeError):
        return None, check
