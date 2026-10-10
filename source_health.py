"""Protected fixed-fixture health checks; callers cannot submit URLs or identifiers."""
import os
import threading
import time
import trio
import leakcheck_client
from public_sources import SOURCES, run_profiles
from report_data import utc_now

_lock = threading.Lock()
_cached = None
_cached_at = 0.0


def registry():
    public = [dict(name=s[0], kind='username', source_url=s[1], docs=s[2],
                   enabled=True, credential_required=False,
                   limitation='Точный публичный username; личность не подтверждена. Ошибка не означает отсутствие аккаунта.') for s in SOURCES]
    return dict(sources=public + [
        dict(name='LeakCheck', kind='breach', source_url='https://leakcheck.io/', docs='https://docs.leakcheck.io/public-api/lookup', enabled=True, credential_required=False, limitation='Хеш email; только метаданные. Категории общие для всех утечек. 1 запрос/секунду.'),
        dict(name='HIBP', kind='breach', source_url='https://haveibeenpwned.com/', enabled=bool(os.getenv('HIBP_API_KEY')), credential_required=True, limitation='Без платного ключа пропущен; полнота базы не гарантируется.'),
        dict(name='Gravatar', kind='avatar', source_url='https://gravatar.com/', enabled=True, credential_required=False, limitation='Публичный аватар по хешу email, не подтверждает регистрацию на других сайтах.'),
        *[dict(name=n, kind='email/phone' if n == 'Amazon' else 'email', enabled=True, credential_required=False, limitation='Косвенные признаки регистрации. Лимиты и изменение страницы делают проверку недоступной.') for n in ('Amazon', 'Instagram', 'Spotify')],
    ], probe_cache_seconds=300, probe_scope='Известные публичные профили и синтетический email; не проверяет все возможные usernames или закрытые аккаунты.')


def verify():
    global _cached, _cached_at
    with _lock:
        if _cached is not None and time.monotonic() - _cached_at < 300:
            return dict(_cached, cached=True)
        checks = trio.run(run_profiles, None, True)
        negatives = trio.run(run_profiles, 'pvtkz8q4n2x7r9')
        for check, negative in zip(checks, negatives):
            check['negative_status'] = negative['status']
        rows, breach_check = leakcheck_client.lookup('example@example.com')
        _, breach_negative = leakcheck_client.lookup('stage2-health-pvtkz8q4n2x7r9@example.invalid')
        breach_check['negative_status'] = breach_negative['status']
        checks.append(breach_check)
        for check in checks:
            check['verified'] = check['status'] == 'found' and check.get('negative_status') == 'not_found' if check['kind'] == 'username' else check['status'] in ('found', 'not_found') and check.get('negative_status') == 'not_found'
        _cached = dict(checked_at=utc_now(), checks=checks,
                       verified_sources=sum(c['verified'] for c in checks),
                       configured_sources=len(registry()['sources']), cached=False)
        _cached_at = time.monotonic()
        return _cached
