"""Selected sources; failures are reported without personal data."""
import hibp_client
import leakcheck_client
from public_sources import SOURCES, run_profiles
import httpx
import phonenumbers
import trio
from search_inputs import normalize_phone, normalize_username
from report_data import utc_now, prepare
from source_checks import instagram, amazon_email as holehe_amazon, amazon_phone as ignorant_amazon, spotify, gravatar, github_username


async def run_checks(checks, arguments):
    output = []
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        for label, check in checks:
            partial = []
            try:
                with trio.fail_after(30):
                    await check(*arguments, client, partial)
                if not partial:
                    raise ValueError('No result')
                for item in partial:
                    item['checked_at'] = utc_now()
                output.extend(partial)
            except Exception:
                output.append({'name': label, 'rateLimit': True, 'exists': False, 'checked_at': utc_now()})
    return output


def collect(items, errors, checks=None, kind="email"):
    checks = checks if checks is not None else []
    found = []
    completed = False
    for item in items:
        source = str(item.get('name', 'Источник'))
        if item.get('rateLimit') or not isinstance(item.get('exists'), bool):
            reason = item.get("reason", "Источник не дал пригодного ответа; блокировка, лимит или ошибка разбора.")
            errors.append(f"{source} ({kind}): {reason}")
            checks.append(dict(source=source, kind=kind, status="unavailable", reason=reason, checked_at=item.get('checked_at')))
        else:
            completed = True
            checks.append(dict(source=source, kind=kind,
                               checked_at=item.get('checked_at'),
                               status='possible' if item['exists'] else 'unknown',
                               reason=item.get('reason') or ('Косвенный признак регистрации; требует подтверждения.' if item['exists'] else 'Модуль не нашёл признак регистрации. Отсутствие аккаунта не подтверждено.')))
            if item['exists']:
                found.append({'site': item.get('name'), 'domain': item.get('domain'), 'exists': True})
    return found if completed else None


def search(email=None, phone=None, username=None):
    phone = normalize_phone(phone)
    username = normalize_username(username)
    results = {'email_breach': None, 'email_registrations': None,
               'phone_registrations': None, 'username_profiles': None, 'errors': [], 'checks': []}
    errors = results['errors']
    checks = results['checks']
    if email:
        try:
            avatars = trio.run(run_checks, [('Gravatar', gravatar)], (email,))
            avatar = avatars[0]
            checks.append(dict(source='Gravatar', kind='avatar',
                               checked_at=avatar.get('checked_at'),
                               status=avatar.get('status', 'unavailable'),
                               reason=avatar.get('reason', 'Проверка Gravatar не выполнена.')))
        except Exception:
            checks.append(dict(source='Gravatar', kind='avatar', status='unavailable', reason='Проверка Gravatar не выполнена.'))
        breaches, check = hibp_client.lookup(email)
        if check['status'] != 'skipped':
            check['checked_at'] = utc_now()
        results['email_breach'] = [dict(row, source='HIBP') for row in breaches] if breaches is not None else None
        checks.append(check)
        leak_breaches, leak_check = leakcheck_client.lookup(email)
        checks.append(leak_check)
        if leak_breaches is not None:
            results['email_breach'] = [dict(row, source='HIBP') for row in (breaches or [])] + leak_breaches
        if leak_check['status'] == 'unavailable':
            errors.append('LeakCheck (email): ' + leak_check['reason'])
        if check['status'] in ('unavailable', 'skipped'):
            errors.append('HIBP (email): ' + check['reason'])
        try:
            items = trio.run(run_checks, [('Instagram', instagram), ('Amazon', holehe_amazon), ('Spotify', spotify)], (email,))
            results['email_registrations'] = collect(items, errors, checks, 'email')
        except Exception:
            errors.append('Проверки email недоступны.')
            for source in ('Instagram', 'Amazon', 'Spotify'):
                checks.append(dict(source=source, kind='email', status='unavailable', reason='Ошибка выполнения проверки.'))
    if not email:
        for source, kind in [('Gravatar', 'avatar'), ('HIBP', 'breach'), ('LeakCheck', 'breach'), ('Instagram', 'email'), ('Amazon', 'email'), ('Spotify', 'email')]:
            checks.append(dict(source=source, kind=kind, status='skipped', reason='Email не указан.'))
    if phone:
        checks.append(dict(source='Instagram', kind='phone', status='disabled', reason='Модуль отключён: может принимать ответ об ошибке за найденный аккаунт.'))
        try:
            number = phonenumbers.parse(phone, None)
            national = phonenumbers.national_significant_number(number)
            items = trio.run(run_checks, [('Amazon', ignorant_amazon)],
                             (national, str(number.country_code)))
            results['phone_registrations'] = collect(items, errors, checks, 'phone')
        except Exception:
            errors.append('Проверки телефона недоступны.')
            checks.append(dict(source='Amazon', kind='phone', status='unavailable', reason='Ошибка номера или выполнения проверки.'))
    else:
        for source in ('Instagram', 'Amazon'):
            checks.append(dict(source=source, kind='phone', status='skipped', reason='Телефон не указан.'))
    if username:
        profile_checks = trio.run(run_profiles, username)
        checks.extend(profile_checks)
        results['username_profiles'] = [dict(site=c['source'], profile_url=c['profile_url'])
                                       for c in profile_checks if c['status'] == 'found']
    else:
        for source in SOURCES:
            checks.append(dict(source=source[0], kind='username', status='skipped', reason='Username не указан.'))
    return prepare(results)
