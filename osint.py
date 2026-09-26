"""Existing sources only; failures are reported without personal data."""
import os
from urllib.parse import quote
import httpx
import phonenumbers
import trio
from holehe.modules.social_media.instagram import instagram
from holehe.modules.shopping.amazon import amazon as holehe_amazon
from ignorant.modules.shopping.amazon import amazon as ignorant_amazon


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
                output.extend(partial)
            except Exception:
                output.append({'name': label, 'rateLimit': True, 'exists': False})
    return output


def collect(items, errors, checks=None, kind="email"):
    checks = checks if checks is not None else []
    found = []
    completed = False
    for item in items:
        source = str(item.get('name', 'Источник'))
        if item.get('rateLimit') or not isinstance(item.get('exists'), bool):
            reason = "Источник не дал пригодного ответа; блокировка, лимит или ошибка разбора."
            errors.append(f"{source} ({kind}): {reason}")
            checks.append(dict(source=source, kind=kind, status="unavailable", reason=reason))
        else:
            completed = True
            checks.append(dict(source=source, kind=kind,
                               status='possible' if item['exists'] else 'unknown',
                               reason='Косвенный признак регистрации; требует подтверждения.' if item['exists'] else 'Модуль не нашёл признак регистрации. Отсутствие аккаунта не подтверждено.'))
            if item['exists']:
                found.append({'site': item.get('name'), 'domain': item.get('domain'), 'exists': True})
    return found if completed else None


def search(email=None, phone=None):
    results = {'email_breach': None, 'email_registrations': None,
               'phone_registrations': None, 'errors': [], 'checks': []}
    errors = results['errors']
    checks = results['checks']
    if email:
        key = os.getenv('HIBP_API_KEY')
        if not key:
            errors.append('HIBP (email): не настроен ключ API.')
            checks.append(dict(source='HIBP', kind='breach', status='skipped', reason='Не настроен ключ API.'))
        else:
            try:
                response = httpx.get(
                    'https://haveibeenpwned.com/api/v3/breachedaccount/' + quote(email, safe=''),
                    headers={'hibp-api-key': key, 'user-agent': 'PriveTek/0.1'},
                    params={'truncateResponse': 'false'}, timeout=20)
                if response.status_code == 404:
                    results['email_breach'] = []
                else:
                    response.raise_for_status()
                    results['email_breach'] = [
                        {'name': b['Name'], 'date': b.get('BreachDate', 'дата неизвестна')}
                        for b in response.json()]
                checks.append(dict(source='HIBP', kind='breach', status='found' if results['email_breach'] else 'not_found', reason='Получен ответ API HIBP.'))
            except Exception:
                checks.append(dict(source='HIBP', kind='breach', status='unavailable', reason='Не удалось получить результат API.'))
                errors.append('HIBP: проверка недоступна. Проверьте ключ, лимиты и соединение.')
        try:
            items = trio.run(run_checks, [('Instagram', instagram), ('Amazon', holehe_amazon)], (email,))
            results['email_registrations'] = collect(items, errors, checks, 'email')
        except Exception:
            errors.append('Проверки email недоступны.')
            for source in ('Instagram', 'Amazon'):
                checks.append(dict(source=source, kind='email', status='unavailable', reason='Ошибка выполнения проверки.'))
    if not email:
        for source, kind in [('HIBP', 'breach'), ('Instagram', 'email'), ('Amazon', 'email')]:
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
    return results
