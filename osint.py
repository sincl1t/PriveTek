"""Existing sources only; failures are reported without personal data."""
import os
from urllib.parse import quote
import httpx
import phonenumbers
import trio
from holehe.modules.social_media.instagram import instagram
from holehe.modules.shopping.amazon import amazon as holehe_amazon
from ignorant.modules.shopping.amazon import amazon as ignorant_amazon
from ignorant.modules.social_media.instagram import instagram as ignorant_instagram


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


def collect(items, errors):
    found = []
    completed = False
    for item in items:
        if item.get('rateLimit') or not isinstance(item.get('exists'), bool):
            errors.append(f"{item.get('name', 'Источник')}: проверка недоступна или ограничена.")
        else:
            completed = True
            if item['exists']:
                found.append({'site': item.get('name'), 'domain': item.get('domain'), 'exists': True})
    return found if completed else None


def search(email=None, phone=None):
    results = {'email_breach': None, 'email_registrations': None,
               'phone_registrations': None, 'errors': []}
    errors = results['errors']
    if email:
        key = os.getenv('HIBP_API_KEY')
        if not key:
            errors.append('Проверка утечек HIBP не выполнена: не настроен ключ API.')
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
            except Exception:
                errors.append('HIBP: проверка недоступна. Проверьте ключ, лимиты и соединение.')
        try:
            items = trio.run(run_checks, [('Instagram', instagram), ('Amazon', holehe_amazon)], (email,))
            results['email_registrations'] = collect(items, errors)
        except Exception:
            errors.append('Проверки email недоступны.')
    if phone:
        try:
            number = phonenumbers.parse(phone, None)
            national = phonenumbers.national_significant_number(number)
            items = trio.run(run_checks, [('Amazon', ignorant_amazon), ('Instagram', ignorant_instagram)],
                             (national, str(number.country_code)))
            results['phone_registrations'] = collect(items, errors)
        except Exception:
            errors.append('Проверки телефона недоступны.')
    return results
