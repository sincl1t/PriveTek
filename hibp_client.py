"""HIBP account lookup. No retries or logging of email addresses / keys."""
import os
from urllib.parse import quote
import httpx


def lookup(email, api_key=None):
    key = api_key if api_key is not None else os.getenv('HIBP_API_KEY', '').strip()
    def result(status, reason, breaches=None):
        return breaches, dict(source='HIBP', kind='breach', status=status, reason=reason)
    if not key:
        return result('skipped', 'Не настроен ключ API; проверка утечек не выполнялась.')
    try:
        response = httpx.get('https://haveibeenpwned.com/api/v3/breachedaccount/' + quote(email, safe=''),
                             headers={'hibp-api-key': key, 'user-agent': 'PriveTek/0.2'},
                             params={'truncateResponse': 'false', 'includeUnverified': 'false'}, timeout=20)
    except httpx.RequestError:
        return result('unavailable', 'Источник не ответил: ошибка соединения или время ожидания истекло.')
    if response.status_code == 404:
        return result('not_found', 'В доступных проверенных утечках HIBP совпадений нет. Это не гарантирует отсутствия утечек.', [])
    reasons = {401: 'Ключ API не принят. Команде сервиса нужно проверить настройки.',
               403: 'Доступ к API запрещён. Команде сервиса нужно проверить разрешения.',
               429: 'Достигнут лимит запросов HIBP. Проверка не завершена.'}
    if response.status_code != 200:
        return result('unavailable', reasons.get(response.status_code, 'HIBP временно недоступен или вернул неожиданный ответ.'))
    try:
        payload = response.json()
        if not isinstance(payload, list) or not payload:
            raise ValueError()
        breaches = []
        for row in payload:
            if not isinstance(row, dict) or not isinstance(row.get('Name'), str) or not row['Name']:
                raise ValueError()
            classes = row.get('DataClasses', [])
            if not isinstance(classes, list) or not all(isinstance(c, str) for c in classes):
                raise ValueError()
            breaches.append({'name': row['Name'], 'date': str(row.get('BreachDate', 'дата неизвестна')),
                             'data_classes': classes})
    except (ValueError, TypeError, KeyError):
        return result('unavailable', 'Ответ HIBP не удалось распознать; результат не считается отрицательным.')
    return result('found', 'Email указан в утечках из базы HIBP. Это не доказывает текущий взлом аккаунта.', breaches)
