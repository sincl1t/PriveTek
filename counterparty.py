"""Read a corporate registry status without returning raw provider records."""
import os
import re
from datetime import datetime, timezone

import httpx

SOURCE = 'DaData · сведения ЕГРЮЛ'
SOURCE_URL = 'https://dadata.ru/api/find-party/'
ENDPOINT = 'https://suggestions.dadata.ru/suggestions/api/4_1/rs/findById/party'

STATUSES = {
    'ACTIVE': ('Действующая', None),
    'LIQUIDATING': ('В процессе ликвидации', 'Начата ликвидация или процедура исключения из ЕГРЮЛ.'),
    'LIQUIDATED': ('Ликвидирована', 'Деятельность юридического лица прекращена.'),
    'BANKRUPT': ('Банкротство', 'Источник отмечает банкротство.'),
    'REORGANIZING': ('Реорганизация', 'Источник отмечает присоединение к другому юрлицу.'),
}


def company_identifier(value):
    if isinstance(value, str):
        value = value.strip()
        if re.fullmatch(r'[1-9][0-9]{9}', value):
            weights = (2, 4, 10, 3, 5, 9, 4, 6, 8)
            if sum(int(digit) * weight for digit, weight in zip(value, weights)) % 11 % 10 == int(value[-1]):
                return 'inn', value
        if re.fullmatch(r'[15][0-9]{12}', value) and int(value[:-1]) % 11 % 10 == int(value[-1]):
            return 'ogrn', value
    raise ValueError('Введите корректный ИНН (10 цифр) или ОГРН (13 цифр) юридического лица.')


def assess(field, identifier, token):
    status, risk = 'Статус не определён', None
    outcome = 'unavailable'
    try:
        response = httpx.post(
            ENDPOINT, headers={'Authorization': 'Token ' + token, 'Accept': 'application/json'},
            json={'query': identifier, 'type': 'LEGAL', 'branch_type': 'MAIN'},
            timeout=5, follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
        suggestions = payload.get('suggestions') if isinstance(payload, dict) else None
        if suggestions == []:
            outcome, status = 'not_found', 'Организация не найдена'
        elif isinstance(suggestions, list):
            matches = []
            for suggestion in suggestions:
                data = suggestion.get('data') if isinstance(suggestion, dict) else None
                if isinstance(data, dict) and data.get(field) == identifier and data.get('type') == 'LEGAL' and data.get('branch_type') == 'MAIN':
                    matches.append(data)
            if len(matches) == 1:
                state = matches[0].get('state')
                code = state.get('status') if isinstance(state, dict) else None
                if isinstance(code, str) and code in STATUSES:
                    outcome = 'found'
                    status, risk = STATUSES[code]
    except (httpx.HTTPError, ValueError):
        pass
    return {
        'outcome': outcome, 'status': status, 'signals': [risk] if risk else [],
        'source': SOURCE, 'source_url': SOURCE_URL,
        'checked_at': datetime.now(timezone.utc).isoformat(),
    }


def provider_token():
    return os.getenv('COUNTERPARTY_DADATA_TOKEN', '').strip()
