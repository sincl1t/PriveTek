"""Presentation metadata and exact-record deduplication; never infer identity."""
from copy import deepcopy
from datetime import datetime, timezone
import json

SOURCE_URLS = {
    'GitHub': 'https://github.com/',
    'HIBP': 'https://haveibeenpwned.com/',
    'Spotify': 'https://www.spotify.com/',
    'Instagram': 'https://www.instagram.com/',
    'Amazon': 'https://www.amazon.com/',
    'Gravatar': 'https://gravatar.com/',
}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def unique_records(rows):
    seen, result = set(), []
    for row in rows:
        canonical = deepcopy(row)
        if isinstance(canonical.get('data_classes'), list):
            canonical['data_classes'] = sorted(set(canonical['data_classes']))
        key = json.dumps(canonical, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            result.append(canonical)
    return result


def prepare(data):
    from public_sources import SOURCES
    SOURCE_URLS.update({row[0]: row[1] for row in SOURCES})
    SOURCE_URLS['LeakCheck'] = 'https://leakcheck.io/'
    result = deepcopy(data)
    removed = 0
    for key in ('checks', 'email_breach'):
        if isinstance(result.get(key), list):
            original = result[key]
            result[key] = unique_records(original)
            removed += len(original) - len(result[key])
    for check in result.get('checks', []):
        check.setdefault('source_url', SOURCE_URLS.get(check.get('source'), ''))
        check.setdefault('checked_at', None)
        check.setdefault('profile_url', None)
        check.setdefault('reason', '')
        check.setdefault('status', 'unknown')
    result['schema_version'] = 1
    result['duplicates_removed'] = result.get('duplicates_removed', 0) + removed
    return result


def display_time(value):
    if not value:
        return 'время не записано'
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            return 'часовой пояс не указан'
        return stamp.astimezone(timezone.utc).strftime('%d.%m.%Y %H:%M:%S UTC')
    except (TypeError, ValueError, AttributeError):
        return 'время не распознано'
