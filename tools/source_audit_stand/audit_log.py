"""Readable audit evidence: request → response → product result → actual PDF text."""
import json
import re

from helpers import trace_context, trace_lock

SOURCES = {'LeakCheck', 'GitHub', 'GitLab', 'Amazon'}
PHONE_QUERY = 'submitted'
LABELS = {'found': 'Найдены сведения', 'not_found': 'Находок в источнике нет',
          'possible': 'Возможная регистрация', 'unknown': 'Неопределённый результат',
          'unavailable': 'Проверка недоступна', 'skipped': 'Не проверялось',
          'disabled': 'Проверка отключена'}
GROUPS = ('Находки и возможные совпадения', 'Проверки без находок', 'Ограничения проверки')


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(', ', ': '))


def event(source, query, stage, details):
    job = getattr(trace_context, 'job_id', '-')
    kind = {'LeakCheck': 'email', 'Amazon': 'phone'}.get(source, 'username')
    with trace_lock:
        print(f'AUDIT | job={job} | {source} | {kind}={compact(query)} | {stage} | {details}', flush=True)


def begin(email, usernames, *, phone_supplied=False):
    trace_context.audit_email = email
    trace_context.audit_phone_supplied = phone_supplied
    trace_context.audit_requests = {}
    trace_context.audit_responses = {}
    trace_context.audit_checks = []


def request(source, query, method, url, mode='live'):
    requests = getattr(trace_context, 'audit_requests', None)
    if requests is not None:
        requests[(source, query)] = f'{method} {url}'
    event(source, query, 'ЗАПРОС', f'{method} {url} | mode={mode}')


def response_fields(source, payload):
    """Allowlisted public evidence; no credentials, profile bio or breach values."""
    if isinstance(payload, list):
        if source != 'GitLab':
            return {'json_type': 'array', 'items_count': len(payload)}
        rows = [response_fields(source, item) for item in payload[:3]]
        return {'users_count': len(payload), 'users': rows, 'users_omitted': max(0, len(payload) - len(rows))}
    if not isinstance(payload, dict):
        return {'json_type': type(payload).__name__, 'value': payload if isinstance(payload, (bool, int, type(None))) else None}
    keys = ('success', 'found', 'error') if source == 'LeakCheck' else (
        ('id', 'login', 'type', 'html_url', 'message') if source == 'GitHub' else
        ('id', 'username', 'web_url', 'state', 'message', 'error'))
    fields = {key: payload[key] for key in keys if key in payload and isinstance(payload[key], (str, int, bool, type(None)))}
    if source == 'LeakCheck':
        if isinstance(payload.get('fields'), list):
            fields['fields'] = [item for item in payload['fields'] if isinstance(item, str)]
        if isinstance(payload.get('sources'), list):
            sources = payload['sources']
            fields['sources_count'] = len(sources)
            fields['sources_first_3'] = [{key: row[key] for key in ('name', 'date')
                                         if key in row and isinstance(row[key], (str, type(None)))}
                                        for row in sources[:3] if isinstance(row, dict)]
            fields['sources_omitted'] = max(0, len(sources) - 3)
    return fields or {'json_type': 'object', 'recognized_fields': []}


def response(source, query, http_response, elapsed_ms):
    if source == 'Amazon':
        fields = {'content_type': http_response.headers.get('content-type'),
                  'bytes': len(http_response.content)}
    else:
        try:
            fields = response_fields(source, http_response.json())
        except ValueError:
            fields = {'json_error': 'Ответ не является корректным JSON',
                      'content_type': http_response.headers.get('content-type'),
                      'bytes': len(http_response.content)}
    observation = {'http_status': http_response.status_code, 'elapsed_ms': elapsed_ms, 'details': fields}
    observations = getattr(trace_context, 'audit_responses', None)
    if observations is not None:
        observations[(source, query)] = observation
    event(source, query, 'ОТВЕТ', f'HTTP {http_response.status_code} | {elapsed_ms} мс | {compact(fields)}')


def failure(source, query, error):
    event(source, query, 'ОШИБКА ЗАПРОСА', type(error).__name__)


def check_query(check):
    if check['source'] == 'LeakCheck':
        return getattr(trace_context, 'audit_email', None)
    if check['source'] == 'Amazon':
        return PHONE_QUERY if getattr(trace_context, 'audit_phone_supplied', False) else None
    return check.get('query_username')


def processed(result):
    checks = [row for row in result['checks'] if row['source'] in SOURCES and
              (row['source'] != 'Amazon' or (row['kind'] == 'phone' and check_query(row) is not None))]
    trace_context.audit_checks = checks
    for check in checks:
        source = check['source']
        query = check_query(check)
        details = {'status': check['status'], 'reason': check.get('reason'),
                   'profile_url': check.get('profile_url')}
        if source == 'LeakCheck':
            rows = [row for row in (result.get('email_breach') or []) if row.get('source') == 'LeakCheck']
            details['sources_passed_to_report'] = None if result.get('email_breach') is None else len(rows)
        elif source == 'Amazon':
            findings = (result.get('identity_resolution') or {}).get('findings', [])
            details['included_as_indirect_signal'] = any(
                row['source'] == source and row['kind'] == 'phone' and row['evidence'] == 'indirect_signal'
                for row in findings)
        else:
            details['included_in_profile_findings'] = any(row.get('site') == source and
                row.get('profile_url') == check.get('profile_url') for row in (result.get('username_profiles') or []))
        if (source, query) not in getattr(trace_context, 'audit_requests', {}):
            event(source, query, 'ЗАПРОС', 'Не отправлялся.')
        event(source, query, 'ОБРАБОТКА ПРИЛОЖЕНИЕМ', compact(details))


def pdf_panels(text):
    """Read captions, grouping and panel contents from extracted PDF, not a guess."""
    labels = '|'.join(re.escape(label) for label in LABELS.values())
    header = re.compile(r'^([^\n]+): (' + labels + r')\s*$', re.MULTILINE)
    panels = []
    sections = [('LeakCheck', 'Утечки данных по email', 'Регистрации email на сайтах'),
                ('Amazon', 'Регистрации телефона на сайтах', 'Публичные профили по username'),
                (None, 'Публичные профили по username', None)]
    for only_source, title, next_title in sections:
        if title not in text:
            continue
        section = text.split(title, 1)[1]
        if next_title:
            section = section.split(next_title, 1)[0]
        matches = list(header.finditer(section))
        for index, match in enumerate(matches):
            source, label = match.group(1).strip(), match.group(2).strip()
            if source not in SOURCES or (only_source and source != only_source):
                continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
            body = ' '.join(section[match.end():end].split())
            before = section[:match.start()]
            group = max(GROUPS, key=lambda value: before.rfind(value))
            if group not in before:
                group = None
            panels.append(dict(source=source, label=f'{source}: {label}', status_label=label,
                               section=title, group=group, body=body))
    return panels


def report(text):
    panels = pdf_panels(text)
    observations = []
    for check in getattr(trace_context, 'audit_checks', []):
        source = check['source']
        query = check_query(check)
        candidates = [panel for panel in panels if panel['source'] == source]
        if source in ('GitHub', 'GitLab') and query is not None:
            pattern = r'Проверялся username:\s*' + re.escape(query or '') + r'(?=\s|$)'
            candidates = [panel for panel in candidates if re.search(pattern, panel['body'])]
        if len(candidates) != 1:
            event(source, query, 'В ОТЧЁТЕ', 'Карточка проверки не сопоставлена с текстом PDF')
            observations.append(dict(source=source, query=query, matched=False))
            continue
        panel = candidates[0]
        reason_present = ' '.join(check.get('reason', '').split()) in panel['body']
        url = check.get('profile_url')
        expected_group = GROUPS[0] if check['status'] in ('found', 'possible') else (
            GROUPS[1] if check['status'] == 'not_found' else GROUPS[2])
        consistent = (panel['status_label'] == LABELS.get(check['status']) and panel['group'] == expected_group
                      and reason_present and (not url or url in panel['body']))
        details = {'раздел': panel['section'], 'группа': panel['group'], 'заголовок': panel['label'],
                   'пояснение': check.get('reason') if reason_present else 'Пояснение не найдено в тексте PDF',
                   'ссылка_на_профиль': url if url and url in panel['body'] else None,
                   'соответствует_результату_обработки': bool(consistent)}
        event(source, query, 'В ОТЧЁТЕ — ПРОЧИТАНО ИЗ PDF', compact(details))
        observations.append(dict(source=source, query=query, matched=True, consistent=bool(consistent), **details))
    return observations
