"""Evidence graph, not probabilistic person inference. User decisions stay explicit."""
from copy import deepcopy
import hashlib
import json
from urllib.parse import urlsplit, urlunsplit
from search_inputs import normalize_phone, normalize_username, normalize_usernames

MAX_ITEMS = 200
DECISIONS = {'unreviewed', 'mine', 'not_mine'}
DECISION_LABELS = {'unreviewed': 'Не уверен / не проверено', 'mine': 'Моё — отмечено пользователем', 'not_mine': 'Не моё — отмечено пользователем'}


def key(parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:24]


def canonical_profile(source, url):
    from public_sources import SOURCES
    from discovery import SOURCES as DISCOVERY_SOURCES
    allowed = {s[0]: urlsplit(s[1]).hostname for s in SOURCES + DISCOVERY_SOURCES}
    if not isinstance(url, str) or len(url) > 500:
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname != allowed.get(source) or parsed.username or parsed.password or parsed.port not in (None, 443):
            return None
        return urlunsplit(('https', parsed.hostname, parsed.path.rstrip('/') or '/', parsed.query, ''))
    except ValueError:
        return None


def build(data, email=None, phone=None, username=None, additional_usernames=None):
    """Each observation links only to its query. No shared nickname/person union."""
    identifiers = []
    usernames = normalize_usernames(username, additional_usernames)
    values = {'email': (email or '').strip().casefold(), 'phone': normalize_phone(phone), 'username': usernames[0] if usernames else ''}
    for kind, value in values.items():
        if not value:
            continue
        masked = value
        if kind == 'email':
            local, _, domain = value.partition('@')
            masked = local[:1] + '***@' + domain
        elif kind == 'phone':
            masked = '+' + '*' * max(0, len(value)-5) + value[-4:]
        identifiers.append(dict(id='identifier-'+kind, kind=kind, title=masked, decision='unreviewed'))
    username_ids = {name: 'identifier-username' + ('-' + str(index+1) if index else '') for index, name in enumerate(usernames)}
    for name in usernames[1:]:
        identifiers.append(dict(id=username_ids[name], kind='username', title=name, decision='unreviewed'))
    nodes = {}; discarded = 0
    for row in data.get('checks', []):
        if not isinstance(row, dict) or row.get('status') not in ('found', 'possible'):
            continue
        kind = row.get('kind')
        query = 'email' if kind in ('email', 'avatar', 'breach') else kind
        if query not in values or not values[query]:
            continue
        identifier_id = 'identifier-' + query
        if kind == 'username':
            query_name = row.get('query_username', values['username'])
            identifier_id = username_ids.get(query_name) if isinstance(query_name, str) else None
            if not identifier_id:
                continue
        source = str(row.get('source', ''))[:80]
        url = canonical_profile(source, row.get('profile_url')) if kind == 'username' else None
        # Exact account grouping requires a canonical, source-owned profile URL.
        if kind == 'username' and not url:
            continue
        title = source + (' — публичный профиль' if kind == 'username' else ' — результат по ' + query)
        node_id = key([source, kind, url] + ([identifier_id] if kind == 'username' and len(usernames)>1 else []))
        if node_id not in nodes:
            if len(nodes) >= MAX_ITEMS:
                discarded += 1
                continue
            nodes[node_id] = dict(id=node_id, source=source, kind=kind, title=title,
                profile_url=url, identifier_id=identifier_id, decision='unreviewed',
                evidence='indirect_signal' if row['status'] == 'possible' else 'source_match', observations=[])
        observation = dict(status=row['status'], checked_at=row.get('checked_at'), reason=str(row.get('reason', ''))[:1000])
        if observation not in nodes[node_id]['observations']:
            nodes[node_id]['observations'].append(observation)
    snapshot = dict(version=1, revision=1, identifiers=identifiers, findings=list(nodes.values()),
                    omitted=discarded, automatic_person_merges=0, coverage=coverage(data.get('checks', [])))
    return summarize(snapshot)


def summarize(snapshot):
    result = deepcopy(snapshot)
    items = result.get('identifiers', []) + result.get('findings', [])
    result['summary'] = {decision: sum(item['decision'] == decision for item in items) for decision in sorted(DECISIONS)}
    result['owner_group'] = [item['id'] for item in items if item['decision'] == 'mine']
    result['edges'] = [dict(finding_id=item['id'], identifier_id=item['identifier_id'], relation='matched_query_only') for item in result.get('findings', [])]
    result['explanation'] = 'Связь с запросом не доказывает общего владельца. Группа «Моё» основана только на ваших отметках, не на независимой проверке.'
    return result


def decide(snapshot, item_id, decision):
    if decision not in DECISIONS or not isinstance(item_id, str):
        raise ValueError('Invalid identity decision')
    result = deepcopy(snapshot)
    item = next((item for item in result['identifiers'] + result['findings'] if item['id'] == item_id), None)
    if item is None:
        raise ValueError('Unknown identity item')
    item['decision'] = decision
    result['revision'] += 1
    return summarize(result)


def coverage(checks):
    groups = {'found':'completed', 'possible':'completed', 'not_found':'completed',
              'unknown':'inconclusive', 'unavailable':'unavailable', 'skipped':'skipped', 'disabled':'disabled'}
    counts = dict.fromkeys(['completed','inconclusive','unavailable','skipped','disabled'], 0)
    entries = []
    for row in checks[:100]:
        state = row.get('status', 'unknown')
        if state not in groups:
            state = 'unknown'
        counts[groups[state]] += 1
        entries.append(dict(source=str(row.get('source','Источник'))[:80], kind=str(row.get('kind',''))[:20],
            status=state, reason=str(row.get('reason',''))[:1000],
            query_username=str(row.get('query_username',''))[:64], checked_at=row.get('checked_at')))
    return dict(counts=counts, entries=entries, omitted=max(0,len(checks)-100))
