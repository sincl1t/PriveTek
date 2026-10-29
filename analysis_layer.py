"""Explainable analysis facts. No LLM may change evidence, ownership or priorities."""
from collections import Counter
from copy import deepcopy
import json
from identity_resolution import canonical_profile, key

VERSION = 1
CLASS_ALIASES = {'Passwords':'password','password':'password','Email addresses':'email','email':'email',
                 'Phone numbers':'phone','phone':'phone','Names':'name','first_name':'name','last_name':'name',
                 'Usernames':'username','username':'username','IP addresses':'ip','ip':'ip',
                 'Dates of birth':'birthdate','address':'address'}
CATEGORY_LABELS = {'breach':'Сведения об утечках','public_profile':'Публичный профиль',
                   'public_avatar':'Публичный аватар','registration_signal':'Возможная регистрация'}
PRIORITY_LABELS = {'high':'В первую очередь','review':'Требует проверки','informational':'Для сведения','excluded':'Исключено по вашей отметке'}
REASONS = {
 'password_record':'Источник сообщает о категории паролей в записи утечки. Проверьте, меняли ли вы пароль после неё; совпадение не доказывает компрометацию действующего пароля.',
 'global_classes':'Категории данных относятся ко всем совпадениям провайдера вместе. Их нельзя приписать отдельной утечке.',
 'breach_metadata':'Получены метаданные утечек. Проверьте записи и принадлежность данных; состав полей не означает раскрытие значений.',
 'public_profile':'Публичный профиль сам по себе не является утечкой или угрозой. Сначала проверьте владельца.',
 'public_avatar':'Публичный аватар сам по себе не является утечкой.',
 'indirect_registration':'Косвенный признак регистрации требует самостоятельного подтверждения.',
 'conflicting_observations':'Наблюдения источника противоречат друг другу. Автоматический вывод не сделан.',
 'excluded_by_user':'Вы отметили результат как «Не моё». Факт источника сохранён, персональная рекомендация исключена.'}


def known_sources():
    from public_sources import SOURCES
    from discovery import SOURCES as DISCOVERY_SOURCES
    return {s[0] for s in SOURCES + DISCOVERY_SOURCES} | {'HIBP','LeakCheck','Gravatar','Amazon','Instagram','Spotify'}


def make_basis(data):
    allowed = known_sources()
    groups = {}; coverage = Counter(); observed = {}; check_seen = set(); duplicates = 0
    checks = data.get('checks', [])
    for check in checks if isinstance(checks,list) else []:
        if not isinstance(check, dict):
            continue
        source, kind, status = check.get('source'), check.get('kind'), check.get('status')
        if not isinstance(source,str) or not isinstance(kind,str) or not isinstance(status,str) or source not in allowed or kind not in {'breach','email','phone','username','avatar'} or status not in {'found','possible','unknown','not_found','unavailable','skipped','disabled'}:
            continue
        profile = canonical_profile(source, check.get('profile_url')) if kind == 'username' else None
        signature = (source,kind,status,profile,check.get('checked_at') if isinstance(check.get('checked_at'),str) else None)
        if signature in check_seen:
            duplicates += 1
            continue
        check_seen.add(signature); coverage[status] += 1
        observation_key = (source,kind,profile)
        observed.setdefault(observation_key,set()).add(status)
        if status not in {'found','possible'}:
            continue
        if kind == 'username' and not profile:
            continue
        category = {'breach':'breach','username':'public_profile','avatar':'public_avatar','email':'registration_signal','phone':'registration_signal'}[kind]
        group_key = (source,kind,profile)
        if group_key not in groups:
            groups[group_key] = dict(source=source,category=category,link_id=key([source,kind,profile]),
                evidence='indirect_signal' if status == 'possible' else 'source_match', observations=0,
                classes=[], record_count=0, classes_scope='unknown', conflict=False)
        else:
            duplicates += 1
        groups[group_key]['observations'] += 1
    for group_key, group in groups.items():
        statuses = observed.get(group_key,set())
        group['conflict'] = 'found' in statuses and 'not_found' in statuses
        if group['category'] != 'breach':
            continue
        records = {}; global_classes = set(); record_classes = set(); scopes = set()
        breaches = data.get('email_breach') or []
        for row in breaches if isinstance(breaches,list) else []:
            if not isinstance(row,dict) or row.get('source','HIBP') != group['source']:
                continue
            scope = 'provider_global' if row.get('classes_scope') else 'per_record'
            scopes.add(scope)
            record_key = (str(row.get('name','')).strip().casefold(),str(row.get('date','')),scope)
            supplied_classes = row.get('data_classes',[])
            classes = {CLASS_ALIASES[c] for c in (supplied_classes if isinstance(supplied_classes,list) else []) if isinstance(c,str) and c in CLASS_ALIASES}
            if record_key in records:
                duplicates += 1
            records.setdefault(record_key,set()).update(classes)
            (global_classes if scope == 'provider_global' else record_classes).update(classes)
        group['record_count'] = len(records)
        group['classes'] = sorted(record_classes | global_classes)
        group['classes_scope'] = 'mixed' if len(scopes)>1 else next(iter(scopes)) if scopes else 'unknown'
        # Never turn global provider categories into a record-specific password claim.
        group['record_password_category'] = 'password' in record_classes
    result = list(groups.values())
    for index, group in enumerate(result):
        group['fact_id'] = 'F' + str(index+1)
    return dict(version=VERSION,groups=result,coverage=dict(coverage),duplicates_grouped=duplicates)


def analyze(data):
    resolution = data.get('identity_resolution') or {}
    basis = deepcopy(resolution.get('analysis_basis')) if resolution.get('analysis_basis',{}).get('version') == VERSION else make_basis(data)
    decisions = {item['id']:item.get('decision','unreviewed') for item in resolution.get('findings',[])}
    items=[]
    for group in basis['groups']:
        item = dict(group)
        ownership = decisions.get(item['link_id'],'unreviewed')
        if ownership not in {'mine','not_mine','unreviewed'}:
            ownership = 'unreviewed'
        item['ownership'] = ownership
        if item['conflict']:
            priority, reason = 'review','conflicting_observations'
        elif item['category'] == 'breach':
            if item.get('record_password_category'):
                priority, reason = 'high','password_record'
            elif item['classes_scope'] in {'provider_global','mixed'}:
                priority, reason = 'review','global_classes'
            else:
                priority, reason = 'review','breach_metadata'
        elif item['category'] == 'registration_signal':
            priority, reason = 'review','indirect_registration'
        elif item['category'] == 'public_profile':
            priority, reason = ('informational' if ownership == 'mine' else 'review'),'public_profile'
        else:
            priority, reason = 'informational','public_avatar'
        if item['evidence'] == 'indirect_signal' and priority == 'high':
            priority, reason = 'review','indirect_registration'
        if ownership == 'not_mine':
            priority, reason = 'excluded','excluded_by_user'
        item.update(priority=priority,reason_code=reason)
        items.append(item)
    counts=Counter(item['priority'] for item in items)
    return dict(version=VERSION,engine='rules',basis=basis,items=items,
                priorities={p:counts[p] for p in PRIORITY_LABELS},coverage=basis['coverage'],
                model_status='not_configured',notice='Приоритет проверки не является вероятностью принадлежности или оценкой взлома. Отметки пользователя не являются независимым доказательством.')


def lines(analysis, limit=5, selected_ids=None):
    order={'high':0,'review':1,'informational':2,'excluded':3}
    by_id={item['fact_id']:item for item in analysis['items']}
    chosen=[by_id[i] for i in selected_ids] if selected_ids is not None else sorted(analysis['items'],key=lambda item:order[item['priority']])[:limit]
    result=[]
    for item in chosen:
        result.append(item['source']+' · '+CATEGORY_LABELS[item['category']]+' · '+PRIORITY_LABELS[item['priority']]+'. '+REASONS[item['reason_code']])
    if not result:
        result.append('Для приоритизации недостаточно положительных сведений. Отсутствие находок не гарантирует безопасность.')
    return result


def model_facts(analysis):
    """Strict allowlist: no names, URLs, timestamps, queries, reasons or breach titles."""
    return dict(version=VERSION,coverage=analysis['coverage'],priorities=analysis['priorities'],
        findings=[{k:item[k] for k in ('fact_id','category','evidence','ownership','priority','reason_code','classes_scope','record_count','classes')} for item in analysis['items']])
