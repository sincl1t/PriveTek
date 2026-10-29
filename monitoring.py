"""Pure monitoring comparison. Failures never remove observations or fabricate absence."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from identity_resolution import canonical_profile,key
from analysis_layer import known_sources

MAX_ITEMS=200
RETENTION=timedelta(days=90)


def stamp(value):
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        return parsed if parsed.tzinfo else datetime.min.replace(tzinfo=timezone.utc)
    except (TypeError,ValueError,AttributeError):return datetime.min.replace(tzinfo=timezone.utc)


def observe(data):
    initialized=set();items={};unavailable=set();states={}
    allowed=known_sources()
    for check in data.get('checks',[]):
        source,kind,status=check.get('source'),check.get('kind'),check.get('status')
        if source not in allowed or kind not in ('email','username','avatar','breach'):
            continue
        coverage_key=source+':'+kind
        states.setdefault(coverage_key,set()).add(status)
        if status in ('found','possible','not_found'):
            initialized.add(coverage_key)
        elif status in ('unavailable','unknown'):
            unavailable.add(coverage_key)
        if status not in ('found','possible'):
            continue
        url=canonical_profile(source,check.get('profile_url')) if kind=='username' else None
        if kind=='username' and not url:
            initialized.discard(coverage_key);unavailable.add(coverage_key);continue
        candidates=[(None,None)]
        if kind=='breach':
            candidates=[(str(row.get('name','')).strip(),str(row.get('date',''))) for row in data.get('email_breach') or [] if row.get('source','HIBP')==source and isinstance(row.get('name'),str) and row['name'].strip()]
            if not candidates:
                initialized.discard(coverage_key);unavailable.add(coverage_key)
        for name,date in candidates:
            # Date corrections and category updates are not a newly observed breach.
            item_key=key([source,kind,url,name.casefold() if name else None])
            items[item_key]=dict(id=item_key,source=source,kind=kind,status=status,
                profile_url=url,breach_name=name[:150] if name else None,breach_date=date[:40] if date else None,
                coverage_key=coverage_key,link_id=key([source,kind,url]))
    conflicts={source for source,statuses in states.items() if 'not_found' in statuses and statuses & {'found','possible'}}
    initialized.difference_update(conflicts);unavailable.update(conflicts)
    items={item_id:item for item_id,item in items.items() if item['coverage_key'] not in conflicts}
    if len(items)>MAX_ITEMS:raise ValueError('Monitor item limit exceeded')
    return dict(items=items,initialized=sorted(initialized),unavailable=sorted(unavailable))


def compare(previous,observations,current,excluded=None):
    previous=deepcopy(previous or {'seen':{},'sources':{}});excluded=excluded or set()
    cutoff=current-RETENTION
    seen={k:v for k,v in previous.get('seen',{}).items() if stamp(v['last_seen'])>cutoff}
    sources={k:v for k,v in previous.get('sources',{}).items() if stamp(v)>cutoff}
    changes=[];baseline_items=[];status_updates=[]
    for item_id,item in observations['items'].items():
        if item['coverage_key'] not in sources:
            baseline_items.append(dict(item,excluded=item_id in excluded))
        elif item_id not in seen:
            changes.append(dict(item,excluded=item_id in excluded))
        elif seen[item_id].get('status',item['status'])!=item['status']:
            status_updates.append(dict(item,from_status=seen[item_id]['status']))
        seen[item_id]={'last_seen':current.isoformat(),'status':item['status']}
    for source in observations['initialized']:sources[source]=current.isoformat()
    if len(seen)>2000:raise ValueError('Monitor history limit exceeded')
    return dict(baseline={'seen':seen,'sources':sources},
        details=dict(items=changes,baseline_items=baseline_items,status_updates=status_updates,unavailable=observations['unavailable'],
                     checked_sources=len(observations['initialized']),baseline_only=not previous.get('sources'),
                     notice='Впервые обнаружено мониторингом; это не дата создания аккаунта или возникновения утечки.'),
        new_count=sum(not item['excluded'] for item in changes))
