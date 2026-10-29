"""Optional, disabled-by-default OpenAI editor. Returns references, never free-form claims."""
import json
import os
import re
import time
import httpx
from analysis_layer import model_facts

ENDPOINT = 'https://api.openai.com/v1/responses'
ORDER = {'high':0,'review':1,'informational':2,'excluded':3}


def validate_selection(value, analysis):
    if not isinstance(value,dict) or set(value) != {'fact_ids'}:
        return False
    ids=value['fact_ids']
    allowed={item['fact_id']:item for item in analysis['items'] if item['priority']!='excluded'}
    if not isinstance(ids,list) or not 1<=len(ids)<=5 or any(not isinstance(i,str) for i in ids) or len(ids)!=len(set(ids)) or any(i not in allowed for i in ids):
        return False
    # A model cannot suppress the first five high-priority rule findings.
    required=[i for i,item in allowed.items() if item['priority']=='high'][:5]
    if not set(required)<=set(ids):
        return False
    ranks=[ORDER[allowed[i]['priority']] for i in ids]
    return ranks==sorted(ranks)


def request_body(analysis, model):
    ids=[item['fact_id'] for item in analysis['items'] if item['priority']!='excluded']
    schema={'type':'object','properties':{'fact_ids':{'type':'array','items':{'type':'string','enum':ids},'minItems':1,'maxItems':5}},'required':['fact_ids'],'additionalProperties':False}
    return dict(model=model,store=False,max_output_tokens=512,
        instructions='Select up to five existing fact IDs for a concise report. Include the first five high priority facts. Order by high, review, informational. Excluded facts must not be selected. Do not infer ownership or change priorities. Return JSON only.',
        input=json.dumps(model_facts(analysis),ensure_ascii=False),
        text={'format':{'type':'json_schema','name':'privetek_summary_selection','strict':True,'schema':schema}})


def select(analysis):
    if os.getenv('AI_SUMMARY_ENABLED','false').lower()!='true':
        return {'status':'disabled'}
    key=os.getenv('OPENAI_API_KEY','');model=os.getenv('AI_SUMMARY_MODEL','')
    if not key or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',model) or os.getenv('AI_DATA_TRANSFER_APPROVED','false').lower()!='true':
        return {'status':'not_configured'}
    try:cap=int(os.getenv('AI_MAX_CALLS_PER_HOUR','0'))
    except ValueError:return {'status':'not_configured'}
    if not 1<=cap<=1000:return {'status':'not_configured'}
    if not any(item['priority']!='excluded' for item in analysis['items']):
        return {'status':'no_findings'}
    payload=request_body(analysis,model)
    if len(payload['input'].encode())>16384:
        return {'status':'input_limit'}
    try:
        # Shared database quota; every attempted API request consumes a slot, even failures.
        import account_store
        if not account_store.quota([('ai-summary:global','all',cap)]):
            return {'status':'rate_limited'}
        deadline=time.monotonic()+12
        with httpx.Client(timeout=httpx.Timeout(8,connect=3,write=3,pool=3),follow_redirects=False,trust_env=False) as client:
            with client.stream('POST',ENDPOINT,json=payload,headers={'Authorization':'Bearer '+key}) as response:
                if response.status_code!=200:return {'status':'unavailable'}
                content=bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content)>65536 or time.monotonic()>deadline:return {'status':'rejected'}
                body=json.loads(content)
        if not isinstance(body,dict) or body.get('status')!='completed':return {'status':'rejected'}
        texts=[part['text'] for item in body.get('output',[]) if item.get('type')=='message' and item.get('role')=='assistant' for part in item.get('content',[]) if part.get('type')=='output_text']
        if len(texts)!=1:return {'status':'rejected'}
        value=json.loads(texts[0])
        if not validate_selection(value,analysis):return {'status':'rejected'}
        return {'status':'selected','fact_ids':value['fact_ids']}
    except Exception:
        # Never log provider text, API credentials or request/response bodies.
        return {'status':'unavailable'}


def display_ids(selection, analysis):
    if not isinstance(selection,dict) or selection.get('status')!='selected':return None
    value={'fact_ids':selection.get('fact_ids')}
    return value['fact_ids'] if validate_selection(value,analysis) else None
