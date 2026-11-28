"""SMS.RU adapter. No network unless both independent live gates are enabled."""
import os
import re
import httpx
from search_inputs import normalize_phone


class SmsUnavailable(Exception):
    pass


def configured():
    return (os.getenv('SMS_AUTH_ENABLED','false').lower()=='true'
            and os.getenv('SMS_LIVE_SEND_ENABLED','false').lower()=='true'
            and os.getenv('SMS_PROVIDER')=='sms_ru' and bool(os.getenv('SMS_RU_API_ID','').strip())
            and bool(os.getenv('SMS_PILOT_PHONE_HASHES','').strip()))


def send_code(phone,code):
    if not configured():raise SmsUnavailable('SMS отключены')
    phone=normalize_phone(phone)
    if not phone or not re.fullmatch(r'\d{8}',code):raise SmsUnavailable('Неверный запрос SMS')
    try:
        response=httpx.post('https://sms.ru/sms/send',data={
            'api_id':os.environ['SMS_RU_API_ID'],'to':phone.lstrip('+'),
            'msg':'PriveTek code: '+code,'json':'1','ttl':'5',
        },timeout=10,follow_redirects=False)
        if response.status_code!=200:raise SmsUnavailable('Отправка SMS не подтверждена')
        body=response.json();row=body.get('sms',{}).get(phone.lstrip('+'),{})
        if body.get('status')!='OK' or row.get('status')!='OK' or row.get('status_code')!=100:
            raise SmsUnavailable('Отправка SMS не подтверждена')
    except (httpx.HTTPError,ValueError,TypeError,AttributeError):
        raise SmsUnavailable('Отправка SMS не подтверждена') from None
    # Provider acceptance is not proof of handset delivery; no automatic retries.
