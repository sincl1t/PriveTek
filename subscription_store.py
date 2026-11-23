"""Encrypted, owner-bound user-confirmed subscription metadata. No statements."""
from datetime import date
from decimal import Decimal, InvalidOperation
import json
import re
import unicodedata
import job_store
from account_crypto import report_cipher


class Conflict(Exception):
    pass


def normalize(data):
    if not isinstance(data, dict) or set(data) != {'revision', 'items'}:
        raise ValueError('Неверный формат списка')
    if type(data['revision']) is not int or data['revision'] < 0:
        raise ValueError('Неверная версия списка')
    if not isinstance(data['items'], list) or len(data['items']) > 100:
        raise ValueError('Можно сохранить до 100 подписок')
    items = []
    for row in data['items']:
        if not isinstance(row, dict) or set(row) != {'id','merchant','amount','currency','period','last_date','status'}:
            raise ValueError('Можно сохранить только сведения о подписке')
        if not isinstance(row['id'],str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',row['id']):
            raise ValueError('Неверный идентификатор')
        name = row['merchant']
        if not isinstance(name,str) or not 1 <= len(name.strip()) <= 100 or any(unicodedata.category(c).startswith('C') for c in name):
            raise ValueError('Название сервиса — до 100 символов')
        if not isinstance(row['amount'], str) or not re.fullmatch(r'\d{1,8}(\.\d{1,2})?',row['amount']):
            raise ValueError('Укажите положительную сумму с точностью до копеек')
        try:
            amount = Decimal(row['amount'])
        except InvalidOperation:
            raise ValueError('Неверная сумма') from None
        if not 0 < amount <= 10000000:
            raise ValueError('Сумма должна быть больше нуля и не превышать 10 000 000')
        if row['currency'] not in ('RUB','USD','EUR','GBP','KZT','BYN','UAH'):
            raise ValueError('Выберите поддерживаемую валюту')
        if row['period'] not in ('weekly','monthly','quarterly','yearly') or row['status'] not in ('active','review','cancelled','not_subscription'):
            raise ValueError('Неверный период или статус')
        try:
            parsed = date.fromisoformat(row['last_date'])
            if parsed.isoformat() != row['last_date'] or not 2000 <= parsed.year <= 2100:
                raise ValueError()
        except (TypeError,ValueError):
            raise ValueError('Укажите дату последнего платежа') from None
        items.append(dict(row,merchant=name.strip(),amount=f'{amount:.2f}'))
    if len({row['id'] for row in items}) != len(items):
        raise ValueError('Повторяющиеся идентификаторы')
    return dict(revision=data['revision'],items=items)


def decode(user_id,row):
    if row is None:
        return dict(revision=0,items=[])
    data=json.loads(report_cipher().decrypt(bytes(row['ciphertext'])))
    if data.pop('user_id') != user_id:
        raise ValueError('Неверный владелец')
    return normalize(dict(revision=row['revision'],items=data['items']))


def read(user_id):
    with job_store.connect() as db:
        row=db.execute('SELECT ciphertext,revision FROM privetek_subscription_lists WHERE user_id=%s',(user_id,)).fetchone()
    return decode(user_id,row)


def save(user_id,data):
    data=normalize(data)
    encrypted=report_cipher().encrypt(json.dumps(dict(user_id=user_id,items=data['items']),ensure_ascii=False).encode())
    with job_store.connect() as db:
        if data['revision']==0:
            row=db.execute('INSERT INTO privetek_subscription_lists (user_id,ciphertext,revision) VALUES (%s,%s,1) ON CONFLICT DO NOTHING RETURNING revision',(user_id,encrypted)).fetchone()
        else:
            row=db.execute('UPDATE privetek_subscription_lists SET ciphertext=%s,revision=revision+1,updated_at=now() WHERE user_id=%s AND revision=%s RETURNING revision',(encrypted,user_id,data['revision'])).fetchone()
        if not row:
            raise Conflict()
    return dict(items=data['items'],revision=row['revision'])
