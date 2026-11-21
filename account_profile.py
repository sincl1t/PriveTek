"""Owner-scoped, encrypted presentation settings; no billing mutations."""
import json
import unicodedata
import job_store
from account_crypto import report_cipher

THEMES = ('sky', 'violet', 'mint', 'rose', 'amber', 'slate')


def normalize(data):
    if set(data) != {'display_name', 'avatar_theme'}:
        raise ValueError('Можно изменить только имя и цвет аватара')
    name, theme = data['display_name'], data['avatar_theme']
    if not isinstance(name, str) or len(name) > 80 or any(unicodedata.category(c).startswith('C') for c in name):
        raise ValueError('Имя — до 80 символов, без управляющих знаков')
    if not isinstance(theme, str) or theme not in THEMES:
        raise ValueError('Выберите цвет аватара из списка')
    return dict(display_name=' '.join(name.split()), avatar_theme=theme)


def read(user_id):
    with job_store.connect() as db:
        row = db.execute('''SELECT p.ciphertext, s.access_until, s.access_until > now() AS manual_active
            FROM privetek_users u
            LEFT JOIN privetek_account_profiles p ON p.user_id=u.id
            LEFT JOIN privetek_profile_search s ON s.user_id=u.id
            WHERE u.id=%s''', (user_id,)).fetchone()
    if row is None:
        raise ValueError('Аккаунт не найден')
    profile = dict(display_name='', avatar_theme='sky')
    if row['ciphertext'] is not None:
        stored = json.loads(report_cipher().decrypt(bytes(row['ciphertext'])))
        if stored.pop('user_id') != user_id:
            raise ValueError('Неверный владелец профиля')
        profile = normalize(stored)
    return dict(**profile, access=dict(mode='pilot', billing_connected=False,
                subscription_required=False, manual_active=bool(row['manual_active']),
                manual_access_until=row['access_until']))


def save(user_id, data):
    profile = normalize(data)
    payload = report_cipher().encrypt(json.dumps(dict(user_id=user_id, **profile), ensure_ascii=False).encode())
    with job_store.connect() as db:
        db.execute('''INSERT INTO privetek_account_profiles (user_id,ciphertext) VALUES (%s,%s)
            ON CONFLICT (user_id) DO UPDATE SET ciphertext=EXCLUDED.ciphertext, updated_at=CURRENT_TIMESTAMP''',
            (user_id, payload))
    return profile
