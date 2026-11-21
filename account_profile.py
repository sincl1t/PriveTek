"""Owner-scoped, encrypted presentation settings; no billing mutations."""
import json
import base64
import hashlib
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



def _decode(user_id, ciphertext):
    profile = dict(display_name='', avatar_theme='sky')
    avatar = None
    if ciphertext is not None:
        stored = json.loads(report_cipher().decrypt(bytes(ciphertext)))
        if stored.pop('user_id') != user_id:
            raise ValueError('Неверный владелец профиля')
        encoded = stored.pop('avatar', None)
        profile = normalize(stored)
        if encoded is not None:
            from account_avatar import MAX_STORED
            if not isinstance(encoded, str) or len(encoded) > ((MAX_STORED + 2) // 3) * 4:
                raise ValueError('Неверное изображение профиля')
            avatar = base64.b64decode(encoded, validate=True)
            if len(avatar) > MAX_STORED or not avatar.startswith(b'\xff\xd8'):
                raise ValueError('Неверное изображение профиля')
    return profile, avatar


def avatar_url(content):
    return '/api/account/profile/avatar?v=' + hashlib.sha256(content).hexdigest()[:24] if content else None


def read(user_id):
    with job_store.connect() as db:
        row = db.execute('''SELECT p.ciphertext, s.access_until, s.access_until > now() AS manual_active
            FROM privetek_users u
            LEFT JOIN privetek_account_profiles p ON p.user_id=u.id
            LEFT JOIN privetek_profile_search s ON s.user_id=u.id
            WHERE u.id=%s''', (user_id,)).fetchone()
    if row is None:
        raise ValueError('Аккаунт не найден')
    profile, avatar = _decode(user_id, row['ciphertext'])
    return dict(**profile, avatar_url=avatar_url(avatar), access=dict(mode='pilot', billing_connected=False,
                subscription_required=False, manual_active=bool(row['manual_active']),
                manual_access_until=row['access_until']))


def _update(user_id, profile=None, avatar=None, change_avatar=False):
    # Serialize both operations so saving a name cannot erase a concurrent upload.
    default = report_cipher().encrypt(json.dumps(dict(user_id=user_id, display_name='', avatar_theme='sky')).encode())
    with job_store.connect() as db:
        db.execute('''INSERT INTO privetek_account_profiles (user_id,ciphertext) VALUES (%s,%s)
            ON CONFLICT (user_id) DO NOTHING''', (user_id, default))
        row = db.execute('SELECT ciphertext FROM privetek_account_profiles WHERE user_id=%s FOR UPDATE', (user_id,)).fetchone()
        saved, photo = _decode(user_id, row['ciphertext'])
        if profile is not None:
            saved = profile
        if change_avatar:
            photo = avatar
        data = dict(user_id=user_id, **saved)
        if photo is not None:
            data['avatar'] = base64.b64encode(photo).decode('ascii')
        payload = report_cipher().encrypt(json.dumps(data, ensure_ascii=False).encode())
        db.execute('UPDATE privetek_account_profiles SET ciphertext=%s,updated_at=CURRENT_TIMESTAMP WHERE user_id=%s',
                   (payload, user_id))
    return saved, photo


def save(user_id, data):
    profile = normalize(data)
    _update(user_id, profile=profile)
    return profile


def set_avatar(user_id, content):
    from account_avatar import MAX_STORED
    if content is not None and (len(content) > MAX_STORED or not content.startswith(b'\xff\xd8')):
        raise ValueError('Неверное изображение профиля')
    _, photo = _update(user_id, avatar=content, change_avatar=True)
    return dict(avatar_url=avatar_url(photo))


def get_avatar(user_id):
    with job_store.connect() as db:
        row = db.execute('SELECT ciphertext FROM privetek_account_profiles WHERE user_id=%s', (user_id,)).fetchone()
    return _decode(user_id, row['ciphertext'])[1] if row else None
