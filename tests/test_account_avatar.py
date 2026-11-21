from io import BytesIO
import struct
import zlib
from unittest.mock import MagicMock
import pytest
from PIL import Image
import account_avatar as avatar
import account_profile
import account_store
import job_store
from account_routes import COOKIE
from test_accounts import client, db, login, register, settings  # noqa: F401


def picture(fmt='PNG'):
    image = Image.new('RGB', (80, 40), 'red')
    image.paste('blue', (40, 0, 80, 40))
    out = BytesIO()
    exif = Image.Exif(); exif[270] = 'PRIVATE-METADATA-FIXTURE'; exif[274] = 6
    image.save(out, format=fmt, exif=exif)
    image.close()
    return out.getvalue()


@pytest.mark.parametrize('fmt', ['PNG','JPEG','WEBP'])
def test_avatar_reencodes_bounds_rotates_and_strips_metadata(fmt):
    normalized = avatar.canonicalize(picture(fmt))
    assert len(normalized) <= avatar.MAX_STORED
    assert b'PRIVATE-METADATA' not in normalized
    with Image.open(BytesIO(normalized)) as im:
        assert im.format == 'JPEG' and im.size == (512,512)
        assert not im.getexif() and 'icc_profile' not in im.info
        # EXIF orientation 6 turns left/right halves into top/bottom halves.
        top, bottom = im.getpixel((256,100)), im.getpixel((256,400))
        assert top[0] > top[2] and bottom[2] > bottom[0]


def test_avatar_rejects_large_dimensions_before_loading_pixels():
    source = picture()
    ihdr = struct.pack('>IIBBBBB',6000,6000,8,2,0,0,0)
    crafted = source[:8] + struct.pack('>I',13) + b'IHDR' + ihdr + struct.pack('>I',zlib.crc32(b'IHDR'+ihdr)) + source[33:]
    with pytest.raises(ValueError, match='25'):
        avatar.canonicalize(crafted)


@pytest.mark.parametrize('content', [b'', b'not an image', b'<svg xmlns="http://www.w3.org/2000/svg"></svg>'])
def test_avatar_rejects_non_image_content(content):
    with pytest.raises(ValueError): avatar.canonicalize(content)


def test_avatar_rejects_animation_and_excess_bytes():
    first, second = Image.new('RGB',(4,4),'red'), Image.new('RGB',(4,4),'blue')
    out = BytesIO(); first.save(out,format='PNG',save_all=True,append_images=[second],duration=100)
    with pytest.raises(ValueError): avatar.canonicalize(out.getvalue())
    with pytest.raises(ValueError): avatar.canonicalize(b'x'*(avatar.MAX_UPLOAD+1))


def test_avatar_limits_simultaneous_decoding():
    avatar._SLOT.acquire()
    try:
        with pytest.raises(avatar.AvatarBusy): avatar.canonicalize(picture())
    finally: avatar._SLOT.release()


def test_avatar_api_guards_before_decoding(settings, monkeypatch):
    c = client()
    assert c.get('/api/account/profile/avatar').status_code == 401
    assert c.put('/api/account/profile/avatar', content=b'x',headers={'Content-Type':'image/png'}).status_code == 401
    assert c.delete('/api/account/profile/avatar').status_code == 401
    monkeypatch.setattr(account_store,'session',lambda _:dict(id='owner',email='owner@example.com'))
    c.cookies.set(COOKIE,'x'*43)
    decode = MagicMock(); monkeypatch.setattr(avatar,'canonicalize',decode)
    assert c.put('/api/account/profile/avatar',content=b'x',headers={'Content-Type':'image/png'}).status_code == 403
    assert c.delete('/api/account/profile/avatar',headers={'Origin':'https://evil.test'}).status_code == 403
    decode.assert_not_called()


def test_db_avatar_private_encrypted_reloads_survives_name_save_and_deletes(db):
    a,b = client(),client(); register(a,db); register(b,db,'other@example.com')
    csrf=login(a); login(b,'other@example.com')
    url='/api/account/profile/avatar'; headers={'X-CSRF-Token':csrf,'Content-Type':'image/png'}
    assert a.get(url).status_code == 404
    response=a.put(url,content=picture(),headers=headers)
    assert response.status_code == 200, response.text
    versioned=response.json()['avatar_url']
    assert versioned.startswith(url+'?v=')
    image=a.get(versioned)
    assert image.status_code==200 and image.headers['content-type']=='image/jpeg'
    assert image.headers['cache-control']=='no-store' and image.headers['x-content-type-options']=='nosniff'
    assert b.get(versioned).status_code==404 and client().get(versioned).status_code==401
    assert a.get('/api/account/profile').json()['avatar_url']==versioned
    with job_store.connect() as conn:
        ciphertext=bytes(conn.execute('SELECT ciphertext FROM privetek_account_profiles').fetchone()['ciphertext'])
        assert image.content not in ciphertext
    payload={'display_name':'Имя с фото','avatar_theme':'mint'}
    assert a.put('/api/account/profile',json=payload,headers={'X-CSRF-Token':csrf}).status_code==200
    assert a.get(versioned).content==image.content
    # A fresh session sees the stored photo, not an in-memory browser preview.
    fresh=client(); fresh_csrf=login(fresh)
    assert fresh.get('/api/account/profile').json()['avatar_url']==versioned
    assert fresh.get(versioned).content==image.content
    # Invalid uploads cannot replace an existing valid avatar.
    assert a.put(url,content=b'bad',headers=headers).status_code==422
    assert a.put(url,content=b'x'*(avatar.MAX_UPLOAD+1),headers=headers).status_code==413
    assert a.put(url,content=b'<svg/>',headers={**headers,'Content-Type':'image/svg+xml'}).status_code==415
    assert a.get(versioned).content==image.content
    assert fresh.delete(url,headers={'X-CSRF-Token':fresh_csrf}).json()=={'avatar_url':None}
    assert fresh.get(versioned).status_code==404
    profile=fresh.get('/api/account/profile').json()
    assert profile['display_name']==payload['display_name'] and profile['avatar_theme']=='mint'
    assert profile['avatar_url'] is None


def test_db_concurrent_name_and_photo_updates_preserve_both(db):
    from concurrent.futures import ThreadPoolExecutor
    c=client(); register(c,db); login(c)
    with job_store.connect() as conn:
        uid=conn.execute('SELECT id FROM privetek_users').fetchone()['id']
    photo=avatar.canonicalize(picture())
    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks=[pool.submit(account_profile.set_avatar,uid,photo),
               pool.submit(account_profile.save,uid,{'display_name':'Parallel','avatar_theme':'rose'})]
        for task in tasks: task.result()
    assert account_profile.read(uid)['display_name']=='Parallel'
    assert account_profile.get_avatar(uid)==photo


def test_avatar_rejects_parallel_uploads_before_buffering(settings, monkeypatch):
    import account_routes
    import account_crypto
    c = client(); c.cookies.set(COOKIE, 'x'*43)
    monkeypatch.setattr(account_store,'session',lambda _:dict(id='owner',email='owner@example.com'))
    monkeypatch.setattr(account_routes,'quota',lambda *a:None)
    decode=MagicMock(); monkeypatch.setattr(avatar,'canonicalize',decode)
    avatar.UPLOAD_SLOTS.acquire(); avatar.UPLOAD_SLOTS.acquire()
    try:
        response=c.put('/api/account/profile/avatar',content=b'x',headers={
            'Content-Type':'image/png','X-CSRF-Token':account_crypto.digest('csrf','x'*43)})
        assert response.status_code==429
        decode.assert_not_called()
    finally:
        avatar.UPLOAD_SLOTS.release(); avatar.UPLOAD_SLOTS.release()
