"""Bounded avatar decoding; original files and EXIF are never persisted."""
from io import BytesIO
import threading
import warnings
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_UPLOAD = 5 * 1024 * 1024
MAX_PIXELS = 25_000_000
MAX_STORED = 256 * 1024
MIME_TYPES = ('image/jpeg', 'image/png', 'image/webp')
UPLOAD_SLOTS = threading.BoundedSemaphore(2)
_SLOT = threading.BoundedSemaphore(1)


class AvatarBusy(Exception):
    pass


def canonicalize(content):
    if not content or len(content) > MAX_UPLOAD:
        raise ValueError('Выберите изображение до 5 МБ')
    if not _SLOT.acquire(blocking=False):
        raise AvatarBusy()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(BytesIO(content)) as image:
                if image.format not in ('JPEG', 'PNG', 'WEBP'):
                    raise ValueError('Поддерживаются JPEG, PNG и WebP')
                if image.width * image.height > MAX_PIXELS or getattr(image, 'n_frames', 1) != 1:
                    raise ValueError('Нужно неподвижное изображение до 25 миллионов пикселей')
                ImageOps.exif_transpose(image, in_place=True)
                cropped = ImageOps.fit(image, (512, 512), method=Image.Resampling.LANCZOS)
                try:
                    rgba = cropped.convert('RGBA')
                    try:
                        clean = Image.new('RGB', (512, 512), '#122336')
                        try:
                            clean.paste(rgba, mask=rgba.getchannel('A'))
                            output = BytesIO()
                            # A new pixel-only image drops EXIF, GPS, comments and profiles.
                            clean.save(output, format='JPEG', quality=85, optimize=True)
                            result = output.getvalue()
                        finally:
                            clean.close()
                    finally:
                        rgba.close()
                finally:
                    cropped.close()
        if len(result) > MAX_STORED:
            raise ValueError('Не удалось уменьшить изображение. Выберите другой файл')
        return result
    except (UnidentifiedImageError, OSError, SyntaxError, EOFError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ValueError('Не удалось прочитать изображение. Выберите корректный JPEG, PNG или WebP') from None
    finally:
        _SLOT.release()
