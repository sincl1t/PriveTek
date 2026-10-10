"""Shared identifier validation for HTTP and direct searches."""
import re
import phonenumbers


def normalize_phone(value):
    value = (value or '').strip()
    if not value:
        return ''
    if not re.fullmatch(r'\+[0-9\s().-]+', value):
        raise ValueError('Телефон укажите с кодом страны, например +7 или +36')
    try:
        number = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        raise ValueError('Не удалось распознать телефон') from None
    if not phonenumbers.is_possible_number(number):
        raise ValueError('Неверная длина или код страны телефона')
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


def normalize_username(value):
    value = (value or '').strip().removeprefix('@')
    if not value:
        return ''
    # MVP checks GitHub handles; never accept URLs or arbitrary request paths.
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', value) or '--' in value:
        raise ValueError('Username: 1–39 латинских букв, цифр или одиночных дефисов')
    return value.lower()
