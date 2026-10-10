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
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value):
        raise ValueError('Username: 1–64 латинских букв, цифр, точек, дефисов или подчёркиваний; без URL')
    return value
