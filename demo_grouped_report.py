"""Synthetic report demonstrating provenance and duplicate handling. No network."""
from pdf_gen import create_report

def sample():
    timestamp = '2026-10-09T12:00:00+00:00'
    def check(source, kind, status, reason):
        row = dict(source=source, kind=kind, status=status, reason=reason)
        if status not in ('skipped', 'disabled'):
            row['checked_at'] = timestamp
        return row
    spotify = check('Spotify', 'email', 'possible', 'Демонстрационный косвенный признак регистрации. Требуется проверка в своём аккаунте.')
    return dict(demo=True, checks=[
        check('Gravatar', 'avatar', 'found', 'Демонстрационный публичный аватар. Это не утечка и не подтверждение личности.'),
        check('HIBP', 'breach', 'found', 'Вымышленная запись для демонстрации отчёта. Реальный запрос не выполнялся.'),
        check('Amazon', 'email', 'unavailable', 'Демонстрационная блокировка запроса. Отсутствие аккаунта не подтверждено.'),
        spotify, dict(spotify),
        check('Instagram', 'email', 'unknown', 'Демонстрационный неопределённый ответ. Наличие аккаунта неизвестно.'),
        check('Amazon', 'phone', 'skipped', 'Телефон не указан.')],
        email_breach=[dict(name='Вымышленный сервис', date='2024-01-15', data_classes=['Email addresses'])])

if __name__ == '__main__':
    print(create_report(sample()))
