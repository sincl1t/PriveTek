"""Conservative report summaries: uncertain results never count as completed."""
from report_data import prepare

def insights(data):
    data = prepare(data)
    checks = data.get('checks', [])
    count = lambda states: sum(c.get('status') in states for c in checks)
    completed = count({'found', 'not_found'})
    uncertain = count({'possible', 'unknown'})
    unavailable = count({'unavailable'})
    skipped = count({'skipped', 'disabled'})
    found = count({'found'})
    possible = count({'possible'})
    breaches = data.get('email_breach') or []
    avatars = sum(c.get('kind') == 'avatar' and c.get('status') == 'found' for c in checks)
    profiles = sum(c.get('kind') == 'username' and c.get('status') == 'found' for c in checks)
    if not completed:
        outcome = 'Оценить цифровой след не удалось: нет проверок с определённым результатом.'
    elif breaches:
        outcome = 'В базе утечек получены совпадения. Проверьте указанные сервисы и защиту аккаунтов.'
    elif profiles:
        outcome = 'Найден публичный профиль по username. Совпадение имени не подтверждает личность владельца.'
    elif avatars:
        outcome = 'Найден публичный аватар. Это открытая информация, а не свидетельство утечки. Проверки регистраций и утечек смотрите отдельно.'
    else:
        outcome = 'В завершённых проверках находок нет. Неполное покрытие не позволяет считать данные защищёнными.'
    summary = [outcome,
               f'Проверок в отчёте: {len(checks)}. С определённым результатом: {completed}.',
               f'Неопределённых: {uncertain}. Недоступных: {unavailable}. Пропущено или отключено: {skipped}.',
               f'Записей об утечках: {len(breaches)}. Возможных регистраций: {possible}. Публичных аватаров: {avatars}.']
    actions = []
    if found and breaches:
        classes = {v for b in breaches for v in b.get('data_classes', [])}
        if 'Passwords' in classes:
            actions.append('Если пароль в затронутом сервисе не менялся после утечки, замените его. Замените также совпадающие пароли в других аккаунтах.')
        else:
            actions.append('Откройте затронутые сервисы напрямую и проверьте уведомления о безопасности. Состав утечки приведён в разделе об утечках; утечка пароля не предполагается автоматически.')
        actions.append('Включите двухфакторную защиту в затронутых аккаунтах и проверьте активные сеансы.')
        actions.append('Остерегайтесь писем, использующих сведения из утечки: открывайте сервисы напрямую, а не по ссылкам из неожиданных сообщений.')
    if profiles:
        actions.append('Проверьте ссылки на найденные профили: одинаковый username может принадлежать разным людям.')
    if possible:
        actions.append('Возможные регистрации проверьте самостоятельно в своих аккаунтах. Косвенный признак не подтверждает владельца.')
    if avatars:
        actions.append('Если вы не хотите связывать email с публичным аватаром, проверьте настройки своего Gravatar. PriveTek не удаляет изображения автоматически.')
    if not completed or unavailable or uncertain or skipped:
        actions.append('Недоступные и неопределённые проверки не означают отсутствия данных. Для самостоятельной проверки утечек откройте https://haveibeenpwned.com/ .')
    if not actions:
        actions.append('Продолжайте использовать уникальные пароли и двухфакторную защиту: отсутствие находок не гарантирует безопасность.')
    return summary, actions
