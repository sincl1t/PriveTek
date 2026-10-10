"""Create a Cyrillic PDF; paths do not depend on the launch directory."""
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from fpdf import FPDF
from report_insights import insights
from report_data import prepare, SOURCE_URLS, display_time

BASE_DIR = Path(__file__).resolve().parent


def create_report(data, output_dir=None):
    data = prepare(data)
    directory = Path(output_dir) if output_dir is not None else BASE_DIR / 'reports'
    directory.mkdir(parents=True, exist_ok=True)
    pdf_path = directory / f'report_{uuid4().hex}.pdf'
    font_path = BASE_DIR / 'DejaVuSansCondensed.ttf'
    if not font_path.is_file():
        raise FileNotFoundError('Нет шрифта DejaVuSansCondensed.ttf рядом с pdf_gen.py')
    pdf = FPDF()
    pdf.set_margins(18, 18, 18)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_font('DejaVu', fname=str(font_path))
    pdf.add_page()

    def paragraph(text, size=11):
        pdf.set_font('DejaVu', size=size)
        pdf.multi_cell(0, 7, text=str(text), new_x='LMARGIN', new_y='NEXT')

    paragraph('PriveTek | Отчёт о цифровом следе', 17)
    pdf.ln(4)
    paragraph('Дата формирования: ' + datetime.now().astimezone().strftime('%d.%m.%Y %H:%M %Z'))
    if data.get('demo'):
        paragraph('ДЕМОНСТРАЦИОННЫЙ ОТЧЁТ. Все результаты вымышлены.')
    pdf.ln(5)
    if 'checks' in data:
        summary, actions = insights(data)
        paragraph('Краткий итог', 14)
        for line in summary:
            paragraph(line, 10)
        if data.get('duplicates_removed'):
            paragraph(f"Одинаковых записей объединено: {data['duplicates_removed']}. Различающиеся результаты сохранены отдельно.", 9)
        pdf.ln(4)
    sections = [
        ('public_avatars', 'Публичные аватары по email'),
        ('email_breach', 'Утечки данных по email'),
        ('email_registrations', 'Регистрации email на сайтах'),
        ('phone_registrations', 'Регистрации телефона на сайтах'),
        ('username_profiles', 'Публичные профили по username'),
    ]
    labels = {'found': 'Найдены сведения', 'not_found': 'Находок в источнике нет',
              'possible': 'Возможная регистрация', 'unknown': 'Неопределённый результат',
              'unavailable': 'Проверка недоступна', 'skipped': 'Не проверялось',
              'disabled': 'Проверка отключена'}
    kinds = {'public_avatars': 'avatar', 'email_breach': 'breach', 'email_registrations': 'email', 'phone_registrations': 'phone', 'username_profiles': 'username'}
    for key, title in sections:
        if pdf.will_page_break(25):
            pdf.add_page()
        paragraph(title, 14)
        if 'checks' in data:
            entries = [c for c in data['checks'] if c['kind'] == kinds[key]]
            order = {'found': 0, 'possible': 1, 'not_found': 2, 'unknown': 3, 'unavailable': 4, 'skipped': 5, 'disabled': 6}
            entries.sort(key=lambda c: order.get(c.get('status'), 7))
            previous_group = None
            for check in entries:
                group = ('Находки и возможные совпадения' if check['status'] in ('found', 'possible') else
                         'Проверки без находок' if check['status'] == 'not_found' else 'Ограничения проверки')
                if pdf.will_page_break(48):
                    pdf.add_page()
                if group != previous_group:
                    paragraph(group, 10)
                    previous_group = group
                paragraph(f"{check['source']}: {labels.get(check['status'], 'Неопределённый результат')}", 11)
                paragraph(check.get('reason', ''), 10)
                if check.get('profile_url'):
                    paragraph('Профиль: ' + check['profile_url'], 9)
                if check['source'] in SOURCE_URLS:
                    paragraph('Источник: ' + SOURCE_URLS[check['source']], 9)
                if check['status'] not in ('skipped', 'disabled'):
                    paragraph('Время проверки: ' + display_time(check.get('checked_at')), 9)
            if not entries:
                paragraph('Нет сведений о выполнении проверки.')
            if key == 'email_breach':
                for breach in data.get(key) or []:
                    if pdf.will_page_break(35):
                        pdf.add_page()
                    paragraph(f"- {breach.get('name', '?')}")
                    paragraph('Дата утечки: ' + breach.get('date', 'дата неизвестна') + '. Источник сведений: HIBP.', 9)
                    classes = breach.get('data_classes', [])
                    if classes:
                        translations = {'Passwords': 'пароли', 'Email addresses': 'email', 'Phone numbers': 'телефоны', 'Names': 'имена', 'Usernames': 'имена пользователей', 'IP addresses': 'IP-адреса', 'Dates of birth': 'даты рождения'}
                        paragraph('Данные в утечке: ' + ', '.join(translations.get(c, c) for c in classes), 10)
            pdf.ln(4)
            continue
        items = data.get(key)
        if items is None:
            paragraph('Проверка не выполнена или недоступна.')
        elif not items:
            paragraph('Находок не получено. Это не гарантирует отсутствия данных.')
        else:
            for item in items:
                if key == 'email_breach':
                    paragraph(f"- {item.get('name', '?')} ({item.get('date', 'дата неизвестна')})")
                else:
                    paragraph('- ' + str(item.get('site') or item.get('domain') or 'Неизвестный сайт'))
        pdf.ln(5)
    if data.get('errors') and 'checks' not in data:
        paragraph('Предупреждения', 14)
        for error in data['errors']:
            paragraph('- ' + str(error))
        pdf.ln(5)
    if 'checks' in data:
        advice_height = 35 + sum(7 * max(1, (len(action) + 89) // 90) for action in actions)
        if pdf.will_page_break(min(advice_height, 240)):
            pdf.add_page()
        paragraph('Что делать дальше', 14)
        for action in actions:
            paragraph('- ' + action, 10)
        pdf.ln(4)
        paragraph('Источник утечек: Have I Been Pwned (https://haveibeenpwned.com/). База не охватывает все возможные утечки.', 9)
    paragraph('Отчёт охватывает только подключённые источники. Ошибки и ограничения источников могут влиять на полноту результатов.', 10)
    pdf.output(str(pdf_path))
    return str(pdf_path)
