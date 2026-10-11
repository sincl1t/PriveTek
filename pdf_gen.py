"""Create a Cyrillic PDF; paths do not depend on the launch directory."""
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from fpdf import FPDF
from fpdf.enums import MethodReturnValue
from report_insights import insights
from report_data import prepare, SOURCE_URLS, display_time

BASE_DIR = Path(__file__).resolve().parent
NAVY = (27, 26, 82)
CYAN = (24, 187, 212)
INK = (40, 48, 66)
MUTED = (105, 116, 135)
PALE = (245, 248, 252)
LOGO_PATH = BASE_DIR / 'assets' / 'privetek-logo.png'


class BrandedPDF(FPDF):
    def header(self):
        if LOGO_PATH.is_file():
            # Embed the user's original transparent PNG without altering the artwork.
            self.image(str(LOGO_PATH), x=16, y=7, w=82)
        else:
            self.set_font('DejaVu', size=18)
            self.set_text_color(*NAVY)
            self.set_xy(18, 15)
            self.cell(82, 10, 'PriveTek')
        self.set_font('DejaVu', size=8)
        self.set_text_color(*MUTED)
        self.set_xy(120, 21)
        self.cell(72, 5, 'Отчёт о цифровом следе', align='R')
        self.set_draw_color(*CYAN)
        self.set_line_width(.65)
        self.line(18, 40, 192, 40)
        self.set_y(48)
        self.set_text_color(*INK)

    def footer(self):
        self.set_draw_color(225, 232, 240)
        self.set_line_width(.25)
        self.line(18, 279, 192, 279)
        self.set_font('DejaVu', size=8)
        self.set_text_color(*MUTED)
        self.set_xy(18, 282)
        self.cell(90, 5, 'PriveTek  |  Личный отчёт')
        self.cell(84, 5, f'Страница {self.page_no()} / {{nb}}', align='R')



def create_report(data, output_dir=None):
    data = prepare(data)
    directory = Path(output_dir) if output_dir is not None else BASE_DIR / 'reports'
    directory.mkdir(parents=True, exist_ok=True)
    pdf_path = directory / f'report_{uuid4().hex}.pdf'
    font_path = BASE_DIR / 'DejaVuSansCondensed.ttf'
    if not font_path.is_file():
        raise FileNotFoundError('Нет шрифта DejaVuSansCondensed.ttf рядом с pdf_gen.py')
    pdf = BrandedPDF()
    pdf.set_margins(18, 48, 18)
    pdf.set_auto_page_break(auto=True, margin=23)
    pdf.alias_nb_pages()
    pdf.set_title("PriveTek | Отчёт о цифровом следе")
    pdf.set_author("PriveTek")
    pdf.set_lang("ru-RU")
    pdf.add_font('DejaVu', fname=str(font_path))
    pdf.add_page()

    def paragraph(text, size=11, color=None, link=''):
        pdf.set_font('DejaVu', size=size)
        pdf.set_text_color(*(color or (NAVY if size >= 14 else INK)))
        pdf.multi_cell(0, 6 if size < 14 else 9, text=str(text), align='L',
                       new_x='LMARGIN', new_y='NEXT', link=link)

    def section_title(title):
        paragraph(title, 14)
        pdf.ln(2)

    def height(text, width, size, leading):
        pdf.set_font('DejaVu', size=size)
        return pdf.multi_cell(width, leading, str(text), align='L', dry_run=True,
                              output=MethodReturnValue.HEIGHT)

    def panel(lines, accent=CYAN):
        # Measure the same wrapped text that will be drawn so cards never overlap.
        inner_width = pdf.epw - 10
        measured = [(text, size, color, link, leading,
                     height(text, inner_width, size, leading))
                    for text, size, color, link, leading in lines if text]
        total = 9 + sum(line[5] + 1.1 for line in measured)
        if total > pdf.h - pdf.t_margin - pdf.b_margin:
            # Unusually long provider text remains readable across normal page breaks.
            for text, size, color, link, _, _ in measured:
                paragraph(text, size, color, link)
            pdf.ln(3)
            return
        if pdf.will_page_break(total + 3):
            pdf.add_page()
        x, y = pdf.l_margin, pdf.get_y()
        pdf.set_fill_color(*PALE)
        pdf.rect(x, y, pdf.epw, total, style='F')
        pdf.set_fill_color(*accent)
        pdf.rect(x, y, 1.1, total, style='F')
        cursor = y + 4
        for text, size, color, link, leading, measured_height in measured:
            pdf.set_xy(x + 5, cursor)
            pdf.set_font('DejaVu', size=size)
            pdf.set_text_color(*color)
            pdf.multi_cell(inner_width, leading, str(text), align='L', link=link,
                           new_x='LMARGIN', new_y='NEXT')
            cursor += measured_height + 1.1
        pdf.set_xy(x, y + total + 3)

    paragraph('Ваш цифровой след', 22)
    pdf.ln(4)
    paragraph('Дата формирования: ' + datetime.now().astimezone().strftime('%d.%m.%Y %H:%M %Z'), 9, MUTED)
    if data.get('demo'):
        paragraph('ДЕМОНСТРАЦИОННЫЙ ОТЧЁТ. Все результаты вымышлены.', 9, MUTED)
    pdf.ln(5)
    if 'checks' in data:
        summary, actions = insights(data)
        section_title('Краткий итог')
        panel([(line, 10, NAVY if index == 0 else INK, '', 5.6)
               for index, line in enumerate(summary)])
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
        if pdf.will_page_break(73):
            pdf.add_page()
        section_title(title)
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
                    paragraph(group, 9, MUTED)
                    pdf.ln(1)
                    previous_group = group
                status = check['status']
                accent = CYAN if status == 'found' else (205, 150, 51) if status == 'possible' else (182, 194, 208)
                lines = [(f"{check['source']}: {labels.get(status, 'Неопределённый результат')}", 11, NAVY, '', 6),
                         (check.get('reason', ''), 10, INK, '', 5.3)]
                if check.get('profile_url'):
                    url = check['profile_url']
                    lines.append(('Профиль: ' + url, 9, (0, 122, 150), url, 4.8))
                if check['source'] in SOURCE_URLS:
                    url = SOURCE_URLS[check['source']]
                    lines.append(('Источник: ' + url, 8.5, MUTED, url, 4.6))
                if status not in ('skipped', 'disabled'):
                    lines.append(('Время проверки: ' + display_time(check.get('checked_at')), 8.5, MUTED, '', 4.6))
                panel(lines, accent)
            if not entries:
                paragraph('Нет сведений о выполнении проверки.')
            if key == 'email_breach':
                for breach in data.get(key) or []:
                    if pdf.will_page_break(35):
                        pdf.add_page()
                    paragraph(f"- {breach.get('name', '?')}")
                    paragraph('Дата утечки: ' + breach.get('date', 'дата неизвестна') + '. Источник сведений: ' + breach.get('source', 'HIBP') + '.', 9)
                    classes = breach.get('data_classes', [])
                    if classes:
                        translations = {'Passwords': 'пароли', 'Email addresses': 'email', 'Phone numbers': 'телефоны', 'Names': 'имена', 'Usernames': 'имена пользователей', 'IP addresses': 'IP-адреса', 'Dates of birth': 'даты рождения', 'password': 'пароли', 'email': 'email', 'username': 'имена пользователей', 'phone': 'телефоны', 'first_name': 'имена', 'last_name': 'фамилии', 'address': 'адреса', 'ip': 'IP-адреса'}
                        paragraph(('Категории во всех совпавших утечках: ' if breach.get('classes_scope') else 'Данные в утечке: ') + ', '.join(translations.get(c, c) for c in classes), 10)
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
        section_title('Что делать дальше')
        for action in actions:
            paragraph('- ' + action, 10)
        pdf.ln(4)
        paragraph('Источники утечек: Have I Been Pwned (https://haveibeenpwned.com/), Powered by LeakCheck (https://leakcheck.io/). Полнота баз не гарантируется.', 9)
    paragraph('Отчёт охватывает только подключённые источники. Ошибки и ограничения источников могут влиять на полноту результатов.', 10)
    pdf.output(str(pdf_path))
    return str(pdf_path)
