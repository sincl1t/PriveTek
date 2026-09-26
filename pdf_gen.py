"""Create a Cyrillic PDF; paths do not depend on the launch directory."""
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from fpdf import FPDF

BASE_DIR = Path(__file__).resolve().parent


def create_report(data, output_dir=None):
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
    sections = [
        ('email_breach', 'Утечки данных по email'),
        ('email_registrations', 'Регистрации email на сайтах'),
        ('phone_registrations', 'Регистрации телефона на сайтах'),
    ]
    labels = {'found': 'Найдены сведения', 'not_found': 'Находок в источнике нет',
              'possible': 'Возможная регистрация', 'unknown': 'Неопределённый результат',
              'unavailable': 'Проверка недоступна', 'skipped': 'Не проверялось',
              'disabled': 'Проверка отключена'}
    kinds = {'email_breach': 'breach', 'email_registrations': 'email', 'phone_registrations': 'phone'}
    for key, title in sections:
        if pdf.will_page_break(25):
            pdf.add_page()
        paragraph(title, 14)
        if 'checks' in data:
            entries = [c for c in data['checks'] if c['kind'] == kinds[key]]
            for check in entries:
                if pdf.will_page_break(28):
                    pdf.add_page()
                paragraph(f"{check['source']}: {labels.get(check['status'], 'Неопределённый результат')}", 11)
                paragraph(check.get('reason', ''), 10)
            if not entries:
                paragraph('Нет сведений о выполнении проверки.')
            if key == 'email_breach':
                for breach in data.get(key) or []:
                    paragraph(f"- {breach.get('name', '?')} ({breach.get('date', 'дата неизвестна')})")
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
    paragraph('Отчёт охватывает только подключённые источники. Ошибки и ограничения источников могут влиять на полноту результатов.', 10)
    pdf.output(str(pdf_path))
    return str(pdf_path)
