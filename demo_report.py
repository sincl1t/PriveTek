"""Local demo: does not perform searches or send mail."""
from pathlib import Path
from pdf_gen import create_report

SAMPLE = {
    'demo': True,
    'email_breach': [{'name': 'Пример утечки (вымышленные данные)', 'date': '2024-01-15'}],
    'email_registrations': [{'site': 'Instagram'}, {'site': 'Amazon'}],
    'phone_registrations': [],
    'errors': ['Демонстрационные данные. Запросы к внешним источникам не выполнялись.'],
}

if __name__ == '__main__':
    print(create_report(SAMPLE, Path(__file__).resolve().parent / 'reports'))
