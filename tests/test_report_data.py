from copy import deepcopy
from pypdf import PdfReader
import httpx
import trio

import osint
from pdf_gen import create_report
from report_data import prepare, display_time
from report_insights import insights


def test_only_identical_observations_merge_without_mutation():
    row = dict(source='Spotify', kind='email', status='possible', reason='Signal', checked_at='2026-10-09T12:00:00+00:00')
    rows = [row, dict(row), dict(row, status='unavailable'), dict(row, kind='phone'),
            dict(row, checked_at='2026-10-10T12:00:00+00:00')]
    data = {'checks': rows}
    before = deepcopy(data)
    result = prepare(data)
    assert len(result['checks']) == 4
    assert result['duplicates_removed'] == 1
    assert data == before
    assert prepare(result) == result


def test_breach_dedup_keeps_dates_and_different_evidence():
    breach = dict(name='Demo', date='2024-01-01', data_classes=['Names', 'Passwords'])
    data = {'email_breach': [breach, dict(breach, data_classes=['Passwords', 'Names']),
                              dict(breach, date='2025-01-01'), dict(breach, data_classes=['Names'])]}
    assert len(prepare(data)['email_breach']) == 3


def test_summary_and_pdf_share_deduplicated_counts(tmp_path):
    row = dict(source='Spotify', kind='email', status='possible', reason='Возможный аккаунт.', checked_at='2026-10-09T14:00:00+02:00')
    data = {'checks': [dict(row, source='Amazon', status='unavailable'), row, dict(row)], 'demo': True}
    assert 'Проверок в отчёте: 2.' in insights(data)[0][1]
    text = ''.join(p.extract_text() for p in PdfReader(create_report(data, tmp_path)).pages)
    assert text.count('Spotify: Возможная регистрация') == 1
    assert 'https://www.spotify.com/' in text
    assert '09.10.2026 12:00:00 UTC' in text
    assert text.index('Spotify:') < text.index('Amazon:')
    assert 'Одинаковых записей объединено: 1' in text


def test_missing_timestamp_not_replaced_by_report_date():
    assert display_time(None) == 'время не записано'
    assert display_time('2026-10-09T12:00:00') == 'часовой пояс не указан'
    assert display_time('invalid') == 'время не распознано'


def test_actual_check_completion_stamps_result_without_network():
    async def fake(email, client, out):
        out.append(dict(name='Spotify', exists=True, rateLimit=False))
    rows = trio.run(osint.run_checks, [('Spotify', fake)], ('test@example.invalid',))
    checks = []
    osint.collect(rows, [], checks)
    assert checks[0]['checked_at'].endswith('+00:00')
