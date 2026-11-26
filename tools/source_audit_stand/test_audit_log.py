"""Readability checks against real generated PDF text; all data is synthetic."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

import audit_log
from helpers import trace_context
import httpx
from pdf_gen import create_report
from pypdf import PdfReader


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.previous = dict(trace_context.__dict__)
        trace_context.__dict__.clear()
        trace_context.job_id = 'synthetic-job'
        audit_log.begin('reader@example.com', [])

    def tearDown(self):
        trace_context.__dict__.clear()
        trace_context.__dict__.update(self.previous)

    def test_response_evidence_omits_unrelated_profile_and_secret_values(self):
        github = audit_log.response_fields('GitHub', {'id': 42, 'login': 'audit-user', 'type': 'User',
            'html_url': 'https://github.com/audit-user', 'email': 'do-not-log@example.com',
            'password': 'secret-value', 'bio': 'unrelated biography'})
        self.assertEqual(github['login'], 'audit-user')
        leak = audit_log.response_fields('LeakCheck', {'success': True, 'found': 5,
            'fields': ['password'], 'sources': [{'name': 'Synthetic Alpha', 'date': '2020-01',
                                               'password': 'secret-value'}] * 4})
        self.assertEqual(leak['sources_count'], 4)
        self.assertEqual(len(leak['sources_first_3']), 3)
        self.assertEqual(leak['sources_omitted'], 1)
        self.assertEqual(leak['found'], 5)
        combined = json.dumps([github, leak])
        for value in ('secret-value', 'unrelated biography', 'do-not-log@example.com'):
            self.assertNotIn(value, combined)
        self.assertEqual(audit_log.response_fields('GitLab', [])['users_count'], 0)

    def test_request_response_and_errors_show_actual_evidence(self):
        output = StringIO()
        with redirect_stdout(output):
            audit_log.request('GitHub', 'AuditUser', 'GET', 'https://api.github.com/users/AuditUser')
            audit_log.response('GitHub', 'AuditUser', httpx.Response(429, json={'message': 'Too many requests'}), 123)
            audit_log.failure('GitHub', 'AuditUser', httpx.ReadTimeout('never-log-error-details'))
            audit_log.response('GitLab', 'audit-user', httpx.Response(200, text='<html>never-log-body</html>'), 15)
        log = output.getvalue()
        for value in ('username="AuditUser"', 'GET https://api.github.com/users/[redacted]',
                      'HTTP 429', 'Too many requests', '123 мс', 'ReadTimeout', 'не является корректным JSON'):
            self.assertIn(value, log)
        self.assertNotIn('never-log-error-details', log)
        self.assertNotIn('never-log-body', log)

    def test_request_and_redirect_urls_use_shared_masking(self):
        new_url = 'https://user:credential@example.invalid/lookup/alphatoken?key=querysecret#fragmentsecret'
        output = StringIO()
        with redirect_stdout(output):
            audit_log.request('GitLab', 'control', 'GET', 'https://gitlab.com/api/v4/users?username=privatehandle')
            audit_log.request('LeakCheck', 'control', 'GET', 'https://leakcheck.io/api/public?check=controlhash')
            audit_log.request('New source', 'control', 'GET', new_url)
            audit_log.response('New source', 'control', httpx.Response(302, headers={
                'Location': '/next/redirecttoken?key=redirectsecret',
            }), 5, request_url='https://example.invalid/lookup/alphatoken')
        log = output.getvalue()
        self.assertIn('GET https://gitlab.com/api/v4/users', log)
        self.assertIn('GET https://leakcheck.io/api/public', log)
        self.assertIn('GET https://example.invalid/[redacted]', log)
        self.assertIn('"location_path": "/[redacted]", "location_origin": "same"', log)
        self.assertEqual(trace_context.audit_requests[('New source', 'control')],
                         'GET https://example.invalid/[redacted]')
        for value in ('credential', 'alphatoken', 'querysecret', 'fragmentsecret', 'privatehandle',
                      'controlhash', 'redirecttoken', 'redirectsecret'):
            self.assertNotIn(value, log)

    def test_unavailable_metadata_remains_null_in_processing_log(self):
        output = StringIO()
        with redirect_stdout(output):
            audit_log.processed({'checks': [dict(source='LeakCheck', status='unavailable', reason='Источник недоступен.')],
                                 'email_breach': None})
        self.assertIn('"status": "unavailable"', output.getvalue())
        self.assertIn('"sources_passed_to_report": null', output.getvalue())

    def test_report_reads_real_pdf_and_matches_each_query(self):
        audit_log.begin('reader@example.com', [], phone_supplied=True)
        rows = [
            dict(source='LeakCheck', kind='breach', status='found', reason='Найдены названия утечек.'),
            dict(source='Amazon', kind='email', status='unavailable', reason='Проверка email отключена.'),
            dict(source='Amazon', kind='phone', status='possible', reason='Косвенный признак регистрации.'),
            dict(source='GitHub', kind='username', status='found', query_username='AuditUser',
                 profile_url='https://github.com/audituser', reason='Принадлежность человеку не подтверждена.'),
            dict(source='GitHub', kind='username', status='unavailable', query_username='another-user',
                 reason='Источник не дал пригодного ответа (HTTP 429); отсутствие профиля не подтверждено.'),
            dict(source='GitLab', kind='username', status='not_found', query_username='absent-user',
                 reason='Публичные данные для этого username не найдены.'),
        ]
        data = dict(checks=rows, email_breach=[dict(source='LeakCheck', name='Synthetic Alpha', date='2020-01', data_classes=[])])
        with tempfile.TemporaryDirectory() as directory:
            path = create_report(data, directory)
            text = '\n'.join(page.extract_text() or '' for page in PdfReader(path).pages)
        output = StringIO()
        with redirect_stdout(output):
            audit_log.processed(data)
            observations = audit_log.report(text)
        self.assertEqual(len(observations), 5)
        self.assertTrue(all(row['matched'] and row['consistent'] for row in observations))
        by_query = {(row['source'], row['query']): row for row in observations}
        self.assertEqual(by_query['GitHub', 'AuditUser']['заголовок'], 'GitHub: Найдены сведения')
        self.assertEqual(by_query['GitHub', 'another-user']['заголовок'], 'GitHub: Проверка недоступна')
        self.assertEqual(by_query['GitLab', 'absent-user']['группа'], 'Проверки без находок')
        self.assertEqual(by_query['Amazon', audit_log.PHONE_QUERY]['заголовок'], 'Amazon: Возможная регистрация')
        self.assertIn('https://github.com/audituser', output.getvalue())

    def test_report_does_not_invent_caption_from_system_status(self):
        trace_context.audit_checks = [dict(source='GitHub', status='found', query_username='audit-user', reason='Actual reason.')]
        text = ('Публичные профили по username\nПроверки без находок\n'
                'GitHub: Находок в источнике нет\nActual reason.\nПроверялся username: audit-user\n')
        with redirect_stdout(StringIO()):
            observations = audit_log.report(text)
        self.assertEqual(observations[0]['заголовок'], 'GitHub: Находок в источнике нет')
        self.assertFalse(observations[0]['consistent'])

    def test_report_handles_skipped_profile_without_username(self):
        trace_context.audit_checks = [dict(source='GitHub', status='skipped', reason='Username не указан.')]
        text = ('Публичные профили по username\nОграничения проверки\n'
                'GitHub: Не проверялось\nUsername не указан.\n')
        with redirect_stdout(StringIO()):
            observations = audit_log.report(text)
        self.assertTrue(observations[0]['consistent'])


if __name__ == '__main__':
    unittest.main()
