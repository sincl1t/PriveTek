from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

import app


class VerificationOutputTests(unittest.TestCase):
    def run_verification(self, scenario_result):
        output = StringIO()
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            with patch.object(app, 'STAND', artifacts), patch.object(app, 'verify_scenario', scenario_result):
                with redirect_stdout(output):
                    passed = app.verify_reports(None, 'unused')
            summary = json.loads((artifacts / 'verification.json').read_text(encoding='utf-8'))
            report = (artifacts / 'verification.txt').read_text(encoding='utf-8')
        return passed, output.getvalue(), summary, report

    def test_scenario_logs_precede_summary_even_when_a_check_fails(self):
        def scenario_result(client, password, scenario, *controls):
            print(f'TRACE {scenario}')
            passed = scenario != 'absent'
            return dict(scenario=scenario, mode='live', passed=passed, leakcheck_status='found',
                        profiles=[dict(source='GitHub', query_username='example', status='found')],
                        github_chat=dict(username='Octocat', http_status=200, status='found',
                                         url='https://github.com/octocat'),
                        checks={'leakcheck_status': passed}, pdf=f'sources-{scenario}.pdf', pdf_pages=3)

        passed, log, summary, report = self.run_verification(scenario_result)

        self.assertFalse(passed)
        self.assertTrue(summary['complete'])
        self.assertFalse(summary['passed'])
        markers = ['СЦЕНАРИЙ 1/3', 'TRACE known', 'СЦЕНАРИЙ 2/3', 'TRACE absent',
                   'СЦЕНАРИЙ 3/3', 'TRACE case', 'ИТОГИ АВТОМАТИЧЕСКОЙ ПРОВЕРКИ']
        offsets = [log.index(marker) for marker in markers]
        self.assertEqual(offsets, sorted(offsets))
        self.assertTrue(log.endswith(report))
        self.assertNotIn('TRACE', report)
        self.assertIn('absent — НЕ ПРОЙДЕН', report)
        self.assertIn('Расхождения: leakcheck_status', report)
        self.assertIn('GitHub: example = found', report)
        self.assertIn('GitHub (чат): Octocat = found · API кабинета HTTP 200 · https://github.com/octocat', report)
        self.assertEqual(summary['rows'][0]['github_chat']['url'], 'https://github.com/octocat')
        self.assertIn('PDF: sources-case.pdf', report)

    def test_execution_error_marks_remaining_scenarios_as_not_run(self):
        def scenario_result(*args):
            raise TimeoutError('unstructured error details')

        passed, log, summary, report = self.run_verification(scenario_result)

        self.assertFalse(passed)
        self.assertFalse(summary['complete'])
        self.assertFalse(summary['passed'])
        self.assertEqual([row['scenario'] for row in summary['rows']], ['known'])
        self.assertIn('Ошибка выполнения: TimeoutError', report)
        self.assertIn('absent — НЕ ЗАПУЩЕН', report)
        self.assertIn('case — НЕ ЗАПУЩЕН', report)
        self.assertNotIn('unstructured error details', log)

    def test_chat_verification_checks_status_and_canonical_url(self):
        profile_url = 'https://github.com/octocat'
        cases = (
            ('Octocat', 'found', 200, {'status': 'found', 'url': profile_url}, (True, True)),
            ('Octocat', 'found', 200, {'status': 'found', 'url': 'https://github.com/Octocat'}, (True, False)),
            ('synthetic-absent', 'not_found', 200, {'status': 'not_found', 'url': None}, (True, True)),
            ('synthetic-absent', 'not_found', 200, {'status': 'not_found', 'url': profile_url}, (True, False)),
            ('synthetic-absent', 'not_found', 503, None, (False, False)),
        )
        for username, expected_status, code, row, expected_checks in cases:
            with self.subTest(username=username, code=code, row=row):
                def respond(request):
                    self.assertEqual(request.method, 'POST')
                    self.assertEqual(request.url.path, '/api/account/profile-search')
                    self.assertEqual(request.headers['X-CSRF-Token'], 'test-token')
                    self.assertEqual(json.loads(request.content), {'username': username, 'consent': True})
                    return httpx.Response(code, json={'results': [dict(site='GitHub', **row)]} if row else {})

                with httpx.Client(base_url='https://stand.example', transport=httpx.MockTransport(respond)) as client:
                    result, checks = app.verify_chat_github(client, {'X-CSRF-Token': 'test-token'}, username, expected_status)
                self.assertEqual(result['http_status'], code)
                self.assertEqual(tuple(checks.values()), expected_checks)
