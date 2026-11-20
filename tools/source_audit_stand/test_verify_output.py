from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
