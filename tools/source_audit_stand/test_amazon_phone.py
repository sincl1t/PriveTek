"""Verify the stand's Amazon route without submitting a contact to Amazon."""
import asyncio
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

import httpx
import trio

from app import VERIFY_PHONE, audit_search
import osint
from profiles import SourceTransport
from source_checks import amazon_phone


class AmazonRoutingTests(unittest.TestCase):
    def test_only_verify_mode_skips_phone_checks(self):
        run_checks = AsyncMock(return_value=[{'name': 'Amazon', 'exists': True, 'domain': 'amazon.com'}])
        with patch.object(osint, 'run_checks', run_checks), redirect_stdout(StringIO()):
            automatic = audit_search(osint.search, phone=VERIFY_PHONE, verify=True)
            run_checks.assert_not_called()
            manual = audit_search(osint.search, phone=VERIFY_PHONE, verify=False)

        run_checks.assert_awaited_once_with([('Amazon', osint.ignorant_amazon)], ('2025550123', '1'))
        for result, expected_status in ((automatic, 'skipped'), (manual, 'possible')):
            check, = [row for row in result['checks'] if row['source'] == 'Amazon' and row['kind'] == 'phone']
            self.assertEqual(check['status'], expected_status)

    def test_capture_saves_only_html_and_preserves_password_form_shape(self):
        html = """
        <form action="/ax/claim?token=synthetic-secret" method="post">
          <input name="email" value="+1 (202) 555-0123">
          <input type="hidden" name="token" value="synthetic-secret">
          <template>
            <div style="display: none; background: url(https://example.com)">
              <input type="password" name="password" value="synthetic-secret">
            </div>
          </template>
          <p>Control +1 (202) 555-0123</p>
        </form>
        <script>synthetic-secret</script><img src="https://example.com">
        """

        def respond(request):
            if request.method == 'POST':
                return httpx.Response(302, json={}, headers={'Location': '/ax/claim'})
            return httpx.Response(200, text=html, headers={'Content-Type': 'text/html; charset=utf-8'})

        async def run(directory):
            transport = SourceTransport(httpx.MockTransport(respond), amazon=True, amazon_html_dir=directory)
            async with httpx.AsyncClient(transport=transport) as client:
                await client.get('https://www.amazon.com/ap/signin')
                await client.post('https://www.amazon.com/ax/claim', follow_redirects=True)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            asyncio.run(run(root))
            self.assertEqual(sorted(path.name for path in root.iterdir()), ['01-GET-200.html', '03-GET-200.html'])
            snapshot = (root / '03-GET-200.html').read_text(encoding='utf-8')
        for marker in ('<template>', 'display: none', 'name="password"', 'action="/ax/claim"', "form-action 'none'"):
            self.assertIn(marker, snapshot)
        for secret in ('synthetic-secret', '555-0123', 'https://example.com', '<script', 'value='):
            self.assertNotIn(secret, snapshot)

    def test_adapter_submits_each_entered_number_and_logs_no_payload(self):
        requests = []

        def respond(request):
            requests.append(request)
            if request.method == 'GET':
                return httpx.Response(200, text='<form method="post" action="/ax/claim">'
                                      '<input name="email"><input type="hidden" name="token" value="secret"></form>')
            return httpx.Response(429, text='sensitive HTML')

        async def run():
            transport = SourceTransport(httpx.MockTransport(respond), amazon=True)
            async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
                with self.assertRaises(httpx.RequestError):
                    await client.get('https://unrelated.example/ap/signin')
                results = []
                await amazon_phone('2025550123', '1', client, results)
                await amazon_phone('2025550124', '1', client, results)
            return results

        output = StringIO()
        with redirect_stdout(output):
            results = trio.run(run)
        self.assertEqual([request.method for request in requests], ['GET', 'POST', 'GET', 'POST'])
        self.assertEqual(requests[1].content, b'token=secret&email=%2B12025550123&claimType=phoneNumber')
        self.assertEqual(requests[3].content, b'token=secret&email=%2B12025550124&claimType=phoneNumber')
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIsNone(result['exists'])
            self.assertIn('HTTP 429', result['reason'])
        self.assertIn('POST https://www.amazon.com/ax/claim', output.getvalue())
        self.assertIn('"claimType": "phoneNumber", "countryCode": null, "email_has_plus": true, "email_digit_count": 11',
                      output.getvalue())
        for value in ('12025550123', '12025550124', 'secret', 'sensitive HTML', 'openid.'):
            self.assertNotIn(value, output.getvalue())

    def test_logs_form_shape_and_redirect_path_without_identifiers(self):
        def respond(request):
            locations = {
                '/ax/claim': '/ax/claim/intent?arb=private-token&email=%2B12025550123',
                '/ax/claim/intent': 'https://private.example/private-path?token=private-token',
                '/ap/signin': '/ax/claim/intent/12025550123/?token=private-token',
            }
            return httpx.Response(302, headers={'Location': locations[request.url.path]})

        async def run():
            transport = SourceTransport(httpx.MockTransport(respond), amazon=True)
            async with httpx.AsyncClient(transport=transport) as client:
                await client.post('https://www.amazon.com/ax/claim', data={
                    'claimType': 'phoneNumber', 'countryCode': 'NL',
                    'email': '+12025550123', 'anti-csrftoken-a2z': 'private-token',
                })
                await client.get('https://www.amazon.com/ax/claim/intent?arb=private-token')
                await client.get('https://www.amazon.com/ap/signin')

        output = StringIO()
        with redirect_stdout(output):
            asyncio.run(run())
        log = output.getvalue()
        self.assertIn('"claimType": "phoneNumber", "countryCode": "NL", "email_has_plus": true, "email_digit_count": 11', log)
        self.assertIn('HTTP 302', log)
        self.assertIn('"location_path": "/ax/claim/intent", "location_origin": "same"', log)
        self.assertIn('"location_path": "/private-path", "location_origin": "other", "location_host": "private.example"', log)
        self.assertIn('"location_path": "/ax/claim/intent/[redacted]/"', log)
        for value in ('12025550123', 'private-token', 'arb=', 'anti-csrftoken-a2z'):
            self.assertNotIn(value, log)
