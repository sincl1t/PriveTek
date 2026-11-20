"""Verify the stand's Amazon route without submitting a contact to Amazon."""
from contextlib import redirect_stdout
from io import StringIO
import unittest

import httpx
import trio

from profiles import SourceTransport
from source_checks import amazon_phone


class AmazonRoutingTests(unittest.TestCase):
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
        self.assertEqual(requests[1].content, b'token=secret&email=12025550123')
        self.assertEqual(requests[3].content, b'token=secret&email=12025550124')
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIsNone(result['exists'])
            self.assertIn('HTTP 429', result['reason'])
        self.assertIn('POST https://www.amazon.com/ax/claim', output.getvalue())
        for value in ('12025550123', '12025550124', 'secret', 'sensitive HTML', 'openid.'):
            self.assertNotIn(value, output.getvalue())
