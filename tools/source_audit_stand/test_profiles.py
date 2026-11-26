"""Offline tests of the stand's network boundary and real adapter delegation."""
from contextlib import redirect_stdout
from io import StringIO
import unittest
from unittest.mock import patch

import httpx
import trio

from profiles import SourceTransport, request_source
import profile_search
import public_sources


class ProfileRoutingTests(unittest.TestCase):
    def test_only_user_api_routes_are_allowed(self):
        allowed = {
            'https://api.github.com/users/octocat': 'GitHub',
            'https://gitlab.com/api/v4/users?username=sytses': 'GitLab',
        }
        for url, source in allowed.items():
            self.assertEqual(request_source(httpx.Request('GET', url)), source)
        denied = [
            'http://api.github.com/users/octocat', 'https://api.github.com/repos/octocat/project',
            'https://github.com/users/octocat', 'https://api.github.com/users/a/b',
            'https://api.github.com/users/octocat?extra=1', 'https://api.github.com:444/users/octocat',
            'https://gitlab.com/api/v4/projects', 'https://gitlab.com/api/v4/users',
            'https://gitlab.com/api/v4/users?username=a&username=b',
            'https://gitlab.com/api/v4/users?username=sytses&search=other',
            'https://unapproved.example/users/octocat',
        ]
        for url in denied:
            self.assertIsNone(request_source(httpx.Request('GET', url)), url)
        self.assertIsNone(request_source(httpx.Request('POST', next(iter(allowed)))))

    def test_denied_request_never_reaches_live_transport(self):
        async def run():
            calls = []
            def forbidden(request):
                calls.append(request)
                raise AssertionError('A blocked request reached the transport')
            async with httpx.AsyncClient(transport=SourceTransport(httpx.MockTransport(forbidden))) as client:
                with self.assertRaises(httpx.RequestError):
                    await client.get('https://unapproved.example/')
            self.assertEqual(calls, [])
        trio.run(run)

    def test_chat_search_uses_only_the_github_html_route(self):
        client_factory = httpx.AsyncClient
        requests = []

        def respond(request):
            requests.append(request)
            return httpx.Response(200, headers={'Content-Type': 'text/html'}, text=(
                '<meta name="octolytics-dimension-user_login" content="octocat">'
                '<meta property="og:url" content="https://github.com/octocat">'
            ))

        def client(**kwargs):
            transport = SourceTransport(httpx.MockTransport(respond), chat=True)
            return client_factory(transport=transport, **kwargs)

        log = StringIO()
        with patch.object(httpx, 'AsyncClient', client), redirect_stdout(log):
            rows = trio.run(profile_search.search_sources, 'Octocat')

        github, = [row for row in rows if row['site'] == 'GitHub']
        self.assertEqual(github, {'site': 'GitHub', 'status': 'found', 'url': 'https://github.com/octocat'})
        request, = requests
        self.assertEqual(str(request.url), 'https://github.com/Octocat')
        self.assertEqual(request.headers['Accept'], 'text/html')
        self.assertIn('"content_type": "text/html"', log.getvalue())
        self.assertNotIn('json_error', log.getvalue())
        for url in ('https://github.com/octocat?tab=repositories', 'https://github.com/octocat/repo'):
            self.assertIsNone(request_source(httpx.Request('GET', url), chat=True))

    def test_production_adapters_receive_transport_responses(self):
        async def run():
            calls = []
            def respond(request):
                calls.append(request)
                if request.url.host == 'api.github.com':
                    return httpx.Response(200, json={'id': 42, 'login': 'audit-user', 'type': 'User'})
                return httpx.Response(200, json=[])
            selected = [s for s in public_sources.SOURCES if s[0] in ('GitHub', 'GitLab')]
            async with httpx.AsyncClient(transport=SourceTransport(httpx.MockTransport(respond))) as client:
                results = [await public_sources.check_profile(source, 'audit-user', client) for source in selected]
            self.assertEqual([r['status'] for r in results], ['found', 'not_found'])
            self.assertEqual(results[0]['profile_url'], 'https://github.com/audit-user')
            self.assertEqual(dict(calls[1].url.params), {'username': 'audit-user'})
        trio.run(run)

    def test_transport_errors_and_limits_stay_unavailable(self):
        async def run():
            selected = [s for s in public_sources.SOURCES if s[0] in ('GitHub', 'GitLab')]
            for source in selected:
                for response in (httpx.ReadTimeout('Synthetic timeout'),
                                 httpx.Response(429, json={'message': 'Not Found'}),
                                 httpx.Response(200, text='<html>Challenge</html>')):
                    def respond(request):
                        if isinstance(response, httpx.HTTPError):
                            raise response
                        return response
                    async with httpx.AsyncClient(transport=SourceTransport(httpx.MockTransport(respond))) as client:
                        result = await public_sources.check_profile(source, 'audit-user', client)
                    self.assertEqual(result['status'], 'unavailable')
                    self.assertIsNone(result['profile_url'])
        trio.run(run)


if __name__ == '__main__':
    unittest.main()
