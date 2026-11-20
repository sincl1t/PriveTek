"""Route and trace live HTTP requests made by the stand's product adapters."""
import re
import time

import httpx

import audit_log

PROFILE_SOURCES = {'GitHub', 'GitLab'}


def control_label(username):
    return {'octocat': 'github_known', 'sytses': 'gitlab_known',
            'pvtkz8q4n2x7r9': 'synthetic_absent'}.get(username.casefold(), 'custom')


def request_source(request):
    url = request.url
    if request.method != 'GET' or url.scheme != 'https' or url.port not in (None, 443) or url.username or url.password:
        return None
    if url.host == 'api.github.com' and not url.query and re.fullmatch(r'/users/[A-Za-z0-9-]{1,39}', url.path):
        return 'GitHub'
    if url.host == 'gitlab.com' and url.path == '/api/v4/users' and len(url.params.multi_items()) == 1:
        if set(url.params) == {'username'} and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', url.params['username']):
            return 'GitLab'
    return None


def skipped(source):
    return dict(source=source[0], kind='username', source_url=source[1], status='skipped',
                checked_at=None, profile_url=None, reason='Источник отключён на стенде аудита; запрос не выполнялся.')


class SourceTransport(httpx.AsyncBaseTransport):
    def __init__(self, live_transport=None, *, amazon=False):
        self.live = live_transport if live_transport is not None else httpx.AsyncHTTPTransport()
        self.mode = 'live' if live_transport is None else 'simulated'
        self.amazon = amazon

    async def handle_async_request(self, request):
        url = request.url
        if self.amazon:
            if (url.scheme != 'https' or url.host != 'www.amazon.com' or url.port not in (None, 443)
                    or url.username or url.password):
                raise httpx.RequestError('Only the Amazon origin is enabled during its phone check', request=request)
            source, query = 'Amazon', audit_log.PHONE_QUERY
            path = url.path if url.path in ('/ap/signin', '/ap/signin/', '/ax/claim') else '/[redacted]'
            logged_url = f'https://www.amazon.com{path}'
        else:
            source = request_source(request)
            if source is None:
                raise httpx.RequestError('Only GitHub/GitLab user API endpoints are enabled', request=request)
            query = url.path.rsplit('/', 1)[1] if source == 'GitHub' else url.params['username']
            logged_url = str(url)
        audit_log.request(source, query, request.method, logged_url, mode=self.mode)
        started = time.monotonic()
        try:
            response = await self.live.handle_async_request(request)
            await response.aread()
        except httpx.HTTPError as error:
            audit_log.failure(source, query, error)
            raise
        audit_log.response(source, query, response, round((time.monotonic() - started) * 1000))
        return response

    async def aclose(self):
        await self.live.aclose()
