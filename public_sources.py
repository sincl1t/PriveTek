"""Allowlisted public profile APIs. No scraped private data or identity inference."""
import re
from urllib.parse import quote
import httpx
import trio
from report_data import utc_now

USER_AGENT = 'PriveTek/2.0 (+https://github.com/sincl1t/PriveTek)'
# name, public home, official docs, known public fixture, handle pattern
SOURCES = [
 ('GitHub', 'https://github.com/', 'https://docs.github.com/en/rest/users/users', 'octocat', r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?'),
 ('GitLab', 'https://gitlab.com/', 'https://docs.gitlab.com/api/users/', 'sytses', r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}'),
 ('Codeberg', 'https://codeberg.org/', 'https://docs.codeberg.org/advanced/api-usage/', 'earl-warren', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,38}'),
 ('Hugging Face', 'https://huggingface.co/', 'https://huggingface.co/docs/hub/en/api', 'julien-c', r'[A-Za-z0-9][A-Za-z0-9-]{0,40}'),
 ('DEV', 'https://dev.to/', 'https://developers.forem.com/api/v1', 'ben', r'[A-Za-z0-9_]{1,30}'),
 ('Hacker News', 'https://news.ycombinator.com/', 'https://github.com/HackerNews/API', 'pg', r'[A-Za-z0-9_-]{1,64}'),
 ('Keybase', 'https://keybase.io/', 'https://keybase.io/docs/api/1.0/call/user/lookup', 'chris', r'[A-Za-z0-9_]{2,16}'),
 ('Lichess', 'https://lichess.org/', 'https://lichess.org/api', 'thibault', r'[A-Za-z0-9_-]{2,30}'),
 ('Chess.com', 'https://www.chess.com/', 'https://www.chess.com/news/view/published-data-api', 'hikaru', r'[A-Za-z0-9_-]{3,25}'),
 ('Wikipedia', 'https://en.wikipedia.org/', 'https://www.mediawiki.org/wiki/API:Users', 'Jimbo_Wales', r'[A-Za-z0-9_.-]{1,64}'),
 ('Discourse Meta', 'https://meta.discourse.org/', 'https://docs.discourse.org/', 'codinghorror', r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,59}'),
]


def endpoint(name, username):
    handle = quote(username, safe='')
    return {
      'GitHub': ('https://api.github.com/users/' + handle, {}),
      'GitLab': ('https://gitlab.com/api/v4/users', {'username': username}),
      'Codeberg': ('https://codeberg.org/api/v1/users/' + handle, {}),
      'Hugging Face': ('https://huggingface.co/api/users/' + handle + '/overview', {}),
      'DEV': ('https://dev.to/api/users/by_username', {'url': username}),
      'Hacker News': ('https://hacker-news.firebaseio.com/v0/user/' + handle + '.json', {}),
      'Keybase': ('https://keybase.io/_/api/1.0/user/lookup.json', {'usernames': username, 'fields': 'basics'}),
      'Lichess': ('https://lichess.org/api/user/' + handle, {}),
      'Chess.com': ('https://api.chess.com/pub/player/' + handle, {}),
      'Wikipedia': ('https://en.wikipedia.org/w/api.php', {'action': 'query', 'list': 'users', 'ususers': username, 'format': 'json'}),
      'Discourse Meta': ('https://meta.discourse.org/u/' + handle + '.json', {}),
    }[name]


def identity(name, body):
    """Return a stable public account ID and its canonical handle."""
    if name == 'GitHub' and body.get('type') == 'User':
        return body.get('id'), body.get('login')
    if name == 'GitLab' and isinstance(body, list) and len(body) == 1:
        return body[0].get('id'), body[0].get('username')
    if name == 'Codeberg':
        return body.get('id'), body.get('login')
    if name == 'Hugging Face' and body.get('type') == 'user':
        return body.get('_id'), body.get('user')
    if name == 'DEV':
        return body.get('id'), body.get('username')
    if name == 'Hacker News':
        return body.get('created'), body.get('id')
    if name == 'Keybase' and body.get('status', {}).get('code') == 0:
        users = body.get('them')
        if isinstance(users, list) and len(users) == 1 and isinstance(users[0], dict):
            return users[0].get('id'), users[0].get('basics', {}).get('username')
    if name == 'Lichess':
        return body.get('createdAt'), body.get('username')
    if name == 'Chess.com':
        return body.get('player_id'), body.get('username')
    if name == 'Wikipedia':
        users = body.get('query', {}).get('users')
        if isinstance(users, list) and len(users) == 1:
            return users[0].get('userid'), users[0].get('name')
    if name == 'Discourse Meta':
        user = body.get('user', {})
        return user.get('id'), user.get('username')
    return None, None


def matches(name, actual, supplied):
    if not isinstance(actual, str):
        return False
    if name == 'Hacker News':
        return actual == supplied
    if name == 'Wikipedia':
        wanted = supplied.replace('_', ' ')
        return actual == wanted[:1].upper() + wanted[1:]
    return actual.casefold() == supplied.casefold()


def absent(name, code, body):
    # Recognise documented JSON misses; HTML challenges never count as absence.
    if code == 200:
        if name == 'GitLab':
            return body == []
        if name == 'Hacker News':
            return body is None
        if name == 'Keybase':
            return isinstance(body, dict) and body.get('status', {}).get('code') == 0 and body.get('them') == [None]
        if name == 'Wikipedia':
            users = body.get('query', {}).get('users', []) if isinstance(body, dict) else []
            return len(users) == 1 and 'missing' in users[0]
    if code != 404 or not isinstance(body, dict):
        return False
    return {
      'GitHub': body.get('message') == 'Not Found',
      'Codeberg': isinstance(body.get('message'), str) and (body['message'] == 'user does not exist' or re.fullmatch(r'user redirect does not exist \[name: [A-Za-z0-9_.-]+\]', body['message']) is not None),
      'Hugging Face': body.get('error') in ('User not found', 'This user does not exist'),
      'DEV': body.get('status') == 404 and body.get('error') in ('Not Found', 'not found'),
      'Lichess': body.get('error') == 'Not found',
      'Chess.com': body.get('code') == 0 and isinstance(body.get('message'), str) and 'not found' in body['message'].lower(),
      'Discourse Meta': body.get('error_type') == 'not_found',
    }.get(name, False)


def profile_url(name, handle):
    encoded = quote(handle, safe='')
    home = next(row[1] for row in SOURCES if row[0] == name)
    return {
      'DEV': home + encoded,
      'Hacker News': home + 'user?id=' + encoded,
      'Lichess': home + '@/' + encoded,
      'Chess.com': home + 'member/' + encoded,
      'Wikipedia': home + 'wiki/Special:Contributions/' + encoded,
      'Discourse Meta': home + 'u/' + encoded,
    }.get(name, home + encoded)


async def check_profile(source, username, client):
    name, home, docs, fixture, pattern = source
    result = dict(source=name, kind='username', status='unavailable', source_url=home,
                  checked_at=utc_now(), profile_url=None,
                  reason='Источник не дал пригодного ответа; ошибка связи, лимит или неизвестный формат.')
    if not re.fullmatch(pattern, username) or (name == 'GitHub' and '--' in username):
        result.update(status='skipped', checked_at=None, reason='Username не соответствует формату этого сайта.')
        return result
    url, params = endpoint(name, username)
    try:
        response = await client.get(url, params=params)
        body = response.json()
        if absent(name, response.status_code, body):
            result.update(status='not_found', reason='Публичные данные для этого username в данном источнике не найдены. Это не исключает закрытый аккаунт или профиль на другом сайте.')
            if name == 'Hacker News':
                result['reason'] = 'Не найден пользователь с публичной активностью. Аккаунт без публичной активности API не показывает.'
            return result
        if response.status_code == 200:
            account_id, actual = identity(name, body)
            if isinstance(account_id, (str, int)) and not isinstance(account_id, bool) and account_id and matches(name, actual, username):
                result.update(status='found', profile_url=profile_url(name, actual),
                              reason='Найден публичный профиль с точным username. Принадлежность человеку не подтверждена.')
                return result
        result['reason'] = f'Источник не дал пригодного ответа (HTTP {response.status_code}); отсутствие профиля не подтверждено.'
    except (httpx.HTTPError, ValueError, TypeError, AttributeError, KeyError, IndexError):
        pass
    return result


async def run_profiles(username=None, fixtures=False):
    output = [None] * len(SOURCES)
    limiter = trio.CapacityLimiter(4)
    async with httpx.AsyncClient(timeout=12, follow_redirects=False, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'}) as client:
        async def run(index, source):
            async with limiter:
                output[index] = await check_profile(source, source[3] if fixtures else username, client)
        async with trio.open_nursery() as nursery:
            for index, source in enumerate(SOURCES):
                nursery.start_soon(run, index, source)
    return output
