"""Conservative adapters: never interpret transport/parser failures as absence."""
import re
import hashlib
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


class Unavailable(Exception):
    pass


async def gravatar(email, client, out):
    """Public avatar lookup only; 404 does not imply no Gravatar account."""
    digest = hashlib.sha256(email.strip().lower().encode('utf-8')).hexdigest()
    check = dict(name='Gravatar', kind='avatar')
    try:
        response = await client.head('https://gravatar.com/avatar/' + digest,
                                     params={'d': '404', 's': '32'}, follow_redirects=False)
        if response.status_code == 200 and response.headers.get('content-type', '').split(';')[0].lower() in ('image/png', 'image/jpeg', 'image/gif', 'image/webp'):
            check.update(status='found', reason='Gravatar вернул публичный аватар для хеша email. Это не утечка и не подтверждение личности владельца.')
        elif response.status_code == 404:
            check.update(status='not_found', reason='Публичный аватар с рейтингом по умолчанию не найден. Это не доказывает отсутствие аккаунта Gravatar или других данных.')
        else:
            check.update(status='unavailable', reason=f'Gravatar вернул неподходящий ответ (HTTP {response.status_code}); проверка не выполнена.')
    except httpx.HTTPError:
        check.update(status='unavailable', reason='Не удалось связаться с Gravatar; проверка не выполнена.')
    out.append(check)


def validate(response):
    if response.status_code != 200:
        raise Unavailable(f"Источник вернул HTTP {response.status_code}; проверка не выполнена.")
    soup = BeautifulSoup(response.text, 'html.parser')
    if soup.select('form[action*="validateCaptcha"], input[name="captcha"], #captchacharacters') or (
            soup.title and 'robot check' in soup.title.get_text().lower()):
        raise Unavailable('Источник запросил CAPTCHA; проверка не выполнена.')
    return soup


async def guarded(source, operation, out, *, not_found_reason=None):
    try:
        exists = await operation()
        result = dict(name=source, domain=source.lower()+'.com', exists=exists, rateLimit=False)
        if exists is False and not_found_reason is not None:
            result.update(status='not_found', reason=not_found_reason)
        out.append(result)
    except Unavailable as exc:
        out.append(dict(name=source, exists=None, rateLimit=True, reason=str(exc)))
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        out.append(dict(name=source, exists=None, rateLimit=True,
                        reason='Ошибка соединения или неизвестный формат ответа источника.'))


AMAZON_SIGNIN_PATHS = ('/ap/signin', '/ap/signin/', '/ax/claim')
AMAZON_CHALLENGE_PATH = '/ax/aaut/verify/ap/challenge'
HIDDEN_STYLE = re.compile(r'(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important\s*)?(?:;|$)', re.I)
# Classes on the controls and their ancestors in the confirmed email sign-in step.
AMAZON_EMAIL_PASSWORD_CLASSES = frozenset({
    'a-aui_72554-c', 'a-aui_template_weblab_cache_333406-c', 'a-box', 'a-box-inner',
    'a-button', 'a-button-inner', 'a-button-input', 'a-button-primary', 'a-button-span12',
    'a-bw_aui_dark_mode_mshop_ios_1390013-t2', 'a-column', 'a-form-label', 'a-input-text',
    'a-m-us', 'a-no-js', 'a-padding-extra-large', 'a-padding-medium', 'a-row',
    'a-section', 'a-spacing-base', 'a-spacing-large', 'a-spacing-none', 'a-span5', 'a-span12',
    'ap-locale-en_US', 'auth-autofocus', 'auth-disable-button-on-submit', 'auth-pagelet-container',
    'auth-real-time-validation', 'auth-required-field', 'auth-validate-form', 'auth-workflow',
})


def amazon_visible(element):
    return not any(
        node.name == 'template' or node.has_attr('hidden') or node.get('aria-hidden', '').lower() == 'true'
        or 'aok-hidden' in node.get('class', ()) or HIDDEN_STYLE.search(node.get('style', ''))
        for node in (element, *element.parents)
    )


def amazon_email_password_step(soup, response_url):
    forms = soup.select('form[name="signIn"][method="post"]')
    # The reference step has no inline stylesheet. The HTML parser cannot
    # establish whether additional rules hide a control.
    if len(forms) != 1 or soup.select_one('style') is not None:
        return False
    form = forms[0]
    target = urlparse(urljoin(str(response_url), form.get('action', '')))
    if target.scheme != 'https' or target.netloc != 'www.amazon.com' or target.path != '/ap/signin':
        return False
    if form.select_one('input#ap_email[name="email"][type="hidden"]') is None or any(
        node.get('id') != 'ap-credential-autofill-hint' or 'hide' not in node.get('class', ())
        for node in form.select('input[name="email"]:not([type="hidden"])')
    ):
        return False

    for selector in (
        'input#ap_password[name="password"][type="password"][autocomplete="current-password"]:not([readonly])',
        'label[for="ap_password"]',
        'input#signInSubmit[type="submit"]',
    ):
        controls = form.select(selector)
        if len(controls) != 1:
            return False
        control = controls[0]
        if not amazon_visible(control) or any(
            node.has_attr('disabled') or node.has_attr('inert') or node.get('style')
            or not AMAZON_EMAIL_PASSWORD_CLASSES.issuperset(node.get('class', ()))
            for node in (control, *control.parents)
        ):
            return False
    return True


def amazon_result(soup, response_url, *, phone_number):
    invalid_phone = soup.select_one('#invalid-phone-alert')
    if invalid_phone is not None and amazon_visible(invalid_phone):
        raise Unavailable('Amazon отклонил номер телефона; проверка не выполнена.')

    new_account = any(
        amazon_visible(node) and ' '.join(node.stripped_strings).replace('’', "'").casefold() == "looks like you're new to amazon"
        for node in soup.select('h1, h2')
    ) and any(
        amazon_visible(node) and ' '.join((node.get('value') or node.get_text(' ', strip=True)).split()).casefold()
        == 'proceed to create an account'
        for node in soup.select('button, input[type="submit"]')
    )

    if new_account and not any(
        node.get('id') != 'auth-credential-autofill-hint' and not node.has_attr('disabled') and amazon_visible(node)
        for node in soup.select('input[type="password"]')
    ):
        return False
    if not new_account and not phone_number and amazon_email_password_step(soup, response_url):
        return True
    raise Unavailable('Amazon не вернул распознаваемый результат; наличие аккаунта неизвестно.')


async def _amazon_lookup(identifier, client, out, *, phone_number=False):
    redirect_paths = AMAZON_SIGNIN_PATHS + ('/ax/claim/intent',) if phone_number else AMAZON_SIGNIN_PATHS

    async def operation():
        response = await client.get('https://www.amazon.com/ap/signin', params={
            'openid.assoc_handle': 'usflex', 'openid.mode': 'checkid_setup',
            'openid.ns': 'http://specs.openid.net/auth/2.0',
            'openid.return_to': 'https://www.amazon.com/',
            'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select'})
        soup = validate(response)
        field = soup.select_one('form input[name="email"]')
        if field is None:
            raise Unavailable('Не найдена ожидаемая форма входа Amazon.')
        form = field.find_parent('form')
        action = urljoin(str(response.url), form.get('action', ''))
        target = urlparse(action)
        if (target.scheme != 'https' or target.netloc != 'www.amazon.com'
                or target.path not in AMAZON_SIGNIN_PATHS
                or form.get('method', '').lower() != 'post'):
            raise Unavailable('Форма входа Amazon изменилась; отправка остановлена.')
        data = {i['name']: i.get('value', '') for i in form.select('input[name]')
                if i.get('type', '').lower() == 'hidden'}
        data['email'] = identifier
        if phone_number:
            data['claimType'] = 'phoneNumber'
        reply = await client.post(action, data=data, follow_redirects=False)
        # Follow only recognized same-origin login steps, using GET after a redirect.
        for _ in range(3):
            if reply.status_code not in (301, 302, 303, 307, 308):
                break
            location = reply.headers.get('location')
            target_url = urljoin(str(reply.url), location or '')
            redirect = urlparse(target_url)
            same_origin = redirect.scheme == 'https' and redirect.netloc == 'www.amazon.com'
            if location and same_origin and redirect.path == AMAZON_CHALLENGE_PATH:
                raise Unavailable('Amazon запросил дополнительную проверку; проверка не выполнена.')
            if reply.status_code in (307, 308):
                break
            if not location or not same_origin or redirect.path not in redirect_paths:
                raise Unavailable('Amazon перенаправил на неподдерживаемую страницу; проверка остановлена.')
            reply = await client.get(target_url, follow_redirects=False)
        return amazon_result(validate(reply), reply.url, phone_number=phone_number)

    await guarded('Amazon', operation, out,
                  not_found_reason='Amazon предложил создать аккаунт для указанного идентификатора.')


async def amazon_email(email, client, out):
    await _amazon_lookup(email, client, out)


async def amazon_phone(phone, country_code, client, out):
    await _amazon_lookup(f'+{country_code}{phone}', client, out, phone_number=True)


async def instagram(email, client, out):
    async def operation():
        response = await client.get('https://www.instagram.com/accounts/emailsignup/')
        validate(response)
        token = next((c.value for c in client.cookies.jar if c.name == 'csrftoken'
                      and c.domain.lstrip('.') in ('instagram.com', 'www.instagram.com')), None)
        if not token:
            match = re.search(r'"csrf_token"\s*:\s*"([A-Za-z0-9_-]+)"', response.text)
            token = match.group(1) if match else None
        if not token:
            raise Unavailable('Instagram не предоставил CSRF-токен; проверка недоступна.')
        response = await client.post(
            'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/',
            data={'email': email, 'username': '', 'first_name': '', 'opt_into_one_tap': 'false'},
            follow_redirects=False,
            headers={'x-csrftoken': token, 'Origin': 'https://www.instagram.com',
                     'Referer': 'https://www.instagram.com/accounts/emailsignup/'})
        validate(response)
        payload = response.json()
        if not isinstance(payload, dict) or payload.get('status') != 'ok' or not isinstance(payload.get('errors'), dict):
            raise Unavailable('Instagram отклонил проверку или изменил формат ответа.')
        errors = payload['errors'].get('email')
        if isinstance(errors, list) and any(isinstance(e, dict) and e.get('code') == 'email_is_taken' for e in errors):
            return True
        # Missing email error is not evidence of absence; sharing limits are not proof either.
        raise Unavailable('Instagram не дал однозначного признака регистрации.')
    await guarded('Instagram', operation, out)


async def spotify(email, client, out):
    """Use validation-only GET; never submit Spotify's account creation form."""
    async def operation():
        response = await client.get(
            'https://spclient.wg.spotify.com/signup/public/v1/account',
            params={'validate': '1', 'email': email}, follow_redirects=False)
        if response.status_code != 200:
            raise Unavailable(f"Источник вернул HTTP {response.status_code}; проверка не выполнена.")
        payload = response.json()
        if not isinstance(payload, dict) or type(payload.get('status')) is not int:
            raise Unavailable('Spotify изменил формат ответа; регистрация неизвестна.')
        if payload['status'] == 20:
            return True
        if payload['status'] == 1:
            return False
        raise Unavailable('Spotify не дал распознаваемого ответа о доступности email.')
    await guarded('Spotify', operation, out)
    if out and out[-1].get('name') == 'Spotify' and not out[-1].get('rateLimit'):
        out[-1]['reason'] = (
            'Форма Spotify сообщила, что email уже используется. Возможная регистрация; подтвердите в своём аккаунте.'
            if out[-1]['exists'] else
            'Форма Spotify разрешила использовать email. Это не доказывает отсутствие аккаунта или данных в других сервисах.')


async def github_username(username, client, out):
    """Public exact-handle lookup; a profile does not establish its owner's identity."""
    from search_inputs import normalize_username
    username = normalize_username(username).lower()
    check = dict(name='GitHub', kind='username')
    try:
        response = await client.get('https://api.github.com/users/' + username,
                                    follow_redirects=False,
                                    headers={'Accept': 'application/vnd.github+json',
                                             'X-GitHub-Api-Version': '2022-11-28'})
        payload = response.json()
        if (response.status_code == 200 and isinstance(payload, dict)
                and isinstance(payload.get('login'), str)
                and payload['login'].lower() == username
                and type(payload.get('id')) is int
                and payload.get('type') == 'User'
                and payload.get('html_url') == 'https://github.com/' + payload['login']):
            check.update(status='found', profile_url=payload['html_url'],
                         reason='Найден публичный профиль с точным username. Принадлежность человеку не подтверждена.')
        elif response.status_code == 404 and isinstance(payload, dict) and payload.get('message') == 'Not Found':
            check.update(status='not_found', reason='GitHub не нашёл публичный профиль с этим username. Это не исключает данные в других источниках.')
        else:
            check.update(status='unavailable', reason=f'GitHub не дал пригодного ответа (HTTP {response.status_code}).')
    except (httpx.HTTPError, ValueError):
        check.update(status='unavailable', reason='Ошибка связи или неизвестный формат ответа GitHub.')
    out.append(check)
