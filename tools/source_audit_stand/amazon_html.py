"""Save a local, inert copy of the HTML seen by the Amazon adapter."""
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, Comment


FORM_PATHS = {'/ap/signin', '/ap/signin/', '/ax/claim', '/ap/register', '/errors/validateCaptcha'}
ATTRIBUTES = {'id', 'class', 'name', 'type', 'method', 'role', 'hidden', 'aria-hidden'}
HIDDEN_STYLE = re.compile(r'(?:^|;)\s*(display\s*:\s*none|visibility\s*:\s*hidden)\b', re.I)
CONTACT = re.compile(
    r'[\w.+%-]+@[\w.-]+\.[a-z]{2,}|\+?\d(?:[\s().-]*\d){6,}', re.I,
)


def save_html(directory, sequence, method, response):
    media_type = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
    if media_type not in ('text/html', 'application/xhtml+xml'):
        return None

    soup = BeautifulSoup(response.text, 'html.parser')
    for tag in reversed(soup.select('script, style, link, meta, base, iframe, object, embed, svg')):
        tag.decompose()
    for node in soup.find_all(string=lambda text: isinstance(text, Comment)):
        node.extract()
    for tag in soup.find_all(True):
        original = tag.attrs
        tag.attrs = {
            name: [CONTACT.sub('[redacted]', item) for item in value]
            if isinstance(value, list) else CONTACT.sub('[redacted]', value)
            for name, value in original.items() if name in ATTRIBUTES
        }
        if tag.name == 'form':
            action = urlsplit(original.get('action', '')).path
            if action in FORM_PATHS:
                tag['action'] = action
        hidden = HIDDEN_STYLE.findall(original.get('style', ''))
        if hidden:
            tag['style'] = '; '.join(hidden)
    for node in soup.find_all(string=CONTACT.search):
        node.replace_with(CONTACT.sub('[redacted]', node))

    policy = soup.new_tag('meta', attrs={
        'http-equiv': 'Content-Security-Policy',
        'content': "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'",
    })
    header = soup.head if soup.head is not None else soup
    header.insert(0, policy)
    header.insert(0, soup.new_tag('meta', charset='utf-8'))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f'{sequence:02d}-{method}-{response.status_code}.html'
    path.write_text(str(soup), encoding='utf-8')
    return path.name
