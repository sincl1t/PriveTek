const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');
const { createContext, runInContext } = require('node:vm');

const source = readFileSync(join(__dirname, '../../account_ui/account.js'), 'utf8');

class Element {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.open = false;
    this.hidden = false;
  }

  get textContent() {
    return this.children.map(child => typeof child === 'string' ? child : child.textContent).join('');
  }

  set textContent(text) { this.children = text ? [text] : []; }
  append(...children) { this.children.push(...children); }
  addEventListener() {}
  setAttribute() {}
  reset() {}
  focus() {}
}

function chat(results, failure) {
  const nodes = new Map();
  const requests = [];
  const get = id => {
    if (!nodes.has(id)) nodes.set(id, new Element('div'));
    return nodes.get(id);
  };
  const context = createContext({
    document: {body: new Element('body'), getElementById: get, createElement: tag => new Element(tag), addEventListener() {}},
    window: {addEventListener() {}},
    setInterval() {},
    fetch(path, options) {
      const method = options.method || 'GET';
      if (path === '/api/account/draft') return new Promise(() => {});
      assert.equal(path, '/api/account/profile-search');
      requests.push(method);
      return {ok: !failure, status: failure ? 500 : 200, json: async () => failure || {busy: false, results}};
    },
  });
  runInContext(source, context, {filename: 'account.js'});
  get('profile-search-name').value = 'octocat';
  get('profile-search-consent').checked = true;
  return {
    requests,
    submit: () => get('profile-search-form').onsubmit({preventDefault() {}}),
    restore: () => runInContext('loadProfileSearch(true)', context),
    reply: () => get('profile-search-log').children.at(-1),
  };
}

function visibleText(node) {
  if (typeof node === 'string') return node;
  if (node.hidden) return '';
  const children = node.tag === 'details' && !node.open ? node.children.slice(0, 1) : node.children;
  return children.map(visibleText).join(' ');
}

function descendants(node, tag) {
  if (typeof node === 'string') return [];
  const children = node.children.flatMap(child => descendants(child, tag));
  return node.tag === tag ? [node, ...children] : children;
}

function detailsFor(reply) {
  const [details] = descendants(reply, 'details');
  assert.ok(details, 'ожидается раскрываемый список в том же сообщении');
  assert.equal(details.open, false);
  assert.equal(details.children[0].tag, 'summary');
  assert.equal(details.children[0].textContent, 'Подробнее по источникам');
  return details;
}

const found = {site: 'GitHub', status: 'found', url: 'https://github.com/octocat'};
const notFound = {site: 'GitLab', status: 'not_found', url: null};
const unavailable = {site: 'Roblox', status: 'unavailable', url: null};
const skipped = {site: 'Codeberg', status: 'skipped', url: null};

test('a new search shows links and counts, with other statuses in collapsed details', async () => {
  const state = chat([notFound, unavailable, found, skipped]);
  await state.submit();
  const reply = state.reply();
  const text = visibleText(reply);
  assert.match(text, /Найдено: 1/);
  assert.match(text, /Проверено без находок: 1/);
  assert.match(text, /Недоступно: 1/);
  assert.match(text, /Пропущено: 1/);
  assert.match(text, /GitHub/);
  assert.doesNotMatch(text, /GitLab|Roblox|Codeberg/);
  assert.deepEqual(descendants(reply, 'a').map(link => link.href), [found.url]);
  const details = detailsFor(reply);
  assert.match(details.textContent, /GitLab — Совпадений не найдено/);
  assert.match(details.textContent, /Roblox — Проверка недоступна/);
  assert.match(details.textContent, /Codeberg — Формат имени не подходит/);
  assert.doesNotMatch(details.textContent, /GitHub/);
  assert.deepEqual(state.requests, ['POST']);
});

test('a definitive negative result has its own message', async () => {
  const state = chat([notFound, unavailable, skipped]);
  await state.submit();
  const text = visibleText(state.reply());
  assert.match(text, /Совпадений не найдено среди успешно выполненных проверок/);
  assert.match(text, /Найдено: 0/);
  assert.match(text, /Проверено без находок: 1/);
  detailsFor(state.reply());
});

for (const [action, method] of [['submit', 'POST'], ['restore', 'GET']]) {
  test(`an inconclusive attempt has its own message (${method})`, async () => {
    const state = chat([unavailable, {...unavailable, site: 'GitLab'}, skipped]);
    await state[action]();
    const reply = state.reply();
    const text = visibleText(reply);
    assert.match(text, /Не удалось завершить проверки/);
    assert.doesNotMatch(text, /Совпадений не найдено/);
    assert.match(text, /Найдено: 0/);
    assert.match(text, /Проверено без находок: 0/);
    assert.match(text, /Недоступно: 2/);
    assert.match(text, /Пропущено: 1/);
    assert.match(detailsFor(reply).textContent, /Codeberg — Формат имени не подходит/);
    assert.deepEqual(state.requests, [method]);
  });
}

test('an HTTP error without source results keeps the existing error message', async () => {
  const state = chat([], {detail: 'Сервис временно недоступен'});
  await state.submit();
  const reply = state.reply();
  assert.match(visibleText(reply), /Сервис временно недоступен/);
  assert.deepEqual(descendants(reply, 'details'), []);
});
