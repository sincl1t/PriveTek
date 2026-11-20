/* Guided landing chat. Contacts stay in the page until a native POST to the account. */
'use strict';
(() => {
  function mount() {
    const original = document.getElementById('form2008423781');
    if (!original || original.dataset.privetekHandoff === 'yes') return;
    const emailTemplate = original.elements?.namedItem('Email');
    if (!emailTemplate) return;
    const color = getComputedStyle(emailTemplate).color;
    const root = document.createElement('div');
    root.id = original.id;
    root.dataset.privetekHandoff = 'yes';
    root.className = 'privetek-landing-chat';
    const style = document.createElement('style');
    style.textContent = `
      .privetek-landing-chat{color:inherit;width:100%;min-width:0;font-family:inherit;text-align:left}
      .privetek-landing-chat *{box-sizing:border-box}
      .privetek-landing-chat-log{max-height:420px;overflow:auto;display:flex;flex-direction:column;gap:12px;padding:4px 2px 18px}
      .privetek-landing-chat-bubble{max-width:94%;padding:16px 18px;border-radius:18px 18px 18px 4px;background:#efedf9;line-height:1.6;color:#171452;font-size:16px;overflow-wrap:anywhere}
      .privetek-landing-chat-bubble.user{align-self:flex-end;background:#dff5f3;border-radius:18px 18px 4px 18px}
      .privetek-landing-chat-author{font-size:13px;font-weight:700;margin-bottom:5px}
      .privetek-landing-chat p{margin:0}
      .privetek-landing-chat input{width:100%;min-width:0;padding:15px;border:1px solid #b4b1cc;border-radius:14px;background:#fff;color:#171452;font:inherit;font-size:16px;margin:8px 0 12px}
      .privetek-landing-chat label{display:block;font-size:14px;line-height:1.5}
      .privetek-landing-chat button{display:inline-block;min-height:48px;padding:14px 20px;border-radius:28px;border:1px solid #171452;background:#171452;color:#fff;font:inherit;font-size:16px;cursor:pointer;white-space:normal}
      .privetek-landing-chat-options{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
      .privetek-landing-chat-options button{background:#fff;color:#171452}
      .privetek-landing-chat [hidden]{display:none!important}
      .privetek-landing-chat button:focus-visible,.privetek-landing-chat input:focus-visible{outline:3px solid #21a8af;outline-offset:3px}
      .privetek-landing-chat-note{font-size:14px;line-height:1.6;margin-top:18px!important}
      .privetek-landing-chat-error{color:#a12a36;margin-bottom:12px!important}
      @media(max-width:480px){.privetek-landing-chat-options button{width:100%}.privetek-landing-chat-bubble{max-width:100%;padding:13px 15px}}
    `;
    root.style.color = color;
    const create = (tag, cls, text) => {
      const node = document.createElement(tag);
      node.className = cls;
      node.textContent = text;
      return node;
    };
    const log = create('div', 'privetek-landing-chat-log', '');
    log.setAttribute('role', 'log');
    log.setAttribute('aria-label', 'Чат подготовки проверки');
    log.tabIndex = 0;
    const options = create('div', 'privetek-landing-chat-options', '');
    const form = document.createElement('form');
    form.noValidate = false;
    const label = create('label', '', 'Ваш email');
    const input = document.createElement('input');
    input.id = 'privetek-chat-answer';
    input.required = true;
    input.maxLength = 254;
    label.htmlFor = input.id;
    input.setAttribute('aria-describedby', 'privetek-chat-error');
    const error = create('p', 'privetek-landing-chat-error', '');
    error.id = 'privetek-chat-error';
    error.setAttribute('role', 'status');
    error.hidden = true;
    const send = create('button', '', 'Отправить');
    send.type = 'submit';
    form.append(label, input, error, send);
    const note = create('p', 'privetek-landing-chat-note',
      'Перед запуском проверки потребуется подтвердить email и войти в кабинет или создать аккаунт. Заявка сохранится на один час.');
    const alternative = create('a', '', 'Продолжить в личном кабинете');
    alternative.href = 'https://lk.privetek.ru/account/start';
    alternative.style.cssText = 'display:block;margin-top:14px;text-decoration:underline;color:inherit;font-size:14px';
    root.append(style, log, options, form, note, alternative);

    let step, email, phone, names;
    function bubble(text, user = false) {
      const item = create('div', 'privetek-landing-chat-bubble' + (user ? ' user' : ''), '');
      item.append(create('div', 'privetek-landing-chat-author', user ? 'Вы' : 'PriveTek'), create('p', '', text));
      log.append(item);
      log.scrollTop = log.scrollHeight;
    }
    function action(text, callback) {
      const button = create('button', '', text);
      button.type = 'button';
      button.onclick = callback;
      options.append(button);
    }
    function ask(next, text, title, type, placeholder) {
      step = next;
      options.textContent = '';
      error.hidden = true;
      error.textContent = '';
      form.hidden = !title;
      input.value = '';
      input.type = type || 'text';
      input.autocomplete = next === 'email' ? 'email' : next === 'phone' ? 'tel' : 'off';
      input.inputMode = next === 'phone' ? 'tel' : next === 'email' ? 'email' : 'text';
      input.autocapitalize = 'none';
      input.spellcheck = false;
      label.textContent = title || 'Ваш ответ';
      input.placeholder = placeholder || '';
      bubble(text);
    }
    function reset() {
      email = ''; phone = ''; names = [];
      log.textContent = '';
      ask('email', 'Помогу проверить ваш цифровой след. Начнём с вашей почты, затем уточним телефон и username. На выходе получите разбор находок, ограничения проверки и полный PDF.', 'Ваш email', 'email', 'you@example.com');
    }
    function review() {
      ask('review', 'Подготовили заявку: email ' + email + ', телефон ' + phone +
        (names.length ? ', username: ' + names.join(', ') : '. Username не указан') +
        '. Продолжим в защищённом кабинете. Передадим введённые данные в PriveTek и сохраним заявку на один час; согласие на поиск по внешним источникам вы дадите перед запуском.');
      action('Продолжить и подтвердить почту', () => {
        if (step !== 'review') return;
        step = 'sending';
        options.querySelectorAll('button').forEach(button => { button.disabled = true; });
        const transfer = document.createElement('form');
        transfer.method = 'post';
        transfer.action = 'https://lk.privetek.ru/account/start';
        transfer.target = '_self';
        transfer.enctype = 'application/x-www-form-urlencoded';
        transfer.hidden = true;
        for (const [key, value] of Object.entries({
          Name: '', Email: email, Phone: phone, Username: names[0] || '',
          AdditionalUsername1: names[1] || '', AdditionalUsername2: names[2] || ''
        })) {
          const field = document.createElement('input');
          field.type = 'hidden'; field.name = key; field.value = value;
          transfer.append(field);
        }
        root.append(transfer);
        HTMLFormElement.prototype.submit.call(transfer);
      });
      action('Изменить данные', reset);
    }
    form.addEventListener('submit', event => {
      event.preventDefault();
      event.stopImmediatePropagation();
      if (!form.reportValidity()) return;
      const value = input.value.trim();
      error.hidden = true;
      if (step === 'email') {
        email = value;
        bubble(value, true);
        ask('phone', 'Укажите свой телефон с кодом страны. Сейчас поиск по телефону проверяет признак регистрации в Amazon; больше находок номер не гарантирует.', 'Ваш телефон', 'tel', '+7 912 345-67-89');
      } else if (step === 'phone') {
        if (!/^\+[0-9\s().-]{7,39}$/.test(value)) {
          error.textContent = 'Укажите номер с кодом страны, начиная с +.';
          error.hidden = false;
          return;
        }
        phone = value;
        bubble('Телефон добавлен', true);
        ask('usernames', 'Какие username вы используете? Можно указать до трёх вариантов через пробел или запятую.', 'Ваши username', 'text', '@username, another_name');
        action('Пропустить username', review);
      } else if (step === 'usernames') {
        const values = [...new Set(value.split(/[,\s]+/).filter(Boolean).map(name => name.replace(/^@/, '')))];
        if (!values.length || values.length > 3 || values.some(name => !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name))) {
          error.textContent = 'Укажите до трёх username без ссылок, до 64 латинских букв, цифр, точек, дефисов и подчёркиваний.';
          error.hidden = false;
          return;
        }
        names = values;
        bubble(names.join(', '), true);
        review();
      }
    });
    reset();
    original.replaceWith(root);
    const record = document.getElementById('rec2008423781');
    const title = record?.querySelector('[field="title"]');
    if (title) { title.textContent = 'Проверьте свой цифровой след в чате'; title.style.color = color; }
    const bottom = record?.querySelector('[field="text2"]');
    if (bottom) {
      bottom.textContent = 'Подтверждение email не подтверждает владение телефоном или профилями. ';
      bottom.style.color = color;
      const privacy = create('a', '', 'Политика конфиденциальности');
      privacy.href = 'https://privetek.ru/page137765066.html';
      privacy.style.color = color;
      bottom.append(privacy);
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
