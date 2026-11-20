'use strict';
(() => {
  const log = $('report-chat-log');
  const options = $('report-chat-options');
  const form = $('report-chat-form');
  const input = $('report-chat-input');
  const send = $('report-chat-send');
  let step = 'start', phone = '', usernames = [], jobId = '', snapshot = null;
  let revision = 0, timer = null, attempts = 0;

  function bubble(text, role = 'bot') {
    const item = textEl('article', 'profile-chat-bubble ' + role, '');
    item.append(textEl('div', 'profile-chat-author', role === 'user' ? 'Вы' : 'PriveTek'));
    item.append(textEl('p', '', text));
    log.append(item);
    log.scrollTop = log.scrollHeight;
    return item;
  }

  function button(label, action) {
    const element = textEl('button', 'button secondary', label);
    element.type = 'button';
    element.onclick = action;
    options.append(element);
  }

  function prompt(next, text, label = '') {
    step = next;
    options.textContent = '';
    message('report-chat-error', '');
    form.hidden = !label;
    input.value = '';
    input.type = next === 'phone' ? 'tel' : 'text';
    input.inputMode = next === 'phone' ? 'tel' : 'text';
    $('report-chat-label').textContent = label || 'Ваш ответ';
    input.placeholder = next === 'phone' ? '+7 912 345-67-89' : '@username';
    bubble(text);
    if (label) input.focus();
  }

  function reset() {
    revision++;
    clearTimeout(timer);
    phone = ''; usernames = []; jobId = ''; snapshot = null; attempts = 0;
    log.textContent = ''; options.textContent = '';
    send.disabled = false;
    prompt('start', 'Начнём с вашей подтверждённой почты. Затем уточним телефон и варианты username. Перед запуском покажу состав проверки.');
    button('Подготовить проверку', () => {
      if (!userEmail || $('dashboard').hidden) return;
      bubble('Проверить мои данные', 'user');
      prompt('phone', 'Для email используем почту вашего аккаунта. Укажите свой телефон с кодом страны. Сейчас телефон проверяется на признак регистрации в Amazon; источник может быть недоступен.', 'Ваш телефон');
    });
  }

  function review() {
    prompt('review', 'Проверим почту ' + userEmail + ', телефон ' + phone +
      (usernames.length ? ' и username: ' + usernames.join(', ') + '.' : '. Username не указан; поиск профилей будет пропущен.'));
    bubble('При запуске разрешаете передать свои данные подключённым источникам: email — Gravatar, LeakCheck, Instagram, Amazon, Spotify и HIBP при подключении; телефон — Amazon; username — площадкам публичных профилей. Хеш email не делает адрес анонимным. Совпадения требуют проверки принадлежности.');
    button('Согласен, проверить мои данные', submit);
    button('Изменить данные', reset);
  }

  async function submit() {
    if (step !== 'review' || $('dashboard').hidden) return;
    const ticket = revision;
    prompt('submitting', 'Запускаю проверку. Это может занять несколько минут.');
    bubble('Согласен на проверку моих данных', 'user');
    $('report-chat-restart').disabled = true;
    try {
      const data = await api('jobs', {method: 'POST', body: JSON.stringify({
        phone, username: usernames[0] || '', additional_usernames: usernames.slice(1), consent: true
      })});
      if (ticket !== revision) return;
      if (!/^[0-9a-f]{32}$/.test(data.job_id)) throw new Error('Не удалось определить номер проверки. Посмотрите историю перед повторным запуском.');
      jobId = data.job_id;
      phone = ''; usernames = []; input.value = '';
      bubble(data.duplicate ? 'Такая заявка уже есть в истории. Проверю её результат.' : 'Заявка принята. Готовый отчёт также сохранится в истории, если закрыть страницу.');
      loadJobs(true).catch(() => {});
      await poll(ticket);
    } catch (error) {
      if (ticket !== revision) return;
      if (error.status === 401) signedOut('Сессия завершилась. Войдите снова.');
      else {
        review();
        bubble(error.message);
      }
    } finally {
      if (ticket === revision) $('report-chat-restart').disabled = false;
    }
  }

  async function poll(ticket) {
    if (ticket !== revision || $('dashboard').hidden) return;
    options.textContent = '';
    try {
      const data = await api('jobs/' + jobId + '/identity');
      if (ticket !== revision) return;
      snapshot = data;
      renderSummary();
      loadJobs(true).catch(() => {});
    } catch (error) {
      if (ticket !== revision) return;
      if (error.status === 401) {
        signedOut('Сессия завершилась. Войдите снова.');
        return;
      }
      if (error.status === 404 && ++attempts < 40) {
        timer = setTimeout(() => poll(ticket), 3000);
      } else {
        bubble(error.status === 404
          ? 'Разбор пока недоступен. Откройте статус заявки в истории или повторите получение результата.'
          : error.message);
        button('Получить результат', () => poll(ticket));
        button('Открыть историю', () => openAccountTab('reports', true));
      }
    }
  }

  function details() {
    const reply = bubble('Результаты по источникам');
    for (const item of snapshot.coverage?.entries || []) {
      const status = {found: 'Найдены сведения', possible: 'Возможное совпадение',
        not_found: 'Совпадений нет', unknown: 'Ответ неопределённый',
        unavailable: 'Источник недоступен', skipped: 'Проверка пропущена', disabled: 'Проверка отключена'};
      reply.append(textEl('p', '', item.source + ' — ' + (status[item.status] || 'Ответ неопределённый') +
        (item.query_username ? ' · ' + item.query_username : '') + '. ' + (item.reason || '')));
    }
    if (snapshot.coverage?.omitted) reply.append(textEl('p', '', 'Остальные проверки перечислены в PDF.'));
    log.scrollTop = reply.offsetTop;
  }

  function advice() {
    const kinds = new Set(snapshot.findings.filter(item => item.decision !== 'not_mine').map(item => item.kind));
    const reply = bubble('Что делать дальше');
    if (kinds.has('breach')) reply.append(textEl('p', '', 'Откройте затронутые сервисы напрямую. Проверьте состав и дату утечки в PDF. Если скомпрометированный пароль ещё используется, замените его и все повторяющиеся пароли. Включите двухфакторную защиту.'));
    if (kinds.has('username')) reply.append(textEl('p', '', 'Сверьте найденные профили со своими. Отметьте принадлежность и проверьте настройки публичности.'));
    if (kinds.has('email') || kinds.has('phone')) reply.append(textEl('p', '', 'Признак регистрации проверьте в собственном аккаунте соответствующего сервиса. Он не подтверждает личность владельца.'));
    if (kinds.has('avatar')) reply.append(textEl('p', '', 'Проверьте публичность аватара и связь изображения с почтой в Gravatar.'));
    reply.append(textEl('p', '', 'Используйте уникальные пароли и двухфакторную защиту. Недоступные источники и отсутствие совпадений ограничивают выводы проверки.'));
    log.scrollTop = log.scrollHeight;
  }

  function renderSummary() {
    step = 'done';
    const entries = snapshot.coverage?.entries || [];
    const counts = snapshot.coverage?.counts || {};
    const confirmed = entries.filter(item => item.status === 'found').length;
    const possible = entries.filter(item => item.status === 'possible').length;
    const reply = bubble('Разбор проверки готов');
    reply.append(textEl('p', '', 'Проверок с находками: ' + confirmed + '. Возможных совпадений: ' + possible + '.'));
    reply.append(textEl('p', '', 'Завершено: ' + (counts.completed || 0) +
      '. Неопределённых: ' + (counts.inconclusive || 0) +
      '. Недоступных: ' + (counts.unavailable || 0) +
      '. Пропущено или отключено: ' + ((counts.skipped || 0) + (counts.disabled || 0)) + '.'));
    for (const item of snapshot.findings) {
      reply.append(textEl('p', '', item.title));
      if (item.profile_url) {
        const link = textEl('a', '', 'Открыть профиль');
        link.href = item.profile_url; link.target = '_blank'; link.rel = 'noopener noreferrer';
        reply.append(link);
      }
    }
    reply.append(textEl('p', 'small', 'Сопоставление с запросом не подтверждает владельца. Полнота охвата ограничена подключёнными источниками.'));
    if (snapshot.omitted || snapshot.coverage?.omitted) reply.append(textEl('p', '', 'Часть результатов показана только в PDF.'));
    const pdf = textEl('a', 'button secondary', 'Скачать полный PDF');
    pdf.href = '/api/account/jobs/' + jobId + '/report'; pdf.download = 'PriveTek-report.pdf';
    reply.append(pdf);
    options.textContent = '';
    button('Что делать дальше?', advice);
    button('Что не удалось проверить?', details);
    button('Какие профили мои?', () => openIdentity(jobId));
    button('Обновить разбор после отметок', () => poll(revision));
    form.hidden = false;
    input.value = '';
    input.type = 'text';
    input.inputMode = 'text';
    input.placeholder = 'Например, что делать дальше?';
    $('report-chat-label').textContent = 'Уточняющий вопрос';
    advice();
  }

  form.onsubmit = event => {
    event.preventDefault();
    message('report-chat-error', '');
    const value = input.value.trim();
    if (step === 'phone') {
      if (!/^\+[0-9\s().-]{7,39}$/.test(value)) {
        message('report-chat-error', 'Укажите телефон с кодом страны, начиная с +.', true);
        return;
      }
      phone = value;
      bubble('Телефон добавлен', 'user');
      prompt('usernames', 'Какие username вы используете? Укажите до трёх вариантов через запятую или пробел.', 'Ваши username');
      button('Пропустить username', review);
    } else if (step === 'usernames') {
      const names = [...new Set(value.split(/[,\s]+/).filter(Boolean).map(name => name.replace(/^@/, '')))];
      if (!names.length || names.length > 3 || names.some(name => !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name))) {
        message('report-chat-error', 'Укажите до трёх username: латинские буквы, цифры, точки, дефисы и подчёркивания, до 64 символов каждый.', true);
        return;
      }
      usernames = names;
      bubble(names.join(', '), 'user');
      review();
    } else if (step === 'done') {
      if (!value) return;
      bubble(value, 'user');
      input.value = '';
      if (/профил|принадлеж|мо[йиёе]|чуж/.test(value.toLowerCase())) {
        bubble('В карточке можно отметить «Моё», «Не моё» или «Не уверен». После изменения обновите разбор в чате.');
        openIdentity(jobId);
      } else if (/источник|не удалось|не провер|почему|полнот/.test(value.toLowerCase())) {
        details();
      } else if (/делать|защит|парол|утеч|риск/.test(value.toLowerCase())) {
        advice();
      } else {
        bubble('Могу пояснить результаты по источникам, подсказать дальнейшие действия или помочь отметить принадлежность профилей. Выберите вопрос под диалогом.');
      }
    }
  };
  $('report-chat-restart').onclick = reset;
  document.addEventListener('account-signed-out', () => {
    reset();
    $('report-chat-restart').disabled = false;
  });
  reset();
})();
