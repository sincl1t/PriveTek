'use strict';
(() => {
  const themes = ['sky', 'violet', 'mint', 'rose', 'amber', 'slate'];
  const shell = $('profile-shell'), toggle = $('profile-toggle'), menu = $('profile-menu');
  const dialog = $('profile-dialog'), form = $('profile-form'), save = $('profile-save');
  let saved = {display_name:'', avatar_theme:'sky', avatar_url:null}, epoch = 0, loaded = false, pending = null;
  let email = '', busy = false, photoBusy = false;


  function photoUrl(value) {
    return typeof value === 'string' && /^\/api\/account\/profile\/avatar\?v=[0-9a-f]{24}$/.test(value) ? value : null;
  }
  function paintPhoto(image, fallback, url) {
    if (!url) { image.hidden = true; fallback.hidden = false; image.removeAttribute('src'); return; }
    if (image.getAttribute('src') !== url) {
      image.hidden = true; fallback.hidden = false; image.src = url;
    } else if (image.complete && image.naturalWidth) { image.hidden = false; fallback.hidden = true; }
  }
  for (const [photoId, fallbackId] of [['profile-header-photo','profile-initials'],['profile-preview-photo','profile-preview-initials']]) {
    const image = $(photoId), fallback = $(fallbackId);
    image.onload = () => { if (image.getAttribute('src') && image.naturalWidth) { image.hidden = false; fallback.hidden = true; } };
    image.onerror = () => { image.hidden = true; fallback.hidden = false; };
  }
  function setControls() {
    const disabled = !loaded || busy || photoBusy;
    save.disabled = disabled;
    $('profile-photo-choose').disabled = disabled;
    $('profile-photo-remove').disabled = disabled;
    $('profile-display-name').disabled = !loaded || busy;
    form.querySelectorAll('input[type=radio]').forEach(input => input.disabled = !loaded || busy);
  }
  $('profile-photo-choose').onclick = () => $('profile-photo-file').click();
  $('profile-photo-file').onchange = () => {
    const file = $('profile-photo-file').files[0];
    $('profile-photo-file').value = '';
    if (file) changePhoto(file);
  };
  $('profile-photo-remove').onclick = () => changePhoto(null);
  async function changePhoto(file) {
    if (!loaded || busy || photoBusy) return;
    const mime = file && (file.type || ({jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',webp:'image/webp'})[file.name.split('.').pop().toLowerCase()]);
    if (file && (!['image/jpeg','image/png','image/webp'].includes(mime) || file.size > 5 * 1024 * 1024)) {
      message('profile-photo-message', 'Выберите JPEG, PNG или WebP до 5 МБ.', true); return;
    }
    const ticket = epoch;
    photoBusy = true; setControls();
    message('profile-photo-message', file ? 'Загружаем фотографию…' : 'Удаляем фотографию…');
    try {
      const data = await api('profile/avatar', file ? {method:'PUT',body:file,headers:{'Content-Type':mime}} : {method:'DELETE'});
      if (ticket !== epoch) return;
      saved.avatar_url = photoUrl(data.avatar_url);
      renderHeader(); preview();
      message('profile-photo-message', file ? 'Фотография сохранена.' : 'Фотография удалена. Используем инициалы.');
    } catch (error) {
      if (ticket !== epoch) return;
      if (error.status === 401) signedOut('Сессия завершилась. Войдите снова.');
      else message('profile-photo-message', error.message, true);
    } finally { if (ticket === epoch) { photoBusy = false; setControls(); } }
  }

  function initials(name) {
    const words = name.trim().split(/\s+/).filter(Boolean);
    const value = words.length > 1 ? Array.from(words[0])[0] + Array.from(words[1])[0]
      : Array.from(words[0] || email.split('@')[0] || 'P').slice(0, 2).join('');
    return value.toLocaleUpperCase('ru');
  }
  function avatar(element, name, theme, base) {
    element.className = base + ' avatar-' + (themes.includes(theme) ? theme : 'sky');
    $('profile-preview-initials').textContent = initials(name);
  }
  function renderHeader() {
    const name = saved.display_name || 'Мой аккаунт';
    // Keep the button's decorative status dot while replacing only its initials.
    toggle.className = 'avatar-button avatar-' + saved.avatar_theme;
    $('profile-initials').textContent = initials(saved.display_name);
    paintPhoto($('profile-header-photo'), $('profile-initials'), saved.avatar_url);
    toggle.setAttribute('aria-label', 'Открыть профиль: ' + name);
    $('profile-menu-name').textContent = name;
    $('profile-menu-email').textContent = email;
    $('profile-summary-name').textContent = name;
    $('profile-summary-email').textContent = email;
  }
  function preview() {
    const theme = form.elements['avatar-theme'].value || 'sky';
    avatar($('profile-avatar-preview'), $('profile-display-name').value, theme, 'profile-avatar');
    paintPhoto($('profile-preview-photo'), $('profile-preview-initials'), saved.avatar_url);
    $('profile-photo-remove').hidden = !saved.avatar_url;
    $('profile-photo-choose').textContent = saved.avatar_url ? 'Заменить фото' : 'Загрузить фото';
  }
  function populate() {
    $('profile-display-name').value = saved.display_name;
    form.elements['avatar-theme'].value = saved.avatar_theme;
    $('profile-email').value = email;
    preview();
  }
  function closeMenu(restore = false) {
    menu.hidden = true; toggle.setAttribute('aria-expanded', 'false');
    if (restore && !shell.hidden) toggle.focus();
  }
  toggle.onclick = () => {
    const opening = menu.hidden;
    menu.hidden = !opening; toggle.setAttribute('aria-expanded', String(opening));
    if (opening) menu.querySelector('button').focus();
  };
  document.addEventListener('click', event => { if (!shell.contains(event.target)) closeMenu(); });
  document.addEventListener('focusin', event => { if (!shell.contains(event.target)) closeMenu(); });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !menu.hidden) { event.preventDefault(); closeMenu(true); }
  });
  document.addEventListener('profile-menu-close', () => closeMenu());

  function view(name) {
    for (const key of ['personal','subscription','settings']) {
      $('profile-view-' + key).hidden = key !== name;
      document.querySelector('[data-profile-view="' + key + '"]').setAttribute('aria-pressed', String(key === name));
    }
    message('profile-message', '');
  }
  async function loadProfile() {
    if (pending) return pending;
    const ticket = epoch;
    setControls();
    $('profile-display-name').disabled = true;
    form.querySelectorAll('input[type=radio]').forEach(input => input.disabled = true);
    pending = (async () => {
      try {
        const data = await api('profile');
        if (ticket !== epoch) return;
        saved = {display_name:data.display_name || '', avatar_theme:themes.includes(data.avatar_theme) ? data.avatar_theme : 'sky',avatar_url:photoUrl(data.avatar_url)};
        loaded = true;
        renderHeader(); populate();
        const access = data.access || {};
        const until = access.manual_active && access.manual_access_until ? new Date(access.manual_access_until) : null;
        const manual = $('profile-manual-access');
        manual.hidden = !until || !Number.isFinite(until.getTime());
        manual.textContent = manual.hidden ? '' : 'Ранее выданный ручной доступ к поиску: до ' + until.toLocaleDateString('ru-RU') + '. Требование подписки сейчас отключено.';
      } catch (error) {
        if (ticket !== epoch) return;
        if (error.status === 401) signedOut('Сессия завершилась. Войдите снова.');
        else if (dialog.hasAttribute('open')) message('profile-message', 'Не удалось загрузить профиль. Закройте и откройте окно, чтобы повторить.', true);
      } finally {
        if (ticket === epoch) { pending = null; setControls(); }
      }
    })();
    return pending;
  }
  for (const button of document.querySelectorAll('[data-profile-open]')) {
    button.onclick = () => {
      closeMenu(); view(button.dataset.profileOpen);
      populate(); openDialog('profile-dialog');
      if (!loaded) loadProfile();
    };
  }
  for (const button of document.querySelectorAll('[data-profile-view]')) button.onclick = () => view(button.dataset.profileView);
  $('profile-close').onclick = () => { closeDialog('profile-dialog'); toggle.focus(); };
  dialog.addEventListener('close', () => {
    if (!busy) populate();
    if (!shell.hidden && (document.activeElement === document.body || dialog.contains(document.activeElement))) toggle.focus();
  });
  form.addEventListener('input', preview);
  form.addEventListener('change', preview);
  form.onsubmit = async event => {
    event.preventDefault(); if (busy || photoBusy || !loaded) return;
    const ticket = epoch;
    const payload = {display_name:$('profile-display-name').value, avatar_theme:form.elements['avatar-theme'].value};
    busy = true; setControls(); message('profile-message', '');
    try {
      const data = await api('profile', {method:'PUT',body:JSON.stringify(payload)});
      if (ticket !== epoch) return;
      saved = {...saved,display_name:data.display_name,avatar_theme:data.avatar_theme};
      renderHeader(); populate(); message('profile-message', 'Изменения сохранены.');
    } catch (error) {
      if (ticket !== epoch) return;
      if (error.status === 401) signedOut('Сессия завершилась. Войдите снова.');
      else message('profile-message', error.message, true);
    } finally { if (ticket === epoch) { busy = false; setControls(); } }
  };
  for (const button of document.querySelectorAll('[data-profile-section]')) button.onclick = () => {
    closeDialog('profile-dialog'); openAccountTab(button.dataset.profileSection, true);
    document.getElementById('account-panel-' + button.dataset.profileSection).scrollIntoView({block:'start'});
  };
  function signedIn(address) {
    epoch++; pending = null; loaded = false; email = address;
    saved = {display_name:'',avatar_theme:'sky',avatar_url:null};
    shell.hidden = false; message('profile-photo-message',''); renderHeader(); populate(); loadProfile();
  }
  document.addEventListener('account-ready', event => signedIn(event.detail.email));
  document.addEventListener('account-signed-out', () => {
    epoch++; closeMenu(); closeDialog('profile-dialog'); shell.hidden = true;
    email = ''; saved = {display_name:'',avatar_theme:'sky',avatar_url:null}; pending = null; loaded = false; busy = false; photoBusy = false;
    renderHeader(); populate(); $('profile-photo-file').value = ''; $('profile-manual-access').textContent = ''; message('profile-message',''); message('profile-photo-message',''); setControls();
  });
  if (!$('dashboard').hidden && userEmail) signedIn(userEmail);
})();
