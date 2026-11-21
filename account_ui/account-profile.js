'use strict';
(() => {
  const themes = ['sky', 'violet', 'mint', 'rose', 'amber', 'slate'];
  const shell = $('profile-shell'), toggle = $('profile-toggle'), menu = $('profile-menu');
  const dialog = $('profile-dialog'), form = $('profile-form'), save = $('profile-save');
  let saved = {display_name:'', avatar_theme:'sky'}, epoch = 0, loaded = false, pending = null;
  let email = '', busy = false;

  function initials(name) {
    const words = name.trim().split(/\s+/).filter(Boolean);
    const value = words.length > 1 ? Array.from(words[0])[0] + Array.from(words[1])[0]
      : Array.from(words[0] || email.split('@')[0] || 'P').slice(0, 2).join('');
    return value.toLocaleUpperCase('ru');
  }
  function avatar(element, name, theme, base) {
    element.className = base + ' avatar-' + (themes.includes(theme) ? theme : 'sky');
    element.textContent = initials(name);
  }
  function renderHeader() {
    const name = saved.display_name || 'Мой аккаунт';
    // Keep the button's decorative status dot while replacing only its initials.
    toggle.className = 'avatar-button avatar-' + saved.avatar_theme;
    $('profile-initials').textContent = initials(saved.display_name);
    toggle.setAttribute('aria-label', 'Открыть профиль: ' + name);
    $('profile-menu-name').textContent = name;
    $('profile-menu-email').textContent = email;
    $('profile-summary-name').textContent = name;
    $('profile-summary-email').textContent = email;
  }
  function preview() {
    const theme = form.elements['avatar-theme'].value || 'sky';
    avatar($('profile-avatar-preview'), $('profile-display-name').value, theme, 'profile-avatar');
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
    save.disabled = true;
    $('profile-display-name').disabled = true;
    form.querySelectorAll('input[type=radio]').forEach(input => input.disabled = true);
    pending = (async () => {
      try {
        const data = await api('profile');
        if (ticket !== epoch) return;
        saved = {display_name:data.display_name || '', avatar_theme:themes.includes(data.avatar_theme) ? data.avatar_theme : 'sky'};
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
        if (ticket === epoch) { pending = null; save.disabled = !loaded; $('profile-display-name').disabled = !loaded; form.querySelectorAll('input[type=radio]').forEach(input => input.disabled = !loaded); }
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
    event.preventDefault(); if (busy || !loaded) return;
    const ticket = epoch;
    const payload = {display_name:$('profile-display-name').value, avatar_theme:form.elements['avatar-theme'].value};
    busy = true; save.disabled = true; message('profile-message', '');
    try {
      const data = await api('profile', {method:'PUT',body:JSON.stringify(payload)});
      if (ticket !== epoch) return;
      saved = {display_name:data.display_name,avatar_theme:data.avatar_theme};
      renderHeader(); populate(); message('profile-message', 'Изменения сохранены.');
    } catch (error) {
      if (ticket !== epoch) return;
      if (error.status === 401) signedOut('Сессия завершилась. Войдите снова.');
      else message('profile-message', error.message, true);
    } finally { if (ticket === epoch) { busy = false; save.disabled = false; } }
  };
  for (const button of document.querySelectorAll('[data-profile-section]')) button.onclick = () => {
    closeDialog('profile-dialog'); openAccountTab(button.dataset.profileSection, true);
    document.getElementById('account-panel-' + button.dataset.profileSection).scrollIntoView({block:'start'});
  };
  function signedIn(address) {
    epoch++; pending = null; loaded = false; email = address;
    saved = {display_name:'',avatar_theme:'sky'};
    shell.hidden = false; renderHeader(); populate(); loadProfile();
  }
  document.addEventListener('account-ready', event => signedIn(event.detail.email));
  document.addEventListener('account-signed-out', () => {
    epoch++; closeMenu(); closeDialog('profile-dialog'); shell.hidden = true;
    email = ''; saved = {display_name:'',avatar_theme:'sky'}; pending = null; loaded = false; busy = false;
    renderHeader(); populate(); $('profile-manual-access').textContent = ''; message('profile-message','');
  });
  if (!$('dashboard').hidden && userEmail) signedIn(userEmail);
})();
