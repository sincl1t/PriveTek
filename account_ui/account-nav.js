'use strict';
const accountTabs = Array.from(document.querySelectorAll('[data-account-tab]'));

function openAccountTab(name, focus = false) {
  const active = accountTabs.find(tab => tab.dataset.accountTab === name) || accountTabs[0];
  for (const tab of accountTabs) {
    const selected = tab === active;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    document.getElementById(tab.getAttribute('aria-controls')).hidden = !selected;
  }
  const hash = '#section-' + active.dataset.accountTab;
  if (location.hash !== hash) history.replaceState(null, '', location.pathname + location.search + hash);
  if (focus) {
    active.focus();
    active.scrollIntoView({block: 'nearest', inline: 'nearest'});
  }
}

function accountTabFromHash() {
  openAccountTab(location.hash.replace(/^#section-/, ''));
}
for (const tab of accountTabs) {
  tab.onclick = () => openAccountTab(tab.dataset.accountTab);
  tab.onkeydown = event => {
    const index = accountTabs.indexOf(tab);
    let target;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') target = accountTabs[(index + 1) % accountTabs.length];
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') target = accountTabs[(index + accountTabs.length - 1) % accountTabs.length];
    else if (event.key === 'Home') target = accountTabs[0];
    else if (event.key === 'End') target = accountTabs[accountTabs.length - 1];
    if (!target) return;
    event.preventDefault();
    openAccountTab(target.dataset.accountTab, true);
  };
}
window.addEventListener('hashchange', accountTabFromHash);
document.addEventListener('account-signed-out', () => openAccountTab('chat'));
accountTabFromHash();

// Keep assistive navigation aligned with the responsive layout.
const compactAccountNav = window.matchMedia('(max-width: 900px)');
function updateAccountOrientation() {
  document.querySelector('.account-tabs').setAttribute('aria-orientation', compactAccountNav.matches ? 'horizontal' : 'vertical');
}
if (compactAccountNav.addEventListener) compactAccountNav.addEventListener('change', updateAccountOrientation);
else compactAccountNav.addListener(updateAccountOrientation);
updateAccountOrientation();
