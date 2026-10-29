'use strict';
const $ = id => document.getElementById(id);
let mfaChallenge = '';
let mode = 'login', challenge = '', csrf = '', userEmail = '', offset = 0, loading = false, authBusy = false;
const statusLabels = {accepted:'В очереди', searching:'Проверяем источники', generating_report:'Готовим отчёт', sending:'Отправляем письмо', provider_accepted:'Письмо принято сервисом', failed:'Проверка не завершена', delivery_unknown:'Доставка требует проверки'};
const activeStatuses = new Set(['accepted','searching','generating_report','sending']);
let hasActive = false, generation = 0;
function message(id, text, error = false) { const el = $(id); el.textContent = text; el.classList.toggle('error',error); el.hidden = !text; }
async function api(path, options = {}) {
  const response = await fetch('/api/account/' + path, {credentials:'same-origin', cache:'no-store', ...options, headers:{'Content-Type':'application/json', ...(csrf ? {'X-CSRF-Token':csrf} : {}), ...options.headers}});
  let data = {}; try { data = await response.json(); } catch (_) {}
  if (!response.ok) { const error = new Error(typeof data.detail === 'string' ? data.detail : 'Не удалось выполнить действие. Попробуйте позже.'); error.status = response.status; throw error; }
  return data;
}
function switchMode(next, notice = '') {
  mode = next; message('auth-message',notice); $('auth-tabs').hidden = !['login','register'].includes(mode);
  $('login-tab').classList.toggle('active',mode==='login'); $('login-tab').setAttribute('aria-selected',String(mode==='login'));
  $('register-tab').classList.toggle('active',mode==='register'); $('register-tab').setAttribute('aria-selected',String(mode==='register'));
  const config = {login:['С возвращением','Войдите, чтобы открыть ваши проверки.','Войти в кабинет →'],register:['Начните с себя','Создайте кабинет для ваших проверок.','Создать кабинет →'],verify:['Подтвердите email','Введите код из письма. Он действует 10 минут.','Подтвердить email →'],forgot:['Восстановить доступ','Укажите email, использованный при регистрации.','Получить код →'],mfa:['Подтвердите вход','Введите код приложения или одноразовый резервный код.','Подтвердить вход →'],reset:['Новый пароль','Введите код из письма и придумайте новый пароль.','Сохранить пароль →']}[mode];
  $('auth-title').textContent = config[0]; $('auth-caption').textContent = config[1]; $('auth-submit').textContent = config[2];
  $('email-field').hidden = ['verify','reset','mfa'].includes(mode); $('email').required = !['verify','reset','mfa'].includes(mode);
  $('password-field').hidden = ['verify','forgot','mfa'].includes(mode); $('password').required = !['verify','forgot','mfa'].includes(mode);
  $('password').minLength = ['register','reset'].includes(mode) ? 15 : 1; $('password').autocomplete = ['register','reset'].includes(mode) ? 'new-password' : 'current-password';
  $('password-hint').hidden = !['register','reset'].includes(mode); $('password').value = ''; $('password').type = 'password'; $('show-password').textContent = 'Показать'; $('show-password').setAttribute('aria-label','Показать пароль');
  $('code-field').hidden = !['verify','reset'].includes(mode); $('code').required = ['verify','reset'].includes(mode); $('code').value = '';
  $('login-mfa-field').hidden = mode !== 'mfa'; $('login-mfa-code').required = mode === 'mfa'; $('login-mfa-code').value = '';
  if (mode !== 'mfa') mfaChallenge = '';
  $('forgot').hidden = mode !== 'login'; $('back-login').hidden = ['login','register'].includes(mode);
  $('auth-note').textContent = mode === 'mfa' ? 'Потеряли телефон? Используйте один из сохранённых резервных кодов. Сброс пароля не отключает 2FA.' : ['verify','reset'].includes(mode) ? 'Не пришло письмо? Проверьте «Спам». Для нового кода вернитесь и повторите запрос.' : 'При регистрации нужно подтвердить email кодом из письма.';
}
$('login-tab').onclick = () => { if (!authBusy) switchMode('login'); };
$('register-tab').onclick = () => { if (!authBusy) switchMode('register'); };
$('forgot').onclick = () => { if (!authBusy) switchMode('forgot'); };
$('back-login').onclick = () => { if (!authBusy) switchMode('login'); };
$('show-password').onclick = () => { const hidden = $('password').type === 'password'; $('password').type = hidden ? 'text' : 'password'; $('show-password').textContent = hidden ? 'Скрыть' : 'Показать'; $('show-password').setAttribute('aria-label',hidden ? 'Скрыть пароль' : 'Показать пароль'); };
$('auth-form').onsubmit = async event => {
  event.preventDefault(); if (authBusy) return; authBusy = true; $('auth-submit').disabled = true; message('auth-message','');
  const current = mode;
  try {
    const path = {login:'login',register:'register',verify:'verify',forgot:'forgot-password',reset:'reset-password',mfa:'mfa-verify'}[current];
    const payload = ['verify','reset'].includes(current) ? {challenge_id:challenge,code:$('code').value} : {email:$('email').value};
    if (current === 'mfa') { payload.challenge_id = mfaChallenge; payload.code = $('login-mfa-code').value.trim(); delete payload.email; }
    if (['login','register','reset'].includes(current)) payload.password = $('password').value;
    const data = await api('auth/' + path,{method:'POST',body:JSON.stringify(payload)});
    if (current === 'login' && data.mfa_required) { switchMode('mfa'); mfaChallenge = data.challenge_id; $('login-mfa-code').focus(); }
    else if (current==='login' || current==='mfa') { $('password').value=''; $('login-mfa-code').value=''; mfaChallenge=''; await openDashboard(); }
    else if (current==='register' || current==='forgot') { challenge=data.challenge_id; switchMode(current==='register'?'verify':'reset',data.message); $('code').focus(); }
    else { challenge=''; switchMode('login',data.message); $('password').focus(); }
  } catch (error) { message('auth-message',error.message,true); }
  finally { authBusy=false; $('auth-submit').disabled=false; }
};
function signedOut(notice='') { clearMonitor(); closeIdentity(); clearMfaSecrets(); generation++; loading=false; challenge=''; csrf=''; userEmail=''; $('check-form').reset(); $('check-email').value=''; $('dashboard').hidden=true; $('auth-view').hidden=false; $('logout').hidden=true; $('jobs-list').replaceChildren(); $('check-dialog').close(); switchMode('login',notice); }
async function openDashboard() {
  const ticket=++generation; let user;
  try { user = await api('me'); } catch(error) { if(ticket!==generation)return; throw error; }
  if(ticket!==generation)return; loading=false; csrf=user.csrf_token; userEmail=user.email;
  $('account-email').textContent=userEmail; $('check-email').value=userEmail; $('auth-view').hidden=true; $('dashboard').hidden=false; $('logout').hidden=false; offset=0; await Promise.all([loadJobs(true), loadSecurity(), loadMonitor()]);
}
function textEl(tag, cls, text) { const el=document.createElement(tag); el.className=cls; el.textContent=text; return el; }
function renderJob(job) {
  if (!/^[0-9a-f]{32}$/.test(job.id)) return null;
  const row=textEl('article','job',''); row.dataset.id=job.id;
  row.append(textEl('div','job-icon','PDF'));
  const details=textEl('div','',''); const stamp=new Date(job.created_at); const date=Number.isNaN(stamp.getTime()) ? 'Дата не указана' : new Intl.DateTimeFormat('ru-RU',{day:'numeric',month:'long',year:'numeric',hour:'2-digit',minute:'2-digit'}).format(stamp);
  details.append(textEl('h3','', 'Проверка цифрового следа'));
  const meta=textEl('div','job-meta',''); meta.append(textEl('span','',date)); const pending=activeStatuses.has(job.status); hasActive ||= pending;
  meta.append(textEl('span','badge'+(pending?' pending':['failed','delivery_unknown'].includes(job.status)?' failed':''),statusLabels[job.status]||'Статус уточняется')); details.append(meta); row.append(details);
  const actions=textEl('div','job-actions','');
  if (job.report_available) {
    const link=textEl('a','button secondary','Скачать PDF ↓'); link.href='/api/account/jobs/'+job.id+'/report'; link.setAttribute('download','PriveTek-report.pdf'); actions.append(link);
    const remove=textEl('button','text-button','Удалить'); remove.type='button'; remove.onclick=async()=>{ if(!confirm('Удалить сохранённую копию отчёта из кабинета? Письмо с отчётом останется у вас.')) return; remove.disabled=true; try {await api('jobs/'+job.id+'/report',{method:'DELETE'}); await loadJobs(true);} catch(error){handleDashboardError(error); remove.disabled=false;} }; actions.append(remove);
  } else actions.append(textEl('span','report-unavailable',pending?'Отчёт готовится':'PDF недоступен'));
  if(job.identity_available) { const review=textEl('button','button secondary','Связи и принадлежность'); review.type='button'; review.onclick=()=>openIdentity(job.id); actions.append(review); }
  row.append(actions); return row;
}
function handleDashboardError(error) { if(error.status===401) signedOut('Сессия завершилась. Войдите снова.'); else message('dashboard-message',error.message,true); }
async function loadJobs(reset=false) {
  if(loading) return; const ticket=generation; loading=true; $('refresh').disabled=true; $('load-more').disabled=true; message('dashboard-message','');
  try {
    const nextOffset=reset?0:offset; const data=await api('jobs?offset='+nextOffset);
    if(ticket!==generation)return;
    if(reset){$('jobs-list').replaceChildren(); hasActive=false;}
    data.items.forEach(job=>{if(!/^[0-9a-f]{32}$/.test(job.id))return; if(!$('jobs-list').querySelector('[data-id="'+job.id+'"]')){const row=renderJob(job); if(row) $('jobs-list').append(row);}});
    offset=nextOffset+data.items.length; $('empty').hidden=offset>0; $('load-more').hidden=!data.has_more;
  }catch(error){if(ticket===generation)handleDashboardError(error);}finally{if(ticket===generation){loading=false; $('refresh').disabled=false; $('load-more').disabled=false;}}
}
$('refresh').onclick=()=>loadJobs(true); $('load-more').onclick=()=>loadJobs(false);
$('logout').onclick=async()=>{ $('logout').disabled=true; try{await api('auth/logout',{method:'POST',body:'{}'}); signedOut('Вы вышли из кабинета.');}catch(error){handleDashboardError(error);}finally{$('logout').disabled=false;} };
function openCheck(){message('check-message',''); $('check-dialog').showModal();}
$('new-check').onclick=openCheck; $('empty-check').onclick=openCheck; $('close-check').onclick=()=>$('check-dialog').close();
$('check-form').onsubmit=async event=>{
  event.preventDefault(); $('check-submit').disabled=true; message('check-message','');
  try{const data=await api('jobs',{method:'POST',body:JSON.stringify({username:$('username').value,phone:$('phone').value,consent:$('consent').checked})}); $('check-dialog').close(); $('check-form').reset(); $('check-email').value=userEmail; await loadJobs(true); message('dashboard-message',data.duplicate?'Эта проверка уже есть в истории.':'Проверка запущена. Статус обновится автоматически.');}
  catch(error){if(error.status===401)signedOut('Сессия завершилась. Войдите снова.');else message('check-message',error.message,true);}finally{$('check-submit').disabled=false;}
};
setInterval(()=>{if(!$('dashboard').hidden && !document.hidden && hasActive && offset<=20)loadJobs(true);},15000);
let securityBusy = false, securityGeneration = 0;
function clearMfaSecrets() {
  securityGeneration++;
  ['mfa-password','mfa-factor','mfa-confirm-code','mfa-secret'].forEach(id => $(id).value='');
  $('mfa-qr').removeAttribute('src'); $('mfa-enrollment').hidden=true;
  $('mfa-codes-text').textContent=''; $('mfa-recovery-codes').hidden=true;
}
function showRecovery(codes) {
  $('mfa-codes-text').textContent=codes.join('\n'); $('mfa-recovery-codes').hidden=!codes.length;
  if(codes.length) $('mfa-recovery-codes').scrollIntoView({block:'nearest'});
}
async function loadSecurity() {
  const ticket=generation;
  try {
    const data=await api('security'); if(ticket!==generation)return;
    $('mfa-status').textContent=data.enabled?'2FA включена':'2FA не подключена';
    $('mfa-status').className='badge'+(data.enabled?'':' pending');
    $('mfa-setup-button').hidden=data.enabled;
    $('mfa-recovery-button').hidden=!data.enabled; $('mfa-disable-button').hidden=!data.enabled;
    $('mfa-factor-field').hidden=!data.enabled; $('mfa-setup-button').disabled=false;
  } catch(error) {if(ticket===generation) message('mfa-message','Не удалось загрузить настройки защиты. Обновите страницу.',true);}
}
async function changeSecurity(name) {
  if(securityBusy)return; securityBusy=true; const ticket=generation;
  const secretTicket=++securityGeneration;
  $('mfa-form').querySelectorAll('button').forEach(b=>b.disabled=true);
  message('mfa-message','');
  try {
    const payload=name==='confirm'?{code:$('mfa-confirm-code').value.trim()}:{password:$('mfa-password').value,code:$('mfa-factor').value.trim()};
    const data=await api('security/'+name,{method:'POST',body:JSON.stringify(payload)});
    if(ticket!==generation || secretTicket!==securityGeneration)return;
    clearMfaSecrets();
    if(name==='setup') {
      $('mfa-qr').src=data.qr_data; $('mfa-secret').value=data.secret; $('mfa-enrollment').hidden=false;
      $('mfa-confirm-code').focus();
    } else {
      await loadSecurity(); if(ticket!==generation)return;
      showRecovery(data.recovery_codes||[]);
      message('mfa-message',name==='disable'?'2FA отключена. Другие сессии завершены.':name==='confirm'?'2FA подключена. Другие сессии завершены. Сохраните резервные коды.':'Прежние резервные коды отменены. Сохраните новые.');
    }
  } catch(error) {if(ticket===generation) message('mfa-message',error.message,true);}
  finally {securityBusy=false; $('mfa-form').querySelectorAll('button').forEach(b=>b.disabled=false); $('mfa-password').value=''; $('mfa-factor').value='';}
}
$('mfa-form').onsubmit=event=>event.preventDefault();
$('mfa-setup-button').onclick=()=>changeSecurity('setup');
$('mfa-recovery-button').onclick=()=>{if(confirm('Создать новые резервные коды? Все прежние коды перестанут работать.'))changeSecurity('recovery');};
$('mfa-disable-button').onclick=()=>{if(confirm('Отключить второй фактор для вашего аккаунта?'))changeSecurity('disable');};
$('mfa-confirm-form').onsubmit=event=>{event.preventDefault();changeSecurity('confirm');};
$('mfa-cancel').onclick=()=>clearMfaSecrets();
$('mfa-codes-saved').onclick=()=>{ $('mfa-codes-text').textContent=''; $('mfa-recovery-codes').hidden=true; };
window.addEventListener('beforeunload',event=>{if(!$('mfa-recovery-codes').hidden){event.preventDefault();event.returnValue='';}});
let identityJob='', identitySnapshot=null, identityBusy=false, identityGeneration=0;
function closeIdentity() {
  identityGeneration++; identityJob=''; identitySnapshot=null;
  $('identity-items').replaceChildren(); $('identity-summary').textContent='';
  $('identity-download').removeAttribute('href'); $('identity-dialog').close();
}
function renderIdentity() {
  const snapshot=identitySnapshot; if(!snapshot)return;
  $('identity-summary').textContent='Моё: '+snapshot.summary.mine+'. Не моё: '+snapshot.summary.not_mine+'. Не проверено: '+snapshot.summary.unreviewed+'.';
  $('identity-items').replaceChildren();
  const labels={}; snapshot.identifiers.forEach(item=>labels[item.id]=item.title);
  const groupOrder={mine:0,unreviewed:1,not_mine:2}; let lastGroup='';
  for(const item of [...snapshot.identifiers,...snapshot.findings].sort((a,b)=>groupOrder[a.decision]-groupOrder[b.decision])) {
    if(item.decision!==lastGroup){$('identity-items').append(textEl('h3','identity-group',{mine:'Моё — отмечено вами',unreviewed:'Требует вашей проверки',not_mine:'Не моё — исключено вами'}[item.decision]));lastGroup=item.decision;}
    const row=textEl('div','identity-item',''); const label=textEl('label','',item.title);
    const select=document.createElement('select'); select.id='identity-'+item.id; label.htmlFor=select.id;
    for(const [value,title] of [['unreviewed','Не уверен / не проверено'],['mine','Моё'],['not_mine','Не моё']]) {const option=document.createElement('option');option.value=value;option.textContent=title;select.append(option);}
    select.value=item.decision; select.disabled=identityBusy;
    select.onchange=()=>saveIdentity(item.id,select.value);
    row.append(label);
    if(item.identifier_id) row.append(textEl('p','small','Найдено по '+(labels[item.identifier_id]||'идентификатору')+'. '+(item.evidence==='indirect_signal'?'Косвенный признак регистрации.':'Совпадение источника не подтверждает владельца.')));
    if(item.profile_url) {const link=textEl('a','identity-profile','Открыть профиль ↗');link.href=item.profile_url;link.target='_blank';link.rel='noopener noreferrer';row.append(link);}
    row.append(select); $('identity-items').append(row);
  }
  if(snapshot.omitted) $('identity-items').append(textEl('p','small','Часть находок не включена из-за ограничения размера. Смотрите исходный PDF.'));
}
async function openIdentity(jobId) {
  closeIdentity(); identityJob=jobId; const ticket=identityGeneration;
  message('identity-message','Загружаем карточку…'); $('identity-dialog').showModal();
  try {const snapshot=await api('jobs/'+jobId+'/identity');if(ticket!==identityGeneration)return;
    identitySnapshot=snapshot; $('identity-download').href='/api/account/jobs/'+jobId+'/identity/report';renderIdentity();message('identity-message','');
  } catch(error) {if(ticket===identityGeneration){if(error.status===401)signedOut('Сессия завершилась. Войдите снова.');else message('identity-message',error.message,true);}}
}
async function saveIdentity(itemId,decision) {
  if(identityBusy||!identitySnapshot)return;identityBusy=true;const ticket=identityGeneration;
  $('identity-items').querySelectorAll('select').forEach(el=>el.disabled=true);message('identity-message','Сохраняем отметку…');
  try {const snapshot=await api('jobs/'+identityJob+'/identity',{method:'PUT',body:JSON.stringify({revision:identitySnapshot.revision,item_id:itemId,decision})});
    if(ticket!==identityGeneration)return;identitySnapshot=snapshot;message('identity-message','Отметка сохранена. Принадлежность указана вами.');
  } catch(error) {if(ticket===identityGeneration){if(error.status===401)signedOut('Сессия завершилась. Войдите снова.');else message('identity-message',error.message,true);}}
  finally {identityBusy=false;if(ticket===identityGeneration)renderIdentity();}
}
$('identity-close').onclick=closeIdentity;
$('identity-dialog').addEventListener('cancel',event=>{event.preventDefault();closeIdentity();});
let monitorBusy=false, monitorSettings=null, monitorHistory=[], monitorOffset=0, monitorAvailable=false;
const monitorLabels={completed:'Проверка выполнена',partial:'Часть источников недоступна',unavailable:'Проверка недоступна',running:'Проверяем',interrupted:'Проверка прервана',cancelled:'Отменена'};
const monitorMailLabels={none:'Письмо не требуется',pending:'Уведомление в очереди',sending:'Отправка начата',provider_accepted:'Провайдер принял письмо',delivery_unknown:'Статус отправки не подтверждён',cancelled:'Уведомление отменено'};
function monitorDate(value){if(!value)return 'ещё нет';const date=new Date(value);return Number.isNaN(date.getTime())?'неизвестно':new Intl.DateTimeFormat('ru-RU',{dateStyle:'short',timeStyle:'short'}).format(date);}
function clearMonitor(){monitorSettings=null;monitorHistory=[];monitorOffset=0; $('monitor-form').reset();$('monitor-history').replaceChildren();$('monitor-exclusions').replaceChildren();$('monitor-dates').textContent='';}
function renderMonitor(data){
  const settings=data.settings;monitorSettings=settings;monitorAvailable=data.available;
  $('monitor-status').textContent={off:'Выключен',active:'Включён · раз в неделю',paused:'На паузе'}[settings.state]||'Статус неизвестен';
  $('monitor-username').value=settings.username||'';$('monitor-use-reviews').checked=settings.use_profile_reviews!==false;
  $('monitor-enable').textContent=settings.state==='off'?'Включить мониторинг':'Сохранить и создать новый исходный снимок';
  $('monitor-enable').disabled=!data.available;
  $('monitor-pause').hidden=settings.state!=='active';$('monitor-resume').hidden=settings.state!=='paused';$('monitor-resume').disabled=!data.available;
  $('monitor-delete').hidden=settings.state==='off';
  $('monitor-dates').textContent='Последняя проверка: '+monitorDate(settings.last_checked_at)+'. Следующая: '+(settings.state==='active'?monitorDate(settings.next_run_at):'не назначена')+'. Пилот до '+monitorDate(settings.pilot_ends_at)+'.';
  $('monitor-exclusions').replaceChildren();
  if(settings.exclusions.length){$('monitor-exclusions').append(textEl('h3','','Исключения из уведомлений'));for(const item of settings.exclusions){const row=textEl('div','monitor-item',item.source+(item.breach_name?' · '+item.breach_name:''));const restore=textEl('button','text-button','Снова учитывать');restore.type='button';restore.onclick=()=>monitorReview(item.id,'restore');row.append(restore);$('monitor-exclusions').append(row);}}
  $('monitor-history').replaceChildren();
  if(!data.history.length){$('monitor-history').append(textEl('p','muted',settings.state==='off'?'Мониторинг включается только по вашему согласию.':'История появится после планового запуска.'));return;}
  $('monitor-history').append(textEl('h3','','История мониторинга'));
  for(const run of data.history){
    const row=textEl('article','monitor-run','');row.append(textEl('h4','',monitorDate(run.started_at)+' · '+(monitorLabels[run.state]||'Статус уточняется')));
    row.append(textEl('p','small','Новых находок для уведомления: '+run.new_count+'. '+(monitorMailLabels[run.mail_state]||'Статус письма уточняется')+'.'));
    const changes=run.changes;
    if(changes){
      if((changes.status_updates||[]).length)row.append(textEl('p','small','Обновлений статуса ранее известных находок: '+changes.status_updates.length+'. Они не считаются новыми находками.'));
      if(changes.baseline_only||changes.baseline_items.length)row.append(textEl('p','small','Создан исходный снимок для впервые проверенных источников. Эти находки не вызывают письмо.'));
      if(changes.unavailable.length)row.append(textEl('p','small','Недоступные или неопределённые источники: '+changes.unavailable.join(', ')+'. Предыдущие находки сохранены.'));
      const items=[...changes.items,...changes.baseline_items];
      if(items.length){const details=document.createElement('details');details.append(textEl('summary','','Находки и исходный снимок ('+items.length+')'));for(const item of items){
        const excluded=(settings.included||[]).includes(item.id)?false:settings.exclusions.some(ex=>ex.id===item.id)||item.excluded;
        const entry=textEl('div','monitor-item',item.source+' · '+({username:'публичный профиль',breach:'сведения об утечке',avatar:'публичный аватар',email:'возможная регистрация'}[item.kind]||'находка')+(item.breach_name?' · '+item.breach_name:''));
        if(item.profile_url){const link=textEl('a','identity-profile','Открыть профиль ↗');link.href=item.profile_url;link.target='_blank';link.rel='noopener noreferrer';entry.append(link);}
        const review=textEl('button','text-button',excluded?'Снова учитывать':'Не моё — не уведомлять');review.type='button';review.onclick=()=>monitorReview(item.id,excluded?'restore':'exclude');entry.append(review);details.append(entry);
      }row.append(details);}
    }$('monitor-history').append(row);
  }
}
async function loadMonitor(reset=true){const ticket=generation;try{const data=await api('monitor?offset='+(reset?0:monitorOffset));if(ticket!==generation)return;if(reset)monitorHistory=[];monitorHistory.push(...data.history);monitorOffset=monitorHistory.length;$('monitor-load-more').hidden=!data.has_more;renderMonitor({...data,history:monitorHistory});if(!data.available)message('monitor-message','Плановые запуски пока не подключены. Включение будет доступно после настройки.');}catch(error){if(ticket===generation)message('monitor-message',error.message,true);}}
async function monitorChange(action){
  if(monitorBusy)return;
  if(action==='enable'&&!$('monitor-consent').checked){message('monitor-message','Подтвердите согласие на мониторинг.',true);return;}
  if(action==='delete'&&!confirm('Выключить мониторинг и удалить его настройки, снимки и историю? Это не удалит обычные отчёты.'))return;
  monitorBusy=true;const ticket=generation;$('monitor-form').querySelectorAll('button').forEach(b=>b.disabled=true);
  try{await api('monitor',{method:'POST',body:JSON.stringify({action,username:$('monitor-username').value,use_profile_reviews:$('monitor-use-reviews').checked,consent:$('monitor-consent').checked})});if(ticket!==generation)return;$('monitor-consent').checked=false;await loadMonitor();message('monitor-message',action==='delete'?'Мониторинг выключен, его данные удалены.':action==='pause'?'Мониторинг на паузе.':'Настройки сохранены. Ожидаем плановый запуск.');}
  catch(error){if(ticket===generation){if(error.status===401)signedOut('Сессия завершилась. Войдите снова.');else message('monitor-message',error.message,true);}}
  finally{monitorBusy=false;$('monitor-form').querySelectorAll('button').forEach(b=>b.disabled=false);$('monitor-enable').disabled=!monitorAvailable;$('monitor-resume').disabled=!monitorAvailable;}
}
async function monitorReview(itemId,action){if(monitorBusy)return;monitorBusy=true;const ticket=generation;try{await api('monitor/exclusions',{method:'POST',body:JSON.stringify({item_id:itemId,action})});if(ticket===generation){await loadMonitor();message('monitor-message','Настройка уведомлений сохранена.');}}catch(error){if(ticket===generation)message('monitor-message',error.message,true);}finally{monitorBusy=false;}}
$('monitor-form').onsubmit=event=>{event.preventDefault();monitorChange('enable');};
$('monitor-pause').onclick=()=>monitorChange('pause');$('monitor-resume').onclick=()=>monitorChange('resume');$('monitor-delete').onclick=()=>monitorChange('delete');$('monitor-refresh').onclick=()=>loadMonitor();$('monitor-load-more').onclick=()=>loadMonitor(false);
openDashboard().catch(error=>{signedOut(); if(error.status!==401)message('auth-message',error.message,true);});
