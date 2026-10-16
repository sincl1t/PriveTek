'use strict';
const $ = id => document.getElementById(id);
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
  const config = {login:['С возвращением','Войдите, чтобы открыть ваши проверки.','Войти в кабинет →'],register:['Начните с себя','Создайте кабинет для ваших проверок.','Создать кабинет →'],verify:['Подтвердите email','Введите код из письма. Он действует 10 минут.','Подтвердить email →'],forgot:['Восстановить доступ','Укажите email, использованный при регистрации.','Получить код →'],reset:['Новый пароль','Введите код из письма и придумайте новый пароль.','Сохранить пароль →']}[mode];
  $('auth-title').textContent = config[0]; $('auth-caption').textContent = config[1]; $('auth-submit').textContent = config[2];
  $('email-field').hidden = ['verify','reset'].includes(mode); $('email').required = !['verify','reset'].includes(mode);
  $('password-field').hidden = ['verify','forgot'].includes(mode); $('password').required = !['verify','forgot'].includes(mode);
  $('password').minLength = ['register','reset'].includes(mode) ? 15 : 1; $('password').autocomplete = ['register','reset'].includes(mode) ? 'new-password' : 'current-password';
  $('password-hint').hidden = !['register','reset'].includes(mode); $('password').value = ''; $('password').type = 'password'; $('show-password').textContent = 'Показать'; $('show-password').setAttribute('aria-label','Показать пароль');
  $('code-field').hidden = !['verify','reset'].includes(mode); $('code').required = ['verify','reset'].includes(mode); $('code').value = '';
  $('forgot').hidden = mode !== 'login'; $('back-login').hidden = ['login','register'].includes(mode);
  $('auth-note').textContent = ['verify','reset'].includes(mode) ? 'Не пришло письмо? Проверьте «Спам». Для нового кода вернитесь и повторите запрос.' : 'При регистрации нужно подтвердить email кодом из письма.';
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
    const path = {login:'login',register:'register',verify:'verify',forgot:'forgot-password',reset:'reset-password'}[current];
    const payload = ['verify','reset'].includes(current) ? {challenge_id:challenge,code:$('code').value} : {email:$('email').value};
    if (['login','register','reset'].includes(current)) payload.password = $('password').value;
    const data = await api('auth/' + path,{method:'POST',body:JSON.stringify(payload)});
    if (current==='login') { $('password').value=''; await openDashboard(); }
    else if (current==='register' || current==='forgot') { challenge=data.challenge_id; switchMode(current==='register'?'verify':'reset',data.message); $('code').focus(); }
    else { challenge=''; switchMode('login',data.message); $('password').focus(); }
  } catch (error) { message('auth-message',error.message,true); }
  finally { authBusy=false; $('auth-submit').disabled=false; }
};
function signedOut(notice='') { generation++; loading=false; challenge=''; csrf=''; userEmail=''; $('check-form').reset(); $('check-email').value=''; $('dashboard').hidden=true; $('auth-view').hidden=false; $('logout').hidden=true; $('jobs-list').replaceChildren(); $('check-dialog').close(); switchMode('login',notice); }
async function openDashboard() {
  const ticket=++generation; let user;
  try { user = await api('me'); } catch(error) { if(ticket!==generation)return; throw error; }
  if(ticket!==generation)return; loading=false; csrf=user.csrf_token; userEmail=user.email;
  $('account-email').textContent=userEmail; $('check-email').value=userEmail; $('auth-view').hidden=true; $('dashboard').hidden=false; $('logout').hidden=false; offset=0; await loadJobs(true);
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
openDashboard().catch(error=>{signedOut(); if(error.status!==401)message('auth-message',error.message,true);});
