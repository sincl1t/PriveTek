/* PriveTek landing form: native POST; no contacts in URLs or JS storage. */
'use strict';
(function(){
 function mount(){
  const original=document.getElementById('form2008423781');
  if(!original || original.dataset.privetekHandoff==='yes')return;
  const emailTemplate=original.elements.namedItem('Email');
  if(!emailTemplate)return;
  const textColor=getComputedStyle(emailTemplate).color;
  const form=original.cloneNode(true);
  form.classList.remove('js-form-proccess');
  for(const attr of Array.from(form.attributes))if(attr.name.startsWith('data-'))form.removeAttribute(attr.name);
  form.dataset.privetekHandoff='yes';form.action='https://lk.privetek.ru/account/start';form.method='post';form.target='_self';form.enctype='application/x-www-form-urlencoded';
  for(const input of Array.from(form.querySelectorAll('input[type="hidden"],input[name="form-spec-comments"]')))input.remove();
  const savedPhone=original.elements.namedItem('Phone');
  const visiblePhone=form.querySelector('input[type="tel"]');
  if(visiblePhone){
   const block=visiblePhone.closest('.t-input-block');
   if(!block)return;
   const phone=document.createElement('input');phone.style.cssText=emailTemplate.style.cssText;phone.style.color=textColor;phone.type='tel';phone.name='Phone';phone.className='t-input t-input_bbonly';phone.placeholder='+7 912 345-67-89';phone.maxLength=40;phone.autocomplete='tel';phone.value=(savedPhone && savedPhone.value)||visiblePhone.value||'';phone.setAttribute('aria-label','Телефон · необязательно');
   block.textContent='';block.append(phone);
  }
  const limits={Name:120,Email:254,Phone:40,Username:65};
  for(const [name,limit] of Object.entries(limits)){
   const input=form.elements.namedItem(name);if(!input)return;
   input.maxLength=limit;input.required=name==='Email';input.classList.remove('js-tilda-rule');
   input.setAttribute('aria-label',{Name:'Имя · необязательно',Email:'Ваш email',Phone:'Телефон · необязательно',Username:'Username · необязательно'}[name]);
   if(name==='Username'){input.autocapitalize='none';input.spellcheck=false;}
  }
  const button=form.querySelector('button[type="submit"]');if(!button)return;
  button.textContent='Продолжить →';
  button.style.color='#16124f';button.style.backgroundColor='#8bf8f4';button.style.border='1px solid #8bf8f4';button.style.borderRadius='999px';button.style.whiteSpace='normal';button.style.maxWidth='100%';
  const note=document.createElement('p');note.className='t-text t-text_xs';note.id='privetek-handoff-note';note.textContent='Для получения отчёта потребуется подтвердить email и создать аккаунт или войти. Данные сохранятся на один час. Поиск начнётся после вашего подтверждения в ЛК.';note.style.margin='18px 0';note.style.color=textColor;note.style.fontSize='14px';note.style.lineHeight='1.6';note.setAttribute('role','note');button.parentNode.insertBefore(note,button);
  const alternative=document.createElement('a');alternative.href='https://lk.privetek.ru/account/start';alternative.textContent='Открыть форму отдельно';alternative.className='t-text t-text_xs';alternative.style.color=textColor;alternative.style.textDecoration='underline';alternative.style.display='block';alternative.style.marginTop='18px';form.append(alternative);
  window.addEventListener('submit',event=>{
   if(event.target!==form)return;
   event.preventDefault();event.stopImmediatePropagation();
   if(form.reportValidity())HTMLFormElement.prototype.submit.call(form);
  },true);
  original.replaceWith(form);
  const record=document.getElementById('rec2008423781');
  const title=record && record.querySelector('[field="title"]');if(title){title.textContent='Начните проверку своих данных';title.style.color=textColor;}
  const bottom=record && record.querySelector('[field="text2"]');
  if(bottom){
   bottom.style.color=textColor;
   bottom.textContent='Сейчас мы сохраним заявку для продолжения в ЛК. Согласие на поиск и передачу данных источникам вы дадите перед запуском. Подтверждение email не подтверждает владение телефоном или профилями. ';
   const privacy=document.createElement('a');privacy.href='https://privetek.ru/page137765066.html';privacy.textContent='Политика конфиденциальности';privacy.style.color=textColor;privacy.style.textDecoration='underline';bottom.append(privacy);
  }
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount);else mount();
})();
