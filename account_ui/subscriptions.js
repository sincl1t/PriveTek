'use strict';
(() => {
 const el=id=>document.getElementById('subs-'+id),core=window.SubscriptionCore;
 const periods={weekly:'раз в неделю',monthly:'раз в месяц',quarterly:'раз в квартал',yearly:'раз в год'};
 const statuses={review:'Нужно проверить',active:'Подтверждаю: активна',cancelled:'Отменена',not_subscription:'Это не подписка'};
 let saved=[],draft=[],revision=0,ticket=0,ready=false,dirty=false,busy=false;
 function note(text){el('message').textContent=text;}
 function node(tag,text){const n=document.createElement(tag);n.textContent=text;return n;}
 function id(){return crypto.randomUUID().replace(/-/g,'');}
 function payload(row){return Object.fromEntries(['id','merchant','amount','currency','period','last_date','status'].map(k=>[k,row[k]]));}
 function currency(value,code){return new Intl.NumberFormat('ru',{style:'currency',currency:code}).format(value);}
 function options(values,value,handler,label){const select=document.createElement('select');select.setAttribute('aria-label',label);select.disabled=busy;for(const [key,text] of Object.entries(values)){const option=node('option',text);option.value=key;select.append(option);}select.value=value;select.onchange=()=>handler(select.value);return select;}
 function render(){
  for(const control of document.querySelectorAll('#account-panel-subscriptions input, #account-panel-subscriptions select, #account-panel-subscriptions button'))control.disabled=busy;
  el('list').textContent='';el('candidates').textContent='';el('save').disabled=busy||!ready||!dirty;el('empty').hidden=saved.length>0;
  for(const [source,rows] of [['list',saved],['candidates',draft]])for(const row of rows){
   const card=document.createElement('article');card.className='subscription-item';card.append(node('h3',row.merchant),node('p',`${currency(row.amount,row.currency)} · ${periods[row.period]}`));
   if(row.evidence)card.append(node('p',row.evidence));
   const next=core.nextDate(row),today=new Date().toISOString().slice(0,10);
   card.append(node('p',`Последний платёж: ${row.last_date}. Следующий по расчёту: ${next}.`));
   if(row.status==='active'&&next<=today)card.append(node('p','Расчётная дата уже наступила. Проверьте списание и актуальность подписки.'));
   card.append(options(statuses,row.status,value=>{row.status=value;if(source==='list')dirty=true;render();},`Статус: ${row.merchant}`));
   const button=node('button',source==='list'?'Убрать из списка':'Добавить в мой список');button.type='button';button.disabled=busy;button.className='button secondary';
   button.onclick=()=>{if(source==='list'){saved=saved.filter(x=>x.id!==row.id);}else{if(saved.length>=100){note('Можно сохранить до 100 подписок');return;}if(saved.some(x=>x.merchant.toLowerCase()===row.merchant.toLowerCase()&&x.currency===row.currency)){note('Этот сервис уже есть в списке. При необходимости удалите старую запись.');return;}saved.push({...row});draft=draft.filter(x=>x.id!==row.id);}dirty=true;render();note('Изменения пока не сохранены в аккаунте. Нажмите «Сохранить список».');};card.append(button);el(source).append(card);
  }
  const totals=core.totals(saved);el('totals').textContent=Object.entries(totals).length?'По вашим отметкам, примерно в месяц: '+Object.entries(totals).map(([code,value])=>currency(value,code)).join(' + ')+'. Валюты не конвертируем.':'Отметьте активные подписки, чтобы оценить расходы в месяц.';
 }
 async function load(){const current=++ticket;ready=false;busy=true;render();try{const data=await api('subscriptions');if(current!==ticket)return;saved=data.items;revision=data.revision;dirty=false;ready=true;busy=false;render();note('Сохранённый список загружен.');}catch(e){if(current===ticket){busy=false;render();note(e.message);}}}
 document.addEventListener('account-ready',()=>{saved=[];draft=[];dirty=false;load();});
 document.addEventListener('account-signed-out',()=>{ticket++;saved=[];draft=[];ready=false;busy=false;dirty=false;revision=0;el('import').reset();el('manual').reset();el('stats').textContent='';note('');render();});
 el('reload').onclick=()=>{if(dirty&&!confirm('Загрузить сохранённый список и потерять несохранённые изменения?'))return;draft=[];load();};
 el('save').onclick=async()=>{const current=ticket;busy=true;render();try{const data=await api('subscriptions',{method:'PUT',body:JSON.stringify({revision,items:saved.map(payload)})});if(current!==ticket)return;saved=data.items;revision=data.revision;dirty=false;note('Список сохранён в аккаунте. Исходная выписка не отправлялась.');}catch(e){if(current===ticket)note(e.message);}finally{if(current===ticket){busy=false;render();}}};
 el('import').onsubmit=async event=>{event.preventDefault();if(!ready){note('Сначала загрузите сохранённый список');return;}const current=ticket;const file=el('file').files[0];if(!file)return;if(file.size>2*1024*1024){note('Размер CSV — до 2 МБ');return;}el('analyze').disabled=true;try{const text=new TextDecoder(el('encoding').value,{fatal:true}).decode(await file.arrayBuffer());if(current!==ticket)return;const result=core.analyze(text,{sign:el('sign').value,currency:el('currency').value});draft=result.items.slice(0,100).map(x=>({...x,id:id()}));el('stats').textContent=`Прочитано строк: ${result.stats.rows}. Пропущено некорректных: ${result.stats.invalid}, операций другого знака: ${result.stats.incoming}, точных дублей: ${result.stats.duplicates}. Предполагаемых подписок: ${result.items.length}. Показываем до 100 кандидатов.`;el('file').value='';render();note(draft.length?'Проверьте кандидатов и добавьте нужные в список.':'Регулярных платежей не обнаружено. Проверьте знак сумм, валюту и период выписки. Это не означает отсутствие подписок.');}catch(e){if(current===ticket)note(e.message);}finally{el('analyze').disabled=false;}};
 el('manual').onsubmit=event=>{event.preventDefault();if(!ready)return;if(saved.length>=100){note('Можно сохранить до 100 подписок');return;}saved.push({id:id(),merchant:el('merchant').value.trim(),amount:Number(el('amount').value).toFixed(2),currency:el('manual-currency').value,period:el('period').value,last_date:el('date').value,status:'review'});dirty=true;el('manual').reset();render();note('Запись добавлена. Подтвердите статус и сохраните список.');};
 el('clear').onclick=()=>{if(!ready)return;if(!confirm('Очистить список? Для удаления сохранённых записей затем нажмите «Сохранить список».'))return;saved=[];draft=[];dirty=true;render();note('Список очищен локально. Сохраните, чтобы удалить сведения из аккаунта.');};
 el('template').onclick=()=>{const text='date;merchant;amount;currency\n2026-08-10;Demo Service;-499.00;RUB\n2026-09-10;Demo Service;-499.00;RUB\n2026-10-10;Demo Service;-499.00;RUB\n';const url=URL.createObjectURL(new Blob(['\uFEFF'+text],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='subscription-template.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
 render();
})();
