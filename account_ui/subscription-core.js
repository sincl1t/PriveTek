/* Pure local statement analysis. Never opens a URL or sends transactions. */
(function(root) {
  'use strict';
  const currencies = ['RUB','USD','EUR','GBP','KZT','BYN','UAH'];
  const aliases = {date:['date','дата','дата операции','дата платежа'],amount:['amount','сумма','сумма операции','сумма платежа'],merchant:['merchant','description','описание','получатель','назначение платежа','наименование операции','сервис'],currency:['currency','валюта','валюта операции']};
  function csv(text) {
    if (text.length > 2*1024*1024) throw Error('Файл должен быть не больше 2 МБ');
    text=text.replace(/^\uFEFF/,'');
    const first=text.split(/\r?\n/)[0];
    const delimiter=[';',',','\t'].sort((a,b)=>first.split(b).length-first.split(a).length)[0];
    const rows=[];let row=[],field='',quoted=false,closed=false;
    for(let i=0;i<text.length;i++) {
      const c=text[i];
      if(quoted) {if(c==='"') {if(text[i+1]==='"'){field+='"';i++;}else {quoted=false;closed=true;}}else field+=c;}
      else if(c==='"'&&!field&&!closed) quoted=true;
      else if(c===delimiter||c==='\n'||c==='\r') {
        row.push(field);field='';closed=false;
        if(c!==delimiter){if(c==='\r'&&text[i+1]==='\n')i++;if(row.some(x=>x.trim()))rows.push(row);row=[];}
      } else {if(closed&&!/\s/.test(c))throw Error('Некорректные кавычки CSV');field+=c;}
      if(field.length>1000||row.length>50||rows.length>10000)throw Error('Слишком большой CSV: до 10 000 строк и 50 колонок');
    }
    if(quoted)throw Error('В CSV не закрыты кавычки');
    row.push(field);if(row.some(x=>x.trim()))rows.push(row);
    if(rows.length<2)throw Error('Нужны заголовки и хотя бы одна операция');
    const head=rows.shift().map(x=>x.trim().toLowerCase());const columns={};
    for(const [key,names] of Object.entries(aliases))columns[key]=head.findIndex(x=>names.includes(x));
    if(['date','amount','merchant'].some(k=>columns[k]<0))throw Error('Не найдены колонки. Используйте шаблон: date;merchant;amount;currency');
    return {rows,columns};
  }
  function parseDate(s) {
    let m=String(s||'').trim().match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if(!m){const d=String(s||'').trim().match(/^(\d{2})[./](\d{2})[./](\d{4})$/);if(d)m=[d[0],d[3],d[2],d[1]];}
    if(!m)return null;
    const date=new Date(Date.UTC(+m[1],+m[2]-1,+m[3]));
    return +m[1]>=2000&&+m[1]<=2100&&date.toISOString().slice(0,10)===`${m[1]}-${m[2]}-${m[3]}`?date:null;
  }
  const iso=d=>d.toISOString().slice(0,10);
  function addMonths(d,n) {const year=d.getUTCFullYear(),month=d.getUTCMonth()+n,day=d.getUTCDate();const end=new Date(Date.UTC(year,month+1,0)).getUTCDate();return new Date(Date.UTC(year,month,Math.min(day,end)));}
  function nextDate(row) {const d=parseDate(row.last_date);if(!d)return null;return iso(row.period==='weekly'?new Date(+d+7*86400000):addMonths(d,{monthly:1,quarterly:3,yearly:12}[row.period]));}
  function analyze(text,options={}) {
    const {rows,columns:c}=csv(text);const groups=new Map(),seen=new Set();let invalid=0,incoming=0,duplicates=0;
    for(const row of rows) {
      const d=parseDate(row[c.date]);let raw=(row[c.amount]||'').trim().replace(/[\s\u00a0]/g,'').replace(',','.');
      const amount=/^[+-]?\d+(\.\d{1,2})?$/.test(raw)?Number(raw):NaN;
      const name=(row[c.merchant]||'').trim().replace(/\s+/g,' ');
      let currency=(c.currency<0?(options.currency||''):row[c.currency]||'').trim().toUpperCase();if(currency==='RUR'||currency==='₽')currency='RUB';
      if(!d||!Number.isFinite(amount)||Math.abs(amount)>10000000||!amount||!name||name.length>100||/[\x00-\x1f\x7f]/.test(name)||!currencies.includes(currency)){invalid++;continue;}
      if(options.sign==='positive'?amount<0:amount>0){incoming++;continue;}
      const groupKey=name.toLocaleLowerCase('ru')+'|'+currency;
      const key=groupKey+'|'+iso(d)+'|'+amount;
      if(seen.has(key)){duplicates++;continue;}seen.add(key);
      if(!groups.has(groupKey))groups.set(groupKey,[]);
      groups.get(groupKey).push({date:d,amount:Math.abs(amount),merchant:name,currency});
    }
    const items=[];
    for(const txs of groups.values()) {
      txs.sort((a,b)=>a.date-b.date);if(txs.length<2)continue;
      const values=txs.map(x=>x.amount).sort((a,b)=>a-b),median=values[Math.floor(values.length/2)];
      if(values.some(x=>Math.abs(x-median)>median*.2))continue;
      let period=null;
      const gaps=txs.slice(1).map((x,i)=>(x.date-txs[i].date)/86400000);
      for(const [name,days,tolerance] of [['weekly',7,2],['monthly',30.44,6],['quarterly',91.31,10],['yearly',365.25,14]]) {
        if(gaps.every(x=>Math.abs(x-days)<=tolerance)){period=name;break;}
      }
      if(!period)continue;
      const last=txs[txs.length-1];items.push({merchant:last.merchant,amount:last.amount.toFixed(2),currency:last.currency,period,last_date:iso(last.date),status:'review',count:txs.length,evidence:`${txs.length} списания с ${iso(txs[0].date)} по ${iso(last.date)}; похожая сумма и периодичность. ${txs.length===2?'Только два наблюдения — проверьте вручную.':'Регулярность не подтверждает подписку.'}`});
    }
    return {items,stats:{rows:rows.length,invalid,incoming,duplicates}};
  }
  function totals(items){const out={};for(const x of items){if(x.status!=='active')continue;out[x.currency]=(out[x.currency]||0)+Number(x.amount)*({weekly:52/12,monthly:1,quarterly:1/3,yearly:1/12}[x.period]);}return out;}
  const api={analyze,parseDate,nextDate,totals};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.SubscriptionCore=api;
})(typeof window==='undefined'?globalThis:window);
