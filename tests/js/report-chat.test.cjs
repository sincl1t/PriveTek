const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

class Element {
  constructor(tag='div', text='') { this.tag=tag; this.children=[]; this._text=text; this.hidden=false; this.value=''; }
  set textContent(value) { this._text=value; this.children=[]; }
  get textContent() { return this._text+this.children.map(child=>typeof child==='string'?child:child.textContent).join(' '); }
  append(...children) { this.children.push(...children); }
  focus() {}
}

async function runScenario(job) {
  const elements=new Map(), timers=[], calls=[];
  const $=id=> { if(!elements.has(id)) elements.set(id,new Element());return elements.get(id); };
  $('dashboard').hidden=false;
  const context={ $, userEmail:'owner@example.com', document:{addEventListener(){}},
    textEl:(tag,cls,text)=>new Element(tag,text), message(){},
    clearTimeout(){},setTimeout:callback=>{timers.push(callback);return timers.length;},
    loadJobs:async()=>{},signedOut:()=>{throw Error('Unexpected logout');},openAccountTab(){},openIdentity(){},
    api:async(endpoint,options)=>{
      calls.push(endpoint);
      if(endpoint==='jobs' && options.method==='POST')return {job_id:'a'.repeat(32)};
      if(endpoint.endsWith('/identity')){const error=new Error('Not ready');error.status=404;throw error;}
      if(endpoint.endsWith('/status'))return job;
      throw Error('Unexpected API '+endpoint);
    }
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../../account_ui/report-chat.js'),'utf8'),context);
  const click=text=>{const option=$('report-chat-options').children.find(child=>child.textContent===text);assert.ok(option,text);return option.onclick();};
  click('Подготовить проверку');
  $('report-chat-input').value='+12025550123';$('report-chat-form').onsubmit({preventDefault(){}});
  $('report-chat-input').value='control';$('report-chat-form').onsubmit({preventDefault(){}});
  await click('Согласен, проверить мои данные');
  return {elements,$,timers,calls,click};
}

(async()=>{
  let scenario=await runScenario({status:'failed',report_available:false});
  assert.equal(scenario.timers.length,0,'Terminal processing failures must not keep the user waiting');
  assert.match(scenario.$('report-chat-log').textContent,/Не удалось подготовить или сохранить отчёт/);
  assert.equal(scenario.calls.filter(call=>call==='jobs').length,1,'No automatic resubmission');
  assert.equal(scenario.$('report-chat-form').hidden,true);
  scenario.click('Подготовить новую проверку');
  assert.equal(scenario.calls.filter(call=>call==='jobs').length,1,'Preparing a retry does not order or send anything');

  scenario=await runScenario({status:'delivery_unknown',report_available:true});
  assert.equal(scenario.timers.length,0);
  assert.match(scenario.$('report-chat-log').textContent,/Результат отправки письма не подтверждён/);
  assert.match(scenario.$('report-chat-log').textContent,/Скачать сохранённый PDF/);
  const links=scenario.$('report-chat-log').children.flatMap(child=>child.children).filter(child=>child.tag==='a');
  assert.equal(links[0].href,'/api/account/jobs/'+'a'.repeat(32)+'/report');

  scenario=await runScenario({status:'provider_accepted',report_available:false});
  assert.equal(scenario.timers.length,0);
  assert.match(scenario.$('report-chat-log').textContent,/получение адресатом не подтверждено/);

  scenario=await runScenario({status:'searching',report_available:false});
  assert.equal(scenario.timers.length,1,'An active search should continue bounded polling');
  assert.doesNotMatch(scenario.$('report-chat-log').textContent,/Не удалось подготовить или сохранить отчёт/);
  console.log('Report chat terminal failures and safe retry checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
