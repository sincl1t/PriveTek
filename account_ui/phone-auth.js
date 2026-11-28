'use strict';
(() => {
 const $p=id=>document.getElementById('phone-'+id);let loginChallenge='',bindChallenge='',epoch=0,available=false;
 function note(id,text){$p(id).textContent=text;}
 async function capabilities(){try{const d=await api('auth/capabilities');available=d.sms_login===true;$p('login').hidden=!available;}catch(_){available=false;$p('login').hidden=true;}}
 async function load(){const ticket=++epoch;try{const d=await api('phone');if(ticket!==epoch)return;$p('manage').hidden=!d.available;note('status',d.linked?'Подключён номер '+d.masked_phone:'Номер для входа пока не подтверждён.');}catch(_){$p('manage').hidden=true;}}
 $p('login-start').onsubmit=async e=>{e.preventDefault();const b=$p('login-send');b.disabled=true;try{const d=await api('auth/sms-start',{method:'POST',body:JSON.stringify({phone:$p('login-number').value})});loginChallenge=d.challenge_id;$p('login-verify').hidden=false;note('login-note',d.message);}catch(error){note('login-note',error.message);}finally{b.disabled=false;}};
 $p('login-verify').onsubmit=async e=>{e.preventDefault();const b=$p('login-submit');b.disabled=true;try{const d=await api('auth/sms-verify',{method:'POST',body:JSON.stringify({challenge_id:loginChallenge,code:$p('login-code').value})});$p('login-code').value='';loginChallenge='';$p('login-verify').hidden=true;
 if(d.mfa_required){$p('login').open=false;switchMode('mfa');mfaChallenge=d.challenge_id;document.getElementById('login-mfa-hint').textContent=d.method==='email'?'Введите код из письма или резервный код.':'Введите код из приложения-аутентификатора или резервный код.';}
 else await openDashboard();
 }catch(error){note('login-note',error.message);}finally{b.disabled=false;}};
 $p('bind').onsubmit=async e=>{e.preventDefault();const b=$p('bind-send');b.disabled=true;try{const d=await api('phone/start',{method:'POST',body:JSON.stringify({phone:$p('bind-number').value,password:$p('bind-password').value,consent:$p('consent').checked})});bindChallenge=d.challenge_id;$p('bind-verify').hidden=false;note('manage-note',d.message);}catch(error){note('manage-note',error.message);}finally{$p('bind-password').value='';b.disabled=false;}};
 $p('bind-verify').onsubmit=async e=>{e.preventDefault();const b=$p('bind-submit');b.disabled=true;try{await api('phone/verify',{method:'POST',body:JSON.stringify({challenge_id:bindChallenge,code:$p('bind-code').value})});bindChallenge='';$p('bind-verify').reset();$p('bind-verify').hidden=true;$p('bind').reset();await load();note('manage-note','Телефон подтверждён. Email и текущая двухфакторная защита сохранены.');}catch(error){note('manage-note',error.message);}finally{b.disabled=false;}};
 $p('unlink').onsubmit=async e=>{e.preventDefault();const b=$p('unlink-submit');b.disabled=true;try{await api('phone/delete',{method:'POST',body:JSON.stringify({password:$p('unlink-password').value})});await load();note('manage-note','Номер отвязан. Вход по email сохранён.');}catch(error){note('manage-note',error.message);}finally{$p('unlink-password').value='';b.disabled=false;}};
 document.addEventListener('account-ready',()=>{loginChallenge='';$p('login').open=false;load();});
 document.addEventListener('account-signed-out',()=>{epoch++;loginChallenge='';bindChallenge='';$p('manage').hidden=true;for(const id of ['bind','bind-verify','unlink','login-start','login-verify'])$p(id).reset();$p('bind-verify').hidden=true;$p('login-verify').hidden=true;note('manage-note','');note('login-note','');});
 capabilities();if(typeof userEmail==='string'&&userEmail)load();
})();
