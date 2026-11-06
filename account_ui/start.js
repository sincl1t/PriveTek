'use strict';
if(document.body.dataset.restore==='yes') fetch('/api/account/draft',{credentials:'same-origin',cache:'no-store'}).then(r=>r.ok?r.json():{}).then(({draft})=>{
 if(!draft)return;
 const values={Name:draft.name,Email:draft.email,Phone:draft.phone,Username:draft.username,AdditionalUsername1:draft.additional_usernames[0]||'',AdditionalUsername2:draft.additional_usernames[1]||''};
 for(const [name,value] of Object.entries(values))document.getElementById('guest-start-form').elements.namedItem(name).value=value||'';
}).catch(()=>{});
