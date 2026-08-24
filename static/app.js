(()=>{
  const $=(s,r=document)=>r.querySelector(s);
  const $$=(s,r=document)=>[...r.querySelectorAll(s)];
  const api=async(url,opts={})=>{
    const r=await fetch(url,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});
    let j={};
    try{j=await r.json()}catch{}
    if(!r.ok) throw Object.assign(new Error(j.message||j.error||'Erro'),{data:j,status:r.status});
    return j;
  };
  const fmtDate=t=>new Date(t*1000).toLocaleString('pt-BR');
  const idem=()=>globalThis.crypto?.randomUUID?globalThis.crypto.randomUUID():String(Date.now())+Math.random();
  function deviceId(){
    let id=localStorage.getItem('clube_device');
    if(!id){id=idem();localStorage.setItem('clube_device',id)}
    return id;
  }
  async function session(){return api('/api/session')}
  async function logout(){await api('/api/logout',{method:'POST',body:'{}'});location='/login'}
  const normalizeSearch=v=>String(v||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
  const searchScore=(value,q)=>{q=normalizeSearch(q);if(!q)return 1;const v=normalizeSearch(value);if(v===q)return 100;if(v.startsWith(q))return 80;if(v.split(/\s+/).some(w=>w.startsWith(q)))return 60;if(v.includes(q))return 40;return 0};
  function confirmDialog(message,{title='Confirmar ação',confirmText='Confirmar',danger=false}={}){return new Promise(resolve=>{let ov=document.getElementById('clubeConfirm');if(ov)ov.remove();ov=document.createElement('div');ov.id='clubeConfirm';ov.className='dialog-overlay';ov.innerHTML=`<div class="dialog-card" role="dialog" aria-modal="true"><h3>${title}</h3><p></p><div class="actions"><button class="btn secondary" data-no>Cancelar</button><button class="btn ${danger?'danger':'ok'}" data-yes>${confirmText}</button></div></div>`;ov.querySelector('p').textContent=message;document.body.appendChild(ov);const done=v=>{ov.remove();resolve(v)};ov.querySelector('[data-no]').onclick=()=>done(false);ov.querySelector('[data-yes]').onclick=()=>done(true);ov.onclick=e=>{if(e.target===ov)done(false)}})}
  function alertDialog(message,{title='Aviso',buttonText='OK'}={}){let ov=document.getElementById('clubeAlert');if(ov)ov.remove();ov=document.createElement('div');ov.id='clubeAlert';ov.className='dialog-overlay';ov.innerHTML=`<div class="dialog-card" role="dialog" aria-modal="true"><h3></h3><p></p><div class="actions"><button class="btn" data-ok>${buttonText}</button></div></div>`;ov.querySelector('h3').textContent=title;ov.querySelector('p').textContent=message;document.body.appendChild(ov);const close=()=>ov.remove();ov.querySelector('[data-ok]').onclick=close;ov.onclick=e=>{if(e.target===ov)close()};return ov}
  window.Clube={api,fmtDate,idem,deviceId,session,logout,$,$$,normalizeSearch,searchScore,confirmDialog,alertDialog};
})();
