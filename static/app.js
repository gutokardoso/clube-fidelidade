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
  window.Clube={api,fmtDate,idem,deviceId,session,logout,$,$$};
})();
