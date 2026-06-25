"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k === "html") e.innerHTML = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null) continue;
    e.append(kid.nodeType ? kid : document.createTextNode(kid));
  }
  return e;
}
const STEPS = ["subdomains","wayback","files","params","reflection","openredirect","livecheck","fuzz"];
const SUBSOURCES = ["crtsh","subfinder","wayback","otx","hackertarget","rapiddns"];

const state = { user:null, targets:[], current:null, tab:"overview",
  page:{}, q:{}, filters:{}, logsLastId:0, logsTimer:null, pollTimer:null };

async function api(method, url, body, isForm) {
  const opt = { method, headers:{} };
  if (body && !isForm) { opt.headers["Content-Type"]="application/json"; opt.body=JSON.stringify(body); }
  if (body && isForm) opt.body = body;
  const r = await fetch(url, opt);
  if (r.status === 401) { showLogin(); throw new Error("unauthorized"); }
  if (!r.ok) { let m=r.statusText; try{m=(await r.json()).detail||m;}catch{} throw new Error(m); }
  const ct = r.headers.get("content-type")||"";
  return ct.includes("application/json") ? r.json() : r.text();
}
function toast(msg, ms=2600){ const t=el("div",{class:"toast"},msg); document.body.append(t); setTimeout(()=>t.remove(),ms); }

/* ---------- auth ---------- */
function showLogin(){ $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); }
function showApp(){ $("#login").classList.add("hidden"); $("#app").classList.remove("hidden"); }
$("#loginForm").addEventListener("submit", async e=>{
  e.preventDefault(); $("#lerr").textContent="";
  try{
    const r = await api("POST","/api/login",{user:$("#lu").value,password:$("#lp").value});
    state.user=r.user; boot();
  }catch(err){ $("#lerr").textContent="Invalid credentials"; }
});
$("#logoutBtn").addEventListener("click", async()=>{ await api("POST","/api/logout"); location.reload(); });

/* ---------- boot ---------- */
async function boot(){
  try{ const me=await api("GET","/api/me"); state.user=me.user; }
  catch{ showLogin(); return; }
  showApp(); $("#whoami").textContent=state.user;
  await loadTargets();
  startPolling();
}
$("#newTargetBtn").addEventListener("click", newTargetModal);
$("#settingsBtn").addEventListener("click", settingsModal);

/* ---------- targets ---------- */
async function loadTargets(){
  state.targets = await api("GET","/api/targets");
  renderTargets();
  if (state.current){
    const t = state.targets.find(x=>x.id===state.current.id);
    if (t){ state.current=t; renderTarget(); }
  }
}
function statusTag(s){
  const map={done:"ok",running:"run",queued:"run",error:"err"};
  return el("span",{class:"tag "+(map[s]||"idle")}, s||"idle");
}
function renderTargets(){
  const list=$("#tlist"); list.innerHTML="";
  if(!state.targets.length) list.append(el("div",{class:"muted",style:"padding:12px;font-size:12px"},"No targets yet."));
  for(const t of state.targets){
    const c=t.counts||{};
    const item=el("div",{class:"titem"+(state.current&&state.current.id===t.id?" active":""),onclick:()=>selectTarget(t.id)},
      el("div",{class:"row spread"}, el("span",{class:"name"},t.name), statusTag(t.job?t.job.status:t.status)),
      el("div",{class:"meta"},`${c.subdomains||0} subs · ${c.urls||0} urls · ${c.secrets||0} secrets · ${c.reflections||0} refl`));
    list.append(item);
  }
}
async function selectTarget(id){
  state.current = await api("GET",`/api/targets/${id}`);
  state.tab="overview"; state.page={}; state.q={}; state.filters={}; state.logsLastId=0;
  renderTargets(); renderTarget();
}

/* ---------- target view ---------- */
function renderTarget(){
  $("#emptyMain").classList.add("hidden");
  const v=$("#targetView"); v.classList.remove("hidden");
  const t=state.current, job=t.job, c=t.counts||{};
  const running = job && (job.status==="running"||job.status==="queued");
  v.innerHTML="";
  v.append(
    el("div",{class:"row spread wrap"},
      el("div",{},
        el("h2",{style:"margin:0"}, t.name, " ", statusTag(job?job.status:t.status)),
        el("div",{class:"muted",style:"font-size:12px;margin-top:2px"}, t.scope_note||"in-scope: *."+t.name)),
      el("div",{class:"row"},
        running? el("button",{class:"btn danger",onclick:stopRun},"■ Stop")
               : el("button",{class:"btn primary",onclick:runModal},"▶ Run recon"),
        el("button",{class:"btn",onclick:()=>window.open(`/api/targets/${t.id}/zip`,"_blank")},"⬇ Export ZIP"),
        el("button",{class:"btn danger",onclick:deleteTarget},"Delete"))));
  if(job && running){
    v.append(el("div",{style:"margin-top:8px"},
      el("div",{class:"muted mono",style:"font-size:12px"},`step: ${job.current_step||"…"} — ${job.progress||0}%`),
      el("div",{class:"prog"}, el("i",{style:`width:${job.progress||0}%`}))));
  }
  // tabs
  const tabs=el("div",{class:"tabs"});
  const TABDEF=tabDefs();
  for(const td of TABDEF){
    const cnt = td.count!=null ? c[td.count]||0 : null;
    tabs.append(el("div",{class:"tab"+(state.tab===td.key?" active":""),onclick:()=>{state.tab=td.key;renderTarget();}},
      td.label, cnt!=null? el("span",{class:"c"},cnt):null));
  }
  v.append(tabs);
  const body=el("div",{id:"tabBody",style:"margin-top:14px"}); v.append(body);
  renderTab(body);
}

function tabDefs(){return [
  {key:"overview",label:"Overview"},
  {key:"subdomains",label:"Subdomains",count:"subdomains"},
  {key:"urls",label:"URLs",count:"urls"},
  {key:"files",label:"JS / Juicy",count:"files"},
  {key:"jslinks",label:"Endpoints",count:"jslinks"},
  {key:"secrets",label:"Secrets",count:"secrets"},
  {key:"params",label:"Parameters",count:"params"},
  {key:"reflections",label:"Reflections",count:"reflections"},
  {key:"openredirects",label:"Open Redirect",count:"openredirects"},
  {key:"live",label:"Live",count:"live"},
  {key:"fuzz",label:"Fuzz",count:"fuzz"},
  {key:"logs",label:"Logs"},
];}

function renderTab(body){
  body.innerHTML="";
  if(state.tab==="overview") return renderOverview(body);
  if(state.tab==="logs") return renderLogs(body);
  renderDataTab(body, state.tab);
}

function renderOverview(body){
  const c=state.current.counts||{};
  const cards=[["subdomains","Subdomains"],["urls","URLs"],["juicy_urls","Juicy URLs"],
    ["param_urls","URLs w/ params"],["files","Files"],["jslinks","Endpoints"],
    ["params","Parameters"],["live","Live hosts"],["fuzz","Fuzz hits"]];
  const grid=el("div",{class:"stats"});
  for(const [k,l] of cards) grid.append(el("div",{class:"stat"},el("div",{class:"n"},c[k]||0),el("div",{class:"l"},l)));
  grid.append(el("div",{class:"stat alert"},el("div",{class:"n"},c.secrets||0),el("div",{class:"l"},"Secrets")));
  grid.append(el("div",{class:"stat alert"},el("div",{class:"n"},c.reflections||0),el("div",{class:"l"},"Reflections")));
  grid.append(el("div",{class:"stat alert"},el("div",{class:"n"},c.openredirects||0),el("div",{class:"l"},"Open Redirects")));
  body.append(grid);
  const mf=el("div",{class:"card",style:"margin-top:8px"},
    el("h3",{style:"margin:0 0 10px"},"Master files"),
    el("div",{class:"row wrap"},
      masterBtn("subdomains.txt","Subdomains"),
      masterBtn("urls.txt","All URLs"),
      masterBtn("parameters.txt","Parameters"),
      masterBtn("reflected.txt","Reflected"),
      masterBtn("openredirect.txt","Open redirects")));
  body.append(mf);
}
function masterBtn(suffix,label){
  const t=state.current;
  const url=`/api/targets/${t.id}/master/${t.slug}_${suffix}`;
  return el("a",{class:"btn sm",href:url,target:"_blank"}, "⬇ "+label);
}

/* ---------- generic data tab ---------- */
const COLS = {
  subdomains:[["host","mono"],["source"]],
  urls:[["url","mono"],["mime"],["archive_ts"],["has_params"],["is_juicy"]],
  jslinks:[["link","mono"],["kind"],["source_file","mono"]],
  params:[["name","mono"],["source"]],
  reflections:[["url","mono"],["param"],["contexts"],["status_code","sc"]],
  openredirects:[["url","mono"],["param"],["payload","mono"],["location","mono"]],
};
function renderDataTab(body, tab){
  const t=state.current;
  const bar=el("div",{class:"toolbar"});
  const search=el("input",{type:"text",placeholder:"search…",value:state.q[tab]||"",
    oninput:e=>{state.q[tab]=e.target.value; state.page[tab]=0; debounceLoad(body,tab);}});
  bar.append(search);
  if(tab==="urls"){
    bar.append(toggle("Juicy only","juicy",body,tab),toggle("Params only","params",body,tab));
  }
  if(tab==="files"){
    bar.append(select("kind",["","js","json","config","map","other"],body,tab),
               select("variant",["","live","archived"],body,tab));
  }
  if(tab==="jslinks"){ bar.append(select("kind",["","url","file","path"],body,tab)); }
  if(tab==="live"){ bar.append(el("input",{type:"text",placeholder:"status code",style:"width:120px",
      value:state.filters[tab]?.status||"",oninput:e=>{state.filters[tab]={status:e.target.value};state.page[tab]=0;debounceLoad(body,tab);}})); }
  bar.append(el("div",{class:"grow"}));
  bar.append(el("a",{class:"btn sm",href:`/api/targets/${t.id}/export/${tab}.csv`,target:"_blank"},"⬇ CSV"));
  body.append(bar);
  const holder=el("div",{id:"tabData"}); body.append(holder);
  loadData(holder,tab);
}
function toggle(label,key,body,tab){
  const on=state.filters[tab]?.[key];
  return el("label",{class:"row",style:"font-size:12px"},
    el("input",{type:"checkbox",...(on?{checked:"checked"}:{}),onchange:e=>{
      state.filters[tab]=state.filters[tab]||{}; state.filters[tab][key]=e.target.checked?1:0;
      state.page[tab]=0; loadData($("#tabData"),tab);}}), label);
}
function select(key,opts,body,tab){
  return el("select",{onchange:e=>{state.filters[tab]=state.filters[tab]||{};state.filters[tab][key]=e.target.value;state.page[tab]=0;loadData($("#tabData"),tab);}},
    ...opts.map(o=>el("option",{value:o},o||("any "+key))));
}
let _deb;
function debounceLoad(body,tab){ clearTimeout(_deb); _deb=setTimeout(()=>loadData($("#tabData"),tab),250); }

async function loadData(holder,tab){
  const t=state.current; const limit=200; const offset=(state.page[tab]||0)*limit;
  const f=state.filters[tab]||{};
  let url=`/api/targets/${t.id}/${tab}?limit=${limit}&offset=${offset}&q=${encodeURIComponent(state.q[tab]||"")}`;
  if(tab==="urls"){ url+=`&juicy=${f.juicy?1:0}&params=${f.params?1:0}`; }
  if(tab==="files"){ if(f.kind)url+=`&kind=${f.kind}`; if(f.variant)url+=`&variant=${f.variant}`; }
  if(tab==="jslinks"&&f.kind){ url+=`&kind=${f.kind}`; }
  if(tab==="live"&&f.status){ url+=`&status=${encodeURIComponent(f.status)}`; }
  holder.innerHTML="<div class='muted' style='padding:20px'>loading…</div>";
  let data; try{ data=await api("GET",url); }catch(e){ holder.innerHTML=`<div class='muted'>${e.message}</div>`; return; }
  holder.innerHTML="";
  if(!data.items.length){ holder.append(el("div",{class:"muted",style:"padding:20px"},"no results")); return; }
  const table=el("table"); const head=el("tr");
  const cols = colsFor(tab);
  for(const c of cols) head.append(el("th",{},c.label));
  table.append(el("thead",{},head));
  const tb=el("tbody");
  for(const row of data.items) tb.append(renderRow(tab,row,cols));
  table.append(tb); holder.append(table);
  holder.append(pager(tab,data,holder));
}
function colsFor(tab){
  if(tab==="files") return [{k:"url",cls:"mono",label:"URL"},{k:"kind",label:"kind"},
    {k:"variant",label:"variant"},{k:"status_code",label:"code",sc:true},
    {k:"content_type",label:"type"},{k:"size",label:"size"},{k:"parent_url",cls:"mono",label:"parent"},{k:"__dl",label:""}];
  if(tab==="secrets") return [{k:"rule",label:"rule"},{k:"severity",label:"sev",sev:true},
    {k:"match",cls:"mono",label:"match"},{k:"source_file",cls:"mono",label:"source"},{k:"context",cls:"mono",label:"context"}];
  if(tab==="live") return [{k:"url",cls:"mono",label:"URL"},{k:"status_code",label:"code",sc:true},
    {k:"title",label:"title"},{k:"content_type",label:"type"},{k:"content_length",label:"len"},{k:"via_proxy",label:"proxy"}];
  if(tab==="fuzz") return [{k:"found_url",cls:"mono",label:"found"},{k:"status_code",label:"code",sc:true},
    {k:"content_type",label:"type"},{k:"length",label:"len"},{k:"base_url",cls:"mono",label:"base"}];
  return (COLS[tab]||[]).map(([k,cls])=>({k,cls:cls&&cls!=="sc"?cls:null,sc:cls==="sc",label:k}));
}
function renderRow(tab,row,cols){
  const tr=el("tr");
  for(const c of cols){
    if(c.k==="__dl"){ tr.append(el("td",{}, el("a",{class:"btn sm",href:`/api/targets/${state.current.id}/files/${row.id}/raw`,target:"_blank"},"raw"))); continue; }
    let v=row[c.k];
    if(typeof v==="boolean") v=v?"✓":"";
    const td=el("td",{class:c.cls||""});
    if(c.sc){ const code=row[c.k]||0; td.append(el("span",{class:"sc sc"+String(code)[0]},code||"-")); }
    else if(c.sev){ td.append(el("span",{class:"sev-"+(v||"low")},v||"")); }
    else td.textContent = v==null?"":String(v);
    tr.append(td);
  }
  return tr;
}
function pager(tab,data,holder){
  const total=data.total, limit=data.limit, page=state.page[tab]||0, pages=Math.ceil(total/limit);
  const p=el("div",{class:"pager"});
  p.append(el("span",{class:"muted"},`${total} rows · page ${page+1}/${Math.max(1,pages)}`));
  if(page>0) p.append(el("button",{class:"btn sm",onclick:()=>{state.page[tab]=page-1;loadData(holder,tab);}},"‹ prev"));
  if(page+1<pages) p.append(el("button",{class:"btn sm",onclick:()=>{state.page[tab]=page+1;loadData(holder,tab);}},"next ›"));
  return p;
}

/* ---------- logs ---------- */
function renderLogs(body){
  body.append(el("div",{class:"row spread"}, el("h3",{style:"margin:0"},"Job log"),
    el("button",{class:"btn sm",onclick:()=>{state.logsLastId=0;$("#logbox").textContent="";}},"clear")));
  body.append(el("div",{class:"log",id:"logbox"}));
  state.logsLastId=0; pumpLogs(true);
}
async function pumpLogs(reset){
  const box=$("#logbox"); if(!box) return;
  try{
    const r=await api("GET",`/api/targets/${state.current.id}/logs?after=${state.logsLastId}`);
    for(const it of r.items){
      box.append(el("div",{class:it.level},`[${(it.created_at||"").slice(11,19)}] ${it.step}: ${it.message}`));
    }
    if(r.items.length){ state.logsLastId=r.last_id; box.scrollTop=box.scrollHeight; }
  }catch{}
}

/* ---------- run modal ---------- */
function modal(node){
  const root=$("#modalRoot");
  const m=el("div",{class:"modal",onclick:e=>{if(e.target===m)root.innerHTML="";}}, node);
  root.innerHTML=""; root.append(m); return m;
}
function closeModal(){ $("#modalRoot").innerHTML=""; }

function runModal(){
  const t=state.current;
  const stepBoxes=el("div",{class:"steps"});
  for(const s of STEPS) stepBoxes.append(el("label",{}, el("input",{type:"checkbox",checked:"checked","data-step":s}), s));
  const srcBoxes=el("div",{class:"steps"});
  for(const s of SUBSOURCES) srcBoxes.append(el("label",{}, el("input",{type:"checkbox",...(s==="subfinder"?{}:{checked:"checked"}),"data-src":s}), s));
  const paste=el("textarea",{rows:4,placeholder:"paste subdomains (one per line) — skips needing crt.sh if you want"});
  const subindex=el("textarea",{rows:3,placeholder:"paste subindex output here (optional)"});
  const subindexFile=el("input",{type:"file"});
  const fromY=el("input",{type:"number",placeholder:"all",style:"width:90px"});
  const toY=el("input",{type:"number",placeholder:"now",style:"width:90px"});
  const batch=el("input",{type:"number",value:50000,style:"width:100px"});
  const wbMax=el("input",{type:"number",value:0,style:"width:100px",title:"max archive urls to harvest, 0=all"});
  const depth=el("input",{type:"number",value:3,style:"width:70px"});
  const vlive=el("input",{type:"checkbox",checked:"checked"}), varch=el("input",{type:"checkbox",checked:"checked"});
  const reflUrls=el("input",{type:"number",value:400,style:"width:90px"});
  const reflParams=el("input",{type:"number",value:1024,style:"width:90px"});
  const paramsFile=el("input",{type:"file"});
  // archive engine + scale caps
  const engineSel=el("select",{},...["both","cdx","waymore"].map(o=>el("option",{value:o},o)));
  const wmTimeout=el("input",{type:"number",value:0,style:"width:90px",title:"waymore overall timeout (s), 0=none"});
  const wmLimit=el("input",{type:"number",value:0,style:"width:90px",title:"waymore per-source request limit, 0=none"});
  const maxFiles=el("input",{type:"number",value:0,style:"width:90px",title:"max juicy files to download, 0=all"});
  const maxSnaps=el("input",{type:"number",value:25,style:"width:80px",title:"max archived captures per file"});
  const liveMax=el("input",{type:"number",value:8000,style:"width:90px"});
  const orMax=el("input",{type:"number",value:1500,style:"width:90px"});
  const fzDirs=el("input",{type:"number",value:300,style:"width:80px"});
  const fzWords=el("input",{type:"number",value:0,style:"width:80px",title:"0=all words"});

  const card=el("div",{class:"card"},
    el("h3",{},"Run recon — "+t.name),
    el("div",{class:"muted",style:"font-size:12px;margin-bottom:8px"},"Untick a step to exclude it."),
    el("b",{},"Steps"), stepBoxes,
    el("b",{},"Subdomain sources"), srcBoxes,
    el("div",{class:"field"},el("label",{},"Paste subdomains (optional)"),paste),
    el("div",{class:"field"},el("label",{},"Subindex output (optional)"),subindex),
    el("div",{class:"field"},el("label",{},"Subindex file upload (optional)"),subindexFile),
    el("b",{},"Archive engine"),
    el("div",{class:"row wrap",style:"gap:14px;margin:6px 0"},
      el("label",{class:"row"},"engine",engineSel),
      el("label",{class:"row"},"waymore timeout s",wmTimeout),
      el("label",{class:"row"},"req limit",wmLimit)),
    el("div",{class:"row wrap",style:"gap:14px"},
      el("label",{class:"row"},"Wayback years",fromY,"→",toY),
      el("label",{class:"row"},"Batch",batch),
      el("label",{class:"row"},"max urls",wbMax),
      el("label",{class:"row"},"Recursion depth",depth)),
    el("div",{class:"row wrap",style:"gap:14px;margin-top:8px"},
      el("label",{class:"row"},vlive,"download live"),
      el("label",{class:"row"},varch,"download archived"),
      el("label",{class:"row"},"max files",maxFiles),
      el("label",{class:"row"},"max snapshots/file",maxSnaps)),
    el("div",{class:"row wrap",style:"gap:14px;margin-top:8px"},
      el("label",{class:"row"},"refl. URLs",reflUrls),
      el("label",{class:"row"},"refl. params",reflParams),
      el("label",{class:"row"},"open-redir URLs",orMax)),
    el("div",{class:"row wrap",style:"gap:14px;margin-top:8px"},
      el("label",{class:"row"},"live max",liveMax),
      el("label",{class:"row"},"fuzz dirs",fzDirs),
      el("label",{class:"row"},"fuzz words",fzWords)),
    el("div",{class:"field",style:"margin-top:8px"},el("label",{},"Base params.txt (optional upload)"),paramsFile),
    el("div",{class:"row spread",style:"margin-top:14px"},
      el("button",{class:"btn",onclick:closeModal},"Cancel"),
      el("button",{class:"btn primary",onclick:async()=>{
        if(paramsFile.files[0]){ const fd=new FormData(); fd.append("file",paramsFile.files[0]);
          try{ await api("POST",`/api/targets/${t.id}/upload_params`,fd,true);}catch(e){toast(e.message);} }
        if(subindexFile.files[0]){ const fd=new FormData(); fd.append("file",subindexFile.files[0]);
          try{ await api("POST",`/api/targets/${t.id}/upload_subdomains`,fd,true);}catch(e){toast(e.message);} }
        const excluded=STEPS.filter(s=>!$(`[data-step="${s}"]`,stepBoxes).checked);
        const sources=SUBSOURCES.filter(s=>$(`[data-src="${s}"]`,srcBoxes).checked);
        const variants=[]; if(vlive.checked)variants.push("live"); if(varch.checked)variants.push("archived");
        const opt={ excluded_steps:excluded, subdomain_sources:sources,
          paste_subdomains:paste.value, subindex_output:subindex.value,
          archive_engine:engineSel.value,
          waymore_run_timeout:+wmTimeout.value||0, waymore_limit_requests:+wmLimit.value||0,
          wayback_from_year:+fromY.value||0, wayback_to_year:+toY.value||0,
          wayback_batch_size:+batch.value||50000, wayback_max_urls:+wbMax.value||0,
          max_recursion_depth:+depth.value||3,
          download_variants:variants, max_files:+maxFiles.value||0,
          max_snapshots_per_url:+maxSnaps.value||25,
          reflection_max_urls:+reflUrls.value||400, reflection_max_params:+reflParams.value||1024,
          openredirect_max_urls:+orMax.value||1500, livecheck_max_urls:+liveMax.value||8000,
          fuzz_max_base_dirs:+fzDirs.value||300, fuzz_max_words:+fzWords.value||0 };
        try{ await api("POST",`/api/targets/${t.id}/start`,opt); toast("recon started"); closeModal();
          await loadTargets(); state.tab="logs"; renderTarget(); }
        catch(e){ toast(e.message); }
      }},"▶ Start")));
  modal(card);
}

async function stopRun(){ try{ await api("POST",`/api/targets/${state.current.id}/stop`); toast("stopping…"); await loadTargets(); }catch(e){toast(e.message);} }
async function deleteTarget(){ if(!confirm("Delete target and all its data?"))return;
  await api("DELETE",`/api/targets/${state.current.id}`); state.current=null;
  $("#targetView").classList.add("hidden"); $("#emptyMain").classList.remove("hidden"); await loadTargets(); }

/* ---------- new target ---------- */
function newTargetModal(){
  const name=el("input",{placeholder:"example.com",style:"width:100%"});
  const note=el("input",{placeholder:"scope note (optional)",style:"width:100%"});
  const err=el("div",{class:"err-msg"});
  const card=el("div",{class:"card"}, el("h3",{},"New target"),
    el("div",{class:"field"},el("label",{},"Root domain"),name),
    el("div",{class:"field"},el("label",{},"Scope note"),note), err,
    el("div",{class:"row spread"}, el("button",{class:"btn",onclick:closeModal},"Cancel"),
      el("button",{class:"btn primary",onclick:async()=>{
        try{ const t=await api("POST","/api/targets",{name:name.value,scope_note:note.value});
          closeModal(); await loadTargets(); selectTarget(t.id);
        }catch(e){ err.textContent=e.message; } }},"Create")));
  modal(card); name.focus();
}

/* ---------- settings ---------- */
async function settingsModal(){
  const s=await api("GET","/api/settings");
  const banner=el("div",{class:"banner"},"⚠ Proxy credentials & API keys are stored only on this server (data/config.json) and are masked here. Rotate anything you shared elsewhere.");
  const proxies=el("textarea",{rows:3,placeholder:"host:port:user:pass  (one per line) — used automatically when the direct IP is WAF/rate-limit blocked"});
  // api keys
  function keyField(label,key){
    const set=s[key+"_set"]; const hint=s[key+"_hint"]||"";
    const inp=el("input",{type:"password",placeholder:set?("set ("+hint+") — leave blank to keep"):"not set",style:"width:100%","data-key":key});
    return el("div",{class:"field"},el("label",{},label+" "+(set?"✓":"—")),inp);
  }
  const urlscan=keyField("URLScan API key","urlscan_api_key");
  const otx=keyField("AlienVault OTX API key","otx_api_key");
  const vt=keyField("VirusTotal API key","virustotal_api_key");
  const ix=keyField("Intelligence X API key","intelx_api_key");
  // archive engine + waymore
  const engine=el("select",{},...["waymore","both","cdx"].map(o=>el("option",{value:o,...(s.archive_engine===o?{selected:"selected"}:{})},o)));
  const wproc=numIn(s.waymore_processes,"80"); const wto=numIn(s.waymore_run_timeout,"110");
  const wlim=numIn(s.waymore_limit_requests,"110"); const cooldown=numIn(s.block_cooldown_sec,"90");
  const caps=numIn(s.max_snapshots_per_url,"80");
  const tt=el("input",{type:"checkbox",...(s.archive_timetravel?{checked:"checked"}:{})});
  const subs=el("input",{type:"checkbox",...(s.waymore_include_subs?{checked:"checked"}:{})});
  // workers
  const dlw=numIn(s.download_workers,"70"); const chw=numIn(s.check_workers,"70");
  const fzw=numIn(s.fuzz_workers,"70"); const conc=numIn(s.max_concurrent_jobs,"70");
  const delay=numIn(s.request_delay_ms,"70");
  const pw=el("input",{type:"password",placeholder:"new password",style:"width:100%"});
  const cur=el("div",{class:"muted mono",style:"font-size:11px"}, (s.proxies||[]).join("  |  ")||"no proxies configured");
  const card=el("div",{class:"card"}, el("h3",{},"Settings"), banner,
    el("div",{},"Active impersonation: ",el("span",{class:"code"},s.impersonate_active||s.impersonate),
        "  ·  proxies: ",el("span",{class:"code"},String(s.proxy_count||0))),
    el("h4",{style:"margin:14px 0 4px"},"Passive-source API keys (used by waymore + subdomain enum)"),
    urlscan,otx,vt,ix,
    el("h4",{style:"margin:14px 0 4px"},"Archive engine"),
    el("div",{class:"row wrap",style:"gap:14px"},
      el("label",{class:"row"},"engine",engine),
      el("label",{class:"row"},"waymore -p",wproc),
      el("label",{class:"row"},"run timeout s",wto),
      el("label",{class:"row"},"req limit",wlim)),
    el("div",{class:"row wrap",style:"gap:14px;margin-top:8px"},
      el("label",{class:"row"},subs,"include subdomains"),
      el("label",{class:"row"},tt,"archive time-travel"),
      el("label",{class:"row"},"max snapshots/file",caps),
      el("label",{class:"row"},"block cooldown s",cooldown)),
    el("h4",{style:"margin:14px 0 4px"},"Proxies"),
    el("div",{class:"field"},el("label",{},"Configured proxies (masked)"),cur),
    el("div",{class:"field"},el("label",{},"Set proxies (replaces list)"),proxies),
    el("h4",{style:"margin:14px 0 4px"},"Concurrency"),
    el("div",{class:"row wrap",style:"gap:14px"},
      el("label",{class:"row"},"download",dlw),el("label",{class:"row"},"check",chw),
      el("label",{class:"row"},"fuzz",fzw),el("label",{class:"row"},"jobs",conc),
      el("label",{class:"row"},"delay ms",delay)),
    el("div",{class:"field",style:"margin-top:10px"},el("label",{},"Change admin password"),pw),
    el("div",{class:"row spread",style:"margin-top:12px"}, el("button",{class:"btn",onclick:closeModal},"Close"),
      el("button",{class:"btn primary",onclick:async()=>{
        const body={ download_workers:+dlw.value, check_workers:+chw.value,
          fuzz_workers:+fzw.value, max_concurrent_jobs:+conc.value, request_delay_ms:+delay.value,
          archive_engine:engine.value, waymore_processes:+wproc.value, waymore_run_timeout:+wto.value,
          waymore_limit_requests:+wlim.value, waymore_include_subs:subs.checked,
          archive_timetravel:tt.checked, max_snapshots_per_url:+caps.value, block_cooldown_sec:+cooldown.value };
        const px=proxies.value.split("\n").map(x=>x.trim()).filter(Boolean);
        if(px.length) body.proxies=px;
        for(const inp of [urlscan,otx,vt,ix].map(f=>$("input",f))){
          const v=inp.value.trim(); if(v) body[inp.getAttribute("data-key")]=v;
        }
        if(pw.value) body.new_password=pw.value;
        try{ await api("POST","/api/settings",body); toast("saved"); closeModal(); }catch(e){toast(e.message);}
      }},"Save")));
  modal(card);
}
function numIn(val,w){ return el("input",{type:"number",value:(val==null?0:val),style:"width:"+(w||"80")+"px"}); }

/* ---------- polling ---------- */
function startPolling(){
  if(state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer=setInterval(async()=>{
    const anyRunning = state.targets.some(t=>t.job&&(t.job.status==="running"||t.job.status==="queued"));
    if(anyRunning) await loadTargets();
    if(state.current && state.tab==="logs") pumpLogs();
  }, 3000);
}

boot();
