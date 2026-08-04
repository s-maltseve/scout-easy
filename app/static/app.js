const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmtBytes = (value) => { let n=Number(value)||0; const u=['Б','КБ','МБ','ГБ','ТБ']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++} return `${n.toFixed(i?1:0)} ${u[i]}`; };
const fmtRate = (value) => `${fmtBytes(value)}/с`;
const fmtUp = (s) => { const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60); return `${d}д ${h}ч ${m}м`; };
const endpoint = (a) => a ? `${a.ip}:${a.port}` : '—';

let state = null;
let actionToken = '';
let processSort = { key: 'cpu_percent', direction: -1 };
let networkSort = { key: 'process', direction: 1 };

function toast(message, bad=false){
  const el=$('toast'); el.textContent=message; el.className=`toast show${bad?' bad':''}`;
  setTimeout(()=>el.className='toast',3200);
}

function searchable(row){ return Object.values(row).join(' ').toLowerCase(); }
function compare(a,b,key,direction){
  let av=a[key], bv=b[key];
  if(key==='local'||key==='remote'){ av=endpoint(av); bv=endpoint(bv); }
  if(typeof av==='number'&&typeof bv==='number') return (av-bv)*direction;
  return String(av??'').localeCompare(String(bv??''),'ru')*direction;
}

async function action(path,payload,confirmText){
  if(!state?.meta.actions_enabled) return toast('Управляющие действия отключены в конфигурации',true);
  if(!confirm(confirmText)) return;
  try{
    const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-SCOUT-ACTION-TOKEN':actionToken},body:JSON.stringify(payload)});
    const body=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(body.detail||`HTTP ${r.status}`);
    toast('Действие выполнено'); await load();
  }catch(e){ toast(e.message,true); }
}


function renderProcesses(){
  if(!state) return;
  const q=$('process-filter').value.trim().toLowerCase();
  const rows=[...state.processes.top].filter(p=>!q||searchable(p).includes(q)).sort((a,b)=>compare(a,b,processSort.key,processSort.direction));
  $('process-order').textContent=`по ${processSort.key==='memory_percent'?'RAM':processSort.key==='cpu_percent'?'CPU':processSort.key}`;
  $('processes').innerHTML=rows.length?rows.map(p=>`<tr><td>${p.pid}</td><td title="${esc(p.cmdline)}"><b>${esc(p.name)}</b><small class="sub">${esc(p.username)}</small></td><td>${p.cpu_percent}%</td><td>${p.memory_percent}%</td></tr>`).join(''):`<tr><td colspan="4" class="empty">Ничего не найдено</td></tr>`;
}

function renderConnections(){
  if(!state) return;
  const q=$('network-filter').value.trim().toLowerCase();
  const rows=[...state.network.connections].filter(c=>!q||`${c.process} ${c.pid||''} ${endpoint(c.local)} ${endpoint(c.remote)} ${c.status}`.toLowerCase().includes(q)).sort((a,b)=>compare(a,b,networkSort.key,networkSort.direction));
  $('connections').innerHTML=rows.length?rows.map(c=>`<tr><td>${esc(c.process)} <small>${c.pid||''}</small></td><td>${esc(endpoint(c.local))}</td><td>${esc(endpoint(c.remote))}</td><td>${esc(c.status)}</td></tr>`).join(''):`<tr><td colspan="4" class="empty">Ничего не найдено</td></tr>`;
}

function render(data){
  state=data; actionToken=data.meta.action_token||'';
  $('version').textContent=`v${data.meta.version}`; $('hostname').textContent=data.system.hostname;
  $('mode').textContent=data.meta.read_only?'режим только чтения':'управление включено';
  const severity=data.warnings.some(w=>w.level==='critical')?'critical':data.warnings.some(w=>w.level==='warning')?'warning':'ok';
  $('status-dot').style.background=severity==='critical'?'var(--bad)':severity==='warning'?'var(--warn)':'var(--ok)';
  $('status-text').textContent=severity==='critical'?'Требуется проверка':'Работает';

  const cards=[['SSH сейчас',data.overview.ssh_sessions],['Ошибки входа',data.overview.auth_failures],['Успешные входы',data.overview.auth_successes],['Заблокировано',data.overview.banned_ips],['Соединения',data.overview.network_connections]];
  $('overview').innerHTML=cards.map(([l,v])=>`<article class="card"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></article>`).join('');
  $('alerts').innerHTML=data.warnings.map(w=>`<div class="alert ${esc(w.level)}"><strong>${esc(w.title)}</strong><span>${esc(w.message)}</span></div>`).join('');

  const metrics=[['CPU',data.system.cpu_percent],['RAM',data.system.memory.percent],['Диск',data.system.disk.percent]];
  $('system').innerHTML=`<div class="metrics">${metrics.map(([l,v])=>`<div class="metric-row"><span>${l}</span><div class="bar"><i style="width:${Math.min(v,100)}%"></i></div><b>${v}%</b></div>`).join('')}<div class="metric-row"><span>Uptime</span><div>${fmtUp(data.system.uptime_seconds)}</div><b></b></div><div class="metric-row"><span>RAM</span><div>${fmtBytes(data.system.memory.used)} / ${fmtBytes(data.system.memory.total)}</div><b></b></div></div>`;

  const t=data.traffic;
  $('traffic').innerHTML=`<div class="traffic-grid"><div class="traffic-card"><span>Сейчас входящий</span><b>↓ ${fmtRate(t.current.recv_per_second)}</b></div><div class="traffic-card"><span>Сейчас исходящий</span><b>↑ ${fmtRate(t.current.sent_per_second)}</b></div><div class="traffic-card"><span>Получено с запуска ОС</span><b>${fmtBytes(t.total.bytes_recv)}</b></div><div class="traffic-card"><span>Отправлено с запуска ОС</span><b>${fmtBytes(t.total.bytes_sent)}</b></div></div><div class="interface-list">${t.interfaces.slice(0,5).map(i=>`<div><span>${esc(i.name)}</span><span>↓ ${fmtBytes(i.bytes_recv)} · ↑ ${fmtBytes(i.bytes_sent)}</span></div>`).join('')}</div>`;

  $('session-count').textContent=`${data.ssh.sessions.length}`;
  $('sessions').innerHTML=data.ssh.sessions.length?data.ssh.sessions.map(s=>`<tr><td>${esc(s.username)}</td><td>${esc(s.source_ip)}</td><td>${esc(s.terminal)}</td><td>${new Date(s.started_at).toLocaleString()}</td><td>${data.meta.actions_enabled?`<button class="danger" data-action="disconnect" data-tty="${esc(s.terminal)}" data-user="${esc(s.username)}">Отключить</button>`:''}</td></tr>`).join(''):`<tr><td colspan="5" class="empty">Активных сессий нет</td></tr>`;
  $('events').innerHTML=data.ssh.events.length?data.ssh.events.slice(0,50).map(e=>`<tr><td><span class="badge ${e.type==='success'?'ok':'bad'}">${e.type==='success'?'успешно':'ошибка'}</span></td><td>${esc(e.user)}</td><td>${esc(e.ip)}</td><td>${esc(e.method)}</td><td>${data.meta.actions_enabled&&e.ip&&data.fail2ban.jails?.length?`<button class="danger ghost" data-action="ban" data-jail="${esc(data.fail2ban.jails[0].name)}" data-ip="${esc(e.ip)}">Бан</button>`:''}</td></tr>`).join(''):`<tr><td colspan="5" class="empty">События не найдены или нет доступа к journal</td></tr>`;

  $('f2b-status').textContent=data.fail2ban.running?'активен':'неактивен';
  $('fail2ban').innerHTML=data.fail2ban.jails?.length?`<div class="jails">${data.fail2ban.jails.map(j=>`<div class="jail"><div class="jail-head"><span>${esc(j.name)}</span><span>${j.currently_banned} банов</span></div><div class="jail-meta">Ошибок сейчас: ${j.currently_failed} · всего ошибок: ${j.total_failed} · всего банов: ${j.total_banned}</div>${data.meta.actions_enabled?`<div class="jail-actions"><button data-action="prompt-ban" data-jail="${esc(j.name)}">Заблокировать IP</button></div>`:''}${j.banned_ips.length?`<div class="ip-list">${j.banned_ips.map(ip=>`<span>${esc(ip)}${data.meta.actions_enabled?`<button title="Разбанить" data-action="unban" data-jail="${esc(j.name)}" data-ip="${esc(ip)}">×</button>`:''}</span>`).join('')}</div>`:''}</div>`).join('')}</div>`:`<div class="empty">${esc(data.fail2ban.error||'Jail не найдены')}</div>`;

  $('network-count').textContent=`${data.network.summary?.total||0}`;
  renderConnections(); renderProcesses();
}

async function load(){
  try{ const r=await fetch('/api/dashboard',{cache:'no-store'}); if(!r.ok) throw new Error(`${r.status} ${await r.text()}`); render(await r.json()); }
  catch(e){ $('status-dot').style.background='var(--bad)'; $('status-text').textContent='Ошибка'; $('alerts').innerHTML=`<div class="alert critical"><strong>Не удалось загрузить данные</strong><span>${esc(e.message)}</span></div>`; }
}


document.addEventListener('click',(event)=>{
  const button=event.target.closest('[data-action]');
  if(!button) return;
  const kind=button.dataset.action;
  if(kind==='disconnect') action('/api/actions/ssh/disconnect',{tty:button.dataset.tty},`Отключить SSH-сессию пользователя ${button.dataset.user} на ${button.dataset.tty}?`);
  if(kind==='ban') action('/api/actions/fail2ban/ban',{jail:button.dataset.jail,ip:button.dataset.ip},`Заблокировать ${button.dataset.ip} через jail ${button.dataset.jail}?`);
  if(kind==='unban') action('/api/actions/fail2ban/unban',{jail:button.dataset.jail,ip:button.dataset.ip},`Разблокировать ${button.dataset.ip} в jail ${button.dataset.jail}?`);
  if(kind==='prompt-ban'){
    const ip=prompt(`IP для блокировки в ${button.dataset.jail}:`);
    if(ip) action('/api/actions/fail2ban/ban',{jail:button.dataset.jail,ip:ip.trim()},`Заблокировать ${ip.trim()} через jail ${button.dataset.jail}?`);
  }
});

$('process-filter').addEventListener('input',renderProcesses);
$('network-filter').addEventListener('input',renderConnections);
document.querySelectorAll('[data-proc-sort]').forEach(el=>el.addEventListener('click',()=>{const key=el.dataset.procSort;processSort={key,direction:processSort.key===key?-processSort.direction:(['cpu_percent','memory_percent','pid'].includes(key)?-1:1)};renderProcesses();}));
document.querySelectorAll('[data-net-sort]').forEach(el=>el.addEventListener('click',()=>{const key=el.dataset.netSort;networkSort={key,direction:networkSort.key===key?-networkSort.direction:1};renderConnections();}));

load(); setInterval(load,5000);
