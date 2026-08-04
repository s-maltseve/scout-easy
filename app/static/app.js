const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const num = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
const list = (value) => Array.isArray(value) ? value : [];
const obj = (value) => value && typeof value === 'object' ? value : {};
const fmtBytes = (value) => { if(value === null || value === undefined) return '—'; let n=num(value); const u=['Б','КБ','МБ','ГБ','ТБ']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++} return `${n.toFixed(i?1:0)} ${u[i]}`; };
const fmtRate = (value) => value === null || value === undefined ? '—' : `${fmtBytes(value)}/с`;
const fmtUp = (s) => { s=num(s); const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60); return `${d}д ${h}ч ${m}м`; };
const endpoint = (a) => a && typeof a === 'object' ? `${a.ip ?? '—'}:${a.port ?? '—'}` : '—';

let state = null;
let processSort = { key: 'cpu_percent', direction: -1 };
let networkSort = { key: 'recv_per_second', direction: -1 };

function toast(message, bad=false){
  const el=$('toast'); if(!el) return;
  el.textContent=message; el.className=`toast show${bad?' bad':''}`;
  setTimeout(()=>el.className='toast',3200);
}

function actionToken(){
  let token=sessionStorage.getItem('scoutActionToken') || '';
  if(!token){
    token=prompt('Введите SCOUT_ACTION_TOKEN. Токен сохранится только до закрытия вкладки:')?.trim() || '';
    if(token) sessionStorage.setItem('scoutActionToken', token);
  }
  return token;
}

function searchable(row){ return JSON.stringify(obj(row)).toLowerCase(); }
function compare(a,b,key,direction){
  let av=a?.[key], bv=b?.[key];
  if(key==='local'||key==='remote'){ av=endpoint(av); bv=endpoint(bv); }
  if(typeof av==='number'||typeof bv==='number') return (num(av)-num(bv))*direction;
  return String(av??'').localeCompare(String(bv??''),'ru')*direction;
}

async function action(path,payload,confirmText){
  if(!state?.meta?.actions_enabled) return toast('Управляющие действия отключены в конфигурации',true);
  if(!confirm(confirmText)) return;
  const token=actionToken();
  if(!token) return toast('Действие отменено: токен не введён',true);
  try{
    const r=await fetch(path,{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','X-SCOUT-ACTION-TOKEN':token},body:JSON.stringify(payload)});
    const body=await r.json().catch(()=>({}));
    if(!r.ok){
      if(r.status===403) sessionStorage.removeItem('scoutActionToken');
      throw new Error(body.detail||`HTTP ${r.status}`);
    }
    toast('Действие выполнено'); await load();
  }catch(e){ toast(e.message,true); }
}

function sectionError(id, message){
  const el=$(id); if(el) el.innerHTML=`<div class="empty error-text">${esc(message || 'Данные недоступны')}</div>`;
}

function renderProcesses(){
  if(!state) return;
  const q=$('process-filter')?.value.trim().toLowerCase() || '';
  const rows=list(state.processes?.top).filter(p=>!q||searchable(p).includes(q)).sort((a,b)=>compare(a,b,processSort.key,processSort.direction));
  $('process-order').textContent=`по ${processSort.key==='memory_percent'?'RAM':processSort.key==='cpu_percent'?'CPU':processSort.key}`;
  $('processes').innerHTML=rows.length?rows.map(p=>`<tr><td>${esc(p.pid)}</td><td title="${esc(p.cmdline)}"><b>${esc(p.name)}</b><small class="sub">${esc(p.username)}</small></td><td>${num(p.cpu_percent)}%</td><td>${num(p.memory_percent)}%</td></tr>`).join(''):`<tr><td colspan="4" class="empty">Ничего не найдено</td></tr>`;
}

function renderProcessTraffic(){
  const rows=list(state?.network?.process_traffic).slice(0,12);
  $('process-traffic').innerHTML=rows.length?rows.map(p=>`<tr><td><b>${esc(p.process)}</b><small class="sub">${num(p.connections)} TCP</small></td><td class="rate down">↓ ${fmtRate(p.recv_per_second)}</td><td class="rate up">↑ ${fmtRate(p.sent_per_second)}</td><td>${fmtBytes(p.bytes_all)}</td></tr>`).join(''):`<tr><td colspan="4" class="empty">Активный TCP-трафик пока не зафиксирован</td></tr>`;
}

function renderConnections(){
  if(!state) return;
  const q=$('network-filter')?.value.trim().toLowerCase() || '';
  const hideLoopback=$('hide-loopback')?.checked ?? true;
  const activeOnly=$('active-traffic-only')?.checked ?? false;
  const hidePassive=$('hide-passive')?.checked ?? true;
  const rows=list(state.network?.connections)
    .filter(c=>!q||`${c.process??''} ${c.pid??''} ${endpoint(c.local)} ${endpoint(c.remote)} ${c.status??''} ${c.type??''}`.toLowerCase().includes(q))
    .filter(c=>!hideLoopback||!c.loopback)
    .filter(c=>!activeOnly||num(c.recv_per_second)+num(c.sent_per_second)>0)
    .filter(c=>!hidePassive||!['LISTEN','TIME_WAIT','NONE'].includes(c.status))
    .sort((a,b)=>compare(a,b,networkSort.key,networkSort.direction));
  $('connection-visible-count').textContent=`показано ${rows.length}`;
  $('connections').innerHTML=rows.length?rows.map(c=>`<tr>
    <td><b>${esc(c.process)}</b><small class="sub">PID ${esc(c.pid||'—')} · ${esc(c.type)}</small></td>
    <td>${esc(endpoint(c.local))}</td><td>${esc(endpoint(c.remote))}</td><td>${esc(c.status)}</td>
    <td class="rate down">${c.traffic_available?`↓ ${fmtRate(c.recv_per_second)}`:'—'}</td>
    <td class="rate up">${c.traffic_available?`↑ ${fmtRate(c.sent_per_second)}`:'—'}</td>
    <td>${c.traffic_available?fmtBytes(c.bytes_all):'—'}</td>
  </tr>`).join(''):`<tr><td colspan="7" class="empty">Ничего не найдено</td></tr>`;
}

function renderFail2ban(fail2ban, meta){
  const jails=list(fail2ban.jails);
  $('f2b-status').textContent=fail2ban.running?'активен':'неактивен';
  if(!jails.length){
    $('fail2ban').innerHTML=`<div class="empty">${esc(fail2ban.error||'Jail не найдены')}</div>`;
    return;
  }
  const manager=meta.actions_enabled?`<form id="f2b-manager" class="f2b-manager">
    <select id="f2b-jail" aria-label="Fail2ban jail">${jails.map(j=>`<option value="${esc(j.name)}">${esc(j.name)}</option>`).join('')}</select>
    <input id="f2b-ip" type="text" inputmode="decimal" placeholder="IP-адрес, например 203.0.113.10" required />
    <button type="submit" class="danger">Добавить в бан</button>
    <button type="button" data-action="clear-action-token" class="ghost">Сбросить токен</button>
  </form>`:`<div class="read-only-note">Для добавления и удаления IP включи <code>SCOUT_ACTIONS_ENABLED=true</code>.</div>`;
  const body=jails.map(j=>{
    const banned=list(j.banned_ips);
    return `<div class="jail"><div class="jail-head"><span>${esc(j.name)}</span><span>${num(j.currently_banned)} банов</span></div>
      <div class="jail-meta">Ошибок сейчас: ${num(j.currently_failed)} · всего ошибок: ${num(j.total_failed)} · всего банов: ${num(j.total_banned)}</div>
      ${banned.length?`<div class="ip-list">${banned.map(ip=>`<span>${esc(ip)}${meta.actions_enabled?`<button title="Удалить из бана" data-action="unban" data-jail="${esc(j.name)}" data-ip="${esc(ip)}">×</button>`:''}</span>`).join('')}</div>`:'<div class="empty compact">Заблокированных IP нет</div>'}
    </div>`;
  }).join('');
  $('fail2ban').innerHTML=manager+`<div class="jails">${body}</div>`;
}

function render(data){
  state=obj(data);
  const meta=obj(state.meta), system=obj(state.system), memory=obj(system.memory), disk=obj(system.disk);
  const overview=obj(state.overview), ssh=obj(state.ssh), fail2ban=obj(state.fail2ban), network=obj(state.network), traffic=obj(state.traffic), processes=obj(state.processes);
  const warnings=list(state.warnings), sessions=list(ssh.sessions), events=list(ssh.events), jails=list(fail2ban.jails);

  $('version').textContent=`v${esc(meta.version || '—')}`;
  $('hostname').textContent=system.hostname || 'данные недоступны';
  $('mode').textContent=meta.read_only===false?'управление включено':'режим только чтения';
  const severity=warnings.some(w=>w.level==='critical')?'critical':warnings.some(w=>w.level==='warning')?'warning':'ok';
  $('status-dot').style.background=severity==='critical'?'var(--bad)':severity==='warning'?'var(--warn)':'var(--ok)';
  $('status-text').textContent=meta.partial?'Частичные данные':severity==='critical'?'Требуется проверка':severity==='warning'?'Предупреждение':'Работает';

  const cards=[['SSH сейчас',num(overview.ssh_sessions)],['Ошибки входа',num(overview.auth_failures)],['Успешные входы',num(overview.auth_successes)],['Заблокировано',num(overview.banned_ips)],['Соединения',num(overview.network_connections)]];
  $('overview').innerHTML=cards.map(([l,v])=>`<article class="card"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></article>`).join('');
  $('alerts').innerHTML=warnings.length?warnings.map(w=>`<div class="alert ${esc(w.level)}"><strong>${esc(w.title)}</strong><span>${esc(w.message)}</span></div>`).join(''):'';

  if(Object.keys(system).length){
    const metrics=[['CPU',num(system.cpu_percent)],['RAM',num(memory.percent)],['Диск',num(disk.percent)]];
    $('system').innerHTML=`<div class="metrics">${metrics.map(([l,v])=>`<div class="metric-row"><span>${l}</span><div class="bar"><i style="width:${Math.min(v,100)}%"></i></div><b>${v}%</b></div>`).join('')}<div class="metric-row"><span>Uptime</span><div>${fmtUp(system.uptime_seconds)}</div><b></b></div><div class="metric-row"><span>RAM</span><div>${fmtBytes(memory.used)} / ${fmtBytes(memory.total)}</div><b></b></div></div>`;
  } else sectionError('system','Не удалось получить системные показатели');

  const current=obj(traffic.current), total=obj(traffic.total), interfaces=list(traffic.interfaces);
  $('traffic').innerHTML=`<div class="traffic-grid"><div class="traffic-card"><span>Сейчас входящий</span><b>↓ ${fmtRate(current.recv_per_second)}</b></div><div class="traffic-card"><span>Сейчас исходящий</span><b>↑ ${fmtRate(current.sent_per_second)}</b></div><div class="traffic-card"><span>Получено с запуска ОС</span><b>${fmtBytes(total.bytes_recv)}</b></div><div class="traffic-card"><span>Отправлено с запуска ОС</span><b>${fmtBytes(total.bytes_sent)}</b></div></div>${interfaces.length?`<div class="interface-list">${interfaces.slice(0,5).map(i=>`<div><span>${esc(i.name)}</span><span>↓ ${fmtBytes(i.bytes_recv)} · ↑ ${fmtBytes(i.bytes_sent)}</span></div>`).join('')}</div>`:'<div class="empty">Сетевые интерфейсы не найдены</div>'}`;

  $('session-count').textContent=String(sessions.length);
  $('sessions').innerHTML=sessions.length?sessions.map(s=>`<tr><td>${esc(s.username)}</td><td>${esc(s.source_ip)}</td><td>${esc(s.terminal)}</td><td>${s.started_at?new Date(s.started_at).toLocaleString():'—'}</td><td>${meta.actions_enabled?`<button class="danger" data-action="disconnect" data-tty="${esc(s.terminal)}" data-user="${esc(s.username)}">Отключить</button>`:''}</td></tr>`).join(''):`<tr><td colspan="5" class="empty">Активных сессий нет</td></tr>`;
  $('events').innerHTML=events.length?events.slice(0,50).map(e=>`<tr><td><span class="badge ${e.type==='success'?'ok':'bad'}">${e.type==='success'?'успешно':'ошибка'}</span></td><td>${esc(e.user)}</td><td>${esc(e.ip)}</td><td>${esc(e.method)}</td><td>${meta.actions_enabled&&e.ip&&jails.length?`<button class="danger ghost" data-action="ban" data-jail="${esc(jails[0].name)}" data-ip="${esc(e.ip)}">Бан</button>`:''}</td></tr>`).join(''):`<tr><td colspan="5" class="empty">События не найдены или нет доступа к journal</td></tr>`;

  renderFail2ban(fail2ban,meta);
  $('network-count').textContent=String(num(network.summary?.total));
  $('network-traffic-count').textContent=`с трафиком ${num(network.summary?.with_traffic)}`;
  state.network=network; state.processes=processes;
  renderConnections(); renderProcessTraffic(); renderProcesses();
}

async function load(){
  try{
    const r=await fetch(`/api/dashboard?_=${Date.now()}`,{cache:'no-store'});
    if(r.status===401){ location.reload(); return; }
    const body=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(body.detail||`HTTP ${r.status}`);
    render(body);
  }catch(e){
    $('status-dot').style.background='var(--bad)'; $('status-text').textContent='Ошибка';
    $('alerts').innerHTML=`<div class="alert critical"><strong>Не удалось загрузить данные</strong><span>${esc(e.message)}</span></div>`;
  }
}

document.addEventListener('click',(event)=>{
  const button=event.target.closest('[data-action]'); if(!button) return;
  const kind=button.dataset.action;
  if(kind==='disconnect') action('/api/actions/ssh/disconnect',{tty:button.dataset.tty},`Отключить SSH-сессию пользователя ${button.dataset.user} на ${button.dataset.tty}?`);
  if(kind==='ban') action('/api/actions/fail2ban/ban',{jail:button.dataset.jail,ip:button.dataset.ip},`Заблокировать ${button.dataset.ip} через jail ${button.dataset.jail}?`);
  if(kind==='unban') action('/api/actions/fail2ban/unban',{jail:button.dataset.jail,ip:button.dataset.ip},`Удалить ${button.dataset.ip} из бана jail ${button.dataset.jail}?`);
  if(kind==='clear-action-token'){sessionStorage.removeItem('scoutActionToken');toast('Административный токен удалён из вкладки');}
});

document.addEventListener('submit',(event)=>{
  if(event.target.id!=='f2b-manager') return;
  event.preventDefault();
  const jail=$('f2b-jail').value;
  const ip=$('f2b-ip').value.trim();
  if(!ip) return;
  action('/api/actions/fail2ban/ban',{jail,ip},`Добавить ${ip} в бан jail ${jail}?`).then(()=>{$('f2b-ip').value='';});
});

$('process-filter').addEventListener('input',renderProcesses);
$('network-filter').addEventListener('input',renderConnections);
['hide-loopback','active-traffic-only','hide-passive'].forEach(id=>$(id).addEventListener('change',renderConnections));
document.querySelectorAll('[data-proc-sort]').forEach(el=>el.addEventListener('click',()=>{const key=el.dataset.procSort;processSort={key,direction:processSort.key===key?-processSort.direction:(['cpu_percent','memory_percent','pid'].includes(key)?-1:1)};renderProcesses();}));
document.querySelectorAll('[data-net-sort]').forEach(el=>el.addEventListener('click',()=>{const key=el.dataset.netSort;networkSort={key,direction:networkSort.key===key?-networkSort.direction:(['recv_per_second','sent_per_second','bytes_all'].includes(key)?-1:1)};renderConnections();}));

load(); setInterval(load,5000);
