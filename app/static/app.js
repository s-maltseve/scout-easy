const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmtBytes = (n) => { const u=['Б','КБ','МБ','ГБ','ТБ']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++} return `${n.toFixed(i?1:0)} ${u[i]}`; };
const fmtUp = (s) => { const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60); return `${d}д ${h}ч ${m}м`; };
const endpoint = (a) => a ? `${esc(a.ip)}:${esc(a.port)}` : '—';

function render(data){
  $('version').textContent = `v${data.meta.version}`;
  $('hostname').textContent = data.system.hostname;
  $('status-dot').style.background = data.warnings.some(w=>w.level==='critical') ? 'var(--bad)' : data.warnings.some(w=>w.level==='warning') ? 'var(--warn)' : 'var(--ok)';
  $('status-text').textContent = data.warnings.some(w=>w.level==='critical') ? 'Требуется проверка' : 'Работает';

  const cards = [
    ['SSH сейчас',data.overview.ssh_sessions],['Ошибки входа',data.overview.auth_failures],['Успешные входы',data.overview.auth_successes],['Заблокировано',data.overview.banned_ips],['Соединения',data.overview.network_connections]
  ];
  $('overview').innerHTML = cards.map(([l,v])=>`<article class="card"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></article>`).join('');
  $('alerts').innerHTML = data.warnings.map(w=>`<div class="alert ${esc(w.level)}"><strong>${esc(w.title)}</strong><span>${esc(w.message)}</span></div>`).join('');

  const metrics=[['CPU',data.system.cpu_percent],['RAM',data.system.memory.percent],['Диск',data.system.disk.percent]];
  $('system').innerHTML=`<div class="metrics">${metrics.map(([l,v])=>`<div class="metric-row"><span>${l}</span><div class="bar"><i style="width:${Math.min(v,100)}%"></i></div><b>${v}%</b></div>`).join('')}<div class="metric-row"><span>Uptime</span><div>${fmtUp(data.system.uptime_seconds)}</div><b></b></div><div class="metric-row"><span>RAM</span><div>${fmtBytes(data.system.memory.used)} / ${fmtBytes(data.system.memory.total)}</div><b></b></div></div>`;

  $('session-count').textContent=`${data.ssh.sessions.length}`;
  $('sessions').innerHTML=data.ssh.sessions.length?data.ssh.sessions.map(s=>`<tr><td>${esc(s.username)}</td><td>${esc(s.source_ip)}</td><td>${esc(s.terminal)}</td><td>${new Date(s.started_at).toLocaleString()}</td></tr>`).join(''):`<tr><td colspan="4" class="empty">Активных сессий нет</td></tr>`;
  $('events').innerHTML=data.ssh.events.length?data.ssh.events.slice(0,50).map(e=>`<tr><td><span class="badge ${e.type==='success'?'ok':'bad'}">${e.type==='success'?'успешно':'ошибка'}</span></td><td>${esc(e.user)}</td><td>${esc(e.ip)}</td><td>${esc(e.method)}</td></tr>`).join(''):`<tr><td colspan="4" class="empty">События не найдены или нет доступа к journal</td></tr>`;

  $('f2b-status').textContent=data.fail2ban.running?'активен':'неактивен';
  $('fail2ban').innerHTML=data.fail2ban.jails?.length?`<div class="jails">${data.fail2ban.jails.map(j=>`<div class="jail"><div class="jail-head"><span>${esc(j.name)}</span><span>${j.currently_banned} банов</span></div><div class="jail-meta">Ошибок сейчас: ${j.currently_failed} · всего ошибок: ${j.total_failed} · всего банов: ${j.total_banned}${j.banned_ips.length?`<br>IP: ${j.banned_ips.map(esc).join(', ')}`:''}</div></div>`).join('')}</div>`:`<div class="empty">${esc(data.fail2ban.error || 'Jail не найдены')}</div>`;

  $('network-count').textContent=`${data.network.summary?.total||0}`;
  $('connections').innerHTML=data.network.connections.length?data.network.connections.slice(0,100).map(c=>`<tr><td>${esc(c.process)} <small>${c.pid||''}</small></td><td>${endpoint(c.local)}</td><td>${endpoint(c.remote)}</td><td>${esc(c.status)}</td></tr>`).join(''):`<tr><td colspan="4" class="empty">Соединения не получены</td></tr>`;
  $('processes').innerHTML=data.processes.top.slice(0,40).map(p=>`<tr><td>${p.pid}</td><td title="${esc(p.cmdline)}">${esc(p.name)}</td><td>${p.cpu_percent}%</td><td>${p.memory_percent}%</td></tr>`).join('');
}

async function load(){
  try {
    const r=await fetch('/api/dashboard',{cache:'no-store'});
    if(!r.ok) throw new Error(`${r.status} ${await r.text()}`);
    render(await r.json());
  } catch(e){ $('status-dot').style.background='var(--bad)'; $('status-text').textContent='Ошибка'; $('alerts').innerHTML=`<div class="alert critical"><strong>Не удалось загрузить данные</strong><span>${esc(e.message)}</span></div>`; }
}
load(); setInterval(load,5000);
