'use strict';
const $ = s => document.querySelector(s);
const appBase = new URL('.', document.currentScript.src).pathname;
let csrf = '', state = null, inbounds = [], refreshing = false, toastTimer, loginMode = 'password', discoveredExisting = [], editingExisting = null;
let hostsData = null, editingHost = null, hostRoute = null;
function configureLogin(mode) {
  loginMode = mode;
  const native = mode === 'panel';
  $('#username-field').hidden = !native; $('#login-username').required = native;
  $('#twofactor-field').hidden = !native;
  $('#login-description').textContent = native ? 'با همان نام کاربری و رمز پنل ثنایی وارد شو.' : 'رمز مستقل Atlas را که هنگام نصب خصوصی دریافت کردی وارد کن.';
  $('#login-hint').textContent = native ? 'ورود قبلی ثنایی در همین مرورگر و همین آدرس، اینجا هم معتبر است.' : 'این نصب از ورود خصوصی Atlas استفاده می‌کند.';
}
const fa = n => Number(n).toLocaleString('fa-IR');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const flag = c => [...c].map(x => String.fromCodePoint(x.charCodeAt(0) + 127397)).join('');
function flagIcon(code) {
  const bands = {FR:['#243b8a','#fff','#ed3340'],NL:['#ae1c28','#fff','#21468b'],DE:['#151515','#d42628','#f4ca36'],IT:['#009246','#fff','#ce2b37'],PL:['#fff','#dc143c']};
  if (!bands[code]) return esc(flag(code));
  const colors=bands[code], vertical=['FR','IT'].includes(code), unit=(vertical?36:25)/colors.length;
  return `<svg viewBox="0 0 36 25" width="36" height="25" aria-label="${code}" role="img">${colors.map((color,i)=>`<rect x="${vertical?i*unit:0}" y="${vertical?0:i*unit}" width="${vertical?unit:36}" height="${vertical?25:unit}" fill="${color}"/>`).join('')}</svg>`;
}
function toast(message, error=false) { const el = $('#toast'); el.textContent = message; el.classList.toggle('error-toast', error); el.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => el.hidden = true, error ? 12000 : 6000); }
async function api(path, body) {
  const response = await fetch(appBase + 'api/' + path, {credentials:'same-origin', cache:'no-store', headers:body ? {'Content-Type':'application/json','X-Atlas-CSRF':csrf} : {}, method:body ? 'POST' : 'GET', body:body ? JSON.stringify(body) : undefined});
  const result = await response.json();
  if (result.mode) configureLogin(result.mode);
  if (!response.ok) { if (response.status === 401 && path !== 'login') showLogin(); throw Error(result.error || 'درخواست کامل نشد.'); }
  return result;
}
async function busy(button, task) {
  const original = button.textContent; button.disabled = true; button.textContent = 'کمی صبر کن…';
  try { return await task(); } catch (e) { toast(e.message, true); } finally { button.disabled = false; button.textContent = original; }
}
function view(name) {
  document.querySelectorAll('.view').forEach(el => el.hidden = el.id !== name);
  document.querySelectorAll('[data-view]').forEach(el => el.classList.toggle('active', el.dataset.view === name));
  $('#view-title').textContent = {overview:'نمای کلی',hosts:'میزبان‌ها و کانفیگ‌ها',settings:'اتصال و بازیابی',guide:'راهنمای شروع'}[name];
  if(name==='hosts') refreshHosts().catch(e=>toast(e.message,true));
  window.scrollTo({top:0, behavior:'smooth'});
}
function showLogin() { $('#shell').hidden = true; $('#login').hidden = false; state = null; }
async function enter() { $('#login').hidden = true; $('#shell').hidden = false; await refresh(); }
async function confirmAction(title, text) {
  $('#confirm-title').textContent = title; $('#confirm-text').textContent = text;
  const dialog = $('#confirm-dialog'); dialog.showModal();
  return new Promise(resolve => {
    const end = value => { dialog.close(); $('#confirm-no').onclick = null; $('#confirm-yes').onclick = null; dialog.oncancel = null; resolve(value); };
    $('#confirm-no').onclick = () => end(false); $('#confirm-yes').onclick = () => end(true); dialog.oncancel = event => { event.preventDefault(); end(false); };
  });
}
function render() {
  renderLicense(state.license);
  $('#preview-banner').hidden = !state.demo;
  $('#setup-banner').hidden = state.connected;
  $('#pending-banner').hidden = !state.pending;
  $('#add-route').disabled = !state.connected || state.pending;
  $('#empty-add').disabled = !state.connected || state.pending;
  $('#import-existing').hidden = !state.existing_available;
  $('#import-existing').disabled = !state.connected || state.pending;
  const enabled = state.routes.filter(r => r.enabled);
  const healthy = enabled.filter(r => state.status[r.id]?.healthy).length;
  const fallback = enabled.filter(r => ['backup','direct'].includes(state.status[r.id]?.state)).length;
  $('#count-total').textContent = fa(state.routes.length); $('#count-healthy').textContent = fa(healthy); $('#count-fallback').textContent = fa(fallback);
  $('#route-count').textContent = state.routes.length;
  $('#system-state').textContent = !state.connected ? 'منتظر اتصال پنل' : !enabled.length ? 'آمادهٔ ساخت مسیر' : healthy === enabled.length ? 'مسیرها بررسی شده‌اند' : 'در حال بررسی مسیرها';
  $('#empty').hidden = state.routes.length > 0;
  $('#routes').classList.toggle('existing-layout',state.routes.length>0 && state.routes.every(r=>r.kind==='existing'));
  $('#routes').innerHTML = state.routes.map(route => {
    const status = state.status[route.id] || {}, active = status.active || {};
    const key = !route.enabled ? 'disabled' : status.state || 'checking';
    const label = {primary:'متصل',backup:'خروجی پشتیبان',direct:'اینترنت سرور',offline:'در دسترس نیست',checking:'در حال بررسی',disabled:'غیرفعال'}[key] || key;
    const tone = key === 'primary' ? 'good' : ['backup','direct'].includes(key) ? 'backup' : key === 'offline' ? 'bad' : '';
    const country = state.countries[route.country] || route.name;
    if (route.kind === 'existing') {
      const caps = route.capabilities || [], actualCode = route.country || active.country || '';
      const title = route.provider === 'existing-psiphon' ? country : route.name === 'Cloudflare WARP' ? route.name : (state.countries[active.country] || route.name);
      const names = (route.bindings || []).map(b=>b.name);
      const controls = caps.includes('country') ? `<button class="icon-button" data-action="existing-edit" data-id="${route.id}" title="کشور و پشتیبان" aria-label="تنظیم مسیر موجود">⚙</button>` : '';
      const reconnect = caps.includes('reconnect') ? `<button class="icon-button" data-action="existing-reconnect" data-id="${route.id}" title="اتصال دوباره به خروجی" aria-label="اتصال دوباره">↻</button>` : '';
      return `<article class="route-card existing-card"><div class="card-top"><span class="flag">${/^[A-Z]{2}$/.test(actualCode) ? flagIcon(actualCode) : '🌐'}</span><span class="status-pill ${tone}">${label}</span></div><h3>${esc(title)}</h3><div class="card-subtitle"><span class="existing-badge">تنظیمات فعلی سرور</span> ${route.provider === 'existing-psiphon' ? 'Psiphon' : route.name === 'Cloudflare WARP' ? 'کشور خودکار' : 'خروجی مستقیم'}</div><div class="card-metrics"><div><span>تأخیر خروجی وب</span><b>${active.latency_ms != null ? esc(active.latency_ms)+' ms':'—'}</b></div><div><span>کشور فعلی</span><b>${esc(state.countries[active.country] || active.country || '—')}</b></div></div><div class="card-ip">${esc(active.ip || 'WAITING FOR A VERIFIED EXIT')}</div><div class="existing-bindings">${names.slice(0,2).map(n=>`<span>${esc(n)}</span>`).join('')}${names.length>2 ? `<small>و ${fa(names.length-2)} اتصال دیگر</small>`:''}</div><div class="card-footer"><button class="text-button card-host" data-action="host" data-id="${route.id}">${fa(names.length)} کانفیگ مرتبط ↗</button><div class="card-actions">${controls}${reconnect}<button class="icon-button" data-action="remove" data-id="${route.id}" title="خروج از فهرست Atlas؛ سرویس اصلی فعال می‌ماند" aria-label="خروج از فهرست مدیریت">×</button></div></div></article>`;
    }
    return `<article class="route-card"><div class="card-top"><span class="flag">${flagIcon(route.country)}</span><span class="status-pill ${tone}">${label}</span></div><h3>${esc(country)}</h3><div class="card-subtitle">${route.provider === 'psiphon' ? 'Psiphon · شخصی / دارای مجوز' : 'خروجی اختصاصی · SOCKS5'}</div><div class="card-metrics"><div><span>تأخیر خروجی وب</span><b>${active.latency_ms != null ? esc(active.latency_ms)+' ms' : '—'}</b></div><div><span>کشور فعلی</span><b>${esc(active.country ? state.countries[active.country] || active.country : '—')}</b></div></div><div class="card-ip">${esc(active.ip || 'WAITING FOR A VERIFIED EXIT')}</div><div class="card-footer"><button class="text-button card-host" data-action="host" data-id="${route.id}">اطلاعات Host ↗</button><div class="card-actions"><button class="icon-button" data-action="reconnect" data-id="${route.id}" title="اتصال دوباره / بررسی خروجی" aria-label="اتصال دوباره" ${!route.enabled ? 'disabled' : ''}>↻</button><button class="icon-button" data-action="toggle" data-id="${route.id}" title="${route.enabled ? 'توقف مسیر' : 'فعال‌کردن مسیر'}" aria-label="تغییر وضعیت">${route.enabled ? 'Ⅱ' : '▷'}</button><button class="icon-button" data-action="remove" data-id="${route.id}" title="حذف مسیر" aria-label="حذف مسیر">×</button></div></div></article>`;
  }).join('');
  $('#events').innerHTML = state.events.length ? state.events.slice(0,6).map(event => `<div class="event"><i></i><span>${esc(event.message)}</span><time>${new Date(event.at*1000).toLocaleTimeString('fa-IR', {hour:'2-digit',minute:'2-digit'})}</time></div>`).join('') : '<p>رویداد تازه‌ای ثبت نشده است.</p>';
  if (document.activeElement !== $('#panel-url') && !$('#panel-url').value) $('#panel-url').value = state.panel_url;
  $('#engine-state').textContent = state.engine_installed ? '● موتور مستقل Atlas نصب است.' : state.external_engine_routes ? `● موتور قبلی سرور برای ${fa(state.external_engine_routes)} مسیر شناسایی شد. موتور مستقل Atlas نصب نیست و برای مسیرهای فعلی لازم نیست.` : '○ موتور مستقل Atlas هنوز نصب نشده است؛ فقط برای ساخت مسیر جدید Psiphon لازم می‌شود.';
  $('#engine-install').textContent = state.engine_installed ? 'بررسی و نصب دوباره' : 'نصب موتور بررسی‌شده';
  const selected = $('#backup-list').value;
  $('#backup-list').innerHTML = state.backups.length ? state.backups.map(name => `<option value="${esc(name)}">${esc(name)}</option>`).join('') : '<option value="">هنوز پشتیبان نداریم</option>';
  if (state.backups.includes(selected)) $('#backup-list').value = selected;
  $('#restore').disabled = !state.backups.length || state.pending; $('#recover').disabled = !state.pending;
}
async function refresh() { if (refreshing || $('#shell').hidden) return; refreshing = true; try { state = await api('state'); render(); } catch(e) { toast(e.message,true); } finally { refreshing=false; } }
async function openAdd() {
  if (!state?.connected) {view('settings'); return;}
  if (state.pending) return toast('ابتدا عملیات نیمه‌تمام را بازیابی کن.',true);
  try {
    inbounds = await api('inbounds');
    $('#country').innerHTML = Object.entries(state.countries).map(([code,name]) => `<option value="${code}">${esc(name)} ${flag(code)}</option>`).join('');
    $('#inbound').innerHTML = inbounds.filter(r => ['vless','vmess','trojan','shadowsocks'].includes(r.protocol)).map(row => `<option value="${row.id}">${esc(row.remark || row.tag)} · ${esc(row.port)}</option>`).join('');
    if (!$('#inbound').options.length) return toast('یک اینباند TCP فعال در پنل لازم است.',true);
    $('#route-form').reset(); providerChanged(); $('#route-dialog').showModal();
  } catch(e) {toast(e.message,true);}
}
function providerChanged() { const ps = $('input[name=provider]:checked').value === 'psiphon'; $('#psiphon-fields').hidden = !ps; $('#socks-fields').hidden = ps; $('#proxy').required = !ps; }
function hostInfo(id) {
  const route = state.routes.find(r => r.id === id); if (!route) return;
  hostRoute = route;
  $('#new-host-instructions').hidden = route.kind === 'existing';
  $('#existing-host-instructions').hidden = route.kind !== 'existing';
  if (route.kind === 'existing') {
    $('#host-details').innerHTML = (route.bindings || []).map(binding=>`<div class="host-row"><span>${esc(binding.name)}</span><code>${esc((binding.addresses || []).join(' / ') || 'ورودی اصلی')} · ${esc(binding.port || '')}</code></div>`).join('') || '<p>نام Host مرتبط پیدا نشد؛ تنظیمات ورودی در ثنایی حفظ شده‌اند.</p>';
    $('#host-dialog h2').textContent = 'اتصال‌های فعلی این خروجی';
    $('#host-dialog').showModal(); return;
  }
  $('#host-dialog h2').textContent = 'کشور را به اشتراک اضافه کن.';
  const values = [['نام Host',route.name],['اینباند موجود',route.inbound_tag],['پورت Host',String(route.entry_port)],['امنیت','همان اینباند / same']];
  $('#host-details').innerHTML = values.map(([key,value]) => `<div class="host-row"><span>${esc(key)}</span><code>${esc(value)}</code><button class="icon-button copy" data-copy="${esc(value)}" title="کپی" aria-label="کپی">⧉</button></div>`).join('');
  $('#host-dialog').showModal();
}
async function refreshHosts() {
  $('#hosts-demo').hidden=!state?.demo;
  hostsData=await api('hosts'); $('#host-count').textContent=fa(hostsData.groups.length);
  $('#host-pending').hidden=!hostsData.pending; $('#host-add').disabled=hostsData.pending;
  $('#hosts-list').innerHTML=hostsData.groups.map(h=>{
    const labels=(h.inboundIds||[]).map(id=>hostsData.inbounds.find(x=>x.id===id)?.remark || String(id));
    return `<article class="panel-box host-card"><div class="card-top"><span class="eyebrow">SUBSCRIPTION HOST</span><span class="status-pill ${h.isDisabled?'bad':'good'}">${h.isDisabled?'غیرفعال':'فعال در اشتراک'}</span></div><h3>${esc(h.remark)}</h3><p>${labels.map(esc).join(' · ')}</p><div class="host-address-list" dir="ltr">${(h.hosts||[]).map(x=>`<code>${esc(x)}</code>`).join('')}</div><div class="card-footer"><small>${esc(h.security||'same')} · ${esc(h.port||'پورت اینباند')}</small><div class="card-actions"><button class="text-button" data-host-action="edit" data-host-id="${esc(h.groupId)}" ${hostsData.pending?'disabled':''}>ویرایش</button><button class="text-button" data-host-action="clone" data-host-id="${esc(h.groupId)}" ${hostsData.pending?'disabled':''}>کپی و افزودن</button><button class="text-button danger-text" data-host-action="delete" data-host-id="${esc(h.groupId)}" ${hostsData.pending?'disabled':''}>حذف</button></div></div></article>`;
  }).join('') || '<p>هنوز Hostی ثبت نشده است. افزودن کانفیگ را بزن.</p>';
}
function fillHost(h) {
  $('#host-name').value=h.remark||''; $('#host-addresses').value=(h.hosts||[]).join('\n');
  $('#host-port').value=h.port||0; $('#host-security').value=h.security||'same';
  for(const option of $('#host-inbounds').options) option.selected=(h.inboundIds||[]).includes(Number(option.value));
  $('#host-sni').value=h.sni||''; $('#host-header').value=h.hostHeader||''; $('#host-path').value=h.path||'';
  $('#host-enabled').checked=!h.isDisabled; firstHostWarning();
}
function firstHostWarning() {
  const ids=[...$('#host-inbounds').selectedOptions].map(x=>Number(x.value));
  $('#host-first-warning').hidden=!!editingHost || !ids.some(id=>!hostsData.groups.some(h=>h.inboundIds.includes(id)));
}
async function openHost(id=null,clone=false,route=null) {
  if(!hostsData) await refreshHosts(); if(hostsData.pending) return toast('ابتدا عملیات نیمه‌تمام Host را بررسی کن.',true);
  const selected=hostsData.groups.find(h=>h.groupId===id);editingHost=clone?null:selected||null;
  $('#host-edit-form').reset(); $('#host-edit-title').textContent=editingHost?'ویرایش کانفیگ':'افزودن کانفیگ';
  $('#host-template').innerHTML='<option value="">تنظیمات اینباند / ارث‌بری</option>'+hostsData.groups.map(h=>`<option value="${esc(h.groupId)}">${esc(h.remark)} · ${esc((h.hosts||[])[0]||'')}</option>`).join('');
  $('#host-template').disabled=!!editingHost; $('#host-template').value=clone?id:'';
  $('#host-inbounds').innerHTML=hostsData.inbounds.map(i=>`<option value="${i.id}">${esc(i.remark||i.tag)} · ${i.port}</option>`).join('');
  fillHost(selected||{security:'same',inboundIds:route?[route.inbound_id]:[],port:route?.entry_port||0,remark:route?.name||''});
  if(clone) $('#host-name').value='Copy '+selected.remark;
  $('#host-edit-dialog').showModal();
}
$('#host-add').onclick=()=>busy($('#host-add'),()=>openHost());
$('#hosts-refresh').onclick=()=>busy($('#hosts-refresh'),refreshHosts);
$('#host-manage').onclick=async()=>{ $('#host-dialog').close();view('hosts');await refreshHosts();if(hostRoute?.kind!=='existing')await openHost(null,false,hostRoute); };
$('#host-inbounds').onchange=firstHostWarning;
$('#host-template').onchange=()=>{const h=hostsData.groups.find(x=>x.groupId===$('#host-template').value);if(h)fillHost(h);};
$('#host-edit-form').onsubmit=async event=>{
  event.preventDefault();
  if(!$('#host-first-warning').hidden && !await confirmAction('اولین Host این اینباند ثبت شود؟','این گزینه جای ورودی خودکار فعلی را در اشتراک می‌گیرد. آدرس قبلی را هم به‌عنوان Host نگه دار تا کاربران آن را از دست ندهند.')) return;
  const values={remark:$('#host-name').value.trim(),hosts:$('#host-addresses').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),port:Number($('#host-port').value),security:$('#host-security').value,inboundIds:[...$('#host-inbounds').selectedOptions].map(x=>Number(x.value)),sni:$('#host-sni').value.trim(),hostHeader:$('#host-header').value.trim(),path:$('#host-path').value,isDisabled:!$('#host-enabled').checked};
  const template=hostsData.groups.find(x=>x.groupId===$('#host-template').value);
  const payload={operation:operationId(),values,...(editingHost?{id:editingHost.groupId,revision:editingHost.revision}:template?{template_id:template.groupId,template_revision:template.revision}:{})};
  await busy($('#host-edit-form button[type=submit]'),async()=>{
    try {await api('hosts/'+(editingHost?'update':'create'),payload);$('#host-edit-dialog').close();toast('کانفیگ در پنل ثبت شد؛ اشتراک Happ را به‌روز کنید.');}
    finally {await refreshHosts();await refresh();}
  });
};
$('#hosts-list').onclick=async event=>{
  const button=event.target.closest('[data-host-action]');if(!button)return;
  const host=hostsData.groups.find(x=>x.groupId===button.dataset.hostId);if(!host)return;
  if(button.dataset.hostAction==='delete') {
    if(!await confirmAction('این Host از اشتراک حذف شود؟','کاربران عضو اینباند هم این گزینه را پس از به‌روزرسانی از دست می‌دهند. کاربر و حجم حذف نمی‌شود؛ قانون اختصاصی وابسته به این Host هم ممکن است تحت تأثیر قرار بگیرد.'))return;
    await busy(button,async()=>{try{await api('hosts/delete',{id:host.groupId,revision:host.revision,operation:operationId()});toast('Host حذف شد؛ اشتراک را تازه کنید.');}finally{await refreshHosts();await refresh();}});
  } else await busy(button,()=>openHost(host.groupId,button.dataset.hostAction==='clone'));
};
$('#host-recover').onclick=()=>busy($('#host-recover'),async()=>{const result=await api('hosts/recover',{});await refreshHosts();await refresh();toast(result.applied?'ثبت Host تأیید شد.':'تغییری ثبت نشده؛ می‌توانی دوباره اقدام کنی.');});

document.querySelectorAll('[data-view]').forEach(button => button.onclick = () => view(button.dataset.view));
document.querySelectorAll('.close-dialog').forEach(button => button.onclick = () => button.closest('dialog').close());
document.querySelectorAll('input[name=provider]').forEach(el => el.onchange = providerChanged);
$('#setup-button').onclick = () => view('settings'); $('#add-route').onclick = openAdd; $('#empty-add').onclick = openAdd;
$('#import-existing').onclick = async () => busy($('#import-existing'),async () => {
  const result=await api('existing'); discoveredExisting=result.routes;
  const imported=new Set(state.routes.map(r=>r.id));
  $('#existing-import-list').innerHTML=discoveredExisting.map(route=>`<label class="existing-import-row"><input type="checkbox" value="${route.id}" ${imported.has(route.id)?'disabled':''} checked><span><b>${esc(route.name)}</b><small>${fa((route.bindings||[]).length)} کانفیگ مرتبط${imported.has(route.id)?' · قبلاً وارد شده':''}</small></span></label>`).join('') || '<p>خروجی پشتیبانی‌شده‌ای پیدا نشد.</p>';
  $('#existing-import-confirm').disabled=!discoveredExisting.some(r=>!imported.has(r.id));
  $('#existing-import-dialog').showModal();
});
$('#existing-import-confirm').onclick = async () => busy($('#existing-import-confirm'),async () => {
  const ids=[...document.querySelectorAll('#existing-import-list input:checked:not(:disabled)')].map(el=>el.value);
  await api('existing/import',{ids}); $('#existing-import-dialog').close(); await refresh(); toast('تنظیمات فعلی وارد شد؛ سرویس‌ها و اشتراک‌ها ادامه دارند.');
});
async function openExistingEdit(id) {
  const result=await api('existing'); editingExisting=result.routes.find(r=>r.id===id);
  if(!editingExisting) throw Error('مسیر موجود پیدا نشد.');
  $('#existing-edit-title').textContent='تنظیم '+(state.countries[editingExisting.country] || editingExisting.name);
  $('#existing-country').innerHTML=Object.entries(state.countries).map(([code,name])=>`<option value="${code}">${esc(name)} ${flag(code)}</option>`).join('');
  $('#existing-country').value=editingExisting.country;
  $('#existing-fallback').checked=!!editingExisting.fallback_enabled;
  $('#existing-restore').disabled=!editingExisting.last_backup;
  $('#existing-edit-form button[type=submit]').disabled=!!editingExisting.pending;
  $('#existing-edit-bindings').innerHTML=(editingExisting.bindings||[]).map(b=>`<p class="existing-binding-label">${esc(b.name)}</p>`).join('');
  $('#existing-edit-dialog').showModal();
}
const operationId = () => crypto.randomUUID ? crypto.randomUUID().replaceAll('-','') : [...crypto.getRandomValues(new Uint8Array(16))].map(v=>v.toString(16).padStart(2,'0')).join('');
$('#existing-edit-form').onsubmit = async event => {
  event.preventDefault(); if(!editingExisting) return;
  const country=$('#existing-country').value, fallback=$('#existing-fallback').checked;
  if(country!==editingExisting.country && !await confirmAction('کشور این خروجی عوض شود؟','اتصال‌های باز همین خروجی ممکن است دوباره متصل شوند. نام Hostهای مرتبط هم با کشور انتخاب‌شده هماهنگ می‌شود.')) return;
  await busy($('#existing-edit-form button[type=submit]'),async () => {
    await api('existing/configure',{id:editingExisting.id,revision:editingExisting.revision,country,fallback_enabled:fallback,operation:operationId()});
    $('#existing-edit-dialog').close(); await refresh(); toast('تنظیم خروجی ذخیره شد؛ کشور واقعی پس از تست روی کارت نمایش داده می‌شود.');
  });
};
$('#existing-restore').onclick = async () => {
  if(!editingExisting?.last_backup || !await confirmAction('تنظیم قبلی همین خروجی برگردد؟','کشور و پشتیبان قبلی برمی‌گردند. اتصال‌های باز همین خروجی ممکن است دوباره ساخته شوند.')) return;
  await busy($('#existing-restore'),async () => {await api('existing/restore',{id:editingExisting.id,revision:editingExisting.revision,backup:editingExisting.last_backup,operation:operationId()});$('#existing-edit-dialog').close();await refresh();toast('تنظیم قبلی خروجی برگشت داده شد.');});
};
$('#login-form').onsubmit = async event => { event.preventDefault(); $('#login-error').textContent = ''; await busy($('#login-form button'), async () => { try { const result = await api('login',{username:$('#login-username').value,password:$('#login-password').value,twoFactorCode:$('#login-twofactor').value}); csrf = result.csrf; $('#login-password').value = ''; $('#login-twofactor').value = ''; await enter(); } catch(e) {$('#login-error').textContent=e.message; throw e;} }); };
$('#logout').onclick = async () => { try {await api('logout',{}); showLogin();} catch(e) {toast(e.message,true);} };
$('#panel-form').onsubmit = async event => {event.preventDefault(); await busy($('#panel-form button'),async () => {await api('connect',{url:$('#panel-url').value,token:$('#panel-token').value}); $('#panel-token').value=''; toast('پنل با موفقیت متصل شد. حالا کشور را اضافه کن.'); await refresh(); view('overview');});};
$('#route-form').onsubmit = async event => {event.preventDefault(); const provider=$('input[name=provider]:checked').value; if(provider==='psiphon' && !state.engine_installed) return toast('ابتدا از تنظیمات، موتور Psiphon را نصب کن.',true); await busy($('#route-form button[type=submit]'),async () => {const result=await api('routes/add',{country:$('#country').value,provider,inbound_id:Number($('#inbound').value),entry_port:$('#entry-port').value ? Number($('#entry-port').value) : null,proxy:$('#proxy').value,fallback_proxy:$('#fallback-proxy').value,allow_direct_fallback:$('#direct-fallback').checked,psiphon_authorized:$('#psiphon-consent').checked}); $('#route-dialog').close(); $('#proxy').value=''; $('#fallback-proxy').value=''; toast('مسیر ساخته شد. حالا Host آن را به پنل اضافه کن.'); await refresh(); hostInfo(result.id); });};
$('#routes').onclick = async event => {
  const button=event.target.closest('button[data-action]'); if (!button) return; const {action,id}=button.dataset;
  if(action==='host') return hostInfo(id);
  const route=state.routes.find(r=>r.id===id);
  if(action==='existing-edit') {try {await openExistingEdit(id);} catch(e) {toast(e.message,true);} return;}
  if(action==='existing-reconnect') {
    const warning=route.name==='Cloudflare WARP' ? 'این سرویس بین چند مسیر مشترک است. اتصال‌های WARP و تماس‌های UDP مربوط ممکن است قطع و دوباره وصل شوند.' : 'اتصال‌های باز همین خروجی ممکن است قطع و دوباره برقرار شوند. IP تازه تضمین نمی‌شود.';
    if(!await confirmAction('خروجی دوباره متصل شود؟',warning)) return;
    return busy(button,async()=>{const fresh=(await api('existing')).routes.find(r=>r.id===id);await api('existing/reconnect',{id,revision:fresh.revision,operation:operationId()});await refresh();toast('اتصال دوباره درخواست شد؛ وضعیت پس از بررسی تازه می‌شود.');});
  }
  if(action==='remove' && !await confirmAction(route?.kind==='existing'?'از فهرست مدیریت خارج شود؟':'این مسیر حذف شود؟',route?.kind==='existing'?'فقط از فهرست Atlas خارج می‌شود؛ سرویس، تنظیمات، Hostها و اتصال‌های اصلی فعال می‌مانند.':'ورودی و قانون همین مسیر حذف می‌شود. Host مربوط را هم در پنل غیرفعال یا حذف کن. کاربران و مسیرهای دیگر باقی می‌مانند.')) return;
  if(action==='reconnect' && !await confirmAction('دوباره به خروجی وصل شویم؟','اتصال‌های باز همین خروجی ممکن است قطع شوند. کشور و IP تازه تا بعد از بررسی تأیید نمی‌شود.')) return;
  await busy(button,async () => {await api('routes/'+action,{id}); await refresh(); toast('درخواست انجام شد. وضعیت جدید پس از بررسی نمایش داده می‌شود.');});
};
$('#host-details').onclick = async event => {const button=event.target.closest('[data-copy]'); if(button) {try {await navigator.clipboard.writeText(button.dataset.copy); toast('کپی شد.');} catch {toast('کپی خودکار ممکن نشد؛ مقدار را انتخاب و کپی کن.',true);}}};
$('#check-all').onclick = async () => busy($('#check-all'),async () => {await api('check',{}); toast('بررسی واقعی مسیرها شروع شد؛ نتیجه روی کارت‌ها نمایش داده می‌شود.');});
$('#engine-install').onclick = async () => {if(!$('#engine-consent').checked) return toast('ابتدا شرایط استفاده را بخوان و تأیید کن.',true); await busy($('#engine-install'),async () => {await api('engine',{authorized:true}); toast('موتور رسمی دریافت و بررسی شد.'); await refresh();});};
$('#restore').onclick = async () => {if(!await confirmAction('مسیرهای این نسخه بازیابی شوند؟','فقط تنظیمات مسیرهای Atlas برمی‌گردد. اتصال‌های همین مسیرها ممکن است دوباره ساخته شوند.')) return; await busy($('#restore'),async () => {await api('restore',{backup:$('#backup-list').value}); await refresh(); toast('مسیرهای Atlas بازیابی شد.');});};
$('#recover').onclick = async () => busy($('#recover'),async () => {await api('recover',{}); await refresh(); toast('تغییرهای عملیات نیمه‌تمام برگشت داده شد.');});
(async () => {try {const session=await api('session'); csrf=session.csrf; if(session.authenticated) await enter(); else showLogin();} catch(e) {showLogin(); $('#login-error').textContent=e.message;}})();
setInterval(refresh,6000);

const LICENSE_PRODUCT="Atlas";
const licenseRequest=(action,body)=>api("license/"+action,body);
const licenseNotice=toast;

function renderLicense(value) {
  const info=value||{status:'missing',can_manage:false};
  const names={active:'فعال',missing:'فعال نشده',invalid:'نامعتبر',revoked:'متوقف شده',expired:'نیازمند تمدید'};
  document.querySelector('#license-product').textContent=LICENSE_PRODUCT;
  document.querySelector('#license-box').dataset.state=info.status;
  document.querySelector('#license-status').textContent=(names[info.status]||info.status)+(info.permanent?' · دائمی':info.expires_at?' · پایان: '+new Date(info.expires_at*1000).toLocaleString('fa-IR'):'')+(info.offline_grace?' · استفاده از مهلت آفلاین':'')+(info.last_error?' · '+info.last_error:'');
}
document.querySelector('#license-form').onsubmit=async event=>{
  event.preventDefault();const button=event.target.querySelector('button');button.disabled=true;
  try{const value=await licenseRequest('activate',{key:document.querySelector('#license-key').value,new_installation:document.querySelector('#license-new').checked});document.querySelector('#license-key').value='';document.querySelector('#license-new').checked=false;renderLicense(value);licenseNotice('لایسنس فعال شد.');}catch(error){licenseNotice(error.message,true);}finally{button.disabled=false;}
};
document.querySelector('#license-refresh').onclick=async event=>{
  event.target.disabled=true;try{renderLicense(await licenseRequest('refresh',{}));licenseNotice('وضعیت اعتبار بررسی شد.');}catch(error){licenseNotice(error.message,true);}finally{event.target.disabled=false;}
};
