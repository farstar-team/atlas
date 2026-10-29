'use strict';
const $ = s => document.querySelector(s);
const appBase = new URL('.', document.currentScript.src).pathname;
let csrf = '', state = null, inbounds = [], refreshing = false, toastTimer, loginMode = 'password';
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
  $('#view-title').textContent = {overview:'نمای کلی',settings:'اتصال و بازیابی',guide:'راهنمای شروع'}[name];
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
  $('#preview-banner').hidden = !state.demo;
  $('#setup-banner').hidden = state.connected;
  $('#pending-banner').hidden = !state.pending;
  $('#add-route').disabled = !state.connected || state.pending;
  $('#empty-add').disabled = !state.connected || state.pending;
  const enabled = state.routes.filter(r => r.enabled);
  const healthy = enabled.filter(r => state.status[r.id]?.healthy).length;
  const fallback = enabled.filter(r => ['backup','direct'].includes(state.status[r.id]?.state)).length;
  $('#count-total').textContent = fa(state.routes.length); $('#count-healthy').textContent = fa(healthy); $('#count-fallback').textContent = fa(fallback);
  $('#route-count').textContent = state.routes.length;
  $('#system-state').textContent = !state.connected ? 'منتظر اتصال پنل' : !enabled.length ? 'آمادهٔ ساخت مسیر' : healthy === enabled.length ? 'مسیرها بررسی شده‌اند' : 'در حال بررسی مسیرها';
  $('#empty').hidden = state.routes.length > 0;
  $('#routes').innerHTML = state.routes.map(route => {
    const status = state.status[route.id] || {}, active = status.active || {};
    const key = !route.enabled ? 'disabled' : status.state || 'checking';
    const label = {primary:'متصل',backup:'خروجی پشتیبان',direct:'اینترنت سرور',offline:'در دسترس نیست',checking:'در حال بررسی',disabled:'غیرفعال'}[key] || key;
    const tone = key === 'primary' ? 'good' : ['backup','direct'].includes(key) ? 'backup' : key === 'offline' ? 'bad' : '';
    const country = state.countries[route.country];
    return `<article class="route-card"><div class="card-top"><span class="flag">${flagIcon(route.country)}</span><span class="status-pill ${tone}">${label}</span></div><h3>${esc(country)}</h3><div class="card-subtitle">${route.provider === 'psiphon' ? 'Psiphon · شخصی / دارای مجوز' : 'خروجی اختصاصی · SOCKS5'}</div><div class="card-metrics"><div><span>تأخیر خروجی وب</span><b>${active.latency_ms != null ? esc(active.latency_ms)+' ms' : '—'}</b></div><div><span>کشور فعلی</span><b>${esc(active.country ? state.countries[active.country] || active.country : '—')}</b></div></div><div class="card-ip">${esc(active.ip || 'WAITING FOR A VERIFIED EXIT')}</div><div class="card-footer"><button class="text-button card-host" data-action="host" data-id="${route.id}">اطلاعات Host ↗</button><div class="card-actions"><button class="icon-button" data-action="reconnect" data-id="${route.id}" title="اتصال دوباره / بررسی خروجی" aria-label="اتصال دوباره" ${!route.enabled ? 'disabled' : ''}>↻</button><button class="icon-button" data-action="toggle" data-id="${route.id}" title="${route.enabled ? 'توقف مسیر' : 'فعال‌کردن مسیر'}" aria-label="تغییر وضعیت">${route.enabled ? 'Ⅱ' : '▷'}</button><button class="icon-button" data-action="remove" data-id="${route.id}" title="حذف مسیر" aria-label="حذف مسیر">×</button></div></div></article>`;
  }).join('');
  $('#events').innerHTML = state.events.length ? state.events.slice(0,6).map(event => `<div class="event"><i></i><span>${esc(event.message)}</span><time>${new Date(event.at*1000).toLocaleTimeString('fa-IR', {hour:'2-digit',minute:'2-digit'})}</time></div>`).join('') : '<p>رویداد تازه‌ای ثبت نشده است.</p>';
  if (document.activeElement !== $('#panel-url') && !$('#panel-url').value) $('#panel-url').value = state.panel_url;
  $('#engine-state').textContent = state.engine_installed ? '● موتور بررسی‌شده نصب است.' : '○ هنوز نصب نشده است.';
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
  const values = [['نام Host',route.name],['اینباند موجود',route.inbound_tag],['پورت Host',String(route.entry_port)],['امنیت','همان اینباند / same']];
  $('#host-details').innerHTML = values.map(([key,value]) => `<div class="host-row"><span>${esc(key)}</span><code>${esc(value)}</code><button class="icon-button copy" data-copy="${esc(value)}" title="کپی" aria-label="کپی">⧉</button></div>`).join('');
  $('#host-dialog').showModal();
}
document.querySelectorAll('[data-view]').forEach(button => button.onclick = () => view(button.dataset.view));
document.querySelectorAll('.close-dialog').forEach(button => button.onclick = () => button.closest('dialog').close());
document.querySelectorAll('input[name=provider]').forEach(el => el.onchange = providerChanged);
$('#setup-button').onclick = () => view('settings'); $('#add-route').onclick = openAdd; $('#empty-add').onclick = openAdd;
$('#login-form').onsubmit = async event => { event.preventDefault(); $('#login-error').textContent = ''; await busy($('#login-form button'), async () => { try { const result = await api('login',{username:$('#login-username').value,password:$('#login-password').value,twoFactorCode:$('#login-twofactor').value}); csrf = result.csrf; $('#login-password').value = ''; $('#login-twofactor').value = ''; await enter(); } catch(e) {$('#login-error').textContent=e.message; throw e;} }); };
$('#logout').onclick = async () => { try {await api('logout',{}); showLogin();} catch(e) {toast(e.message,true);} };
$('#panel-form').onsubmit = async event => {event.preventDefault(); await busy($('#panel-form button'),async () => {await api('connect',{url:$('#panel-url').value,token:$('#panel-token').value}); $('#panel-token').value=''; toast('پنل با موفقیت متصل شد. حالا کشور را اضافه کن.'); await refresh(); view('overview');});};
$('#route-form').onsubmit = async event => {event.preventDefault(); const provider=$('input[name=provider]:checked').value; if(provider==='psiphon' && !state.engine_installed) return toast('ابتدا از تنظیمات، موتور Psiphon را نصب کن.',true); await busy($('#route-form button[type=submit]'),async () => {const result=await api('routes/add',{country:$('#country').value,provider,inbound_id:Number($('#inbound').value),entry_port:$('#entry-port').value ? Number($('#entry-port').value) : null,proxy:$('#proxy').value,fallback_proxy:$('#fallback-proxy').value,allow_direct_fallback:$('#direct-fallback').checked,psiphon_authorized:$('#psiphon-consent').checked}); $('#route-dialog').close(); $('#proxy').value=''; $('#fallback-proxy').value=''; toast('مسیر ساخته شد. حالا Host آن را به پنل اضافه کن.'); await refresh(); hostInfo(result.id); });};
$('#routes').onclick = async event => {
  const button=event.target.closest('button[data-action]'); if (!button) return; const {action,id}=button.dataset;
  if(action==='host') return hostInfo(id);
  if(action==='remove' && !await confirmAction('این مسیر حذف شود؟','ورودی و قانون همین مسیر حذف می‌شود. Host مربوط را هم در پنل غیرفعال یا حذف کن. کاربران و مسیرهای دیگر باقی می‌مانند.')) return;
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
