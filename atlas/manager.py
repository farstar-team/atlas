"""Serial, backed-up panel operations with managed-resource rollback."""
import copy
import ipaddress
import secrets
import threading
import re
import urllib.parse
from pathlib import Path

from .network import socks_url
from .panel import Panel, PanelError, check_delta, merge_template, panel_url, route_tag
from .runtime import COUNTRIES, flag
from .storage import atomic_json, fingerprint
from .existing import ExistingClient, public_route


class Manager:
    def __init__(self, store, runtime, panel_factory=Panel, existing_client=None):
        self.store, self.runtime, self.panel_factory = store, runtime, panel_factory
        self.lock = threading.RLock()
        self.pending = store.root / 'pending.json'
        self.existing = existing_client or ExistingClient()

    def panel(self):
        config = self.store.read().get('panel')
        if not config:
            raise ValueError('ابتدا اتصال پنل را ثبت کنید.')
        return self.panel_factory(config)

    def connect(self, data):
        with self.lock:
            config = self.store.read()
            old = config.get('panel', {})
            url = panel_url(str(data.get('url', '')))
            token = str(data.get('token') or old.get('token', ''))
            if not token or len(token) > 4096 or any(c in token for c in '\r\n'):
                raise ValueError('توکن Admin معتبر پنل را وارد کنید.')
            if config['routes'] and url != old.get('url'):
                raise ValueError('پیش از تغییر سرور پنل، مسیرهای فعلی را حذف کنید.')
            panel_config = {'url': url, 'token': token}
            rows = self.panel_factory(panel_config).check()
            config['panel'] = panel_config
            self.store.save(config)
            self.store.event('panel', 'اتصال و قابلیت‌های پنل بررسی شد.')
            return rows

    def build_route(self, data, rows, routes):
        country = data.get('country')
        if country not in COUNTRIES:
            raise ValueError('کشور معتبر را انتخاب کنید.')
        if sum(r.get('kind') != 'existing' for r in routes) >= 32:
            raise ValueError('سقف این نسخه ۳۲ مسیر است.')
        inbound = next((r for r in rows if r['id'] == int(data.get('inbound_id', 0))), None)
        if not inbound or inbound['protocol'] not in ('vless', 'vmess', 'trojan', 'shadowsocks'):
            raise ValueError('یک اینباند TCP فعال و پشتیبانی‌شده را انتخاب کنید.')
        slots = {r['slot'] for r in routes if r.get('kind') != 'existing'}
        slot = next(i for i in range(1, 33) if i not in slots)
        port = int(data.get('entry_port') or 20000 + slot)
        occupied = {int(r['port']) for r in rows} | {r['entry_port'] for r in routes if r.get('kind') != 'existing'}
        if not 1024 <= port <= 60999 or port in occupied:
            raise ValueError('پورت ورودی باید آزاد و بین ۱۰۲۴ و ۶۰۹۹۹ باشد.')
        provider = data.get('provider', 'socks')
        if provider not in ('socks', 'psiphon'):
            raise ValueError('نوع خروجی معتبر نیست.')
        if provider == 'psiphon' and data.get('psiphon_authorized') is not True:
            raise ValueError('استفاده از شبکهٔ Psiphon باید با شرایط و مجوز آن سازگار باشد.')
        target = inbound.get('listen') or '0.0.0.0'
        if target in ('0.0.0.0', '::', '*'):
            target = '127.0.0.1'
        ipaddress.ip_address(target)
        if ':' in target:
            raise ValueError('این نسخه برای ورودیِ فقط IPv6 مناسب نیست؛ یک اینباند IPv4 انتخاب کنید.')
        route = {'id': secrets.token_hex(8), 'slot': slot, 'country': country,
            'name': COUNTRIES[country] + ' ' + flag(country), 'provider': provider,
            'inbound_id': inbound['id'], 'inbound_tag': inbound['tag'], 'target_ip': target,
            'target_port': int(inbound['port']), 'entry_port': port,
            'source_ip': '127.77.0.' + str(slot), 'socks_port': 61100 + slot,
            'provider_port': 61200 + slot, 'enabled': True,
            'allow_direct_fallback': data.get('allow_direct_fallback') is True}
        if provider == 'socks':
            route['proxy'] = socks_url(str(data.get('proxy', '')))
        if data.get('fallback_proxy'):
            route['fallback_proxy'] = socks_url(str(data['fallback_proxy']))
        return route

    def apply(self, routes, reason):
        """Journal before first side effect; don't retry an ambiguous API write."""
        if self.pending.exists():
            raise ValueError('یک عملیات نیمه‌تمام وجود دارد؛ ابتدا «بازیابی عملیات» را بزنید.')
        before_config = self.store.read()
        if not any(r.get('kind') != 'existing' for r in before_config['routes'] + routes):
            backup = self.store.backup({'config': before_config, 'reason': reason})
            self.runtime.submit(self.runtime.reload(routes))
            before_config['routes'] = copy.deepcopy(routes)
            self.store.save(before_config)
            self.store.event('change', reason + '؛ مسیرهای اصلی سرور حفظ شدند.')
            return backup
        panel = self.panel()
        template, test_url = panel.template()
        known = {r['id']: r for r in before_config['routes'] + routes}
        known = list(known.values())
        owned = [r for r in known if r.get('kind') != 'existing']
        desired = merge_template(template, [r for r in routes if r.get('kind') != 'existing'], owned)
        check_delta(template, desired, owned)
        backup = {'config': before_config, 'template': template, 'reason': reason}
        backup_id = self.store.backup(backup)
        operation = {'backup': backup_id, 'before_routes': before_config['routes'],
                     'after_routes': routes, 'known': known, 'phase': 'prepared'}
        atomic_json(self.pending, operation)
        try:
            # Listeners must bind successfully before we change native routing.
            self.runtime.submit(self.runtime.reload(routes))
            panel.allow_sources([r['source_ip'] for r in routes if r.get('kind') != 'existing' and r.get('enabled', True)])
            # Detect another editor before writing the whole native template.
            current, _ = panel.template()
            if fingerprint(current) != fingerprint(template):
                raise PanelError('تنظیمات پنل هم‌زمان تغییر کرد؛ دوباره تلاش کنید.')
            operation['phase'] = 'writing'
            atomic_json(self.pending, operation)
            panel.update(desired, test_url)
            actual, _ = panel.template()
            # Native panel may normalize DNS/stats rules. Verify our resources,
            # then keep native normalization instead of force-overwriting it.
            expected_out = {x['tag']: x for x in desired['outbounds'] if x.get('tag') in {route_tag(r) for r in owned}}
            actual_out = {x['tag']: x for x in actual.get('outbounds', []) if x.get('tag') in {route_tag(r) for r in owned}}
            expected_rules = [x for x in desired['routing']['rules'] if x.get('ruleTag') in expected_out]
            actual_rules = [x for x in actual.get('routing', {}).get('rules', []) if x.get('ruleTag') in expected_out]
            if actual_out != expected_out or actual_rules != expected_rules:
                raise PanelError('بازخوانی تنظیمات ثبت‌شده با تغییر مورد انتظار یکسان نیست.')
            config = self.store.read()
            config['routes'] = copy.deepcopy(routes)
            self.store.save(config)
            self.pending.unlink()
            self.store.event('change', reason + '؛ پشتیبان ذخیره شد.')
            return backup_id
        except Exception:
            try:
                self._rollback(operation)
            except Exception:
                self.store.event('error', 'عملیات کامل نشد؛ بازیابی عملیات برای بررسی نگه داشته شد.')
                raise PanelError('عملیات کامل نشد و بازیابی نیاز به بررسی دارد؛ در بخش تنظیمات «بازیابی عملیات» را بزنید.') from None
            raise

    def _rollback(self, operation):
        panel = self.panel()
        current, test_url = panel.template()
        owned = [r for r in operation['known'] if r.get('kind') != 'existing']
        restored = merge_template(current, [r for r in operation['before_routes'] if r.get('kind') != 'existing'], owned)
        check_delta(current, restored, owned)
        if fingerprint(current) != fingerprint(restored):
            panel.update(restored, test_url)
        self.runtime.submit(self.runtime.reload(operation['before_routes']))
        config = self.store.read()
        config['routes'] = operation['before_routes']
        self.store.save(config)
        self.pending.unlink(missing_ok=True)
        self.store.event('restore', 'تغییرهای همین عملیات برگشت داده شد؛ سایر تنظیمات حفظ شد.')

    def recover(self):
        import json
        with self.lock:
            if self.pending.exists():
                operation = json.loads(self.pending.read_text(encoding='utf-8'))
                self._rollback(operation)

    def add(self, data):
        with self.lock:
            config = self.store.read()
            route = self.build_route(data, self.panel().inbounds(), config['routes'])
            self.apply(config['routes'] + [route], 'مسیر ' + COUNTRIES[route['country']] + ' اضافه شد')
            return route['id']

    def remove(self, rid):
        with self.lock:
            routes = self.store.read()['routes']
            if not any(r['id'] == rid for r in routes):
                raise ValueError('مسیر پیدا نشد.')
            if next(r for r in routes if r['id'] == rid).get('kind') == 'existing':
                self.store.backup({'config': self.store.read(), 'reason': 'خروج مسیر موجود از فهرست مدیریت'})
                config = self.store.read(); config['routes'] = [r for r in routes if r['id'] != rid]
                self.runtime.submit(self.runtime.reload(config['routes']))
                self.store.save(config)
                self.store.event('change', 'مسیر موجود از فهرست Atlas خارج شد؛ سرویس اصلی فعال ماند.')
                return
            self.apply([r for r in routes if r['id'] != rid], 'مسیر حذف شد')

    def toggle(self, rid):
        with self.lock:
            routes = self.store.read()['routes']
            route = next((r for r in routes if r['id'] == rid), None)
            if not route:
                raise ValueError('مسیر پیدا نشد.')
            if route.get('kind') == 'existing':
                raise ValueError('برای مسیر موجود از تنظیم کشور و پشتیبان استفاده کنید.')
            route['enabled'] = not route.get('enabled', True)
            self.apply(routes, 'وضعیت مسیر تغییر کرد')

    def restore(self, name):
        with self.lock:
            backup = self.store.load_backup(name)
            # Restores Atlas' route definitions only, merging into today's panel.
            # Does not overwrite newer unrelated panel settings or credentials.
            linked = [r for r in self.store.read()['routes'] if r.get('kind') == 'existing']
            owned = [r for r in backup['config']['routes'] if r.get('kind') != 'existing']
            return self.apply(owned + linked, 'مسیرهای نسخهٔ پشتیبان بازیابی شد')

    def _bindings(self, resources, rows, hosts):
        country_names = [COUNTRIES[r['country']] for r in resources if r.get('country') in COUNTRIES]
        for route in resources:
            tags = set(route.get('inbound_tags', []))
            selected = [row for row in rows if row['tag'] in tags]
            ids = {row['id'] for row in selected}
            word = COUNTRIES.get(route.get('country'))
            groups = [g for g in hosts if ids.intersection(g.get('inboundIds', [])) and not g.get('isDisabled')]
            if word:
                groups = [g for g in groups if word.lower() in g.get('remark', '').lower()]
            else:
                groups = [g for g in groups if not any(name.lower() in g.get('remark', '').lower() for name in country_names)]
            route['host_groups'] = [g['groupId'] for g in groups]
            bindings = []
            for group in groups:
                for row in selected:
                    if row['id'] in group.get('inboundIds', []):
                        bindings.append({'name': (row.get('remark', '') + ' ' + group.get('remark', '')).strip(),
                            'inbound_id': row['id'], 'port': group.get('port'), 'addresses': list(group.get('hosts', []))})
            covered = {i for g in hosts for i in g.get('inboundIds', [])}
            if not word:
                bindings += [{'name': row.get('remark', row['tag']), 'inbound_id': row['id'], 'port': row['port'], 'addresses': []}
                    for row in selected if row['id'] not in covered]
            route['bindings'] = bindings
        return resources

    def discover_existing(self):
        resources = self.existing.inventory()
        panel = self.panel()
        return self._bindings(resources, panel.inbounds(), panel.call('hosts/list'))

    def import_existing(self, ids):
        with self.lock:
            if self.pending.exists():
                raise ValueError('ابتدا عملیات نیمه‌تمام را بازیابی کنید.')
            resources = self.discover_existing()
            if not isinstance(ids, list) or not ids or set(ids) - {r['id'] for r in resources}:
                raise ValueError('مسیرهای انتخاب‌شده معتبر نیستند.')
            config = self.store.read()
            existing_ids = {r['id'] for r in config['routes']}
            additions = [r for r in resources if r['id'] in ids and r['id'] not in existing_ids]
            if not additions:
                return []
            backup = self.store.backup({'config': config, 'reason': 'واردکردن مسیرهای موجود بدون تغییر ترافیک'})
            desired = config['routes'] + additions
            self.runtime.submit(self.runtime.reload(desired))
            config['routes'] = desired; self.store.save(config)
            self.store.event('import', str(len(additions)) + ' مسیر موجود وارد Atlas شد؛ سرویس‌های فعلی ادامه دارند.')
            return [r['id'] for r in additions]

    def _rename_hosts(self, route, old_country, new_country):
        if old_country == new_country or old_country not in COUNTRIES or new_country not in COUNTRIES:
            return
        panel = self.panel()
        groups = panel.call('hosts/list')
        touched = []
        try:
            for group in groups:
                if group.get('groupId') not in route.get('host_groups', []):
                    continue
                old = group.get('remark', '')
                if COUNTRIES[old_country].lower() not in old.lower():
                    continue  # Preserve operator-customized names.
                new = re.sub(re.escape(COUNTRIES[old_country]), COUNTRIES[new_country], old, count=1, flags=re.I)
                new = new.replace(flag(old_country), '').rstrip() + ' ' + flag(new_country)
                modified = copy.deepcopy(group); modified['remark'] = new
                panel.call('hosts/update/' + urllib.parse.quote(str(group['groupId']), safe=''), modified, json_body=True)
                touched.append((group['groupId'], old, new))
        except Exception:
            # Restore only our labels, merging into the freshest Host objects.
            for gid, old, new in reversed(touched):
                current = next((g for g in panel.call('hosts/list') if g.get('groupId') == gid), None)
                if current and current.get('remark') == new:
                    current['remark'] = old
                    panel.call('hosts/update/' + urllib.parse.quote(str(gid), safe=''), current, json_body=True)
            raise

    def change_existing(self, rid, action, data=None):
        with self.lock:
            data = data or {}
            config = self.store.read()
            prior = next((r for r in config['routes'] if r['id'] == rid and r.get('kind') == 'existing'), None)
            if not prior:
                raise ValueError('مسیر موجود پیدا نشد.')
            resource = copy.deepcopy(prior)
            if data.get('revision'):
                resource['revision'] = data['revision']
            self.store.backup({'config': config, 'reason': 'تنظیم خروجی موجود'})
            updated = self.existing.change(resource, action, data)
            try:
                self._rename_hosts(prior, prior.get('country'), updated.get('country'))
            except Exception:
                if updated.get('last_backup'):
                    self.existing.change(updated, 'restore', {'backup': updated['last_backup']})
                raise ValueError('نام Host تأیید نشد؛ تنظیم قبلی خروجی برگشت داده شد. وضعیت را دوباره بررسی کنید.') from None
            # Rebuild associations from today's metadata. No native routing,
            # inbound, user, quota, UUID or transport setting is rewritten.
            all_resources = [updated] + [r for r in config['routes'] if r.get('kind') == 'existing' and r['id'] != rid]
            panel = self.panel()
            self._bindings(all_resources, panel.inbounds(), panel.call('hosts/list'))
            config['routes'] = [updated if r['id'] == rid else r for r in config['routes']]
            self.runtime.submit(self.runtime.reload(config['routes']))
            self.store.save(config)
            self.store.event('change', 'تنظیم مسیر موجود ' + updated['name'] + ' انجام شد؛ Hostهای مرتبط هماهنگ شدند.')
            return public_route(updated)

    def state(self):
        config = self.store.read()
        routes = []
        fresh = {}
        existing_error = False
        if any(r.get('kind') == 'existing' for r in config['routes']):
            try:
                fresh = {r['id']: r for r in self.existing.inventory()}
            except (OSError, ValueError):
                existing_error = True
        for route in config['routes']:
            if route.get('kind') == 'existing':
                # Refresh recovery metadata even if the helper or web daemon
                # stopped before its successful response reached local state.
                route = {**route, **fresh.get(route['id'], {})}
                route['control_available'] = route['id'] in fresh
            public = public_route(route)
            public['has_backup'] = bool(route.get('fallback_proxy') or route.get('fallback_enabled'))
            routes.append(public)
        return {'connected': bool(config.get('panel')), 'panel_url': config.get('panel', {}).get('url', ''),
            'routes': routes, 'status': self.runtime.public_status(), 'events': self.store.events(),
            'backups': self.store.backups(), 'pending': self.pending.exists(),
            'engine_installed': (self.store.root / 'engine' / 'ConsoleClient').is_file(),
            'existing_available': not existing_error and (Path(self.existing.path).exists() if hasattr(self.existing, 'path') else True),
            'countries': COUNTRIES}
