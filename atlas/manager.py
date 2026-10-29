"""Serial, backed-up panel operations with managed-resource rollback."""
import copy
import ipaddress
import secrets
import threading

from .network import socks_url
from .panel import Panel, PanelError, check_delta, merge_template, panel_url, route_tag
from .runtime import COUNTRIES, flag
from .storage import atomic_json, fingerprint


class Manager:
    def __init__(self, store, runtime, panel_factory=Panel):
        self.store, self.runtime, self.panel_factory = store, runtime, panel_factory
        self.lock = threading.RLock()
        self.pending = store.root / 'pending.json'

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
        if len(routes) >= 32:
            raise ValueError('سقف این نسخه ۳۲ مسیر است.')
        inbound = next((r for r in rows if r['id'] == int(data.get('inbound_id', 0))), None)
        if not inbound or inbound['protocol'] not in ('vless', 'vmess', 'trojan', 'shadowsocks'):
            raise ValueError('یک اینباند TCP فعال و پشتیبانی‌شده را انتخاب کنید.')
        slots = {r['slot'] for r in routes}
        slot = next(i for i in range(1, 33) if i not in slots)
        port = int(data.get('entry_port') or 20000 + slot)
        occupied = {int(r['port']) for r in rows} | {r['entry_port'] for r in routes}
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
        panel = self.panel()
        template, test_url = panel.template()
        known = {r['id']: r for r in before_config['routes'] + routes}
        known = list(known.values())
        desired = merge_template(template, routes, known)
        check_delta(template, desired, known)
        backup = {'config': before_config, 'template': template, 'reason': reason}
        backup_id = self.store.backup(backup)
        operation = {'backup': backup_id, 'before_routes': before_config['routes'],
                     'after_routes': routes, 'known': known, 'phase': 'prepared'}
        atomic_json(self.pending, operation)
        try:
            # Listeners must bind successfully before we change native routing.
            self.runtime.submit(self.runtime.reload(routes))
            panel.allow_sources([r['source_ip'] for r in routes if r.get('enabled', True)])
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
            expected_out = {x['tag']: x for x in desired['outbounds'] if x.get('tag') in {route_tag(r) for r in known}}
            actual_out = {x['tag']: x for x in actual.get('outbounds', []) if x.get('tag') in {route_tag(r) for r in known}}
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
        restored = merge_template(current, operation['before_routes'], operation['known'])
        check_delta(current, restored, operation['known'])
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
            self.apply([r for r in routes if r['id'] != rid], 'مسیر حذف شد')

    def toggle(self, rid):
        with self.lock:
            routes = self.store.read()['routes']
            route = next((r for r in routes if r['id'] == rid), None)
            if not route:
                raise ValueError('مسیر پیدا نشد.')
            route['enabled'] = not route.get('enabled', True)
            self.apply(routes, 'وضعیت مسیر تغییر کرد')

    def restore(self, name):
        with self.lock:
            backup = self.store.load_backup(name)
            # Restores Atlas' route definitions only, merging into today's panel.
            # Does not overwrite newer unrelated panel settings or credentials.
            return self.apply(backup['config']['routes'], 'مسیرهای نسخهٔ پشتیبان بازیابی شد')

    def state(self):
        config = self.store.read()
        routes = []
        for route in config['routes']:
            public = {k: v for k, v in route.items() if k not in ('proxy', 'fallback_proxy')}
            public['has_backup'] = bool(route.get('fallback_proxy'))
            routes.append(public)
        return {'connected': bool(config.get('panel')), 'panel_url': config.get('panel', {}).get('url', ''),
            'routes': routes, 'status': self.runtime.public_status(), 'events': self.store.events(),
            'backups': self.store.backups(), 'pending': self.pending.exists(),
            'engine_installed': (self.store.root / 'engine' / 'ConsoleClient').is_file(),
            'countries': COUNTRIES}
