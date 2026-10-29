"""Native 3x-ui 3.11 API adapter. Never writes panel files or client records."""
import copy
import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


class PanelError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def panel_url(value):
    value = value.strip()
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('آدرس کامل پنل، شامل مسیر مخفی آن، را وارد کنید.')
    if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('برای آدرس عمومی پنل، HTTPS معتبر لازم است.')
    _ = parsed.port
    return value.rstrip('/') + '/'


class Panel:
    def __init__(self, config):
        self.url = panel_url(config['url'])
        self.token = config['token']
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def call(self, path, data=None, method=None):
        body = urllib.parse.urlencode(data or {}).encode() if data is not None else None
        req = urllib.request.Request(self.url + 'panel/api/' + path.lstrip('/'), body,
            {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json',
             'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'},
            method=method or ('POST' if data is not None else 'GET'))
        try:
            with self.opener.open(req, timeout=35) as response:
                raw = response.read(5 * 1024 * 1024 + 1)
            if len(raw) > 5 * 1024 * 1024:
                raise PanelError('پاسخ پنل بیش از حد بزرگ است.')
            result = json.loads(raw)
            if not isinstance(result, dict) or not result.get('success'):
                # Upstream errors can contain configuration secrets.
                raise PanelError('پنل درخواست را نپذیرفت؛ دسترسی توکن و سازگاری نسخه را بررسی کنید.')
            return result.get('obj')
        except urllib.error.HTTPError as exc:
            raise PanelError('پاسخ پنل: HTTP ' + str(exc.code)) from None
        except (OSError, ValueError) as exc:
            raise PanelError('ارتباط امن با پنل برقرار نشد؛ آدرس، گواهی و توکن را بررسی کنید.') from None

    def template(self):
        wrapper = self.call('xray/', {})
        if isinstance(wrapper, str):
            wrapper = json.loads(wrapper)
        template = wrapper.get('xraySetting') if isinstance(wrapper, dict) else None
        if isinstance(template, str):
            template = json.loads(template)
        if not isinstance(template, dict) or not isinstance(template.get('outbounds'), list):
            raise PanelError('API تنظیمات Xray این نسخه پشتیبانی نمی‌شود.')
        return copy.deepcopy(template), wrapper.get('outboundTestUrl', 'https://www.google.com/generate_204')

    def inbounds(self):
        rows = self.call('inbounds/list')
        if not isinstance(rows, list):
            raise PanelError('لیست اینباندها معتبر نیست.')
        return [{k: row.get(k) for k in ('id', 'remark', 'port', 'tag', 'listen', 'enable', 'protocol')}
                for row in rows if row.get('enable') and row.get('tag') != 'api']

    def check(self):
        template, _ = self.template()
        services = template.get('api', {}).get('services', [])
        if not {'HandlerService', 'RoutingService'}.issubset(services):
            raise PanelError('HandlerService و RoutingService باید از تنظیمات خود پنل فعال باشند.')
        rows = self.inbounds()
        if rows:
            self.route_test(rows[0]['tag'])
        return rows

    def route_test(self, tag, source=None):
        return self.call('xray/routeTest', {'inboundTag': tag, 'domain': 'www.cloudflare.com', 'port': 443, 'network': 'tcp'})

    def update(self, template, test_url):
        return self.call('xray/update', {'xraySetting': json.dumps(template, separators=(',', ':')),
                                       'outboundTestUrl': test_url})

    def allow_sources(self, addresses):
        """Round-trip the native redacted view, preserving unrelated settings."""
        settings = self.call('setting/all', {})
        if not isinstance(settings, dict) or 'ipLimitAllowlist' not in settings:
            raise PanelError('این نسخه API فهرست IPهای مجاز را ندارد؛ تغییری اعمال نشد.')
        old = settings.get('ipLimitAllowlist') or ''
        current = [x.strip() for x in old.split(',') if x.strip()]
        networks = []
        for item in current:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass
        missing = [ip for ip in addresses if not any(ipaddress.ip_address(ip) in net for net in networks)]
        if missing:
            settings['ipLimitAllowlist'] = ','.join(current + missing)
            # Presence flags are response-only. Secrets stay redacted; the native
            # API explicitly treats blank secrets as unchanged.
            payload = {k: (json.dumps(v) if isinstance(v, (dict, list)) else
                ('true' if v else 'false') if isinstance(v, bool) else v if v is not None else '')
                for k, v in settings.items() if not k.startswith('has')}
            self.call('setting/update', payload)
            verified = self.call('setting/all', {})
            trusted = []
            for item in str(verified.get('ipLimitAllowlist') or '').split(','):
                try:
                    trusted.append(ipaddress.ip_network(item.strip(), strict=False))
                except ValueError:
                    pass
            if not all(any(ipaddress.ip_address(ip) in net for net in trusted) for ip in addresses):
                raise PanelError('ثبت آدرس‌های داخلی مجاز در پنل تأیید نشد؛ مسیر فعال نشد.')
        return old


def route_tag(route):
    return 'atlas-' + route['id']


def merge_template(template, routes, known):
    """Touch only explicitly owned outbound/rule tags; retain default order."""
    result = copy.deepcopy(template)
    owned = {route_tag(r) for r in known}
    result['outbounds'] = [x for x in result.get('outbounds', []) if x.get('tag') not in owned]
    routing = result.setdefault('routing', {})
    rules = [x for x in routing.get('rules', []) if x.get('ruleTag') not in owned]
    block_tags = {x.get('tag') for x in result['outbounds'] if x.get('protocol') == 'blackhole'}
    position = 0
    while position < len(rules) and (rules[position].get('outboundTag') in block_tags or
            rules[position].get('outboundTag') == template.get('api', {}).get('tag', 'api')):
        position += 1
    additions = []
    for route in routes:
        if not route.get('enabled', True):
            continue
        tag = route_tag(route)
        if any(x.get('tag') == tag for x in result['outbounds']):
            raise PanelError('تداخل نام اوتباند؛ چیزی بازنویسی نشد.')
        result['outbounds'].append({'tag': tag, 'protocol': 'socks', 'settings': {
            'servers': [{'address': '127.0.0.1', 'port': route['socks_port']}]}})
        additions.append({'type': 'field', 'ruleTag': tag, 'inboundTag': [route['inbound_tag']],
            'source': [route['source_ip'] + '/32'], 'network': 'tcp', 'port': '80,443', 'outboundTag': tag})
    routing['rules'] = rules[:position] + additions + rules[position:]
    return result


def check_delta(before, after, known):
    """Fail closed if an operation touches DNS, users, inbounds or other tags."""
    owned = {route_tag(r) for r in known}
    def foreign(value):
        v = copy.deepcopy(value)
        v['outbounds'] = [x for x in v.get('outbounds', []) if x.get('tag') not in owned]
        if 'routing' in v:
            v['routing']['rules'] = [x for x in v['routing'].get('rules', []) if x.get('ruleTag') not in owned]
        return v
    if foreign(before) != foreign(after):
        raise PanelError('تغییر بیرون از محدودهٔ Atlas شناسایی شد؛ عملیات متوقف شد.')
