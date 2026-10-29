"""Adopt existing exits without moving their traffic or restarting providers.

The unprivileged UI talks to a narrow local root helper. The helper supports
only discovered outbound resources and the known FARSTAR country/WARP units.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import time
import urllib.parse

from .runtime import COUNTRIES, flag
from .storage import atomic_json, fingerprint


SOCKET = '/run/farstar-atlas-existing/control.sock'
SECRET_FIELDS = {'proxy', 'primary_proxy', 'fallback_proxy'}


def public_route(route):
    return {k: copy.deepcopy(v) for k, v in route.items() if k not in SECRET_FIELDS}


class ExistingClient:
    def __init__(self, path=SOCKET):
        self.path = path

    def request(self, payload):
        raw = json.dumps(payload).encode() + b'\n'
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(120)
                connection.connect(self.path)
                connection.sendall(raw)
                connection.shutdown(socket.SHUT_WR)
                chunks, size = [], 0
                while chunk := connection.recv(65536):
                    size += len(chunk)
                    if size > 1024 * 1024:
                        raise ValueError('پاسخ مدیریت مسیر موجود بیش از حد بزرگ است.')
                    chunks.append(chunk)
            result = json.loads(b''.join(chunks))
        except (OSError, ValueError) as exc:
            raise ValueError('مدیریت مسیرهای موجود در دسترس نیست؛ سرویس رابط را بررسی کنید.') from None
        if not result.get('ok'):
            raise ValueError(result.get('error', 'تنظیم مسیر موجود کامل نشد.'))
        return result['result']

    def inventory(self):
        return self.request({'action': 'inventory'})

    def change(self, resource, action, data=None):
        data = data or {}
        return self.request({'action': action, 'id': resource['id'],
            'revision': resource.get('revision', ''), 'operation': data.get('operation') or secrets.token_hex(16),
            **{k: data[k] for k in ('country', 'fallback_enabled', 'backup') if k in data}})


def section(text, backend):
    pattern = r'(?m)^backend ' + re.escape(backend) + r'[ \t]*\n(?:(?!^(?:global|defaults|frontend|backend|listen)\b)[\s\S])*'
    match = re.search(pattern, text)
    if not match:
        raise ValueError('ساختار پشتیبان این سرویس شناخته‌شده نیست؛ تغییری انجام نشد.')
    return match


def update_backend(text, backend, country=None, fallback=None):
    match = section(text, backend)
    block = match.group(0)
    if country is not None:
        block, count = re.subn(r'(?m)^([ \t]*tcp-check expect string loc=)[A-Z]{2}[ \t]*$',
                               lambda m: m.group(1) + country, block)
        if count != 1:
            raise ValueError('قانون بررسی کشور شناخته‌شده نیست؛ تغییری انجام نشد.')
    if fallback is not None:
        pattern = r'(?m)^([ \t]*server germany_fallback [^\n]+?)(?: disabled)?[ \t]*$'
        block, count = re.subn(pattern, lambda m: m.group(1).rstrip() + ('' if fallback else ' disabled'), block)
        if count != 1:
            raise ValueError('خروجی پشتیبان شناخته‌شده نیست؛ تغییری انجام نشد.')
    return text[:match.start()] + block + text[match.end():]


def atomic_preserve(path, data):
    """Keep root-owned source permissions; never relax provider/HAProxy files."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError('فایل سرویس نباید پیوند نمادین باشد.')
    stat = path.stat()
    temporary = path.with_name('.atlas-' + path.name + '-' + secrets.token_hex(6))
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, stat.st_mode & 0o777)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.st_mode & 0o777)
        if os.name == 'posix':
            os.chown(temporary, stat.st_uid, stat.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class Controller:
    def __init__(self, config, state, runner=None):
        self.config, self.state = config, Path(state)
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.runner = runner or subprocess.run

    def known_unit(self, name, marker):
        path = Path(self.config.get('units_dir', '/etc/systemd/system')) / (name + '.service')
        return path.is_file() and marker in path.read_text(errors='replace')

    def run(self, args, timeout=25):
        environment = dict(os.environ)
        if self.config.get('library_path'):
            environment['LD_LIBRARY_PATH'] = self.config['library_path']
        result = self.runner(args, capture_output=True, text=True, timeout=timeout, env=environment)
        if result.returncode:
            raise ValueError('فرمان سرویس کامل نشد؛ نسخهٔ پشتیبان حفظ شد.')
        return result.stdout.strip()

    def last(self):
        path = self.state / 'last.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def pending(self):
        path = self.state / 'pending.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def resources(self):
        native = json.loads(Path(self.config['native_config']).read_text())
        root = Path(self.config['country_root'])
        haproxy = root / 'haproxy.cfg'
        ha = haproxy.read_text() if haproxy.exists() else ''
        result = {}
        for out in native.get('outbounds', []):
            protocol, tag = out.get('protocol'), out.get('tag', '')
            if protocol not in ('socks', 'freedom') or not tag or tag.startswith('atlas-'):
                continue
            rid = 'existing-' + hashlib.sha256(tag.encode()).hexdigest()[:16]
            route = {'id': rid, 'kind': 'existing', 'enabled': True, 'outbound_tag': tag,
                'provider': 'existing-direct' if protocol == 'freedom' else 'existing-socks',
                'country': '', 'name': 'Direct' if protocol == 'freedom' else tag,
                'capabilities': [], 'inbound_tags': sorted({x for rule in native.get('routing', {}).get('rules', [])
                    if rule.get('outboundTag') == tag for x in rule.get('inboundTag', []) if x != 'api'})}
            if protocol == 'freedom' and native.get('outbounds', [{}])[0].get('tag') == tag:
                unconditional = {name for rule in native.get('routing', {}).get('rules', [])
                    if rule.get('outboundTag') != tag and set(rule) <= {'type', 'ruleTag', 'inboundTag', 'outboundTag'}
                    for name in rule.get('inboundTag', [])}
                route['inbound_tags'] = sorted({row['tag'] for row in native.get('inbounds', [])
                    if row.get('tag') != 'api' and row.get('tag') not in unconditional})
            control = {}
            if protocol == 'socks':
                servers = out.get('settings', {}).get('servers', [])
                if len(servers) != 1:
                    continue
                server = servers[0]
                address, port = str(server.get('address', '')), int(server.get('port', 0))
                if not address or not 1 <= port <= 65535:
                    continue
                user = next(iter(server.get('users') or []), {})
                auth = (urllib.parse.quote(user.get('user', ''), safe='') + ':' +
                        urllib.parse.quote(user.get('pass', ''), safe='') + '@') if user else ''
                host = '[' + address + ']' if ':' in address else address
                route['proxy'] = 'socks5h://' + auth + host + ':' + str(port)
                if tag == 'warp':
                    route['name'] = 'Cloudflare WARP'
                for code, entry_port, provider_port in (('fr', 62040, 62030), ('nl', 62041, 62031)):
                    path = root / (code + '.json')
                    if address != '127.0.0.1' or port != entry_port or not path.exists():
                        continue
                    if not self.known_unit('irg-country-' + code, str(path)):
                        continue
                    cfg = json.loads(path.read_text())
                    backend = code + '_exit'
                    block = section(ha, backend).group(0)
                    if int(cfg.get('LocalSocksProxyPort', 0)) != provider_port or not re.search(
                            r'(?m)^\s*server country 127\.0\.0\.1:' + str(provider_port) + r'\s', block):
                        continue
                    country = cfg.get('EgressRegion', '')
                    if country not in COUNTRIES:
                        continue
                    route.update(provider='existing-psiphon', country=country,
                        name=COUNTRIES[country] + ' ' + flag(country),
                        primary_proxy='socks5h://127.0.0.1:' + str(provider_port),
                        fallback_enabled=not bool(re.search(r'(?m)^\s*server germany_fallback .*\bdisabled\s*$', block)),
                        capabilities=['country', 'fallback', 'reconnect', 'rollback'])
                    control = {'unit': 'irg-country-' + code, 'provider': path, 'haproxy': haproxy, 'backend': backend}
                    break
                if tag == 'warp' and address == '10.79.0.2' and port == 11980 and self.known_unit('irg-warp-daemon', 'warp-svc'):
                    control = {'unit': 'irg-warp-daemon'}
                    route['capabilities'] = ['reconnect']
            basis = {'outbound': out, 'control': str(control)}
            if 'provider' in control:
                basis.update(provider=control['provider'].read_text(), backend=section(ha, control['backend']).group(0))
            route['revision'] = fingerprint(basis)
            route['last_backup'] = self.last().get(rid)
            route['pending'] = self.pending().get('id') == rid
            result[rid] = (route, control)
        return result

    def inventory(self):
        return [route for route, _ in self.resources().values()]

    def backup(self, rid, control):
        bid = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(6)
        data = {'id': rid, 'provider': json.loads(control['provider'].read_text()),
            'backend': section(control['haproxy'].read_text(), control['backend']).group(0)}
        atomic_json(self.state / 'backups' / (bid + '.json'), data)
        return bid

    def validate_haproxy(self, path, text):
        temporary = path.with_name('.atlas-check-' + secrets.token_hex(6) + '.cfg')
        try:
            temporary.write_text(text); temporary.chmod(0o600)
            self.run([self.config['haproxy_binary'], '-c', '-q', '-f', str(temporary)])
        finally:
            temporary.unlink(missing_ok=True)

    def apply(self, rid, control, cfg, new_ha, reconnect=False):
        path, haproxy = control['provider'], control['haproxy']
        old_cfg, old_ha = path.read_bytes(), haproxy.read_bytes()
        latest = json.loads(old_cfg)
        latest['EgressRegion'] = cfg['EgressRegion']
        cfg = latest
        wanted_fallback = not bool(re.search(r'(?m)^\s*server germany_fallback .*\bdisabled\s*$', section(new_ha, control['backend']).group(0)))
        # Merge only the two owned settings into the latest file, preserving
        # other backends and operator changes outside those fields.
        new_ha = update_backend(old_ha.decode().replace('\r\n', '\n'), control['backend'], cfg['EgressRegion'], wanted_fallback)
        cfg_bytes = (json.dumps(cfg, indent=2) + '\n').encode()
        changed_country = json.loads(old_cfg).get('EgressRegion') != cfg.get('EgressRegion')
        changed_ha = old_ha.decode().replace('\r\n', '\n') != new_ha
        if not changed_country and not changed_ha and not reconnect:
            return None
        self.validate_haproxy(haproxy, new_ha)
        if path.read_bytes() != old_cfg or haproxy.read_bytes() != old_ha:
            raise ValueError('تنظیمات سرویس هم‌زمان تغییر کرد؛ دوباره بررسی کنید.')
        bid = self.backup(rid, control)
        last = self.last(); last[rid] = bid
        atomic_json(self.state / 'last.json', last)
        atomic_json(self.state / 'pending.json', {'id': rid, 'backup': bid})
        try:
            if changed_country:
                atomic_preserve(path, cfg_bytes)
            if changed_ha:
                content = new_ha.replace('\n', '\r\n') if b'\r\n' in old_ha else new_ha
                atomic_preserve(haproxy, content.encode())
            if changed_country or reconnect:
                self.run(['systemctl', 'restart', control['unit']])
            if changed_ha:
                # The existing -Ws master reloads workers gracefully. No native
                # Xray/panel or ingress service is restarted.
                self.run(['systemctl', 'reload', 'irg-country-entry'])
        except Exception:
            atomic_preserve(path, old_cfg); atomic_preserve(haproxy, old_ha)
            if changed_country or reconnect:
                self.run(['systemctl', 'restart', control['unit']])
            if changed_ha:
                self.run(['systemctl', 'reload', 'irg-country-entry'])
            (self.state / 'pending.json').unlink(missing_ok=True)
            raise
        (self.state / 'pending.json').unlink(missing_ok=True)
        return bid

    def dispatch(self, request):
        allowed = {'action', 'id', 'revision', 'operation', 'country', 'fallback_enabled', 'backup'}
        if not isinstance(request, dict) or set(request) - allowed:
            raise ValueError('درخواست مدیریت مسیر معتبر نیست.')
        action = request.get('action')
        if action == 'inventory':
            return self.inventory()
        if action not in ('configure', 'reconnect', 'restore'):
            raise ValueError('این عملیات پشتیبانی نمی‌شود.')
        rid, op = request.get('id', ''), request.get('operation', '')
        if not re.fullmatch(r'[0-9a-f]{32}', op):
            raise ValueError('شناسهٔ عملیات معتبر نیست.')
        cache = self.state / 'operations' / (op + '.json')
        digest = fingerprint(request)
        if cache.exists():
            prior = json.loads(cache.read_text())
            if prior['request'] != digest:
                raise ValueError('شناسهٔ عملیات قبلاً برای درخواست دیگری استفاده شده است.')
            return prior['result']
        resources = self.resources()
        if rid not in resources:
            raise ValueError('مسیر موجود پیدا نشد.')
        route, control = resources[rid]
        pending = self.pending()
        if pending and (action != 'restore' or pending.get('id') != rid):
            raise ValueError('عملیات قبلی نیمه‌تمام است؛ ابتدا تنظیم قبلی همان خروجی را بازگردانید.')
        if route['revision'] != request.get('revision'):
            raise ValueError('تنظیمات مسیر هم‌زمان تغییر کرده؛ صفحه را تازه کنید.')
        if action == 'reconnect' and route['provider'] == 'existing-socks' and route.get('name') == 'Cloudflare WARP' and 'reconnect' in route['capabilities']:
            self.run(['systemctl', 'restart', 'irg-warp-daemon'])
        elif control.get('provider'):
            cfg = json.loads(control['provider'].read_text())
            text = control['haproxy'].read_text()
            if action == 'configure':
                country = request.get('country', cfg['EgressRegion'])
                fallback = request.get('fallback_enabled', route['fallback_enabled'])
                if country not in COUNTRIES or type(fallback) is not bool:
                    raise ValueError('کشور یا تنظیم پشتیبان معتبر نیست.')
                cfg['EgressRegion'] = country
                text = update_backend(text, control['backend'], country, fallback)
            elif action == 'restore':
                bid = request.get('backup') or route.get('last_backup') or ''
                if not re.fullmatch(r'[0-9A-Za-z-]{1,80}', bid):
                    raise ValueError('نسخهٔ پشتیبان معتبر نیست.')
                path = self.state / 'backups' / (bid + '.json')
                if not path.exists():
                    raise ValueError('نسخهٔ پشتیبان پیدا نشد.')
                saved = json.loads(path.read_text())
                if saved['id'] != rid:
                    raise ValueError('این پشتیبان متعلق به مسیر دیگری است.')
                cfg['EgressRegion'] = saved['provider']['EgressRegion']
                fallback = not bool(re.search(r'(?m)^\s*server germany_fallback .*\bdisabled\s*$', saved['backend']))
                text = update_backend(text, control['backend'], cfg['EgressRegion'], fallback)
            self.apply(rid, control, cfg, text, reconnect=action == 'reconnect')
            if action == 'restore' and self.pending().get('id') == rid:
                (self.state / 'pending.json').unlink(missing_ok=True)
        else:
            raise ValueError('این خروجی فقط قابل مشاهده و آزمایش است؛ کشور سرور مستقیم/WARP قابل انتخاب نیست.')
        result = self.resources()[rid][0]
        atomic_json(cache, {'request': digest, 'result': result})
        return result


def serve(config_path='/etc/farstar-atlas/existing.json', path=SOCKET):
    import grp
    import pwd
    if os.geteuid() != 0:
        raise SystemExit('Existing-service helper must run as root.')
    config_path = Path(config_path)
    if config_path.is_symlink() or config_path.stat().st_uid != 0 or config_path.stat().st_mode & 0o022:
        raise SystemExit('Unsafe existing-service configuration.')
    controller = Controller(json.loads(config_path.read_text()), '/var/lib/farstar-atlas-existing')
    allowed_uid = pwd.getpwnam('farstar-atlas').pw_uid
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(15)
            _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid not in (0, allowed_uid):
                return
            try:
                raw = self.rfile.readline(4097)
                if len(raw) > 4096 or not raw.endswith(b'\n'):
                    raise ValueError('درخواست بیش از حد بزرگ است.')
                result = controller.dispatch(json.loads(raw))
                response = {'ok': True, 'result': result}
            except ValueError as exc:
                response = {'ok': False, 'error': str(exc)[:250]}
            except Exception:
                response = {'ok': False, 'error': 'عملیات مسیر موجود کامل نشد؛ پشتیبان را بررسی کنید.'}
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode())
    target = Path(path); target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    gid = grp.getgrnam('farstar-atlas').gr_gid
    os.chown(target.parent, 0, gid); target.parent.chmod(0o750)
    target.unlink(missing_ok=True)
    with socketserver.UnixStreamServer(path, Handler) as server:
        os.chown(target, 0, gid); target.chmod(0o660)
        server.serve_forever()


if __name__ == '__main__':
    serve()
