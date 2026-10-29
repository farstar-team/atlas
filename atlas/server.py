"""Public native-panel SSO and optional private-password administration."""
import collections
import http.cookies
import http.server
import json
from pathlib import Path
import secrets
import socket
import threading
import time
import urllib.parse
import ssl

from . import __version__
from .storage import password_matches
from .access import PanelAccess, LoginRequired, PanelUnavailable, native_cookie


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    def __init__(self, address, manager, static=None, tls=False, access=None):
        self.manager = manager
        self.static = Path(static or Path(__file__).parent.parent / 'web')
        self.tls = tls
        self.access = access or {}
        self.native = PanelAccess(access) if access and access.get('mode') == 'panel' else None
        self.base_path = self.access.get('base_path', '/')
        self.tls_lock = threading.Lock()
        self.tls_stamp = None
        self.tls_context = None
        self.sessions = {}
        self.attempts = collections.defaultdict(list)
        self.auth_lock = threading.Lock()
        super().__init__(address, Handler)

    def context(self):
        cfg = self.access
        stamp = (Path(cfg['cert_file']).stat().st_mtime_ns, Path(cfg['key_file']).stat().st_mtime_ns)
        with self.tls_lock:
            if stamp != self.tls_stamp:
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.load_cert_chain(cfg['cert_file'], cfg['key_file'])
                    self.tls_context, self.tls_stamp = context, stamp
                except (OSError, ssl.SSLError):
                    # A renewal may be replacing the pair. Keep the prior valid
                    # context until both files can be loaded together.
                    if self.tls_context is None:
                        raise
            return self.tls_context

    def process_request_thread(self, request, client_address):
        wrapped = request
        try:
            if self.tls:
                request.settimeout(10)
                wrapped = self.context().wrap_socket(request, server_side=True)
            super().process_request_thread(wrapped, client_address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            wrapped.close()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'Atlas'
    sys_version = ''
    def handle(self):
        try:
            super().handle()
        except (ConnectionError, socket.timeout):
            pass
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *_):
        pass  # URLs, credentials and native subscription IDs do not belong in logs.

    def send(self, status, body, content_type='application/json; charset=utf-8', cookie=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header('X-Frame-Options', 'DENY')
        if cookie:
            for value in cookie if isinstance(cookie, list) else [cookie]:
                self.send_header('Set-Cookie', value)
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        value = self.headers.get('Host', '')
        try:
            parsed = urllib.parse.urlsplit('//' + value)
            hostname = parsed.hostname
            port = parsed.port or (443 if self.server.tls else 80)
            configured = self.server.manager.store.read().get('public_hostname')
            hosts = ['127.0.0.1', 'localhost', self.server.server_address[0], configured]
            hosts.extend(self.server.access.get('hosts', []))
            return not parsed.username and not parsed.password and not parsed.path and hostname in hosts and port == self.server.server_port
        except ValueError:
            return False

    def session(self):
        if self.server.native:
            return self.server.native.validate(native_cookie(self.headers.get('Cookie', '')), self.origin())
        try:
            cookies = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            token = cookies['atlas_session'].value
        except (KeyError, http.cookies.CookieError):
            return None
        with self.server.auth_lock:
            item = self.server.sessions.get(token)
            if item and item['expires'] > time.time():
                return item
            self.server.sessions.pop(token, None)
        return None

    def origin(self):
        return ('https' if self.server.tls else 'http') + '://' + self.headers.get('Host', '')

    def relative_path(self):
        path = urllib.parse.urlsplit(self.path).path
        base = self.server.base_path
        if path.startswith(base):
            return '/' + path[len(base):]
        return None

    def body(self):
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ValueError('نوع درخواست باید JSON باشد.')
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('درخواست معتبر نیست.')
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 < size <= 16384:
            raise ValueError('اندازهٔ درخواست معتبر نیست.')
        result = json.loads(self.rfile.read(size))
        if not isinstance(result, dict):
            raise ValueError('درخواست معتبر نیست.')
        return result

    def do_GET(self):
        if not self.valid_host():
            return self.send(403, {'error': 'آدرس میزبان مجاز نیست.'})
        raw_path = urllib.parse.urlsplit(self.path).path
        if raw_path == '/healthz':
            return self.send(200, {'ok': True, 'version': __version__})
        if raw_path in ('/', self.server.base_path.rstrip('/')) and raw_path != self.server.base_path:
            self.send_response(302)
            self.send_header('Location', self.server.base_path)
            self.send_header('Content-Length', '0')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            return
        path = self.relative_path()
        if path == '/api/session':
            try:
                session = self.session()
            except LoginRequired:
                session = None
            except PanelUnavailable as exc:
                return self.send(503, {'error': str(exc), 'mode': 'panel'})
            return self.send(200, {'authenticated': bool(session), 'csrf': session['csrf'] if session else '',
                'mode': 'panel' if self.server.native else 'password'})
        if path and path.startswith('/api/'):
            try:
                if not self.session():
                    raise LoginRequired('ابتدا وارد Atlas شوید.')
                if path == '/api/state':
                    result = self.server.manager.state()
                    if self.server.native and not result.get('panel_url'):
                        host = self.server.native.config['panel_hostname'] if self.server.tls else '127.0.0.1'
                        result['panel_url'] = self.server.native.login_url(host)
                    return self.send(200, result)
                if path == '/api/inbounds':
                    return self.send(200, self.server.manager.panel().inbounds())
            except Exception as exc:
                return self.error(exc)
            return self.send(404, {'error': 'پیدا نشد.'})
        paths = {'/': ('index.html', 'text/html; charset=utf-8'),
            '/app.css': ('app.css', 'text/css; charset=utf-8'),
            '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
            '/atlas.svg': ('atlas.svg', 'image/svg+xml')}
        if path not in paths:
            return self.send(404, 'Not found', 'text/plain')
        name, mime = paths[path]
        return self.send(200, (self.server.static / name).read_bytes(), mime)

    def error(self, exc):
        from .panel import PanelError
        if isinstance(exc, LoginRequired):
            return self.send(401, {'error': str(exc)[:400]})
        if isinstance(exc, PanelUnavailable):
            return self.send(503, {'error': str(exc)[:400]})
        if isinstance(exc, (ValueError, PanelError)):
            return self.send(400, {'error': str(exc)[:400]})
        return self.send(500, {'error': 'عملیات کامل نشد؛ وضعیت مسیر و بازیابی عملیات را بررسی کنید.'})

    def do_POST(self):
        if not self.valid_host():
            return self.send(403, {'error': 'آدرس میزبان مجاز نیست.'})
        expected = self.origin()
        if self.headers.get('Origin') != expected:
            return self.send(403, {'error': 'مبدأ درخواست معتبر نیست.'})
        path = self.relative_path()
        try:
            data = self.body()
            if path == '/api/login':
                now = time.time()
                address = self.client_address[0]
                with self.server.auth_lock:
                    self.server.attempts[address] = [t for t in self.server.attempts[address] if now - t < 300]
                    if len(self.server.attempts[address]) >= 10:
                        return self.send(429, {'error': 'تلاش زیاد؛ پنج دقیقه دیگر امتحان کنید.'})
                    self.server.attempts[address].append(now)
                if self.server.native:
                    cookie_value, max_age = self.server.native.login(data, self.client_address[0])
                    session = self.server.native.validate(cookie_value, expected)
                    with self.server.auth_lock:
                        self.server.attempts[address] = []
                    return self.send(200, {'ok': True, 'csrf': session['csrf']},
                        cookie=self.server.native.browser_cookie(cookie_value, max_age=max_age))
                if not password_matches(str(data.get('password', '')), self.server.manager.store.read()['password_hash']):
                    return self.send(401, {'error': 'رمز ورود صحیح نیست.'})
                token = secrets.token_urlsafe(32)
                session = {'csrf': secrets.token_urlsafe(32), 'expires': now + 8 * 3600}
                with self.server.auth_lock:
                    self.server.sessions = {k: v for k, v in self.server.sessions.items() if v['expires'] > now}
                    if len(self.server.sessions) >= 32:
                        self.server.sessions.pop(next(iter(self.server.sessions)))
                    self.server.sessions[token] = session
                    self.server.attempts[address] = []
                cookie = 'atlas_session=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'
                if self.server.tls:
                    cookie += '; Secure'
                return self.send(200, {'ok': True, 'csrf': session['csrf']}, cookie=cookie)
            session = self.session()
            if not session:
                return self.send(401, {'error': 'ابتدا وارد Atlas شوید.'})
            if not secrets.compare_digest(self.headers.get('X-Atlas-CSRF', ''), session['csrf']):
                return self.send(403, {'error': 'درخواست منقضی شد؛ صفحه را تازه کنید.'})
            manager = self.server.manager
            if path == '/api/logout':
                if self.server.native:
                    cookies = [self.server.native.browser_cookie('', expires=True)]
                    if self.server.native.config['panel_base_path'] != '/':
                        cookies.append(cookies[0].replace('Path=' + self.server.native.config['panel_base_path'] + ';', 'Path=/;'))
                    return self.send(200, {'ok': True}, cookie=cookies)
                with self.server.auth_lock:
                    for key in [k for k, v in self.server.sessions.items() if v is session]:
                        del self.server.sessions[key]
                return self.send(200, {'ok': True}, cookie='atlas_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            if path == '/api/connect':
                return self.send(200, {'inbounds': manager.connect(data)})
            if path == '/api/routes/add':
                return self.send(200, {'id': manager.add(data)})
            if path in ('/api/routes/remove', '/api/routes/toggle', '/api/routes/reconnect'):
                rid = str(data.get('id', ''))
                if not any(r['id'] == rid for r in manager.store.read()['routes']):
                    raise ValueError('مسیر پیدا نشد.')
                if path.endswith('remove'):
                    manager.remove(rid)
                elif path.endswith('toggle'):
                    manager.toggle(rid)
                else:
                    with manager.lock:
                        manager.runtime.submit(manager.runtime.reconnect(rid))
                return self.send(200, {'ok': True})
            if path == '/api/check':
                # Return promptly; status is polled. A running check is reused.
                import asyncio
                if not manager.runtime.probe_lock.locked():
                    asyncio.run_coroutine_threadsafe(manager.runtime.check_all(), manager.runtime.loop)
                return self.send(200, {'ok': True})
            if path == '/api/recover':
                manager.recover()
                return self.send(200, {'ok': True})
            if path == '/api/restore':
                return self.send(200, {'backup': manager.restore(str(data.get('backup', '')))})
            if path == '/api/engine':
                if data.get('authorized') is not True:
                    raise ValueError('ابتدا شرایط استفاده را تأیید کنید.')
                from .engine import install
                with manager.lock:
                    install(manager.store.root)
                return self.send(200, {'ok': True})
            return self.send(404, {'error': 'پیدا نشد.'})
        except Exception as exc:
            return self.error(exc)
