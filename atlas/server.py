"""Loopback-first admin UI with password sessions, origin and CSRF checks."""
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

from . import __version__
from .storage import password_matches


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    def __init__(self, address, manager, static=None, tls=False):
        self.manager = manager
        self.static = Path(static or Path(__file__).parent.parent / 'web')
        self.tls = tls
        self.sessions = {}
        self.attempts = collections.defaultdict(list)
        self.auth_lock = threading.Lock()
        super().__init__(address, Handler)


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
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        value = self.headers.get('Host', '')
        try:
            parsed = urllib.parse.urlsplit('//' + value)
            hostname = parsed.hostname
            port = parsed.port or (443 if self.server.tls else 80)
            configured = self.server.manager.store.read().get('public_hostname')
            return not parsed.username and not parsed.password and hostname in (
                '127.0.0.1', 'localhost', self.server.server_address[0], configured) and port == self.server.server_port
        except ValueError:
            return False

    def session(self):
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
        path = urllib.parse.urlsplit(self.path).path
        if path == '/healthz':
            return self.send(200, {'ok': True, 'version': __version__})
        if path == '/api/session':
            session = self.session()
            return self.send(200, {'authenticated': bool(session), 'csrf': session['csrf'] if session else ''})
        if path.startswith('/api/'):
            if not self.session():
                return self.send(401, {'error': 'ابتدا وارد Atlas شوید.'})
            try:
                if path == '/api/state':
                    return self.send(200, self.server.manager.state())
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
        if isinstance(exc, (ValueError, PanelError)):
            return self.send(400, {'error': str(exc)[:400]})
        return self.send(500, {'error': 'عملیات کامل نشد؛ وضعیت مسیر و بازیابی عملیات را بررسی کنید.'})

    def do_POST(self):
        if not self.valid_host():
            return self.send(403, {'error': 'آدرس میزبان مجاز نیست.'})
        expected = ('https' if self.server.tls else 'http') + '://' + self.headers['Host']
        if self.headers.get('Origin') != expected:
            return self.send(403, {'error': 'مبدأ درخواست معتبر نیست.'})
        path = urllib.parse.urlsplit(self.path).path
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
