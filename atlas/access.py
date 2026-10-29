"""Local native-panel login/session bridge. Never stores panel passwords."""
import hashlib
import hmac
import http.client
import http.cookies
import json
import secrets
import socket
import ssl
import urllib.parse


COOKIE = '3x-ui'


class LoginRequired(PermissionError):
    pass


class PanelUnavailable(RuntimeError):
    pass


def native_cookie(header):
    if not header or len(header) > 8192 or '\r' in header or '\n' in header:
        return ''
    try:
        # Browsers send the most specific path first. Do not let a stale
        # legacy Path=/ cookie replace a fresh native-base-path cookie.
        for part in header.split(';'):
            parsed = http.cookies.SimpleCookie(part.strip())
            if COOKIE in parsed:
                return parsed[COOKIE].value
        return ''
    except http.cookies.CookieError:
        return ''


class PanelAccess:
    def __init__(self, config):
        self.config = config
        self.secret = secrets.token_bytes(32)

    def request(self, path, data=None, cookie='', csrf='', client_ip=''):
        cfg = self.config
        if cfg['scheme'] == 'https':
            context = ssl.create_default_context(cafile=cfg['cert_file'])
            context.verify_flags |= getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0)
            connection = http.client.HTTPSConnection(cfg['panel_hostname'], cfg['panel_port'], context=context, timeout=10)
        else:
            connection = http.client.HTTPConnection(cfg['panel_hostname'], cfg['panel_port'], timeout=10)
        connection._create_connection = lambda *a, **k: socket.create_connection((cfg['panel_connect_host'], cfg['panel_port']), timeout=6)
        headers = {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
        if cookie:
            headers['Cookie'] = COOKIE + '=' + cookie
        if data is not None:
            headers.update({'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': self.panel_origin(cfg['panel_hostname']), 'X-CSRF-Token': csrf})
            # Never forward caller-provided forwarding headers.
            if client_ip:
                headers.update({'X-Forwarded-For': client_ip, 'X-Real-IP': client_ip})
        try:
            body = urllib.parse.urlencode(data).encode() if data is not None else None
            connection.request('POST' if data is not None else 'GET', cfg['panel_base_path'] + path, body, headers)
            response = connection.getresponse()
            raw = response.read(5 * 1024 * 1024 + 1)
            if response.status in (401, 403, 404):
                raise LoginRequired('ابتدا با حساب پنل ثنایی وارد شوید.')
            if response.status != 200 or len(raw) > 5 * 1024 * 1024:
                raise PanelUnavailable('ارتباط با پنل ثنایی برقرار نشد؛ دوباره امتحان کنید.')
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError('Invalid native response')
            cookies = [v for k, v in response.getheaders() if k.lower() == 'set-cookie']
            return result, cookies
        except (LoginRequired, PanelUnavailable):
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise PanelUnavailable('ارتباط با پنل ثنایی برقرار نشد؛ دوباره امتحان کنید.') from None
        finally:
            connection.close()

    def validate(self, cookie, origin):
        if not cookie:
            raise LoginRequired('با نام کاربری و رمز پنل ثنایی وارد شوید.')
        result, _ = self.request('panel/api/inbounds/list', cookie=cookie)
        if not result.get('success') or not isinstance(result.get('obj'), list):
            raise LoginRequired('نشست ثنایی معتبر نیست؛ دوباره وارد شوید.')
        return {'csrf': hmac.new(self.secret, (cookie + '\0' + origin).encode(), hashlib.sha256).hexdigest()}

    def login(self, data, client_ip):
        username, password = str(data.get('username', '')), str(data.get('password', ''))
        code = str(data.get('twoFactorCode', ''))
        if not username or not password or len(username) > 256 or len(password) > 4096 or len(code) > 32:
            raise LoginRequired('نام کاربری، رمز و در صورت نیاز کد دومرحله‌ای ثنایی را وارد کنید.')
        initial, cookies = self.request('csrf-token')
        cookie = next((native_cookie(value) for value in reversed(cookies) if native_cookie(value)), '')
        if not initial.get('success') or not initial.get('obj') or not cookie:
            raise PanelUnavailable('نسخهٔ پنل برای ورود مرورگری پشتیبانی نمی‌شود.')
        result, cookies = self.request('login', {'username': username, 'password': password, 'twoFactorCode': code},
            cookie=cookie, csrf=str(initial['obj']), client_ip=client_ip)
        if not result.get('success'):
            raise LoginRequired('نام کاربری، رمز یا کد دومرحله‌ای ثنایی صحیح نیست.')
        cookie = next((native_cookie(value) for value in reversed(cookies) if native_cookie(value)), '')
        if not cookie:
            raise PanelUnavailable('پنل نشست ورود برنگرداند؛ دوباره تلاش کنید.')
        selected = next((value for value in reversed(cookies) if native_cookie(value) == cookie), '')
        parsed = http.cookies.SimpleCookie(selected)
        max_age = parsed[COOKIE]['max-age'] or None
        return cookie, max_age

    def panel_origin(self, hostname):
        host = '[' + hostname + ']' if ':' in hostname else hostname
        return self.config['scheme'] + '://' + host + ':' + str(self.config['panel_port'])

    def login_url(self, hostname):
        return self.panel_origin(hostname) + self.config['panel_base_path']

    def browser_cookie(self, cookie, expires=False, max_age=None):
        # Host-only, native path and native scheme: shared across ports, never
        # widened to unrelated domains, and compatible with native sign-out.
        value = COOKIE + '=' + cookie + '; Path=' + self.config['panel_base_path'] + '; HttpOnly; SameSite=Lax'
        if self.config['scheme'] == 'https':
            value += '; Secure'
        if expires:
            value += '; Max-Age=0'
        elif max_age and str(max_age).lstrip('-').isdigit():
            value += '; Max-Age=' + str(max_age)
        return value
