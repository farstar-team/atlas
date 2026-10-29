"""Installer-only read-only discovery of native panel web metadata."""
import ipaddress
import json
import os
from pathlib import Path
import shlex
import socket
import sqlite3
import ssl
import subprocess
import urllib.parse


SETTINGS = ('webPort', 'webBasePath', 'webListen', 'webDomain', 'webCertFile', 'webKeyFile')


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError('Native panel discovery failed: ' + str(args[0]))
    return result.stdout.strip()


def panel_environment(unit):
    try:
        pid = command(['systemctl', 'show', unit, '-p', 'MainPID', '--value'])
        if not pid.isdigit() or int(pid) < 2:
            return {}
        return dict(item.decode().split('=', 1) for item in (Path('/proc') / pid / 'environ').read_bytes().split(b'\0') if b'=' in item)
    except (OSError, ValueError):
        return {}


def read_sqlite(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError('Native panel database not found; use --panel-db PATH or --panel-unit NAME.')
    uri = 'file:' + urllib.parse.quote(str(path), safe='/') + '?mode=ro'
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        placeholders = ','.join('?' for _ in SETTINGS)
        return dict(connection.execute('SELECT key,value FROM settings WHERE key IN (' + placeholders + ')', SETTINGS))
    finally:
        connection.close()


def settings(args):
    if args.panel_db:
        return read_sqlite(args.panel_db)
    # Reuse only public-web metadata from an already installed ZARIB, never its
    # database reader credentials, accounting state or private API token.
    zarib = Path('/etc/farstar-inbound-multiplier/config.json')
    if zarib.is_file():
        data = json.loads(zarib.read_text())
        return {'webPort': data['panel_port'], 'webBasePath': data['base_path'],
            'webDomain': data['hostname'], 'webListen': data.get('panel_connect_host', '127.0.0.1'),
            'webCertFile': data.get('cert_file', ''), 'webKeyFile': data.get('key_file', '')}
    env = panel_environment(args.panel_unit)
    if env.get('XUI_DB_TYPE', '').lower() not in ('postgres', 'postgresql', 'pg'):
        return read_sqlite(Path(env.get('XUI_DB_FOLDER', '/etc/x-ui')) / 'x-ui.db')
    dsn = env.get('XUI_DB_DSN', '')
    if dsn.startswith(('postgres://', 'postgresql://')):
        parsed = urllib.parse.urlsplit(dsn)
        host, port, database = parsed.hostname or '127.0.0.1', parsed.port or 5432, urllib.parse.unquote(parsed.path.lstrip('/')) or 'xui'
    else:
        values = dict(item.split('=', 1) for item in shlex.split(dsn) if '=' in item)
        host, port, database = values.get('host', '127.0.0.1'), int(values.get('port', 5432)), values.get('dbname', 'xui')
    if host not in ('127.0.0.1', '::1', 'localhost') and not host.startswith('/'):
        raise ValueError('Automatic discovery supports a local panel database only.')
    query = "SELECT COALESCE(json_object_agg(key,value),'{}') FROM settings WHERE key IN (" + ','.join("'" + s + "'" for s in SETTINGS) + ');'
    args = ['runuser', '-u', 'postgres', '--', 'psql', '-X']
    if host.startswith('/'):
        args += ['-h', host]
    result = subprocess.run(args + ['-p', str(port), '-d', database, '-At', '-v', 'ON_ERROR_STOP=1'], input=query,
        capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError('Read-only local PostgreSQL discovery failed; check the panel database service.')
    return json.loads(result.stdout)


def hostname(value):
    value = value.strip().strip('[]')
    if not value or len(value) > 253 or any(c in value for c in '/\\\r\n\t @?#;'):
        raise ValueError('Provide a public hostname or IP without scheme, path or port.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if ':' in value:
            raise ValueError('Invalid hostname') from None
        return value.encode('idna').decode('ascii').lower()


def addresses():
    rows = json.loads(command(['ip', '-j', '-4', 'address', 'show', 'scope', 'global']))
    return [str(ipaddress.ip_address(item['local'])) for row in rows for item in row.get('addr_info', [])
            if item.get('local') and (row.get('ifname') != 'lo' or ipaddress.ip_address(item['local']).is_global)]


def discover(args, old=None):
    data = settings(args)
    base = str(data.get('webBasePath') or '/')
    if not base.startswith('/') or any(c in base for c in ('?', '#', '\r', '\n', '\\', ';')) or '..' in base.split('/'):
        raise ValueError('Invalid native panel base path')
    base = base.rstrip('/') + '/'
    cert, key = str(data.get('webCertFile') or ''), str(data.get('webKeyFile') or '')
    if bool(cert) != bool(key):
        raise ValueError('Native panel certificate and key must both be configured.')
    ips = addresses()
    names = []
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        decoded = ssl._ssl._test_decode_cert(cert)
        names = [v for kind, v in decoded.get('subjectAltName', []) if kind in ('DNS', 'IP Address') and '*' not in v]
    primary = hostname(args.host or data.get('webDomain') or (names[0] if names else '') or
        next((ip for ip in ips if ipaddress.ip_address(ip).is_global), '') or (ips[0] if ips else ''))
    # Native TLS validation uses a certificate name even when a browser uses an
    # IP alias. A native panel with webDomain uses that name for its Host check.
    native_host = hostname(data.get('webDomain') or (names[0] if names else primary))
    panel_port = int(data.get('webPort') or 2053)
    wanted = args.web_port or (old or {}).get('port') or 9786
    candidates = [wanted] if args.web_port else list(dict.fromkeys([wanted, 9787, 9788]))
    chosen = None
    for port in candidates:
        if not 1024 <= port <= 60999 or port == panel_port:
            continue
        # Existing Atlas is intentionally allowed to keep its own bound port.
        if old and port == old.get('port'):
            chosen = port; break
        try:
            with socket.socket() as listener:
                listener.bind(('0.0.0.0', port))
            chosen = port; break
        except OSError:
            continue
    if chosen is None:
        raise ValueError('No free public Atlas port; specify --web-port PORT.')
    listen = data.get('webListen')
    return {'mode': 'panel', 'listen': '0.0.0.0', 'port': chosen,
        'hostname': primary, 'hosts': sorted(set([primary, native_host, *ips])),
        'scheme': 'https' if cert else 'http', 'base_path': base + 'atlas/',
        'panel_base_path': base, 'panel_hostname': native_host, 'panel_port': panel_port,
        'panel_connect_host': listen if listen not in (None, '', '0.0.0.0', '::') else '127.0.0.1',
        'cert_source': cert, 'key_source': key}
