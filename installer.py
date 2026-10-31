#!/usr/bin/env python3
"""Atomic sidecar installation. No database access, firewall flush or x-ui restart."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
import http.client
import json
import ssl
import socket


UNIT = '''[Unit]
Description=FARSTAR Atlas country exits
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=farstar-atlas
Group=farstar-atlas
WorkingDirectory=/opt/farstar-atlas/current
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -m atlas --state /var/lib/farstar-atlas serve
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
StateDirectory=farstar-atlas
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=true
LimitNOFILE=8192
TasksMax=512

[Install]
WantedBy=multi-user.target
'''

CERT_UNIT = '''[Unit]
Description=Refresh Atlas copies of the native panel TLS certificate

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/farstar-atlas/current
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m atlas.certificates --config /etc/farstar-atlas/access.json
NoNewPrivileges=true
PrivateTmp=true
PrivateNetwork=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/etc/farstar-atlas/tls
'''

CERT_TIMER = '''[Unit]
Description=Refresh Atlas panel TLS certificate copies

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=farstar-atlas-certificates.service

[Install]
WantedBy=timers.target
'''

EXISTING_UNIT = '''[Unit]
Description=Atlas restricted controller for existing country exits
After=network.target

[Service]
Type=simple
User=root
Group=farstar-atlas
WorkingDirectory=/opt/farstar-atlas/current
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m atlas.existing
Restart=on-failure
RestartSec=3
RuntimeDirectory=farstar-atlas-existing
RuntimeDirectoryMode=0750
StateDirectory=farstar-atlas-existing
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateNetwork=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=-/opt/irg-country-egress
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER

[Install]
WantedBy=multi-user.target
'''


def install_existing_helper(access_path, gid, write_root):
    config = {'native_config': '/usr/local/x-ui/bin/config.json', 'country_root': '/opt/irg-country-egress',
        'haproxy_binary': '/opt/irg-tls-runtime/usr/sbin/haproxy' if Path('/opt/irg-tls-runtime/usr/sbin/haproxy').is_file() else '/usr/sbin/haproxy',
        'library_path': '/opt/irg-tls-runtime/usr/lib/x86_64-linux-gnu' if Path('/opt/irg-tls-runtime/usr/lib/x86_64-linux-gnu').is_dir() else ''}
    # Never accept helper paths/units from browser or service-user state.
    write_root(access_path.parent/'existing.json', json.dumps(config, indent=2).encode(), gid)
    target = Path('/etc/systemd/system/farstar-atlas-existing.service')
    target.write_text(EXISTING_UNIT); target.chmod(0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'farstar-atlas-existing.service'], stdout=subprocess.DEVNULL)
    run(['systemctl', 'restart', 'farstar-atlas-existing.service'])
    for _ in range(30):
        try:
            from atlas.existing import ExistingClient
            ExistingClient().inventory()
            return
        except (OSError, ValueError):
            time.sleep(.2)
    raise RuntimeError('Existing-exit helper did not become healthy.')


def probe_web(access, private_port=9786):
    """Connect over loopback while validating the real public Host and TLS."""
    if not access:
        access = {'hostname': '127.0.0.1', 'scheme': 'http', 'port': private_port, 'base_path': '/'}
    if access['scheme'] == 'https':
        context = ssl.create_default_context(cafile=access['cert_file'])
        context.verify_flags |= getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0)
        connection = http.client.HTTPSConnection(access['panel_hostname'], access['port'], context=context, timeout=3)
    else:
        connection = http.client.HTTPConnection(access['hostname'], access['port'], timeout=3)
    connection._create_connection = lambda *a, **k: socket.create_connection(('127.0.0.1', access['port']), timeout=3)
    try:
        connection.request('GET', '/healthz', headers={'Host': access['hostname'] + ':' + str(access['port'])})
        response = connection.getresponse()
        if response.status != 200 or not json.loads(response.read(4096)).get('ok'):
            raise RuntimeError('Atlas health check failed')
    finally:
        connection.close()


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def checked_files(source):
    records = []
    for line in (source / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split(None, 1)
        name = name.lstrip('* ')
        path = (source / name).resolve()
        if not path.is_relative_to(source.resolve()) or (source / name).is_symlink() or len(digest) != 64:
            raise RuntimeError('Unsafe manifest')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Checksum mismatch: ' + name)
        records.append(name)
    required = {'atlas/__main__.py', 'atlas/server.py', 'atlas/license_client.py', 'atlas/ui_errors.py', 'web/ui-feedback.js', 'atlas/existing.py', 'atlas/hosts.py', 'web/index.html', 'providers/psiphon.json', 'VERSION'}
    if not required.issubset(records):
        raise RuntimeError('Incomplete manifest')
    return records


def stage(source, root):
    files = checked_files(source)
    version = (source / 'VERSION').read_text().strip()
    if not version or any(c not in '0123456789.-abcdefghijklmnopqrstuvwxyz' for c in version):
        raise RuntimeError('Invalid version')
    digest = hashlib.sha256((source / 'SHA256SUMS').read_bytes()).hexdigest()[:12]
    release = root / 'releases' / (version + '-' + digest)
    if release.exists():
        # A damaged existing release must never be reused silently.
        for name in files:
            if not (release/name).is_file() or (release/name).read_bytes() != (source/name).read_bytes():
                raise RuntimeError('Existing release is damaged: ' + name)
        return release
    temporary = release.with_name('.' + release.name + '-' + str(os.getpid()))
    (root / 'releases').mkdir(parents=True, exist_ok=True, mode=0o755)
    (root / 'releases').chmod(0o755)
    temporary.mkdir(parents=True, mode=0o755)
    temporary.chmod(0o755)
    try:
        for name in files:
            destination = temporary / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            shutil.copyfile(source / name, destination)
            destination.chmod(0o644)
        (temporary / 'SHA256SUMS').write_bytes((source / 'SHA256SUMS').read_bytes())
        (temporary / 'SHA256SUMS').chmod(0o644)
        for directory, _, _ in os.walk(temporary):
            Path(directory).chmod(0o755)
        for script in (temporary / 'atlas').glob('*.py'):
            compile(script.read_bytes(), str(script), 'exec')
        os.replace(temporary, release)
        return release
    except BaseException:
        if temporary.is_relative_to(root / 'releases'):
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def point(root, release):
    temporary = root / ('.current-' + str(os.getpid()))
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(release, target_is_directory=True)
    os.replace(temporary, root / 'current')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).parent)
    parser.add_argument('--root', type=Path, default=Path('/opt/farstar-atlas'))
    parser.add_argument('--stage-only', action='store_true', help='Package verification for isolated tests; never touches services')
    parser.add_argument('--private', action='store_true', help='Opt into legacy loopback/password administration')
    parser.add_argument('--host', help='Public panel hostname or IP; detected automatically by default')
    parser.add_argument('--web-port', type=int)
    parser.add_argument('--panel-db', type=Path)
    parser.add_argument('--panel-unit', default='x-ui.service')
    args = parser.parse_args()
    if not args.stage_only and (os.name != 'posix' or os.geteuid() != 0):
        parser.error('Run as root on Linux.')
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    root.chmod(0o755)
    release = stage(args.source.resolve(), root)
    if args.stage_only:
        print('Verified release: ' + str(release))
        return
    if root != Path('/opt/farstar-atlas'):
        parser.error('Custom roots are supported only with --stage-only.')
    if not Path('/usr/local/x-ui/x-ui').is_file():
        parser.error('Install a native 3x-ui panel first; Docker panels are not supported in this version.')
    old = (root/'current').resolve() if (root/'current').is_symlink() else None
    old_unit = Path('/etc/systemd/system/farstar-atlas.service')
    old_unit_bytes = old_unit.read_bytes() if old_unit.exists() else None
    helper_unit = Path('/etc/systemd/system/farstar-atlas-existing.service')
    helper_bytes = helper_unit.read_bytes() if helper_unit.exists() else None
    helper_was_active = subprocess.run(['systemctl', 'is-active', '--quiet', 'farstar-atlas-existing'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    access_path = Path('/etc/farstar-atlas/access.json')
    old_access_bytes = access_path.read_bytes() if access_path.exists() else None
    old_access = json.loads(old_access_bytes) if old_access_bytes else None
    access = None
    if not args.private:
        from atlas.discovery import discover
        access = discover(args, old_access)
    if subprocess.run(['id', '-u', 'farstar-atlas'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(['useradd', '--system', '--home-dir', '/var/lib/farstar-atlas', '--shell', '/usr/sbin/nologin', 'farstar-atlas'])
    state = Path('/var/lib/farstar-atlas')
    state.mkdir(mode=0o700, exist_ok=True)
    shutil.chown(state, user='farstar-atlas', group='farstar-atlas')
    state.chmod(0o700)
    run(['runuser', '-u', 'farstar-atlas', '--', '/usr/bin/python3', '-m', 'atlas', '--state', str(state), 'init'], cwd=release,
        stdout=None if args.private else subprocess.PIPE)
    from atlas.certificates import sync as sync_certificates, write as write_root
    import grp
    gid = grp.getgrnam('farstar-atlas').gr_gid
    access_path.parent.mkdir(mode=0o750, exist_ok=True)
    if access_path.parent.is_symlink() or access_path.parent.stat().st_uid != 0 or access_path.parent.stat().st_mode & 0o022:
        raise RuntimeError('Unsafe Atlas access directory')
    os.chown(access_path.parent, 0, gid); access_path.parent.chmod(0o750)
    if access:
        access.update(cert_file=str(access_path.parent/'tls/panel.pem'), key_file=str(access_path.parent/'tls/panel.key'))
        write_root(access_path, json.dumps(access, indent=2).encode(), gid)
        try:
            sync_certificates(access_path)
        except BaseException:
            if old_access_bytes is not None:
                write_root(access_path, old_access_bytes, gid)
            else:
                access_path.unlink(missing_ok=True)
            raise
    else:
        access_path.unlink(missing_ok=True)
    point(root, release)
    old_unit.write_text(UNIT)
    old_unit.chmod(0o644)
    launcher = Path('/usr/local/bin/atlas')
    launcher.write_text('#!/bin/sh\ncd /opt/farstar-atlas/current || exit 1\nexec /usr/bin/python3 -m atlas "$@"\n')
    launcher.chmod(0o755)
    run(['systemctl', 'daemon-reload'])
    try:
        install_existing_helper(access_path, gid, write_root)
        run(['systemctl', 'enable', 'farstar-atlas.service'], stdout=subprocess.DEVNULL)
        run(['systemctl', 'restart', 'farstar-atlas.service'])
        for attempt in range(20):
            try:
                probe_web(access, private_port=json.loads((state/'config.json').read_text()).get('port', 9786))
                break
            except (OSError, ValueError, RuntimeError, http.client.HTTPException):
                time.sleep(0.5)
        else:
            raise RuntimeError('Atlas health check failed')
        if access and access['scheme'] == 'https':
            for name, content in (('farstar-atlas-certificates.service', CERT_UNIT), ('farstar-atlas-certificates.timer', CERT_TIMER)):
                path = Path('/etc/systemd/system')/name
                path.write_text(content); path.chmod(0o644)
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'enable', '--now', 'farstar-atlas-certificates.timer'], stdout=subprocess.DEVNULL)
        else:
            subprocess.run(['systemctl', 'disable', '--now', 'farstar-atlas-certificates.timer'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except BaseException:
        subprocess.run(['systemctl', 'stop', 'farstar-atlas-existing'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if helper_bytes is not None:
            helper_unit.write_bytes(helper_bytes)
        else:
            subprocess.run(['systemctl', 'disable', 'farstar-atlas-existing'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            helper_unit.unlink(missing_ok=True)
        if old_access_bytes is not None:
            write_root(access_path, old_access_bytes, gid)
            sync_certificates(access_path)
        else:
            access_path.unlink(missing_ok=True)
        if old:
            point(root, old)
            if old_unit_bytes is not None:
                old_unit.write_bytes(old_unit_bytes)
            run(['systemctl', 'daemon-reload'])
            if helper_was_active and helper_bytes is not None:
                run(['systemctl', 'restart', 'farstar-atlas-existing'])
            run(['systemctl', 'restart', 'farstar-atlas.service'])
        else:
            subprocess.run(['systemctl', 'stop', 'farstar-atlas.service'])
        raise
    if access:
        print('\nAtlas is ready. Sign in using your existing 3x-ui account.')
        print('URL: ' + access['scheme'] + '://' + access['hostname'] + ':' + str(access['port']) + access['base_path'])
        for ip in access['hosts']:
            if ip != access['hostname']:
                print('Alias: ' + access['scheme'] + '://' + ip + ':' + str(access['port']) + access['base_path'])
        print('HTTPS aliases require the native certificate to cover that IP or hostname, just like the original panel.')
    else:
        print('\nAtlas private UI: http://127.0.0.1:9786 (SSH forwarding required).')
    print('Updates restart Atlas only; active Atlas streams may reconnect. x-ui is never explicitly restarted.')


if __name__ == '__main__':
    main()
