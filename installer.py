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
    required = {'atlas/__main__.py', 'atlas/server.py', 'web/index.html', 'providers/psiphon.json', 'VERSION'}
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
    if subprocess.run(['id', '-u', 'farstar-atlas'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(['useradd', '--system', '--home-dir', '/var/lib/farstar-atlas', '--shell', '/usr/sbin/nologin', 'farstar-atlas'])
    state = Path('/var/lib/farstar-atlas')
    state.mkdir(mode=0o700, exist_ok=True)
    shutil.chown(state, user='farstar-atlas', group='farstar-atlas')
    state.chmod(0o700)
    run(['runuser', '-u', 'farstar-atlas', '--', '/usr/bin/python3', '-m', 'atlas', '--state', str(state), 'init'], cwd=release)
    point(root, release)
    old_unit.write_text(UNIT)
    old_unit.chmod(0o644)
    launcher = Path('/usr/local/bin/atlas')
    launcher.write_text('#!/bin/sh\ncd /opt/farstar-atlas/current || exit 1\nexec /usr/bin/python3 -m atlas "$@"\n')
    launcher.chmod(0o755)
    run(['systemctl', 'daemon-reload'])
    try:
        run(['systemctl', 'enable', 'farstar-atlas.service'], stdout=subprocess.DEVNULL)
        run(['systemctl', 'restart', 'farstar-atlas.service'])
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(20):
            try:
                with opener.open('http://127.0.0.1:9786/healthz', timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError('Atlas health check failed')
    except BaseException:
        if old:
            point(root, old)
            if old_unit_bytes is not None:
                old_unit.write_bytes(old_unit_bytes)
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'restart', 'farstar-atlas.service'])
        else:
            subprocess.run(['systemctl', 'stop', 'farstar-atlas.service'])
        raise
    print('\nAtlas is ready. Its admin UI is private by default.')
    print('From your computer: ssh -L 9786:127.0.0.1:9786 root@YOUR_SERVER -p YOUR_SSH_PORT')
    print('Then open http://127.0.0.1:9786')
    print('Updates restart Atlas only; active Atlas streams may reconnect. x-ui is never explicitly restarted.')


if __name__ == '__main__':
    main()
