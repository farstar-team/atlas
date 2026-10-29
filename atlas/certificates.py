"""Root-only TLS copy refresh; no access to user-writable Atlas state."""
import argparse
import grp
import json
import os
from pathlib import Path
import secrets
import ssl


def write(path, data, gid, mode=0o640):
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(5))
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.chown(temporary, 0, gid); temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def sync(config_path):
    config_path = Path(config_path)
    if os.geteuid() != 0 or config_path.is_symlink():
        raise ValueError('TLS refresh requires a root-owned access configuration.')
    stat = config_path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise ValueError('Access configuration must not be writable by the service user.')
    cfg = json.loads(config_path.read_text())
    if cfg.get('scheme') != 'https':
        return
    directory = config_path.parent / 'tls'
    if directory.is_symlink():
        raise ValueError('Unsafe TLS directory')
    directory.mkdir(mode=0o750, exist_ok=True)
    st = directory.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError('Unsafe TLS directory owner/mode')
    gid = grp.getgrnam('farstar-atlas').gr_gid
    os.chown(directory, 0, gid); directory.chmod(0o750)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cfg['cert_source'], cfg['key_source'])
    # Validate the complete source pair before atomically replacing either file.
    for source, target in ((cfg['cert_source'], 'panel.pem'), (cfg['key_source'], 'panel.key')):
        data = Path(source).read_bytes()
        if not 0 < len(data) <= 1024 * 1024:
            raise ValueError('Invalid TLS file size')
        destination = directory / target
        if destination.is_symlink():
            raise ValueError('Unsafe TLS destination')
        if not destination.exists() or destination.read_bytes() != data:
            write(destination, data, gid)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--config', required=True)
    sync(parser.parse_args().config)
