"""Download the reviewed official Psiphon binary; never execute a mutable URL."""
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import tempfile

from .storage import atomic_json


def install(root):
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise ValueError('موتور آمادهٔ Psiphon در این نسخه فقط برای Linux x86_64 است؛ خروجی SOCKS روی ARM هم قابل استفاده است.')
    root = Path(root)
    manifest = json.loads((Path(__file__).parent.parent / 'providers' / 'psiphon.json').read_text(encoding='utf-8'))
    engine = root / 'engine'
    engine.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.download-', dir=engine)
    os.close(fd)
    temporary = Path(temporary)
    try:
        result = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
            '--max-time', '180', '--connect-timeout', '15', '--max-filesize', '20000000',
            '--output', str(temporary), manifest['url']], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=190)
        if result.returncode or hashlib.sha256(temporary.read_bytes()).hexdigest() != manifest['sha256']:
            raise ValueError('دریافت یا بررسی صحت فایل کامل نشد؛ فایل اجرا نشد.')
        temporary.chmod(0o700)
        atomic_json(engine / 'public-config.json', manifest['public_config'])
        os.replace(temporary, engine / 'ConsoleClient')
    except subprocess.TimeoutExpired:
        raise ValueError('مهلت دریافت موتور تمام شد؛ دوباره تلاش کنید.') from None
    finally:
        temporary.unlink(missing_ok=True)
