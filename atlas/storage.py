"""Atomic private configuration and a bounded, credential-free event log."""
import copy
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest


def password_matches(password, stored):
    try:
        return secrets.compare_digest(password_hash(password, stored.split(':')[0]), stored)
    except (ValueError, TypeError):
        return False


class Store:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / 'config.json'
        self.lock = threading.RLock()
        if not self.path.exists():
            raise RuntimeError('ابتدا atlas init را اجرا کنید.')
        self.config = json.loads(self.path.read_text(encoding='utf-8'))
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at REAL, kind TEXT, message TEXT)')
        try:
            (self.root / 'events.sqlite').chmod(0o600)
        except OSError:
            pass

    @contextlib.contextmanager
    def db(self):
        connection = sqlite3.connect(self.root / 'events.sqlite', timeout=15)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, value):
        with self.lock:
            atomic_json(self.path, value)
            self.config = copy.deepcopy(value)

    def read(self):
        with self.lock:
            return copy.deepcopy(self.config)

    def event(self, kind, message):
        # Only fixed, operator-facing messages belong here; never API bodies.
        with self.db() as db:
            db.execute('INSERT INTO events (at,kind,message) VALUES (?,?,?)', (time.time(), kind, message))
            db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 300)')

    def events(self):
        with self.db() as db:
            return [dict(zip(('id', 'at', 'kind', 'message'), row)) for row in db.execute(
                'SELECT id,at,kind,message FROM events ORDER BY id DESC LIMIT 30')]

    def backup(self, value):
        name = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(4)
        atomic_json(self.root / 'backups' / (name + '.json'), value)
        return name

    def backups(self):
        return sorted((p.stem for p in (self.root / 'backups').glob('*.json')), reverse=True)[:30]

    def load_backup(self, name):
        if name not in self.backups():
            raise ValueError('نسخهٔ پشتیبان پیدا نشد.')
        return json.loads((self.root / 'backups' / (name + '.json')).read_text(encoding='utf-8'))
