import argparse
import asyncio
import getpass
import os
from pathlib import Path
import secrets
import signal
import ssl
import threading

from . import __version__
from .manager import Manager
from .runtime import Runtime
from .server import Server
from .storage import Store, atomic_json, password_hash


def main():
    parser = argparse.ArgumentParser(description='FARSTAR Atlas ' + __version__)
    parser.add_argument('--state', default=os.environ.get('ATLAS_STATE', '/var/lib/farstar-atlas'))
    parser.add_argument('command', choices=['init', 'serve', 'password', 'engine', 'detach', 'recover'])
    parser.add_argument('--listen')
    parser.add_argument('--port', type=int)
    parser.add_argument('--hostname')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == 'init':
        path = Path(args.state) / 'config.json'
        if path.exists():
            print('Atlas is already initialized. Configuration preserved.')
            return
        password = secrets.token_urlsafe(18)
        atomic_json(path, {'schema': 1, 'password_hash': password_hash(password), 'routes': [],
            'listen': '127.0.0.1', 'port': 9786, 'public_hostname': None})
        print('Atlas password (shown once): ' + password)
        return
    store = Store(args.state)
    if args.command == 'password':
        value = getpass.getpass('New Atlas password: ')
        if len(value) < 12:
            parser.error('Use at least 12 characters.')
        if value != getpass.getpass('Repeat password: '):
            parser.error('Passwords did not match.')
        config = store.read()
        config['password_hash'] = password_hash(value)
        store.save(config)
        print('Password changed. Restart farstar-atlas to expire existing sessions.')
        return
    if args.command == 'engine':
        from .engine import install
        install(store.root)
        print('Verified official engine installed.')
        return
    runtime = Runtime(store)
    manager = Manager(store, runtime)
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    startup_error = []
    def worker():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(runtime.start(load_routes=args.command == 'serve'))
        except Exception as exc:
            startup_error.append(exc)
            loop.run_until_complete(runtime.close())
            loop.close()
            ready.set()
            return
        ready.set()
        loop.run_forever()
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    ready.wait(30)
    if startup_error or not ready.is_set():
        raise RuntimeError('Atlas runtime could not start. Check occupied ports and installed engine.')
    try:
        if args.command == 'detach':
            with manager.lock:
                manager.apply([], 'مسیرهای Atlas از پنل جدا شد')
            print('Atlas resources detached; panel clients and unrelated settings preserved.')
            return
        if args.command == 'recover':
            manager.recover()
            print('Pending operation recovered.')
            return
        config = store.read()
        listen, port = args.listen or config['listen'], args.port or config['port']
        if args.hostname:
            config['public_hostname'] = args.hostname
            store.save(config)
        if listen not in ('localhost', '127.0.0.1') and not (args.cert and args.key):
            raise ValueError('Public Atlas UI requires --cert and --key. Use an SSH forward for loopback.')
        server = Server((listen, port), manager, tls=bool(args.cert))
        if args.cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.cert, args.key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        if manager.pending.exists():
            store.event('error', 'عملیات نیمه‌تمام شناسایی شد؛ از تنظیمات بازیابی کنید.')
        def stop(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        print('Atlas ' + __version__ + ' listening on ' + listen + ':' + str(port), flush=True)
        server.serve_forever(poll_interval=0.25)
        server.server_close()
    finally:
        runtime.submit(runtime.close(), timeout=15)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)


if __name__ == '__main__':
    main()
