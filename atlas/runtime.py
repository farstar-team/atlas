"""Managed Psiphon processes, HTTPS health checks and connection failover."""
import asyncio
import contextlib
import copy
import ipaddress
import json
import os
from pathlib import Path
import time

from .network import serve_entry, serve_socks
from .storage import atomic_json


COUNTRIES = {'FR': 'France', 'NL': 'Netherlands', 'DE': 'Germany', 'GB': 'United Kingdom',
    'US': 'United States', 'CA': 'Canada', 'JP': 'Japan', 'SG': 'Singapore', 'SE': 'Sweden',
    'CH': 'Switzerland', 'IT': 'Italy', 'PL': 'Poland', 'AU': 'Australia'}


def flag(code):
    return ''.join(chr(ord(c) + 127397) for c in code)


async def probe(proxy, expected='', runner=None):
    """A connected TCP port is not health: TLS must return an IP and country."""
    args = ['curl', '--silent', '--show-error', '--fail', '--max-time', '12', '--connect-timeout', '5',
        '--max-filesize', '65536', '--proxy', proxy or '', '--noproxy', '',
        'https://www.cloudflare.com/cdn-cgi/trace']
    started = time.monotonic()
    process = None
    try:
        if runner:
            code, output = await runner(args)
        else:
            # The proxy URL, which may include credentials, is not a CLI argument.
            # curl reads it from stdin instead of exposing it in the process list.
            args[args.index('--proxy') + 1] = ''
            if proxy:
                args = [a for a in args]
                idx = args.index('--proxy')
                del args[idx:idx + 2]
                args = args[:-1] + ['--config', '-', args[-1]]
            process = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            config = ('proxy = ' + json.dumps(proxy) + '\n').encode() if proxy else b''
            output, _ = await asyncio.wait_for(process.communicate(config), 16)
            code = process.returncode
        fields = dict(line.split('=', 1) for line in output.decode().splitlines() if '=' in line)
        ipaddress.ip_address(fields.get('ip', ''))
        if code or len(fields.get('loc', '')) != 2:
            raise ValueError('No verified HTTP response')
        if expected and fields['loc'] != expected:
            return {'ok': False, 'country': fields['loc'], 'ip': fields['ip'], 'reason': 'country_mismatch'}
        return {'ok': True, 'ip': fields['ip'], 'country': fields['loc'],
                'latency_ms': round((time.monotonic() - started) * 1000)}
    except (OSError, ValueError, asyncio.TimeoutError):
        if process and process.returncode is None:
            process.kill()
            await process.wait()
        return {'ok': False, 'reason': 'https_failed'}


class Runtime:
    def __init__(self, store):
        self.store = store
        self.loop = None
        self.entries = {}
        self.status = {}
        self.stopping = False
        self.probe_lock = asyncio.Lock()
        self.lifecycle_lock = asyncio.Lock()
        self.connections = 0
        self.limit = 2048

    async def start(self, load_routes=True):
        self.loop = asyncio.get_running_loop()
        if load_routes:
            await self.reload(self.store.read()['routes'])
        self.worker = asyncio.create_task(self.monitor())

    def submit(self, coro, timeout=240):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        try:
            return future.result(timeout)
        except TimeoutError:
            future.cancel()
            raise

    async def guarded(self, handler, reader, writer):
        if self.connections >= self.limit:
            writer.close()
            return
        self.connections += 1
        try:
            await handler(reader, writer)
        finally:
            self.connections -= 1

    async def spawn(self, route):
        if route['provider'] != 'psiphon':
            return None
        executable = self.store.root / 'engine' / 'ConsoleClient'
        metadata = self.store.root / 'engine' / 'public-config.json'
        if not executable.exists() or not metadata.exists():
            raise RuntimeError('موتور Psiphon نصب نیست؛ از بخش تنظیمات نصب کنید.')
        root = self.store.root / 'providers' / route['id']
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        config = json.loads(metadata.read_text(encoding='utf-8'))
        config.update({'EgressRegion': route['country'], 'LocalSocksProxyPort': route['provider_port'],
            'ListenInterface': 'lo', 'DisableLocalHTTPProxy': True, 'ClientPlatform': 'Linux',
            'DataRootDirectory': str(root), 'RemoteServerListDownloadFilename': str(root / 'server-list'),
            'NetworkID': 'ATLAS', 'EstablishTunnelTimeoutSeconds': 90})
        atomic_json(root / 'config.json', config)
        return await asyncio.create_subprocess_exec(str(executable), '-config', str(root / 'config.json'),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            env={k: v for k, v in os.environ.items() if 'proxy' not in k.lower()})

    async def stop_entry(self, rid):
        item = self.entries.pop(rid)
        for server in item['servers']:
            server.close()
            await server.wait_closed()
        process = item.get('process')
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        self.status.pop(rid, None)

    async def reload(self, routes):
        async with self.lifecycle_lock:
            await self._reload(routes)

    async def _reload(self, routes):
        desired = {r['id']: r for r in routes if r.get('enabled', True)}
        for rid in list(self.entries):
            if rid not in desired or self.entries[rid]['route'] != desired[rid]:
                await self.stop_entry(rid)
        for rid, route in desired.items():
            if rid in self.entries:
                continue
            if route.get('kind') == 'existing':
                # Observe the installed listeners and processes. Never bind,
                # replace, terminate or take ownership of their live traffic.
                self.entries[rid] = {'route': copy.deepcopy(route), 'servers': [], 'process': None,
                    'last_restart': time.monotonic()}
                self.status[rid] = {'healthy': False, 'state': 'checking'}
                continue
            servers = []
            process = None
            try:
                process = await self.spawn(route)
                async def socks(reader, writer, key=rid):
                    await serve_socks(reader, writer, lambda: self.status.get(key, {}).get('_selected'))
                async def entry(reader, writer, item=copy.deepcopy(route)):
                    await serve_entry(reader, writer, item)
                async def s_handler(reader, writer, fn=socks):
                    await self.guarded(fn, reader, writer)
                async def e_handler(reader, writer, fn=entry):
                    await self.guarded(fn, reader, writer)
                servers.append(await asyncio.start_server(s_handler, '127.0.0.1', route['socks_port']))
                servers.append(await asyncio.start_server(e_handler, route.get('entry_listen', '0.0.0.0'), route['entry_port']))
                self.entries[rid] = {'route': copy.deepcopy(route), 'servers': servers, 'process': process, 'last_restart': time.monotonic()}
                self.status[rid] = {'healthy': False, 'state': 'checking', '_selected': None}
            except BaseException:
                for server in servers:
                    server.close()
                if process and process.returncode is None:
                    process.terminate()
                    await process.wait()
                raise

    async def check_one(self, route):
        rid = route['id']
        if route.get('kind') == 'existing':
            return await self.check_existing(route)
        primary = ('socks5h://127.0.0.1:' + str(route['provider_port'])) if route['provider'] == 'psiphon' else route['proxy']
        main = await probe(primary, route['country'])
        selected, active, state = None, {}, 'offline'
        if main['ok']:
            selected, active, state = primary, main, 'primary'
        elif route.get('fallback_proxy'):
            backup = await probe(route['fallback_proxy'])
            if backup['ok']:
                selected, active, state = route['fallback_proxy'], backup, 'backup'
        if not selected and route.get('allow_direct_fallback'):
            backup = await probe('')
            if backup['ok']:
                selected, active, state = 'direct', backup, 'direct'
        async with self.lifecycle_lock:
            await self.publish_check(route, main, selected, active, state)

    async def publish_check(self, route, main, selected, active, state):
        rid = route['id']
        old = self.status.get(rid, {})
        # Don't resurrect a route removed while a network probe was in flight.
        if rid not in self.entries or self.entries[rid]['route'] != route:
            return
        self.status[rid] = {'healthy': bool(selected), 'state': state, 'primary': main,
            'active': active, 'checked_at': time.time(), '_selected': selected,
            'failures': 0 if main['ok'] else old.get('failures', 0) + 1}
        if old.get('state') != state:
            self.store.event('route', 'مسیر ' + COUNTRIES[route['country']] + ': ' + state)
        item = self.entries.get(rid)
        # Re-discover through the official engine; no scanning or IP guarantee.
        if item and route['provider'] == 'psiphon' and not main['ok'] and time.monotonic() - item['last_restart'] > 180:
            process = item.get('process')
            if process and process.returncode is None:
                process.terminate()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(process.wait(), 5)
                if process.returncode is None:
                    process.kill()
                    await process.wait()
            item['process'] = await self.spawn(route)
            item['last_restart'] = time.monotonic()

    async def check_existing(self, route):
        primary = await probe(route.get('primary_proxy') or route.get('proxy') or '', route.get('country', ''))
        active = primary
        if route.get('primary_proxy'):
            # Check the real installed HAProxy path too: the engine may have
            # recovered while the existing health-check rise delay still uses
            # its backup. Show the actual selected egress, not an assumption.
            active = await probe(route['proxy'])
        state = 'offline'
        if active.get('ok'):
            state = 'backup' if route.get('country') and active.get('country') != route['country'] else 'primary'
        async with self.lifecycle_lock:
            rid = route['id']
            if rid not in self.entries or self.entries[rid]['route'] != route:
                return
            old = self.status.get(rid, {})
            self.status[rid] = {'healthy': bool(active.get('ok')), 'state': state,
                'primary': primary, 'active': active if active.get('ok') else {}, 'checked_at': time.time()}
            if old.get('state') != state:
                self.store.event('route', 'مسیر موجود ' + route.get('name', '') + ': ' + state)

    async def check_all(self):
        async with self.probe_lock:
            semaphore = asyncio.Semaphore(4)
            async def one(route):
                async with semaphore:
                    await self.check_one(route)
            await asyncio.gather(*(one(copy.deepcopy(v['route'])) for v in list(self.entries.values())))

    async def reconnect(self, rid):
        async with self.lifecycle_lock:
            await self._reconnect(rid)

    async def _reconnect(self, rid):
        route = self.entries[rid]['route']
        if route['provider'] != 'psiphon':
            # The normal check acquires lifecycle_lock while publishing.
            asyncio.create_task(self.check_one(copy.deepcopy(route)))
            return
        # Keep the relay listener and existing TCP streams alive; only the
        # provider process reconnects. Its own active streams may close.
        process = self.entries[rid].get('process')
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        self.entries[rid]['process'] = await self.spawn(route)
        self.entries[rid]['last_restart'] = time.monotonic()
        self.status[rid]['_selected'] = None
        self.status[rid]['state'] = 'checking'

    async def monitor(self):
        while not self.stopping:
            try:
                await self.check_all()
            except Exception:
                self.store.event('error', 'بررسی دوره‌ای مسیر کامل نشد؛ دوباره تلاش می‌شود.')
            await asyncio.sleep(20)

    async def close(self):
        self.stopping = True
        if hasattr(self, 'worker'):
            self.worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.worker
        for rid in list(self.entries):
            await self.stop_entry(rid)

    def public_status(self):
        return {rid: {k: copy.deepcopy(v) for k, v in item.items() if not k.startswith('_')}
                for rid, item in list(self.status.items())}
