import asyncio
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from atlas.network import connect_socks, exact, serve_socks, socks_url
from atlas.runtime import Runtime, probe
from atlas.storage import Store, atomic_json
from tests.test_core import route


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_bidirectional_transfer_through_socks(self):
        payload = bytes(range(256)) * 4096
        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data); await writer.drain()
            finally: writer.close()
        echo_server = await asyncio.start_server(echo, '127.0.0.1', 0)
        async def socks(reader, writer): await serve_socks(reader, writer, lambda:'direct')
        proxy_server = await asyncio.start_server(socks, '127.0.0.1', 0)
        try:
            reader, writer = await connect_socks('socks5://127.0.0.1:' + str(proxy_server.sockets[0].getsockname()[1]),
                '127.0.0.1', echo_server.sockets[0].getsockname()[1])
            async def upload():
                writer.write(payload); await writer.drain()
            upload_task = asyncio.create_task(upload())
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 10), payload)
            await upload_task
            writer.close(); await writer.wait_closed()
        finally:
            proxy_server.close(); echo_server.close()
            await proxy_server.wait_closed(); await echo_server.wait_closed()
    async def test_unhealthy_exit_fails_closed(self):
        async def socks(reader, writer): await serve_socks(reader, writer, lambda:None)
        server = await asyncio.start_server(socks, '127.0.0.1', 0)
        try:
            with self.assertRaises(ConnectionError):
                await connect_socks('socks5://127.0.0.1:' + str(server.sockets[0].getsockname()[1]), 'example.com', 443)
        finally: server.close(); await server.wait_closed()
    async def test_udp_is_explicitly_rejected(self):
        async def socks(reader, writer): await serve_socks(reader, writer, lambda:'direct')
        server = await asyncio.start_server(socks, '127.0.0.1', 0)
        try:
            r,w = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            w.write(b'\x05\x01\x00'); await w.drain(); self.assertEqual(await exact(r,2), b'\x05\x00')
            w.write(b'\x05\x03\x00\x01' + bytes(6)); await w.drain()
            self.assertEqual((await exact(r,10))[1], 7)
            w.close(); await w.wait_closed()
        finally: server.close(); await server.wait_closed()
    async def test_probe_requires_https_and_matching_country(self):
        async def runner(_): return 0,b'ip=203.0.113.9\nloc=NL\n'
        self.assertTrue((await probe('socks5://127.0.0.1:1080','NL',runner))['ok'])
        result=await probe('socks5://127.0.0.1:1080','FR',runner)
        self.assertFalse(result['ok']); self.assertEqual(result['reason'],'country_mismatch')
        async def bad(_): return 0,b'connected'
        self.assertFalse((await probe('',runner=bad))['ok'])
    async def test_real_fallback_selection_and_primary_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            atomic_json(Path(root)/'config.json', {'routes':[]})
            store=Store(root); runtime=Runtime(store); item=route(); item['fallback_proxy']='socks5://backup:1080'
            runtime.entries[item['id']]={'route':copy.deepcopy(item)}
            async def failed_primary(proxy,expected=''):
                return {'ok':False} if expected else {'ok':True,'country':'DE','ip':'203.0.113.2','latency_ms':10}
            with patch('atlas.runtime.probe',failed_primary): await runtime.check_one(item)
            self.assertEqual(runtime.status[item['id']]['state'],'backup')
            self.assertEqual(runtime.status[item['id']]['_selected'], item['fallback_proxy'])
            self.assertEqual(runtime.public_status()[item['id']]['active']['country'],'DE')
            self.assertNotIn('_selected',runtime.public_status()[item['id']])
            async def recovered(proxy,expected=''): return {'ok':True,'country':'FR','ip':'203.0.113.1','latency_ms':12}
            with patch('atlas.runtime.probe',recovered): await runtime.check_one(item)
            self.assertEqual(runtime.status[item['id']]['state'],'primary')
    async def test_direct_fallback_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as root:
            atomic_json(Path(root)/'config.json',{'routes':[]}); runtime=Runtime(Store(root)); item=route()
            runtime.entries[item['id']]={'route':copy.deepcopy(item)}
            async def failed(proxy,expected=''): return {'ok':False} if proxy else {'ok':True,'country':'DE','ip':'203.0.113.2'}
            with patch('atlas.runtime.probe',failed): await runtime.check_one(item)
            self.assertIsNone(runtime.status[item['id']]['_selected'])
            item['allow_direct_fallback']=True; runtime.entries[item['id']]['route']=copy.deepcopy(item)
            with patch('atlas.runtime.probe',failed): await runtime.check_one(item)
            self.assertEqual(runtime.status[item['id']]['_selected'],'direct')
    async def test_socks_credentials_length_and_scheme_validation(self):
        for value in ('http://example.com:80','socks5://example.com','socks5://example.com:1080/path',
                      'socks5://'+'a'*256+':password@example.com:1080'):
            with self.assertRaises(ValueError): socks_url(value)


if __name__ == '__main__': unittest.main()
