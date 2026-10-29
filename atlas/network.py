"""Small bounded TCP relays; all public entries retain native inbound auth."""
import asyncio
import contextlib
import ipaddress
import struct
import urllib.parse


async def exact(reader, size):
    return await asyncio.wait_for(reader.readexactly(size), 15)


async def read_address(reader, kind):
    if kind == 1:
        return str(ipaddress.ip_address(await exact(reader, 4)))
    if kind == 4:
        return str(ipaddress.ip_address(await exact(reader, 16)))
    if kind == 3:
        return (await exact(reader, (await exact(reader, 1))[0])).decode('idna')
    raise ValueError('Invalid SOCKS address')


def socks_url(value):
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in ('socks5', 'socks5h') or not parsed.hostname or not parsed.port:
        raise ValueError('آدرس SOCKS باید مثل socks5://127.0.0.1:1080 باشد.')
    if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('آدرس SOCKS معتبر نیست.')
    if parsed.username and len(urllib.parse.unquote(parsed.username).encode()) > 255:
        raise ValueError('نام کاربری SOCKS طولانی است.')
    if parsed.password and len(urllib.parse.unquote(parsed.password).encode()) > 255:
        raise ValueError('رمز SOCKS طولانی است.')
    return value.strip()


async def connect_socks(url, host, port):
    parsed = urllib.parse.urlsplit(socks_url(url))
    reader, writer = await asyncio.wait_for(asyncio.open_connection(parsed.hostname, parsed.port), 10)
    try:
        username = urllib.parse.unquote(parsed.username or '').encode()
        password = urllib.parse.unquote(parsed.password or '').encode()
        writer.write(b'\x05\x02\x00\x02' if username else b'\x05\x01\x00')
        await writer.drain()
        reply = await exact(reader, 2)
        if reply == b'\x05\x02' and username:
            writer.write(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
            await writer.drain()
            if await exact(reader, 2) != b'\x01\x00':
                raise ConnectionError('SOCKS authentication failed')
        elif reply != b'\x05\x00':
            raise ConnectionError('SOCKS negotiation failed')
        encoded = host.encode('idna')
        if len(encoded) > 255:
            raise ValueError('Destination too long')
        writer.write(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded + struct.pack('!H', port))
        await writer.drain()
        version, reply, _, kind = await exact(reader, 4)
        if version != 5 or reply != 0:
            raise ConnectionError('SOCKS destination failed')
        await read_address(reader, kind)
        await exact(reader, 2)
        return reader, writer
    except BaseException:
        writer.close()
        raise


async def pipe(left_r, left_w, right_r, right_w):
    async def pump(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
                await writer.drain()
        except (ConnectionError, OSError):
            pass
    try:
        await asyncio.wait_for(asyncio.gather(pump(left_r, right_w), pump(right_r, left_w)), 6 * 3600)
    finally:
        for writer in (left_w, right_w):
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def serve_socks(reader, writer, choose):
    try:
        if (await exact(reader, 1)) != b'\x05':
            return
        methods = await exact(reader, (await exact(reader, 1))[0])
        if 0 not in methods:
            writer.write(b'\x05\xff')
            return
        writer.write(b'\x05\x00')
        await writer.drain()
        version, command, _, kind = await exact(reader, 4)
        if version != 5 or command != 1:
            writer.write(b'\x05\x07\x00\x01' + bytes(6))
            return
        host = await read_address(reader, kind)
        port = struct.unpack('!H', await exact(reader, 2))[0]
        selected = choose()
        if not selected:
            raise ConnectionError('No healthy exit')
        if selected == 'direct':
            remote_r, remote_w = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        else:
            remote_r, remote_w = await connect_socks(selected, host, port)
        writer.write(b'\x05\x00\x00\x01' + bytes(6))
        await writer.drain()
        await pipe(reader, writer, remote_r, remote_w)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        with contextlib.suppress(OSError):
            writer.write(b'\x05\x04\x00\x01' + bytes(6))
            await writer.drain()
    finally:
        writer.close()


async def serve_entry(reader, writer, route):
    remote_w = None
    try:
        remote_r, remote_w = await asyncio.wait_for(asyncio.open_connection(
            route['target_ip'], route['target_port'], local_addr=(route['source_ip'], 0)), 10)
        await pipe(reader, writer, remote_r, remote_w)
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        if remote_w:
            remote_w.close()
