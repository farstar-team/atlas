"""Opt-in integration against an expendable local 3x-ui 3.11.0 instance.

Never point this at production. Uses a local TLS fixture, an isolated native
VLESS account, a real core/client, real SOCKS relays and native stats counters.
It proves configuration/data flow, not public Psiphon reachability.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

from atlas.manager import Manager
from atlas.network import exact, pipe, read_address
from atlas.panel import Panel
from atlas.runtime import Runtime
from atlas.storage import Store, atomic_json, password_hash


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args();root=args.root.resolve()
    if root.name != 'atlas-native-integration' or not (root/'x-ui/x-ui').is_file():
        raise SystemExit('Only an expendable atlas-native-integration directory is accepted.')
    binary=root/'x-ui/bin/xray-linux-amd64'
    token=re.findall(r'[A-Za-z0-9_-]{32,}',(root/'token.txt').read_text())[-1]
    panel=Panel({'url':'http://127.0.0.1:32154/atlas-test/','token':token})
    def json_api(path,data):
        request=urllib.request.Request(panel.url+'panel/api/'+path,json.dumps(data).encode(),
            {'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
        result=json.load(urllib.request.urlopen(request,timeout=35))
        if not result.get('success'): raise AssertionError(str(result.get('msg','native API failed'))[:200])
        return result.get('obj')
    existing=panel.inbounds()
    if existing:
        raise SystemExit('This fixture requires a fresh panel with no inbounds.')
    state=root/'atlas-state';state.mkdir(mode=0o700,exist_ok=True)
    cert=root/'fixture.pem';key=root/'fixture.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),
        '-days','1','-subj','/CN=www.cloudflare.com','-addext','subjectAltName=DNS:www.cloudflare.com'],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    os.environ['CURL_CA_BUNDLE']=str(cert)
    native_port=port();upstream_port=port();tls_port=port();entry_port=port();client_port=port()
    inbound={'remark':'atlas-test native','enable':'true','listen':'127.0.0.1','port':native_port,
        'protocol':'vless','settings':json.dumps({'clients':[],'decryption':'none'}),
        'streamSettings':json.dumps({'network':'tcp','security':'none','tcpSettings':{'header':{'type':'none'}}}),
        'sniffing':json.dumps({'enabled':False,'destOverride':['http','tls']})}
    panel.call('inbounds/add',inbound)
    native=panel.inbounds()[0];identity=secrets.token_hex(16)
    import uuid
    identity=str(uuid.UUID(identity))
    email='atlas-test-'+secrets.token_hex(4)
    json_api('clients/add',{'client':{'id':identity,'email':email,'enable':True,'totalGB':0,
        'expiryTime':0,'limitIp':0,'subId':secrets.token_hex(8),'reset':0,'flow':''},'inboundIds':[native['id']]})
    time.sleep(3)
    # Capture after fixture setup. Atlas itself must not restart this process.
    def pids():
        found=subprocess.check_output(['pgrep','-f',str(binary)],text=True).split()
        return [pid for pid in found if str(root/'client.json').encode() not in Path('/proc/'+pid+'/cmdline').read_bytes()]
    baseline_pids=pids()
    before_client=panel.call('clients/get/'+email)
    original_template,_=panel.template()
    atomic_json(state/'config.json',{'routes':[],'panel':{'url':panel.url,'token':token},
        'password_hash':password_hash('integration-only-password'),'listen':'127.0.0.1','port':9786})
    store=Store(state);runtime=Runtime(store);manager=Manager(store,runtime)
    loop=asyncio.new_event_loop();ready=threading.Event();servers=[]
    transfers={'uploads':0,'downloads':0,'upstream_connections':0}
    async def https_fixture(reader,writer):
        try:
            header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),10)
            length=0
            for line in header.split(b'\r\n'):
                if line.lower().startswith(b'content-length:'):length=int(line.split(b':',1)[1])
            if length:
                body=await reader.readexactly(length);transfers['uploads']+=len(body)
                result=hashlib.sha256(body).hexdigest().encode()
            elif b'/download' in header.split(b'\r\n')[0]:
                result=bytes(range(256))*4096;transfers['downloads']+=len(result)
            else: result=b'ip=203.0.113.9\nloc=FR\n'
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(result)).encode()+b'\r\nConnection: close\r\n\r\n'+result)
            await writer.drain()
        finally:writer.close()
    async def upstream(reader,writer):
        try:
            if await exact(reader,1)!=b'\x05':return
            await exact(reader,(await exact(reader,1))[0]);writer.write(b'\x05\x00');await writer.drain()
            _,_,_,kind=await exact(reader,4);await read_address(reader,kind);await exact(reader,2)
            r,w=await asyncio.open_connection('127.0.0.1',tls_port)
            transfers['upstream_connections']+=1
            writer.write(b'\x05\x00\x00\x01'+bytes(6));await writer.drain()
            await pipe(reader,writer,r,w)
        finally:writer.close()
    async def startup():
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        servers.append(await asyncio.start_server(https_fixture,'127.0.0.1',tls_port,ssl=context))
        servers.append(await asyncio.start_server(upstream,'127.0.0.1',upstream_port))
        await runtime.start()
    def worker():
        asyncio.set_event_loop(loop);loop.run_until_complete(startup());ready.set();loop.run_forever()
    thread=threading.Thread(target=worker,daemon=True);thread.start();assert ready.wait(20)
    client=None
    try:
        manager.connect({'url':panel.url,'token':token})
        rid=manager.add({'country':'FR','provider':'socks','proxy':'socks5://127.0.0.1:'+str(upstream_port),
                         'inbound_id':native['id'],'entry_port':entry_port})
        runtime.submit(runtime.check_all());assert runtime.public_status()[rid]['state']=='primary'
        assert pids()==baseline_pids,'Atlas unexpectedly restarted the native core'
        client_config={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':client_port,'protocol':'socks','settings':{'udp':False}}],
            'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':entry_port,
            'users':[{'id':identity,'encryption':'none'}]}]},'streamSettings':{'network':'tcp','security':'none'}}]}
        atomic_json(root/'client.json',client_config)
        client=subprocess.Popen([str(binary),'run','-c',str(root/'client.json')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(.7)
        def curl(path,body=None):
            args=['curl','-fsS','--max-time','15','--proxy','socks5h://127.0.0.1:'+str(client_port),
                '--noproxy','','--cacert',str(cert),'https://www.cloudflare.com'+path]
            if body is not None:args+=['--data-binary','@-']
            return subprocess.check_output(args,input=body,timeout=20)
        assert b'loc=FR' in curl('/cdn-cgi/trace')
        data=curl('/download');assert data==bytes(range(256))*4096
        upload=bytes(range(256))*2048
        assert curl('/upload',upload).decode()==hashlib.sha256(upload).hexdigest()
        assert transfers['upstream_connections']>=4
        active_template,_=panel.template()
        assert any(x.get('tag')=='atlas-'+rid for x in active_template['outbounds'])
        after_client=panel.call('clients/get/'+email)
        # A quota/identity/membership check, independent of counters increasing.
        assert before_client['client']==after_client['client'],'Native client record changed'
        assert before_client['inboundIds']==after_client['inboundIds'],'Membership changed'
        time.sleep(6)
        stats=subprocess.check_output([str(binary),'api','statsquery','--server=127.0.0.1:62789','-reset=false','-pattern','user>>>'+email],text=True)
        stat_values=json.loads(stats).get('stat',[])
        assert sum(int(x.get('value',0)) for x in stat_values)>0,'Native traffic counters did not increase'
        manager.remove(rid)
        final_template,_=panel.template()
        assert not any(x.get('tag')=='atlas-'+rid for x in final_template['outbounds'])
        assert pids()==baseline_pids
        assert final_template['outbounds']==original_template['outbounds']
        report={'native_panel':'3.11.0','native_xray_pid_preserved':True,'country_fixture':'FR (local TLS fixture)',
            'download_bytes':len(data),'upload_bytes':len(upload),'native_counters_increased':True,
            'client_identity_quota_membership_preserved':True,'managed_outbound_and_rule_removed':True,
            'upstream_connections':transfers['upstream_connections']}
        (root/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
    finally:
        if client:client.terminate();client.wait(timeout=5)
        runtime.submit(runtime.close())
        for server in servers:loop.call_soon_threadsafe(server.close)
        loop.call_soon_threadsafe(loop.stop);thread.join(5)


if __name__=='__main__':main()
