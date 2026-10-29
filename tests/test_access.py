import copy
import http.client
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.parse

from atlas.access import PanelAccess, native_cookie
from atlas.manager import Manager
from atlas.server import Server
from atlas.storage import Store, atomic_json, password_hash
from tests.test_core import FakePanel, FakeRuntime


class NativeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def reply(self, value, cookie=None, status=200):
        body=json.dumps(value).encode();self.send_response(status)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        self.server.calls.append(dict(self.headers))
        if self.path=='/secret/csrf-token':
            return self.reply({'success':True,'obj':'native-csrf'},'3x-ui=prelogin; Path=/secret/; HttpOnly')
        if self.path=='/secret/panel/api/inbounds/list' and self.server.valid and native_cookie(self.headers.get('Cookie','')) in ('native-valid','another-valid'):
            return self.reply({'success':True,'obj':[]})
        self.reply({'success':False},status=401)
    def do_POST(self):
        self.server.calls.append(dict(self.headers))
        data=urllib.parse.parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
        self.server.last_data=data
        okay=(self.path=='/secret/login' and native_cookie(self.headers.get('Cookie',''))=='prelogin' and
            self.headers.get('X-CSRF-Token')=='native-csrf' and data.get('username')==['admin'] and
            data.get('password')==['NATIVE-TEST-PASSWORD'] and data.get('twoFactorCode')==['123456'])
        self.reply({'success':okay},'3x-ui=native-valid; Path=/secret/; HttpOnly' if okay else None)


class PublicAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        self.native=http.server.ThreadingHTTPServer(('127.0.0.1',0),NativeHandler)
        self.native.valid=True;self.native.calls=[]
        self.nt=threading.Thread(target=self.native.serve_forever,daemon=True);self.nt.start()
        atomic_json(root/'config.json',{'routes':[],'password_hash':password_hash('OLD-PRIVATE-PASSWORD'),
            'panel':{'url':'http://127.0.0.1:1234/','token':'PRIVILEGED-BACKGROUND-TOKEN'}})
        manager=Manager(Store(root),FakeRuntime(),lambda _:FakePanel())
        cfg={'mode':'panel','scheme':'http','panel_hostname':'127.0.0.1','panel_port':self.native.server_port,
            'panel_connect_host':'127.0.0.1','panel_base_path':'/secret/','base_path':'/secret/atlas/',
            'hosts':['203.0.113.15']}
        self.server=Server(('0.0.0.0',0),manager,access=cfg)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.host='203.0.113.15:'+str(self.server.server_port);self.origin='http://'+self.host
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join()
        self.native.shutdown();self.native.server_close();self.nt.join();self.temp.cleanup()
    def request(self,path,body=None,headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        hdr={'Host':self.host,'Origin':self.origin,'Content-Type':'application/json'};hdr.update(headers or {})
        conn.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,hdr)
        response=conn.getresponse();raw=response.read();status=response.status;head={}
        for k,v in response.getheaders():head.setdefault(k,v)
        conn.close()
        try:raw=json.loads(raw)
        except ValueError:pass
        return status,raw,head
    def login(self,code='123456'):
        return self.request('/secret/atlas/api/login',{'username':'admin','password':'NATIVE-TEST-PASSWORD','twoFactorCode':code})
    def test_public_root_redirects_and_nested_assets_work(self):
        status,_,headers=self.request('/')
        self.assertEqual(status,302);self.assertEqual(headers['Location'],'/secret/atlas/')
        self.assertEqual(self.request('/secret/atlas/')[0],200)
        self.assertEqual(self.request('/secret/atlas/app.js')[0],200)
        self.assertEqual(self.request('/api/state')[0],404)
    def test_native_login_and_2fa_create_native_cookie(self):
        self.assertEqual(self.login('bad')[0],401)
        status,result,headers=self.login()
        self.assertEqual(status,200);self.assertTrue(result['csrf'])
        self.assertIn('3x-ui=native-valid',headers['Set-Cookie'])
        self.assertIn('Path=/secret/',headers['Set-Cookie'])
        self.assertNotIn('atlas_session',headers['Set-Cookie'])
        self.assertEqual(self.native.last_data['twoFactorCode'],['123456'])
    def test_existing_native_session_is_automatically_accepted(self):
        status,result,_=self.request('/secret/atlas/api/session',headers={'Cookie':'3x-ui=native-valid'})
        self.assertEqual(status,200);self.assertTrue(result['authenticated']);self.assertEqual(result['mode'],'panel')
    def test_native_revocation_takes_effect_on_next_request(self):
        headers={'Cookie':'3x-ui=native-valid'}
        self.assertEqual(self.request('/secret/atlas/api/state',headers=headers)[0],200)
        self.native.valid=False
        self.assertEqual(self.request('/secret/atlas/api/state',headers=headers)[0],401)
    def test_stored_background_token_does_not_authorize_browser(self):
        self.assertEqual(self.request('/secret/atlas/api/state',headers={'Authorization':'Bearer PRIVILEGED-BACKGROUND-TOKEN'})[0],401)
        self.assertEqual(self.request('/secret/atlas/api/state',headers={'Cookie':'3x-ui=invalid'})[0],401)
        self.assertTrue(all('Authorization' not in call for call in self.native.calls))
    def test_csrf_is_bound_to_native_cookie_and_origin(self):
        _,session,_=self.request('/secret/atlas/api/session',headers={'Cookie':'3x-ui=native-valid'})
        headers={'Cookie':'3x-ui=native-valid','X-Atlas-CSRF':session['csrf']}
        self.assertEqual(self.request('/secret/atlas/api/recover',{},headers)[0],200)
        headers['Cookie']='3x-ui=another-valid'
        self.assertEqual(self.request('/secret/atlas/api/recover',{},headers)[0],403)
        headers.update(Cookie='3x-ui=native-valid',Origin='https://evil.example')
        self.assertEqual(self.request('/secret/atlas/api/recover',{},headers)[0],403)
    def test_logout_expires_shared_native_cookie(self):
        _,session,_=self.request('/secret/atlas/api/session',headers={'Cookie':'3x-ui=native-valid'})
        status,_,headers=self.request('/secret/atlas/api/logout',{}, {'Cookie':'3x-ui=native-valid','X-Atlas-CSRF':session['csrf']})
        self.assertEqual(status,200);self.assertIn('Max-Age=0',headers['Set-Cookie'])
        self.assertIn('Path=/secret/',headers['Set-Cookie'])
    def test_public_host_allowlist_is_not_a_wildcard(self):
        self.assertEqual(self.request('/secret/atlas/',headers={'Host':'evil.example:'+str(self.server.server_port)})[0],403)
    def test_https_cookie_is_secure_and_header_injection_is_rejected(self):
        cfg=copy.deepcopy(self.server.access);cfg['scheme']='https'
        self.assertIn('; Secure',PanelAccess(cfg).browser_cookie('abc'))
        self.assertEqual(native_cookie('3x-ui=abc\r\nAuthorization: Bearer evil'),'')
        self.assertEqual(native_cookie('3x-ui=new-path; 3x-ui=old-root'),'new-path')


if __name__=='__main__':unittest.main()
