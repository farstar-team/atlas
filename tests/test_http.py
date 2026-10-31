import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from atlas.manager import Manager
from atlas.server import Server
from atlas.storage import Store,atomic_json,password_hash
from tests.test_core import FakePanel,FakeRuntime


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(); root=Path(cls.temp.name)
        atomic_json(root/'config.json',{'password_hash':password_hash('TEST-ONLY-PASSWORD'), 'routes':[], 'listen':'127.0.0.1','port':9786})
        cls.manager=Manager(Store(root),FakeRuntime(),lambda _:FakePanel())
        cls.server=Server(('127.0.0.1',0),cls.manager)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start()
        cls.origin='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.temp.cleanup()
    def request(self,path,body=None,headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        hdr={'Content-Type':'application/json','Origin':self.origin};hdr.update(headers or {})
        conn.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,hdr)
        response=conn.getresponse();status=response.status;result=response.read();head=dict(response.getheaders());conn.close()
        try:result=json.loads(result)
        except ValueError:pass
        return status,result,head
    def login(self):
        status,data,headers=self.request('/api/login',{'password':'TEST-ONLY-PASSWORD'})
        self.assertEqual(status,200)
        return data['csrf'],headers['Set-Cookie'].split(';')[0]
    def test_unauthenticated_cannot_read_state(self):
        self.assertEqual(self.request('/api/state')[0],401)
    def test_unlicensed_management_is_blocked_without_mutating_routes(self):
        csrf,cookie=self.login()
        headers={'Cookie':cookie,'X-Atlas-CSRF':csrf}
        before=self.manager.store.read()
        status,value,_=self.request('/api/routes/add',{},headers)
        self.assertEqual(status,400)
        self.assertIn('لایسنس',value['error'])
        self.assertEqual(self.manager.store.read(),before)
        status,value,_=self.request('/api/license',headers=headers)
        self.assertEqual(status,200)
        self.assertFalse(value['can_manage'])
        self.assertNotIn('installation_token',value)
    def test_health_does_not_include_credentials(self):
        status,data,_=self.request('/healthz')
        self.assertEqual(status,200);self.assertEqual(set(data),{'ok','version'})
    def test_error_response_has_cause_hint_and_safe_tracking_id(self):
        status,value,_=self.request('/api/state')
        self.assertEqual(status,401)
        self.assertEqual(value['error_code'],'login_required')
        self.assertTrue(value['error_title'] and value['error_hint'])
        self.assertEqual(len(value['error_id']),12)
    def test_shared_feedback_asset_is_served(self):
        status,value,headers=self.request('/ui-feedback.js')
        self.assertEqual(status,200)
        self.assertIn('javascript',headers['Content-Type'])
    def test_license_is_a_separate_hidden_view_at_start(self):
        status,value,_=self.request('/')
        self.assertEqual(status,200)
        self.assertIn(b'data-view="license"',value)
        self.assertIn(b'id="license" class="view" hidden',value)
    def test_host_rebinding_is_rejected(self):
        self.assertEqual(self.request('/api/session',headers={'Host':'attacker.example'})[0],403)
    def test_cross_origin_login_is_rejected(self):
        self.assertEqual(self.request('/api/login',{'password':'TEST-ONLY-PASSWORD'},{'Origin':'https://attacker.example'})[0],403)
    def test_cookie_and_csrf_required_for_mutation(self):
        csrf,cookie=self.login()
        self.assertIn('atlas_session=',cookie)
        self.assertEqual(self.request('/api/recover',{}, {'Cookie':cookie})[0],403)
        self.assertEqual(self.request('/api/recover',{}, {'Cookie':cookie,'X-Atlas-CSRF':csrf})[0],200)
        self.assertEqual(self.request('/api/state',headers={'Cookie':cookie})[0],200)
    def test_logout_invalidates_session(self):
        csrf,cookie=self.login();hdr={'Cookie':cookie,'X-Atlas-CSRF':csrf}
        self.assertEqual(self.request('/api/logout',{},hdr)[0],200)
        self.assertEqual(self.request('/api/state',headers=hdr)[0],401)
    def test_static_has_csp_and_no_traversal(self):
        status,body,headers=self.request('/')
        self.assertEqual(status,200);self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
        self.assertEqual(self.request('/../../config.json')[0],404)
    def test_login_cookie_has_http_only_and_same_site(self):
        _,_,headers=self.request('/api/login',{'password':'TEST-ONLY-PASSWORD'})
        self.assertIn('HttpOnly',headers['Set-Cookie']);self.assertIn('SameSite=Strict',headers['Set-Cookie'])


if __name__ == '__main__': unittest.main()
