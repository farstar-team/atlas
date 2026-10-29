import asyncio
import copy
import json
from pathlib import Path
import secrets
import tempfile
import types
import unittest
from unittest.mock import patch

from atlas.existing import Controller, public_route, update_backend
from atlas.manager import Manager
from atlas.runtime import Runtime
from atlas.storage import Store, atomic_json
from tests.test_core import FakePanel, FakeRuntime, route, template


def backend(code, port):
    return ('frontend '+code+'_socks\n    bind 127.0.0.1:'+str(port+10)+'\n    default_backend '+code+'_exit\n'
        'backend '+code+'_exit\n    option tcp-check\n    tcp-check expect string loc='+code.upper()+'\n'
        '    server country 127.0.0.1:'+str(port)+' check inter 15s fall 2 rise 2\n'
        '    server germany_fallback 127.0.0.1:62039 backup\n')


class Runner:
    def __init__(self): self.calls=[]; self.fail_once=False
    def __call__(self,args,**kwargs):
        self.calls.append(list(args))
        if self.fail_once and args[:2]==['systemctl','reload']:
            self.fail_once=False;return types.SimpleNamespace(returncode=1,stdout='')
        return types.SimpleNamespace(returncode=0,stdout='')


class ExistingControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.country=self.root/'country';self.country.mkdir()
        for code,port in [('fr',62030),('nl',62031)]:
            atomic_json(self.country/(code+'.json'),{'EgressRegion':code.upper(),'LocalSocksProxyPort':port,'PreserveThis':'untouched'})
        self.ha=backend('fr',62030)+backend('nl',62031)
        (self.country/'haproxy.cfg').write_text(self.ha)
        self.units=self.root/'units';self.units.mkdir()
        for code in ('fr','nl'):(self.units/('irg-country-'+code+'.service')).write_text('ExecStart=/provider -config '+str(self.country/(code+'.json')))
        (self.units/'irg-warp-daemon.service').write_text('ExecStart=/provider/warp-svc')
        self.native={'inbounds':[{'tag':'api'},{'tag':'one'},{'tag':'two'}], 'outbounds':[
            {'tag':'direct','protocol':'freedom'}, {'tag':'blocked','protocol':'blackhole'},
            {'tag':'country-fr','protocol':'socks','settings':{'servers':[{'address':'127.0.0.1','port':62040}]}},
            {'tag':'country-nl','protocol':'socks','settings':{'servers':[{'address':'127.0.0.1','port':62041}]}},
            {'tag':'warp','protocol':'socks','settings':{'servers':[{'address':'10.79.0.2','port':11980,'users':[{'user':'private','pass':'SECRET'}]}]}}],
            'routing':{'rules':[{'inboundTag':['one'],'source':['127.0.0.21/32'],'outboundTag':'country-fr'},
                {'inboundTag':['two'],'outboundTag':'warp'}]}}
        self.native_path=self.root/'native.json';atomic_json(self.native_path,self.native)
        self.runner=Runner();self.controller=Controller({'native_config':str(self.native_path),'country_root':str(self.country),
            'haproxy_binary':'/reviewed/haproxy','units_dir':str(self.units)},self.root/'state',self.runner)
    def tearDown(self):self.temp.cleanup()
    def fr(self):return next(r for r in self.controller.inventory() if r['outbound_tag']=='country-fr')
    def request(self,action='configure',**kwargs):
        resource=self.fr()
        return {'id':resource['id'],'revision':resource['revision'],'action':action,'operation':secrets.token_hex(16),**kwargs}
    def test_discovery_is_read_only_and_preserves_native_json(self):
        before=self.native_path.read_bytes();cfg=(self.country/'fr.json').read_bytes();ha=(self.country/'haproxy.cfg').read_bytes()
        resources=self.controller.inventory()
        self.assertEqual(len(resources),4);self.assertEqual(before,self.native_path.read_bytes())
        self.assertEqual(cfg,(self.country/'fr.json').read_bytes());self.assertEqual(ha,(self.country/'haproxy.cfg').read_bytes())
        self.assertFalse(self.runner.calls)
        self.assertEqual(self.fr()['capabilities'],['country','fallback','reconnect','rollback'])
    def test_public_metadata_redacts_socks_credentials(self):
        warp=next(r for r in self.controller.inventory() if r['outbound_tag']=='warp')
        self.assertIn('SECRET',warp['proxy']);self.assertNotIn('SECRET',json.dumps(public_route(warp)))
    def test_country_update_changes_only_region_and_matching_backend(self):
        native_before=self.native_path.read_bytes();result=self.controller.dispatch(self.request(country='US',fallback_enabled=True))
        self.assertEqual(result['country'],'US')
        self.assertEqual(json.loads((self.country/'fr.json').read_text())['PreserveThis'],'untouched')
        ha=(self.country/'haproxy.cfg').read_text();self.assertIn('loc=US',ha);self.assertIn(backend('nl',62031),ha)
        self.assertEqual(native_before,self.native_path.read_bytes())
        self.assertIn(['systemctl','restart','irg-country-fr'],self.runner.calls)
        self.assertIn(['systemctl','reload','irg-country-entry'],self.runner.calls)
        self.assertFalse(any('x-ui' in ' '.join(c) or 'xray' in ' '.join(c) for c in self.runner.calls))
    def test_fallback_change_only_reloads_country_balancer(self):
        cfg=(self.country/'fr.json').read_bytes()
        result=self.controller.dispatch(self.request(fallback_enabled=False))
        self.assertFalse(result['fallback_enabled']);self.assertEqual(cfg,(self.country/'fr.json').read_bytes())
        self.assertIn('germany_fallback 127.0.0.1:62039 backup disabled',(self.country/'haproxy.cfg').read_text())
        self.assertFalse(any(c[:2]==['systemctl','restart'] for c in self.runner.calls))
    def test_noop_does_not_restart_or_rewrite_files(self):
        before=(self.country/'fr.json').read_bytes();ha=(self.country/'haproxy.cfg').read_bytes()
        self.controller.dispatch(self.request(country='FR',fallback_enabled=True))
        self.assertFalse(self.runner.calls);self.assertEqual(before,(self.country/'fr.json').read_bytes())
        self.assertEqual(ha,(self.country/'haproxy.cfg').read_bytes())
    def test_operation_id_is_idempotent(self):
        request=self.request('reconnect');self.controller.dispatch(request);calls=len(self.runner.calls)
        self.controller.dispatch(request);self.assertEqual(len(self.runner.calls),calls)
        request['country']='US'
        with self.assertRaises(ValueError):self.controller.dispatch(request)
    def test_reconnect_only_restarts_its_provider(self):
        self.controller.dispatch(self.request('reconnect'))
        self.assertEqual([c for c in self.runner.calls if c[0]=='systemctl'],[['systemctl','restart','irg-country-fr']])
    def test_warp_reconnect_requires_known_service(self):
        (self.units/'irg-warp-daemon.service').unlink()
        warp=next(r for r in self.controller.inventory() if r['outbound_tag']=='warp')
        with self.assertRaises(ValueError):
            self.controller.dispatch({'id':warp['id'],'revision':warp['revision'],'action':'reconnect','operation':secrets.token_hex(16)})
        self.assertFalse(self.runner.calls)
    def test_failed_reload_restores_previous_files(self):
        cfg=(self.country/'fr.json').read_bytes();ha=(self.country/'haproxy.cfg').read_bytes();self.runner.fail_once=True
        with self.assertRaises(ValueError):self.controller.dispatch(self.request(country='US'))
        self.assertEqual(cfg,(self.country/'fr.json').read_bytes());self.assertEqual(ha,(self.country/'haproxy.cfg').read_bytes())
        self.assertTrue(list((self.root/'state/backups').glob('*.json')))
    def test_restore_preserves_other_backend_and_manual_provider_fields(self):
        result=self.controller.dispatch(self.request(country='US',fallback_enabled=False));bid=result['last_backup']
        cfg=json.loads((self.country/'fr.json').read_text());cfg['PreserveThis']='new-manual-value';atomic_json(self.country/'fr.json',cfg)
        ha=(self.country/'haproxy.cfg').read_text().replace('loc=NL','loc=CA');(self.country/'haproxy.cfg').write_text(ha)
        self.controller.dispatch(self.request('restore',backup=bid))
        self.assertEqual(json.loads((self.country/'fr.json').read_text())['EgressRegion'],'FR')
        self.assertEqual(json.loads((self.country/'fr.json').read_text())['PreserveThis'],'new-manual-value')
        self.assertIn('loc=CA',(self.country/'haproxy.cfg').read_text())
    def test_stale_revision_and_overposted_commands_are_rejected(self):
        request=self.request(country='US');request['revision']='stale'
        with self.assertRaises(ValueError):self.controller.dispatch(request)
        for extra in ({'unit':'x-ui'},{'command':'sh -c something'},{'operation':'../../etc/passwd'},{'country':'FR\nbackend evil'}):
            with self.assertRaises(ValueError):self.controller.dispatch({**self.request(),**extra})
        self.assertFalse(self.runner.calls)
    def test_backup_traversal_and_cross_resource_backup_are_rejected(self):
        with self.assertRaises(ValueError):self.controller.dispatch(self.request('restore',backup='../../private'))
        result=self.controller.dispatch(self.request(country='US'))
        nl=next(r for r in self.controller.inventory() if r['outbound_tag']=='country-nl')
        with self.assertRaises(ValueError):self.controller.dispatch({'action':'restore','id':nl['id'],'revision':nl['revision'],
            'operation':secrets.token_hex(16),'backup':result['last_backup']})
    def test_prepared_crash_can_be_restored_without_a_restart(self):
        resource,control=self.controller.resources()[self.fr()['id']]
        bid=self.controller.backup(resource['id'],control)
        atomic_json(self.root/'state/last.json',{resource['id']:bid})
        atomic_json(self.root/'state/pending.json',{'id':resource['id'],'backup':bid})
        self.assertTrue(self.fr()['pending'])
        with self.assertRaises(ValueError):self.controller.dispatch(self.request(country='US'))
        self.controller.dispatch(self.request('restore',backup=bid))
        self.assertFalse(self.fr()['pending']);self.assertFalse(self.runner.calls)


class LinkPanel(FakePanel):
    def __init__(self):
        super().__init__();self.hosts=[{'groupId':'group-fr','inboundIds':[1],'remark':'France 🇫🇷','port':443,
            'hosts':['198.51.100.9:443'],'security':'same','muxParams':{'keep':'unchanged'}}]
    def call(self,path,data=None,json_body=False):
        if path=='hosts/list':return copy.deepcopy(self.hosts)
        if path.startswith('hosts/update/'):
            self.hosts=[copy.deepcopy(data) if g['groupId']==data['groupId'] else g for g in self.hosts];return None
        raise AssertionError('Unexpected panel call '+path)


class LinkClient:
    def __init__(self):
        self.resource={'id':'existing-fixture','kind':'existing','name':'France 🇫🇷','country':'FR','enabled':True,
            'provider':'existing-psiphon','inbound_tags':['inbound-20867'],'outbound_tag':'country-fr',
            'proxy':'socks5://user:PRIVATE@127.0.0.1:62040','primary_proxy':'socks5://user:PRIVATE@127.0.0.1:62030',
            'capabilities':['country','fallback','reconnect','rollback'],'revision':'initial','fallback_enabled':True}
        self.calls=[]
    def inventory(self):return [copy.deepcopy(self.resource)]
    def change(self,resource,action,data):
        self.calls.append(action);self.resource.update(country=data.get('country',self.resource['country']),revision='next')
        return copy.deepcopy(self.resource)


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        atomic_json(self.root/'config.json',{'routes':[],'panel':{'url':'http://127.0.0.1:1/','token':'PANEL-PRIVATE'}})
        self.store=Store(self.root);self.panel=LinkPanel();self.runtime=FakeRuntime();self.client=LinkClient()
        self.manager=Manager(self.store,self.runtime,lambda _:self.panel,self.client)
    def tearDown(self):self.temp.cleanup()
    def test_adoption_is_idempotent_and_never_updates_native_configuration(self):
        before=copy.deepcopy(self.panel.value)
        self.assertEqual(self.manager.import_existing(['existing-fixture']),['existing-fixture'])
        self.assertEqual(self.manager.import_existing(['existing-fixture']),[])
        self.assertEqual(self.panel.value,before);self.assertFalse(self.panel.calls);self.assertFalse(self.client.calls)
        self.assertEqual(self.store.read()['routes'][0]['bindings'][0]['name'],'IR1 France 🇫🇷')
        self.assertNotIn('PRIVATE',json.dumps(self.manager.state()))
    def test_owned_route_changes_preserve_imported_outbounds(self):
        self.manager.import_existing(['existing-fixture'])
        self.panel.value['outbounds'].append({'tag':'country-fr','protocol':'socks','settings':{'servers':[]}})
        before=copy.deepcopy(self.panel.value['outbounds'][-1])
        self.manager.apply(self.store.read()['routes']+[route()],'test')
        self.assertIn(before,self.panel.value['outbounds'])
        self.assertFalse(any(o.get('tag')=='atlas-existing-fixture' for o in self.panel.value['outbounds']))
    def test_country_edit_changes_only_host_remark(self):
        self.manager.import_existing(['existing-fixture']);host=copy.deepcopy(self.panel.hosts[0])
        self.manager.change_existing('existing-fixture','configure',{'country':'US'})
        expected=copy.deepcopy(host);expected['remark']='United States 🇺🇸'
        self.assertEqual(self.panel.hosts[0],expected)
        self.assertEqual(self.panel.value,template());self.assertFalse(self.panel.calls)
    def test_recovery_metadata_refreshes_after_lost_response(self):
        self.manager.import_existing(['existing-fixture'])
        self.client.resource.update(revision='after-crash',pending=True,last_backup='saved-backup')
        state=self.manager.state()['routes'][0]
        self.assertEqual(state['revision'],'after-crash');self.assertTrue(state['pending'])
        self.assertEqual(state['last_backup'],'saved-backup')
        self.assertNotIn('PRIVATE',json.dumps(state))
    def test_unadoption_and_detach_do_not_touch_native_or_provider_services(self):
        self.manager.import_existing(['existing-fixture']);self.manager.remove('existing-fixture')
        self.assertEqual(self.store.read()['routes'],[]);self.assertFalse(self.client.calls);self.assertFalse(self.panel.calls)
        self.manager.import_existing(['existing-fixture']);self.manager.apply([],'detach')
        self.assertFalse(self.client.calls);self.assertFalse(self.panel.calls)


class ExistingRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_stop_only_observes_external_services(self):
        with tempfile.TemporaryDirectory() as root:
            atomic_json(Path(root)/'config.json',{'routes':[]});runtime=Runtime(Store(root));resource=LinkClient().resource
            with patch('asyncio.start_server',side_effect=AssertionError('must not bind any listener')), \
                 patch.object(runtime,'spawn',side_effect=AssertionError('must not spawn a provider')):
                await runtime.reload([resource]);self.assertEqual(runtime.entries[resource['id']]['servers'],[])
                await runtime.reload([]);self.assertFalse(runtime.entries)
    async def test_health_reports_real_existing_backup_country(self):
        with tempfile.TemporaryDirectory() as root:
            atomic_json(Path(root)/'config.json',{'routes':[]});runtime=Runtime(Store(root));resource=LinkClient().resource
            await runtime.reload([resource])
            async def probe(proxy,expected=''):
                return {'ok':True,'country':'FR','ip':'203.0.113.2'} if proxy.endswith('62030') else {'ok':True,'country':'DE','ip':'203.0.113.3'}
            with patch('atlas.runtime.probe',probe):await runtime.check_existing(resource)
            status=runtime.public_status()[resource['id']]
            self.assertEqual(status['state'],'backup');self.assertEqual(status['active']['country'],'DE')
            self.assertTrue(status['primary']['ok'])
            await runtime.reload([])


if __name__=='__main__':unittest.main()
