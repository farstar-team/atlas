import copy
import json
from pathlib import Path
import secrets
import tempfile
import unittest

from atlas.hosts import endpoint
from atlas.manager import Manager
from atlas.panel import PanelError
from atlas.storage import Store, atomic_json
from tests.test_existing import LinkPanel, LinkClient
from tests.test_core import FakeRuntime


class HostPanel(LinkPanel):
    def __init__(self):
        super().__init__(); self.host_calls=[]; self.fail_before=False; self.fail_after=False
        self.hosts[0].update(sni='one.example.com',snis=['one.example.com','two.example.com'],
            sniSharedRandom=True,isHidden=False,isDisabled=False,path='/preserve',security='same',
            sockoptParams='{"keep":true}',finalMask='{"keep":true}')
    def call(self,path,data=None,json_body=False):
        if path=='hosts/list':return copy.deepcopy(self.hosts)
        if not path.startswith('hosts/'):raise AssertionError('Unexpected mutation '+path)
        assert json_body; self.host_calls.append((path,copy.deepcopy(data)))
        if self.fail_before:raise PanelError('unavailable')
        if path=='hosts/add':self.hosts.append(copy.deepcopy(data))
        elif path.startswith('hosts/update/'):
            self.hosts=[copy.deepcopy(data) if h['groupId']==data['groupId'] else h for h in self.hosts]
        elif path.startswith('hosts/del/'):
            self.hosts=[h for h in self.hosts if h['groupId']!=path.rsplit('/',1)[1]]
        else:raise AssertionError(path)
        if self.fail_after:
            self.fail_after=False;raise PanelError('timeout after commit')


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        atomic_json(self.root/'config.json',{'routes':[],'panel':{'url':'http://127.0.0.1:1/','token':'PRIVATE'}})
        self.panel=HostPanel();self.client=LinkClient();self.store=Store(self.root)
        self.manager=Manager(self.store,FakeRuntime(),lambda _:self.panel,self.client)
        self.hosts=self.manager.hosts
    def tearDown(self):self.temp.cleanup()
    def op(self,values=None,**extra):
        data={'operation':secrets.token_hex(16)}
        if values is not None:data['values']=values
        return {**data,**extra}
    def create(self,**values):
        return self.hosts.change('create',self.op({'remark':'New France 🇫🇷','hosts':['vpn.example.com'],'port':443,'inboundIds':[1],**values}))
    def test_list_exposes_only_host_fields_not_client_or_advanced_secrets(self):
        listing=self.hosts.listing();self.assertEqual(len(listing['groups']),1)
        self.assertNotIn('muxParams',listing['groups'][0]);self.assertNotIn('PRIVATE',json.dumps(listing))
        self.assertFalse(self.panel.host_calls);self.assertFalse(self.panel.calls)
    def test_create_adds_only_a_host_without_native_template_or_client_write(self):
        before=copy.deepcopy(self.panel.value);old=copy.deepcopy(self.panel.hosts[0])
        created=self.create()['group'];self.assertTrue(created['groupId'].startswith('atlas-'))
        self.assertEqual(self.panel.hosts[0],old);self.assertEqual(self.panel.value,before)
        self.assertEqual([c[0] for c in self.panel.host_calls],['hosts/add']);self.assertFalse(self.panel.calls)
    def test_edit_merges_fresh_full_group_preserving_advanced_and_sni_pool(self):
        prior=copy.deepcopy(self.panel.hosts[0]);public=self.hosts.listing()['groups'][0]
        self.hosts.change('update',self.op({'remark':'Renamed 🇫🇷','sni':prior['sni']},id=public['groupId'],revision=public['revision']))
        expected=copy.deepcopy(prior);expected['remark']='Renamed 🇫🇷';self.assertEqual(self.panel.hosts[0],expected)
    def test_explicit_sni_edit_replaces_the_old_random_pool(self):
        h=self.hosts.listing()['groups'][0]
        self.hosts.change('update',self.op({'sni':'new.example.com'},id=h['groupId'],revision=h['revision']))
        self.assertEqual(self.panel.hosts[0]['snis'],['new.example.com']);self.assertFalse(self.panel.hosts[0]['sniSharedRandom'])
    def test_clone_keeps_advanced_fields_and_original_untouched(self):
        old=copy.deepcopy(self.panel.hosts[0]);h=self.hosts.listing()['groups'][0]
        self.hosts.change('create',self.op({'remark':'Copy France 🇫🇷','sni':old['sni']},template_id=h['groupId'],template_revision=h['revision']))
        self.assertEqual(self.panel.hosts[0],old);self.assertEqual(self.panel.hosts[1]['muxParams'],old['muxParams'])
        self.assertEqual(self.panel.hosts[1]['snis'],old['snis'])
    def test_create_retry_operation_is_idempotent(self):
        req=self.op({'remark':'New','hosts':['vpn.example.com'],'inboundIds':[1]})
        first=self.hosts.change('create',req);self.assertEqual(self.hosts.change('create',req),first)
        self.assertEqual(len(self.panel.host_calls),1);req['values']['remark']='Other'
        with self.assertRaises(ValueError):self.hosts.change('create',req)
    def test_stale_edit_or_template_is_rejected_before_any_write(self):
        h=self.hosts.listing()['groups'][0];self.panel.hosts[0]['path']='/changed'
        with self.assertRaises(ValueError):self.hosts.change('update',self.op({'remark':'x'},id=h['groupId'],revision=h['revision']))
        with self.assertRaises(ValueError):self.hosts.change('create',self.op({'remark':'x'},template_id=h['groupId'],template_revision=h['revision']))
        self.assertFalse(self.panel.host_calls)
    def test_timeout_after_committed_add_is_reconciled_without_duplicate(self):
        self.panel.fail_after=True;result=self.create()
        self.assertTrue(result['applied']);self.assertEqual(len(self.panel.hosts),2);self.assertFalse(self.hosts.pending.exists())
    def test_failed_write_journals_and_read_only_recovery_unblocks(self):
        self.panel.fail_before=True
        with self.assertRaises(PanelError):self.create()
        self.assertTrue(self.hosts.pending.exists())
        with self.assertRaises(ValueError):self.create()
        count=len(self.panel.host_calls);self.assertFalse(self.hosts.recover()['applied'])
        self.assertEqual(len(self.panel.host_calls),count);self.assertFalse(self.hosts.pending.exists())
    def test_recovery_preserves_a_conflicting_external_edit(self):
        h=self.hosts.listing()['groups'][0];self.panel.fail_before=True
        with self.assertRaises(PanelError):self.hosts.change('update',self.op({'remark':'new'},id=h['groupId'],revision=h['revision']))
        self.panel.hosts[0]['remark']='independent edit'
        with self.assertRaises(PanelError):self.hosts.recover()
        self.assertEqual(self.panel.hosts[0]['remark'],'independent edit');self.assertTrue(self.hosts.pending.exists())
    def test_delete_is_scoped_and_repeated_request_does_not_delete_another_host(self):
        self.create();h=self.hosts.listing()['groups'][0];req=self.op(id=h['groupId'],revision=h['revision'])
        self.hosts.change('delete',req);self.hosts.change('delete',req)
        self.assertEqual(len(self.panel.hosts),1);self.assertNotEqual(self.panel.hosts[0]['groupId'],h['groupId'])
    def test_invalid_and_overposted_fields_cannot_write(self):
        for values in ({'user':{}},{'hosts':['http://host/path']},{'hosts':[{}]},{'port':True},{'port':99999},
            {'inboundIds':[999]},{'remark':'bad\nname'},{'hosts':['host:99999']},{'security':'invalid'},{'isHidden':1}):
            with self.subTest(values=values),self.assertRaises(ValueError):self.create(**values)
        self.assertFalse(self.panel.host_calls)
    def test_address_parser_supports_domains_and_ipv6(self):
        self.assertEqual(endpoint('[2001:db8::1]:443'),('2001:db8::1',443))
        self.assertEqual(endpoint('2001:db8::1',80),('2001:db8::1',80));self.assertEqual(endpoint('EXAMPLE.com:8443'),('example.com',8443))
        self.assertEqual(endpoint('198.51.100.0/24:443'),('198.51.100.0/24',443))
        self.assertEqual(endpoint('[2001:db8::/64]:443'),('2001:db8::/64',443))
    def test_disabled_inbound_associations_remain_selectable_and_preserved(self):
        self.panel.hosts[0]['inboundIds']=[1,99];h=self.hosts.listing()['groups'][0]
        self.assertIn(99,[i['id'] for i in self.hosts.listing()['inbounds']])
        self.hosts.change('update',self.op({'inboundIds':[1,99]},id=h['groupId'],revision=h['revision']))
        self.assertEqual(self.panel.hosts[0]['inboundIds'],[1,99])
    def test_host_change_refreshes_linked_configuration_labels(self):
        self.manager.import_existing(['existing-fixture']);h=self.hosts.listing()['groups'][0]
        self.hosts.change('update',self.op({'remark':'Custom France 🇫🇷'},id=h['groupId'],revision=h['revision']))
        self.assertIn('Custom France',self.store.read()['routes'][0]['bindings'][0]['name'])


if __name__=='__main__':unittest.main()
