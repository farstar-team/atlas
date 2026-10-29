import copy
import json
from pathlib import Path
import tempfile
import unittest

from atlas.manager import Manager
from atlas.panel import PanelError, check_delta, merge_template, panel_url, route_tag
from atlas.storage import Store, atomic_json, password_hash, password_matches


def template():
    return {'api': {'tag': 'api', 'services': ['HandlerService', 'RoutingService', 'StatsService']},
        'inbounds': [{'tag': 'api', 'protocol': 'dokodemo-door', 'port': 62789}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'blocked', 'protocol': 'blackhole'},
            {'tag': 'existing-vpn', 'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': 11980}]}}],
        'dns': {'servers': ['1.1.1.1']}, 'policy': {'system': {'statsOutboundUplink': True}},
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'inboundTag': ['api'], 'outboundTag': 'api', 'type': 'field'},
            {'ip': ['geoip:private'], 'outboundTag': 'blocked', 'type': 'field'},
            {'inboundTag': ['inbound-20867'], 'outboundTag': 'existing-vpn', 'type': 'field'}]}}


def route(rid='abcd'):
    return {'id': rid, 'slot': 1, 'country': 'FR', 'name': 'France 🇫🇷', 'provider': 'socks',
        'proxy': 'socks5://user:SECRET@127.0.0.1:1080', 'inbound_id': 1, 'inbound_tag': 'inbound-20867',
        'source_ip': '127.77.0.1', 'socks_port': 61101, 'provider_port': 61201,
        'entry_port': 20001, 'target_ip': '127.0.0.1', 'target_port': 20867, 'enabled': True,
        'allow_direct_fallback': False}


class FakeRuntime:
    def __init__(self):
        self.routes = []
        self.fail_next = False
    def reload(self, routes):
        if self.fail_next:
            self.fail_next = False
            raise OSError('port occupied')
        self.routes = copy.deepcopy(routes)
    def submit(self, value, timeout=None):
        return value
    def public_status(self):
        return {'abcd': {'healthy': True}}


class FakePanel:
    def __init__(self):
        self.value = template()
        self.calls = []
        self.fail_after_write = False
        self.fail_rollback = False
        self.race = False
        self.reads = 0
    def check(self):
        return self.inbounds()
    def inbounds(self):
        return [{'id': 1, 'port': 20867, 'tag': 'inbound-20867', 'listen': '', 'enable': True, 'protocol': 'vless', 'remark': 'IR1'}]
    def template(self):
        self.reads += 1
        if self.race and self.reads == 2:
            self.value['dns']['servers'].append('9.9.9.9')
        return copy.deepcopy(self.value), 'https://www.google.com/generate_204'
    def allow_sources(self, ips):
        self.calls.append(('allow', list(ips)))
    def update(self, value, test_url):
        self.calls.append(('update', copy.deepcopy(value)))
        if self.fail_rollback:
            raise PanelError('unavailable')
        self.value = copy.deepcopy(value)
        if self.fail_after_write:
            self.fail_after_write = False
            # An independent admin edit after a timed-out write must survive.
            self.value['dns']['servers'].append('9.9.9.9')
            raise PanelError('ambiguous timeout')


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        atomic_json(self.root/'config.json', {'password_hash': password_hash('TEST-PASSWORD-ONLY'),
            'routes': [], 'panel': {'url': 'http://127.0.0.1:1234/', 'token': 'PANEL-SECRET'}, 'listen': '127.0.0.1', 'port': 9786})
        self.store = Store(self.root)
        self.panel = FakePanel()
        self.runtime = FakeRuntime()
        self.manager = Manager(self.store, self.runtime, lambda _: self.panel)
    def tearDown(self):
        self.temp.cleanup()
    def test_password_hash_and_wrong_password(self):
        digest = password_hash('a sufficiently long password')
        self.assertTrue(password_matches('a sufficiently long password', digest))
        self.assertFalse(password_matches('wrong', digest))
        self.assertFalse(password_matches('wrong', 'corrupt'))
    def test_atomic_state_is_private(self):
        self.assertEqual(self.store.read()['routes'], [])
        import os
        if os.name == 'posix':
            self.assertEqual((self.root/'config.json').stat().st_mode & 0o777, 0o600)
    def test_merge_preserves_foreign_resources_and_security_prefix(self):
        before = template()
        after = merge_template(before, [route()], [route()])
        check_delta(before, after, [route()])
        self.assertEqual(after['outbounds'][:3], before['outbounds'])
        self.assertEqual(after['routing']['rules'][:2], before['routing']['rules'][:2])
        self.assertEqual(after['routing']['rules'][2]['source'], ['127.77.0.1/32'])
        self.assertEqual(after['routing']['rules'][2]['port'], '80,443')
        self.assertEqual(after['routing']['rules'][2]['network'], 'tcp')
        self.assertEqual(after['routing']['rules'][3], before['routing']['rules'][2])
        self.assertEqual(before, template())
    def test_merge_is_idempotent(self):
        once = merge_template(template(), [route()], [route()])
        self.assertEqual(merge_template(once, [route()], [route()]), once)
    def test_disable_removes_only_owned(self):
        configured = merge_template(template(), [route()], [route()])
        disabled = route(); disabled['enabled'] = False
        self.assertEqual(merge_template(configured, [disabled], [route()]), template())
    def test_guard_rejects_inbound_dns_or_foreign_outbound_edits(self):
        for mutate in (lambda x: x['inbounds'].clear(), lambda x: x['dns']['servers'].append('8.8.8.8'),
                       lambda x: x['outbounds'].pop(0)):
            after = template(); mutate(after)
            with self.assertRaises(PanelError):
                check_delta(template(), after, [route()])
    def test_success_is_persisted_and_backed_up(self):
        self.manager.apply([route()], 'test')
        self.assertEqual(self.store.read()['routes'], [route()])
        self.assertFalse(self.manager.pending.exists())
        self.assertEqual(len(self.store.backups()), 1)
        self.assertEqual(self.runtime.routes, [route()])
        self.assertEqual(self.panel.calls[0], ('allow', ['127.77.0.1']))
    def test_ambiguous_write_rolls_back_only_owned_changes(self):
        self.panel.fail_after_write = True
        with self.assertRaises(PanelError):
            self.manager.apply([route()], 'test')
        self.assertEqual(self.store.read()['routes'], [])
        self.assertFalse(self.manager.pending.exists())
        self.assertEqual(self.panel.value['dns']['servers'], ['1.1.1.1', '9.9.9.9'])
        self.assertEqual(self.panel.value['outbounds'], template()['outbounds'])
    def test_port_collision_does_not_write_panel(self):
        self.runtime.fail_next = True
        with self.assertRaises(OSError):
            self.manager.apply([route()], 'test')
        self.assertEqual(self.panel.value, template())
        self.assertFalse(self.panel.calls)
        self.assertFalse(self.manager.pending.exists())
    def test_concurrent_edit_is_detected_and_preserved(self):
        self.panel.race = True
        with self.assertRaises(PanelError):
            self.manager.apply([route()], 'test')
        self.assertFalse(any(call[0] == 'update' for call in self.panel.calls))
        self.assertIn('9.9.9.9', self.panel.value['dns']['servers'])
    def test_failed_rollback_retains_recovery_journal(self):
        original = self.panel.update
        def fail(value, url):
            self.panel.value = copy.deepcopy(value)
            self.panel.fail_rollback = True
            raise PanelError('lost connection')
        self.panel.update = fail
        with self.assertRaises(PanelError):
            self.manager.apply([route()], 'test')
        self.assertTrue(self.manager.pending.exists())
        self.panel.update = original; self.panel.fail_rollback = False
        self.manager.recover()
        self.assertEqual(self.panel.value, template())
        self.assertFalse(self.manager.pending.exists())
    def test_restore_does_not_restore_old_password_or_foreign_settings(self):
        backup_id = self.manager.apply([route()], 'test')
        config = self.store.read(); config['password_hash'] = 'NEW-HASH'; self.store.save(config)
        self.panel.value['dns']['servers'].append('9.9.9.9')
        self.manager.restore(backup_id)
        self.assertEqual(self.store.read()['password_hash'], 'NEW-HASH')
        self.assertEqual(self.store.read()['routes'], [])
        self.assertIn('9.9.9.9', self.panel.value['dns']['servers'])
    def test_public_state_never_returns_proxy_or_panel_secrets(self):
        config = self.store.read(); config['routes'] = [route()]; self.store.save(config)
        result = json.dumps(self.manager.state())
        self.assertNotIn('SECRET', result)
        self.assertNotIn('password_hash', result)
    def test_psiphon_requires_authorization(self):
        with self.assertRaises(ValueError):
            self.manager.build_route({'country':'FR','provider':'psiphon','inbound_id':1}, self.panel.inbounds(), [])
    def test_invalid_ports_are_rejected(self):
        for port in (443, 20867, 61101, 70000):
            with self.assertRaises(ValueError):
                self.manager.build_route({'country':'FR','provider':'socks','proxy':'socks5://127.0.0.1:1080',
                    'inbound_id':1,'entry_port':port}, self.panel.inbounds(), [])
    def test_route_name_ends_with_country_flag(self):
        result = self.manager.build_route({'country':'FR','provider':'socks','proxy':'socks5://127.0.0.1:1080',
            'inbound_id':1}, self.panel.inbounds(), [])
        self.assertEqual(result['name'], 'France 🇫🇷')
        self.assertEqual(result['source_ip'], '127.77.0.1')
    def test_backup_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.load_backup('../../config')
    def test_http_panel_requires_loopback_and_no_embedded_credentials(self):
        for value in ('http://public.example/panel/', 'https://user:password@example.com/', 'https://example.com/?token=secret'):
            with self.assertRaises(ValueError): panel_url(value)
        self.assertEqual(panel_url('http://127.0.0.1:2053/secret'), 'http://127.0.0.1:2053/secret/')


if __name__ == '__main__': unittest.main()
