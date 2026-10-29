import copy
import unittest

from atlas.panel import Panel,PanelError


class SettingsPanel(Panel):
    def __init__(self,settings,persist=True):
        self.settings=copy.deepcopy(settings);self.writes=[];self.persist=persist
    def call(self,path,data=None,method=None):
        if path=='setting/all':return copy.deepcopy(self.settings)
        if path=='setting/update':
            self.writes.append(copy.deepcopy(data))
            if self.persist:self.settings['ipLimitAllowlist']=data['ipLimitAllowlist']
            return None
        raise AssertionError('Unexpected native operation: '+path)


class PanelSettingsTests(unittest.TestCase):
    def test_allowlist_preserves_existing_networks_and_unrelated_settings(self):
        panel=SettingsPanel({'ipLimitAllowlist':'192.0.2.1,127.1.0.0/16', 'webPort':2053,
            'twoFactorEnable':True,'smtpPassword':'','hasSmtpPassword':True,'panelOutbound':'old-warp'})
        old=panel.allow_sources(['127.77.0.1'])
        self.assertEqual(old,'192.0.2.1,127.1.0.0/16')
        payload=panel.writes[0]
        self.assertEqual(payload['ipLimitAllowlist'],'192.0.2.1,127.1.0.0/16,127.77.0.1')
        self.assertEqual(payload['webPort'],2053)
        self.assertEqual(payload['twoFactorEnable'],'true')
        self.assertEqual(payload['smtpPassword'],'')
        self.assertEqual(payload['panelOutbound'],'old-warp')
        self.assertNotIn('hasSmtpPassword',payload)
    def test_existing_covering_cidr_does_not_write_settings(self):
        panel=SettingsPanel({'ipLimitAllowlist':'127.77.0.0/24'})
        panel.allow_sources(['127.77.0.1','127.77.0.2'])
        self.assertFalse(panel.writes)
    def test_api_ignoring_allowlist_write_fails_closed(self):
        panel=SettingsPanel({'ipLimitAllowlist':''},persist=False)
        with self.assertRaises(PanelError):panel.allow_sources(['127.77.0.1'])
    def test_missing_native_allowlist_capability_does_not_write(self):
        panel=SettingsPanel({'webPort':2053})
        with self.assertRaises(PanelError):panel.allow_sources(['127.77.0.1'])
        self.assertFalse(panel.writes)


if __name__=='__main__':unittest.main()
