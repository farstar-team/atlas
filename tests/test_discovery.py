import argparse
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from atlas import discovery


class DiscoveryTests(unittest.TestCase):
    def test_sqlite_discovery_reads_only_web_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'panel.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE settings (key TEXT,value TEXT)')
                db.executemany('INSERT INTO settings VALUES (?,?)',[('webPort','2053'),('webBasePath','/secret/'),
                    ('webKeyFile','/private/path'),('someSecret','DO-NOT-READ')])
            db.close()
            before=path.read_bytes();result=discovery.read_sqlite(path)
            self.assertEqual(path.read_bytes(),before)
            self.assertNotIn('someSecret',result)
            self.assertEqual(result['webPort'],'2053')
    def test_public_ip_discovery_skips_empty_entries_and_private_loopback(self):
        rows=[{'ifname':'lo','addr_info':[{}, {'local':'10.255.255.254'}]},
            {'ifname':'eth0','addr_info':[{'local':'203.0.113.9'}]}]
        with patch('atlas.discovery.command',return_value=json.dumps(rows)):
            self.assertEqual(discovery.addresses(),['203.0.113.9'])
    def test_public_default_keeps_native_base_path_and_cookie_scope(self):
        args=argparse.Namespace(panel_db=None,panel_unit='x-ui.service',host='203.0.113.9',web_port=None)
        with patch('atlas.discovery.settings',return_value={'webPort':'2053','webBasePath':'/secret/'}), \
             patch('atlas.discovery.addresses',return_value=['203.0.113.9']):
            cfg=discovery.discover(args,old={'port':19786})
        self.assertEqual(cfg['listen'],'0.0.0.0');self.assertEqual(cfg['mode'],'panel')
        self.assertEqual(cfg['base_path'],'/secret/atlas/');self.assertEqual(cfg['port'],19786)
        self.assertEqual(cfg['panel_base_path'],'/secret/')
    def test_invalid_host_and_base_paths_are_rejected(self):
        for host in ('https://example.com','user@example.com','example.com/path','example.com\r\nX: bad'):
            with self.assertRaises(ValueError):discovery.hostname(host)
        args=argparse.Namespace(panel_db=None,panel_unit='x-ui',host='203.0.113.9',web_port=None)
        with patch('atlas.discovery.settings',return_value={'webBasePath':'/../private/'}):
            with self.assertRaises(ValueError):discovery.discover(args)


if __name__=='__main__':unittest.main()
