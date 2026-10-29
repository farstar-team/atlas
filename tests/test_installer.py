import hashlib
from pathlib import Path
import tempfile
import unittest

import installer


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)
        self.source=self.base/'source';self.source.mkdir()
        for name,content in {'VERSION':'0.1.0\n','atlas/__main__.py':'# test fixture\n','atlas/server.py':'# test fixture\n',
            'web/index.html':'<html>fixture</html>','providers/psiphon.json':'{}'}.items():
            p=self.source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
        self.manifest()
    def tearDown(self):self.temp.cleanup()
    def manifest(self):
        files=sorted(p for p in self.source.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
        (self.source/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(self.source).as_posix()+'\n' for p in files))
    def test_staging_and_repeated_install_preserve_release(self):
        target=self.base/'installed';target.mkdir()
        first=installer.stage(self.source,target);second=installer.stage(self.source,target)
        self.assertEqual(first,second);self.assertEqual((first/'VERSION').read_text(),'0.1.0\n')
    def test_unlisted_private_file_is_not_copied(self):
        (self.source/'private-password.txt').write_text('TEST-SECRET')
        target=self.base/'installed';target.mkdir();release=installer.stage(self.source,target)
        self.assertFalse((release/'private-password.txt').exists())
    def test_tampered_source_is_rejected(self):
        (self.source/'atlas/server.py').write_text('tampered')
        with self.assertRaisesRegex(RuntimeError,'Checksum mismatch'):installer.checked_files(self.source)
    def test_incomplete_manifest_is_rejected(self):
        (self.source/'SHA256SUMS').write_text('')
        with self.assertRaisesRegex(RuntimeError,'Incomplete'):installer.checked_files(self.source)
    def test_traversal_manifest_is_rejected(self):
        (self.source/'SHA256SUMS').write_text('0'*64+'  ../private.txt\n')
        with self.assertRaisesRegex(RuntimeError,'Unsafe'):installer.checked_files(self.source)
    def test_corrupted_installed_release_is_not_reused(self):
        target=self.base/'installed';target.mkdir();release=installer.stage(self.source,target)
        (release/'atlas/server.py').write_text('modified')
        with self.assertRaisesRegex(RuntimeError,'damaged'):installer.stage(self.source,target)
    def test_sidecar_unit_has_no_native_restart_command(self):
        self.assertIn('User=farstar-atlas',installer.UNIT)
        self.assertIn('NoNewPrivileges=true',installer.UNIT)
        self.assertNotIn('restart x-ui',Path('install.sh').read_text())
        self.assertNotIn('restart xray',Path('install.sh').read_text())


if __name__=='__main__':unittest.main()
