"""Generate an explicit distributable manifest; never include private state."""
import hashlib
from pathlib import Path

root=Path(__file__).resolve().parent.parent
files=[root/name for name in ('VERSION','LICENSE','README.md','README.en.md','SECURITY.md','THIRD_PARTY.md','install.sh','uninstall.sh','installer.py')]
for folder,pattern in (('atlas','*.py'),('web','*'),('providers','*.json'),('docs','*.md'),('docs/images','*.png')):
    files.extend(p for p in (root/folder).glob(pattern) if p.is_file())
manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(root).as_posix()+'\n' for p in sorted(files))
(root/'SHA256SUMS').write_text(manifest,encoding='ascii',newline='\n')
print('Manifest:',len(files),'files')
