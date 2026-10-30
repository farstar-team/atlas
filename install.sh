#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if [[ ${EUID} -ne 0 ]]; then printf 'Run as root.\n' >&2; exit 1; fi
if [[ ! -d /run/systemd/system ]] || ! command -v apt-get >/dev/null; then
  printf 'Atlas requires Debian/Ubuntu with systemd and an existing native 3x-ui panel.\n' >&2; exit 1
fi
printf '\n  FARSTAR / ATLAS — Independent country exits\n\n'
missing=()
for package in python3 python3-cryptography curl ca-certificates iproute2; do
  if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q '^install ok installed$'; then missing+=("$package"); fi
done
if ! command -v psql >/dev/null; then missing+=(postgresql-client); fi
if (( ${#missing[@]} )); then
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
  apt-get -q update
  apt-get -q -y --no-install-recommends install "${missing[@]}"
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ is required"'
if [[ -n ${ATLAS_SOURCE_DIR:-} ]]; then
  source_dir=$(realpath -- "$ATLAS_SOURCE_DIR")
else
  staging=$(mktemp -d /tmp/farstar-atlas.XXXXXXXX)
  cleanup() { if [[ $staging == /tmp/farstar-atlas.* && -d $staging ]]; then rm -rf -- "$staging"; fi; }
  trap cleanup EXIT
  # Resolve one revision first. The archive cannot mix revisions during an update.
  curl --fail --silent --show-error --location --proto '=https' --connect-timeout 15 --max-time 90 \
    'https://api.github.com/repos/farstar-team/atlas/commits/main' --output "$staging/revision.json"
  revision=$(python3 -c 'import json,sys,re; v=json.load(open(sys.argv[1]))["sha"]; assert re.fullmatch("[0-9a-f]{40}",v); print(v)' "$staging/revision.json")
  curl --fail --silent --show-error --location --proto '=https' --connect-timeout 15 --max-time 120 \
    "https://codeload.github.com/farstar-team/atlas/tar.gz/$revision" --output "$staging/source.tar.gz"
  python3 - "$staging/source.tar.gz" "$staging" <<'PY'
import sys,tarfile,pathlib
target=pathlib.Path(sys.argv[2]).resolve()
with tarfile.open(sys.argv[1]) as archive:
    for item in archive.getmembers():
        if item.issym() or item.islnk() or not (item.isfile() or item.isdir()): raise SystemExit('Unsafe archive entry')
        if not (target/item.name).resolve().is_relative_to(target): raise SystemExit('Unsafe archive path')
    archive.extractall(target, filter='data') if sys.version_info >= (3,12) else archive.extractall(target)
PY
  source_dir="$staging/atlas-$revision"
fi
[[ -f $source_dir/installer.py && -f $source_dir/SHA256SUMS ]] || { printf 'Incomplete Atlas archive.\n' >&2; exit 1; }
(cd "$source_dir" && sha256sum --check --quiet SHA256SUMS)
python3 "$source_dir/installer.py" --source "$source_dir" "$@"
