#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
printf 'Detaching Atlas-managed routes first. Clients and unrelated panel settings are preserved.\n'
systemctl stop farstar-atlas.service
# A failed/ambiguous detach must leave the files available for recovery.
if ! runuser -u farstar-atlas -- /usr/local/bin/atlas detach; then
  systemctl start farstar-atlas.service
  printf 'Detach failed. Atlas was restarted. Recover from its UI before retrying.\n' >&2
  exit 1
fi
systemctl disable farstar-atlas.service
systemctl disable --now farstar-atlas-existing.service 2>/dev/null || true
systemctl disable --now farstar-atlas-certificates.timer 2>/dev/null || true
systemctl stop farstar-atlas-certificates.service 2>/dev/null || true
rm -f -- /etc/systemd/system/farstar-atlas.service /etc/systemd/system/farstar-atlas-existing.service /etc/systemd/system/farstar-atlas-certificates.service /etc/systemd/system/farstar-atlas-certificates.timer /usr/local/bin/atlas
systemctl daemon-reload
printf 'Service removed. State, credentials and backups remain in /var/lib/farstar-atlas.\n'
printf 'Delete Atlas Hosts from the native panel manually. No customer records were deleted.\n'
