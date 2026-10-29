# FARSTAR Atlas

Independent country exits beside native Sanaei **3x-ui**, with a simple Persian RTL interface.

[فارسی](README.md) · [Host walkthrough (Persian)](docs/hosts.fa.md) · [Architecture](docs/architecture.md) · [Validation](docs/validation.md)

![Atlas dashboard — explicitly labelled fixture data](docs/images/desktop.png)

Atlas creates a separate TCP entry for an existing inbound, then registers its own SOCKS outbound and source-specific web routing rule through the native panel API. Existing credentials, quotas and memberships remain in the native inbound. Add a **Host manually** in the panel to expose that entry in subscriptions.

Supports your own SOCKS5 exits and an optional official Psiphon engine for personal/authorized use. The public Psiphon service [does not permit redistribution or resale without an agreement](https://psiphon.ca/terms); use owned or appropriately licensed exits for customers.

## Install

Requirements: native 3x-ui **3.11.0** on the same Debian 12+/Ubuntu 22.04+ systemd server, Python 3.10+, Admin API token, valid panel TLS (or loopback HTTP), HandlerService and RoutingService. Docker panels are unsupported. SOCKS exits support Linux amd64/arm64; the pinned prebuilt Psiphon engine supports Linux amd64 only.

As root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/farstar-team/atlas/main/install.sh)
```

Save the generated Atlas password. On your computer, open an SSH forward:

```bash
ssh -L 9786:127.0.0.1:9786 root@YOUR_SERVER -p YOUR_SSH_PORT
```

Visit **http://127.0.0.1:9786**. Connect the panel with its complete base URL and Admin API token. Add a country, owned SOCKS endpoint and existing TCP inbound. Atlas creates the entry/outbound/rule. Use the card's Host details to add a native Host using that entry port, then refresh Happ's subscription. Ports must be reachable through your firewall and any existing Iran-to-foreign tunnel.

Only **TCP destination ports 80 and 443** use the new exit. UDP and other ports retain the existing route. IPv6 depends on the exit and is not covered by this release's probe. Atlas does not create the inter-server tunnel or guarantee calls, games, a new IP, nationwide-outage access or uninterrupted operation.

Real HTTPS probes verify egress IP and requested country. Explicit SOCKS/direct fallback applies only to new connections, and its actual country is displayed. A reconnect can close active provider streams; no existing stream migration is promised.

Re-run the install command to update. Only Atlas restarts, so Atlas streams may reconnect. The installer never explicitly restarts x-ui/Xray. Native API changes were hot-applied in testing; the panel may itself fall back to a restart on API errors. Compatibility with future panel API changes requires testing.

Uninstall:

```bash
bash /opt/farstar-atlas/current/uninstall.sh
```

Managed panel resources are detached first. User state/backups remain under `/var/lib/farstar-atlas`; delete manually-created Hosts in the panel. If detach fails, uninstall stops and restarts Atlas for recovery.

Atlas never writes panel source files or accesses its SQL database. Updates can preserve integration because persistent changes live in the official Xray template API, but this is not a guarantee against future breaking API changes. Never edit the same template concurrently through the panel and Atlas: the native API does not provide an atomic compare-and-swap endpoint.

See [operations](docs/operations.fa.md), [security](SECURITY.md), [development](docs/development.md) and [MIT license](LICENSE).
