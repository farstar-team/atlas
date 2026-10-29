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

The installer discovers the native panel's public hostname/IP, base path and certificate. Open the printed public URL on any phone or computer; everyday use requires no SSH forwarding. Example:

```bash
https://YOUR_PANEL_DOMAIN:9786/YOUR_PANEL_PATH/atlas/
```

Login uses the **existing 3x-ui account**, like ZARIB. Existing native sessions on the same hostname/browser sign in automatically; new devices can enter the native username/password and optional 2FA code directly in Atlas. No extra Atlas password is required. Passwords are forwarded only to the local native login endpoint and never stored. Native revocation takes effect on the next protected request.

Configured public IP aliases are accepted too. The native certificate must cover the address used by the browser; use the panel domain for valid HTTPS when its certificate is domain-only. Atlas preserves the native HTTP/HTTPS scheme and automatically refreshes restricted TLS copies. The firewall is preserved. Legacy private/password mode is an explicit installer `--private` option.

Connect the panel with its complete base URL and Admin API token for background route management. Add a country, owned SOCKS endpoint and existing TCP inbound. Atlas creates the entry/outbound/rule. Use the card's Host details to add a native Host using that entry port, then refresh Happ's subscription. Ports must be reachable through your firewall and any existing Iran-to-foreign tunnel.

Only **TCP destination ports 80 and 443** use the new exit. UDP and other ports retain the existing route. IPv6 depends on the exit and is not covered by this release's probe. Atlas does not create the inter-server tunnel or guarantee calls, games, a new IP, nationwide-outage access or uninterrupted operation.

Real HTTPS probes verify egress IP and requested country. Explicit SOCKS/direct fallback applies only to new connections, and its actual country is displayed. A reconnect can close active provider streams; no existing stream migration is promised.

Re-run the install command to update. Only Atlas restarts, so Atlas streams may reconnect. The installer never explicitly restarts x-ui/Xray. Native API changes were hot-applied in testing; the panel may itself fall back to a restart on API errors. Compatibility with future panel API changes requires testing.

Uninstall:

```bash
bash /opt/farstar-atlas/current/uninstall.sh
```

Managed panel resources are detached first. User state/backups remain under `/var/lib/farstar-atlas`; delete manually-created Hosts in the panel. If detach fails, uninstall stops and restarts Atlas for recovery.

Atlas never writes panel source files or changes panel SQL records during installation. The installer reads only web settings from SQLite/local PostgreSQL, or reuses existing ZARIB web metadata; the running daemon never accesses SQL. Persistent route changes use the official Xray template API. Future breaking API changes may still need an Atlas update. Never edit the same template concurrently through the panel and Atlas; the native API has no atomic compare-and-swap endpoint.

See [operations](docs/operations.fa.md), [security](SECURITY.md), [development](docs/development.md) and [MIT license](LICENSE).
