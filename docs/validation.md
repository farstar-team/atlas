# Host administration validation — 0.4.0, 2026-10-29

93 automated tests pass. New coverage includes native Host creation/edit/clone/delete, preserved advanced metadata/SNI pools, disabled-inbound associations, stale revisions, strict editable fields, idempotent operation IDs, committed-write timeout reconciliation, incomplete-operation recovery and external-engine detection.

Chrome exercised authenticated Host listing and CRUD, clone preservation, deletion cancellation, the external-vs-internal engine message, desktop/mobile rendering and overflow checks. Screenshots use labelled synthetic data and reserved IPs. The prior route/adoption browser suites still pass.

Against an expendable official 3x-ui 3.11.0 instance, a Host created through Atlas appeared as a new address in the actual delivered VLESS subscription. Editing its label retained the native Host row ID. A disabled clone was excluded, both test groups were removed, and the original Host list, native template, client identity/quota/membership and running core PID were preserved. These endpoint-delivery checks do not claim that an arbitrary new public address/port has network reachability.

Native subscription naming remains controlled by the panel template; adding a Host does not automatically rewrite naming, tunnel configuration or per-client Host restrictions. The native `isHidden` flag is not treated as subscription exclusion; this release exposes the actual native enable/disable control instead.

---

# Existing exit management validation — 0.3.0, 2026-10-29

77 automated tests cover the previous behavior plus passive adoption, exclusion from native template ownership, preserved Host/security metadata, root-controller command restrictions, stale revisions, operation idempotency, backup scoping, failure rollback, crash-recovery metadata and truthful active-backup reporting. The native configuration is asserted unchanged during controller tests.

Chrome exercised discovery, importing four fixture exits, country/fallback editing, restoration, unchanged Host fields, WARP reconnect cancellation, linked-configuration help and 390 px mobile rendering with no JavaScript errors or horizontal overflow. New screenshots are explicitly labelled fixture data.

The installed restricted root helper was exercised through its real Unix socket from the unprivileged Atlas UID in an expendable Linux VM. Real protected files and disposable systemd providers were used: no-op preserved the provider PID, a country change replaced only the intended region/backend, and restore recovered the prior settings. An unrelated UID sharing the socket group was rejected. These were synthetic providers, not evidence of Internet country connectivity.

Separately, the actual production HAProxy binary validated four staged country/fallback variants without changing the original config or restarting services. The other country's backend remained unchanged. Active country settings are not changed merely to validate deployment.

Import adds management references to existing exits; it does not prove outage resilience or upgrade external tunnel software. Explicit edits can reconnect streams on the affected provider. A process crash across separate provider/Host updates can leave labels stale; the architecture and operations guides describe recovery limits.

---

# Public access validation — 0.2.0, 2026-10-29

57 automated tests pass, including native-session authentication, native login/2FA forwarding, per-request revocation, CSRF bound to cookie/origin, public Host allowlists, nested-path assets, read-only SQLite discovery and public address discovery.

A real isolated 3x-ui 3.11.0 instance with HTTPS and TOTP enabled was used with the installed unprivileged systemd service. Requests reached Atlas over the VM's non-loopback IP with verified TLS. Wrong TOTP was rejected; correct native credentials/TOTP issued a native secure cookie and authorized Atlas. Logout cleared the shared native cookie. The certificate-refresh service succeeded, root-owned access metadata rejected service-user writes, and the original key permissions remained unchanged. No SSH forward was used for these tests.

The 0.1.0 validation below remains the evidence for unchanged routing/accounting behavior. This update changes administration access and login, not the VPN relay or user-accounting implementation.

---

# Validation — 2026-10-29

Release: **0.1.0**. Tests ran locally and inside an expendable Linux VM; no production customer server was changed to validate this release.

## Automated checks

**44 automated tests passed on Windows and Linux (Python 3.14).** They cover:

- Real bidirectional SOCKS transfer, explicit UDP rejection and fail-closed behavior.
- Primary/backup selection and recovery, requested-country mismatch detection, opt-in direct fallback.
- Managed-resource merging, preservation of foreign template sections and routing order.
- Port-bind failure, visible concurrent edits, ambiguous native writes, scoped rollback and retained crash journal when rollback fails.
- Backups restoring route definitions without restoring an old password or unrelated native settings.
- Panel settings round-trip preserving unrelated values and redacted secrets, existing CIDR handling and failed allowlist-persistence detection.
- Login/session authentication, Host/origin checks, CSRF enforcement, logout invalidation, CSP and static-path isolation.
- Explicit installer manifest, tamper/incomplete/traversal rejection, idempotent staging and exclusion of unlisted private files.

CI covers Python 3.10, 3.12 and 3.14, plus JavaScript syntax, shell syntax, checksum and package-staging checks. The published code revision `abe9b2d5cc394c33ae75be06f8c7cdadffc764c0` passed the matrix in [GitHub Actions run 40857585959](https://github.com/farstar-team/atlas/actions/runs/40857585959). Later revisions have their own check results.

## Browser

Installed Chrome exercised login, dashboard, settings, route creation, Host help, deletion confirmation and mobile rendering at 390 px. No JavaScript errors or horizontal overflow were observed. Screenshots in `docs/images` use explicitly marked fixture data and reserved documentation IPs.

## Native panel and real core/client

An isolated official **3x-ui 3.11.0** Linux release, SHA-256 `0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916`, ran with its own database, listener and temporary VLESS client. It supplied Xray **26.10.21**.

The opt-in native integration test passed through this complete path:

```text
curl → real Xray VLESS client → Atlas entry → existing authenticated native inbound
     → managed native SOCKS outbound → Atlas bridge → SOCKS upstream → HTTPS fixture
```

- 1,048,576 downloaded bytes matched exactly.
- 524,288 uploaded bytes matched the fixture's SHA-256 response.
- Native user traffic counters increased; queries explicitly did not reset counters.
- The native client record, identity, quota and inbound membership remained equal.
- The native core PID remained unchanged through route addition and removal.
- Managed outbound/rule removal preserved the original foreign outbounds.

The certificate and `FR / 203.0.113.9` response in that test are a **local TLS fixture**, not evidence of reaching a public French server.

## Public Psiphon network, separately checked

Using the pinned official binary for personal test traffic, public HTTPS probes returned the requested **France** and **Netherlands** country codes. Example measured cold-request durations were 562 ms and 858 ms from the test environment; these are not end-user ping or throughput guarantees.

The complete installation also ran as the unprivileged `farstar-atlas` **systemd service**, not just a development process. A real VLESS client through that installed service obtained a verified public **FR** trace and downloaded **262,144 bytes** from Cloudflare's public speed endpoint.

The service needs `AF_NETLINK` alongside its TCP/Unix socket families so the official engine can inspect interfaces. This was validated under the actual service restrictions.

These checks prove the observed connection at test time. They do not establish availability from every Iranian operator, commercial permission to redistribute the public network, continuous uptime, always-new IPs or access during a nationwide international outage.

## Installation and lifecycle

The one-command installer was executed in the isolated VM, initialized private state and started an unprivileged systemd service. Re-running installation preserved the exact private configuration bytes and engine cache, activated the staged release and kept the native core PID. The actual uninstall script successfully detached managed resources, removed its service/launcher, and retained private state/backups while the native core PID remained unchanged. Code activation and manifest staging were checked independently. Atlas's own restart can reconnect Atlas streams; it does not explicitly restart the native panel/core.

After publication, the exact README installation command was also executed in the isolated VM: the bootstrap resolved GitHub `main`, fetched the public commit archive, verified all packaged SHA-256 entries, preserved existing private configuration and started a healthy service. This was a public-download test in addition to private staging.
