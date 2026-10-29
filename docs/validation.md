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
