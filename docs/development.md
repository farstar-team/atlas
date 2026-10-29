# Development

Python 3.10+ and curl are runtime dependencies. The installed daemon has no pip/npm runtime dependencies.

## Unit / integration tests without a real panel

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
node --check web/app.js
bash -n install.sh
bash -n uninstall.sh
```

The tests include real bidirectional SOCKS transport and HTTP authentication requests. Fake native API objects are confined to tests and are never selected by the installed app.

## Browser interactions and screenshots

Install Playwright in a development environment and provide an existing Chrome executable, or use its Chrome channel:

```bash
python3 -m pip install playwright
python3 -m tests.browser_smoke --chrome /path/to/chrome
```

The UI preview is explicitly marked as fixture data. The test exercises login, route listing, settings, route creation, Host instructions, deletion confirmation and mobile overflow. It writes screenshots under `docs/images` and checks for JavaScript errors.

## Native 3x-ui integration

`tests/native_integration.py` is opt-in and must only run against an expendable local 3x-ui instance. It intentionally creates a native VLESS inbound/client to verify identity, quota preservation and counters. Never use it against production.

Prepare the official 3.11.0 Linux release in a directory named `atlas-native-integration`, with `x-ui/`, a separate `db/`, and CLI `setting -getApiToken` output in `token.txt`. Configure that **isolated panel** to listen on `127.0.0.1:32154` with base path `/atlas-test/`, and run it from its own working directory with `XUI_DB_FOLDER`, `XUI_BIN_FOLDER` and `XUI_LOG_FOLDER` pointing inside the fixture. It must have no inbounds.

```bash
PYTHONPATH=. python3 tests/native_integration.py --root /absolute/path/atlas-native-integration
```

The script creates a one-day test certificate and local HTTPS fixture. A real native Xray client reaches the real native inbound through the Atlas entry and SOCKS bridge. It checks 1 MiB download, 512 KiB upload, native counter growth, unchanged native core PID, unchanged identity/quota/membership and clean removal of managed outbounds. The fixture TLS trust is confined to the test process. **This proves local data flow, not public Psiphon reachability or Iran-operator access.**

The fixture is deliberately retained for inspection after execution. Shut down its panel/core and remove only your expendable fixture directory when finished.

## Optional public engine probe

For personal/authorized use, after installing the engine into a private initialized test state:

```bash
PYTHONPATH=. python3 tests/public_psiphon_probe.py --state /path/to/private/test-state --country FR
```

This test starts the official engine, waits up to roughly 100 seconds, verifies a public HTTPS country response and stops its child process. It is not part of routine CI and makes no claim about future availability.

## Packaging

`tools/checksums.py` regenerates `SHA256SUMS` for distributable files, excluding itself and CI/dev-only metadata. Run it after changing code/docs/assets, then verify the staging installer:

```bash
python3 tools/checksums.py
python3 installer.py --source . --root /tmp/atlas-stage --stage-only
```

Do not add real state, engine cache, panel databases, subscription links, tokens or SSH scripts to the repository. Source packaging is based on the explicit checksum list, not a recursive copy of the developer workspace.
