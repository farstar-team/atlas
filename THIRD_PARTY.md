# Third-party software and services

Atlas code is MIT-licensed. It does not bundle a Psiphon or Xray binary.

| Dependency | Source and purpose |
|---|---|
| Native 3x-ui | [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui), tested against v3.11.0 official API; its upstream license applies |
| Xray-core | [XTLS/Xray-core](https://github.com/XTLS/Xray-core), operated by the existing panel; its upstream license applies |
| Optional Psiphon ConsoleClient | [Source/build instructions](https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master/ConsoleClient), [official binary repository](https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries); upstream AGPL and applicable dependency notices apply |
| Public Psiphon network | [Terms](https://psiphon.ca/terms), [FAQ](https://psiphon.ca/faq); public network access is separate from the software license |
| Public Psiphon bootstrap parameters | Public anonymous sponsor/channel and server-list verification key, also published in [bepass-org/warp-plus psiphon/p.go](https://github.com/bepass-org/warp-plus/blob/master/psiphon/p.go); these are not private user credentials |
| HTTPS health endpoint | Cloudflare's public `https://www.cloudflare.com/cdn-cgi/trace`; no Cloudflare API credential is used |
| Development browser tests | [Playwright](https://playwright.dev/python/), optional development dependency only; not installed on production servers |

The optional engine is downloaded directly from the official publisher at a pinned revision documented in `providers/psiphon.json`. Atlas verifies the SHA-256 of that asset and does not modify it. The public network's service terms and country availability are not controlled by Atlas.
