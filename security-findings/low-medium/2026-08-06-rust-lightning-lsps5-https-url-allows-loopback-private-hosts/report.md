# LSPS5 LSPSUrl::parse only requires https scheme (no block on loopback/private hosts)

- Project: rust-lightning (lightningdevkit/rust-lightning)
- Commit/version: `4347eb85277d19bd06660228a7bed4b8a5b3c514`
- Category: incomplete URL validation / SSRF footgun for consumers
- Severity: Medium — library does not fetch URLs itself; consumers that fetch peer-supplied webhook URLs can hit internal hosts
- Reproduction: static — parse checks scheme==https only
- Confirmed: code-review
- Attacker model: malicious LSP peer; impact requires consumer HTTP fetch
- Default config affected: consumer-dependent
- Reported upstream: no
- Source: sentinel, 2026-08-06

## Suggested fix
Optional deny-list for private/loopback IPs; document SSRF-safe fetch.

## References
- lightning-liquidity/src/lsps5/url_utils.rs ~45-52
