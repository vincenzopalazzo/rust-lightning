# CI coverage job downloads and executes the codecov binary from a floating 'latest' URL without hash/signature verification on self-hosted runners

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: dependency
- Severity: Low
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: host (USB-connected computer)
- Default config affected: unknown
- Reported upstream: no

## Summary

The coverage job in build.yml fetches the codecov uploader from https://cli.codecov.io/latest/linux/codecov — a moving 'latest' URL — and executes it with no checksum, signature, or version pinning, passing it a (publicly visible, hardcoded) upload token. A compromise or MITM of that endpoint (or a malicious 'latest' release) yields arbitrary code execution on LDK's self-hosted CI runners in a job context that has the full source checkout; the same runners execute the fuzz and build jobs for the repository. All other binary downloads in this CI (bitcoind, electrs, benchmark fixtures) are sha25...

## Exploit chain

1. Entry point at `.github/workflows/build.yml:78`
2. The coverage job in build.yml fetches the codecov uploader from https://cli.codecov.io/latest/linux/codecov — a moving 'latest' URL — and executes it with no checksum, signature, or version pinning, passing it a (publicly visible, hardcoded) upload token. A compromise or MITM of that endpoint (or a

## Root cause

The workflow does download https://cli.codecov.io/latest/linux/codecov, chmod it executable, and run it on a self-hosted runner without pinning a version or verifying a checksum/signature. Exploitation requires compromise/control of Codecov's distribution path or equivalent TLS/DNS/CDN compromise, not merely an untrusted PR, so the attacker prerequisite is high. Worst-case impact is arbitrary code execution in the CI job context on the self-hosted runner, with possible access to the repo checkou...

## Impact

Attacker compromises the codecov CLI distribution endpoint or DNS/CDN path serving cli.codecov.io -> tainted 'latest' binary -> executed on the next coverage run -> runner-level code execution with repo checkout and any runner-persistent secrets/cache -> potential poisoned artifacts or cache poisoning affecting subsequent CI runs.

## Source

- Harness: redteam
- Finding ID: DEP-004
- Repo: lightningdevkit/rust-lightning
- File: .github/workflows/build.yml:78
- Confidence: high
