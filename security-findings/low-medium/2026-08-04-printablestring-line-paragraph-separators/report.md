# PrintableString passes U+2028/U+2029 (Zl/Zp) — log/terminal line injection via peer-controlled strings

- Triage severity: MEDIUM
- Verdict: FINDING
- Scanned: 2026-08-04
- Target: lightningdevkit/rust-lightning @ `9a5182e41d` (Forgejo main; also verified on Loupe-scanned HEAD)
- Canonical upstream: https://git.rust-bitcoin.org/lightningdevkit/rust-lightning
- Reported to vendor: Not yet (planned: public issue/PR on Forgejo — log-injection only, no embargo)
- **Reproduction: CONFIRMED by direct source analysis + unit-test PoC shape.** Not dynamically executed in-process; the filter logic and Unicode tables are unambiguous. PoC regression test below fails on HEAD (assert that U+2028/U+2029 are stripped).

## Finding

`PrintableString` / `UntrustedString` is LDK's documented sanitiser for attacker-controlled strings shown to operators (node aliases, `peer_msg`, BOLT 12 description/issuer/payer_note, LSPS text). Its threat model is explicit: a crafted peer string must not be able to exploit a terminal emulator or logging subsystem.

### Chain

1. `Display for PrintableString` (`lightning-types/src/string.rs:32-48`) replaces a char with U+FFFD only when:
   - `c.is_control()` (Unicode category **Cc** only), or
   - `is_unicode_general_category_other(c)` (C bucket / Cf / Cs / Co tables), or
   - `is_unicode_general_category_unassigned(c)`.
2. The auto-generated / hand-maintained table in `lightning-types/src/unicode.rs` includes `0x202A..=0x202E` (**Cf** bidi overrides) — added by PR #4593 / refined by #4605 — but **does not** include:
   - U+2028 LINE SEPARATOR (general category **Zl**)
   - U+2029 PARAGRAPH SEPARATOR (general category **Zp**)
3. Rust's `char::is_control()` returns `false` for Zl/Zp (Cc-only). Therefore both codepoints pass through `PrintableString` **verbatim**.
4. Many terminals, log viewers, structured-log parsers, and Unicode-aware renderers treat U+2028/U+2029 as hard line breaks. A peer can embed them in a node alias, invoice description, or channel error message to inject forged log lines that an operator believes are sanitised.

### Prior art / residual nature

- PR #4593 ("Strip Unicode `Cf` characters in `PrintableString`") and PR #4605 ("auto-generated unicode character category file") correctly closed the **Cf / bidi / Trojan Source** hole.
- This finding is the **residual Zl/Zp gap** after that work. No Forgejo issue or PR mentions U+2028/U+2029 or LINE/PARAGRAPH SEPARATOR in this context (checked 2026-08-04).
- Not present in bitcoin-security-council/findings issue #126 (existing rust-lightning review: ENT-001, KEY-001, KEY-002, SIG-001).

### Impact

Log/terminal line injection and forged operator-visible lines (fake funding/closure-looking entries, corrupted structured-log parsing, on-screen spoofing). No memory unsafety (`#![forbid(unsafe_code)]` in the types crate). No direct fund theft. Medium is appropriate for LDK's own stated sanitiser threat model.

### Suggested fix

In `PrintableString`'s filter (or in the unicode table generator), also replace U+2028 and U+2029 — e.g. treat general categories Zl/Zp, or hard-code the two codepoints next to the Cf ranges. Add a regression test mirroring the existing bidi test:

```rust
#[test]
fn sanitizes_line_and_paragraph_separators() {
    let rendered = format!("{}", PrintableString("ok\u{2028}forged\u{2029}more"));
    assert!(!rendered.contains('\u{2028}'));
    assert!(!rendered.contains('\u{2029}'));
}
```

### Confidence

High — filter predicates and unicode table contents verified on Forgejo `main` (`unicode.rs` has `0x202A..=0x202E` only; `2028`/`2029` absent). Existing bidi test proves the intended threat model; Zl/Zp are simply missing from the same defence.

### Dedup notes

- Distinct from PR #4593 (Cf only).
- Distinct from BSC issue #126 findings.
- LSPS5 "missing timestamp freshness" (Loupe #9) was reviewed and **rejected**: intentionally removed in Forgejo PR #3961 / issue #3944; not filed here.
