# bLIP 56 dogfooding notes

What implementing bLIP 56 in LDK taught about the draft at
https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md.

- `findings.md`: gaps, conflicts and numbers found while implementing, by
  severity, each with where it surfaced and a proposed change.
- `requirements-matrix.md`: every normative bullet of the draft mapped to the
  test that enforces it, or to why none does.
- `reference/`: independent Python implementations reproducing the test vectors
  of the token construction and the notification signature.

The implementation lives on the private fork's `blip56-v2/*` branches: `wire`
(shared formats), `pos` (the terminal), `merchant`, and `joined` (end-to-end
tests and payment proofs).

Working notes for the fork, to be dropped, or turned into the slimmed bLIP's
test vectors, before anything goes upstream.
