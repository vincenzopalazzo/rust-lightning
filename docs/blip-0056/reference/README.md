# bLIP 56 reference vectors

Independent, stdlib-only Python implementations of the two constructions the
LDK code pins test vectors for. They exist so the vectors are not just LDK
agreeing with itself, and so the constructions can be proposed for the draft
with something a second implementer can run.

| Script | Reproduces | LDK test |
|--------|------------|----------|
| `payment_token_ref.py` | `payment_token` sealing: ECDH, HMAC-SHA256 key derivation, RFC 8439 ChaCha20-Poly1305 with the ephemeral key as AAD | `offers::payment_token::tests::payment_token_test_vector` |
| `payment_notification_ref.py` | `payment_notification` BOLT 12 merkle root, tagged digest and BIP 340 signature | `offers::payment_notification::tests::payment_notification_test_vector` |

`payment_token_ref.py` checks its AEAD against the RFC 8439 section 2.8.2 test
vector before producing anything.

```bash
python3 -I docs/blip-0056/reference/payment_token_ref.py
```

```bash
python3 -I docs/blip-0056/reference/payment_notification_ref.py
```

`payment_notification_ref.py` also takes a hex-encoded signed notification as
an argument and checks its signature against the test issuer key.

These are review aids for the private fork and are meant to be dropped, or
moved into the bLIP as its test vectors, before anything goes upstream.
