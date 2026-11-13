"""Independent reference implementation of the bLIP 56 payment_token construction
proposed in lightning/src/offers/payment_token.rs, using only the Python stdlib."""
import hashlib, hmac, struct

# --- secp256k1 -------------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)

def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

def ser(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')

def ecdh(secret, pub):  # libsecp256k1 default: SHA256(compressed(secret * pub))
    return hashlib.sha256(ser(mul(secret, pub))).digest()

# --- RFC 8439 ChaCha20-Poly1305 --------------------------------------------
def rotl(v, c): return ((v << c) & 0xffffffff) | (v >> (32 - c))

def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)

def chacha_block(key, counter, nonce):
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + \
        list(struct.unpack('<8L', key)) + [counter] + list(struct.unpack('<3L', nonce))
    w = st[:]
    for _ in range(10):
        qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
        qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14)
    return struct.pack('<16L', *[(w[i] + st[i]) & 0xffffffff for i in range(16)])

def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], ks))
    return bytes(out)

def poly1305(key, msg):
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], 'little')
    acc, p = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b'\x01', 'little')
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')

def pad16(b): return b'\x00' * (-len(b) % 16)

def aead_encrypt(key, nonce, aad, pt):
    otk = chacha_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, pt)
    mac = aad + pad16(aad) + ct + pad16(ct) + struct.pack('<QQ', len(aad), len(ct))
    return ct, poly1305(otk, mac)

# RFC 8439 section 2.8.2 test vector, to validate the AEAD above.
_pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
       b"the future, sunscreen would be it.")
_ct, _tag = aead_encrypt(bytes(range(0x80, 0xa0)), bytes.fromhex('070000004041424344454647'),
                         bytes.fromhex('50515253c0c1c2c3c4c5c6c7'), _pt)
assert _ct[:16].hex() == 'd31a8d34648e60db7b86afbc53ef7ec2', _ct[:16].hex()
assert _tag.hex() == '1ae10b594f09e26a7e902ecbd0600691', _tag.hex()

# --- bLIP 56 payment_token -------------------------------------------------
def bigsize(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'big')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'big')
    return b'\xff' + n.to_bytes(8, 'big')

def tu64(n): return n.to_bytes(8, 'big').lstrip(b'\x00')

def record(t, v): return bigsize(t) + bigsize(len(v)) + v

def sealed_order(amount_msat, description, order_metadata):
    return record(0, tu64(amount_msat)) + record(2, description.encode()) + \
        record(4, order_metadata)

def seal(issuer_pub, ephemeral_secret, plaintext):
    e_pub = ser(mul(ephemeral_secret, G))
    k = hmac.new(b'blip56_payment_token', ecdh(ephemeral_secret, issuer_pub), 'sha256').digest()
    ct, tag = aead_encrypt(k, b'\x00' * 12, e_pub, plaintext)
    return e_pub + ct + tag

if __name__ == '__main__':
    issuer_secret = int.from_bytes(b'\x2a' * 32, 'big')
    issuer_pub = mul(issuer_secret, G)
    plaintext = sealed_order(50_000, 'coffee, large', b'\x11' * 16)
    token = seal(issuer_pub, int.from_bytes(b'\x21' * 32, 'big'), plaintext)
    print('issuer_id      ', ser(issuer_pub).hex())
    print('ephemeral_key  ', '21' * 32)
    print('sealed_order   ', plaintext.hex())
    print('payment_token  ', token.hex())
    print('token_hash     ', hashlib.sha256(token).hexdigest())
