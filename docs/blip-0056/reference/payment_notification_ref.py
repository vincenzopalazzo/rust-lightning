"""Independent reference for the bLIP 56 payment_notification signature: BOLT 12 merkle
construction plus BIP 340, stdlib only. Reuses the secp256k1 helpers of payment_token_ref.py."""
import hashlib, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from payment_token_ref import G, N, P, mul, add, bigsize, tu64, record  # noqa: E402

def sha(b): return hashlib.sha256(b).digest()

def tagged(tag, msg):
    t = sha(tag)
    return sha(t + t + msg)

# --- BOLT 12 merkle root -----------------------------------------------------
def parse_records(stream):
    """Yields (type, type_bytes, record_bytes) for a well-formed TLV stream."""
    i, out = 0, []
    def read_bigsize(j):
        b = stream[j]
        if b < 0xfd: return b, j + 1
        n = {0xfd: 2, 0xfe: 4, 0xff: 8}[b]
        return int.from_bytes(stream[j + 1:j + 1 + n], 'big'), j + 1 + n
    while i < len(stream):
        start = i
        t, i = read_bigsize(i)
        type_bytes = stream[start:i]
        length, i = read_bigsize(i)
        i += length
        out.append((t, type_bytes, stream[start:i]))
    return out

def merkle_root(stream):
    records = [r for r in parse_records(stream) if not 240 <= r[0] <= 1000]
    first = records[0][2]
    leaves = []
    for _, type_bytes, rec in records:
        leaf = tagged(b'LnLeaf', rec)
        nonce = tagged(b'LnNonce' + first, type_bytes)
        leaves.append(tagged(b'LnBranch', min(leaf, nonce) + max(leaf, nonce)))
    # Pair adjacent nodes level by level; an odd node out is carried up unchanged, so the
    # deepest subtrees are on the lowest-order leaves.
    while len(leaves) > 1:
        nxt = []
        for i in range(0, len(leaves) - 1, 2):
            a, b = leaves[i], leaves[i + 1]
            nxt.append(tagged(b'LnBranch', min(a, b) + max(a, b)))
        if len(leaves) % 2: nxt.append(leaves[-1])
        leaves = nxt
    return leaves[0]

# --- BIP 340 -----------------------------------------------------------------
def xonly(pt): return pt[0].to_bytes(32, 'big')

def bip340_sign(seckey, msg, aux=b'\x00' * 32):
    pt = mul(seckey, G)
    d = seckey if pt[1] % 2 == 0 else N - seckey
    t = (d ^ int.from_bytes(tagged(b'BIP0340/aux', aux), 'big')).to_bytes(32, 'big')
    k0 = int.from_bytes(tagged(b'BIP0340/nonce', t + xonly(pt) + msg), 'big') % N
    R = mul(k0, G)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged(b'BIP0340/challenge', xonly(R) + xonly(pt) + msg), 'big') % N
    return xonly(R) + ((k + e * d) % N).to_bytes(32, 'big')

def lift_x(x):
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    return (x, y if y % 2 == 0 else P - y)

def bip340_verify(pubx, msg, sig):
    pt = lift_x(int.from_bytes(pubx, 'big'))
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    e = int.from_bytes(tagged(b'BIP0340/challenge', sig[:32] + pubx + msg), 'big') % N
    R = add(mul(s, G), mul(N - e, pt))
    return R is not None and R[1] % 2 == 0 and R[0] == r

if __name__ == '__main__':
    preimage = b'\x44' * 32
    unsigned = (record(0, b'\x31' * 32) + record(2, b'\x22' * 32) + record(4, sha(preimage)) +
                record(6, preimage) + record(8, tu64(50_000)))
    root = merkle_root(unsigned)
    digest = tagged(b'lightningpayment_notificationsignature', root)
    issuer = int.from_bytes(b'\x2a' * 32, 'big')
    sig = bip340_sign(issuer, digest)
    assert bip340_verify(xonly(mul(issuer, G)), digest, sig)
    print('unsigned       ', unsigned.hex())
    print('merkle_root    ', root.hex())
    print('digest         ', digest.hex())
    print('notification   ', (unsigned + record(240, sig)).hex())
    if len(sys.argv) > 1:  # verify a signed notification produced elsewhere
        signed = bytes.fromhex(sys.argv[1])
        recs = parse_records(signed)
        sig_other = [r for r in recs if r[0] == 240][0][2][-64:]
        body = b''.join(r[2] for r in recs if r[0] != 240)
        d = tagged(b'lightningpayment_notificationsignature', merkle_root(body))
        print('external verifies:', bip340_verify(xonly(mul(issuer, G)), d, sig_other))
