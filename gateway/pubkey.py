"""Ed25519 public keys: canonical unpadded base64url, on-curve, and in the prime-order subgroup.

OpenSSL's Ed25519PublicKey.from_public_bytes accepts any 32 bytes (including the identity, which
verifies any message). The loader therefore decodes as RFC 8032 §5.1.3, refuses small-order and
non-canonical encodings, and requires [L]P to be the identity so a torsion component cannot sneak in.
"""
import base64
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY_RE = re.compile(r"[A-Za-z0-9_-]{43}")
P = 2**255 - 19
D = (-121665 * pow(121666, -1, P)) % P
# sqrt(-1) mod p, used in the RFC 8032 recovery of x
I = pow(2, (P - 1) // 4, P)
# RFC 8032 prime-order subgroup order
L = 2**252 + 27742317777372353535851937790883648493
# 2d, for extended twisted-Edwards addition (a = -1)
_K = (2 * D) % P


def _le(n: int) -> bytes:
    return n.to_bytes(32, "little")


# libsodium ge25519_has_small_order: identity, y=0, y=-1, the two order-8 points, and the
# non-canonical encodings of 0 and 1 (y = p, y = p+1). Compared with the sign bit cleared.
SMALL_ORDER = frozenset({
    _le(0),
    _le(1),
    bytes.fromhex("26e8958fc2b227b045c3f524ba5eec544d6ecdca7a87654ddc5b701cadb84c59"),
    bytes.fromhex("c7176a703d4dda708e3d9a29fb4c1adb021ecd0b755554001400000000000000"),
    _le(P - 1),
    _le(P),
    _le(P + 1),
})


def _add(p, q):
    """Extended twisted-Edwards addition, a = -1 (Hisil, Wong, Carter, Dawson)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = _K * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = (b - a) % P, (d - c) % P, (d + c) % P, (b + a) % P
    return e * f % P, g * h % P, f * g % P, e * h % P


def _mul(pt, n):
    acc = (0, 1, 1, 0)
    addend = pt
    while n:
        if n & 1:
            acc = _add(acc, addend)
        addend = _add(addend, addend)
        n >>= 1
    return acc


def _decode_point(raw: bytes):
    """RFC 8032 §5.1.3 decode, or None if non-canonical, off-curve, or small-order listed."""
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    if y >= P:
        return None
    if (raw[:31] + bytes([raw[31] & 0x7F])) in SMALL_ORDER:
        return None
    x_0 = raw[31] >> 7
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == (P - u) % P:
        x = (x * I) % P
        vx2 = (v * x * x) % P
    if vx2 != u or (x == 0 and x_0):
        return None
    if x_0:
        x = P - x
    return (x, y, 1, x * y % P)


def _is_identity(pt) -> bool:
    x, y, z, _ = pt
    return x == 0 and y == z and z != 0


def accepted_public_bytes(raw: bytes) -> bool:
    """True if raw is a 32-byte canonical, on-curve Ed25519 key in the prime-order subgroup."""
    pt = _decode_point(raw)
    if pt is None:
        return False
    if _is_identity(_mul(pt, 8)):
        return False
    return _is_identity(_mul(pt, L))


def public_key(text: str) -> Ed25519PublicKey | None:
    """An Ed25519 public key as canonical unpadded base64url of its 32 raw bytes, else None."""
    if not PUBLIC_KEY_RE.fullmatch(text):
        return None
    raw = base64.urlsafe_b64decode(text + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text or not accepted_public_bytes(raw):
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        return None
