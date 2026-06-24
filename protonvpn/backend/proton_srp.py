"""Proton SRP implementation — matches the official proton-python-client library.

Proton uses a heavily modified SRP-6a variant:
  - PMHash (4×SHA-512 → 256-byte digest) instead of plain SHA-512
  - k = PMHash(g_256le | N_256le)  — g first (as full 256 bytes), then N
  - password hash = PMHash(bcrypt(pw, (salt+b'proton')[:16]) | N_256le)
  - K = S as raw bytes  (no hashing of S)
  - M1 = PMHash(A | B | K)  — no username/salt/XOR in the proof

Sources: proton/session/srp/_pysrp.py and util.py from the proton-python-client package.
"""
import base64
import hashlib
import os

import bcrypt

_STD_B64    = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCRYPT_B64 = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_TO_BCRYPT  = bytes.maketrans(_STD_B64, _BCRYPT_B64)

_G       = 2
_MOD_LEN = 256   # 2048-bit group → 256 bytes


def _pmhash(data: bytes) -> bytes:
    """Proton's custom 256-byte hash: SHA512(data+\x00) ‖ … ‖ SHA512(data+\x03)."""
    return b"".join(hashlib.sha512(data + bytes([i])).digest() for i in range(4))


def _le(n: int, length: int = _MOD_LEN) -> bytes:
    return n.to_bytes(length, "little")


def _from_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def extract_pgp_content(pgp_message: str) -> bytes:
    """Strip PGP clearsign wrapper; return decoded base64 payload."""
    lines = pgp_message.splitlines()
    body: list[str] = []
    in_body = False
    for line in lines:
        if "-----BEGIN PGP SIGNATURE-----" in line:
            break
        if "-----BEGIN PGP SIGNED MESSAGE-----" in line:
            in_body = False
            continue
        if not in_body:
            if line.strip() == "":
                in_body = True
            continue
        if line.strip():
            body.append(line.strip())
    content = "".join(body)
    pad = (4 - len(content) % 4) % 4
    return base64.b64decode(content + "=" * pad)


def _hash_password(password: str, salt: bytes, modulus_bytes: bytes) -> bytes:
    """Proton v4 password hash: PMHash(bcrypt(pw, (salt+b'proton')[:16]) | modulus).

    The API salt is padded with the literal b'proton' (not zero bytes).
    The modulus is concatenated to the bcrypt output before the final PMHash.
    Returns 256 bytes (raw PMHash digest).
    """
    padded     = (salt + b"proton")[:16]
    bcrypt_b64 = base64.b64encode(padded).translate(_TO_BCRYPT)[:22]
    bcrypt_salt = b"$2y$10$" + bcrypt_b64
    hashed = bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt_salt)
    return _pmhash(hashed + modulus_bytes)


def compute_proof(
    username: str,
    password: str,
    salt_bytes: bytes,
    modulus_bytes: bytes,
    server_eph_bytes: bytes,
) -> tuple[bytes, bytes]:
    """Compute (M1_proof, A_ephemeral) for a single SRP exchange.

    Matches proton-python-client/_pysrp.py exactly.
    Returns raw bytes; base64-encode before sending to the Proton API.
    `username` is accepted for API compatibility but is not used in any hash
    (Proton's M1 formula omits I).
    """
    N = _from_le(modulus_bytes)
    B = _from_le(server_eph_bytes)

    # k = PMHash(g_256le | N_256le) — g as full 256-byte LE, g before N
    k = _from_le(_pmhash(_le(_G) + modulus_bytes))

    # a = 32-byte random with MSB set (matching get_random_of_length(32))
    a = _from_le(os.urandom(32)) | (1 << 255)
    A_int   = pow(_G, a, N)
    A_bytes = _le(A_int)

    # u = PMHash(A_256le | B_256le) as LE integer
    u = _from_le(_pmhash(A_bytes + server_eph_bytes))

    # x = LE int of PMHash(bcrypt(pw,(salt+b'proton')[:16]) | modulus)
    x = _from_le(_hash_password(password, salt_bytes, modulus_bytes))

    v = pow(_G, x, N)
    S = pow((B - k * v) % N, a + u * x, N)

    # K = S as raw bytes (no hashing)
    K = _le(S)

    # M1 = PMHash(A | B | K)
    M1 = _pmhash(A_bytes + server_eph_bytes + K)

    return M1, A_bytes
