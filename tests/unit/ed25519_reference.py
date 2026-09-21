"""Small RFC 8032 Ed25519 reference used only for wire-contract tests.

This is deliberately not production cryptography.  Control delegates signing
and verification to trusted composition; the test needs an implementation
independent of that future adapter so a canonicalization defect cannot make a
fake verifier green.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inverse(value: int) -> int:
    return pow(value, _P - 2, _P)


_D = (-121665 * _inverse(121666)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int:
    x_squared = ((y * y - 1) * _inverse(_D * y * y + 1)) % _P
    x = pow(x_squared, (_P + 3) // 8, _P)
    if (x * x - x_squared) % _P:
        x = (x * _SQRT_M1) % _P
    if (x * x - x_squared) % _P:
        raise ValueError("point has no square root")
    if (x & 1) != sign:
        x = _P - x
    return x


_BASE_Y = (4 * _inverse(5)) % _P
_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y)


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    factor = (_D * x1 * x2 * y1 * y2) % _P
    return (
        ((x1 * y2 + x2 * y1) * _inverse(1 + factor)) % _P,
        ((y1 * y2 + x1 * x2) * _inverse(1 - factor)) % _P,
    )


def _multiply(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("non-canonical point")
    point = (_recover_x(y, value >> 255), y)
    if _encode(point) != encoded:
        raise ValueError("non-canonical point")
    return point


def _expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    scalar, _prefix = _expand(seed)
    return _encode(_multiply(scalar, _BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand(seed)
    public = public_key(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    encoded_nonce = _encode(_multiply(nonce, _BASE))
    challenge = (
        int.from_bytes(
            hashlib.sha512(encoded_nonce + public + message).digest(), "little"
        )
        % _L
    )
    response = (nonce + challenge * scalar) % _L
    return encoded_nonce + response.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        encoded_nonce, encoded_response = signature[:32], signature[32:]
        response = int.from_bytes(encoded_response, "little")
        if response >= _L:
            return False
        public_point = _decode(public)
        nonce_point = _decode(encoded_nonce)
        challenge = (
            int.from_bytes(
                hashlib.sha512(encoded_nonce + public + message).digest(), "little"
            )
            % _L
        )
        return _multiply(response, _BASE) == _add(
            nonce_point, _multiply(challenge, public_point)
        )
    except ValueError:
        return False
