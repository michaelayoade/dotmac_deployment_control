"""Deterministic purpose-typed doubles for signed dispatch tests."""

from __future__ import annotations

import base64
import hashlib

from dotmac_deployment_control import (
    DISPATCH_PURPOSE,
    DispatchSignature,
    DispatchSignerIdentity,
    PublicKeyFingerprintV1,
)

DISPATCH_PUBLIC_KEY_B64 = (
    base64.urlsafe_b64encode(b"test-dispatch-public-key").decode("ascii").rstrip("=")
)
DISPATCH_PUBLIC_KEY_FINGERPRINT = PublicKeyFingerprintV1.from_public_key_b64(
    DISPATCH_PUBLIC_KEY_B64
).canonical


class TestDispatchSigner:
    __test__ = False

    def __init__(
        self, *, public_key_fingerprint: str = DISPATCH_PUBLIC_KEY_FINGERPRINT
    ) -> None:
        self.calls = 0
        self.dispatch_identity = DispatchSignerIdentity(
            key_id="test-dispatch-key",
            algorithm="test-sha256",
            public_key_fingerprint=public_key_fingerprint,
        )

    def sign_dispatch(self, canonical_bytes: bytes) -> DispatchSignature:
        self.calls += 1
        identity = self.dispatch_identity
        signature = hashlib.sha256(
            DISPATCH_PUBLIC_KEY_B64.encode() + b"\0dispatch\0" + canonical_bytes
        ).hexdigest()
        return DispatchSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key_fingerprint=identity.public_key_fingerprint,
            signature=signature,
        )


class TestDispatchVerifier:
    __test__ = False

    def verify_dispatch(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        if (
            key_id != "test-dispatch-key"
            or algorithm != "test-sha256"
            or purpose != DISPATCH_PURPOSE
            or public_key_fingerprint != DISPATCH_PUBLIC_KEY_FINGERPRINT
        ):
            return False
        expected = hashlib.sha256(
            DISPATCH_PUBLIC_KEY_B64.encode() + b"\0dispatch\0" + canonical_bytes
        ).hexdigest()
        return signature == expected


DISPATCH_SIGNER = TestDispatchSigner()
DISPATCH_VERIFIER = TestDispatchVerifier()
