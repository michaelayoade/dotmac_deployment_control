"""Deterministic non-cryptographic doubles for authorization contract tests."""

from __future__ import annotations

import base64
import hashlib

from dotmac_deployment_control import (
    AUTHORIZATION_PURPOSE,
    AuthorizationSignature,
    AuthorizationSignerIdentity,
    PublicKeyFingerprintV1,
)

AUTHORIZATION_PUBLIC_KEY_B64 = (
    base64.urlsafe_b64encode(b"test-authorization-public-key")
    .decode("ascii")
    .rstrip("=")
)
AUTHORIZATION_PUBLIC_KEY_FINGERPRINT = PublicKeyFingerprintV1.from_public_key_b64(
    AUTHORIZATION_PUBLIC_KEY_B64
).canonical


class TestAuthorizationSigner:
    __test__ = False
    identity = AuthorizationSignerIdentity(
        key_id="test-authorization-key",
        algorithm="test-sha256",
        public_key_fingerprint=AUTHORIZATION_PUBLIC_KEY_FINGERPRINT,
    )

    def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
        signature = hashlib.sha256(
            self.identity.key_id.encode() + b"\0" + canonical_bytes
        ).hexdigest()
        return AuthorizationSignature(
            key_id=self.identity.key_id,
            algorithm=self.identity.algorithm,
            public_key_fingerprint=self.identity.public_key_fingerprint,
            signature=signature,
            purpose=AUTHORIZATION_PURPOSE,
        )


class TestAuthorizationVerifier:
    __test__ = False

    def verify(
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
            key_id != "test-authorization-key"
            or algorithm != "test-sha256"
            or purpose != AUTHORIZATION_PURPOSE
            or public_key_fingerprint != AUTHORIZATION_PUBLIC_KEY_FINGERPRINT
        ):
            return False
        expected = hashlib.sha256(key_id.encode() + b"\0" + canonical_bytes).hexdigest()
        return signature == expected


SIGNER = TestAuthorizationSigner()
VERIFIER = TestAuthorizationVerifier()
