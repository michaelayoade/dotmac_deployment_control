"""Deterministic non-cryptographic doubles for authorization contract tests."""

from __future__ import annotations

import hashlib

from dotmac_deployment_control import (
    AUTHORIZATION_PURPOSE,
    AuthorizationSignature,
    AuthorizationSignerIdentity,
)


class TestAuthorizationSigner:
    __test__ = False
    identity = AuthorizationSignerIdentity(
        key_id="test-authorization-key", algorithm="test-sha256"
    )

    def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
        signature = hashlib.sha256(
            self.identity.key_id.encode() + b"\0" + canonical_bytes
        ).hexdigest()
        return AuthorizationSignature(
            key_id=self.identity.key_id,
            algorithm=self.identity.algorithm,
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
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        if (
            key_id != "test-authorization-key"
            or algorithm != "test-sha256"
            or purpose != AUTHORIZATION_PURPOSE
        ):
            return False
        expected = hashlib.sha256(key_id.encode() + b"\0" + canonical_bytes).hexdigest()
        return signature == expected


SIGNER = TestAuthorizationSigner()
VERIFIER = TestAuthorizationVerifier()
