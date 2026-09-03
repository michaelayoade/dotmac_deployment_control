"""Deterministic purpose-typed doubles for target observation tests."""

from __future__ import annotations

import base64
import hashlib

from dotmac_deployment_control import (
    EXECUTION_OBSERVATION_PURPOSE,
    ExecutionObservationSignature,
    ExecutionObservationSignerIdentity,
    ExecutionObservationVerificationKey,
    PublicKeyFingerprintV1,
)


def observation_public_key_b64(key_id: str) -> str:
    raw = hashlib.sha256(b"observation-public-key\0" + key_id.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def observation_public_key_fingerprint(key_id: str) -> str:
    return PublicKeyFingerprintV1.from_public_key_b64(
        observation_public_key_b64(key_id)
    ).canonical


class TestExecutionObservationSigner:
    __test__ = False

    def __init__(self, key_id: str, *, public_key_b64: str | None = None) -> None:
        self.public_key_b64 = public_key_b64 or observation_public_key_b64(key_id)
        self.execution_observation_identity = ExecutionObservationSignerIdentity(
            key_id=key_id,
            algorithm="test-sha256",
            public_key_fingerprint=PublicKeyFingerprintV1.from_public_key_b64(
                self.public_key_b64
            ).canonical,
        )

    def sign_execution_observation(
        self, canonical_bytes: bytes
    ) -> ExecutionObservationSignature:
        identity = self.execution_observation_identity
        signature = hashlib.sha256(
            self.public_key_b64.encode() + b"\0observation\0" + canonical_bytes
        ).hexdigest()
        return ExecutionObservationSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key_fingerprint=identity.public_key_fingerprint,
            signature=signature,
        )


class TestExecutionObservationVerifier:
    __test__ = False

    def verify_execution_observation(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_b64: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        if (
            algorithm != "test-sha256"
            or purpose != EXECUTION_OBSERVATION_PURPOSE
            or PublicKeyFingerprintV1.from_public_key_b64(public_key_b64).canonical
            != public_key_fingerprint
        ):
            return False
        expected = hashlib.sha256(
            public_key_b64.encode() + b"\0observation\0" + canonical_bytes
        ).hexdigest()
        return signature == expected


OBSERVATION_VERIFIER = TestExecutionObservationVerifier()
OBSERVATION_VERIFICATION_KEY = ExecutionObservationVerificationKey(
    key_id="target-observation-key",
    algorithm="test-sha256",
    purpose=EXECUTION_OBSERVATION_PURPOSE,
    public_key_b64=observation_public_key_b64("target-observation-key"),
    public_key_fingerprint=observation_public_key_fingerprint("target-observation-key"),
)
