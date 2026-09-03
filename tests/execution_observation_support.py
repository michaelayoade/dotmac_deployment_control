"""Deterministic purpose-typed doubles for target observation tests."""

from __future__ import annotations

import hashlib

from dotmac_deployment_control import (
    EXECUTION_OBSERVATION_PURPOSE,
    ExecutionObservationSignature,
    ExecutionObservationSignerIdentity,
)


class TestExecutionObservationSigner:
    __test__ = False

    def __init__(self, key_id: str) -> None:
        self.execution_observation_identity = ExecutionObservationSignerIdentity(
            key_id=key_id, algorithm="test-sha256"
        )

    def sign_execution_observation(
        self, canonical_bytes: bytes
    ) -> ExecutionObservationSignature:
        identity = self.execution_observation_identity
        signature = hashlib.sha256(
            identity.key_id.encode() + b"\0observation\0" + canonical_bytes
        ).hexdigest()
        return ExecutionObservationSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
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
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        if algorithm != "test-sha256" or purpose != EXECUTION_OBSERVATION_PURPOSE:
            return False
        expected = hashlib.sha256(
            key_id.encode() + b"\0observation\0" + canonical_bytes
        ).hexdigest()
        return signature == expected


OBSERVATION_VERIFIER = TestExecutionObservationVerifier()
