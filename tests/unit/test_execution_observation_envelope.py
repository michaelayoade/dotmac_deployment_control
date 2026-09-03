"""The target execution result is signed evidence, not caller-populated state."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

import pytest

from dotmac_deployment_control import (
    AuthorizationSignerIdentity,
    ExecutionObservationEnvelopeV1,
    ExecutionObservationRefusalCode,
    ExecutionObservationRefusedError,
    issue_execution_observation_envelope,
    verify_execution_observation_envelope,
)
from tests.authorization_support import SIGNER as AUTHORIZATION_SIGNER
from tests.execution_observation_support import (
    OBSERVATION_VERIFICATION_KEY,
    OBSERVATION_VERIFIER,
    TestExecutionObservationSigner,
)

_NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
_D1 = "sha256:" + "11" * 32
_D2 = "sha256:" + "22" * 32
_D3 = "sha256:" + "33" * 32
_D4 = "sha256:" + "44" * 32


def _fields() -> dict[str, object]:
    images = [
        {
            "service": "app",
            "repository": "ghcr.io/dotmac/platform",
            "digest": "sha256:" + "aa" * 32,
        }
    ]
    return {
        "report_id": "report-1",
        "authorization_id": "1cf99794-b135-4ec7-93e0-ea85c8cc4660",
        "authorization_plan_id": "74ef9ff8-4eef-4fef-949f-202fd978d95e",
        "authorization_control_version": "0.1.0a10",
        "authorization_envelope_digest": "sha256:" + "55" * 32,
        "execution_sequence": 1,
        "attempt_no": 1,
        "rollout_ref": "rollout-1",
        "target_id": "46029f90-2a76-437c-b3d0-05b464e87472",
        "target_ref": "vendor-cp-prod",
        "product_code": "dotmac_platform_control_plane",
        "environment": "production",
        "operation": "deploy",
        "release_ref": "release-1",
        "observed_release_ref": "release-1",
        "authorized_images": images,
        "observed_images": images,
        "plan_digest": _D1,
        "descriptor_digest": _D2,
        "execution_plan_digest": _D3,
        "observed_spec_digest": _D4,
        "observed_revision": "git:0123456789abcdef",
        "runtime_identity": {
            "kind": "oci_container",
            "identifier": "container:abcdef",
        },
        "outcome": "succeeded",
        "observed_at": _NOW,
    }


def _issued() -> ExecutionObservationEnvelopeV1:
    return issue_execution_observation_envelope(
        _fields(), signer=TestExecutionObservationSigner("target-observation-key")
    )


def test_a_clean_execution_observation_verifies() -> None:
    verified = verify_execution_observation_envelope(
        _issued(),
        verifier=OBSERVATION_VERIFIER,
        verification_key=OBSERVATION_VERIFICATION_KEY,
    )
    assert verified.statement.authorization_id == _fields()["authorization_id"]
    assert verified.statement.runtime_identity.identifier == "container:abcdef"


def test_the_positive_control_would_fail_with_an_all_refusing_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sensitivity: the clean-path test cannot pass against deny-everything."""
    monkeypatch.setattr(
        OBSERVATION_VERIFIER,
        "verify_execution_observation",
        lambda **_arguments: False,
    )
    with pytest.raises(ExecutionObservationRefusedError) as caught:
        test_a_clean_execution_observation_verifies()
    assert caught.value.code is ExecutionObservationRefusalCode.SIGNATURE_INVALID


def test_authorization_signer_cannot_cross_the_observation_purpose_boundary() -> None:
    assert isinstance(AUTHORIZATION_SIGNER.identity, AuthorizationSignerIdentity)
    with pytest.raises(ExecutionObservationRefusedError) as caught:
        issue_execution_observation_envelope(
            _fields(),
            signer=AUTHORIZATION_SIGNER,  # type: ignore[arg-type]
        )
    assert caught.value.code is ExecutionObservationRefusalCode.PURPOSE_MISMATCH


_SCALAR_MUTATIONS: tuple[tuple[str, object], ...] = (
    ("report_id", "report-2"),
    ("authorization_id", "8cf99794-b135-4ec7-93e0-ea85c8cc4660"),
    ("authorization_plan_id", "84ef9ff8-4eef-4fef-949f-202fd978d95e"),
    ("authorization_control_version", "0.1.0a99"),
    ("authorization_envelope_digest", "sha256:" + "66" * 32),
    ("execution_sequence", 2),
    ("attempt_no", 2),
    ("rollout_ref", "rollout-2"),
    ("target_id", "56029f90-2a76-437c-b3d0-05b464e87472"),
    ("target_ref", "vendor-cp-stage"),
    ("product_code", "dotmac_sub"),
    ("environment", "staging"),
    ("operation", "rollback"),
    ("release_ref", "release-2"),
    ("observed_release_ref", "release-2"),
    ("plan_digest", "sha256:" + "55" * 32),
    ("descriptor_digest", "sha256:" + "66" * 32),
    ("execution_plan_digest", "sha256:" + "77" * 32),
    ("observed_spec_digest", "sha256:" + "88" * 32),
    ("observed_revision", "git:fedcba9876543210"),
    ("runtime_identity", {"kind": "oci_container", "identifier": "other"}),
    ("outcome", "failed"),
    ("observed_at", "2026-09-03T12:01:00Z"),
    ("key_id", "other-observation-key"),
    ("algorithm", "other-algorithm"),
    ("public_key_fingerprint", "sha256:" + "99" * 32),
)
_DEDICATED = {"schema", "version", "purpose", "authorized_images", "observed_images"}


def test_every_signed_key_has_a_mutation_or_a_dedicated_proof() -> None:
    keys = set(_issued().statement.as_mapping())
    mutations = {name for name, _ in _SCALAR_MUTATIONS}
    assert not mutations & _DEDICATED
    assert keys == mutations | _DEDICATED


@pytest.mark.parametrize(("field", "replacement"), _SCALAR_MUTATIONS)
def test_every_scalar_mutation_invalidates_the_signature(
    field: str, replacement: object
) -> None:
    payload = _issued().as_mapping()
    payload["statement"][field] = replacement  # type: ignore[index]
    with pytest.raises(ExecutionObservationRefusedError) as caught:
        verify_execution_observation_envelope(
            payload,
            verifier=OBSERVATION_VERIFIER,
            verification_key=OBSERVATION_VERIFICATION_KEY,
        )
    assert caught.value.code is ExecutionObservationRefusalCode.SIGNATURE_INVALID


@pytest.mark.parametrize("field", ["authorized_images", "observed_images"])
def test_each_image_set_is_signed_by_member_and_digest(field: str) -> None:
    payload = _issued().as_mapping()
    changed = deepcopy(payload["statement"][field])  # type: ignore[index]
    changed[0]["digest"] = "sha256:" + "99" * 32
    payload["statement"][field] = changed  # type: ignore[index]
    with pytest.raises(ExecutionObservationRefusedError) as caught:
        verify_execution_observation_envelope(
            payload,
            verifier=OBSERVATION_VERIFIER,
            verification_key=OBSERVATION_VERIFICATION_KEY,
        )
    assert caught.value.code is ExecutionObservationRefusalCode.SIGNATURE_INVALID


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "dotmac.other"),
        ("version", 2),
        ("purpose", "deployment_authorization"),
    ],
)
def test_contract_identity_is_refused_before_signature_verification(
    field: str, value: object
) -> None:
    payload = _issued().as_mapping()
    payload["statement"][field] = value  # type: ignore[index]
    with pytest.raises(ExecutionObservationRefusedError) as caught:
        ExecutionObservationEnvelopeV1.parse(payload)
    assert caught.value.code in {
        ExecutionObservationRefusalCode.UNSUPPORTED_VERSION,
        ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
    }


def test_boolean_is_not_an_integer_observation_version() -> None:
    payload = _issued().as_mapping()
    payload["statement"]["version"] = True  # type: ignore[index]
    with pytest.raises(ExecutionObservationRefusedError) as caught:
        ExecutionObservationEnvelopeV1.parse(payload)
    assert caught.value.code is ExecutionObservationRefusalCode.UNSUPPORTED_VERSION


@pytest.mark.parametrize(("field", "value"), [("schema", "same"), ("version", 1)])
def test_contract_identity_cannot_be_caller_supplied(field: str, value: object) -> None:
    fields = _fields()
    fields[field] = value
    with pytest.raises(ExecutionObservationRefusedError, match="derived"):
        issue_execution_observation_envelope(
            fields,
            signer=TestExecutionObservationSigner("target-observation-key"),
        )
