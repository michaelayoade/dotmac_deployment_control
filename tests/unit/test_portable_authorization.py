"""The portable authorization: signed bytes, not a live-database claim."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from dotmac_deployment_control import (
    AuthorizationEnvelopeRefusalCode,
    AuthorizationEnvelopeRefusedError,
    AuthorizationEnvelopeV1,
    AuthorizationSignature,
    issue_authorization_envelope,
    verify_authorization_envelope,
)
from tests.authorization_support import SIGNER, VERIFIER, TestAuthorizationSigner

_NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
_D1 = "sha256:" + "11" * 32
_D2 = "sha256:" + "22" * 32
_D3 = "sha256:" + "33" * 32


def _fields() -> dict[str, object]:
    return {
        "authorization_id": "1cf99794-b135-4ec7-93e0-ea85c8cc4660",
        "rollout_ref": "rollout-1",
        "plan_id": "74ef9ff8-4eef-4fef-949f-202fd978d95e",
        "target_id": "46029f90-2a76-437c-b3d0-05b464e87472",
        "target_ref": "vendor-cp-prod",
        "product_code": "dotmac_platform_control_plane",
        "environment": "production",
        "operation": "deploy",
        "release_ref": "ghcr.io/dotmac/platform@sha256:" + "aa" * 32,
        "authorized_images": [
            {
                "service": "worker",
                "repository": "ghcr.io/dotmac/worker",
                "digest": "sha256:" + "bb" * 32,
            },
            {
                "service": "app",
                "repository": "ghcr.io/dotmac/app",
                "digest": "sha256:" + "aa" * 32,
            },
        ],
        "plan_digest": _D1,
        "descriptor_digest": _D2,
        "execution_plan_digest": _D3,
        "approval_policy_code": "deployment.production",
        "approval_policy_version": 4,
        "approval_decision_ref": "approval-88",
        "approval_decision_status": "granted",
        "approved_at": _NOW - timedelta(minutes=1),
        "issued_at": _NOW,
        "expires_at": _NOW + timedelta(minutes=30),
    }


def _issued() -> AuthorizationEnvelopeV1:
    return issue_authorization_envelope(_fields(), signer=SIGNER)


def test_signer_identity_is_inside_the_bytes_and_must_match_its_result() -> None:
    class LyingSigner(TestAuthorizationSigner):
        def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
            signed = super().sign(canonical_bytes)
            return AuthorizationSignature(
                "another-key", signed.algorithm, signed.signature
            )

    with pytest.raises(AuthorizationEnvelopeRefusedError) as caught:
        issue_authorization_envelope(_fields(), signer=LyingSigner())
    assert (
        caught.value.code is AuthorizationEnvelopeRefusalCode.SIGNER_IDENTITY_MISMATCH
    )


def test_an_unsigned_path_cannot_look_signed() -> None:
    class EmptySigner(TestAuthorizationSigner):
        def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
            return AuthorizationSignature(
                self.identity.key_id, self.identity.algorithm, ""
            )

    with pytest.raises(AuthorizationEnvelopeRefusedError) as caught:
        issue_authorization_envelope(_fields(), signer=EmptySigner())
    assert caught.value.code is AuthorizationEnvelopeRefusalCode.UNSIGNED


def test_a_nonempty_but_false_signature_cannot_look_verified() -> None:
    class FalseSigner(TestAuthorizationSigner):
        def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
            return AuthorizationSignature(
                self.identity.key_id, self.identity.algorithm, "not-a-signature"
            )

    envelope = issue_authorization_envelope(_fields(), signer=FalseSigner())
    with pytest.raises(AuthorizationEnvelopeRefusedError) as caught:
        verify_authorization_envelope(envelope, verifier=VERIFIER, at=_NOW)
    assert caught.value.code is AuthorizationEnvelopeRefusalCode.SIGNATURE_INVALID


def test_image_order_has_no_meaning_but_membership_and_value_do() -> None:
    first = _issued()
    fields = _fields()
    fields["authorized_images"] = list(reversed(fields["authorized_images"]))  # type: ignore[arg-type]
    reordered = issue_authorization_envelope(fields, signer=SIGNER)
    assert reordered.statement.canonical_bytes == first.statement.canonical_bytes
    assert reordered.signature == first.signature

    changed = _fields()
    images = deepcopy(changed["authorized_images"])
    images[0]["digest"] = "sha256:" + "cc" * 32  # type: ignore[index]
    changed["authorized_images"] = images
    assert (
        issue_authorization_envelope(changed, signer=SIGNER).signature
        != first.signature
    )
    signed_mutation = first.as_mapping()
    signed_mutation["statement"]["authorized_images"] = images  # type: ignore[index]
    with pytest.raises(AuthorizationEnvelopeRefusedError) as caught:
        verify_authorization_envelope(signed_mutation, verifier=VERIFIER, at=_NOW)
    assert caught.value.code is AuthorizationEnvelopeRefusalCode.SIGNATURE_INVALID

    fewer = _fields()
    fewer["authorized_images"] = fewer["authorized_images"][1:]  # type: ignore[index]
    assert (
        issue_authorization_envelope(fewer, signer=SIGNER).signature != first.signature
    )


def test_a_cryptographically_valid_revoked_decision_is_still_refused() -> None:
    valid = _issued()
    payload = valid.as_mapping()
    payload["statement"]["approval_decision_status"] = "revoked"  # type: ignore[index]
    statement = AuthorizationEnvelopeV1.parse(
        {"statement": payload["statement"], "signature": "temporary"}
    ).statement
    signed = SIGNER.sign(statement.canonical_bytes)
    revoked = AuthorizationEnvelopeV1(statement=statement, signature=signed.signature)

    with pytest.raises(AuthorizationEnvelopeRefusedError) as caught:
        verify_authorization_envelope(revoked, verifier=VERIFIER, at=_NOW)
    assert caught.value.code is AuthorizationEnvelopeRefusalCode.APPROVAL_NOT_STANDING

    fields = _fields()
    fields["approval_decision_status"] = "revoked"
    with pytest.raises(AuthorizationEnvelopeRefusedError) as issuance:
        issue_authorization_envelope(fields, signer=SIGNER)
    assert issuance.value.code is AuthorizationEnvelopeRefusalCode.APPROVAL_NOT_STANDING


#: Every signed key that a single scalar replacement can prove, and the value
#: it is replaced with. Read by the ratchet below as well as by the test.
_MUTATIONS: list[tuple[str, object]] = [
    # `schema` and `version` identify WHICH contract these bytes are, and a
    # reader that accepted either under a different name would be verifying
    # a statement it had not agreed to. `version` was already moved
    # elsewhere; `schema` was the one signed key nothing in this file
    # touched, which made it a field asserted rather than proven.
    ("schema", "dotmac.authorization-other"),
    ("authorization_id", "3810cb66-a430-44b0-abf9-c8105d3b648c"),
    ("rollout_ref", "rollout-2"),
    ("plan_id", "2b0de647-2542-4e89-b9f9-dfba2f453722"),
    ("target_id", "daf3a34b-6b5f-4823-9b12-d6dc33e1044e"),
    ("target_ref", "vendor-cp-stage"),
    ("product_code", "dotmac_sub"),
    ("environment", "staging"),
    ("operation", "rollback"),
    ("release_ref", "release-2"),
    ("plan_digest", "sha256:" + "44" * 32),
    ("descriptor_digest", "sha256:" + "55" * 32),
    ("execution_plan_digest", "sha256:" + "66" * 32),
    ("approval_policy_code", "deployment.emergency"),
    ("approval_policy_version", 5),
    ("approval_decision_ref", "approval-89"),
    ("approval_decision_status", "revoked"),
    ("approved_at", "2026-09-02T10:00:00Z"),
    ("issued_at", "2026-09-02T11:59:00Z"),
    ("expires_at", "2026-09-02T12:31:00Z"),
    ("key_id", "another-key"),
    ("algorithm", "another-algorithm"),
]

#: Signed keys proven by a DEDICATED test rather than by scalar replacement.
#: Named individually, with the reason, because an unexplained exemption list is
#: how a field stops being proven without anyone deciding that it should.
#:
#: `authorized_images` needs membership, ordering and value cases that one
#: scalar replacement cannot express — see the ordering test.
#:
#: `version` is refused EARLIER than the signature, with its own
#: UNSUPPORTED_VERSION code, because a reader must reject a contract it does not
#: implement before it tries to interpret the bytes under it. Adding it to the
#: parametrize list would assert the wrong refusal.
_COVERED_ELSEWHERE = {"authorized_images", "version"}


def test_a_clean_envelope_verifies_and_returns_its_statement() -> None:
    """THE POSITIVE CONTROL, and without it this whole file proves nothing.

    Every other `verify_authorization_envelope` call in this module is inside a
    `pytest.raises`. A suite shaped like that passes unchanged against a
    verifier that refuses EVERYTHING — twenty-three mutation tests all reporting
    SIGNATURE_INVALID, all green, none of them evidence that a correct
    authorization is accepted. That is the same shape as a guard whose negative
    control could not fail, and it is the one this repository keeps finding.

    So: an untouched envelope verifies, and the statement it returns is the one
    that was signed. Every refusal below is a difference from THIS.
    """
    envelope = _issued()
    statement = verify_authorization_envelope(envelope, verifier=VERIFIER, at=_NOW)

    assert statement.authorization_id == _fields()["authorization_id"]
    assert statement.plan_digest == _D1
    assert statement.descriptor_digest == _D2
    assert statement.execution_plan_digest == _D3
    # The three digests are distinct VALUES in the signed bytes and stay
    # distinct through a round trip. Foundation is being repaired in parallel to
    # refuse when one is substituted for another; this is Control's half of
    # that boundary.
    assert (
        len(
            {
                statement.plan_digest,
                statement.descriptor_digest,
                statement.execution_plan_digest,
            }
        )
        == 3
    )


def test_every_signed_key_has_a_mutation_and_no_mutation_is_orphaned() -> None:
    """THE RATCHET, in both directions.

    A field listed in the signed bytes and never mutated is a field this suite
    has ASSERTED rather than proven, and it would be added silently — the
    parametrize list below is hand-kept, so nothing about adding a signed field
    forces a proof for it.

    This derives the signed key set from the statement itself and requires the
    two sets to be equal. A new signed field fails here until it is mutated; a
    mutation naming a field that no longer exists fails here too, rather than
    passing over a key the statement stopped carrying.

    `authorized_images` is covered by its own test rather than the parametrize
    list, because a list needs membership, ordering and value cases that a
    single scalar replacement cannot express — so it is named here explicitly
    instead of being quietly exempt.
    """
    signed_keys = set(_issued().statement.as_mapping())
    mutated = {field for field, _ in _MUTATIONS} | _COVERED_ELSEWHERE

    assert signed_keys == mutated, (
        "signed keys and proven keys disagree:\n"
        f"  signed but never mutated: {sorted(signed_keys - mutated)}\n"
        f"  mutated but not signed  : {sorted(mutated - signed_keys)}"
    )


@pytest.mark.parametrize(("field", "replacement"), _MUTATIONS)
def test_every_bound_field_mutation_invalidates_the_signature(
    field: str, replacement: object
) -> None:
    payload = _issued().as_mapping()
    payload["statement"][field] = replacement  # type: ignore[index]
    with pytest.raises(AuthorizationEnvelopeRefusedError) as caught:
        verify_authorization_envelope(payload, verifier=VERIFIER, at=_NOW)
    assert caught.value.code is AuthorizationEnvelopeRefusalCode.SIGNATURE_INVALID


def test_plan_digest_substitution_is_not_a_descriptor_mismatch() -> None:
    payload = _issued().as_mapping()
    payload["statement"]["plan_digest"] = "sha256:" + "77" * 32  # type: ignore[index]
    with pytest.raises(AuthorizationEnvelopeRefusedError) as caught:
        verify_authorization_envelope(payload, verifier=VERIFIER, at=_NOW)
    assert caught.value.code is AuthorizationEnvelopeRefusalCode.SIGNATURE_INVALID
    assert "descriptor" not in caught.value.code.value


def test_unsupported_version_and_expiry_are_distinct_refusals() -> None:
    payload = _issued().as_mapping()
    payload["statement"]["version"] = 2  # type: ignore[index]
    with pytest.raises(AuthorizationEnvelopeRefusedError) as unsupported:
        AuthorizationEnvelopeV1.parse(payload)
    assert (
        unsupported.value.code is AuthorizationEnvelopeRefusalCode.UNSUPPORTED_VERSION
    )

    with pytest.raises(AuthorizationEnvelopeRefusedError) as expired:
        verify_authorization_envelope(
            _issued(), verifier=VERIFIER, at=_NOW + timedelta(minutes=30)
        )
    assert expired.value.code is AuthorizationEnvelopeRefusalCode.EXPIRED

    with pytest.raises(AuthorizationEnvelopeRefusedError) as early:
        verify_authorization_envelope(
            _issued(), verifier=VERIFIER, at=_NOW - timedelta(microseconds=1)
        )
    assert early.value.code is AuthorizationEnvelopeRefusalCode.NOT_YET_VALID
