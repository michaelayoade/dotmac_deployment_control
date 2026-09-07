"""V3: binds Platform Health's evidence into a signed successor authorization.

**Admit control here is FIXTURE-SHAPED, not end-to-end.** Every test in this
file exercises Control's own verification/binding contract against
synthetic evidence built by `tests.health_evidence_support` (a MIRROR of
`dotmac_platform_health.evidence.canonical_health_evidence_bytes`'s
documented encoding, not an import of it — see that module's docstring). No
real `dotmac-platform-health` producer, real Ed25519 key, or real Foundation
verifier is exercised anywhere here. The genuine end-to-end integration proof
— a real signed `DeploymentHealthEvidence.v1` from a real Platform Health
service composition, verified by a real injected `HealthEvidenceVerifier`,
consumed by a real Foundation offline verifier — is a later step in this
programme, after Foundation is frozen and built once. Describing anything
below as end-to-end proof would be the overclaim two prior PRs in this chain
were already corrected for.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from dotmac_deployment_control import (
    AuthorizationEnvelopeV3,
    AuthorizationEnvelopeV3RefusalCode,
    AuthorizationEnvelopeV3RefusedError,
    AuthorizationSignature,
    AuthorizationSubjectV3,
    control_plan_digest_preimage,
    issue_authorization_envelope_v3,
    parse_signed_health_evidence_document,
    verify_authorization_envelope_v3,
)
from dotmac_deployment_control.authorization_v3 import (
    CONTROL_PLAN_DIGEST_EXCLUDED_FIELDS,
)
from tests.authorization_support import SIGNER, VERIFIER, TestAuthorizationSigner
from tests.health_evidence_support import (
    HEALTH_EVIDENCE_VERIFIER,
    REAL_HEALTH_EVIDENCE_KEY_ID,
    TestHealthEvidenceVerifier,
    build_component,
    build_signed_health_evidence_document,
)

_NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
_D1 = "sha256:" + "11" * 32
_D2 = "sha256:" + "22" * 32
_D3 = "sha256:" + "33" * 32
_ROSTER = ("api", "db", "worker")


def _fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "authorization_id": "1cf99794-b135-4ec7-93e0-ea85c8cc4660",
        "execution_sequence": 1,
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
    base.update(overrides)
    return base


def _evidence_document(
    *,
    roster: tuple[str, ...] = _ROSTER,
    evaluated_at: datetime = _NOW - timedelta(minutes=1),
    valid_until: datetime = _NOW + timedelta(hours=1),
    key_id: str = REAL_HEALTH_EVIDENCE_KEY_ID,
    signature_override: bytes | None = None,
) -> dict[str, object]:
    components = [build_component(code) for code in roster]
    return build_signed_health_evidence_document(
        evaluated_at=evaluated_at,
        valid_until=valid_until,
        components=components,
        key_id=key_id,
        signature_override=signature_override,
    )


def _issued(**field_overrides: object) -> AuthorizationEnvelopeV3:
    return issue_authorization_envelope_v3(
        _fields(**field_overrides),
        evidence_document=_evidence_document(),
        required_component_roster=_ROSTER,
        evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
        signer=SIGNER,
    )


def _matching_subject(envelope: AuthorizationEnvelopeV3) -> AuthorizationSubjectV3:
    return envelope.statement.subject


# ── Admit control (fixture-shaped; see module docstring) ───────────────────


def test_genuine_evidence_correctly_bound_produces_a_v3_authorization() -> None:
    """The chain must be able to say YES before it can be trusted to say NO.

    FIXTURE-SHAPED (see module docstring): "genuine" here means signed by
    `tests.health_evidence_support`'s double under the key id it treats as
    real, not by an actual Platform Health service.
    """
    envelope = _issued()
    verified = verify_authorization_envelope_v3(
        envelope,
        verifier=VERIFIER,
        expected_subject=_matching_subject(envelope),
        at=_NOW,
    )
    assert verified.statement.health_evidence_digest.startswith("sha256:")
    assert verified.statement.required_component_roster == _ROSTER
    assert verified.statement.control_plan_digest.startswith("sha256:")


# ── control_plan_digest: canonical preimage, explicit exclusion ────────────


def test_control_plan_digest_is_stable_regardless_of_a_planted_self_reference() -> None:
    """`control_plan_digest` must never be inside the bytes it is a digest of.

    Plants the field, with THREE different values, directly inside the
    mapping handed to the preimage builder — modelling a caller (or a future
    bug) trying to make the digest describe itself. The filter is structural
    (a set-difference, not a presence check), so the resulting preimage, and
    therefore the resulting digest, must be IDENTICAL regardless of what a
    caller put in the excluded key.
    """
    base_mapping = {
        "target_id": "t-1",
        "environment": "production",
        "control_plan_digest": "sha256:" + "00" * 32,
    }
    first = control_plan_digest_preimage(base_mapping)
    assert "control_plan_digest" not in first

    planted_other_value = dict(base_mapping)
    planted_other_value["control_plan_digest"] = "sha256:" + "ff" * 32
    second = control_plan_digest_preimage(planted_other_value)
    assert first == second

    planted_missing = {"target_id": "t-1", "environment": "production"}
    third = control_plan_digest_preimage(planted_missing)
    assert first == third


def test_control_plan_digest_is_not_a_second_name_for_the_plan_digest() -> None:
    envelope = _issued()
    assert envelope.statement.control_plan_digest != envelope.statement.plan_digest
    # Same plan_digest, different target -> different control_plan_digest.
    other_target = _issued(target_id="a-different-target-id")
    assert (
        other_target.statement.plan_digest == envelope.statement.plan_digest
    ), "fixture sanity: both use the same plan_digest"
    assert (
        other_target.statement.control_plan_digest
        != envelope.statement.control_plan_digest
    )


def test_control_plan_digest_is_re_derivable_by_an_independent_reader() -> None:
    """ "Canonical and re-derivable": ANY holder of the full mapping recomputes it."""
    from dotmac_deployment_control.digests import ControlPlanDigestV1, canonical_json

    envelope = _issued()
    mapping = envelope.statement.as_mapping()
    preimage = control_plan_digest_preimage(mapping)
    recomputed = ControlPlanDigestV1.over_bytes(canonical_json(preimage)).canonical
    assert recomputed == envelope.statement.control_plan_digest


def test_a_corrupted_control_plan_digest_is_refused_before_subject_checks() -> None:
    """Defensive re-derivation at verify time, isolated from the outer signature.

    A hand-corrupted `control_plan_digest`, RE-SIGNED (so the outer signature
    genuinely verifies), still fails: the value no longer re-derives from the
    statement's own bound terms.
    """
    envelope = _issued()
    mapping = envelope.as_mapping()
    mapping["statement"]["control_plan_digest"] = "sha256:" + "ee" * 32
    tampered_statement = AuthorizationEnvelopeV3.parse(
        {"statement": mapping["statement"], "signature": "placeholder"}
    ).statement
    resigned = SIGNER.sign(tampered_statement.canonical_bytes)
    tampered = AuthorizationEnvelopeV3(
        statement=tampered_statement, signature=resigned.signature
    )
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            tampered,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            at=_NOW,
        )
    assert (
        caught.value.code
        is AuthorizationEnvelopeV3RefusalCode.CONTROL_PLAN_DIGEST_MISMATCH
    )


# ── Signature verified, not merely present ──────────────────────────────


def test_a_nonempty_but_false_outer_signature_cannot_look_verified() -> None:
    class FalseSigner(TestAuthorizationSigner):
        def sign(self, canonical_bytes: bytes) -> AuthorizationSignature:
            return AuthorizationSignature(
                key_id=self.identity.key_id,
                algorithm=self.identity.algorithm,
                public_key_fingerprint=self.identity.public_key_fingerprint,
                signature="not-a-signature",
            )

    envelope = issue_authorization_envelope_v3(
        _fields(),
        evidence_document=_evidence_document(),
        required_component_roster=_ROSTER,
        evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
        signer=FalseSigner(),
    )
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            at=_NOW,
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.SIGNATURE_INVALID


def test_reject_tampering_a_mutated_outer_statement_fails_signature_verification() -> (
    None
):
    envelope = _issued()
    mapping = envelope.as_mapping()
    mapping["statement"]["target_id"] = "a-different-target-entirely"
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            mapping,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            at=_NOW,
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.SIGNATURE_INVALID


def test_a_forged_future_evidence_field_earns_no_semantic_diagnostic() -> None:
    envelope = _issued()
    mapping = envelope.as_mapping()
    mapping["statement"]["health_evidence_evaluated_at"] = (
        _NOW + timedelta(minutes=1)
    ).isoformat()
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            mapping,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            at=_NOW,
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.SIGNATURE_INVALID


# ── Evidence signature: verified, not merely present ────────────────────


def test_a_false_evidence_signature_is_refused_at_issuance() -> None:
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        issue_authorization_envelope_v3(
            _fields(),
            evidence_document=_evidence_document(signature_override=b"not-real"),
            required_component_roster=_ROSTER,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
    assert (
        caught.value.code
        is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_SIGNATURE_INVALID
    )


def test_evidence_signed_under_an_unenrolled_key_is_refused() -> None:
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        issue_authorization_envelope_v3(
            _fields(),
            evidence_document=_evidence_document(key_id="an-attacker-held-key"),
            required_component_roster=_ROSTER,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
    assert (
        caught.value.code
        is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_SIGNATURE_INVALID
    )


# ── Evidence digest: compared, not merely carried ───────────────────────


def test_evidence_digest_is_recomputed_and_compared_not_merely_carried() -> None:
    """Mutate the evidence bytes; the recomputed digest must disagree.

    If Control only CARRIED the digest string without recomputing it from
    bytes handed in again, this mutation would go unnoticed.
    """
    envelope = _issued()
    # A DIFFERENT evaluation than the one actually bound at issuance -- its
    # own signature is internally valid (it is genuine evidence, just of a
    # different moment), which is what makes this a DIGEST-comparison proof
    # rather than a signature-verification one: the outer authorization was
    # never re-signed, and the mismatch must be caught by recomputing the
    # digest over the bytes handed in and comparing, not by any signature
    # check.
    different_evidence = build_signed_health_evidence_document(
        evaluated_at=_NOW - timedelta(minutes=2),
        valid_until=_NOW + timedelta(hours=1),
        components=[build_component(code) for code in _ROSTER],
    )
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            evidence_document_for_tamper_check=different_evidence,
            at=_NOW,
        )
    assert (
        caught.value.code is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_DIGEST_MISMATCH
    )


def test_evidence_digest_comparison_stays_silent_for_the_exact_bytes_bound() -> None:
    """Near-miss control: re-supplying the SAME evidence must not refuse."""
    envelope = _issued()
    verify_authorization_envelope_v3(
        envelope,
        verifier=VERIFIER,
        expected_subject=_matching_subject(envelope),
        evidence_document_for_tamper_check=_evidence_document(),
        at=_NOW,
    )


# ── Reject wrong-subject evidence (roster mismatch) ─────────────────────


def test_evidence_describing_the_wrong_roster_is_refused() -> None:
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        issue_authorization_envelope_v3(
            _fields(),
            evidence_document=_evidence_document(roster=("api", "db")),
            required_component_roster=_ROSTER,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
    assert (
        caught.value.code is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_ROSTER_MISMATCH
    )


def test_evidence_with_an_extra_component_is_also_a_roster_mismatch() -> None:
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        issue_authorization_envelope_v3(
            _fields(),
            evidence_document=_evidence_document(roster=(*_ROSTER, "extra-component")),
            required_component_roster=_ROSTER,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
    assert (
        caught.value.code is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_ROSTER_MISMATCH
    )


def test_roster_order_has_no_meaning_and_a_reordered_roster_stays_silent() -> None:
    """Near-miss control: the ONLY thing that matters is the SET of codes."""
    issue_authorization_envelope_v3(
        _fields(),
        evidence_document=_evidence_document(roster=tuple(reversed(_ROSTER))),
        required_component_roster=_ROSTER,
        evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
        signer=SIGNER,
    )


# ── The one-caller negative control ─────────────────────────────────────


def test_the_one_caller_negative_control() -> None:
    """A single caller supplying BOTH the evidence and the requirement cannot pass.

    The caller here freely chooses: the evidence bytes' roster (made to
    equal `required_component_roster` exactly), the `evaluated_at`/
    `valid_until` values, and the `required_component_roster` argument
    itself — every value ONE PARTY controls. What they cannot choose is a
    signature the injected `HealthEvidenceVerifier` accepts, because that
    verifier models Platform Health's real key: a signature this caller
    invents by hand (or copies from an unrelated document) is a second
    reading only if it independently reproduces the ACQUISITION PATH — being
    signed by the real key — not merely the SHAPE of a signature field. Two
    fields supplied by one caller, matching each other perfectly, remain one
    reading, and this test is the proof that this module refuses exactly
    that.
    """
    self_asserted_roster = _ROSTER
    self_signed_evidence = _evidence_document(
        roster=self_asserted_roster,
        # The caller's own fabricated "signature" — same length/shape as a
        # real one, produced with no knowledge of the double's real secret.
        signature_override=b"\x00" * 32,
    )
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        issue_authorization_envelope_v3(
            _fields(),
            evidence_document=self_signed_evidence,
            required_component_roster=self_asserted_roster,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
    assert (
        caught.value.code
        is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_SIGNATURE_INVALID
    ), (
        "content agreement alone (matching roster, well-formed bytes) must "
        "never substitute for a genuine, independently-verified signature"
    )


def test_the_one_caller_control_with_a_permissive_verifier_stub() -> None:
    """A degenerate verifier that always returns True is not this module's job to
    prevent —
    it is why `HealthEvidenceVerifier` is INJECTED rather than trusted by
    presence. This test proves the converse sensitivity: swap in a verifier
    that ALWAYS says yes, and the one-caller case now (correctly, for that
    broken verifier) succeeds — demonstrating the refusal above genuinely
    depends on the verifier doing real work, not on some other structural
    accident catching it.
    """

    class AlwaysTrueVerifier(TestHealthEvidenceVerifier):
        def verify_health_evidence(self, **_: object) -> bool:  # type: ignore[override]
            return True

    self_signed_evidence = _evidence_document(signature_override=b"\x00" * 32)
    issue_authorization_envelope_v3(
        _fields(),
        evidence_document=self_signed_evidence,
        required_component_roster=_ROSTER,
        evidence_verifier=AlwaysTrueVerifier(),
        signer=SIGNER,
    )


# ── Reject substitution: product / environment / target / rollout+sequence / approval


def test_reject_substitution_wrong_product() -> None:
    envelope = _issued()
    subject = _matching_subject(envelope)
    wrong = replace(subject, product_code="a-different-product")
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope, verifier=VERIFIER, expected_subject=wrong, at=_NOW
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.PRODUCT_MISMATCH


def test_reject_substitution_wrong_environment() -> None:
    envelope = _issued()
    subject = _matching_subject(envelope)
    wrong = replace(subject, environment="staging")
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope, verifier=VERIFIER, expected_subject=wrong, at=_NOW
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.ENVIRONMENT_MISMATCH


def test_reject_substitution_wrong_target() -> None:
    envelope = _issued()
    subject = _matching_subject(envelope)
    wrong = replace(subject, target_id="a-different-target-id")
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope, verifier=VERIFIER, expected_subject=wrong, at=_NOW
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.TARGET_MISMATCH


def test_reject_substitution_wrong_execution_sequence() -> None:
    """`rollout_ref`/`execution_sequence` are NOT a lease (Michael's ruling):
    Foundation's real lease is `HostLease.v2`, bound through
    `authorization_run_id` at execution time. This module compares its own
    rollout/attempt coordinate, and the refusal codes say exactly that."""
    envelope = _issued()
    subject = _matching_subject(envelope)
    wrong = replace(subject, execution_sequence=999)
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope, verifier=VERIFIER, expected_subject=wrong, at=_NOW
        )
    assert (
        caught.value.code
        is AuthorizationEnvelopeV3RefusalCode.EXECUTION_SEQUENCE_MISMATCH
    )


def test_reject_substitution_wrong_rollout() -> None:
    envelope = _issued()
    subject = _matching_subject(envelope)
    wrong_rollout = replace(subject, rollout_ref="a-different-rollout")
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope, verifier=VERIFIER, expected_subject=wrong_rollout, at=_NOW
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.ROLLOUT_MISMATCH


def test_reject_substitution_wrong_approval() -> None:
    envelope = _issued()
    subject = _matching_subject(envelope)
    wrong = replace(subject, approval_decision_ref="a-different-approval")
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope, verifier=VERIFIER, expected_subject=wrong, at=_NOW
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.APPROVAL_MISMATCH


def test_a_matching_subject_stays_silent() -> None:
    """Near-miss control kept permanently: the legitimately-matching case must
    never be refused, or every substitution test above would be meaningless."""
    envelope = _issued()
    verify_authorization_envelope_v3(
        envelope,
        verifier=VERIFIER,
        expected_subject=_matching_subject(envelope),
        at=_NOW,
    )


# ── Window discipline: outer expiry never outlives the evidence ────────────


def test_control_expiry_may_not_extend_past_the_evidence_valid_until() -> None:
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        issue_authorization_envelope_v3(
            _fields(expires_at=_NOW + timedelta(hours=2)),
            evidence_document=_evidence_document(
                valid_until=_NOW + timedelta(minutes=30)
            ),
            required_component_roster=_ROSTER,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
    assert (
        caught.value.code is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_WINDOW_EXCEEDED
    )


def test_control_expiry_inside_the_evidence_window_stays_silent() -> None:
    issue_authorization_envelope_v3(
        _fields(expires_at=_NOW + timedelta(minutes=10)),
        evidence_document=_evidence_document(valid_until=_NOW + timedelta(minutes=30)),
        required_component_roster=_ROSTER,
        evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
        signer=SIGNER,
    )


def test_evidence_evaluated_at_issued_at_is_admissible() -> None:
    envelope = issue_authorization_envelope_v3(
        _fields(),
        evidence_document=_evidence_document(evaluated_at=_NOW),
        required_component_roster=_ROSTER,
        evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
        signer=SIGNER,
    )
    verify_authorization_envelope_v3(
        envelope,
        verifier=VERIFIER,
        expected_subject=_matching_subject(envelope),
        at=_NOW,
    )


@pytest.mark.parametrize(
    "evaluated_at",
    [_NOW + timedelta(minutes=1), _NOW + timedelta(hours=2)],
    ids=["after-issued-at", "after-valid-until"],
)
def test_future_evidence_is_refused_at_issuance(evaluated_at: datetime) -> None:
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        issue_authorization_envelope_v3(
            _fields(),
            evidence_document=_evidence_document(evaluated_at=evaluated_at),
            required_component_roster=_ROSTER,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_FUTURE_DATED


def test_a_verification_instant_past_the_evidence_valid_until_is_refused() -> None:
    envelope = _issued()
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            at=_NOW + timedelta(hours=2),
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_EXPIRED


def test_control_expiry_before_the_evidence_boundary_is_distinct() -> None:
    envelope = _issued(expires_at=_NOW + timedelta(minutes=10))
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            at=_NOW + timedelta(minutes=15),
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.EXPIRED


def test_future_evidence_is_refused_before_authorization_not_yet_valid() -> None:
    envelope = _issued()
    with pytest.raises(AuthorizationEnvelopeV3RefusedError) as caught:
        verify_authorization_envelope_v3(
            envelope,
            verifier=VERIFIER,
            expected_subject=_matching_subject(envelope),
            at=_NOW - timedelta(minutes=2),
        )
    assert caught.value.code is AuthorizationEnvelopeV3RefusalCode.EVIDENCE_FUTURE_DATED


# ── control_plan_digest is derivable structurally: sanity over the whole statement ─


def test_control_plan_digest_excludes_exactly_self_reference() -> None:
    assert CONTROL_PLAN_DIGEST_EXCLUDED_FIELDS == {"control_plan_digest"}


def test_control_plan_digest_changes_for_each_non_excluded_field() -> None:
    envelope = _issued()
    mapping = envelope.statement.as_mapping()
    bound_fields = set(mapping) - CONTROL_PLAN_DIGEST_EXCLUDED_FIELDS
    assert bound_fields
    for field in bound_fields:
        mutated = dict(mapping)
        value = mutated[field]
        if isinstance(value, str):
            mutated[field] = value + "-changed"
        elif isinstance(value, int):
            mutated[field] = value + 1
        elif value is None:
            mutated[field] = "changed"
        elif isinstance(value, list):
            mutated[field] = list(reversed(value))
        else:
            raise AssertionError(
                f"unhandled serialized field type for {field}: {value!r}"
            )
        assert _compute_digest(mutated) != envelope.statement.control_plan_digest, field


def _compute_digest(mapping: dict[str, object]) -> str:
    from dotmac_deployment_control.digests import ControlPlanDigestV1, canonical_json

    return ControlPlanDigestV1.over_bytes(
        canonical_json(control_plan_digest_preimage(mapping))
    ).canonical


def test_reordered_signed_evidence_and_required_roster_normalize_identically() -> None:
    reordered_evidence = build_signed_health_evidence_document(
        evaluated_at=_NOW - timedelta(minutes=1),
        valid_until=_NOW + timedelta(hours=1),
        components=[build_component(code) for code in reversed(_ROSTER)],
        preserve_component_order=True,
    )
    assert parse_signed_health_evidence_document(
        reordered_evidence
    ).component_codes == tuple(reversed(_ROSTER))
    first = issue_authorization_envelope_v3(
        _fields(),
        evidence_document=reordered_evidence,
        required_component_roster=_ROSTER,
        evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
        signer=SIGNER,
    )
    second = issue_authorization_envelope_v3(
        _fields(),
        evidence_document=reordered_evidence,
        required_component_roster=tuple(reversed(_ROSTER)),
        evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
        signer=SIGNER,
    )
    assert first.statement.required_component_roster == _ROSTER
    assert second.statement.required_component_roster == _ROSTER
    assert first.statement.control_plan_digest == second.statement.control_plan_digest


def test_no_caller_supplied_control_plan_digest_is_ever_accepted() -> None:
    with pytest.raises(AuthorizationEnvelopeV3RefusedError):
        issue_authorization_envelope_v3(
            _fields(control_plan_digest="sha256:" + "aa" * 32),
            evidence_document=_evidence_document(),
            required_component_roster=_ROSTER,
            evidence_verifier=HEALTH_EVIDENCE_VERIFIER,
            signer=SIGNER,
        )
