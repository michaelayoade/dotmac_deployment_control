"""Authority to operate the protected, disposable rehearsal issuer.

`test_a_real_rehearsal_issuer_authorization_is_admitted` is the load-bearing
test: everything else here is a refusal, and a suite of refusals passes
trivially when construction is broken. It proves the refusals mean something.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import dotmac_deployment_control
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    REHEARSAL_ISSUER_PURPOSE,
    REHEARSAL_ONLY_ENVIRONMENT,
    A6ProvenanceKind,
    RehearsalIssuerAuthorizationRefusalCode,
    RehearsalIssuerAuthorizationRefusedError,
    RehearsalIssuerAuthorizationSignature,
    RehearsalIssuerAuthorizationSignerIdentity,
    RehearsalIssuerAuthorizationStanding,
    RehearsalIssuerAuthorizationStatementV1,
    RehearsalIssuerAuthorizationSubject,
    RehearsalIssuerAuthorizationV1,
    issue_rehearsal_issuer_authorization,
    rehearsal_issuer_standing,
    verify_rehearsal_issuer_authorization,
)

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
DESIRED_STATE_DIGEST = "sha256:" + "a" * 64
PROFILE_DIGEST = "sha256:" + "b" * 64
EXECUTION_PLAN_DIGEST = "sha256:" + "c" * 64
IMAGE_DIGEST = "sha256:" + "d" * 64
OTHER_IMAGE_DIGEST = "sha256:" + "e" * 64


class _Signer:
    def __init__(self, fingerprint: str = "fp-issuer") -> None:
        self._fingerprint = fingerprint

    @property
    def rehearsal_issuer_identity(self) -> RehearsalIssuerAuthorizationSignerIdentity:
        return RehearsalIssuerAuthorizationSignerIdentity(
            "k-issuer", "ed25519", self._fingerprint
        )

    def sign_rehearsal_issuer_authorization(
        self, canonical_bytes: bytes
    ) -> RehearsalIssuerAuthorizationSignature:
        assert canonical_bytes
        return RehearsalIssuerAuthorizationSignature(
            "k-issuer", "ed25519", REHEARSAL_ISSUER_PURPOSE, self._fingerprint, "SIG"
        )


class _Verifier:
    def verify_rehearsal_issuer_authorization(self, **kwargs: object) -> bool:
        return kwargs["signature"] == "SIG"


class _AlwaysFalseVerifier:
    def verify_rehearsal_issuer_authorization(self, **kwargs: object) -> bool:
        return False


def _statement(**overrides: object) -> RehearsalIssuerAuthorizationStatementV1:
    fields: dict[str, object] = {
        "authorization_id": "auth-1",
        "immutable_reference": "release-42",
        "target_id": "t-1",
        "target_ref": "lane3-rehearsal",
        "target_provenance": A6ProvenanceKind.DERIVED,
        "desired_state_digest": DESIRED_STATE_DIGEST,
        "desired_state_provenance": A6ProvenanceKind.DERIVED,
        "profile_digest": PROFILE_DIGEST,
        "profile_provenance": A6ProvenanceKind.DERIVED,
        "authorized_image_digests": (IMAGE_DIGEST,),
        "authorized_images_provenance": A6ProvenanceKind.DERIVED,
        "execution_plan_digest": EXECUTION_PLAN_DIGEST,
        "execution_plan_provenance": A6ProvenanceKind.DERIVED,
        "controller_fingerprint": "controller-1",
        "key_id": "k-issuer",
        "algorithm": "ed25519",
        "public_key_fingerprint": "fp-issuer",
        "lease_id": "lease-1",
        "single_use_reference": "rr-1",
        "environment": REHEARSAL_ONLY_ENVIRONMENT,
        "not_before": NOW - timedelta(minutes=5),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=2),
        "control_version": "0.1.0a14",
    }
    fields.update(overrides)
    return RehearsalIssuerAuthorizationStatementV1(**fields)  # type: ignore[arg-type]


def _envelope(*, signer: _Signer | None = None, **overrides: object) -> dict[str, Any]:
    return issue_rehearsal_issuer_authorization(
        _statement(**overrides), signer=signer or _Signer()
    ).as_mapping()


# ── the admitting case, first ────────────────────────────────────────────────


def test_a_real_rehearsal_issuer_authorization_is_admitted() -> None:
    statement = _statement()
    verified = verify_rehearsal_issuer_authorization(
        _envelope(), verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert verified.statement.authorization_id == "auth-1"
    assert verified.statement.purpose == REHEARSAL_ISSUER_PURPOSE
    standing = rehearsal_issuer_standing(
        _envelope(), verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert standing.standing is RehearsalIssuerAuthorizationStanding.VALID
    assert standing.authorizes is True


def test_round_trip_as_mapping_and_parse_are_equal() -> None:
    statement = _statement()
    mapping = statement.as_mapping()
    reparsed = RehearsalIssuerAuthorizationV1.parse(
        {"statement": mapping, "signature": "SIG"}
    ).statement
    assert reparsed == statement


def test_rehearsal_issuer_standing_is_absent_for_none() -> None:
    result = rehearsal_issuer_standing(
        None, verifier=_Verifier(), subject=_statement().subject, at=NOW
    )
    assert result.standing is RehearsalIssuerAuthorizationStanding.ABSENT
    assert result.authorizes is False


# ── schema / version / purpose, before any field-level comparison ───────────


def test_schema_mismatch_is_refused_before_any_field_is_compared() -> None:
    other = {
        "statement": {
            "schema": "dotmac.deployment_control.authorization",
            "version": 2,
        },
        "signature": "SIG",
    }
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            other, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.SCHEMA_MISMATCH


def test_version_mismatch_is_refused() -> None:
    envelope = _envelope()
    envelope["statement"]["version"] = 999
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            envelope, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.SCHEMA_MISMATCH


def test_purpose_mismatch_is_refused() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        _statement(purpose="deployment_authorization")
    assert (
        refused.value.code is RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH
    )


def _every_other_purpose_in_the_package() -> list[str]:
    """DERIVED, not hand-maintained: every public `*_PURPOSE` string constant
    the top-level package exports, other than this module's own.

    A hand-maintained list is exactly the "asserted, not provable" shape
    AGENTS.md's guard rule warns about — an independent review found the
    original static list here covered 5 of at least 7 real purposes and its
    own test name claimed exhaustiveness it didn't have. Scanning
    `dotmac_deployment_control.__all__` at test time means a future purpose
    is covered automatically, and this function's own sensitivity is
    provable: it necessarily finds at least one match (this module's import
    already put several `*_PURPOSE` constants into the package namespace),
    so it cannot be vacuously empty.
    """
    found = [
        name
        for name in dotmac_deployment_control.__all__
        if name.endswith("_PURPOSE")
        and getattr(dotmac_deployment_control, name) != REHEARSAL_ISSUER_PURPOSE
    ]
    assert found, "the scan itself found nothing — the guard would be vacuous"
    return [getattr(dotmac_deployment_control, name) for name in found]


def test_the_purpose_inventory_scan_is_not_vacuous() -> None:
    """SENSITIVITY for `_every_other_purpose_in_the_package` itself: it must
    name a real, non-trivial set, not just "some string"."""
    other_purposes = _every_other_purpose_in_the_package()
    assert len(other_purposes) >= 6, other_purposes
    assert REHEARSAL_ISSUER_PURPOSE not in other_purposes


@pytest.mark.parametrize("other_purpose", _every_other_purpose_in_the_package())
def test_every_other_purpose_in_the_package_is_refused(other_purpose: str) -> None:
    """Purpose separation. A signer/verifier bound to ANY other purpose this
    package exports — derived, not a hand-maintained list — must not satisfy
    this contract."""
    assert other_purpose != REHEARSAL_ISSUER_PURPOSE
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        RehearsalIssuerAuthorizationSignerIdentity("k", "ed25519", "fp", other_purpose)
    assert (
        refused.value.code is RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH
    )
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        _statement(purpose=other_purpose)
    assert (
        refused.value.code is RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH
    )


# ── the structural non-production guard ──────────────────────────────────────


@pytest.mark.parametrize(
    "value", ["production", "staging", "rehearsal-prod", "REHEARSAL", ""]
)
def test_not_a_rehearsal_environment_is_refused(value: str) -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        _statement(environment=value)
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.NOT_A_REHEARSAL_ENVIRONMENT
    )


def test_rehearsal_environment_itself_is_admitted() -> None:
    # SENSITIVITY, the near-miss half: the guard above only means something
    # because the one value it must accept still passes.
    _statement(environment=REHEARSAL_ONLY_ENVIRONMENT)


def test_a_subject_naming_a_non_rehearsal_environment_is_refused_at_verification() -> (
    None
):
    statement = _statement()
    bad_subject = RehearsalIssuerAuthorizationSubject(
        immutable_reference=statement.immutable_reference,
        target_id=statement.target_id,
        target_ref=statement.target_ref,
        desired_state_digest=statement.desired_state_digest,
        profile_digest=statement.profile_digest,
        authorized_image_digests=statement.authorized_image_digests,
        execution_plan_digest=statement.execution_plan_digest,
        controller_fingerprint=statement.controller_fingerprint,
        environment="production",
        signer_public_key_fingerprint=statement.public_key_fingerprint,
        lease_id=statement.lease_id,
    )
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=bad_subject, at=NOW
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.NOT_A_REHEARSAL_ENVIRONMENT
    )


# ── the seven named subject mismatches, each independent ────────────────────


def _subject_from(statement: RehearsalIssuerAuthorizationStatementV1) -> Any:
    return statement.subject


def test_candidate_mismatch_only() -> None:
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, immutable_reference="release-99")
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert (
        refused.value.code is RehearsalIssuerAuthorizationRefusalCode.CANDIDATE_MISMATCH
    )


def test_signer_mismatch_only() -> None:
    subject = _subject_from(_statement())
    other = dataclasses.replace(
        subject, signer_public_key_fingerprint="fp-someone-else"
    )
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.SIGNER_MISMATCH


def test_target_mismatch_only() -> None:
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, target_id="t-other")
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.TARGET_MISMATCH


def test_profile_mismatch_only() -> None:
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, profile_digest="sha256:" + "f" * 64)
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert (
        refused.value.code is RehearsalIssuerAuthorizationRefusalCode.PROFILE_MISMATCH
    )


def test_image_mismatch_only() -> None:
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, authorized_image_digests=(OTHER_IMAGE_DIGEST,))
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.IMAGE_MISMATCH


def test_execution_plan_mismatch_only() -> None:
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, execution_plan_digest="sha256:" + "9" * 64)
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.EXECUTION_PLAN_MISMATCH
    )


def test_controller_mismatch_only() -> None:
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, controller_fingerprint="controller-other")
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.CONTROLLER_MISMATCH
    )


def test_desired_state_mismatch_only() -> None:
    """Added under the "one code per binding" rule; see the module docstring."""
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, desired_state_digest="sha256:" + "9" * 64)
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.DESIRED_STATE_MISMATCH
    )


def test_lease_mismatch_only() -> None:
    """Added under the "one code per binding" rule after independent review
    found `lease_id` signed into the statement and never compared: this
    contract's whole stated scope is authority "for one bounded lease", so a
    presented lease that disagrees with the authorized one must refuse."""
    subject = _subject_from(_statement())
    other = dataclasses.replace(subject, lease_id="lease-other")
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(), verifier=_Verifier(), subject=other, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.LEASE_MISMATCH


def test_matching_subject_is_admitted() -> None:
    # SENSITIVITY, the near-miss half for every mismatch test above,
    # including `lease_id` — `.subject` carries the statement's own
    # `lease_id`, so a genuinely matching subject (this one) must still pass.
    subject = _statement().subject
    assert subject.lease_id == "lease-1"
    verify_rehearsal_issuer_authorization(
        _envelope(), verifier=_Verifier(), subject=subject, at=NOW
    )


# ── provenance ────────────────────────────────────────────────────────────


def test_derived_with_no_reason_succeeds() -> None:
    _statement(target_provenance=A6ProvenanceKind.DERIVED, target_override_reason=None)


def test_override_with_missing_reason_is_refused() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        _statement(
            target_provenance=A6ProvenanceKind.OVERRIDE, target_override_reason=None
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.PROVENANCE_MALFORMED
    )


def test_override_with_empty_reason_is_refused() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        _statement(
            target_provenance=A6ProvenanceKind.OVERRIDE, target_override_reason="   "
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.PROVENANCE_MALFORMED
    )


def test_override_with_a_reason_succeeds_and_round_trips() -> None:
    statement = _statement(
        target_provenance=A6ProvenanceKind.OVERRIDE,
        target_override_reason="operator hand-picked target for this rehearsal",
    )
    mapping = statement.as_mapping()
    assert (
        mapping["target_override_reason"]
        == "operator hand-picked target for this rehearsal"
    )
    reparsed = RehearsalIssuerAuthorizationV1.parse(
        {"statement": mapping, "signature": "SIG"}
    ).statement
    assert reparsed.target_override_reason == statement.target_override_reason
    assert reparsed.target_provenance is A6ProvenanceKind.OVERRIDE


def test_derived_with_a_reason_present_is_refused() -> None:
    """A reason with nothing to explain is itself a defect."""
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        _statement(
            target_provenance=A6ProvenanceKind.DERIVED,
            target_override_reason="unnecessary",
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.PROVENANCE_MALFORMED
    )


# ── window ────────────────────────────────────────────────────────────────


def test_not_yet_valid() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW - timedelta(minutes=10),
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.NOT_YET_VALID


def test_expired() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW + timedelta(hours=3),
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.EXPIRED


# ── revocation and replay ────────────────────────────────────────────────


def test_revoked() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
            revoked_authorization_ids=frozenset({"auth-1"}),
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.REVOKED


def test_already_consumed() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
            consumed_references=frozenset({"rr-1"}),
        )
    assert (
        refused.value.code is RehearsalIssuerAuthorizationRefusalCode.ALREADY_CONSUMED
    )


# ── exact key-set enforcement ─────────────────────────────────────────────


def test_missing_key_is_refused_as_malformed() -> None:
    envelope = _envelope()
    del envelope["statement"]["lease_id"]
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            envelope, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.MALFORMED


def test_unexpected_key_is_refused_as_malformed() -> None:
    envelope = _envelope()
    envelope["statement"]["unexpected_field"] = "surprise"
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            envelope, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.MALFORMED


# ── signature ─────────────────────────────────────────────────────────────


def test_unsigned_is_refused() -> None:
    envelope = _envelope()
    envelope["signature"] = ""
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            envelope, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalIssuerAuthorizationRefusalCode.UNSIGNED


def test_signature_invalid_is_refused() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        verify_rehearsal_issuer_authorization(
            _envelope(),
            verifier=_AlwaysFalseVerifier(),
            subject=_statement().subject,
            at=NOW,
        )
    assert (
        refused.value.code is RehearsalIssuerAuthorizationRefusalCode.SIGNATURE_INVALID
    )


def test_issuance_refuses_a_statement_naming_a_different_key_than_the_signer() -> None:
    with pytest.raises(RehearsalIssuerAuthorizationRefusedError) as refused:
        issue_rehearsal_issuer_authorization(
            _statement(), signer=_Signer(fingerprint="fp-not-the-statements")
        )
    assert (
        refused.value.code
        is RehearsalIssuerAuthorizationRefusalCode.SIGNER_PURPOSE_REUSED
    )
