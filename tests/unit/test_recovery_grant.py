"""Recovery is authorized by its own grant, and by nothing else.

The load-bearing test here is `test_a_real_recovery_grant_is_admitted`. Every
other test is a refusal, and a suite of refusals passes trivially when
construction is broken -- the admitting case is what proves the refusals mean
something rather than that nothing can be built at all.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from dotmac_deployment_control.authorization import (
    AuthorizationEnvelopeRefusedError,
    verify_authorization_envelope,
)
from dotmac_deployment_control.recovery_grant import (
    RECOVERY_PURPOSE,
    RecoveryGrantRefusalCode,
    RecoveryGrantRefusedError,
    RecoveryGrantSignature,
    RecoveryGrantSignerIdentity,
    RecoveryGrantStatementV1,
    RecoveryStanding,
    issue_recovery_grant,
    recovery_standing,
    verify_recovery_grant,
)

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


class _Signer:
    @property
    def recovery_identity(self) -> RecoveryGrantSignerIdentity:
        return RecoveryGrantSignerIdentity("k-rec", "ed25519", "fp-rec")

    def sign_recovery(self, canonical_bytes: bytes) -> RecoveryGrantSignature:
        assert canonical_bytes
        return RecoveryGrantSignature(
            "k-rec", "ed25519", RECOVERY_PURPOSE, "fp-rec", "SIG"
        )


class _Verifier:
    def verify_recovery(self, **kwargs: object) -> bool:
        return kwargs["signature"] == "SIG"


def _statement(**overrides: object) -> RecoveryGrantStatementV1:
    fields: dict[str, object] = {
        "grant_id": "g-1",
        "product_code": "platform-cp",
        "target_id": "t-1",
        "target_ref": "vendor-cp-prod",
        "environment": "production",
        "recovery_execution_plan_digest": "sha256:" + "a" * 64,
        "recovery_bundle_digest": "sha256:" + "b" * 64,
        "incumbent_prestate_digest": "sha256:" + "c" * 64,
        "approval_policy_code": "recovery.standard",
        "approval_policy_version": 1,
        "approval_decision_ref": "dec-1",
        "approval_decision_status": "granted",
        "approved_at": NOW - timedelta(hours=1),
        "not_before": NOW - timedelta(minutes=5),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=2),
        "control_version": "0.1.0a12",
        "key_id": "k-rec",
        "algorithm": "ed25519",
        "public_key_fingerprint": "fp-rec",
    }
    fields.update(overrides)
    return RecoveryGrantStatementV1(**fields)  # type: ignore[arg-type]


def _grant(**overrides: object) -> dict[str, object]:
    return issue_recovery_grant(_statement(**overrides), signer=_Signer()).as_mapping()


# ── the admitting case, first, because everything else depends on it ────────


def test_a_real_recovery_grant_is_admitted() -> None:
    """NON-VACUITY. A suite of refusals proves nothing if nothing can be built."""
    statement = _statement()
    verified = verify_recovery_grant(
        _grant(), verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert verified.statement.grant_id == "g-1"
    assert verified.statement.purpose == RECOVERY_PURPOSE
    standing = recovery_standing(
        _grant(), verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert standing.standing is RecoveryStanding.VALID
    assert standing.authorizes is True


def test_the_grant_carries_no_operation_field() -> None:
    """The TYPE identifies the act. An `operation` here would do two jobs, and
    the second -- self-identification -- is what `schema` owns instead."""
    mapping = _grant()
    assert "operation" not in mapping["statement"]  # type: ignore[operator]
    assert mapping["statement"]["schema"].endswith("recovery_grant")  # type: ignore[index]


# ── neither grant can be the other, both directions ─────────────────────────


def test_a_deployment_authorization_cannot_authorize_a_recovery() -> None:
    """Substituted, not annotated. A deployment envelope is a different
    document and is refused before a single field is compared."""
    deployment = {
        "statement": {
            "schema": "dotmac.deployment_control.authorization",
            "version": 2,
            "operation": "recover",
            "target_id": "t-1",
        },
        "signature": "SIG",
    }
    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(
            deployment,
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
        )
    assert refused.value.code is RecoveryGrantRefusalCode.SCHEMA_MISMATCH


def test_a_recovery_grant_cannot_authorize_a_deployment_or_rollback() -> None:
    """The other direction, through the real deployment verifier."""

    class _AnyVerifier:
        def verify(self, **kwargs: object) -> bool:
            return True

    with pytest.raises(AuthorizationEnvelopeRefusedError):
        verify_authorization_envelope(_grant(), verifier=_AnyVerifier(), at=NOW)


# ── every bound term refuses on its own, by comparison not by presence ──────


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("product_code", RecoveryGrantRefusalCode.PRODUCT_MISMATCH),
        ("target_id", RecoveryGrantRefusalCode.TARGET_MISMATCH),
        ("target_ref", RecoveryGrantRefusalCode.TARGET_MISMATCH),
        ("environment", RecoveryGrantRefusalCode.ENVIRONMENT_MISMATCH),
        (
            "recovery_execution_plan_digest",
            RecoveryGrantRefusalCode.RECOVERY_PLAN_MISMATCH,
        ),
        ("recovery_bundle_digest", RecoveryGrantRefusalCode.BUNDLE_MISMATCH),
        ("incumbent_prestate_digest", RecoveryGrantRefusalCode.PRESTATE_MISMATCH),
    ],
)
def test_a_changed_subject_term_refuses_with_its_own_code(
    field: str, code: RecoveryGrantRefusalCode
) -> None:
    """The grant carries the term; that is not the same as the term matching."""
    asked = dataclasses.replace(_statement().subject, **{field: "SOMETHING-ELSE"})
    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(_grant(), verifier=_Verifier(), subject=asked, at=NOW)
    assert refused.value.code is code


def test_a_changed_signature_refuses_before_any_term_is_compared() -> None:
    """Authenticity first: a forged document never earns field-level
    diagnostics about what it would have had to say."""
    forged = _grant()
    forged["signature"] = "NOT-THE-SIGNATURE"
    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(
            forged,
            verifier=_Verifier(),
            subject=dataclasses.replace(_statement().subject, target_id="ELSE"),
            at=NOW,
        )
    assert refused.value.code is RecoveryGrantRefusalCode.SIGNATURE_INVALID


# ── revoked, expired and unresolved are four different answers ──────────────


def test_absent_revoked_expired_and_unresolved_are_distinguishable() -> None:
    """An operator reading "unavailable" needs to know WHICH, because those are
    four different next actions."""
    subject = _statement().subject
    verifier = _Verifier()

    assert (
        recovery_standing(None, verifier=verifier, subject=subject, at=NOW).standing
        is RecoveryStanding.ABSENT
    )
    assert (
        recovery_standing(
            _grant(), verifier=verifier, subject=subject, at=NOW + timedelta(hours=3)
        ).standing
        is RecoveryStanding.EXPIRED
    )
    assert (
        recovery_standing(
            _grant(), verifier=verifier, subject=subject, at=NOW - timedelta(hours=1)
        ).standing
        is RecoveryStanding.NOT_YET_VALID
    )
    assert (
        recovery_standing(
            _grant(),
            verifier=verifier,
            subject=subject,
            at=NOW,
            revoked_grant_ids=frozenset({"g-1"}),
        ).standing
        is RecoveryStanding.REVOKED
    )
    unresolved = recovery_standing(
        _grant(),
        verifier=verifier,
        subject=dataclasses.replace(
            subject, recovery_bundle_digest="sha256:" + "f" * 64
        ),
        at=NOW,
    )
    assert unresolved.standing is RecoveryStanding.UNRESOLVED
    assert unresolved.refusal is RecoveryGrantRefusalCode.BUNDLE_MISMATCH
    assert unresolved.authorizes is False


def test_a_recovery_may_not_be_approval_exempt() -> None:
    """Deployment authorizations accept `approval_exempt`; a recovery does not.

    An exempt recovery is a destructive act with no approval evidence, and
    approval evidence is one of the things this grant exists to bind.
    """
    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(
            _grant(approval_decision_status="approval_exempt"),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
        )
    assert refused.value.code is RecoveryGrantRefusalCode.APPROVAL_NOT_STANDING


# ── the seam carries typed, canonical data ──────────────────────────────────


def test_the_signed_document_survives_the_seam_as_canonical_bytes() -> None:
    """Nested signed evidence must reach the verifier as the object the
    signature covers, never a restatement of it."""
    statement = _statement()
    grant = issue_recovery_grant(statement, signer=_Signer())
    round_tripped = verify_recovery_grant(
        grant.as_mapping(), verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert round_tripped.statement.canonical_bytes() == statement.canonical_bytes()
    assert isinstance(grant.as_mapping()["statement"], dict)


def test_a_signer_of_another_purpose_cannot_sign_a_recovery() -> None:
    with pytest.raises(RecoveryGrantRefusedError) as refused:
        RecoveryGrantSignerIdentity(
            "k", "ed25519", "fp", purpose="deployment_authorization"
        )
    assert refused.value.code is RecoveryGrantRefusalCode.PURPOSE_MISMATCH


# ── a recovery failure can never be reported as a deployment fault ──────────


def test_recovery_refusals_are_not_deployment_refusals_in_either_direction() -> None:
    """The same decision `OperationNotExecutableError` needed, generalised.

    `service.py`, `web.py`, `dispatch_envelope.py` and
    `execution_observation.py` all carry broad `except DeploymentControlError`
    handlers, and several narrower `except OperationRefusedError` ones that turn
    an unparsable word into a typed disposition. If a recovery refusal
    subclassed any deployment refusal, one of those would silently downgrade
    "this grant does not authorize this recovery" into "that operation is not a
    word" -- two facts with nothing in common and very different next actions.

    Asserted in BOTH directions, because a later refactor could invert the
    hierarchy just as easily as extend it.
    """
    from dotmac_deployment_control.dispatch_envelope import (
        DispatchEnvelopeRefusedError,
    )
    from dotmac_deployment_control.ports import (
        DeploymentControlError,
        OperationNotExecutableError,
        OperationRefusedError,
    )

    deployment_refusals = (
        OperationRefusedError,
        OperationNotExecutableError,
        AuthorizationEnvelopeRefusedError,
        DispatchEnvelopeRefusedError,
    )
    for other in deployment_refusals:
        assert not issubclass(RecoveryGrantRefusedError, other), other.__name__
        assert not issubclass(other, RecoveryGrantRefusedError), other.__name__

    # They share only the root every refusal in this package shares, which is
    # what keeps a caller able to catch "this command was refused" at all.
    assert issubclass(RecoveryGrantRefusedError, DeploymentControlError)


def test_catching_an_operation_refusal_does_not_catch_a_recovery_refusal() -> None:
    """The non-inheritance, exercised rather than only asserted structurally."""
    from dotmac_deployment_control.ports import OperationRefusedError

    with pytest.raises(RecoveryGrantRefusedError):
        try:
            verify_recovery_grant(
                _grant(),
                verifier=_Verifier(),
                subject=dataclasses.replace(_statement().subject, target_id="ELSE"),
                at=NOW,
            )
        except OperationRefusedError as swallowed:  # pragma: no cover - must not run
            raise AssertionError(
                "a recovery refusal was caught as an operation refusal"
            ) from swallowed
