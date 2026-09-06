"""A rehearsal is authorized by its own grant, and its subject is a REFUSAL.

The load-bearing test here is `test_a_real_rehearsal_grant_is_admitted`. Almost
every other test is a refusal, and a suite of refusals passes trivially when
construction is broken — the admitting case is what proves the refusals mean
something rather than that nothing can be built at all.

Two of these tests are about the DESIGN rather than a field, and they are the
ones to read first:

* `test_no_rehearse_member_was_added_to_either_operations_vocabulary` — the
  Foundation withdrew `recover` from `OPERATIONS` and recorded the reversal
  precisely so this mistake would not be made a second time under a new name.
* `test_a_grant_cannot_carry_an_outcome_that_contradicts_its_provocation` — the
  property that separates this from a boolean. A deployment authorization
  permits an act that may succeed; this authorizes an act that must refuse, and
  a document saying otherwise authorizes neither.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from dotmac_deployment_control.authorization import (
    AuthorizationEnvelopeRefusedError,
    verify_authorization_envelope,
)
from dotmac_deployment_control.counterparty import EXECUTOR_OPERATIONS
from dotmac_deployment_control.digests import (
    ExecutionPlanDigestV1,
    FoundationArtifactDigestV1,
)
from dotmac_deployment_control.operations import (
    OPERATIONS,
    DeploymentOperation,
    require_operation,
)
from dotmac_deployment_control.ports import DigestEncodingError, OperationRefusedError
from dotmac_deployment_control.recovery_grant import (
    RecoveryGrantRefusalCode,
    RecoveryGrantRefusedError,
    RecoverySubject,
    verify_recovery_grant,
)
from dotmac_deployment_control.rehearsal_grant import (
    FOUNDATION_STEP_KINDS,
    REHEARSAL_GRANT_SCHEMA,
    REHEARSAL_PURPOSE,
    AuthorizedProvocationV1,
    CandidateArtifactRef,
    ProvocableRefusal,
    ProvokedTerminal,
    RehearsalGrantRefusalCode,
    RehearsalGrantRefusedError,
    RehearsalGrantSignature,
    RehearsalGrantSignerIdentity,
    RehearsalGrantStatementV1,
    RehearsalStanding,
    foundation_step_vocabulary_drift,
    issue_rehearsal_grant,
    rehearsal_standing,
    verify_rehearsal_grant,
)

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
PLAN_DIGEST = "sha256:" + "a" * 64
#: Stands in for the digest of the Foundation WHEEL FILE
#: (`FoundationArtifactDigestV1`'s subject) — the value this module receives,
#: binds and compares, never computes.
FOUNDATION_ARTIFACT_DIGEST = "sha256:" + "d" * 64


class _Signer:
    @property
    def rehearsal_identity(self) -> RehearsalGrantSignerIdentity:
        return RehearsalGrantSignerIdentity("k-reh", "ed25519", "fp-reh")

    def sign_rehearsal(self, canonical_bytes: bytes) -> RehearsalGrantSignature:
        assert canonical_bytes
        return RehearsalGrantSignature(
            "k-reh", "ed25519", REHEARSAL_PURPOSE, "fp-reh", "SIG"
        )


class _Verifier:
    def verify_rehearsal(self, **kwargs: object) -> bool:
        return kwargs["signature"] == "SIG"


def _statement(**overrides: object) -> RehearsalGrantStatementV1:
    fields: dict[str, object] = {
        "grant_id": "g-1",
        "single_use_reference": "rr-1",
        "product_code": "platform-cp",
        "target_id": "t-1",
        "target_ref": "lane3-rehearsal",
        "environment": "rehearsal",
        "candidate_repository": "michaelayoade/dotmac_starter_mt",
        "candidate_run_id": "33780438726",
        "candidate_artifact_id": "9903418260",
        "candidate_foundation_artifact_digest": FOUNDATION_ARTIFACT_DIGEST,
        "execution_plan_digest": PLAN_DIGEST,
        "provocation_refusal": ProvocableRefusal.PLAN_VERIFICATION_REFUSAL,
        "provocation_at_step": "gate_candidate",
        "lease_id": "lease-1",
        "approval_policy_code": "rehearsal.standard",
        "approval_policy_version": 1,
        "approval_decision_ref": "dec-1",
        "approval_decision_status": "granted",
        "approved_at": NOW - timedelta(hours=1),
        "not_before": NOW - timedelta(minutes=5),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=2),
        "control_version": "0.1.0a12",
        "key_id": "k-reh",
        "algorithm": "ed25519",
        "public_key_fingerprint": "fp-reh",
    }
    fields.update(overrides)
    return RehearsalGrantStatementV1(**fields)  # type: ignore[arg-type]


def _grant(**overrides: object) -> dict[str, Any]:
    return issue_rehearsal_grant(_statement(**overrides), signer=_Signer()).as_mapping()


# ── the admitting case, first, because everything else depends on it ────────


def test_a_real_rehearsal_grant_is_admitted() -> None:
    """NON-VACUITY. A suite of refusals proves nothing if nothing can be built."""
    statement = _statement()
    verified = verify_rehearsal_grant(
        _grant(), verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert verified.statement.grant_id == "g-1"
    assert verified.statement.purpose == REHEARSAL_PURPOSE
    assert verified.statement.single_use_reference == "rr-1"
    standing = rehearsal_standing(
        _grant(), verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert standing.standing is RehearsalStanding.VALID
    assert standing.authorizes is True


# ── the design, not a field ─────────────────────────────────────────────────


def test_no_rehearse_member_was_added_to_either_operations_vocabulary() -> None:
    """The precedent this whole module exists to obey.

    The Foundation added `recover` to `OPERATIONS` and withdrew it one commit
    later, recording that *"an executor existing is not the test; an executor
    for THE NAMED ACT is."* A `rehearse` member here would name an act in the
    DEPLOYMENT vocabulary and thereby reach the deployment executor, the
    deployment receipt shape and an operation-agnostic settlement — all built
    for an act that is supposed to succeed.
    """
    for word in ("rehearse", "rehearsal", "provoke"):
        assert word not in OPERATIONS
        assert word not in EXECUTOR_OPERATIONS
        with pytest.raises(OperationRefusedError):
            require_operation(word, where="test")
    assert {member.value for member in DeploymentOperation} == {
        "deploy",
        "rollback",
        "recover",
    }


def test_the_grant_carries_no_operation_field() -> None:
    """The TYPE identifies the act, exactly as it does for a recovery grant."""
    mapping = _grant()
    statement = mapping["statement"]
    assert "operation" not in statement
    assert statement["schema"] == REHEARSAL_GRANT_SCHEMA
    assert statement["schema"].endswith("rehearsal_grant")


def test_a_grant_cannot_exist_without_naming_which_refusal_and_where() -> None:
    """Required and undefaulted, so there is no `authorized_provocation`-less shape.

    Checked in both places it could be got round: the dataclass has no default
    for either term, and the parser refuses a document that omits them.
    """
    defaults = {
        field.name: field.default
        for field in dataclasses.fields(RehearsalGrantStatementV1)
    }
    assert defaults["provocation_refusal"] is dataclasses.MISSING
    assert defaults["provocation_at_step"] is dataclasses.MISSING

    for missing in ("provocation_refusal", "provocation_at_step"):
        envelope = _grant()
        del envelope["statement"][missing]
        with pytest.raises(RehearsalGrantRefusedError) as refused:
            verify_rehearsal_grant(
                envelope,
                verifier=_Verifier(),
                subject=_statement().subject,
                at=NOW,
            )
        assert refused.value.code in {
            RehearsalGrantRefusalCode.MALFORMED,
            RehearsalGrantRefusalCode.PROVOCATION_UNKNOWN,
        }


def test_a_grant_cannot_carry_an_outcome_that_contradicts_its_provocation() -> None:
    """THE ANTI-BOOLEAN PROPERTY, and the reason this is not a flag on a deploy.

    A deployment authorization permits an act that MAY succeed. This authorizes
    an act that must END IN A REFUSAL, and the terminal is derived from the
    refusal rather than declared beside it — so a document claiming the
    rehearsal may simply succeed is refused rather than believed.
    """
    provocation = AuthorizedProvocationV1(
        refusal=ProvocableRefusal.PLAN_VERIFICATION_REFUSAL, at_step="gate_candidate"
    )
    assert provocation.expected_terminal is ProvokedTerminal.ROLLED_BACK

    envelope = _grant()
    assert envelope["statement"]["expected_terminal"] == "rolled_back"
    # PLANT THE DEFECT: a grant that says the provoked act may just succeed.
    envelope["statement"]["expected_terminal"] = "succeeded"
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            envelope, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalGrantRefusalCode.PROVOCATION_MISMATCH


def test_the_derived_terminal_is_not_a_check_that_passes_over_anything() -> None:
    """SENSITIVITY, the near-miss half. The correct terminal is admitted.

    A guard that refuses every value is not a guard about terminals; the
    planted case above only means something because this one passes.
    """
    envelope = _grant()
    envelope["statement"]["expected_terminal"] = "rolled_back"
    verify_rehearsal_grant(
        envelope, verifier=_Verifier(), subject=_statement().subject, at=NOW
    )
    assert set(ProvokedTerminal) == {ProvokedTerminal.ROLLED_BACK}


# ── no document can be another document, in every direction ─────────────────


def test_a_deployment_authorization_cannot_authorize_a_rehearsal() -> None:
    """Substituted, not annotated. Refused before a single field is compared."""
    deployment = {
        "statement": {
            "schema": "dotmac.deployment_control.authorization",
            "version": 2,
            "operation": "deploy",
            "target_id": "t-1",
        },
        "signature": "SIG",
    }
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            deployment, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalGrantRefusalCode.SCHEMA_MISMATCH


def test_a_rehearsal_grant_cannot_authorize_a_deployment_or_rollback() -> None:
    """The other direction, through the real deployment verifier.

    This is the finding that produced the module, inverted into a test: the
    only authorization Lane 3 could previously obtain was a `deploy`, so a
    production deployment would have been authorized for an act whose entire
    purpose is to fail.
    """

    class _AnyVerifier:
        def verify(self, **kwargs: object) -> bool:
            return True

    with pytest.raises(AuthorizationEnvelopeRefusedError):
        verify_authorization_envelope(_grant(), verifier=_AnyVerifier(), at=NOW)


def test_a_rehearsal_grant_cannot_authorize_a_recovery() -> None:
    """Three grant types, and none of them satisfies another's verifier."""

    class _AnyRecoveryVerifier:
        def verify_recovery(self, **kwargs: object) -> bool:
            return True

    with pytest.raises(RecoveryGrantRefusedError) as refused:
        verify_recovery_grant(
            _grant(),
            verifier=_AnyRecoveryVerifier(),
            subject=RecoverySubject(
                product_code="platform-cp",
                target_id="t-1",
                target_ref="lane3-rehearsal",
                environment="rehearsal",
                recovery_execution_plan_digest=PLAN_DIGEST,
                recovery_bundle_digest="sha256:" + "b" * 64,
                incumbent_prestate_digest="sha256:" + "c" * 64,
                incumbent_prestate_discriminator="x",
            ),
            at=NOW,
        )
    assert refused.value.code is RecoveryGrantRefusalCode.SCHEMA_MISMATCH


# ── the provocation vocabulary is closed, in both halves ────────────────────


def test_a_step_the_executor_does_not_publish_is_refused() -> None:
    """PLANT THE DEFECT: a provocation at a place nothing performs."""
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        AuthorizedProvocationV1(
            refusal=ProvocableRefusal.PLAN_VERIFICATION_REFUSAL,
            at_step="delete_everything",
        )
    assert refused.value.code is RehearsalGrantRefusalCode.PROVOCATION_UNKNOWN


@pytest.mark.parametrize("step", sorted(FOUNDATION_STEP_KINDS))
def test_every_published_step_is_admitted_as_a_place(step: str) -> None:
    """SENSITIVITY, the near-miss half. The closure refuses the unpublished
    word and admits every published one — not everything."""
    provocation = AuthorizedProvocationV1(
        refusal=ProvocableRefusal.PLAN_VERIFICATION_REFUSAL, at_step=step
    )
    assert provocation.at_step == step


@pytest.mark.parametrize("step", ["apply_exposure", "restore_exposure"])
def test_a_grant_naming_the_exposure_steps_is_admitted_end_to_end(step: str) -> None:
    """THE ADMIT CONTROL for the vocabulary repair. Read this one first.

    Before this repair, `FOUNDATION_STEP_KINDS` had 25 members and neither
    `apply_exposure` nor `restore_exposure` — the exact steps Foundation added
    at `6147618a918b8a56a39af022b5c3a3657e8a2c88` for reconciling a target's
    declared exposure under the lock. `AuthorizedProvocationV1.__post_init__`
    would have raised `PROVOCATION_UNKNOWN` for either one, which means a
    grant naming the one provocation this module exists for — Lane 3 item 8,
    at the step where exposure is reconciled — could not have been
    CONSTRUCTED, let alone issued or verified. This is not a refusal test:
    every other test in this file could pass while this one fails, and that
    was precisely the bug. It runs the full lifecycle — statement, signature,
    verification, standing — because a value object admitting the string is
    not the same claim as a grant being issuable and verifiable end to end.
    """
    statement = _statement(provocation_at_step=step)
    envelope = issue_rehearsal_grant(statement, signer=_Signer()).as_mapping()
    verified = verify_rehearsal_grant(
        envelope, verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert verified.statement.provocation_at_step == step
    standing = rehearsal_standing(
        envelope, verifier=_Verifier(), subject=statement.subject, at=NOW
    )
    assert standing.standing is RehearsalStanding.VALID
    assert standing.authorizes is True


def test_an_unknown_or_differently_cased_refusal_word_is_refused() -> None:
    """`operations.py`'s argument, applied to the refusal vocabulary.

    A case fold would give one act two identities, and the act here is which
    refusal a rehearsal is allowed to cause.
    """
    for word in ("PLAN_VERIFICATION_REFUSAL", "anything_at_all"):
        with pytest.raises(RehearsalGrantRefusedError) as refused:
            _statement(provocation_refusal=word)
        assert refused.value.code is RehearsalGrantRefusalCode.PROVOCATION_UNKNOWN
    # NEAR MISS: the exact member, as text, is accepted.
    assert (
        _statement(provocation_refusal="plan_verification_refusal").provocation_refusal
        is ProvocableRefusal.PLAN_VERIFICATION_REFUSAL
    )


def test_the_same_refusal_at_another_step_is_a_different_act() -> None:
    """The `where` half of the binding, biting on its own.

    A grant for one refusal at one step is not a grant for that refusal
    somewhere else — the target's exposure at `gate_candidate` and at `switch`
    are not the same thing to break.
    """
    asked = dataclasses.replace(
        _statement().subject,
        provocation=AuthorizedProvocationV1(
            refusal=ProvocableRefusal.PLAN_VERIFICATION_REFUSAL, at_step="switch"
        ),
    )
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(_grant(), verifier=_Verifier(), subject=asked, at=NOW)
    assert refused.value.code is RehearsalGrantRefusalCode.PROVOCATION_MISMATCH


# ── every bound term refuses on its own, by comparison not by presence ──────


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("product_code", RehearsalGrantRefusalCode.PRODUCT_MISMATCH),
        ("target_id", RehearsalGrantRefusalCode.TARGET_MISMATCH),
        ("target_ref", RehearsalGrantRefusalCode.TARGET_MISMATCH),
        ("environment", RehearsalGrantRefusalCode.ENVIRONMENT_MISMATCH),
        ("execution_plan_digest", RehearsalGrantRefusalCode.EXECUTION_PLAN_MISMATCH),
    ],
)
def test_a_changed_subject_term_refuses_with_its_own_code(
    field: str, code: RehearsalGrantRefusalCode
) -> None:
    """The grant carries the term; that is not the same as the term matching.

    `target` is the reason this matters most here: a staging rehearsal must not
    authorize production, and the only thing standing between the two is this
    comparison.
    """
    replacement = "sha256:" + "f" * 64 if field.endswith("digest") else "SOMETHING-ELSE"
    asked = dataclasses.replace(_statement().subject, **{field: replacement})
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(_grant(), verifier=_Verifier(), subject=asked, at=NOW)
    assert refused.value.code is code


@pytest.mark.parametrize(
    ("part", "replacement"),
    [
        ("repository", "SOMETHING-ELSE"),
        ("run_id", "SOMETHING-ELSE"),
        ("artifact_id", "SOMETHING-ELSE"),
        ("foundation_artifact_digest", "sha256:" + "e" * 64),
    ],
)
def test_a_rehearsal_of_other_bytes_is_refused(part: str, replacement: str) -> None:
    """The candidate is bound by run AND artifact id AND repository AND digest.

    An artifact id is unique only within the repository that produced it, so
    all three locating fields are the identity rather than two of them plus
    context — and the digest is a FOURTH independent term: two runs that
    happen to share a location are not the same bytes, so a grant issued for
    one run's digest must refuse a rehearsal that presents another, even at
    the identical (repository, run_id, artifact_id).
    """
    asked = dataclasses.replace(
        _statement().subject,
        candidate=dataclasses.replace(_statement().candidate, **{part: replacement}),
    )
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(_grant(), verifier=_Verifier(), subject=asked, at=NOW)
    assert refused.value.code is RehearsalGrantRefusalCode.CANDIDATE_MISMATCH


def test_the_candidate_reference_is_admitted_when_all_four_agree() -> None:
    """SENSITIVITY, the near-miss half of the four refusals above.

    NON-VACUITY for the digest term specifically: this is the case that would
    stay silent if `foundation_artifact_digest` were carried on the type but
    never actually compared — the field would be present either way, and only
    an admitted rehearsal proves the comparison ran and agreed rather than
    having been skipped.
    """
    asked = dataclasses.replace(
        _statement().subject,
        candidate=CandidateArtifactRef(
            repository="michaelayoade/dotmac_starter_mt",
            run_id="33780438726",
            artifact_id="9903418260",
            foundation_artifact_digest=FOUNDATION_ARTIFACT_DIGEST,
        ),
    )
    verify_rehearsal_grant(_grant(), verifier=_Verifier(), subject=asked, at=NOW)


def test_the_foundation_artifact_digest_is_actually_compared_not_merely_carried() -> (
    None
):
    """NON-VACUITY, stated as its own test rather than left to be inferred.

    Constructs two subjects that are identical except for
    `foundation_artifact_digest`, against the SAME grant, and shows one is
    admitted and the other is refused. A comparison that had been wired to
    compare something else (or nothing) would admit both or refuse both.
    """
    matching = dataclasses.replace(
        _statement().subject,
        candidate=dataclasses.replace(
            _statement().candidate,
            foundation_artifact_digest=FOUNDATION_ARTIFACT_DIGEST,
        ),
    )
    verify_rehearsal_grant(_grant(), verifier=_Verifier(), subject=matching, at=NOW)

    disagreeing = dataclasses.replace(
        _statement().subject,
        candidate=dataclasses.replace(
            _statement().candidate,
            foundation_artifact_digest="sha256:" + "9" * 64,
        ),
    )
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            _grant(), verifier=_Verifier(), subject=disagreeing, at=NOW
        )
    assert refused.value.code is RehearsalGrantRefusalCode.CANDIDATE_MISMATCH


def test_a_malformed_foundation_artifact_digest_is_refused_before_any_comparison() -> (
    None
):
    """The digest is parsed with `FoundationArtifactDigestV1`, which is
    STRICT: not bare hex, not uppercase, not a bare string. An encoding fault
    is refused as MALFORMED before the grant can be built at all — the same
    split `digests.py` draws for `execution_plan_digest`."""
    for bad in ("a" * 64, "sha256:" + "A" * 64, "sha256:short", "not-a-digest"):
        with pytest.raises(RehearsalGrantRefusedError) as refused:
            CandidateArtifactRef(
                repository="michaelayoade/dotmac_starter_mt",
                run_id="r",
                artifact_id="a",
                foundation_artifact_digest=bad,
            )
        assert refused.value.code is RehearsalGrantRefusalCode.MALFORMED


def test_a_digest_of_the_wrong_subject_is_not_structurally_distinguishable() -> None:
    """THE HONEST FINDING. Say plainly what this module cannot tell.

    A source-tree digest, a workflow-ZIP digest and a genuine wheel digest are
    all `sha256:<64 lowercase hex>` — the same shape, the same type once
    parsed, nothing in the bytes naming which of the four forbidden subjects
    (or the one correct one) produced them. This module's comparison catches
    DISAGREEMENT between what the grant names and what the caller presents; it
    cannot catch two sides agreeing on the WRONG subject, because verifying
    that a digest is of the wheel and not of the source tree is
    `host_source.require_host_source`'s job, upstream of this parser, never
    this one's.

    This test proves the limitation rather than papering over it: a
    consistently-wrong digest (playing the role of a source-tree digest that
    both the grant and the caller mistakenly agree is "the" digest) is
    ADMITTED, exactly as a genuine wheel digest would be, because nothing here
    can tell the difference.
    """
    consistently_wrong_but_well_formed = "sha256:" + "5" * 64
    statement = _statement(
        candidate_foundation_artifact_digest=consistently_wrong_but_well_formed
    )
    asked = dataclasses.replace(
        statement.subject,
        candidate=dataclasses.replace(
            statement.candidate,
            foundation_artifact_digest=consistently_wrong_but_well_formed,
        ),
    )
    # No refusal: two sides agreeing on the WRONG subject is indistinguishable,
    # at this boundary, from two sides agreeing on the right one.
    verify_rehearsal_grant(
        issue_rehearsal_grant(statement, signer=_Signer()).as_mapping(),
        verifier=_Verifier(),
        subject=asked,
        at=NOW,
    )


# ── the lease window, revocation and the replay coordinate ──────────────────


def test_a_grant_outside_its_window_is_refused_at_both_ends() -> None:
    """A rehearsal authorization must not outlive its window."""
    with pytest.raises(RehearsalGrantRefusedError) as early:
        verify_rehearsal_grant(
            _grant(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW - timedelta(hours=1),
        )
    assert early.value.code is RehearsalGrantRefusalCode.NOT_YET_VALID
    with pytest.raises(RehearsalGrantRefusedError) as late:
        verify_rehearsal_grant(
            _grant(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW + timedelta(days=1),
        )
    assert late.value.code is RehearsalGrantRefusalCode.EXPIRED


def test_a_revoked_grant_is_refused_and_reads_as_revoked() -> None:
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            _grant(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
            revoked_grant_ids=frozenset({"g-1"}),
        )
    assert refused.value.code is RehearsalGrantRefusalCode.REVOKED
    assert (
        rehearsal_standing(
            _grant(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
            revoked_grant_ids=frozenset({"g-1"}),
        ).standing
        is RehearsalStanding.REVOKED
    )


def test_a_spent_replay_coordinate_is_a_second_execution_authority_and_is_refused() -> (
    None
):
    """One rehearsal per grant.

    Note what this establishes and what it does not: the function refuses a
    reference it is TOLD was spent. The durable record of consumption belongs
    to whoever holds the store, and there is none in this repository yet.
    """
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            _grant(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
            consumed_references=frozenset({"rr-1"}),
        )
    assert refused.value.code is RehearsalGrantRefusalCode.ALREADY_CONSUMED
    assert (
        rehearsal_standing(
            _grant(),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
            consumed_references=frozenset({"rr-1"}),
        ).standing
        is RehearsalStanding.CONSUMED
    )
    # NEAR MISS: somebody else's spent coordinate does not refuse this grant.
    verify_rehearsal_grant(
        _grant(),
        verifier=_Verifier(),
        subject=_statement().subject,
        at=NOW,
        consumed_references=frozenset({"rr-2"}),
    )


def test_a_grant_with_no_replay_coordinate_cannot_be_built() -> None:
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        _statement(single_use_reference="   ")
    assert refused.value.code is RehearsalGrantRefusalCode.MALFORMED


# ── approval, authenticity and envelope shape ───────────────────────────────


def test_a_rehearsal_is_not_exemptable() -> None:
    """A deliberately provoked failure against a real target with no approval
    evidence behind it is the case this grant exists for, not an exception."""
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            _grant(approval_decision_status="approval_exempt"),
            verifier=_Verifier(),
            subject=_statement().subject,
            at=NOW,
        )
    assert refused.value.code is RehearsalGrantRefusalCode.APPROVAL_NOT_STANDING


def test_a_changed_signature_refuses_before_any_term_is_compared() -> None:
    """Authenticity first: a forged document never earns field-level
    diagnostics about what it would have had to say."""
    forged = _grant()
    forged["signature"] = "NOT-THE-SIGNATURE"
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            forged,
            verifier=_Verifier(),
            subject=dataclasses.replace(_statement().subject, target_ref="production"),
            at=NOW,
        )
    assert refused.value.code is RehearsalGrantRefusalCode.SIGNATURE_INVALID


def test_an_unexpected_statement_key_is_refused() -> None:
    """Both directions on the key set, so a term cannot be smuggled in."""
    envelope = _grant()
    envelope["statement"]["allow_production"] = True
    with pytest.raises(RehearsalGrantRefusedError) as refused:
        verify_rehearsal_grant(
            envelope, verifier=_Verifier(), subject=_statement().subject, at=NOW
        )
    assert refused.value.code is RehearsalGrantRefusalCode.MALFORMED


def test_the_execution_plan_digest_is_the_counterpartys_and_is_never_recomputed() -> (
    None
):
    """The middle term is real here too.

    `ExecutionPlanDigestV1` has no `over_json`, so there is no route from a
    payload to one of these in Control; and its parser is strict, so a bare-hex
    or uppercase spelling is refused rather than tidied.
    """
    assert not hasattr(ExecutionPlanDigestV1, "over_json")
    for bad in ("a" * 64, "sha256:" + "A" * 64, "sha256:short"):
        with pytest.raises(RehearsalGrantRefusedError) as refused:
            _statement(execution_plan_digest=bad)
        assert refused.value.code is RehearsalGrantRefusalCode.MALFORMED


def test_the_foundation_artifact_digest_type_is_read_only_and_type_distinct() -> None:
    """`FoundationArtifactDigestV1` never computes and never satisfies another
    digest's binding by arriving in the right shape.

    Mirrors `test_the_execution_plan_digest_is_the_counterpartys_and_is_never_
    recomputed` for the new type: no `over_json`, and — the part that answers
    "can an execution-plan digest satisfy this binding by having the same
    bytes?" — no. `FoundationArtifactDigestV1` and `ExecutionPlanDigestV1`
    share only the bytes; a frozen dataclass compares unequal across types
    even when every field matches.
    """
    assert not hasattr(FoundationArtifactDigestV1, "over_json")
    same_bytes = "sha256:" + "b" * 64
    assert FoundationArtifactDigestV1.parse(same_bytes) != ExecutionPlanDigestV1.parse(
        same_bytes
    )
    for bad in ("b" * 64, "sha256:" + "B" * 64, "sha256:short"):
        with pytest.raises(DigestEncodingError):
            FoundationArtifactDigestV1.parse(bad)


def test_absent_authority_is_absent_and_not_a_failure() -> None:
    """`None` is a claim: nobody has authorized a rehearsal for this target."""
    result = rehearsal_standing(
        None, verifier=_Verifier(), subject=_statement().subject, at=NOW
    )
    assert result.standing is RehearsalStanding.ABSENT
    assert result.authorizes is False


# ── drift detection over the mirrored counterparty vocabulary ───────────────


def test_the_step_vocabulary_matches_the_installed_executor_when_one_is_present() -> (
    None
):
    """The mirror is the primary source; this is drift detection over it.

    The closure runs ALWAYS against the literal — a guard that skips is a guard
    that is off, and this repository's CI does not install the Foundation.
    Where it IS importable, the mirror is compared with the real thing, and the
    skip names what it saw so a silent pass is never read as agreement.

    STATED PLAINLY: in THIS repository's own CI, `dotmac_deployment_foundation`
    is never importable, so this specific comparison never actually runs
    there — it is a real check with a real refusal path, exercised only on a
    workstation that happens to have Foundation's source checked out beside
    this one. That gap is real and is named rather than implied to be closed;
    see `test_foundation_step_vocabulary_drift_names_a_step_the_mirror_lacks`
    and its sibling below for the part of this mechanism that DOES run
    unconditionally.
    """
    plan = pytest.importorskip(
        "dotmac_deployment_foundation.engine.plan",
        reason=(
            "dotmac-deployment-foundation is not importable here; the mirrored "
            "step vocabulary is compared once it is. UNMONITORED in this "
            "repository's own CI today — see the docstring above"
        ),
    )
    drift = foundation_step_vocabulary_drift(member.value for member in plan.StepKind)
    assert not drift, (
        "the mirrored counterparty step vocabulary no longer matches the "
        f"installed distribution; drift={sorted(drift)!r}. A provocation "
        "could name a step that is gone, or the mirror could be refusing a "
        "step that now exists"
    )


# ── the comparator's OWN sensitivity, provable with no Foundation installed ─


def test_foundation_step_vocabulary_drift_names_a_step_the_mirror_lacks() -> None:
    """PLANT THE DEFECT: simulate Foundation publishing a step the mirror does
    not have — exactly the shape of the real `apply_exposure`/
    `restore_exposure` staleness this repair fixes, reproduced synthetically so
    the comparator's sensitivity does not depend on Foundation being
    installed, which in this repository's CI it never is.
    """
    observed = FOUNDATION_STEP_KINDS | {"drain_traffic_planted_for_this_test"}
    drift = foundation_step_vocabulary_drift(observed)
    assert drift == {
        "drain_traffic_planted_for_this_test"
    }, "the planted step was not named by the drift detector"


def test_foundation_step_vocabulary_drift_is_silent_when_nothing_changed() -> None:
    """NEAR MISS, kept as a PERMANENT NEGATIVE CONTROL.

    An observed vocabulary that agrees with the mirror is not drift, and the
    detector must say so by staying silent — an empty result — rather than
    reporting a difference that does not exist. This is the case that would
    catch a comparator that always reports SOMETHING (e.g. one that compared
    object identity instead of set membership, or hashed the sets instead of
    diffing them): it would fail this test even though nothing has drifted.
    """
    observed = frozenset(FOUNDATION_STEP_KINDS)  # equal by value, not identity
    assert observed is not FOUNDATION_STEP_KINDS
    drift = foundation_step_vocabulary_drift(observed)
    assert drift == frozenset()
