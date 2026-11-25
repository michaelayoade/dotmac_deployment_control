"""Dispatch-only recovery (a2): the first dispatch never committed, the rollout is
still the exact untouched REQUESTED one, and the original coordinates are replayed.

Recovery grants no new authority: it re-opens ONE dispatch on the same rollout under a
fresh hold, with the exact original authorization bytes, a currently granted and
unrevoked approval, zero attempts (settled ones included) and distinct command keys.
A second use, a different command, a revoked approval or an approval-exempt plan is
refused.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dotmac_deployment_control import (
    ApprovalRefusedError,
    AuthorizationEnvelopeV2,
    DispatchEnvelopeRefusedError,
    DispatchResumeExpectation,
    RequestRolloutCommand,
    RevokePlanApprovalCommand,
    TransitionRefusedError,
    dispatch_attempt,
    request_rollout,
    revoke_plan_approval,
)
from dotmac_deployment_control.models import Rollout
from tests.authorization_support import SIGNER, VERIFIER
from tests.dispatch_support import DISPATCH_SIGNER
from tests.unit import test_deployment_control_intent as intent

# The shared fixtures (in-memory SQLite, a fixed clock), re-exported by name.
db = intent.db
_installed_module_audit_actions = intent._installed_module_audit_actions
_fixed_control_clock = intent._fixed_control_clock


def _setup(db, **plan_overrides):  # type: ignore[no-untyped-def]
    target = intent._desired(db, intent._target(db).id)
    plan = (
        intent._approved_plan(db, target.id)
        if not plan_overrides
        else intent._plan(db, target.id, **plan_overrides)
    )
    command = RequestRolloutCommand(
        command_id=intent._cmd(),
        rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
        plan_id=plan.id,
        authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
    )
    view = request_rollout(db, command, signer=SIGNER)
    row = db.get(Rollout, view.id)
    expectation = DispatchResumeExpectation(
        rollout_id=view.id,
        plan_id=plan.id,
        rollout_ref=command.rollout_ref,
        rollout_command_id=command.command_id,
        dispatch_command_id=intent._cmd(),
        execution_sequence=row.execution_sequence,
        original_authorization=AuthorizationEnvelopeV2.parse(
            row.authorization_envelope
        ),
    )
    return plan, command, view, expectation


def _recover(db, view, expectation, **over):  # type: ignore[no-untyped-def]
    args = {
        "command_id": getattr(expectation, "dispatch_command_id", None),
        "rollout_id": view.id,
        "verifier": VERIFIER,
        "dispatch_signer": DISPATCH_SIGNER,
        "resume_expectation": expectation,
    }
    args.update(over)
    return dispatch_attempt(db, **args)


def test_the_untouched_requested_rollout_is_recovered_exactly_once(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    # The original request is replayed as an exact duplicate: no new issuance.
    again = request_rollout(db, command, signer=SIGNER, resume_expectation=expectation)
    assert again.id == view.id
    intent_ = _recover(db, view, expectation)
    assert intent_.rollout_ref == command.rollout_ref
    # A second use is refused: the rollout now has an attempt, and the command key
    # is spent.
    with pytest.raises(TransitionRefusedError):
        _recover(db, view, expectation)


def test_recovery_never_issues_a_new_authorization(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    other = RequestRolloutCommand(
        command_id=intent._cmd(),  # not the original command
        rollout_ref=command.rollout_ref,
        plan_id=plan.id,
        authorization_expires_at=command.authorization_expires_at,
    )
    with pytest.raises(TransitionRefusedError, match="differs from the original"):
        request_rollout(db, other, signer=SIGNER, resume_expectation=expectation)
    changed = RequestRolloutCommand(
        command_id=command.command_id,
        rollout_ref=command.rollout_ref,
        plan_id=plan.id,
        authorization_expires_at=datetime(2098, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(TransitionRefusedError, match="differs from the original"):
        request_rollout(db, changed, signer=SIGNER, resume_expectation=expectation)
    with pytest.raises(TransitionRefusedError, match="typed recovery expectation"):
        request_rollout(db, command, signer=SIGNER, resume_expectation={})  # type: ignore[arg-type]


def test_dispatch_recovery_refuses_anything_but_the_original_coordinates(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    with pytest.raises(TransitionRefusedError, match="original coordinates"):
        _recover(db, view, expectation, command_id=intent._cmd())
    with pytest.raises(TransitionRefusedError, match="original coordinates"):
        _recover(db, view, expectation, actor_ref="someone")
    with pytest.raises(TransitionRefusedError, match="typed recovery expectation"):
        _recover(db, view, {}, command_id=expectation.dispatch_command_id)


def test_the_expectation_itself_refuses_inconsistent_coordinates(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    base = expectation.as_mapping()
    bad_variants = (
        {"execution_sequence": expectation.execution_sequence + 1},
        {"rollout_ref": "another-ref"},
        {"dispatch_command_id": expectation.rollout_command_id},  # keys must differ
    )
    for change in bad_variants:
        with pytest.raises(DispatchEnvelopeRefusedError):
            DispatchResumeExpectation.parse({**base, **change})
    assert DispatchResumeExpectation.parse(base) == expectation


def test_a_revoked_approval_cannot_recover(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    revoke_plan_approval(
        db,
        RevokePlanApprovalCommand(
            command_id=intent._cmd(), plan_id=plan.id, revocation_ref="withdrawn"
        ),
    )
    with pytest.raises(ApprovalRefusedError):
        _recover(db, view, expectation)


def test_an_approval_exempt_plan_is_outside_the_recovery_profile(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(
        db,
        requires_approval=False,
        approval_policy_code=None,
        approval_policy_version=None,
    )
    with pytest.raises((ApprovalRefusedError, TransitionRefusedError)):
        _recover(db, view, expectation)


def test_a_rollout_that_already_has_an_attempt_is_never_recovered(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    dispatch_attempt(
        db,
        command_id=intent._cmd(),
        rollout_id=view.id,
        verifier=VERIFIER,
        dispatch_signer=DISPATCH_SIGNER,
    )
    with pytest.raises(TransitionRefusedError):
        _recover(db, view, expectation)


# ── T-1: validate_recovery_dispatch_statement ───────────────────────────────

import dataclasses  # noqa: E402
import uuid  # noqa: E402
from datetime import timedelta  # noqa: E402

from dotmac_deployment_control import (  # noqa: E402
    DispatchEnvelopeRefusalCode,
    DispatchSignerIdentity,
    validate_recovery_dispatch_statement,
)
from dotmac_deployment_control.dispatch_envelope import (  # noqa: E402
    issue_dispatch_envelope,
)

_ISSUED = intent._NOW + timedelta(minutes=1)
_AT = intent._NOW + timedelta(minutes=2)
_DEADLINE = intent._NOW + timedelta(minutes=10)


def _fixture(db):  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    statement = issue_dispatch_envelope(
        authorization_envelope=expectation.original_authorization,
        dispatch_id=str(uuid.uuid4()),
        attempt_no=1,
        issued_at=_ISSUED,
        signer=DISPATCH_SIGNER,
    ).statement
    return expectation, statement


def _validate(expectation, statement, **over):  # type: ignore[no-untyped-def]
    args = {
        "expectation": expectation,
        "dispatch_identity": DISPATCH_SIGNER.dispatch_identity,
        "control_version": statement.control_version,
        "not_before": intent._NOW,
        "deadline": _DEADLINE,
        "at": _AT,
    }
    args.update(over)
    return validate_recovery_dispatch_statement(statement, **args)


def _code(call):  # type: ignore[no-untyped-def]
    with pytest.raises(DispatchEnvelopeRefusedError) as refused:
        call()
    return refused.value.code


def test_a_statement_bound_to_the_original_in_its_window_is_accepted(db) -> None:  # type: ignore[no-untyped-def]
    expectation, statement = _fixture(db)
    assert _validate(expectation, statement) == statement


def test_the_sign_time_window_is_bounded_by_the_original_lifetime(db) -> None:  # type: ignore[no-untyped-def]
    expectation, statement = _fixture(db)
    original = expectation.original_authorization.statement
    refused = DispatchEnvelopeRefusalCode.AUTHORIZATION_MISMATCH
    for over in (
        {"at": _DEADLINE},  # sign time at or after the deadline
        {"at": _DEADLINE + timedelta(seconds=1)},
        {"at": statement.issued_at - timedelta(seconds=1)},  # before issuance
        {"not_before": statement.issued_at + timedelta(seconds=1)},  # after issuance
        {"not_before": original.issued_at - timedelta(seconds=1)},  # before original
        {"deadline": original.expires_at},  # must end inside the original
        {"deadline": original.expires_at + timedelta(days=1)},
    ):
        assert (
            _code(lambda o=over: _validate(expectation, statement, **o)) == refused
        ), over


def test_the_dispatch_key_must_differ_from_the_authorization_key(db) -> None:  # type: ignore[no-untyped-def]
    expectation, statement = _fixture(db)
    reused = expectation.original_authorization.statement.public_key_fingerprint
    same = dataclasses.replace(statement, public_key_fingerprint=reused)
    identity = DispatchSignerIdentity(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        public_key_fingerprint=reused,
    )
    code = _code(lambda: _validate(expectation, same, dispatch_identity=identity))
    assert code == DispatchEnvelopeRefusalCode.SIGNER_PURPOSE_REUSED


def test_recovery_is_attempt_one_under_the_exact_signer_and_version(db) -> None:  # type: ignore[no-untyped-def]
    expectation, statement = _fixture(db)
    mismatch = DispatchEnvelopeRefusalCode.SIGNER_IDENTITY_MISMATCH
    other_fp = "sha256:" + "ab" * 32
    cases = (
        dataclasses.replace(statement, attempt_no=2),
        dataclasses.replace(statement, key_id="another-key"),
        dataclasses.replace(statement, algorithm="another-algorithm"),
        dataclasses.replace(statement, public_key_fingerprint=other_fp),
    )
    for variant in cases:
        assert _code(lambda v=variant: _validate(expectation, v)) == mismatch
    # A different control version than the one signing now.
    assert (
        _code(lambda: _validate(expectation, statement, control_version="9.9.9"))
        == mismatch
    )
    # The purpose is part of the statement and of the identity: neither can be
    # constructed with another one.
    with pytest.raises(DispatchEnvelopeRefusedError):
        dataclasses.replace(statement, purpose="not-a-dispatch-purpose")
    with pytest.raises(DispatchEnvelopeRefusedError):
        DispatchSignerIdentity(
            key_id="k", algorithm="a", public_key_fingerprint=other_fp, purpose="x"
        )


def test_the_dispatch_id_must_be_a_canonical_uuid4(db) -> None:  # type: ignore[no-untyped-def]
    expectation, statement = _fixture(db)
    malformed = DispatchEnvelopeRefusalCode.MALFORMED
    for bad in (
        str(uuid.uuid1()),  # not version 4
        str(uuid.uuid4()).upper(),  # not canonical
        "not-a-uuid",
        str(uuid.uuid4()).replace("-", ""),
    ):
        variant = dataclasses.replace(statement, dispatch_id=bad)
        assert _code(lambda v=variant: _validate(expectation, v)) == malformed, bad


def test_the_statement_must_project_the_original_authorization(db) -> None:  # type: ignore[no-untyped-def]
    expectation, statement = _fixture(db)
    variant = dataclasses.replace(statement, authorization_plan_id=str(uuid.uuid4()))
    assert (
        _code(lambda: _validate(expectation, variant))
        == DispatchEnvelopeRefusalCode.AUTHORIZATION_MISMATCH
    )
    with pytest.raises(DispatchEnvelopeRefusedError):
        validate_recovery_dispatch_statement(  # type: ignore[arg-type]
            statement,
            expectation={},
            dispatch_identity=DISPATCH_SIGNER.dispatch_identity,
            control_version=statement.control_version,
            not_before=intent._NOW,
            deadline=_DEADLINE,
            at=_AT,
        )


# ── T-2: the exact untouched requested rollout ──────────────────────────────


def plan_row(db, plan):  # type: ignore[no-untyped-def]
    from dotmac_deployment_control.models import DeploymentPlan

    return db.get(DeploymentPlan, plan.id)


def _touch(db, view, plan_ref, **changes):  # type: ignore[no-untyped-def]
    """Mutate the stored rows the dispatch re-reads under its locks."""
    from dotmac_deployment_control.models import DeploymentTarget

    rollout = db.get(Rollout, view.id)
    rows = {
        "rollout": rollout,
        "plan": plan_row(db, plan_ref),
        "target": db.get(DeploymentTarget, rollout.target_id),
    }
    for which, values in changes.items():
        for key, value in values.items():
            setattr(rows[which], key, value)
    db.flush()


@pytest.mark.parametrize(
    "changes",
    [
        {"rollout": {"record_version": 2}},
        {"rollout": {"status": "dispatched"}},
        {"rollout": {"completed_at": datetime(2026, 9, 1, tzinfo=UTC)}},
        {"target": {"status": "suspended"}},
        {"plan": {"status": "superseded"}},
        {"plan": {"status": "cancelled"}},
    ],
    ids=[
        "record_version",
        "rollout_status",
        "completed_at",
        "target_not_active",
        "plan_superseded",
        "plan_cancelled",
    ],
)
def test_a_touched_rollout_target_or_plan_is_not_recoverable(db, changes) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    _touch(db, view, plan, **changes)
    with pytest.raises(TransitionRefusedError, match="untouched requested rollout"):
        _recover(db, view, expectation)


def test_a_plan_superseded_by_another_is_not_recoverable(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    row = plan_row(db, plan)
    row.superseded_by_id = row.id
    db.flush()
    with pytest.raises(TransitionRefusedError, match="untouched requested rollout"):
        _recover(db, view, expectation)


# ── T-3: the exact authorization bytes and a granted approval ───────────────


def test_authorization_bytes_that_differ_are_refused(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    rollout = db.get(Rollout, view.id)
    stored = dict(rollout.authorization_envelope)
    stored["signature"] = str(stored["signature"]) + "-altered"
    rollout.authorization_envelope = stored
    db.flush()
    with pytest.raises(TransitionRefusedError, match="exact original authorization"):
        _recover(db, view, expectation)


def test_a_pending_or_revoked_approval_is_refused(db) -> None:  # type: ignore[no-untyped-def]
    """The decision vocabulary is granted/revoked; a PENDING approval is no decision
    at all (None) and a DENIED one is a revoked one."""
    for state in (None, "revoked"):
        plan, command, view, expectation = _setup(db)
        row = plan_row(db, plan)
        row.approval_decision_status = state
        db.flush()
        with pytest.raises(ApprovalRefusedError):
            _recover(db, view, expectation)


# ── T-4: a duplicate dispatch command; the normal path is unchanged ──────────


def test_a_duplicate_dispatch_command_cannot_recover(db) -> None:  # type: ignore[no-untyped-def]
    plan, command, view, expectation = _setup(db)
    dispatch_attempt(
        db,
        command_id=expectation.dispatch_command_id,
        rollout_id=view.id,
        verifier=VERIFIER,
        dispatch_signer=DISPATCH_SIGNER,
    )
    with pytest.raises(TransitionRefusedError, match="duplicate dispatch command"):
        _recover(db, view, expectation)


def test_the_normal_path_without_an_expectation_is_unchanged(db) -> None:  # type: ignore[no-untyped-def]
    """No resume expectation: the request is issued once, the dispatch opens attempt
    one, a repeated request is idempotent, and a second dispatch while one is in
    flight is still refused. Recovery code does not touch this path."""
    plan, command, view, _ = _setup(db)
    again = request_rollout(db, command, signer=SIGNER)
    assert again.id == view.id
    first = dispatch_attempt(
        db,
        command_id=intent._cmd(),
        rollout_id=view.id,
        verifier=VERIFIER,
        dispatch_signer=DISPATCH_SIGNER,
    )
    assert first.rollout_ref == command.rollout_ref
    with pytest.raises(TransitionRefusedError):
        dispatch_attempt(
            db,
            command_id=intent._cmd(),
            rollout_id=view.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
