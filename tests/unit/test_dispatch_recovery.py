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
        rollout_ref="rol-recovery",
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
        "command_id": expectation.dispatch_command_id,
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
