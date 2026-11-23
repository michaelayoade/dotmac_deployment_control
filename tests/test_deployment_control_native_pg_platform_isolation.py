"""Foundation a2 NATIVE_PG proofs on a REAL PostgreSQL: approval-standing locking and
first-commit dispatch-only recovery. Discovered by `run_platform_isolation_canaries`
(the "platform isolation canary (PostgreSQL)" job) through its glob.

Two scenarios had no real-PG test anywhere:

(a) an approval standing HOLD (`SELECT ... FOR SHARE`, granted and unrevoked) blocks a
    concurrent withdrawal (`revoke_plan_approval`, `FOR UPDATE`): it waits behind the
    hold (observed as a real PostgreSQL lock wait) or, with NOWAIT, refuses; the hold's
    own view stays coherent until it commits; and after the withdrawal commits a new
    hold finds no standing.
(d) first-commit dispatch-only recovery: the original authorization is committed and
    the dispatch withheld; recovery on the SAME coordinates succeeds exactly once, a
    second use is refused, and concurrent attempts give exactly one winner.

Requires real PostgreSQL (`TEST_MIGRATION_DATABASE_URL`); the shared fixtures are the
isolation module's.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    AuthorizationEnvelopeV2,
    DesiredDeployment,
    DispatchResumeExpectation,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RevokePlanApprovalCommand,
    SetDesiredStateCommand,
    TransitionRefusedError,
    approve_plan,
    dispatch_attempt,
    propose_plan,
    register_target,
    request_rollout,
    revoke_plan_approval,
    set_desired_state,
)
from dotmac_deployment_control.models import DeploymentPlan, Rollout, RolloutAttempt
from tests import test_deployment_control_platform_isolation as iso
from tests.authorization_support import SIGNER, VERIFIER
from tests.dispatch_support import DISPATCH_SIGNER

# The isolation module's scratch database and audit-action fixtures, by name.
migrated_scratch = iso.migrated_scratch
_module_audit_actions = iso._module_audit_actions

_DESCRIPTOR = "sha256:" + "3c" * 32
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_STANDING_HOLD = (
    "SELECT id FROM mod_deploy.deployment_plans WHERE id = :plan "
    "AND approval_decision_status = 'granted' AND approval_revoked_at IS NULL"
)


@dataclass(frozen=True)
class _Approved:
    engine: Engine
    plan_id: uuid.UUID
    rollout_id: uuid.UUID
    command: RequestRolloutCommand
    expectation: DispatchResumeExpectation


@pytest.fixture
def approved_rollout(
    migrated_scratch: tuple[str, str, str],  # noqa: F811
    _module_audit_actions: None,  # noqa: F811
) -> Iterator[_Approved]:
    """An APPROVED plan with its rollout REQUESTED and COMMITTED, dispatch withheld."""
    admin_url, _, _ = migrated_scratch
    engine = create_engine(admin_url, future=True)
    suffix = uuid.uuid4().hex[:10]
    with Session(engine) as db:
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=f"seed-target-{suffix}",
                target_ref=f"a2-target-{suffix}",
                subject_ref=f"subject-{suffix}",
                product_code="dotmac_sub",
                environment="production",
            ),
        )
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=f"seed-desired-{suffix}",
                target_id=target.id,
                desired=DesiredDeployment(
                    release_ref="dotmac_sub@1", spec={"replicas": 2}, images=[]
                ),
            ),
        )
        plan = propose_plan(
            db,
            ProposePlanCommand(
                command_id=f"seed-plan-{suffix}",
                target_id=target.id,
                operation="deploy",
                descriptor_digest=_DESCRIPTOR,
                execution_plan_digest=_EXECUTION_PLAN,
                purpose="foundation_execution",
                requires_approval=True,
                approval_policy_code="deployment.production",
                approval_policy_version=1,
            ),
        )
        approve_plan(
            db,
            ApprovePlanCommand(
                command_id=f"approve-plan-{suffix}",
                plan_id=plan.id,
                evidence=ApprovalEvidence(
                    policy_code="deployment.production",
                    policy_version=1,
                    decision_ref=f"decision-{suffix}",
                    content_digest=plan.plan_digest or "",
                    decided_at=datetime.now(UTC),
                    operation="deploy",
                    execution_plan_digest=_EXECUTION_PLAN,
                    decision_status="granted",
                ),
            ),
        )
        command = RequestRolloutCommand(
            command_id=f"seed-rollout-{suffix}",
            rollout_ref=f"a2-rollout-{suffix}",
            plan_id=plan.id,
            authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        )
        view = request_rollout(db, command, signer=SIGNER)
        db.commit()  # the original authorization is COMMITTED; no dispatch exists
        row = db.get(Rollout, view.id)
        expectation = DispatchResumeExpectation(
            rollout_id=view.id,
            plan_id=plan.id,
            rollout_ref=command.rollout_ref,
            rollout_command_id=command.command_id,
            dispatch_command_id=f"recover-dispatch-{suffix}",
            execution_sequence=row.execution_sequence,
            original_authorization=AuthorizationEnvelopeV2.parse(
                row.authorization_envelope
            ),
        )
        plan_id, rollout_id = plan.id, view.id
    try:
        yield _Approved(engine, plan_id, rollout_id, command, expectation)
    finally:
        engine.dispose()


# ── (a) approval standing hold versus withdrawal ────────────────────────────


def test_native_pg_approval_standing_hold_for_share_blocks_a_withdrawal_for_update(
    approved_rollout: _Approved,
) -> None:
    """The hold (FOR SHARE) is taken first; the withdrawal waits behind it as a real
    PostgreSQL lock wait; NOWAIT refuses; the hold stays coherent until it commits;
    after the withdrawal commits a NEW hold finds no standing."""
    engine, plan_id = approved_rollout.engine, approved_rollout.plan_id
    sessions = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    hold = engine.connect()
    hold_tx = hold.begin()
    try:
        # 1. The standing hold: granted and unrevoked, locked FOR SHARE.
        held = hold.execute(
            text(_STANDING_HOLD + " FOR SHARE"), {"plan": plan_id}
        ).first()
        assert held is not None, "the approval must be standing before the hold"

        finished = threading.Event()
        errors: list[BaseException] = []
        backend: dict[str, int] = {}

        def withdraw() -> None:
            db = sessions()
            try:
                backend["pid"] = int(
                    db.execute(text("SELECT pg_backend_pid()")).scalar_one()
                )
                revoke_plan_approval(
                    db,
                    RevokePlanApprovalCommand(
                        command_id=f"withdraw-{uuid.uuid4()}",
                        plan_id=plan_id,
                        revocation_ref=f"decision-{uuid.uuid4()}",
                    ),
                )
                db.commit()
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)
                db.rollback()
            finally:
                db.close()
                finished.set()

        worker = threading.Thread(target=withdraw)
        worker.start()
        deadline = time.monotonic() + 10
        while "pid" not in backend and time.monotonic() < deadline:
            time.sleep(0.01)
        assert "pid" in backend, "the withdrawal never opened a backend"
        # 2. The withdrawal WAITS behind the hold: PostgreSQL reports a lock wait.
        iso._wait_until_postgres_reports_lock(engine, backend["pid"])
        assert not finished.is_set(), "the withdrawal got past a standing hold"
        # 3. A competing FOR UPDATE with NOWAIT refuses outright (no waiting).
        with engine.connect() as other:
            with pytest.raises(DBAPIError):
                other.execute(
                    text(_STANDING_HOLD + " FOR UPDATE NOWAIT"), {"plan": plan_id}
                )
        # 4. The hold's own view is coherent: still granted, still unrevoked.
        assert hold.execute(text(_STANDING_HOLD), {"plan": plan_id}).first() is not None
    finally:
        hold_tx.commit()
        hold.close()
    # 5. Order of operations: the withdrawal completes only after the hold released.
    worker.join(timeout=30)
    assert not worker.is_alive(), "the withdrawal never completed after the release"
    assert not errors, errors
    with Session(engine) as db:
        plan = db.get(DeploymentPlan, plan_id)
        assert plan.approval_decision_status == "revoked"
        assert plan.approval_revoked_at is not None
    # 6. A hold taken AFTER the withdrawal committed finds no standing.
    with engine.begin() as after:
        assert (
            after.execute(
                text(_STANDING_HOLD + " FOR SHARE"), {"plan": plan_id}
            ).first()
            is None
        )


def test_native_pg_a_withdrawal_committed_first_leaves_no_standing_to_hold(
    approved_rollout: _Approved,
) -> None:
    """The other order: the withdrawal commits first, so the hold finds nothing."""
    engine, plan_id = approved_rollout.engine, approved_rollout.plan_id
    with Session(engine) as db:
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=f"withdraw-{uuid.uuid4()}",
                plan_id=plan_id,
                revocation_ref=f"decision-{uuid.uuid4()}",
            ),
        )
        db.commit()
    with engine.begin() as conn:
        assert (
            conn.execute(text(_STANDING_HOLD + " FOR SHARE"), {"plan": plan_id}).first()
            is None
        )


# ── (d) first-commit dispatch-only recovery ─────────────────────────────────


def _attempts(engine: Engine, rollout_id: uuid.UUID) -> int:
    with Session(engine) as db:
        return int(
            db.execute(
                select(func.count())
                .select_from(RolloutAttempt)
                .where(RolloutAttempt.rollout_id == rollout_id)
            ).scalar_one()
        )


def test_native_pg_dispatch_only_recovery_on_the_same_coordinates_succeeds_exactly_once(
    approved_rollout: _Approved,
) -> None:
    engine = approved_rollout.engine
    exp, command = approved_rollout.expectation, approved_rollout.command
    # The original authorization is committed and the dispatch is withheld.
    assert _attempts(engine, exp.rollout_id) == 0
    with Session(engine) as db:
        row = db.get(Rollout, exp.rollout_id)
        assert (row.status, row.record_version) == ("requested", 1)
    # Recovery: the exact original request replays as a duplicate (no new issuance),
    # then ONE dispatch opens under a fresh hold taken after the locks.
    with Session(engine) as db:
        again = request_rollout(db, command, signer=SIGNER, resume_expectation=exp)
        assert again.id == exp.rollout_id
        intent = dispatch_attempt(
            db,
            command_id=exp.dispatch_command_id,
            rollout_id=exp.rollout_id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
            resume_expectation=exp,
        )
        db.commit()
    assert intent.rollout_ref == exp.rollout_ref
    assert _attempts(engine, exp.rollout_id) == 1
    with Session(engine) as db:
        attempt = db.execute(
            select(RolloutAttempt).where(RolloutAttempt.rollout_id == exp.rollout_id)
        ).scalar_one()
        issued = exp.original_authorization.statement.issued_at
        assert attempt.attempt_no == 1 and attempt.dispatched_at >= issued
    # A second use is refused and adds nothing.
    with Session(engine) as db:
        with pytest.raises(TransitionRefusedError):
            dispatch_attempt(
                db,
                command_id=exp.dispatch_command_id,
                rollout_id=exp.rollout_id,
                verifier=VERIFIER,
                dispatch_signer=DISPATCH_SIGNER,
                resume_expectation=exp,
            )
        db.rollback()
    assert _attempts(engine, exp.rollout_id) == 1


def test_native_pg_concurrent_dispatch_only_recovery_has_exactly_one_winner(
    approved_rollout: _Approved,
) -> None:
    engine = approved_rollout.engine
    exp = approved_rollout.expectation
    sessions = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    workers = 4
    start = threading.Barrier(workers)
    outcomes: list[tuple[str, object]] = []
    guard = threading.Lock()

    def recover() -> None:
        db = sessions()
        try:
            start.wait(timeout=30)
            dispatch_attempt(
                db,
                command_id=exp.dispatch_command_id,
                rollout_id=exp.rollout_id,
                verifier=VERIFIER,
                dispatch_signer=DISPATCH_SIGNER,
                resume_expectation=exp,
            )
            db.commit()
            result: tuple[str, object] = ("won", None)
        except BaseException as exc:
            db.rollback()
            result = ("refused", exc)
        finally:
            db.close()
        with guard:
            outcomes.append(result)

    threads = [threading.Thread(target=recover) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive(), "concurrent recovery deadlocked"
    winners = [o for o in outcomes if o[0] == "won"]
    losers = [o[1] for o in outcomes if o[0] == "refused"]
    assert len(outcomes) == workers
    assert len(winners) == 1, outcomes
    # Every loser is REFUSED (a typed refusal or the kernel's duplicate-command
    # refusal), never a second success and never silently nothing.
    assert all(isinstance(exc, Exception) for exc in losers), losers
    assert len(losers) == workers - 1, [type(exc).__name__ for exc in losers]
    assert _attempts(engine, exp.rollout_id) == 1
