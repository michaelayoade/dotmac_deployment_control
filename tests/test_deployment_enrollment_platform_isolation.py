"""Hosted PostgreSQL canaries for commit visibility, locks, ACLs and retention.

Run only in the repository's dedicated test-server lane. No local Docker.
Owner doubles qualify no production evidence; real public consumption lookup,
PostgreSQL transactions, RI, role grants and append-only triggers are exercised.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from dotmac_kernel.idempotency import execute_once_platform
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

import dotmac_deployment_control.deployment_enrollment as enrollment
from dotmac_deployment_control.host_admission import admission_consumption_fingerprint
from dotmac_deployment_control.models import (
    DeploymentCurrentEnrollment,
    DeploymentEnrollment,
    DeploymentEnrollmentClosure,
    DeploymentEnrollmentComponent,
    DeploymentHealthAssessment,
    DeploymentTarget,
    RolloutAttempt,
    TargetCurrentHost,
    TargetHostAssociation,
    TargetHostAssociationClosure,
)
from tests.test_deployment_control_platform_isolation import (
    DEPLOY_VERSIONS,
    KERNEL_VERSIONS,
    REPO_ROOT,
    _migrated_database,
)
from tests.test_deployment_control_platform_isolation import (
    _module_audit_actions as _module_audit_actions,
)
from tests.unit.test_deployment_enrollment import (
    _assert_caller_rollback,
    _assert_command_boundary,
    _assert_late_closure_receipt_regression,
    _assert_late_receipt_refusal,
    _assert_natural_reference_conflicts,
    _boundary_counts,
    _seed_enrollment,
    _successor,
)

pytestmark = pytest.mark.usefixtures("_module_audit_actions")


@pytest.fixture
def postgres_enrollment(monkeypatch):
    for urls in _migrated_database():
        engine = create_engine(urls[0])
        with Session(engine) as db:
            ctx = _seed_enrollment(db, monkeypatch)
            ctx.engine = engine
            ctx.urls = urls
            yield ctx
        engine.dispose()


def _reader(engine):
    @contextmanager
    def existing_owner_committed_read_scope():
        # This is the test assembly's scope, not transaction authority in Control.
        with Session(engine) as db:
            yield db

    return enrollment.PublicCommittedConsumptionReader(
        committed_read_scope=existing_owner_committed_read_scope
    )


def _stage_test_verified_ledger(ctx):
    """Test-only permanent kernel record matching an already seeded signed pair."""
    committed = ctx.owners.consumed
    fingerprint = admission_consumption_fingerprint(
        dispatch_envelope_digest=committed.dispatch_envelope_digest,
        candidate_attestation_envelope_digest=committed.candidate_attestation_envelope_digest,
        installed_attestation_envelope_digest=committed.installed_attestation_envelope_digest,
    )
    result = {
        "kind": "foundation_v3",
        "attempt_id": str(ctx.aid),
        "dispatch_id": str(ctx.aid),
        "authorization_envelope_digest": committed.authorization_envelope_digest,
        "dispatch_digest": committed.dispatch_envelope_digest,
        "execution_plan_digest": committed.execution_plan_digest,
        "candidate_attestation_envelope_digest": (
            committed.candidate_attestation_envelope_digest
        ),
        "installed_attestation_envelope_digest": (
            committed.installed_attestation_envelope_digest
        ),
    }
    scope = "deployment.consume_dispatch_challenge.v1"
    execute_once_platform(
        ctx.db,
        scope=scope,
        key=str(ctx.aid),
        fingerprint=fingerprint,
        expires_at=None,
        operation_name=scope,
        operation=lambda _db: result,
    )
    ctx.db.flush()


def test_public_reader_cannot_see_uncommitted_consumption_then_sees_commit(
    postgres_enrollment, monkeypatch
):
    ctx = postgres_enrollment
    reader = _reader(ctx.engine)
    monkeypatch.setattr(
        enrollment,
        "_installed_sources",
        replace(enrollment._installed_sources, consumption=reader),
    )
    _stage_test_verified_ledger(ctx)
    assert (
        reader.lookup_in_new_transaction(
            control_consumption_ref=f"control-dispatch:{ctx.aid}"
        )
        is None
    )
    with pytest.raises(
        enrollment.DeploymentEnrollmentRefusedError, match="committed consumption"
    ):
        enrollment.enroll_deployment(ctx.db, ctx.command)
    ctx.db.commit()
    assert (
        reader.lookup_in_new_transaction(
            control_consumption_ref=f"control-dispatch:{ctx.aid}"
        )
        == ctx.owners.consumed
    )
    projection = enrollment.enroll_deployment(ctx.db, ctx.command)
    assert projection.enrollment_ref == f"control-health:{ctx.aid}"
    ctx.db.rollback()


@pytest.mark.parametrize("role_index", [0, 1])
def test_real_roles_admit_child_fk_but_cannot_rewrite_immutable_parent(
    postgres_enrollment, role_index
):
    ctx = postgres_enrollment
    role_engine = create_engine(ctx.urls[role_index])
    try:
        with Session(role_engine) as db:
            # Entire initial graph, successor closure/pointer advance, and final
            # closure run as each real service role, including legacy-parent RI.
            projection = enrollment.enroll_deployment(db, ctx.command)
            db.commit()
            row = db.execute(
                select(DeploymentEnrollment).where(
                    DeploymentEnrollment.enrollment_ref == projection.enrollment_ref
                )
            ).scalar_one()
            db.add(
                DeploymentHealthAssessment(
                    id=uuid4(),
                    assessment_ref=f"role-{role_index}",
                    enrollment_id=row.id,
                    sequence=2,
                    assessed_at=ctx.owners.now(),
                    document={},
                )
            )
            db.flush()
            db.rollback()
            successor_command = _successor(ctx)
            ctx.db.commit()
            successor = enrollment.enroll_deployment(db, successor_command)
            db.commit()
            pointer = db.get(DeploymentCurrentEnrollment, ctx.tid)
            successor_row = db.execute(
                select(DeploymentEnrollment).where(
                    DeploymentEnrollment.enrollment_ref == successor.enrollment_ref
                )
            ).scalar_one()
            assert pointer.enrollment_id == successor_row.id
            assert (
                db.get(DeploymentEnrollmentClosure, row.id).successor_id
                == successor_row.id
            )
            enrollment.close_enrollment(
                db,
                enrollment.CloseEnrollmentCommand(
                    "close:" + str(f"role-close-{role_index}"),
                    successor.enrollment_ref,
                    f"role-close-{role_index}",
                ),
            )
            db.commit()
            assert db.get(DeploymentCurrentEnrollment, ctx.tid) is None
            assert db.get(DeploymentEnrollmentClosure, successor_row.id) is not None
            for statement in (
                "UPDATE mod_deploy.deployment_enrollments SET id=id WHERE id=:id",
                (
                    "UPDATE mod_deploy.deployment_enrollments "
                    "SET projection=projection WHERE id=:id"
                ),
                "DELETE FROM mod_deploy.deployment_enrollments WHERE id=:id",
                "TRUNCATE mod_deploy.deployment_enrollments CASCADE",
            ):
                with pytest.raises(DBAPIError), db.begin_nested():
                    db.execute(text(statement), {"id": row.id})
            db.rollback()
    finally:
        role_engine.dispose()


def test_permanent_role_code_installation_and_attempt_constraints(postgres_enrollment):
    ctx = postgres_enrollment
    projection = enrollment.enroll_deployment(ctx.db, ctx.command)
    enrollment.close_enrollment(
        ctx.db,
        enrollment.CloseEnrollmentCommand(
            "close:" + "close-before-uniqueness",
            projection.enrollment_ref,
            "close-before-uniqueness",
        ),
    )
    second_attempt = uuid4()
    ctx.db.add(RolloutAttempt(id=second_attempt, rollout_id=ctx.rid, attempt_no=2))
    ctx.db.commit()
    row = ctx.db.execute(select(DeploymentEnrollment)).scalar_one()
    duplicates = (
        (
            DeploymentEnrollmentComponent(
                component_code=projection.component_codes[0],
                enrollment_id=row.id,
                role="different",
            ),
            "deployment_enrollment_components_pkey",
        ),
        (
            DeploymentEnrollmentComponent(
                component_code="another-code", enrollment_id=row.id, role="web"
            ),
            "uq_health_enrollment_role",
        ),
        (
            DeploymentEnrollment(
                id=uuid4(),
                enrollment_ref="attempt-reuse",
                attempt_id=row.attempt_id,
                target_id=row.target_id,
                installation_ref="other-installation",
                identity_fingerprint="a" * 64,
                projection=row.projection,
                binding=row.binding,
            ),
            "uq_health_enrollment_attempt",
        ),
        (
            DeploymentEnrollment(
                id=uuid4(),
                enrollment_ref="installation-reuse",
                attempt_id=second_attempt,
                target_id=row.target_id,
                installation_ref=row.installation_ref,
                identity_fingerprint="a" * 64,
                projection=row.projection,
                binding=row.binding,
            ),
            "uq_health_enrollment_installation",
        ),
    )
    for duplicate, constraint in duplicates:
        with pytest.raises(IntegrityError) as refused, ctx.db.begin_nested():
            ctx.db.add(duplicate)
            ctx.db.flush()
        assert refused.value.orig.diag.constraint_name == constraint


def _wait_for_blocked(engine, backend_pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with engine.connect() as connection:
            wait = connection.execute(
                text("SELECT wait_event_type FROM pg_stat_activity WHERE pid=:pid"),
                {"pid": backend_pid},
            ).scalar_one_or_none()
        if wait == "Lock":
            return
        time.sleep(0.02)
    pytest.fail("second transaction never demonstrably blocked on the target lock")


@pytest.mark.parametrize("action", ["replay", "new-command", "conflict", "close"])
def test_concurrent_replay_and_closure_wait_for_exact_target_lock(
    postgres_enrollment, action
):
    ctx = postgres_enrollment
    original = enrollment.enroll_deployment(ctx.db, ctx.command)
    if action == "close":
        ctx.db.commit()
        enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=original.enrollment_ref
        )
    started = threading.Event()
    result = {}

    def waiter():
        try:
            with Session(ctx.engine) as db:
                result["pid"] = db.execute(text("SELECT pg_backend_pid()")).scalar_one()
                started.set()
                if action != "close":
                    command = ctx.command
                    if action == "new-command":
                        command = replace(command, command_id="concurrent-new-command")
                    elif action == "conflict":
                        command = replace(command, actor_ref="other-actor")
                    result["value"] = enrollment.enroll_deployment(db, command)
                else:
                    enrollment.close_enrollment(
                        db,
                        enrollment.CloseEnrollmentCommand(
                            "close:" + "concurrent-close",
                            original.enrollment_ref,
                            "concurrent-close",
                        ),
                    )
                db.commit()
        except BaseException as error:
            result["error"] = error
            started.set()

    thread = threading.Thread(target=waiter)
    thread.start()
    try:
        assert started.wait(5)
        _wait_for_blocked(ctx.engine, result["pid"])
        ctx.db.commit()
    finally:
        ctx.db.rollback()
        thread.join(5)
    assert not thread.is_alive()
    if action == "conflict":
        assert isinstance(
            result.get("error"), enrollment.DeploymentEnrollmentRefusedError
        )
        assert "fingerprint" in str(result["error"])
    else:
        assert "error" not in result
    with Session(ctx.engine) as fresh:
        assert (
            fresh.execute(
                select(func.count()).select_from(DeploymentEnrollment)
            ).scalar_one()
            == 1
        )
        assert _boundary_counts(fresh) == (
            (1, 1) if action in {"replay", "conflict"} else (2, 2)
        )
        if action in {"replay", "new-command", "conflict"}:
            if action != "conflict":
                assert result["value"] == original
            assert (
                fresh.execute(
                    select(func.count()).select_from(DeploymentHealthAssessment)
                ).scalar_one()
                == 1
            )
            assert fresh.get(DeploymentCurrentEnrollment, ctx.tid) is not None
        else:
            assert (
                fresh.execute(
                    select(func.count()).select_from(DeploymentEnrollmentClosure)
                ).scalar_one()
                == 1
            )
            with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
                enrollment.current_eligibility_get(
                    fresh, enrollment_ref=original.enrollment_ref
                )


def test_downgrade_refuses_retained_epoch(postgres_enrollment):
    from alembic import command
    from alembic.config import Config

    ctx = postgres_enrollment
    projection = enrollment.enroll_deployment(ctx.db, ctx.command)
    ctx.db.commit()
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("version_locations", f"{KERNEL_VERSIONS} {DEPLOY_VERSIONS}")
    with pytest.raises(
        RuntimeError, match="refuses to discard health enrollment history"
    ):
        command.downgrade(cfg, "dc_0016_controller_key_nonreuse")
    with Session(ctx.engine) as db:
        assert (
            enrollment.historical_get(db, enrollment_ref=projection.enrollment_ref)
            == projection
        )


@pytest.mark.parametrize("drift", ["second-open", "malformed-coherent-host"])
def test_current_host_uses_owner_history_and_fleet_grammar_guard(
    postgres_enrollment, drift
):
    from dotmac_deployment_control.host_admission_service import (
        HostAdmissionStateRefusalCode,
        HostAdmissionStateRefusedError,
    )

    ctx = postgres_enrollment
    current = ctx.db.get(TargetCurrentHost, ctx.tid)
    new_id = uuid4()
    host = "host-2" if drift == "second-open" else "Bad/Host"
    ctx.db.add(
        TargetHostAssociation(
            id=new_id,
            target_id=ctx.tid,
            host_id=host,
            bound_at=ctx.owners.now(),
            authority="test-host-owner",
        )
    )
    ctx.db.flush()
    if drift == "malformed-coherent-host":
        ctx.db.add(
            TargetHostAssociationClosure(
                association_id=current.association_id,
                closed_at=ctx.owners.now(),
                authority="test-host-owner",
                successor_id=new_id,
            )
        )
        current.association_id = new_id
        ctx.owners.runtime["runtime-1"] = replace(
            ctx.owners.runtime["runtime-1"], host_id=host
        )
        ctx.owners.custody["custody-1"] = replace(
            ctx.owners.custody["custody-1"], host_id=host
        )
    ctx.db.commit()
    with pytest.raises(HostAdmissionStateRefusedError) as refused:
        enrollment.enroll_deployment(ctx.db, ctx.command)
    expected = (
        HostAdmissionStateRefusalCode.HOST_AMBIGUOUS
        if drift == "second-open"
        else HostAdmissionStateRefusalCode.MALFORMED
    )
    assert refused.value.code == expected
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentEnrollment)
        ).scalar_one()
        == 0
    )


@pytest.mark.parametrize("operation", ["initial", "successor", "assess"])
@pytest.mark.parametrize("position", ["before-end", "exact-end", "after-end"])
def test_late_flush_refusal_cannot_commit_new_eligibility_or_pointer_changes(
    postgres_enrollment, operation, position
):
    ctx = postgres_enrollment
    original = None
    original_id = None
    if operation != "initial":
        original = enrollment.enroll_deployment(ctx.db, ctx.command)
        ctx.db.commit()
        original_id = ctx.db.execute(
            select(DeploymentEnrollment.id).where(
                DeploymentEnrollment.enrollment_ref == original.enrollment_ref
            )
        ).scalar_one()
        ctx.db.commit()
    command = _successor(ctx) if operation == "successor" else ctx.command
    if operation == "successor":
        ctx.db.commit()
    sentinel_id = uuid4()
    ctx.db.add(
        DeploymentTarget(
            id=sentinel_id,
            target_ref=f"sentinel-{sentinel_id}",
            subject_ref="unrelated-caller-work",
            product_code="test-product",
            environment="test",
        )
    )
    end = ctx.owners.custody[command.credential_evidence_ref].valid_until
    finish = (
        end
        + {
            "before-end": -timedelta(microseconds=1),
            "exact-end": timedelta(0),
            "after-end": timedelta(microseconds=1),
        }[position]
    )
    fired = False
    pending_target_flush = False
    assessment_ref = f"late-flush-{position}"

    def detect_only_new_mutation(session, _flush_context, _instances):
        nonlocal pending_target_flush
        pending_target_flush = any(
            (
                isinstance(row, DeploymentEnrollment)
                and row.attempt_id == command.attempt_id
            )
            if operation != "assess"
            else (
                isinstance(row, DeploymentHealthAssessment)
                and row.assessment_ref == assessment_ref
            )
            for row in session.new
        )

    def advance_after_target_flush(_session, _flush_context):
        nonlocal fired, pending_target_flush
        if pending_target_flush:
            ctx.owners.now_value = finish
            fired = True
            pending_target_flush = False

    event.listen(ctx.db, "before_flush", detect_only_new_mutation)
    event.listen(ctx.db, "after_flush_postexec", advance_after_target_flush)
    try:

        def invoke():
            if operation == "assess":
                return enrollment.assess_health_eligibility(
                    ctx.db,
                    enrollment.AssessHealthEligibilityCommand(
                        "assess:" + str(assessment_ref),
                        original.enrollment_ref,
                        assessment_ref,
                        "runtime-1",
                        "custody-1",
                    ),
                )
            return enrollment.enroll_deployment(ctx.db, command)

        if position == "before-end":
            result = invoke()
        else:
            with pytest.raises(
                enrollment.DeploymentEnrollmentRefusedError, match="expired|regressed"
            ):
                invoke()
        assert fired, "clock must advance only after the new eligibility flush"
        # Deliberately catch the ordinary refusal and commit the caller's outer
        # transaction. Only the service's savepoint may remove its refused rows.
        ctx.db.commit()
    finally:
        event.remove(ctx.db, "before_flush", detect_only_new_mutation)
        event.remove(ctx.db, "after_flush_postexec", advance_after_target_flush)

    with Session(ctx.engine) as fresh:
        assert fresh.get(DeploymentTarget, sentinel_id) is not None

        def count(model):
            return fresh.execute(select(func.count()).select_from(model)).scalar_one()

        baseline = 0 if operation == "initial" else 1
        accepted = 1 if position == "before-end" else 0
        assert _boundary_counts(fresh) == (baseline + accepted, baseline + accepted)
        pointer = fresh.get(DeploymentCurrentEnrollment, ctx.tid)
        if position != "before-end":
            baseline = 0 if operation == "initial" else 1
            assert count(DeploymentEnrollment) == baseline
            assert count(DeploymentEnrollmentComponent) == baseline
            assert count(DeploymentHealthAssessment) == baseline
            assert count(DeploymentEnrollmentClosure) == 0
            if operation == "initial":
                assert pointer is None
            else:
                assert pointer.enrollment_id == original_id
                assert (
                    enrollment.historical_get(
                        fresh, enrollment_ref=original.enrollment_ref
                    )
                    == original
                )
        elif operation == "assess":
            assert count(DeploymentEnrollment) == 1
            assert count(DeploymentHealthAssessment) == 2
            assert count(DeploymentEnrollmentClosure) == 0
            assert pointer.enrollment_id == original_id
            assert (
                enrollment.current_eligibility_get(
                    fresh, enrollment_ref=original.enrollment_ref
                )
                == result
            )
        else:
            expected = 2 if operation == "successor" else 1
            assert count(DeploymentEnrollment) == expected
            assert count(DeploymentEnrollmentComponent) == expected
            assert count(DeploymentHealthAssessment) == expected
            assert count(DeploymentEnrollmentClosure) == expected - 1
            current = fresh.execute(
                select(DeploymentEnrollment).where(
                    DeploymentEnrollment.enrollment_ref == result.enrollment_ref
                )
            ).scalar_one()
            assert pointer.enrollment_id == current.id


def test_command_receipt_audit_replay_and_conflict_on_postgresql(postgres_enrollment):
    _assert_command_boundary(postgres_enrollment)
    with Session(postgres_enrollment.engine) as fresh:
        assert _boundary_counts(fresh) == (6, 6)


def test_caller_rollback_removes_all_command_effects_on_postgresql(postgres_enrollment):
    _assert_caller_rollback(postgres_enrollment)
    with Session(postgres_enrollment.engine) as fresh:
        assert _boundary_counts(fresh) == (0, 0)
        assert (
            fresh.execute(
                select(func.count()).select_from(DeploymentEnrollment)
            ).scalar_one()
            == 0
        )


def test_postreceipt_expiry_rolls_back_command_but_keeps_caller_work_on_postgresql(
    postgres_enrollment,
):
    _assert_late_receipt_refusal(postgres_enrollment)
    with Session(postgres_enrollment.engine) as fresh:
        assert _boundary_counts(fresh) == (0, 0)
        assert (
            fresh.execute(
                select(func.count()).select_from(DeploymentEnrollment)
            ).scalar_one()
            == 0
        )
        assert (
            fresh.execute(
                select(func.count())
                .select_from(DeploymentTarget)
                .where(DeploymentTarget.subject_ref == "unrelated")
            ).scalar_one()
            == 1
        )


def test_new_command_domain_conflicts_preserve_receipts_on_postgresql(
    postgres_enrollment,
):
    _assert_natural_reference_conflicts(postgres_enrollment)
    with Session(postgres_enrollment.engine) as fresh:
        assert _boundary_counts(fresh) == (3, 3)


def test_late_closure_receipt_regression_is_atomic_on_postgresql(postgres_enrollment):
    _assert_late_closure_receipt_regression(postgres_enrollment)
    with Session(postgres_enrollment.engine) as fresh:
        assert _boundary_counts(fresh) == (1, 1)
        assert (
            fresh.get(DeploymentCurrentEnrollment, postgres_enrollment.tid) is not None
        )
        assert (
            fresh.execute(
                select(func.count()).select_from(DeploymentEnrollmentClosure)
            ).scalar_one()
            == 0
        )
