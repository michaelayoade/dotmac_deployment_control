"""Intent, plans and rollouts — the guards, not the happy path.

The invariant this file protects: **what gets dispatched is the plan that was
approved, and nothing else can reach a target.** A suite that only walked
register → plan → approve → roll out would pass against an implementation that
read the target's current desired state at dispatch time, which is the single
most consequential way this module could be wrong: the approval would be for one
thing and the deployment would be another.

So the tests below are mostly refusals, plus the two properties that are easy to
implement almost-correctly — digest binding and one-attempt-at-a-time.

In-memory SQLite — logic only. Grants, the append-only triggers, the claim/proof
CHECKs and migration-from-empty are proven against real Postgres in
`tests/test_deployment_control_platform_isolation.py`.
"""

from __future__ import annotations

import copy
import re
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovalRefusedError,
    ApprovePlanCommand,
    AttemptOutcome,
    DesiredDeployment,
    DigestEncodingError,
    EnrolCredentialCommand,
    ExpectedStateError,
    PlanDigestV1,
    PlanRefusedError,
    PlanStatus,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RevokePlanApprovalCommand,
    RolloutStatus,
    RolloutTransitionCommand,
    SetDesiredStateCommand,
    SettleAttemptCommand,
    TargetStatus,
    TargetTransitionCommand,
    TransitionRefusedError,
    approve_plan,
    cancel_plan,
    cancel_rollout,
    decommission_target,
    dispatch_attempt,
    drift,
    enrol_credential,
    get_plan,
    get_rollout,
    get_target,
    module,
    propose_plan,
    register_target,
    request_rollout,
    require_manual_repair,
    revoke_plan_approval,
    set_desired_state,
    settle_attempt,
    snapshot_digest,
    suspend_target,
)
from dotmac_deployment_control.models import Rollout
from tests.authorization_support import SIGNER, VERIFIER

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_POLICY = "deployment.production"
_POLICY_VERSION = 4

#: A stand-in for the Deployment Foundation's `ExecutionPlanDigestV1`.
#:
#: WRITTEN OUT as canonical text rather than computed from anything, and that is
#: the point rather than laziness: Control cannot compute one, so a fixture that
#: derived it would be exercising a capability the module deliberately does not
#: have — and would go on passing if somebody gave it one.
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_OTHER_EXECUTION_PLAN = "sha256:" + "2b" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


@pytest.fixture
def db() -> Generator[Session, None, None]:
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        # pysqlite does not emit BEGIN on its own, which leaves SAVEPOINT
        # semantics broken — and every command runs inside one.
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _emit_begin(connection):  # type: ignore[no-untyped-def]
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[
            table
            for table in Base.metadata.tables.values()
            if table.schema == "mod_deploy"
            or table.name
            in {
                "platform_idempotency_records",
                "platform_audit_events",
                "platform_admins",
                "platform_outbox_events",
            }
        ],
    )
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _cmd() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _target(db: Session, **overrides: object):
    fields: dict[str, object] = {
        "command_id": _cmd(),
        "target_ref": f"tgt-{uuid.uuid4().hex[:8]}",
        "subject_ref": "acme-operator",
        "product_code": "dotmac_sub",
        "environment": "production",
    }
    fields.update(overrides)
    return register_target(db, RegisterTargetCommand(**fields))  # type: ignore[arg-type]


def _desired(db: Session, target_id, **overrides: object):  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "release_ref": "dotmac_sub@7.187.1",
        "spec": {"replicas": 2},
        "licence_ref": "lic-1",
        "brand_profile_ref": "brand-acme",
        "images": [],
    }
    fields.update(overrides)
    return set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=target_id,
            desired=DesiredDeployment(**fields),  # type: ignore[arg-type]
        ),
    )


def _plan(db: Session, target_id, **overrides: object):  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "command_id": _cmd(),
        "target_id": target_id,
        "operation": "deploy",
        "descriptor_digest": _DESCRIPTOR,
        "execution_plan_digest": _EXECUTION_PLAN,
        "requires_approval": True,
        "approval_policy_code": _POLICY,
        "approval_policy_version": _POLICY_VERSION,
    }
    fields.update(overrides)
    return propose_plan(db, ProposePlanCommand(**fields))  # type: ignore[arg-type]


def _evidence(digest: str, **overrides: object) -> ApprovalEvidence:
    fields: dict[str, object] = {
        "policy_code": _POLICY,
        "policy_version": _POLICY_VERSION,
        "decision_ref": f"apr-{uuid.uuid4().hex[:8]}",
        "content_digest": digest,
        "decided_at": _NOW,
        "operation": "deploy",
        "execution_plan_digest": _EXECUTION_PLAN,
        "decision_status": "granted",
    }
    fields.update(overrides)
    return ApprovalEvidence(**fields)  # type: ignore[arg-type]


def _approved_plan(db: Session, target_id):  # type: ignore[no-untyped-def]
    plan = _plan(db, target_id)
    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_cmd(),
            plan_id=plan.id,
            evidence=_evidence(plan.plan_digest or ""),
        ),
    )


def _rollout(db: Session, plan_id):  # type: ignore[no-untyped-def]
    return request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_cmd(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan_id,
            authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            authorization_issued_at=_NOW,
        ),
        signer=SIGNER,
    )


# ── Targets ─────────────────────────────────────────────────────────────────


class TestTargetsAndDesiredState:
    def test_a_new_target_starts_registered_with_no_desired_state(self, db) -> None:
        view = _target(db)
        assert view.status == TargetStatus.REGISTERED.value
        assert view.desired_release_ref is None
        assert view.desired_revision == 0

    def test_registering_the_same_ref_twice_is_idempotent(self, db) -> None:
        ref = f"tgt-{uuid.uuid4().hex[:8]}"
        first = _target(db, target_ref=ref)
        second = _target(db, target_ref=ref)
        assert first.id == second.id

    def test_setting_desired_state_bumps_the_revision_and_activates(self, db) -> None:
        view = _desired(db, _target(db).id)
        assert view.status == TargetStatus.ACTIVE.value
        assert view.desired_revision == 1
        assert view.desired_release_ref == "dotmac_sub@7.187.1"

    def test_re_declaring_the_same_state_still_bumps_the_revision(self, db) -> None:
        """A revision records that a DECISION was taken. An operator
        re-declaring the same state after an incident wants a plan they can
        approve, not a silent no-op that leaves the fleet exactly as it was."""
        target = _target(db)
        first = _desired(db, target.id)
        second = _desired(db, target.id)
        assert second.desired_revision == first.desired_revision + 1

    def test_a_decommissioned_target_refuses_a_desired_state(self, db) -> None:
        target = _desired(db, _target(db).id)
        decommission_target(db, TargetTransitionCommand(_cmd(), target.id))
        with pytest.raises(TransitionRefusedError, match="decommissioned"):
            _desired(db, target.id)

    def test_a_stale_record_version_is_refused(self, db) -> None:
        target = _desired(db, _target(db).id)
        stale = target.record_version
        _desired(db, target.id)
        with pytest.raises(ExpectedStateError):
            set_desired_state(
                db,
                SetDesiredStateCommand(
                    command_id=_cmd(),
                    target_id=target.id,
                    desired=DesiredDeployment(release_ref="x"),
                    expected_version=stale,
                ),
            )


# ── Credentials ─────────────────────────────────────────────────────────────


class TestCredentials:
    def test_enrolment_lands_pending_not_active(self, db) -> None:
        """An enrolled key is a claim that someone registered it. Enrolling
        straight to active would let anyone who can call the endpoint
        impersonate a deployment (ADR-0007)."""
        from dotmac_deployment_control import CredentialStatus, TargetCredential

        target = _target(db)
        credential_id = enrol_credential(
            db,
            EnrolCredentialCommand(
                command_id=_cmd(),
                target_id=target.id,
                key_id="k1",
                public_key_b64="AAAA",
                public_key_fingerprint="sha256:aa",
                enrollment_authority="platform_admin_policy",
            ),
        )
        row = db.get(TargetCredential, credential_id)
        assert row is not None
        assert row.status == CredentialStatus.PENDING.value

    def test_a_credential_with_no_fingerprint_is_refused(self, db) -> None:
        """base64 text is not canonical — padding and alphabet variants would
        each enrol separately, defeating the uniqueness constraint."""
        target = _target(db)
        with pytest.raises(TransitionRefusedError, match="fingerprint"):
            enrol_credential(
                db,
                EnrolCredentialCommand(
                    command_id=_cmd(),
                    target_id=target.id,
                    key_id="k1",
                    public_key_b64="AAAA",
                    public_key_fingerprint="",
                    enrollment_authority="platform_admin_policy",
                ),
            )


# ── Plans ───────────────────────────────────────────────────────────────────


class TestPlansFreezeAndSupersede:
    def test_proposing_freezes_a_snapshot_and_a_digest(self, db) -> None:
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        assert plan.status == PlanStatus.PROPOSED.value
        # CANONICAL, not bare hex. Through `0.1.0a4` this column held 64
        # characters that could not say which algorithm produced them, while
        # `spec_digest` ten lines away produced the prefixed form — one kind of
        # value with two encodings, compared with `!=`.
        assert plan.plan_digest and re.fullmatch(
            r"sha256:[0-9a-f]{64}", plan.plan_digest
        ), plan.plan_digest
        assert PlanDigestV1.parse(plan.plan_digest) == PlanDigestV1.over_json(
            plan.snapshot
        )
        assert plan.desired_revision == target.desired_revision
        assert plan.snapshot["release_ref"] == "dotmac_sub@7.187.1"

    def test_the_snapshot_digest_is_deterministic(self, db) -> None:
        """If it is not, an approval goes stale on its own between two reads of
        unchanged data."""
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        assert snapshot_digest(plan.snapshot) == plan.plan_digest

    def test_a_later_plan_supersedes_an_earlier_undecided_one(self, db) -> None:
        """Two proposed plans for one target would let an operator approve the
        older one and roll out state that has since been replaced."""
        target = _desired(db, _target(db).id)
        first = _plan(db, target.id)
        _desired(db, target.id, spec={"replicas": 5})
        second = _plan(db, target.id)
        stale = get_plan(db, first.id)
        assert stale is not None
        assert stale.status == PlanStatus.SUPERSEDED.value
        assert stale.superseded_by_id == second.id

    def test_a_target_with_no_desired_release_cannot_be_planned(self, db) -> None:
        target = _target(db)
        # A registered-but-undeclared target is not active, so this is caught by
        # the status guard first — which is the correct order: an inactive target
        # is not planned for at all.
        with pytest.raises(PlanRefusedError, match="active"):
            _plan(db, target.id)

    def test_a_suspended_target_cannot_be_planned_for(self, db) -> None:
        target = _desired(db, _target(db).id)
        suspend_target(db, TargetTransitionCommand(_cmd(), target.id))
        with pytest.raises(PlanRefusedError, match="active"):
            _plan(db, target.id)

    def test_a_plan_requiring_approval_must_name_its_policy(self, db) -> None:
        """Otherwise the decision stops being explainable the moment the policy
        changes."""
        target = _desired(db, _target(db).id)
        with pytest.raises(PlanRefusedError, match="name the policy"):
            _plan(db, target.id, approval_policy_code=None)

    def test_a_plan_with_a_rollout_cannot_be_cancelled(self, db) -> None:
        target = _desired(db, _target(db).id)
        plan = _approved_plan(db, target.id)
        _rollout(db, plan.id)
        with pytest.raises(TransitionRefusedError, match="already has a rollout"):
            cancel_plan(db, command_id=_cmd(), plan_id=plan.id)


# ── Approval binding ────────────────────────────────────────────────────────


class TestApprovalBindsToThePlanDigest:
    def test_matching_evidence_approves(self, db) -> None:
        target = _desired(db, _target(db).id)
        plan = _approved_plan(db, target.id)
        assert plan.status == PlanStatus.APPROVED.value
        # Naive comparison: SQLite has no tz-aware type and returns the
        # stored instant naive; Postgres returns it aware. The property under
        # test is that the DECIDING owner's clock was recorded rather than
        # this module's, and that survives the normalisation.
        assert plan.approved_at is not None
        assert plan.approved_at.replace(tzinfo=None) == _NOW.replace(tzinfo=None)

    def test_a_mismatched_digest_is_refused(self, db) -> None:
        """The blast radius of a transferable approval here is other people's
        running systems."""
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        with pytest.raises(ApprovalRefusedError, match="plan changed"):
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(), plan_id=plan.id, evidence=_evidence("f" * 64)
                ),
            )

    def test_the_same_digest_in_a4s_ENCODING_still_authorizes(self, db) -> None:
        """THE DEFECT `0.1.0a5` WAS CUT FOR, and its sensitivity proof.

        The evidence carries a4's bare-hex rendering of the plan's OWN digest.
        As strings the two values differ, so a4's `evidence.content_digest !=
        row.plan_digest` refused this and said the plan had changed — a
        security refusal standing in for a formatting bug.

        This test cannot be satisfied by a string comparison, which is what
        makes it worth its length rather than a restatement of the happy path.
        """
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        a4_form = PlanDigestV1.parse(plan.plan_digest or "").a4_bare_hex
        assert a4_form != plan.plan_digest, "the two encodings must differ here"
        approved = approve_plan(
            db,
            ApprovePlanCommand(
                command_id=_cmd(), plan_id=plan.id, evidence=_evidence(a4_form)
            ),
        )
        assert approved.status == PlanStatus.APPROVED.value

    @pytest.mark.parametrize(
        "unreadable",
        [
            "",
            "not-a-digest",
            "SHA256:" + "a" * 64,
            "sha256:" + "A" * 64,
            "md5:" + "a" * 32,
        ],
        ids=[
            "empty",
            "prose",
            "uppercase-algorithm",
            "uppercase-hex",
            "wrong-algorithm",
        ],
    )
    def test_an_unreadable_digest_is_an_encoding_fault_not_a_mutation(
        self, db, unreadable: str
    ) -> None:
        """A caller who sends something unreadable must not be told the plan
        changed. The two findings have different readers and different repairs,
        and collapsing them is what made a4's refusal look like the system
        working."""
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        with pytest.raises(DigestEncodingError) as raised:
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(), plan_id=plan.id, evidence=_evidence(unreadable)
                ),
            )
        message = str(raised.value).lower()
        assert "plan changed" not in message, raised.value
        assert "no comparison was made" in message, raised.value
        assert not isinstance(raised.value, ApprovalRefusedError)

    def test_a_stale_digest_is_still_reported_as_a_changed_plan(self, db) -> None:
        """THE OTHER HALF. Separating the encoding fault from the mutation must
        not have loosened the binding — a fix that made everything approve
        would satisfy every test above."""
        target = _desired(db, _target(db).id)
        first = _plan(db, target.id)
        _desired(db, target.id, spec={"replicas": 9})
        second = _plan(db, target.id)
        assert second.plan_digest != first.plan_digest
        with pytest.raises(ApprovalRefusedError, match="plan changed"):
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(),
                    plan_id=second.id,
                    evidence=_evidence(first.plan_digest or ""),
                ),
            )

    def test_evidence_naming_a_different_policy_is_refused(self, db) -> None:
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        with pytest.raises(ApprovalRefusedError, match="policy"):
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(),
                    plan_id=plan.id,
                    evidence=_evidence(
                        plan.plan_digest or "", policy_code="deployment.pilot"
                    ),
                ),
            )

    def test_evidence_naming_a_different_policy_version_is_refused(self, db) -> None:
        """Policy revisions differ in quorum and eligibility. An approval under
        v3 is not an approval under v4."""
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        with pytest.raises(ApprovalRefusedError, match="policy version"):
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(),
                    plan_id=plan.id,
                    evidence=_evidence(plan.plan_digest or "", policy_version=3),
                ),
            )

    def test_approving_a_plan_that_needs_no_approval_is_refused(self, db) -> None:
        """Recording a decision nothing asked for would make the approval trail
        say something untrue about what was reviewed."""
        target = _desired(db, _target(db).id)
        plan = _plan(
            db,
            target.id,
            requires_approval=False,
            approval_policy_code=None,
            approval_policy_version=None,
        )
        with pytest.raises(ApprovalRefusedError, match="does not require approval"):
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(),
                    plan_id=plan.id,
                    evidence=_evidence(plan.plan_digest or ""),
                ),
            )


# ── Rollouts ────────────────────────────────────────────────────────────────


class TestRolloutsOnlyRunApprovedPlans:
    def test_an_unapproved_sensitive_plan_cannot_be_rolled_out(self, db) -> None:
        """The one thing the approval gate exists to prevent."""
        target = _desired(db, _target(db).id)
        plan = _plan(db, target.id)
        with pytest.raises(ApprovalRefusedError, match="requires approval"):
            _rollout(db, plan.id)

    def test_an_approval_exempt_plan_can_be_rolled_out_directly(self, db) -> None:
        """Sensitivity is a product policy declared per plan, not inferred from
        the environment — a pilot's rollout needs no ceremony."""
        target = _desired(db, _target(db).id)
        plan = _plan(
            db,
            target.id,
            requires_approval=False,
            approval_policy_code=None,
            approval_policy_version=None,
        )
        rollout = _rollout(db, plan.id)
        assert rollout.status == RolloutStatus.REQUESTED.value

    def test_a_suspended_target_cannot_be_rolled_out_to(self, db) -> None:
        target = _desired(db, _target(db).id)
        plan = _approved_plan(db, target.id)
        suspend_target(db, TargetTransitionCommand(_cmd(), target.id))
        with pytest.raises(TransitionRefusedError, match="excluded from rollouts"):
            _rollout(db, plan.id)

    def test_requesting_the_same_rollout_ref_twice_is_idempotent(self, db) -> None:
        target = _desired(db, _target(db).id)
        plan = _approved_plan(db, target.id)
        ref = f"rol-{uuid.uuid4().hex[:8]}"
        first = request_rollout(
            db,
            RequestRolloutCommand(
                _cmd(), ref, plan.id, datetime(2099, 1, 1, tzinfo=UTC), _NOW
            ),
            signer=SIGNER,
        )
        second = request_rollout(
            db,
            RequestRolloutCommand(
                _cmd(), ref, plan.id, datetime(2099, 1, 1, tzinfo=UTC), _NOW
            ),
            signer=SIGNER,
        )
        assert first.id == second.id


class TestDispatchCarriesThePlanNotTheCurrentState:
    def test_the_intent_carries_the_frozen_plan_and_its_digest(self, db) -> None:
        """The single most consequential property in this module: editing the
        desired state after approval must not change what is dispatched."""
        target = _desired(db, _target(db).id)
        plan = _approved_plan(db, target.id)
        rollout = _rollout(db, plan.id)

        # The desired state moves on AFTER approval.
        _desired(db, target.id, release_ref="dotmac_sub@9.0.0", spec={"replicas": 99})

        intent = dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        assert (
            intent.release_ref == "dotmac_sub@7.187.1"
        ), "dispatch must carry the APPROVED plan, not the newest desired state"
        assert intent.spec == {"replicas": 2}
        assert intent.plan_digest == plan.plan_digest
        assert intent.attempt_no == 1

    def test_the_intent_is_provider_neutral(self, db) -> None:
        """No endpoint, credential reference, transport name or retry policy —
        those are the Integrator's (ADR-0024)."""
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        intent = dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        fields = set(intent.__dataclass_fields__)
        for forbidden in (
            "endpoint",
            "endpoint_url",
            "credential",
            "credential_ref",
            "transport",
            "retry_policy",
            "connection_ref",
        ):
            assert forbidden not in fields

    def test_two_attempts_cannot_be_in_flight_at_once(self, db) -> None:
        """Two deliveries racing to converge one target is the failure this
        prevents."""
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        with pytest.raises(TransitionRefusedError, match="already has attempt"):
            dispatch_attempt(
                db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
            )

    def test_retry_is_the_same_operation_as_dispatch(self, db) -> None:
        """There is no separate `retry()` with different rules, because a retry
        that took a different path from the first attempt is a retry nobody
        tested."""
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        first = dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=first.attempt_no,
                outcome=AttemptOutcome.FAILED.value,
                error_code="unreachable",
            ),
        )
        second = dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        assert second.attempt_no == 2
        assert second.plan_digest == first.plan_digest


class TestSettlingAnAttempt:
    def _dispatched(self, db):  # type: ignore[no-untyped-def]
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        return rollout

    def test_a_succeeded_attempt_succeeds_the_rollout(self, db) -> None:
        rollout = self._dispatched(db)
        view = settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.SUCCEEDED.value,
                integrator_ref="ig-1",
            ),
        )
        assert view.status == RolloutStatus.SUCCEEDED.value
        assert view.completed_at is not None

    def test_transport_settlement_does_not_rewrite_signed_authorization(
        self, db
    ) -> None:
        """Transport outcome and authorization issuance are different facts.

        Settling an Integrator attempt may move rollout state. It cannot edit
        the portable statement that authorized the attempt, and the settlement
        command has no field through which a transport could supply one.
        """
        rollout = self._dispatched(db)
        stored = db.get(Rollout, rollout.id)
        assert stored is not None
        before = copy.deepcopy(stored.authorization_envelope)

        settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.SUCCEEDED.value,
                integrator_ref="ig-settlement-only",
            ),
        )

        db.refresh(stored)
        assert stored.authorization_envelope == before
        assert "authorization_envelope" not in SettleAttemptCommand.__dataclass_fields__

    def test_revoking_the_approval_does_not_rewrite_an_issued_authorization(
        self, db
    ) -> None:
        """AN ISSUED AUTHORIZATION IS HISTORY, and revocation is not a rewrite.

        The two facts are easy to collapse and must not be. Revoking an approval
        withdraws the authority to issue anything NEW; it cannot reach backwards
        into a statement that was already signed and handed to an executor. The
        bytes were true when they were signed, something acted on them, and a
        record that edited itself afterwards would destroy the only evidence of
        what was actually authorized.

        The opposite error is just as bad, so both halves are asserted here: the
        stored envelope is byte-identical afterwards, AND the revoked plan can no
        longer produce a new one.
        """
        rollout = self._dispatched(db)
        stored = db.get(Rollout, rollout.id)
        assert stored is not None
        before = copy.deepcopy(stored.authorization_envelope)
        assert before, "the fixture did not actually issue an authorization"

        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(),
                plan_id=stored.plan_id,
                revocation_ref="apr-rev-after-issue",
                reason="withdrawn after the authorization was already issued",
            ),
        )

        db.refresh(stored)
        assert stored.authorization_envelope == before, (
            "revoking the approval rewrote an authorization that had already "
            "been issued and acted on"
        )

        # And the forward half: the withdrawal is what it is for.
        with pytest.raises(ApprovalRefusedError):
            request_rollout(
                db,
                RequestRolloutCommand(
                    command_id=_cmd(),
                    rollout_ref=f"rol-after-revoke-{uuid.uuid4().hex[:8]}",
                    plan_id=stored.plan_id,
                    authorization_expires_at=_NOW + timedelta(minutes=30),
                ),
            )

    def test_a_failed_attempt_leaves_the_rollout_retryable(self, db) -> None:
        """One transport error is not a deployment decision. Treating it as one
        turns every transient failure into something an operator has to undo."""
        rollout = self._dispatched(db)
        view = settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.FAILED.value,
                error_code="timeout",
            ),
        )
        assert view.status == RolloutStatus.FAILED.value
        assert view.completed_at is None, "a failed rollout is not settled"
        # And it can still be dispatched again.
        assert dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )

    def test_timed_out_is_a_distinct_state_from_failed(self, db) -> None:
        """A failure means something reported an error; a timeout means nothing
        reported at all, and the second is far more likely a transport problem."""
        rollout = self._dispatched(db)
        view = settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.TIMED_OUT.value,
            ),
        )
        assert view.status == RolloutStatus.TIMED_OUT.value

    def test_an_attempt_cannot_be_settled_twice(self, db) -> None:
        rollout = self._dispatched(db)
        command = SettleAttemptCommand(
            command_id=_cmd(),
            rollout_id=rollout.id,
            attempt_no=1,
            outcome=AttemptOutcome.SUCCEEDED.value,
        )
        settle_attempt(db, command)
        with pytest.raises(TransitionRefusedError, match="already settled"):
            settle_attempt(
                db,
                SettleAttemptCommand(
                    command_id=_cmd(),
                    rollout_id=rollout.id,
                    attempt_no=1,
                    outcome=AttemptOutcome.FAILED.value,
                ),
            )

    def test_replaying_a_settle_command_is_idempotent(self, db) -> None:
        rollout = self._dispatched(db)
        command = SettleAttemptCommand(
            command_id="cmd-fixed",
            rollout_id=rollout.id,
            attempt_no=1,
            outcome=AttemptOutcome.SUCCEEDED.value,
        )
        first = settle_attempt(db, command)
        second = settle_attempt(db, command)
        assert first.record_version == second.record_version

    def test_settling_an_attempt_that_does_not_exist_is_refused(self, db) -> None:
        rollout = self._dispatched(db)
        with pytest.raises(TransitionRefusedError, match="no attempt"):
            settle_attempt(
                db,
                SettleAttemptCommand(
                    command_id=_cmd(),
                    rollout_id=rollout.id,
                    attempt_no=99,
                    outcome=AttemptOutcome.SUCCEEDED.value,
                ),
            )


class TestCancelIsNotManualRepair:
    def _dispatched(self, db):  # type: ignore[no-untyped-def]
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        return rollout

    def test_cancelling_settles_the_rollout_and_its_in_flight_attempt(self, db) -> None:
        """Leaving an attempt PENDING would block the next dispatch forever on a
        rollout nobody is waiting for."""
        rollout = self._dispatched(db)
        view = cancel_rollout(
            db, RolloutTransitionCommand(_cmd(), rollout.id, reason="withdrawn")
        )
        assert view.status == RolloutStatus.CANCELLED.value
        assert view.completed_at is not None
        assert view.attempts[0].outcome == AttemptOutcome.CANCELLED.value

    def test_manual_repair_keeps_the_rollout_open(self, db) -> None:
        """A cancelled rollout is not wanted; a repairing one is wanted and
        stuck. An operator's queue must tell them apart."""
        rollout = self._dispatched(db)
        view = require_manual_repair(
            db, RolloutTransitionCommand(_cmd(), rollout.id, reason="disk full")
        )
        assert view.status == RolloutStatus.MANUAL_REPAIR.value
        assert view.completed_at is None
        assert view.attempts[0].outcome == AttemptOutcome.PENDING.value

    def test_a_succeeded_rollout_cannot_be_cancelled(self, db) -> None:
        rollout = self._dispatched(db)
        settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.SUCCEEDED.value,
            ),
        )
        with pytest.raises(TransitionRefusedError, match="settled"):
            cancel_rollout(db, RolloutTransitionCommand(_cmd(), rollout.id))

    def test_a_settled_rollout_cannot_be_dispatched_again(self, db) -> None:
        rollout = self._dispatched(db)
        cancel_rollout(db, RolloutTransitionCommand(_cmd(), rollout.id))
        with pytest.raises(TransitionRefusedError, match="not retried"):
            dispatch_attempt(
                db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
            )


# ── Drift, before anything has been observed ────────────────────────────────


class TestDriftIsSilentUntilThereIsEvidence:
    def test_a_never_observed_target_is_unknown_not_drifted(self, db) -> None:
        """A model that collapsed these would show every freshly registered
        target as a drift incident."""
        target = _desired(db, _target(db).id)
        report = drift(db, target.id)
        assert report is not None
        assert report.never_observed is True
        assert report.drifted is False

    def test_drift_is_computed_not_stored(self, db) -> None:
        """A cached flag would need invalidating by every desired-state edit,
        every observation and every rollout — three writers for one derived
        value."""
        from dotmac_deployment_control import DeploymentTarget

        columns = set(DeploymentTarget.__table__.columns.keys())
        for forbidden in ("is_drifted", "drifted", "drift_status", "in_sync"):
            assert forbidden not in columns


# ── Transaction authority ───────────────────────────────────────────────────


class TestTheModuleOwnsNoTransaction:
    def test_nothing_is_committed_so_a_rollback_discards_it(self, db) -> None:
        """Hard rule 8. If the service committed, the rollback below would not
        remove the row — which is exactly what this asserts against."""
        target = _target(db)
        db.rollback()
        assert get_target(db, target.id) is None
        assert get_rollout(db, uuid.uuid4()) is None
