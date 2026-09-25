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
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.idempotency import purge_expired
from dotmac_kernel.idempotency_models import (
    INBOX_SCOPE,
    IdempotencyStatus,
    PlatformIdempotencyRecord,
)
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.host_admission_coordinator as admission_coordinator
import dotmac_deployment_control.service as control_service
from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovalRefusedError,
    ApprovePlanCommand,
    AttemptOutcome,
    AuthorizationEnvelopeV1,
    AuthorizationEnvelopeV2,
    CredentialTransitionCommand,
    DeploymentControlError,
    DesiredDeployment,
    DigestEncodingError,
    DispatchEnvelopeV1,
    EnrolCredentialCommand,
    EnrolHostAdmissionCredentialCommand,
    ExpectedStateError,
    FoundationDispatchConsumptionV1,
    FoundationExecutionContextV1,
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
    activate_credential,
    approve_plan,
    cancel_plan,
    cancel_rollout,
    credential_is_eligible,
    decommission_target,
    dispatch_attempt,
    drift,
    enrol_credential,
    enrol_host_admission_credential,
    get_plan,
    get_rollout,
    get_target,
    install_foundation_consumption_security,
    lookup_foundation_execution_consumption,
    module,
    propose_plan,
    register_target,
    request_rollout,
    require_manual_repair,
    retire_credential,
    revoke_plan_approval,
    set_desired_state,
    settle_attempt,
    snapshot_digest,
    suspend_target,
)
from dotmac_deployment_control.attestation_trust_registry import (
    AttestationRootDescriptorTerms,
    enrol_root,
)
from dotmac_deployment_control.foundation_consumption import (
    _receipt_from_pair,
    _reset_foundation_consumption_security_for_tests,
)
from dotmac_deployment_control.host_admission import (
    HostAdmissionPresentationStatementV1,
    HostAdmissionPresentationV1,
)
from dotmac_deployment_control.host_admission_coordinator import (
    HostAdmissionForeignVerificationEvidenceV1,
    HostAdmissionRefusalCode,
    HostAdmissionRefusedError,
    admit_and_consume_host_admission,
    install_host_admission_security,
    resolve_host_admission_context,
)
from dotmac_deployment_control.host_admission_service import (
    BindTargetHostCommand,
    SetTargetAdmissionPolicyCommand,
    bind_target_host,
    rotate_target_host,
    set_target_admission_policy,
)
from dotmac_deployment_control.models import (
    Rollout,
    RolloutAttempt,
    RolloutAttemptSettlement,
)
from tests.authorization_support import SIGNER, VERIFIER
from tests.dispatch_support import (
    DISPATCH_SIGNER,
    DISPATCH_VERIFIER,
    TestDispatchSigner,
)
from tests.execution_observation_support import observation_public_key_b64

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


@pytest.fixture(autouse=True)
def _fixed_control_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control_service, "_control_now", lambda: _NOW)


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
        "purpose": "foundation_execution",
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
                algorithm="test-sha256",
                public_key_b64=observation_public_key_b64("k1"),
                enrollment_authority="platform_admin_policy",
            ),
        )
        row = db.get(TargetCredential, credential_id)
        assert row is not None
        assert row.status == CredentialStatus.PENDING.value

    def test_a_credential_with_noncanonical_key_bytes_is_refused(self, db) -> None:
        """Control derives the fingerprint only from canonical base64url bytes."""
        target = _target(db)
        with pytest.raises(DigestEncodingError, match="canonical unpadded base64url"):
            enrol_credential(
                db,
                EnrolCredentialCommand(
                    command_id=_cmd(),
                    target_id=target.id,
                    key_id="k1",
                    algorithm="test-sha256",
                    public_key_b64="not*base64url",
                    enrollment_authority="platform_admin_policy",
                ),
            )

    def test_retirement_closes_the_active_half_open_window(
        self, db, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from dotmac_deployment_control import CredentialStatus, TargetCredential

        target = _target(db)
        credential_id = enrol_credential(
            db,
            EnrolCredentialCommand(
                command_id=_cmd(),
                target_id=target.id,
                key_id="retire-k1",
                algorithm="test-sha256",
                public_key_b64=observation_public_key_b64("retire-k1"),
                enrollment_authority="platform_admin_policy",
            ),
        )
        activate_credential(
            db,
            CredentialTransitionCommand(command_id=_cmd(), credential_id=credential_id),
        )
        active = db.get(TargetCredential, credential_id)
        assert active is not None
        active.activated_at = _NOW
        db.flush()
        monkeypatch.setattr(
            control_service, "_control_now", lambda: _NOW + timedelta(minutes=1)
        )
        retire_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
                reason="planned successor",
            ),
        )
        row = db.get(TargetCredential, credential_id)
        assert row is not None
        assert row.status == CredentialStatus.RETIRED.value
        assert row.retired_at is not None
        assert credential_is_eligible(db, row.key_id, at=_NOW) == (
            True,
            target.target_ref,
        )
        assert credential_is_eligible(db, row.key_id, at=row.retired_at) == (
            False,
            target.target_ref,
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

    def test_a_v1_authorization_remains_readable_only_as_historical_v1(
        self, db
    ) -> None:
        """Reading old rows is not silently promoting their authority.

        Production can hold a9 rollouts after a10 is installed. The operator
        read path must retain those bytes and their exact V1 type, while the
        dispatch path remains V2-only.
        """
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        stored = db.get(Rollout, rollout.id)
        assert stored is not None and stored.authorization_envelope is not None
        historical = copy.deepcopy(stored.authorization_envelope)
        statement = historical["statement"]
        statement["version"] = 1
        statement.pop("purpose")
        statement.pop("control_version")
        statement.pop("execution_sequence")
        statement.pop("public_key_fingerprint")
        stored.authorization_envelope = historical
        db.flush()

        view = get_rollout(db, rollout.id)
        assert view is not None
        assert isinstance(view.authorization_envelope, AuthorizationEnvelopeV1)
        assert not isinstance(view.authorization_envelope, AuthorizationEnvelopeV2)


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
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
        assert (
            intent.release_ref == "dotmac_sub@7.187.1"
        ), "dispatch must carry the APPROVED plan, not the newest desired state"
        assert intent.spec == {"replicas": 2}
        assert intent.plan_digest == plan.plan_digest
        assert intent.attempt_no == 1
        assert intent.dispatch_envelope.statement.attempt_no == 1
        assert "attempt_no" not in intent.__dataclass_fields__

    def test_replay_returns_the_exact_stored_dispatch_without_resigning(
        self, db
    ) -> None:
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        signer = TestDispatchSigner()
        command_id = _cmd()

        first = dispatch_attempt(
            db,
            command_id=command_id,
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=signer,
        )
        second = dispatch_attempt(
            db,
            command_id=command_id,
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=signer,
        )

        assert signer.calls == 1
        assert first.dispatch_envelope.canonical_bytes == (
            second.dispatch_envelope.canonical_bytes
        )
        assert (
            DispatchEnvelopeV1.parse(first.dispatch_envelope.as_mapping())
            == first.dispatch_envelope
        )

    def test_pre_a11_replay_is_a_typed_refusal_not_a_key_error(self, db) -> None:
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        command_id = _cmd()
        db.add(
            RolloutAttempt(
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.PENDING.value,
                dispatched_at=_NOW,
                dispatch_envelope=None,
            )
        )
        db.add(
            PlatformIdempotencyRecord(
                scope=INBOX_SCOPE,
                key=command_id,
                operation="deployment.dispatch_attempt",
                status=IdempotencyStatus.EXECUTED.value,
                result={"attempt_no": 1},
            )
        )
        db.flush()

        with pytest.raises(TransitionRefusedError, match="predates the signed"):
            dispatch_attempt(
                db,
                command_id=command_id,
                rollout_id=rollout.id,
                verifier=VERIFIER,
                dispatch_signer=DISPATCH_SIGNER,
            )

    @pytest.mark.parametrize(
        "result",
        [
            {"attempt_id": "not-a-uuid"},
            {"attempt_id": str(uuid.uuid4()), "attempt_no": 1},
            {"attempt": 1},
        ],
    )
    def test_malformed_or_mixed_dispatch_replay_result_is_typed_refusal(
        self, db, result: dict[str, object]
    ) -> None:
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        command_id = _cmd()
        db.add(
            PlatformIdempotencyRecord(
                scope=INBOX_SCOPE,
                key=command_id,
                operation="deployment.dispatch_attempt",
                status=IdempotencyStatus.EXECUTED.value,
                result=result,
            )
        )
        db.flush()

        with pytest.raises(TransitionRefusedError, match="dispatch idempotency"):
            dispatch_attempt(
                db,
                command_id=command_id,
                rollout_id=rollout.id,
                verifier=VERIFIER,
                dispatch_signer=DISPATCH_SIGNER,
            )

    def test_the_intent_is_provider_neutral(self, db) -> None:
        """No endpoint, credential reference, transport name or retry policy —
        those are the Integrator's (ADR-0024)."""
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        intent = dispatch_attempt(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
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
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
        with pytest.raises(TransitionRefusedError, match="already has attempt"):
            dispatch_attempt(
                db,
                command_id=_cmd(),
                rollout_id=rollout.id,
                verifier=VERIFIER,
                dispatch_signer=DISPATCH_SIGNER,
            )

    def test_retry_is_the_same_operation_as_dispatch(self, db) -> None:
        """There is no separate `retry()` with different rules, because a retry
        that took a different path from the first attempt is a retry nobody
        tested."""
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        first = dispatch_attempt(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
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
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
        assert second.attempt_no == 2
        assert second.plan_digest == first.plan_digest


class TestSettlingAnAttempt:
    def _dispatched(self, db):  # type: ignore[no-untyped-def]
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        dispatch_attempt(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
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

    def test_settlement_preserves_issuance_and_drives_the_returned_projection(
        self, db
    ) -> None:
        """A delivery report appends outcome evidence; it cannot edit issuance."""
        rollout = self._dispatched(db)
        attempt = db.query(RolloutAttempt).filter_by(rollout_id=rollout.id).one()
        issuance = (
            attempt.outcome,
            attempt.integrator_ref,
            attempt.error_code,
            attempt.detail,
            attempt.settled_at,
        )

        view = settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=attempt.attempt_no,
                outcome=AttemptOutcome.FAILED.value,
                integrator_ref="ig-immutable-issuance",
                error_code="transport_refused",
                detail="provider-neutral diagnostic",
            ),
        )

        db.refresh(attempt)
        assert (
            attempt.outcome,
            attempt.integrator_ref,
            attempt.error_code,
            attempt.detail,
            attempt.settled_at,
        ) == issuance
        settlement = (
            db.query(RolloutAttemptSettlement).filter_by(attempt_id=attempt.id).one()
        )
        assert settlement.outcome == AttemptOutcome.FAILED.value
        assert settlement.integrator_ref == "ig-immutable-issuance"
        assert view.attempts[0].outcome == AttemptOutcome.FAILED.value
        assert view.attempts[0].error_code == "transport_refused"

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
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
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
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
        return rollout

    def test_cancelling_settles_the_rollout_and_its_in_flight_attempt(self, db) -> None:
        """Leaving an attempt PENDING would block the next dispatch forever on a
        rollout nobody is waiting for."""
        rollout = self._dispatched(db)
        attempt = db.query(RolloutAttempt).filter_by(rollout_id=rollout.id).one()
        issuance = (
            attempt.outcome,
            attempt.integrator_ref,
            attempt.error_code,
            attempt.detail,
            attempt.settled_at,
        )
        view = cancel_rollout(
            db, RolloutTransitionCommand(_cmd(), rollout.id, reason="withdrawn")
        )
        assert view.status == RolloutStatus.CANCELLED.value
        assert view.completed_at is not None
        assert view.attempts[0].outcome == AttemptOutcome.CANCELLED.value
        db.refresh(attempt)
        assert (
            attempt.outcome,
            attempt.integrator_ref,
            attempt.error_code,
            attempt.detail,
            attempt.settled_at,
        ) == issuance
        assert attempt.settlement is not None
        assert attempt.settlement.outcome == AttemptOutcome.CANCELLED.value

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
                db,
                command_id=_cmd(),
                rollout_id=rollout.id,
                verifier=VERIFIER,
                dispatch_signer=DISPATCH_SIGNER,
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


class TestDispatchConsumptionStaging:
    """SQLite proves service wiring only; PostgreSQL race proof lives separately."""

    _CANDIDATE_DIGEST = "sha256:" + "ca" * 32
    _INSTALLED_DIGEST = "sha256:" + "1d" * 32

    def test_direct_f2_only_stage_cannot_create_a_marker(self, db: Session) -> None:
        attempt = self._attempt(db)
        arguments = {
            "attempt_id": attempt.id,
            "expected_target": self._expected_target(db, attempt),
            "candidate_attestation_envelope_digest": self._CANDIDATE_DIGEST,
            "installed_attestation_envelope_digest": self._INSTALLED_DIGEST,
        }
        with pytest.raises(TypeError, match="foundation_expected"):
            control_service._stage_dispatch_consumption(db, **arguments)
        with pytest.raises(TypeError, match="verified Foundation V3 expectation"):
            control_service._stage_dispatch_consumption(
                db, **arguments, foundation_expected=None
            )
        assert (
            db.query(PlatformIdempotencyRecord).filter_by(key=str(attempt.id)).count()
            == 0
        )

    @staticmethod
    def _verified_expected(
        db: Session, attempt_id: uuid.UUID
    ) -> control_service._ExpectedFoundationConsumption:
        attempt = db.get(RolloutAttempt, attempt_id)
        assert attempt is not None and attempt.dispatch_envelope is not None
        rollout = db.get(Rollout, attempt.rollout_id)
        assert rollout is not None and rollout.authorization_envelope is not None
        authorization = AuthorizationEnvelopeV2.parse(rollout.authorization_envelope)
        dispatch = DispatchEnvelopeV1.parse(attempt.dispatch_envelope)
        receipt = _receipt_from_pair(authorization, dispatch)
        context = FoundationExecutionContextV1(
            product_code=receipt.product_code,
            environment=receipt.environment,
            target_id=receipt.target_id,
            target_ref=receipt.target_ref,
            operation=receipt.operation,
            release_ref=receipt.release_ref,
            rollout_ref=receipt.rollout_ref,
            plan_id=receipt.plan_id,
            approval_decision_ref=receipt.approval_decision_ref,
            control_plan_digest=receipt.control_plan_digest,
            execution_sequence=receipt.execution_sequence,
            attempt_no=receipt.attempt_no,
        )
        return control_service._ExpectedFoundationConsumption(
            authorization=authorization,
            dispatch=dispatch,
            context=context,
            execution_plan_digest=receipt.execution_plan_digest,
        )

    def _stage(
        self,
        db: Session,
        *,
        attempt_id: uuid.UUID,
        expected_target: control_service._ExpectedDispatchTarget,
    ):
        return control_service._stage_dispatch_consumption(
            db,
            attempt_id=attempt_id,
            expected_target=expected_target,
            candidate_attestation_envelope_digest=self._CANDIDATE_DIGEST,
            installed_attestation_envelope_digest=self._INSTALLED_DIGEST,
            foundation_expected=self._verified_expected(db, attempt_id),
        )

    @staticmethod
    def _attempt(db: Session) -> RolloutAttempt:
        target = _desired(db, _target(db).id)
        rollout = _rollout(db, _approved_plan(db, target.id).id)
        dispatch_attempt(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
        return db.query(RolloutAttempt).filter_by(rollout_id=rollout.id).one()

    @staticmethod
    def _expected_target(
        db: Session, attempt: RolloutAttempt
    ) -> control_service._ExpectedDispatchTarget:
        rollout = db.get(Rollout, attempt.rollout_id)
        assert rollout is not None
        target = get_target(db, rollout.target_id)
        assert target is not None
        return control_service._ExpectedDispatchTarget(target.id, target.target_ref)

    def test_staging_writes_a_permanent_bare_fingerprint_receipt(
        self, db: Session
    ) -> None:
        attempt = self._attempt(db)

        staged = self._stage(
            db,
            attempt_id=attempt.id,
            expected_target=self._expected_target(db, attempt),
        )

        record = (
            db.query(PlatformIdempotencyRecord).filter_by(key=str(attempt.id)).one()
        )
        assert staged.dispatch_id == str(attempt.id)
        assert record.scope == "deployment.consume_dispatch_challenge.v1"
        assert record.fingerprint == control_service.admission_consumption_fingerprint(
            dispatch_envelope_digest=staged.dispatch_digest.canonical,
            candidate_attestation_envelope_digest=self._CANDIDATE_DIGEST,
            installed_attestation_envelope_digest=self._INSTALLED_DIGEST,
        )
        assert record.expires_at is None
        assert record.result["dispatch_digest"] == staged.dispatch_digest.canonical

    def test_commit_then_interruption_refuses_a_second_consumption(
        self, db: Session
    ) -> None:
        attempt = self._attempt(db)
        self._stage(
            db,
            attempt_id=attempt.id,
            expected_target=self._expected_target(db, attempt),
        )
        db.commit()  # Simulates a process dying after durable authority cut-off.

        with pytest.raises(control_service._DispatchConsumptionRefusedError) as caught:
            self._stage(
                db,
                attempt_id=attempt.id,
                expected_target=self._expected_target(db, attempt),
            )

        assert (
            caught.value.code
            is control_service._DispatchConsumptionRefusalCode.ALREADY_CONSUMED
        )

    def test_same_dispatch_with_changed_evidence_is_an_integrity_conflict(
        self, db: Session
    ) -> None:
        attempt = self._attempt(db)
        expected = self._expected_target(db, attempt)
        self._stage(db, attempt_id=attempt.id, expected_target=expected)
        db.commit()

        with pytest.raises(control_service._DispatchConsumptionRefusedError) as caught:
            control_service._stage_dispatch_consumption(
                db,
                attempt_id=attempt.id,
                expected_target=expected,
                candidate_attestation_envelope_digest="sha256:" + "ee" * 32,
                installed_attestation_envelope_digest=self._INSTALLED_DIGEST,
                foundation_expected=self._verified_expected(db, attempt.id),
            )
        assert (
            caught.value.code
            is control_service._DispatchConsumptionRefusalCode.INTEGRITY_CONFLICT
        )

    def test_kernel_expiry_sweep_cannot_reclaim_a_consumed_dispatch(
        self, db: Session
    ) -> None:
        attempt = self._attempt(db)
        self._stage(
            db,
            attempt_id=attempt.id,
            expected_target=self._expected_target(db, attempt),
        )
        db.commit()

        removed = purge_expired(
            db,
            now=_NOW + timedelta(days=3650),
            scope="deployment.consume_dispatch_challenge.v1",
            platform=True,
        )

        assert removed == 0
        assert (
            db.query(PlatformIdempotencyRecord).filter_by(key=str(attempt.id)).count()
            == 1
        )

    def test_rollback_discards_the_marker_so_the_retry_can_stage(
        self, db: Session
    ) -> None:
        attempt = self._attempt(db)
        db.commit()
        self._stage(
            db,
            attempt_id=attempt.id,
            expected_target=self._expected_target(db, attempt),
        )
        db.rollback()

        staged = self._stage(
            db,
            attempt_id=attempt.id,
            expected_target=self._expected_target(db, attempt),
        )

        assert staged.dispatch_id == str(attempt.id)

    def test_committed_revocation_before_consumption_refuses(self, db: Session) -> None:
        attempt = self._attempt(db)
        rollout = db.get(Rollout, attempt.rollout_id)
        assert rollout is not None
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(),
                plan_id=rollout.plan_id,
                revocation_ref="withdrawn-decision",
            ),
        )
        db.commit()

        with pytest.raises(control_service._DispatchConsumptionRefusedError) as caught:
            self._stage(
                db,
                attempt_id=attempt.id,
                expected_target=self._expected_target(db, attempt),
            )

        assert (
            caught.value.code
            is control_service._DispatchConsumptionRefusalCode.APPROVAL_NOT_STANDING
        )

    def test_a_suspended_target_refuses_even_with_the_correct_coordinate(
        self, db: Session
    ) -> None:
        """`COORDINATE_MISMATCH` and `TARGET_NOT_LIVE` are two different
        faults sharing one raise site's neighbourhood, not one composite
        condition: suspension changes `status`, never `id`/`target_ref`, so
        the coordinate check at the top of the function passes and control
        reaches the later status check instead."""
        attempt = self._attempt(db)
        expected_target = self._expected_target(db, attempt)
        rollout = db.get(Rollout, attempt.rollout_id)
        assert rollout is not None
        suspend_target(db, TargetTransitionCommand(_cmd(), rollout.target_id))
        db.commit()

        with pytest.raises(control_service._DispatchConsumptionRefusedError) as caught:
            self._stage(db, attempt_id=attempt.id, expected_target=expected_target)

        assert (
            caught.value.code
            is control_service._DispatchConsumptionRefusalCode.TARGET_NOT_LIVE
        )
        assert (
            db.query(PlatformIdempotencyRecord).filter_by(key=str(attempt.id)).count()
            == 0
        )

    def test_other_target_cannot_stage_this_attempt_or_write_a_marker(
        self, db: Session
    ) -> None:
        attempt = self._attempt(db)
        other = _desired(db, _target(db).id)
        supplied = control_service._ExpectedDispatchTarget(other.id, other.target_ref)

        with pytest.raises(control_service._DispatchConsumptionRefusedError) as caught:
            self._stage(db, attempt_id=attempt.id, expected_target=supplied)

        assert (
            caught.value.code
            is control_service._DispatchConsumptionRefusalCode.COORDINATE_MISMATCH
        )
        assert (
            db.query(PlatformIdempotencyRecord).filter_by(key=str(attempt.id)).count()
            == 0
        )


class _AdmissionClock:
    def now(self) -> datetime:
        return _NOW


class _AdmissionVerifier:
    def verify_host_admission_presentation(self, **values: object) -> bool:
        return (
            values["key_id"] == "admission-key-1"
            and values["purpose"] == "dotmac.control.host-admission-presentation.v1"
            and values["signature"] == "c2ln"
        )


@pytest.fixture(autouse=True)
def _installed_foundation_consumption_security() -> Generator[None, None, None]:
    _reset_foundation_consumption_security_for_tests()
    install_foundation_consumption_security(
        authorization_verifier=VERIFIER,
        dispatch_verifier=DISPATCH_VERIFIER,
        clock=_AdmissionClock(),
    )
    yield
    _reset_foundation_consumption_security_for_tests()


@pytest.fixture(autouse=True)
def _installed_host_admission_security() -> Generator[None, None, None]:
    admission_coordinator._reset_host_admission_security_for_tests()
    install_host_admission_security(
        verifier=_AdmissionVerifier(), clock=_AdmissionClock()
    )
    yield
    admission_coordinator._reset_host_admission_security_for_tests()


def _admission_fixture_inputs(
    db: Session, *, operation: str = "deploy"
) -> tuple[uuid.UUID, HostAdmissionPresentationV1]:
    target = _desired(db, _target(db).id)
    plan = _plan(db, target.id, operation=operation)
    approved = approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_cmd(),
            plan_id=plan.id,
            evidence=_evidence(plan.plan_digest or "", operation=operation),
        ),
    )
    rollout = _rollout(db, approved.id)
    dispatch_attempt(
        db,
        command_id=_cmd(),
        rollout_id=rollout.id,
        verifier=VERIFIER,
        dispatch_signer=DISPATCH_SIGNER,
    )
    attempt = db.query(RolloutAttempt).filter_by(rollout_id=rollout.id).one()
    dispatch = DispatchEnvelopeV1.parse(attempt.dispatch_envelope)

    credential_id = enrol_host_admission_credential(
        db,
        EnrolHostAdmissionCredentialCommand(
            command_id=_cmd(),
            target_id=target.id,
            key_id="admission-key-1",
            algorithm="ed25519",
            public_key_b64=observation_public_key_b64("admission-key-1"),
            enrollment_authority="control-test",
        ),
    )
    activate_credential(
        db,
        CredentialTransitionCommand(command_id=_cmd(), credential_id=credential_id),
    )
    bind_target_host(
        db,
        BindTargetHostCommand(
            target_id=target.id, host_id="host-one", authority="control-test"
        ),
    )
    set_target_admission_policy(
        db,
        SetTargetAdmissionPolicyCommand(
            target_id=target.id,
            candidate_root_subject="foundation-release",
            candidate_audience="foundation-candidate",
            installed_audience="foundation-installed",
            expected_foundation_package="dotmac-sub",
            authority="control-test",
        ),
    )
    for custody_domain, subject, purpose in (
        (
            "candidate_release_signer",
            "foundation-release",
            "dotmac.foundation.candidate-artifact.v2",
        ),
        ("host_attester", "host-one", "dotmac.foundation.installed-host.v2"),
    ):
        enrol_root(
            db,
            custody_domain=custody_domain,
            subject=subject,
            public_key_b64=observation_public_key_b64(subject),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/test/{subject}",
            enrolment_authority="control-test",
            descriptor=AttestationRootDescriptorTerms(
                issuer="control-test",
                attestation_key_id=f"attestation-{subject}",
                evidence_purpose=purpose,
                not_after=_NOW + timedelta(days=1),
            ),
            enrolled_at=_NOW - timedelta(days=1),
        )
    presentation = HostAdmissionPresentationV1(
        statement=HostAdmissionPresentationStatementV1(
            presentation_id="presentation-1",
            key_id="admission-key-1",
            dispatch_id=dispatch.statement.dispatch_id,
            candidate_attestation_envelope_digest="sha256:" + "ca" * 32,
            installed_attestation_envelope_digest="sha256:" + "1d" * 32,
            issued_at=_NOW,
            expires_at=_NOW + timedelta(minutes=5),
        ),
        signature="c2ln",
    )
    return attempt.id, presentation


def _resolve_admission_fixture(db: Session, *, operation: str = "deploy"):  # type: ignore[no-untyped-def]
    attempt_id, presentation = _admission_fixture_inputs(db, operation=operation)
    return resolve_host_admission_context(
        db, attempt_id=attempt_id, presentation=presentation
    )


def _matching_foreign_evidence(context) -> HostAdmissionForeignVerificationEvidenceV1:  # type: ignore[no-untyped-def]
    return HostAdmissionForeignVerificationEvidenceV1(
        candidate_attestation_envelope_digest=(
            context.presentation.statement.candidate_attestation_envelope_digest
        ),
        installed_attestation_envelope_digest=(
            context.presentation.statement.installed_attestation_envelope_digest
        ),
        verification_context_digest=context.context_digest,
        verified_host_identity=context.host_id,
        verified_observation_id=context.dispatch_id,
        verified_package=context.expected_foundation_package,
        verified_candidate_audience=context.candidate_audience,
        verified_installed_audience=context.installed_audience,
        verified_candidate_root=admission_coordinator.HostAdmissionForeignRootV1(
            public_key_fingerprint=context.candidate_root.public_key_fingerprint,
            root_version=context.candidate_root.root_version,
            key_id=context.candidate_root.key_id,
            algorithm=context.candidate_root.algorithm,
            purpose=context.candidate_root.purpose,
            custody_domain=context.candidate_root.custody_domain,
            issuer=context.candidate_root.issuer,
        ),
        verified_installed_root=admission_coordinator.HostAdmissionForeignRootV1(
            public_key_fingerprint=context.installed_root.public_key_fingerprint,
            root_version=context.installed_root.root_version,
            key_id=context.installed_root.key_id,
            algorithm=context.installed_root.algorithm,
            purpose=context.installed_root.purpose,
            custody_domain=context.installed_root.custody_domain,
            issuer=context.installed_root.issuer,
        ),
    )


def _corrupted_foreign_evidence(
    context,  # type: ignore[no-untyped-def]
    **overrides: object,
) -> HostAdmissionForeignVerificationEvidenceV1:
    """`_matching_foreign_evidence` with exactly the named fields replaced --
    used to prove each of the seven new semantic fields is independently
    compared, one at a time, with the other six held correct."""
    return replace(_matching_foreign_evidence(context), **overrides)


def _execution_for_context(
    db: Session, context: admission_coordinator.HostAdmissionVerificationContextV1
) -> FoundationDispatchConsumptionV1:
    attempt = db.get(RolloutAttempt, context.attempt_id)
    assert attempt is not None and attempt.dispatch_envelope is not None
    rollout = db.get(Rollout, attempt.rollout_id)
    assert rollout is not None and rollout.authorization_envelope is not None
    authorization = AuthorizationEnvelopeV2.parse(rollout.authorization_envelope)
    dispatch = DispatchEnvelopeV1.parse(attempt.dispatch_envelope)
    receipt = _receipt_from_pair(authorization, dispatch)
    observed = FoundationExecutionContextV1(
        product_code=receipt.product_code,
        environment=receipt.environment,
        target_id=receipt.target_id,
        target_ref=receipt.target_ref,
        operation=receipt.operation,
        release_ref=receipt.release_ref,
        rollout_ref=receipt.rollout_ref,
        plan_id=receipt.plan_id,
        approval_decision_ref=receipt.approval_decision_ref,
        control_plan_digest=receipt.control_plan_digest,
        execution_sequence=receipt.execution_sequence,
        attempt_no=receipt.attempt_no,
    )
    return FoundationDispatchConsumptionV1(
        authorization_material_json=authorization.canonical_bytes,
        dispatch_material_json=dispatch.canonical_bytes,
        expected_context=observed,
        expected_execution_plan_digest=receipt.execution_plan_digest,
        control_consumption_ref=f"control-dispatch:{receipt.dispatch_id}",
    )


class TestUnifiedFoundationConsumption:
    @pytest.mark.parametrize("operation", ["deploy", "rollback"])
    def test_one_committed_marker_and_recovery_lookup(
        self, db: Session, operation: str
    ) -> None:
        context = _resolve_admission_fixture(db, operation=operation)
        execution = _execution_for_context(db, context)
        assert context.dispatch_id == str(context.attempt_id)
        assert context.dispatch_id != context.attempt_id.hex
        assert execution.expected_context.operation == operation
        evidence = _matching_foreign_evidence(context)
        assert evidence.verified_observation_id == context.dispatch_id
        db.commit()
        staged = admit_and_consume_host_admission(
            db, context=context, foreign_evidence=evidence, execution=execution
        )
        assert staged.dispatch_id == context.dispatch_id
        assert (
            db.query(PlatformIdempotencyRecord)
            .filter_by(key=context.dispatch_id)
            .count()
            == 1
        )
        db.commit()
        with Session(db.get_bind()) as reader:
            committed = lookup_foundation_execution_consumption(
                reader, control_consumption_ref=execution.control_consumption_ref
            )
        assert committed is not None
        assert committed.attempt_id == context.attempt_id
        assert committed.dispatch_id == context.dispatch_id
        assert (
            committed.execution_plan_digest == execution.expected_execution_plan_digest
        )
        assert committed.candidate_attestation_envelope_digest == (
            evidence.candidate_attestation_envelope_digest
        )
        assert committed.installed_attestation_envelope_digest == (
            evidence.installed_attestation_envelope_digest
        )
        with pytest.raises(control_service._DispatchConsumptionRefusedError) as caught:
            admit_and_consume_host_admission(
                db, context=context, foreign_evidence=evidence, execution=execution
            )
        assert (
            caught.value.code
            is control_service._DispatchConsumptionRefusalCode.ALREADY_CONSUMED
        )

    def test_rollback_leaves_no_committed_consumption(self, db: Session) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        evidence = _matching_foreign_evidence(context)
        db.commit()
        admit_and_consume_host_admission(
            db, context=context, foreign_evidence=evidence, execution=execution
        )
        db.rollback()
        with Session(db.get_bind()) as reader:
            assert (
                lookup_foundation_execution_consumption(
                    reader, control_consumption_ref=execution.control_consumption_ref
                )
                is None
            )
        admit_and_consume_host_admission(
            db, context=context, foreign_evidence=evidence, execution=execution
        )

    @pytest.mark.parametrize("material", ["authorization", "dispatch"])
    def test_wrong_pair_bytes_refuse_before_marker(
        self, db: Session, material: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        changed = replace(
            execution,
            **{f"{material}_material_json": b"{}"},
        )
        monkeypatch.setattr(
            admission_coordinator,
            "lock_target",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("row lock reached before signed-pair refusal")
            ),
        )
        with pytest.raises(DeploymentControlError):
            admit_and_consume_host_admission(
                db,
                context=context,
                foreign_evidence=_matching_foreign_evidence(context),
                execution=changed,
            )
        assert (
            db.query(PlatformIdempotencyRecord)
            .filter_by(key=context.dispatch_id)
            .count()
            == 0
        )

    @pytest.mark.parametrize(
        "field,value",
        [
            ("target_ref", "wrong-target"),
            ("execution_sequence", 999),
            ("attempt_no", 999),
            ("control_plan_digest", "sha256:" + "e" * 64),
        ],
    )
    def test_independent_control_context_mismatch_refuses(
        self, db: Session, field: str, value: object
    ) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        changed = replace(
            execution,
            expected_context=replace(execution.expected_context, **{field: value}),
        )
        with pytest.raises(DeploymentControlError):
            admit_and_consume_host_admission(
                db,
                context=context,
                foreign_evidence=_matching_foreign_evidence(context),
                execution=changed,
            )

    def test_digest_and_recovery_coordinate_mismatch_refuse(self, db: Session) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        for changed in (
            replace(execution, expected_execution_plan_digest="sha256:" + "f" * 64),
            replace(execution, control_consumption_ref="control-dispatch:wrong"),
        ):
            with pytest.raises(DeploymentControlError):
                admit_and_consume_host_admission(
                    db,
                    context=context,
                    foreign_evidence=_matching_foreign_evidence(context),
                    execution=changed,
                )

    @pytest.mark.parametrize("cutoff", ["revocation", "settlement"])
    def test_revocation_or_settlement_committing_first_refuses(
        self, db: Session, cutoff: str
    ) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        attempt = db.get(RolloutAttempt, context.attempt_id)
        assert attempt is not None
        rollout = db.get(Rollout, attempt.rollout_id)
        assert rollout is not None
        if cutoff == "revocation":
            revoke_plan_approval(
                db,
                RevokePlanApprovalCommand(
                    command_id=_cmd(),
                    plan_id=rollout.plan_id,
                    revocation_ref="withdrawn",
                ),
            )
        else:
            settle_attempt(
                db,
                SettleAttemptCommand(
                    command_id=_cmd(),
                    rollout_id=rollout.id,
                    attempt_no=attempt.attempt_no,
                    outcome=AttemptOutcome.SUCCEEDED.value,
                ),
            )
        db.commit()
        with pytest.raises(control_service._DispatchConsumptionRefusedError):
            admit_and_consume_host_admission(
                db,
                context=context,
                foreign_evidence=_matching_foreign_evidence(context),
                execution=execution,
            )

    def test_security_install_is_startup_fixed(self) -> None:
        with pytest.raises(RuntimeError, match="already installed"):
            install_foundation_consumption_security(
                authorization_verifier=VERIFIER,
                dispatch_verifier=DISPATCH_VERIFIER,
                clock=_AdmissionClock(),
            )

    def test_no_installed_v3_trust_has_no_fallback(self, db: Session) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        _reset_foundation_consumption_security_for_tests()
        with pytest.raises(DeploymentControlError, match="not installed"):
            admit_and_consume_host_admission(
                db,
                context=context,
                foreign_evidence=_matching_foreign_evidence(context),
                execution=execution,
            )
        assert (
            db.query(PlatformIdempotencyRecord)
            .filter_by(key=context.dispatch_id)
            .count()
            == 0
        )

    def test_issuer_purpose_cannot_consume_foundation_dispatch(
        self, db: Session
    ) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        attempt = db.get(RolloutAttempt, context.attempt_id)
        assert attempt is not None
        rollout = db.get(Rollout, attempt.rollout_id)
        assert rollout is not None
        plan = db.get(control_service.DeploymentPlan, rollout.plan_id)
        assert plan is not None
        plan.purpose = "rehearsal_issuer_operation"
        db.commit()
        with pytest.raises(DeploymentControlError):
            admit_and_consume_host_admission(
                db,
                context=context,
                foreign_evidence=_matching_foreign_evidence(context),
                execution=execution,
            )

    def test_lookup_refuses_changed_stored_coordinate(self, db: Session) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        evidence = _matching_foreign_evidence(context)
        db.commit()
        admit_and_consume_host_admission(
            db, context=context, foreign_evidence=evidence, execution=execution
        )
        db.commit()
        marker = (
            db.query(PlatformIdempotencyRecord).filter_by(key=context.dispatch_id).one()
        )
        marker.result = {
            **marker.result,
            "installed_attestation_envelope_digest": "sha256:" + "e" * 64,
        }
        db.flush()
        with pytest.raises(DeploymentControlError, match="stored consumption evidence"):
            lookup_foundation_execution_consumption(
                db, control_consumption_ref=execution.control_consumption_ref
            )


class TestAuthenticatedHostAdmission:
    def test_resolve_fails_closed_until_startup_security_is_installed(
        self, db: Session
    ) -> None:
        attempt_id, presentation = _admission_fixture_inputs(db)
        admission_coordinator._reset_host_admission_security_for_tests()
        with pytest.raises(HostAdmissionRefusedError) as caught:
            resolve_host_admission_context(
                db,
                attempt_id=attempt_id,
                presentation=presentation,
            )
        assert caught.value.code is HostAdmissionRefusalCode.AUTHENTICATION_FAILED
        assert (
            db.query(PlatformIdempotencyRecord)
            .filter_by(key=presentation.statement.dispatch_id)
            .count()
            == 0
        )

    def test_startup_security_cannot_be_replaced(self) -> None:
        with pytest.raises(RuntimeError, match="already installed"):
            install_host_admission_security(
                verifier=_AdmissionVerifier(), clock=_AdmissionClock()
            )

    def test_resolve_returns_context_and_admit_and_consume_stages_composite_coordinate(
        self, db: Session
    ) -> None:
        context = _resolve_admission_fixture(db)
        assert context.host_id == "host-one"
        assert context.expected_foundation_package == "dotmac-sub"
        assert context.installed_root.public_key_base64.endswith("=")
        execution = _execution_for_context(db, context)

        # Prove the redesign's whole point: no lock survives resolve. Commit
        # (releasing anything SQLAlchemy might otherwise hold pending) between
        # resolve and admit-and-consume, then admit in the SAME session -- if
        # any lock or transaction affinity had leaked across the gap, this
        # would behave differently than a real CP adapter's two separate
        # transactions.
        db.commit()

        staged = admit_and_consume_host_admission(
            db,
            context=context,
            foreign_evidence=_matching_foreign_evidence(context),
            execution=execution,
        )
        assert staged.dispatch_id == context.dispatch_id

    def test_one_field_evidence_substitution_refuses_without_consumption(
        self, db: Session
    ) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        bad_evidence = _corrupted_foreign_evidence(
            context,
            candidate_attestation_envelope_digest="sha256:" + "ee" * 32,
        )
        with pytest.raises(HostAdmissionRefusedError) as caught:
            admit_and_consume_host_admission(
                db, context=context, foreign_evidence=bad_evidence, execution=execution
            )
        assert caught.value.code is HostAdmissionRefusalCode.EVIDENCE_CHANGED
        assert (
            db.query(PlatformIdempotencyRecord)
            .filter_by(key=context.dispatch_id)
            .count()
            == 0
        )

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"verified_host_identity": "host-two"}, id="host_identity"),
            pytest.param(
                {"verified_observation_id": uuid.uuid4().hex}, id="observation_id"
            ),
            pytest.param({"verified_package": "dotmac-other"}, id="package"),
            pytest.param(
                {"verified_candidate_audience": "foundation-candidate-other"},
                id="candidate_audience",
            ),
            pytest.param(
                {"verified_installed_audience": "foundation-installed-other"},
                id="installed_audience",
            ),
        ],
    )
    def test_a_mismatched_verified_field_is_refused_without_consumption(
        self, db: Session, overrides: dict[str, object]
    ) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        bad_evidence = _corrupted_foreign_evidence(context, **overrides)
        with pytest.raises(HostAdmissionRefusedError) as caught:
            admit_and_consume_host_admission(
                db, context=context, foreign_evidence=bad_evidence, execution=execution
            )
        assert (
            caught.value.code
            is HostAdmissionRefusalCode.FOREIGN_EVIDENCE_SEMANTIC_MISMATCH
        )
        assert (
            db.query(PlatformIdempotencyRecord)
            .filter_by(key=context.dispatch_id)
            .count()
            == 0
        )

    @pytest.mark.parametrize(
        "root_field", ["verified_candidate_root", "verified_installed_root"]
    )
    def test_a_mismatched_verified_root_is_refused_without_consumption(
        self, db: Session, root_field: str
    ) -> None:
        context = _resolve_admission_fixture(db)
        execution = _execution_for_context(db, context)
        db.commit()
        wrong_root = admission_coordinator.HostAdmissionForeignRootV1(
            public_key_fingerprint="sha256:" + "ff" * 32,
            root_version="v-wrong",
            key_id="wrong-key",
            algorithm="ed25519",
            purpose="dotmac.foundation.candidate-artifact.v2",
            custody_domain="candidate_release_signer",
            issuer="wrong-issuer",
        )
        bad_evidence = _corrupted_foreign_evidence(context, **{root_field: wrong_root})
        with pytest.raises(HostAdmissionRefusedError) as caught:
            admit_and_consume_host_admission(
                db, context=context, foreign_evidence=bad_evidence, execution=execution
            )
        assert (
            caught.value.code
            is HostAdmissionRefusalCode.FOREIGN_EVIDENCE_SEMANTIC_MISMATCH
        )
        assert (
            db.query(PlatformIdempotencyRecord)
            .filter_by(key=context.dispatch_id)
            .count()
            == 0
        )

    def test_host_rotation_requires_a_policy_revision_before_new_admission(
        self, db: Session
    ) -> None:
        context = _resolve_admission_fixture(db)
        rotate_target_host(
            db,
            BindTargetHostCommand(
                target_id=context.target_id,
                host_id="host-two",
                authority="control-test",
            ),
        )
        presentation = HostAdmissionPresentationV1(
            statement=HostAdmissionPresentationStatementV1(
                presentation_id="presentation-2",
                key_id="admission-key-1",
                dispatch_id=context.dispatch_id,
                candidate_attestation_envelope_digest=(
                    context.presentation.statement.candidate_attestation_envelope_digest
                ),
                installed_attestation_envelope_digest=(
                    context.presentation.statement.installed_attestation_envelope_digest
                ),
                issued_at=_NOW,
                expires_at=_NOW + timedelta(minutes=5),
            ),
            signature="c2ln",
        )
        with pytest.raises(HostAdmissionRefusedError) as caught:
            resolve_host_admission_context(
                db,
                attempt_id=context.attempt_id,
                presentation=presentation,
            )
        assert caught.value.code is HostAdmissionRefusalCode.POLICY_HOST_MISMATCH
