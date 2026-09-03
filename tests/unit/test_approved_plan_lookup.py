"""The read-only approved-plan lookup, and every typed refusal it can give.

## What was broken, measured rather than supposed

There was no read API for an approved plan in this control plane. No
fetch-by-digest, no verify-approved — only the WRITE path, which compares an
expected digest while an approval is being recorded.

So a promotion in another system was **handed** an authorization and could not
confirm one. Its receipt compared what ran against terms its own caller had
supplied, which proves a caller consistent with itself and is not a
verification. That is the defect that makes a receipt unverifiable, and it is
what `find_approved_plan` closes.

## What this file holds

**Each refusal is observed on its own.** A single "the lookup said no"
assertion would pass against an implementation that could only ever detect one
reason, and the reasons here have genuinely different readers: an unreadable
digest is a fault in the caller's encoding, an unresolved one is a statement
about this database, a revoked approval is a decision somebody took, and an
undeclared image set is the original defect refusing to be answered around.

**A negative is distinguishable from an absence.** Every refusal carries a
typed code, and the lookup result is FALSY for every one of them — so `if
find_approved_plan(...)` cannot pass on a no, which is the shape a plain
dataclass would have given.

**Revocation is reachable from the lookup itself.** A consumer asking "is this
approved?" is told about a withdrawn decision by the same call it already
makes, not by a second query it has to remember. A consumer that gets a yes for
a revoked plan is worse off than one with no API at all, because the one with
no API asks a person.

**Control still cannot recompute an execution-plan digest.** The lookup
RETURNS that value, which is exactly the point at which somebody might be
tempted to re-derive it. `test_the_lookup_returns_the_frozen_digest_and_still_
cannot_compute_one` states both halves.

In-memory SQLite; logic only.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.service as control_service
from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovedPlanRefusalCode,
    ApprovedPlanRefusedError,
    ApprovePlanCommand,
    DesiredDeployment,
    ExecutionPlanDigestV1,
    ExpectedStateError,
    PlanStatus,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RevokePlanApprovalCommand,
    SetDesiredStateCommand,
    TransitionRefusedError,
    approve_plan,
    find_approved_plan,
    module,
    propose_plan,
    register_target,
    request_rollout,
    require_approved_plan,
    revoke_plan_approval,
    set_desired_state,
)
from dotmac_deployment_control.models import DeploymentPlan, Rollout
from dotmac_deployment_control.ports import ApprovalRefusedError
from tests.authorization_support import SIGNER, VERIFIER

_NOW = datetime(2026, 9, 2, 9, 0, tzinfo=UTC)
_POLICY = "deployment.production"
_POLICY_VERSION = 4
_RELEASE = "dotmac_sub@7.187.1"

#: The Foundation's, written out — Control cannot compute one, so a fixture
#: that derived it would exercise a capability this module does not have.
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_OTHER_EXECUTION_PLAN = "sha256:" + "2b" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32

_IMAGE_A = "sha256:" + "aa" * 32
_IMAGES = [
    {
        "service": "api",
        "repository": "registry.dotmac.io/api",
        "digest": _IMAGE_A,
    }
]


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


def _target(db: Session, *, images: object = None, target_ref: str = "tgt-1"):
    view = register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref=target_ref,
            subject_ref="acme-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=view.id,
            desired=DesiredDeployment(
                release_ref=_RELEASE,
                spec={"replicas": 2},
                images=images if images is not None else _IMAGES,  # type: ignore[arg-type]
            ),
        ),
    )
    return view


def _propose(db: Session, target_id, **overrides: object):  # type: ignore[no-untyped-def]
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


def _evidence(plan, **overrides: object) -> ApprovalEvidence:  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "policy_code": _POLICY,
        "policy_version": _POLICY_VERSION,
        "decision_ref": f"apr-{uuid.uuid4().hex[:8]}",
        "content_digest": plan.plan_digest or "",
        "decided_at": _NOW,
        "operation": "deploy",
        "execution_plan_digest": _EXECUTION_PLAN,
        "decision_status": "granted",
    }
    fields.update(overrides)
    return ApprovalEvidence(**fields)  # type: ignore[arg-type]


def _approved(db: Session, **target_kwargs: object):
    """A target, a plan, and a standing approval over it."""
    view = _target(db, **target_kwargs)  # type: ignore[arg-type]
    plan = _propose(db, view.id)
    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_cmd(), plan_id=plan.id, evidence=_evidence(plan)
        ),
    )


def _rollout(db: Session, plan):  # type: ignore[no-untyped-def]
    existing = db.query(Rollout).filter(Rollout.plan_id == plan.id).one_or_none()
    if existing is not None:
        return existing
    return request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_cmd(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan.id,
            authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        ),
        signer=SIGNER,
    )


def _lookup(db: Session, plan, **kwargs: object):  # type: ignore[no-untyped-def]
    rollout = _rollout(db, plan)
    return find_approved_plan(
        db,
        plan_digest=plan.plan_digest or "",
        authorization_id=rollout.id,
        verifier=VERIFIER,
        at=_NOW,
        **kwargs,
    )


def _require(db: Session, plan):  # type: ignore[no-untyped-def]
    rollout = _rollout(db, plan)
    return require_approved_plan(
        db,
        plan_digest=plan.plan_digest or "",
        authorization_id=rollout.id,
        verifier=VERIFIER,
        at=_NOW,
    )


# ── The positive answer ─────────────────────────────────────────────────────


class TestAStandingApprovalResolvesWithEveryTerm:
    def test_the_lookup_returns_the_terms_a_consumer_must_verify(
        self, db: Session
    ) -> None:
        """Every term Michael named, from one read, none of them re-derived."""
        plan = _approved(db)

        lookup = _lookup(db, plan)
        assert lookup, "a standing approval must be truthy"
        auth = lookup.authorization
        assert auth is not None

        assert auth.plan_id == plan.id
        assert auth.plan_digest == plan.plan_digest
        assert auth.descriptor_digest == _DESCRIPTOR
        assert auth.authorization_envelope.statement.plan_digest == auth.plan_digest
        # The execution binding — a THIRD value, not the plan digest.
        assert auth.execution_plan_digest == _EXECUTION_PLAN
        assert auth.execution_plan_digest != auth.plan_digest
        assert auth.operation == "deploy"
        # Policy identity AND version: a code alone reads as current after the
        # policy has moved.
        assert auth.approval_policy_code == _POLICY
        assert auth.approval_policy_version == _POLICY_VERSION
        # The decision, and its standing.
        assert auth.approval_decision_ref is not None
        assert auth.approval_decision_status == "granted"
        assert auth.approved_at is not None
        # Compared tz-naive, the way the sibling suites do: this lane runs on
        # in-memory SQLite, whose driver erases `tzinfo` on a round trip. The
        # INSTANT is what matters here and it is preserved; the timezone-aware
        # round trip is a Postgres property and is proven in the Postgres lane.
        assert auth.approved_at.replace(tzinfo=None) == _NOW.replace(tzinfo=None)
        # And what may run.
        assert [image.as_mapping() for image in auth.authorized_images] == _IMAGES

    def test_a_plan_authorizing_no_images_resolves_with_an_empty_tuple(
        self, db: Session
    ) -> None:
        """`()` is an authorization, not an absence — a receipt recording any
        image contradicts it, and that is a decidable comparison."""
        plan = _approved(db, images=[])

        auth = _require(db, plan)
        assert auth.authorized_images == ()

    def test_the_lookup_writes_nothing(self, db: Session) -> None:
        """A READ. It must not move a record version, a status or a timestamp."""
        plan = _approved(db)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        before = (row.record_version, row.status, row.approval_decision_status)

        _lookup(db, plan)
        find_approved_plan(db, plan_digest="sha256:" + "ff" * 32)
        db.flush()

        db.refresh(row)
        assert (row.record_version, row.status, row.approval_decision_status) == before

    def test_the_lookup_returns_the_frozen_digest_and_still_cannot_compute_one(
        self, db: Session
    ) -> None:
        """Returning the value must not become re-deriving it.

        This is the exact point at which the property is easiest to lose: a
        read surface that hands back the Foundation's digest is one line away
        from a read surface that rebuilds it. `ExecutionPlanDigestV1` inherits
        the READ-ONLY base, so there is no constructor to reach for, and the
        returned text is byte-identical to what was frozen.
        """
        plan = _approved(db)
        auth = _require(db, plan)

        assert auth.execution_plan_digest == _EXECUTION_PLAN
        assert not hasattr(ExecutionPlanDigestV1, "over_json")
        with pytest.raises(AttributeError):
            ExecutionPlanDigestV1.over_json({"any": "payload"})  # type: ignore[attr-defined]

    def test_an_expected_execution_plan_digest_can_be_confirmed(
        self, db: Session
    ) -> None:
        """The optional third term: supply it and the lookup confirms it."""
        plan = _approved(db)

        assert _lookup(db, plan, expected_execution_plan_digest=_EXECUTION_PLAN)


# ── Every refusal, observed on its own ──────────────────────────────────────


class TestEachRefusalIsItsOwnFinding:
    def test_an_unreadable_digest_is_an_encoding_fault_naming_no_plan(
        self, db: Session
    ) -> None:
        """The `0.1.0a4` lesson on the read path.

        "I cannot read what you sent" says nothing about any plan. Reporting it
        as "not approved" would hand an operator a security-shaped answer for a
        formatting bug — the failure that looks exactly like the system
        working.
        """
        _approved(db)

        lookup = find_approved_plan(db, plan_digest="NOT-A-DIGEST")
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.DIGEST_UNREADABLE
        assert lookup.refusal.plan_id is None, "no plan was looked at"
        assert "encoding fault" in lookup.refusal.detail

    def test_a_well_formed_digest_nothing_holds_is_a_different_finding(
        self, db: Session
    ) -> None:
        """Unresolvable, and it says so as a statement about this database."""
        _approved(db)

        lookup = find_approved_plan(db, plan_digest="sha256:" + "ff" * 32)
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.DIGEST_UNRESOLVED
        assert lookup.refusal.plan_id is None

    def test_a_proposed_plan_is_not_approved_and_names_its_actual_status(
        self, db: Session
    ) -> None:
        plan = _propose(db, _target(db).id)

        lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.NOT_APPROVED
        assert lookup.refusal.plan_id == plan.id
        assert lookup.refusal.plan_status == PlanStatus.PROPOSED.value

    def test_a_revoked_approval_is_refused_by_the_lookup_itself(
        self, db: Session
    ) -> None:
        """THE ONE THAT MATTERS MOST.

        A consumer asking "is this approved?" learns about the withdrawal from
        the call it already makes. If revocation were a separate query, this is
        the consumer that would forget it — and a yes for a revoked plan is
        worse than no API at all.
        """
        plan = _approved(db)
        rollout = _rollout(db, plan)
        stored_before = db.get(Rollout, rollout.id)
        assert stored_before is not None
        envelope_before = copy.deepcopy(stored_before.authorization_envelope)
        assert _lookup(db, plan)

        revoked = revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(),
                plan_id=plan.id,
                revocation_ref="apr-rev-88",
                reason="artifact withdrawn by the release lane",
            ),
        )

        lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.APPROVAL_REVOKED
        assert lookup.refusal.plan_id == plan.id
        assert "apr-rev-88" in lookup.refusal.detail
        assert "artifact withdrawn" in lookup.refusal.detail

        # The plan still READS approved, deliberately — that is history, and
        # the refusal above is what stops it being read as an authorization.
        assert revoked.status == PlanStatus.APPROVED.value
        assert lookup.refusal.plan_status == PlanStatus.APPROVED.value
        assert revoked.approval_decision_status == "revoked"
        assert revoked.approval_revocation_ref == "apr-rev-88"
        stored = db.get(Rollout, rollout.id)
        assert stored is not None
        assert stored.authorization_envelope == envelope_before

    def test_an_approval_whose_standing_was_never_recorded_is_not_read_as_granted(
        self, db: Session
    ) -> None:
        """A pre-`dc_0004` approval. Reading 'granted' out of a blank column
        would be inferring an authorization from an absence."""
        plan = _approved(db)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.approval_decision_status = None
        db.flush()

        lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert not lookup
        assert lookup.refusal is not None
        assert (
            lookup.refusal.code is ApprovedPlanRefusalCode.APPROVAL_STANDING_UNRECORDED
        )

    def test_an_approval_with_no_execution_binding_is_refused(
        self, db: Session
    ) -> None:
        """A `0.1.0a7` plan: an authorization no executor could verify."""
        plan = _approved(db)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.authorized_execution_plan_digest = None
        row.authorized_operation = None
        db.flush()

        lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.EXECUTION_BINDING_ABSENT

    def test_an_undeclared_image_set_is_refused_rather_than_answered(
        self, db: Session
    ) -> None:
        """THE ORIGINAL DEFECT, refused.

        An authorization that cannot say which images it covers is one a
        consumer would have to fill in from its own caller. Answering it with a
        blank is exactly what let a receipt verify against images supplied by
        whoever was asking.

        Note this is an ABSENCE and not an empty set — a plan authorizing no
        images resolves normally, which the positive case above observes.
        """
        plan = _approved(db, images=[], target_ref="tgt-noimages")
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        snapshot = dict(row.snapshot or {})
        del snapshot["authorized_images"]
        row.snapshot = snapshot
        db.flush()

        lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.IMAGE_SET_UNDECLARED
        assert "ABSENCE" in lookup.refusal.detail

    def test_an_execution_plan_the_caller_did_not_expect_is_its_own_refusal(
        self, db: Session
    ) -> None:
        """Compared as VALUES, and reported as a different execution rather
        than as an encoding difference."""
        plan = _approved(db)

        lookup = find_approved_plan(
            db,
            plan_digest=plan.plan_digest or "",
            expected_execution_plan_digest=_OTHER_EXECUTION_PLAN,
        )
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.EXECUTION_PLAN_MISMATCH
        assert "not an encoding difference" in lookup.refusal.detail

    def test_an_unreadable_expected_execution_digest_makes_no_comparison(
        self, db: Session
    ) -> None:
        """Still an encoding fault, and it says so — no claim about the plan."""
        plan = _approved(db)

        lookup = find_approved_plan(
            db,
            plan_digest=plan.plan_digest or "",
            expected_execution_plan_digest="deadbeef",
        )
        assert not lookup
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.DIGEST_UNREADABLE
        assert "NO comparison was made" in lookup.refusal.detail

    def test_a_legacy_plan_without_descriptor_binding_is_refused(self, db) -> None:
        plan = _approved(db)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        snapshot = dict(row.snapshot or {})
        snapshot.pop("descriptor_digest")
        row.snapshot = snapshot
        db.flush()
        lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.DESCRIPTOR_BINDING_ABSENT

    def test_a_different_expected_descriptor_is_its_own_refusal(self, db) -> None:
        plan = _approved(db)
        lookup = find_approved_plan(
            db,
            plan_digest=plan.plan_digest or "",
            expected_descriptor_digest="sha256:" + "ff" * 32,
        )
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.DESCRIPTOR_MISMATCH

    def test_a_plan_approval_without_a_rollout_is_not_a_portable_authorization(
        self, db
    ) -> None:
        plan = _approved(db)
        lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert lookup.refusal is not None
        assert (
            lookup.refusal.code is ApprovedPlanRefusalCode.AUTHORIZATION_ENVELOPE_ABSENT
        )

    def test_an_unknown_authorization_id_is_refused(self, db) -> None:
        plan = _approved(db)
        lookup = find_approved_plan(
            db,
            plan_digest=plan.plan_digest or "",
            authorization_id=uuid.uuid4(),
            verifier=VERIFIER,
        )
        assert lookup.refusal is not None
        assert lookup.refusal.code is ApprovedPlanRefusalCode.AUTHORIZATION_UNRESOLVED

    def test_a_verifier_is_required_for_a_stored_envelope(self, db) -> None:
        plan = _approved(db)
        rollout = _rollout(db, plan)
        lookup = find_approved_plan(
            db, plan_digest=plan.plan_digest or "", authorization_id=rollout.id
        )
        assert lookup.refusal is not None
        assert (
            lookup.refusal.code is ApprovedPlanRefusalCode.AUTHORIZATION_VERIFIER_ABSENT
        )

    def test_a_mutated_stored_envelope_is_refused(self, db) -> None:
        plan = _approved(db)
        rollout = _rollout(db, plan)
        row = db.get(Rollout, rollout.id)
        assert row is not None and row.authorization_envelope is not None
        payload = dict(row.authorization_envelope)
        payload["signature"] = "mutated"
        row.authorization_envelope = payload
        db.flush()
        lookup = find_approved_plan(
            db,
            plan_digest=plan.plan_digest or "",
            authorization_id=rollout.id,
            verifier=VERIFIER,
            at=_NOW,
        )
        assert lookup.refusal is not None
        assert (
            lookup.refusal.code
            is ApprovedPlanRefusalCode.AUTHORIZATION_ENVELOPE_INVALID
        )

    def test_every_refusal_code_is_reachable(self) -> None:
        """The set of codes and the set this file observes are the same set.

        A vocabulary member nothing can produce is a member that will be
        produced wrongly one day, and a member nothing observes is a claim
        nobody has checked. Both directions, so adding a code without a test
        fails here rather than silently.
        """
        observed = {
            ApprovedPlanRefusalCode.DIGEST_UNREADABLE,
            ApprovedPlanRefusalCode.DIGEST_UNRESOLVED,
            ApprovedPlanRefusalCode.NOT_APPROVED,
            ApprovedPlanRefusalCode.APPROVAL_REVOKED,
            ApprovedPlanRefusalCode.APPROVAL_STANDING_UNRECORDED,
            ApprovedPlanRefusalCode.EXECUTION_BINDING_ABSENT,
            ApprovedPlanRefusalCode.IMAGE_SET_UNDECLARED,
            ApprovedPlanRefusalCode.EXECUTION_PLAN_MISMATCH,
            ApprovedPlanRefusalCode.DESCRIPTOR_BINDING_ABSENT,
            ApprovedPlanRefusalCode.DESCRIPTOR_MISMATCH,
            ApprovedPlanRefusalCode.AUTHORIZATION_ENVELOPE_ABSENT,
            ApprovedPlanRefusalCode.AUTHORIZATION_ENVELOPE_INVALID,
            ApprovedPlanRefusalCode.AUTHORIZATION_UNRESOLVED,
            ApprovedPlanRefusalCode.AUTHORIZATION_VERIFIER_ABSENT,
        }
        assert observed == set(ApprovedPlanRefusalCode)


# ── The shape of the answer ─────────────────────────────────────────────────


class TestARefusalCannotBeMistakenForAnApproval:
    def test_a_refusal_is_falsy_and_an_authorization_is_truthy(
        self, db: Session
    ) -> None:
        """A plain dataclass is ALWAYS truthy, so `if lookup:` would pass on
        every refusal. That is the precise false success this surface exists to
        remove, so truthiness is approval here."""
        plan = _approved(db)

        assert bool(_lookup(db, plan))
        assert not bool(find_approved_plan(db, plan_digest="sha256:" + "ff" * 32))

    def test_an_absent_answer_is_not_a_possible_answer(self, db: Session) -> None:
        """There is no empty result to confuse with a negative one: every
        lookup carries exactly one of an authorization or a typed refusal."""
        plan = _approved(db)
        yes = _lookup(db, plan)
        no = find_approved_plan(db, plan_digest="sha256:" + "ff" * 32)

        assert (yes.authorization is None) != (yes.refusal is None)
        assert (no.authorization is None) != (no.refusal is None)
        assert no.refusal is not None and no.refusal.code is not None

    def test_the_requiring_entry_point_raises_with_the_typed_code(
        self, db: Session
    ) -> None:
        """A caller that must not proceed cannot be handed something falsy it
        might forget to check — and it still branches on a code, not a
        sentence."""
        plan = _approved(db)
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(), plan_id=plan.id, revocation_ref="apr-rev-1"
            ),
        )

        with pytest.raises(ApprovedPlanRefusedError) as caught:
            require_approved_plan(db, plan_digest=plan.plan_digest or "")
        assert caught.value.refusal.code is ApprovedPlanRefusalCode.APPROVAL_REVOKED

    def test_the_two_entry_points_give_one_answer(self, db: Session) -> None:
        """One decision, one function, no second copy of the rules: whatever
        `find_approved_plan` refuses, `require_approved_plan` raises."""
        plan = _propose(db, _target(db).id)

        assert not find_approved_plan(db, plan_digest=plan.plan_digest or "")
        with pytest.raises(ApprovedPlanRefusedError):
            require_approved_plan(db, plan_digest=plan.plan_digest or "")


# ── Revocation as a write ───────────────────────────────────────────────────


class TestRevocationIsADecisionWithAReference:
    def test_a_revoked_approval_cannot_be_rolled_out(self, db: Session) -> None:
        """The internal half of the same gate. `status` still reads approved,
        so the standing is checked separately or a revoked plan reaches the
        fleet."""
        plan = _approved(db)
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(), plan_id=plan.id, revocation_ref="apr-rev-2"
            ),
        )

        with pytest.raises(ApprovalRefusedError) as caught:
            request_rollout(
                db,
                RequestRolloutCommand(
                    command_id=_cmd(),
                    rollout_ref="rol-1",
                    plan_id=plan.id,
                    authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                ),
                signer=SIGNER,
            )
        assert "revoked" in str(caught.value)

    def test_revoking_twice_does_not_overwrite_the_first_decision(
        self, db: Session
    ) -> None:
        """The first revocation is the one an incident review needs."""
        plan = _approved(db)
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(), plan_id=plan.id, revocation_ref="apr-rev-first"
            ),
        )

        with pytest.raises(TransitionRefusedError):
            revoke_plan_approval(
                db,
                RevokePlanApprovalCommand(
                    command_id=_cmd(),
                    plan_id=plan.id,
                    revocation_ref="apr-rev-second",
                ),
            )

        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        assert row.approval_revocation_ref == "apr-rev-first"

    def test_a_revocation_with_no_reference_is_refused(self, db: Session) -> None:
        """An authorization that disappears with no decision behind it is
        indistinguishable from a defect afterwards."""
        plan = _approved(db)

        with pytest.raises(ApprovalRefusedError):
            revoke_plan_approval(
                db,
                RevokePlanApprovalCommand(
                    command_id=_cmd(), plan_id=plan.id, revocation_ref=""
                ),
            )

    def test_an_unapproved_plan_has_no_approval_to_revoke(self, db: Session) -> None:
        plan = _propose(db, _target(db).id)

        with pytest.raises(ExpectedStateError):
            revoke_plan_approval(
                db,
                RevokePlanApprovalCommand(
                    command_id=_cmd(), plan_id=plan.id, revocation_ref="apr-rev-3"
                ),
            )


# ── The decision standing on the way in ─────────────────────────────────────


class TestApprovalEvidenceMustSayWhatTheDecisionWas:
    def test_evidence_with_no_decision_status_is_refused(self, db: Session) -> None:
        """Reaching `approve_plan` is not evidence a decision granted anything
        — the same inference a defaulted operation makes."""
        plan = _propose(db, _target(db).id)

        with pytest.raises(ApprovalRefusedError) as caught:
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(),
                    plan_id=plan.id,
                    evidence=_evidence(plan, decision_status=None),
                ),
            )
        assert "does not say what the decision was" in str(caught.value)

    def test_a_revoked_decision_replayed_here_does_not_become_an_approval(
        self, db: Session
    ) -> None:
        """The arrival this refusal exists for, and far more likely than a
        mistyped word."""
        plan = _propose(db, _target(db).id)

        with pytest.raises(ApprovalRefusedError) as caught:
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(),
                    plan_id=plan.id,
                    evidence=_evidence(plan, decision_status="revoked"),
                ),
            )
        assert "authorizes nothing" in str(caught.value)

    def test_a_differently_cased_standing_is_refused_not_folded(
        self, db: Session
    ) -> None:
        """A case fold is an inference — one standing with two spellings is one
        standing with two identities, exactly as for the operation vocabulary."""
        plan = _propose(db, _target(db).id)

        with pytest.raises(ApprovalRefusedError) as caught:
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_cmd(),
                    plan_id=plan.id,
                    evidence=_evidence(plan, decision_status="Granted"),
                ),
            )
        assert "spelling is exact" in str(caught.value)
