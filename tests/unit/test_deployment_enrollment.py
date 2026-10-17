"""Hosted-only source canaries. Fixture owners are explicit test doubles.

These tests do not qualify production descriptor/runtime/custody adapters.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import dotmac_deployment_control.deployment_enrollment as enrollment
from dotmac_deployment_control.authorization import issue_authorization_envelope
from dotmac_deployment_control.digests import (
    AuthorizationEnvelopeDigestV1,
    DispatchEnvelopeDigestV1,
    PlanDigestV1,
)
from dotmac_deployment_control.dispatch_envelope import issue_dispatch_envelope
from dotmac_deployment_control.foundation_consumption import (
    FoundationCommittedConsumptionV1,
)
from dotmac_deployment_control.models import (
    DeploymentCurrentEnrollment,
    DeploymentEnrollment,
    DeploymentEnrollmentClosure,
    DeploymentEnrollmentComponent,
    DeploymentHealthAssessment,
    DeploymentPlan,
    DeploymentTarget,
    Rollout,
    RolloutAttempt,
    RolloutAttemptSettlement,
    TargetCurrentHost,
    TargetHostAssociation,
)
from tests.authorization_support import SIGNER
from tests.dispatch_support import TestDispatchSigner

_NOW = datetime(2027, 6, 1, tzinfo=UTC)
_DESCRIPTOR = "sha256:" + "ab" * 32
_EXECUTION = "sha256:" + "cd" * 32
_IMAGE = ("web", "registry.example.test/web", "sha256:" + "ef" * 32)


class _Owners:
    """Test-only authenticated owner ledger with independently revocable domains."""

    def __init__(self, attempt_id):
        self.now_value = _NOW
        self.revoked = set()
        self.runtime = {}
        self.custody = {}
        self.consumed = None
        self.binding = enrollment.InstallationSourceBinding(
            "installation-epoch-1",
            "configuration-1",
            "source-1",
            "account-1",
            "transport-1",
            "generation-opaque-7",
            "credential-original",
            "7",
        )
        self.descriptor = enrollment.QualifiedDescriptor(
            _DESCRIPTOR, ("web",), (_IMAGE,), "configuration-1", "candidate-1"
        )
        component = enrollment.RuntimeComponent(
            "web", "container-1", _NOW - timedelta(minutes=5), 731, _IMAGE
        )
        self.runtime["runtime-1"] = enrollment.AuthenticatedRuntimeEvidence(
            "runtime-1",
            "runtime-authority",
            attempt_id,
            "host-1",
            "boot-1",
            "configuration-1",
            "candidate-1",
            (component,),
            _NOW,
            _NOW - timedelta(minutes=1),
            _NOW + timedelta(minutes=10),
        )
        self.custody["custody-1"] = enrollment.AuthenticatedStartupAssignment(
            "custody-1",
            "custody-authority",
            attempt_id,
            "host-1",
            "boot-1",
            "runtime-1",
            self.binding,
            (component,),
            _NOW - timedelta(minutes=5),
            _NOW - timedelta(minutes=1),
            _NOW + timedelta(minutes=6),
        )

    def require_ready(self):
        if "outage" in self.revoked:
            raise enrollment.DeploymentEnrollmentRefusedError("owner unavailable")

    def now(self):
        return self.now_value

    def qualified_v5(self, descriptor_digest):
        assert descriptor_digest == _DESCRIPTOR
        return self.descriptor

    def authenticated_lookup(self, evidence_ref=None, **coordinates):
        if evidence_ref is None:
            assert coordinates["configuration_ref"] == "configuration-1"
            return self.binding
        return (self.runtime | self.custody)[evidence_ref]

    def require_current(self, evidence, *, at):
        self.require_ready()
        if type(evidence).__name__ in self.revoked:
            raise enrollment.DeploymentEnrollmentRefusedError("owner revoked")

    def lookup_in_new_transaction(self, *, control_consumption_ref):
        assert control_consumption_ref.startswith("control-dispatch:")
        return self.consumed


@pytest.fixture
def admitted(monkeypatch):
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def attach(dbapi_connection, _record):
        # Make the test assembly own SQLite BEGIN so SAVEPOINT release cannot
        # accidentally commit outside a real outer transaction (legacy mode).
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def begin(connection):
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[t for t in Base.metadata.tables.values() if t.schema == "mod_deploy"],
    )
    with Session(engine) as db:
        yield _seed_enrollment(db, monkeypatch)
    engine.dispose()


def _seed_enrollment(db, monkeypatch):
    tid, pid, rid, aid = (uuid4() for _ in range(4))
    owners = _Owners(aid)
    monkeypatch.setattr(
        enrollment,
        "_installed_sources",
        enrollment._Sources(owners, owners, owners, owners, owners, owners),
    )
    snapshot = {
        "plan_purpose": "foundation_execution",
        "release_ref": "release-1",
        "descriptor_digest": _DESCRIPTOR,
        "authorized_images": [
            {"service": _IMAGE[0], "repository": _IMAGE[1], "digest": _IMAGE[2]}
        ],
    }
    digest = PlanDigestV1.over_json(snapshot).canonical
    # Deployment authority expired yesterday; unchanged runtime health is fresh.
    issued = _NOW - timedelta(days=2)
    auth = issue_authorization_envelope(
        {
            "authorization_id": str(rid),
            "execution_sequence": 1,
            "rollout_ref": "rollout-1",
            "plan_id": str(pid),
            "target_id": str(tid),
            "target_ref": "target-1",
            "product_code": "product-1",
            "environment": "test",
            "operation": "deploy",
            "release_ref": "release-1",
            "authorized_images": snapshot["authorized_images"],
            "plan_digest": digest,
            "descriptor_digest": _DESCRIPTOR,
            "execution_plan_digest": _EXECUTION,
            "approval_policy_code": "policy-1",
            "approval_policy_version": 1,
            "approval_decision_ref": "decision-1",
            "approval_decision_status": "granted",
            "approved_at": issued - timedelta(minutes=1),
            "issued_at": issued,
            "expires_at": issued + timedelta(minutes=30),
        },
        signer=SIGNER,
    )
    dispatch = issue_dispatch_envelope(
        authorization_envelope=auth,
        dispatch_id=str(aid),
        attempt_no=1,
        issued_at=issued,
        signer=TestDispatchSigner(),
    )
    owners.consumed = FoundationCommittedConsumptionV1(
        f"control-dispatch:{aid}",
        aid,
        str(aid),
        AuthorizationEnvelopeDigestV1.over_bytes(auth.canonical_bytes).canonical,
        DispatchEnvelopeDigestV1.over_bytes(dispatch.canonical_bytes).canonical,
        _EXECUTION,
        "sha256:" + "12" * 32,
        "sha256:" + "34" * 32,
    )
    db.add(
        DeploymentTarget(
            id=tid,
            target_ref="target-1",
            subject_ref="subject-1",
            product_code="product-1",
            environment="test",
        )
    )
    db.add(
        DeploymentPlan(
            id=pid,
            target_id=tid,
            sequence=1,
            purpose="foundation_execution",
            snapshot=snapshot,
            plan_digest=digest,
            operation="deploy",
            authorized_operation="deploy",
            execution_plan_digest=_EXECUTION,
            authorized_execution_plan_digest=_EXECUTION,
            approval_decision_ref="decision-1",
        )
    )
    db.add(
        Rollout(
            id=rid,
            target_id=tid,
            plan_id=pid,
            rollout_ref="rollout-1",
            execution_sequence=1,
            authorization_envelope=auth.as_mapping(),
        )
    )
    db.add(
        RolloutAttempt(
            id=aid,
            rollout_id=rid,
            attempt_no=1,
            dispatch_envelope=dispatch.as_mapping(),
        )
    )
    db.add(RolloutAttemptSettlement(id=uuid4(), attempt_id=aid, outcome="succeeded"))
    host = TargetHostAssociation(
        id=uuid4(),
        target_id=tid,
        host_id="host-1",
        bound_at=issued,
        authority="host-owner",
    )
    db.add(host)
    db.add(TargetCurrentHost(target_id=tid, association_id=host.id))
    db.commit()
    return SimpleNamespace(
        db=db,
        owners=owners,
        aid=aid,
        tid=tid,
        pid=pid,
        rid=rid,
        command=enrollment.EnrollDeploymentCommand(aid, "runtime-1", "custody-1"),
    )


def test_expired_execution_token_fresh_health_and_flush_only(admitted):
    ctx = admitted
    before = ctx.db.get_transaction()
    projection = enrollment.enroll_deployment(ctx.db, ctx.command)
    assert len(projection.component_codes[0]) == 101
    assert projection.credential_ref == "generation-opaque-7"
    assert projection.eligible_until == _NOW + timedelta(minutes=6)
    assert ctx.db.in_transaction() and before is None
    assessment = enrollment.current_eligibility_get(
        ctx.db, enrollment_ref=projection.enrollment_ref
    )
    assert assessment.identity_fingerprint == projection.identity_fingerprint
    ctx.db.rollback()
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentEnrollment)
        ).scalar_one()
        == 0
    )


@pytest.mark.parametrize("missing", ["consumption", "settlement", "pair"])
def test_no_partial_provenance_qualifies(admitted, missing):
    ctx = admitted
    if missing == "consumption":
        ctx.owners.consumed = None
    elif missing == "settlement":
        ctx.db.delete(ctx.db.execute(select(RolloutAttemptSettlement)).scalar_one())
        ctx.db.flush()
    else:
        ctx.db.get(RolloutAttempt, ctx.aid).dispatch_envelope = None
        ctx.db.flush()
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(ctx.db, ctx.command)
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentEnrollment)
        ).scalar_one()
        == 0
    )


@pytest.mark.parametrize(
    "coordinate",
    [
        "attempt_id",
        "dispatch_id",
        "authorization_envelope_digest",
        "dispatch_envelope_digest",
        "execution_plan_digest",
    ],
)
def test_consumption_join_refuses_every_wrong_coordinate(admitted, coordinate):
    value = (
        uuid4()
        if coordinate == "attempt_id"
        else (str(uuid4()) if coordinate == "dispatch_id" else "sha256:" + "98" * 32)
    )
    admitted.owners.consumed = replace(admitted.owners.consumed, **{coordinate: value})
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(admitted.db, admitted.command)


@pytest.mark.parametrize(
    "coordinate,value",
    [
        ("attempt_id", uuid4()),
        ("host_id", "wrong-host"),
        ("host_incarnation", "wrong-boot"),
        ("configuration_ref", "wrong-config"),
        ("candidate_ref", "wrong-candidate"),
        ("components", ()),
        ("authority_ref", "custody-authority"),
    ],
)
def test_runtime_claim_cannot_replace_authenticated_exact_join(
    admitted, coordinate, value
):
    admitted.owners.runtime["runtime-1"] = replace(
        admitted.owners.runtime["runtime-1"], **{coordinate: value}
    )
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(admitted.db, admitted.command)


def test_renewal_retains_original_identity_and_appends_current_evidence(admitted):
    ctx = admitted
    original = enrollment.enroll_deployment(ctx.db, ctx.command)
    ctx.db.commit()
    ctx.owners.now_value += timedelta(minutes=2)
    ctx.owners.runtime["runtime-2"] = replace(
        ctx.owners.runtime["runtime-1"],
        evidence_ref="runtime-2",
        observed_at=ctx.owners.now_value,
        valid_from=ctx.owners.now_value,
        valid_until=_NOW + timedelta(minutes=20),
    )
    ctx.owners.custody["custody-2"] = replace(
        ctx.owners.custody["custody-1"],
        evidence_ref="custody-2",
        runtime_evidence_ref="runtime-2",
        valid_from=ctx.owners.now_value,
        valid_until=_NOW + timedelta(minutes=15),
    )
    current = enrollment.assess_health_eligibility(
        ctx.db,
        enrollment.AssessHealthEligibilityCommand(
            original.enrollment_ref, "assessment-2", "runtime-2", "custody-2"
        ),
    )
    assert current.valid_until == _NOW + timedelta(minutes=15)
    assert current.identity_fingerprint == original.identity_fingerprint
    assert (
        enrollment.historical_get(ctx.db, enrollment_ref=original.enrollment_ref)
        == original
    )
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentHealthAssessment)
        ).scalar_one()
        == 2
    )
    # A later read checks current standing without creating another assessment.
    assert (
        enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=original.enrollment_ref
        )
        == current
    )
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentHealthAssessment)
        ).scalar_one()
        == 2
    )


@pytest.mark.parametrize(
    "revocation",
    [
        "AuthenticatedRuntimeEvidence",
        "AuthenticatedStartupAssignment",
        "InstallationSourceBinding",
        "outage",
        "stale",
    ],
)
def test_current_read_refuses_revocation_outage_or_stale_evidence(admitted, revocation):
    projection = enrollment.enroll_deployment(admitted.db, admitted.command)
    if revocation == "stale":
        admitted.owners.now_value += timedelta(hours=1)
    else:
        admitted.owners.revoked.add(revocation)
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.current_eligibility_get(
            admitted.db, enrollment_ref=projection.enrollment_ref
        )


def test_closure_replay_keeps_historical_identity_and_never_reopens(admitted):
    ctx = admitted
    original = enrollment.enroll_deployment(ctx.db, ctx.command)
    enrollment.close_enrollment(
        ctx.db, enrollment.CloseEnrollmentCommand(original.enrollment_ref, "close-1")
    )
    assert enrollment.enroll_deployment(ctx.db, ctx.command) == original
    assert ctx.db.get(DeploymentCurrentEnrollment, ctx.tid) is None
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentEnrollmentClosure)
        ).scalar_one()
        == 1
    )
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=original.enrollment_ref
        )
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(
            ctx.db, replace(ctx.command, runtime_evidence_ref="runtime-other")
        )


def test_permanent_code_and_installation_uniqueness_survive_closure(admitted):
    ctx = admitted
    projection = enrollment.enroll_deployment(ctx.db, ctx.command)
    ctx.db.commit()
    code = projection.component_codes[0]
    row = ctx.db.execute(select(DeploymentEnrollment)).scalar_one()
    with pytest.raises(IntegrityError), ctx.db.begin_nested():
        ctx.db.add(
            DeploymentEnrollmentComponent(
                component_code=code, enrollment_id=row.id, role="other"
            )
        )
        ctx.db.flush()
    with pytest.raises(IntegrityError), ctx.db.begin_nested():
        ctx.db.add(
            DeploymentEnrollment(
                id=uuid4(),
                enrollment_ref="other",
                attempt_id=uuid4(),
                target_id=ctx.tid,
                installation_ref=row.installation_ref,
                identity_fingerprint="a" * 64,
                projection=row.projection,
                binding=row.binding,
            )
        )
        ctx.db.flush()


def test_raw_producer_dto_and_missing_startup_sources_are_refused(
    admitted, monkeypatch
):
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(admitted.db, {"attempt_id": admitted.aid})
    monkeypatch.setattr(enrollment, "_installed_sources", None)
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(admitted.db, admitted.command)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dispatch_id", str(uuid4())),
        ("authorization_id", str(uuid4())),
        ("authorization_plan_id", str(uuid4())),
        ("rollout_ref", "other-rollout"),
        ("target_id", str(uuid4())),
        ("target_ref", "other-target"),
        ("product_code", "other-product"),
        ("environment", "other-environment"),
        ("operation", "upgrade"),
        ("release_ref", "other-release"),
        ("execution_sequence", 7),
        ("attempt_no", 7),
        ("authorization_envelope_digest", "sha256:" + "91" * 32),
        ("descriptor_digest", "sha256:" + "92" * 32),
        ("execution_plan_digest", "sha256:" + "93" * 32),
        ("plan_digest", "sha256:" + "94" * 32),
    ],
)
def test_retained_dispatch_must_match_every_execution_coordinate(
    admitted, field, value
):
    import copy

    from dotmac_deployment_control.ports import DeploymentControlError

    attempt = admitted.db.get(RolloutAttempt, admitted.aid)
    altered = copy.deepcopy(attempt.dispatch_envelope)
    altered["statement"][field] = value
    attempt.dispatch_envelope = altered
    admitted.db.flush()
    with pytest.raises(DeploymentControlError):
        enrollment.enroll_deployment(admitted.db, admitted.command)


@pytest.mark.parametrize(
    "field,value",
    [
        ("container_id", "other-container"),
        ("process_id", 732),
        ("started_at", _NOW - timedelta(minutes=4)),
        ("image", ("web", "other-registry.test/web", _IMAGE[2])),
    ],
)
def test_startup_assignment_must_name_exact_measured_consumer(admitted, field, value):
    runtime = admitted.owners.runtime["runtime-1"]
    admitted.owners.runtime["runtime-1"] = replace(
        runtime, components=(replace(runtime.components[0], **{field: value}),)
    )
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(admitted.db, admitted.command)


@pytest.mark.parametrize(
    "invalid",
    ["duplicate-role", "unapproved-image", "expired-runtime", "expired-custody"],
)
def test_descriptor_roster_approval_and_independent_validity_are_required(
    admitted, invalid
):
    owners = admitted.owners
    if invalid == "duplicate-role":
        owners.descriptor = replace(owners.descriptor, roles=("web", "web"))
    elif invalid == "unapproved-image":
        owners.descriptor = replace(
            owners.descriptor, images=(("web", _IMAGE[1], "sha256:" + "01" * 32),)
        )
    elif invalid == "expired-runtime":
        owners.runtime["runtime-1"] = replace(
            owners.runtime["runtime-1"], valid_until=_NOW
        )
    else:
        owners.custody["custody-1"] = replace(
            owners.custody["custody-1"], valid_until=_NOW
        )
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.enroll_deployment(admitted.db, admitted.command)


def test_execution_approval_revocation_does_not_revoke_unchanged_health(admitted):
    projection = enrollment.enroll_deployment(admitted.db, admitted.command)
    plan = admitted.db.get(DeploymentPlan, admitted.pid)
    plan.approval_decision_status = "revoked"
    admitted.db.flush()
    assert (
        enrollment.current_eligibility_get(
            admitted.db, enrollment_ref=projection.enrollment_ref
        ).standing
        == "eligible"
    )


def test_changed_credential_generation_requires_new_epoch(admitted):
    projection = enrollment.enroll_deployment(admitted.db, admitted.command)
    owners = admitted.owners
    owners.binding = replace(
        owners.binding, credential_ref="generation-opaque-8", credential_version="8"
    )
    owners.custody["custody-1"] = replace(
        owners.custody["custody-1"], installation=owners.binding
    )
    with pytest.raises(
        enrollment.DeploymentEnrollmentRefusedError, match="binding changed"
    ):
        enrollment.current_eligibility_get(
            admitted.db, enrollment_ref=projection.enrollment_ref
        )


def _successor(ctx):
    from dotmac_deployment_control.authorization import AuthorizationEnvelopeV2

    attempt_id = uuid4()
    auth = AuthorizationEnvelopeV2.parse(
        ctx.db.get(Rollout, ctx.rid).authorization_envelope
    )
    dispatch = issue_dispatch_envelope(
        authorization_envelope=auth,
        dispatch_id=str(attempt_id),
        attempt_no=2,
        issued_at=auth.statement.issued_at,
        signer=TestDispatchSigner(),
    )
    ctx.db.add(
        RolloutAttempt(
            id=attempt_id,
            rollout_id=ctx.rid,
            attempt_no=2,
            dispatch_envelope=dispatch.as_mapping(),
        )
    )
    ctx.db.add(
        RolloutAttemptSettlement(id=uuid4(), attempt_id=attempt_id, outcome="succeeded")
    )
    owners = ctx.owners
    owners.binding = replace(owners.binding, installation_ref="installation-epoch-2")
    owners.runtime["runtime-successor"] = replace(
        owners.runtime["runtime-1"],
        evidence_ref="runtime-successor",
        attempt_id=attempt_id,
    )
    owners.custody["custody-successor"] = replace(
        owners.custody["custody-1"],
        evidence_ref="custody-successor",
        attempt_id=attempt_id,
        runtime_evidence_ref="runtime-successor",
        installation=owners.binding,
    )
    owners.consumed = replace(
        owners.consumed,
        attempt_id=attempt_id,
        dispatch_id=str(attempt_id),
        control_consumption_ref=f"control-dispatch:{attempt_id}",
        dispatch_envelope_digest=DispatchEnvelopeDigestV1.over_bytes(
            dispatch.canonical_bytes
        ).canonical,
    )
    ctx.db.flush()
    return enrollment.EnrollDeploymentCommand(
        attempt_id, "runtime-successor", "custody-successor"
    )


def test_successor_close_and_advance_share_transaction_and_preserve_old_epoch(admitted):
    ctx = admitted
    original = enrollment.enroll_deployment(ctx.db, ctx.command)
    ctx.db.commit()
    successor_command = _successor(ctx)
    ctx.db.commit()
    successor = enrollment.enroll_deployment(ctx.db, successor_command)
    assert set(original.component_codes).isdisjoint(successor.component_codes)
    assert ctx.db.get(DeploymentCurrentEnrollment, ctx.tid).enrollment_id != (
        ctx.db.execute(
            select(DeploymentEnrollment).where(
                DeploymentEnrollment.enrollment_ref == original.enrollment_ref
            )
        )
        .scalar_one()
        .id
    )
    ctx.db.rollback()
    successor_binding = ctx.owners.binding
    ctx.owners.binding = ctx.owners.custody["custody-1"].installation
    assert (
        enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=original.enrollment_ref
        ).standing
        == "eligible"
    )
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentEnrollmentClosure)
        ).scalar_one()
        == 0
    )
    ctx.owners.binding = successor_binding
    successor = enrollment.enroll_deployment(ctx.db, successor_command)
    ctx.db.commit()
    assert (
        enrollment.historical_get(ctx.db, enrollment_ref=original.enrollment_ref)
        == original
    )
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=original.enrollment_ref
        )
    assert (
        enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=successor.enrollment_ref
        ).standing
        == "eligible"
    )


@pytest.mark.parametrize("operation", ["enroll", "assess", "current"])
@pytest.mark.parametrize("position", ["before-end", "exact-end", "after-end"])
def test_owner_io_clock_advance_checks_original_bounds(
    admitted, monkeypatch, operation, position
):
    ctx = admitted
    if operation != "enroll":
        projection = enrollment.enroll_deployment(ctx.db, ctx.command)
        ctx.db.commit()
    before_enrollments = ctx.db.execute(
        select(func.count()).select_from(DeploymentEnrollment)
    ).scalar_one()
    before_assessments = ctx.db.execute(
        select(func.count()).select_from(DeploymentHealthAssessment)
    ).scalar_one()
    end = ctx.owners.custody["custody-1"].valid_until
    finish = (
        end
        + {
            "before-end": -timedelta(microseconds=1),
            "exact-end": timedelta(0),
            "after-end": timedelta(microseconds=1),
        }[position]
    )
    original_check = ctx.owners.require_current

    def advance_clock_after_owner_check(evidence, *, at):
        original_check(evidence, at=at)
        if isinstance(evidence, enrollment.InstallationSourceBinding):
            ctx.owners.now_value = finish

    monkeypatch.setattr(ctx.owners, "require_current", advance_clock_after_owner_check)

    def invoke():
        if operation == "enroll":
            return enrollment.enroll_deployment(ctx.db, ctx.command)
        if operation == "assess":
            return enrollment.assess_health_eligibility(
                ctx.db,
                enrollment.AssessHealthEligibilityCommand(
                    projection.enrollment_ref,
                    "io-clock-assessment",
                    "runtime-1",
                    "custody-1",
                ),
            )
        return enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=projection.enrollment_ref
        )

    if position == "before-end":
        result = invoke()
        assert (
            result.eligible_until if operation == "enroll" else result.valid_until
        ) == end
    else:
        with pytest.raises(
            enrollment.DeploymentEnrollmentRefusedError, match="expired|regressed"
        ):
            invoke()
        assert (
            ctx.db.execute(
                select(func.count()).select_from(DeploymentEnrollment)
            ).scalar_one()
            == before_enrollments
        )
        assert (
            ctx.db.execute(
                select(func.count()).select_from(DeploymentHealthAssessment)
            ).scalar_one()
            == before_assessments
        )


def test_current_assessment_rejects_clock_rollback_behind_assessed_at(admitted):
    ctx = admitted
    projection = enrollment.enroll_deployment(ctx.db, ctx.command)
    ctx.db.commit()
    ctx.owners.now_value = _NOW + timedelta(minutes=2)
    # Evidence observed at T remains owner-valid, but the refresh was assessed at T+2.
    assessment = enrollment.assess_health_eligibility(
        ctx.db,
        enrollment.AssessHealthEligibilityCommand(
            projection.enrollment_ref, "assessed-at-plus-two", "runtime-1", "custody-1"
        ),
    )
    ctx.db.commit()
    assert assessment.assessed_at == _NOW + timedelta(minutes=2)
    ctx.owners.now_value = _NOW + timedelta(minutes=1)
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError):
        enrollment.current_eligibility_get(
            ctx.db, enrollment_ref=projection.enrollment_ref
        )
    count = ctx.db.execute(
        select(func.count()).select_from(DeploymentHealthAssessment)
    ).scalar_one()
    with pytest.raises(
        enrollment.DeploymentEnrollmentRefusedError, match="durable history"
    ):
        enrollment.assess_health_eligibility(
            ctx.db,
            enrollment.AssessHealthEligibilityCommand(
                projection.enrollment_ref,
                "regressed-assessment",
                "runtime-1",
                "custody-1",
            ),
        )
    assert (
        ctx.db.execute(
            select(func.count()).select_from(DeploymentHealthAssessment)
        ).scalar_one()
        == count
    )


@pytest.mark.parametrize("operation", ["enroll", "assess", "current"])
def test_owner_io_clock_regression_is_refused(admitted, monkeypatch, operation):
    ctx = admitted
    if operation != "enroll":
        projection = enrollment.enroll_deployment(ctx.db, ctx.command)
        ctx.db.commit()
    original_check = ctx.owners.require_current

    def regress_after_owner_check(evidence, *, at):
        original_check(evidence, at=at)
        if isinstance(evidence, enrollment.InstallationSourceBinding):
            ctx.owners.now_value = _NOW - timedelta(microseconds=1)

    monkeypatch.setattr(ctx.owners, "require_current", regress_after_owner_check)
    with pytest.raises(enrollment.DeploymentEnrollmentRefusedError, match="regressed"):
        if operation == "enroll":
            enrollment.enroll_deployment(ctx.db, ctx.command)
        elif operation == "assess":
            enrollment.assess_health_eligibility(
                ctx.db,
                enrollment.AssessHealthEligibilityCommand(
                    projection.enrollment_ref, "io-regression", "runtime-1", "custody-1"
                ),
            )
        else:
            enrollment.current_eligibility_get(
                ctx.db, enrollment_ref=projection.enrollment_ref
            )
