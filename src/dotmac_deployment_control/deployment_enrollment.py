"""Control-owned health epochs; source preparation, never an execution permission.

The composing assembly MUST install authenticated durable owner adapters. Their
lookup methods authenticate stored evidence; none accepts a producer DTO, a
caller verifier, a role list, or a claimed verification boolean. Descriptor
qualification belongs to Foundation's parsed V5 owner, transport/installation
identity to its existing owner, runtime measurement and credential custody to
independent owners. No accepting production implementation is supplied here.

Mutations flush in the caller's transaction. A required consumption reader opens
a separate NEW transaction and calls the public
``lookup_foundation_execution_consumption`` after execution committed. Its
verified EXECUTED ledger is historical provenance, with no invented timestamp
and no present-day re-verification of expired execution tokens. Health never
consumes another execution token. Source outages and revoked standing refuse.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from threading import Lock
from typing import Any, Protocol, TypeVar, cast
from uuid import UUID, uuid4

from dotmac_kernel.audit import write_platform_audit_event
from dotmac_kernel.fingerprints import fingerprint_of
from dotmac_kernel.idempotency import IdempotencyConflict, execute_once_platform
from dotmac_kernel.transactions import conflict_savepoint
from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_deployment_control.authorization import AuthorizationEnvelopeV2
from dotmac_deployment_control.digests import (
    AuthorizationEnvelopeDigestV1,
    DescriptorDigestV1,
    DispatchEnvelopeDigestV1,
    ExecutionPlanDigestV1,
    PlanDigestV1,
)
from dotmac_deployment_control.dispatch_envelope import DispatchEnvelopeV1
from dotmac_deployment_control.foundation_consumption import (
    FoundationCommittedConsumptionV1,
    lookup_foundation_execution_consumption,
)
from dotmac_deployment_control.host_admission_service import (
    require_current_target_host_locked,
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
)
from dotmac_deployment_control.ports import DeploymentControlError


class DeploymentEnrollmentRefusedError(DeploymentControlError):
    """Missing, conflicting, expired, revoked, or unresolved owner evidence."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise DeploymentEnrollmentRefusedError(reason)


def _text(value: str) -> None:
    _require(
        isinstance(value, str) and bool(value.strip()) and len(value) <= 200,
        "bounded nonempty owner reference required",
    )


def _instant(value: datetime) -> datetime:
    _require(
        isinstance(value, datetime) and value.utcoffset() is not None,
        "owner time must be aware",
    )
    return value


def _hash(document: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class EnrollmentProjection:
    """Structural PH contract. Original evidence references never change."""

    enrollment_ref: str
    installation_ref: str
    configuration_ref: str
    candidate_ref: str
    source_ref: str
    account_ref: str
    transport_ref: str
    credential_ref: str
    component_codes: tuple[str, ...]
    runtime_evidence_ref: str
    runtime_authority_ref: str
    credential_evidence_ref: str
    credential_authority_ref: str
    eligible_from: datetime
    eligible_until: datetime
    standing: str

    def document(self) -> dict[str, object]:
        result = asdict(self)
        result["component_codes"] = sorted(self.component_codes)
        result["eligible_from"] = self.eligible_from.isoformat()
        result["eligible_until"] = self.eligible_until.isoformat()
        return result

    def identity_document(self) -> dict[str, object]:
        return {
            key: value
            for key, value in self.document().items()
            if key not in {"eligible_from", "eligible_until", "standing"}
        }

    @property
    def identity_fingerprint(self) -> str:
        return _hash(self.identity_document())

    @property
    def fingerprint(self) -> str:
        return _hash(self.document())


@dataclass(frozen=True, slots=True)
class HealthEligibilityAssessment:
    assessment_ref: str
    enrollment_ref: str
    identity_fingerprint: str
    assessed_at: datetime
    valid_from: datetime
    valid_until: datetime
    standing: str
    runtime_evidence_ref: str
    runtime_authority_ref: str
    credential_evidence_ref: str
    credential_authority_ref: str

    def document(self) -> dict[str, object]:
        result = asdict(self)
        for name in ("assessed_at", "valid_from", "valid_until"):
            result[name] = getattr(self, name).isoformat()
        return result


@dataclass(frozen=True, slots=True)
class QualifiedDescriptor:
    """Foundation adapter output from exact digest and complete parsed V5.

    roles are every active role, not a producer-selected subset. Each image is
    (service, repository, digest); configuration_ref and candidate_ref must be
    the V5 owner's canonical qualified coordinates.
    """

    descriptor_digest: str
    roles: tuple[str, ...]
    images: tuple[tuple[str, str, str], ...]
    configuration_ref: str
    candidate_ref: str


@dataclass(frozen=True, slots=True)
class InstallationSourceBinding:
    """Existing installation/transport owner result; never Foundation DTO data.

    credential_ref is the owner's immutable generation reference, retained
    verbatim. original_credential_ref and credential_version are separate and
    never concatenated into a replacement identity.
    """

    installation_ref: str
    configuration_ref: str
    source_ref: str
    account_ref: str
    transport_ref: str
    credential_ref: str
    original_credential_ref: str
    credential_version: str


@dataclass(frozen=True, slots=True)
class RuntimeComponent:
    role: str
    container_id: str
    started_at: datetime
    process_id: int
    image: tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class AuthenticatedRuntimeEvidence:
    evidence_ref: str
    authority_ref: str
    attempt_id: UUID
    host_id: str
    host_incarnation: str
    configuration_ref: str
    candidate_ref: str
    components: tuple[RuntimeComponent, ...]
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class AuthenticatedStartupAssignment:
    evidence_ref: str
    authority_ref: str
    attempt_id: UUID
    host_id: str
    host_incarnation: str
    runtime_evidence_ref: str
    installation: InstallationSourceBinding
    # Exact startup consumers, including their immutable container/start/PID.
    components: tuple[RuntimeComponent, ...]
    assigned_at: datetime
    valid_from: datetime
    valid_until: datetime


class DescriptorSource(Protocol):
    def require_ready(self) -> None: ...
    def qualified_v5(self, descriptor_digest: str) -> QualifiedDescriptor:
        """Resolve exact frozen digest through Foundation's parsed V5 owner."""
        ...


class RuntimeSource(Protocol):
    def require_ready(self) -> None: ...
    def authenticated_lookup(self, evidence_ref: str) -> AuthenticatedRuntimeEvidence:
        """Authenticate durable measurement, never producer claim material."""
        ...

    def require_current(
        self, evidence: AuthenticatedRuntimeEvidence, *, at: datetime
    ) -> None: ...


class StartupAssignmentSource(Protocol):
    def require_ready(self) -> None: ...
    def authenticated_lookup(self, evidence_ref: str) -> AuthenticatedStartupAssignment:
        """Authenticate historical startup custody and exact consumers."""
        ...

    def require_current(
        self, assignment: AuthenticatedStartupAssignment, *, at: datetime
    ) -> None: ...


class InstallationSource(Protocol):
    def require_ready(self) -> None: ...
    def authenticated_lookup(
        self, *, attempt_id: UUID, configuration_ref: str
    ) -> InstallationSourceBinding: ...
    def require_current(
        self, binding: InstallationSourceBinding, *, at: datetime
    ) -> None: ...


class CommittedConsumptionSource(Protocol):
    def require_ready(self) -> None: ...
    def lookup_in_new_transaction(
        self, *, control_consumption_ref: str
    ) -> FoundationCommittedConsumptionV1 | None:
        """Call public Control lookup using fresh separate postcommit Session.

        Never read the command's Session, synthesize a DTO, use a private staged
        marker or invoke a finalizer. The assembly owns the transaction factory.
        """
        ...


class PublicCommittedConsumptionReader:
    """Reuse an assembly-owned separate committed read scope; no DB authority.

    The required scope must be the existing owner's fresh postcommit read-only
    scope. This adapter constructs no Session/engine, begins no transaction,
    commits nothing and cannot accept a producer's consumption DTO.
    """

    def __init__(
        self, *, committed_read_scope: Callable[[], AbstractContextManager[Session]]
    ) -> None:
        if not callable(committed_read_scope):
            raise TypeError("existing committed read scope required")
        self._read_scope = committed_read_scope

    def require_ready(self) -> None:
        if not callable(self._read_scope):
            raise DeploymentEnrollmentRefusedError("committed read scope unavailable")

    def lookup_in_new_transaction(
        self, *, control_consumption_ref: str
    ) -> FoundationCommittedConsumptionV1 | None:
        with self._read_scope() as db:
            return lookup_foundation_execution_consumption(
                db, control_consumption_ref=control_consumption_ref
            )


class EnrollmentClock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class _Sources:
    descriptors: DescriptorSource
    runtime: RuntimeSource
    custody: StartupAssignmentSource
    installations: InstallationSource
    consumption: CommittedConsumptionSource
    clock: EnrollmentClock


_INSTALL_LOCK = Lock()
_installed_sources: _Sources | None = None


def install_sources(
    *,
    descriptors: DescriptorSource,
    runtime: RuntimeSource,
    custody: StartupAssignmentSource,
    installations: InstallationSource,
    consumption: CommittedConsumptionSource,
    clock: EnrollmentClock,
) -> None:
    """Install required trusted owner adapters exactly once during startup."""
    sources = _Sources(descriptors, runtime, custody, installations, consumption, clock)
    for owner in (descriptors, runtime, custody, installations, consumption):
        owner.require_ready()
    _instant(clock.now())
    global _installed_sources
    with _INSTALL_LOCK:
        if _installed_sources is not None:
            raise RuntimeError("deployment enrollment sources already installed")
        _installed_sources = sources


def _sources() -> _Sources:
    _require(_installed_sources is not None, "enrollment sources not installed")
    assert _installed_sources is not None
    for owner in (
        _installed_sources.descriptors,
        _installed_sources.runtime,
        _installed_sources.custody,
        _installed_sources.installations,
        _installed_sources.consumption,
    ):
        owner.require_ready()
    return _installed_sources


@dataclass(frozen=True, slots=True)
class EnrollDeploymentCommand:
    command_id: str
    attempt_id: UUID
    runtime_evidence_ref: str
    credential_evidence_ref: str
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class AssessHealthEligibilityCommand:
    command_id: str
    enrollment_ref: str
    assessment_ref: str
    runtime_evidence_ref: str
    credential_evidence_ref: str
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class CloseEnrollmentCommand:
    command_id: str
    enrollment_ref: str
    closure_ref: str
    actor_ref: str | None = None


AUDIT_ACTION_HEALTH_ENROLLMENT = "deployment.health_enrollment.changed"
_SCOPE_ENROLL = "deployment.enroll_deployment.v1"
_SCOPE_ASSESS = "deployment.assess_health_eligibility.v1"
_SCOPE_CLOSE = "deployment.close_enrollment.v1"


def _code(attempt_id: UUID, role: str) -> str:
    return (
        f"dc1:{attempt_id.hex}:"
        + hashlib.sha256(b"dc-health-role:v1\0" + role.encode()).hexdigest()
    )


_Model = TypeVar("_Model")


def _one(db: Session, model: type[_Model], **coordinates: object) -> _Model:
    query = (
        select(model).filter_by(**coordinates).execution_options(populate_existing=True)
    )
    row = db.execute(query).scalar_one_or_none()
    _require(row is not None, "Control coordinate unresolved")
    return cast(_Model, row)


def _locked_execution(
    db: Session, attempt_id: UUID
) -> tuple[DeploymentTarget, DeploymentPlan, Rollout, RolloutAttempt]:
    # Locate immutable issuance without locking it, then take established order.
    attempt = _one(db, RolloutAttempt, id=attempt_id)
    locator = _one(db, Rollout, id=attempt.rollout_id)
    target = db.execute(
        select(DeploymentTarget)
        .where(DeploymentTarget.id == locator.target_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    plan = db.execute(
        select(DeploymentPlan)
        .where(DeploymentPlan.id == locator.plan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    rollout = db.execute(
        select(Rollout)
        .where(Rollout.id == locator.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    attempt = _one(db, RolloutAttempt, id=attempt_id)
    _require(
        attempt.rollout_id == rollout.id
        and rollout.target_id == target.id
        and rollout.plan_id == plan.id
        and plan.target_id == target.id,
        "execution ownership differs",
    )
    return target, plan, rollout, attempt


def _execution(
    db: Session,
    sources: _Sources,
    target: DeploymentTarget,
    plan: DeploymentPlan,
    rollout: Rollout,
    attempt: RolloutAttempt,
) -> QualifiedDescriptor:
    settlement = _one(db, RolloutAttemptSettlement, attempt_id=attempt.id)
    _require(settlement.outcome == "succeeded", "successful settlement required")
    _require(plan.purpose == "foundation_execution", "Foundation execution required")
    snapshot = plan.snapshot
    _require(isinstance(snapshot, dict), "frozen plan required")
    assert isinstance(snapshot, dict)
    _require(
        rollout.authorization_envelope is not None
        and attempt.dispatch_envelope is not None,
        "retained signed pair required",
    )
    auth = AuthorizationEnvelopeV2.parse(rollout.authorization_envelope)
    dispatch = DispatchEnvelopeV1.parse(attempt.dispatch_envelope)
    signed, sent = auth.statement, dispatch.statement
    auth_digest = AuthorizationEnvelopeDigestV1.over_bytes(
        auth.canonical_bytes
    ).canonical
    dispatch_digest = DispatchEnvelopeDigestV1.over_bytes(
        dispatch.canonical_bytes
    ).canonical
    _require(
        PlanDigestV1.over_json(snapshot) == PlanDigestV1.parse(plan.plan_digest),
        "frozen snapshot digest differs",
    )
    frozen_descriptor = DescriptorDigestV1.parse(snapshot.get("descriptor_digest"))
    expected = {
        "product_code": target.product_code,
        "environment": target.environment,
        "target_id": str(target.id),
        "target_ref": target.target_ref,
        "operation": plan.authorized_operation,
        "release_ref": snapshot.get("release_ref"),
        "rollout_ref": rollout.rollout_ref,
        "execution_sequence": rollout.execution_sequence,
    }
    for key, value in expected.items():
        _require(
            value is not None
            and getattr(signed, key) == value
            and getattr(sent, key) == value,
            "retained signed coordinate differs",
        )
    _require(
        signed.authorization_id == str(rollout.id)
        and signed.plan_id == str(plan.id)
        and signed.approval_decision_ref == plan.approval_decision_ref
        and signed.approval_decision_ref is not None
        and sent.authorization_id == str(rollout.id)
        and sent.authorization_plan_id == str(plan.id)
        and sent.dispatch_id == str(attempt.id)
        and sent.attempt_no == attempt.attempt_no
        and sent.authorization_envelope_digest == auth_digest,
        "retained decision or dispatch identity differs",
    )
    _require(
        PlanDigestV1.parse(signed.plan_digest)
        == PlanDigestV1.parse(plan.plan_digest)
        == PlanDigestV1.parse(sent.plan_digest),
        "frozen Control plan differs",
    )
    execution = ExecutionPlanDigestV1.parse(plan.execution_plan_digest)
    _require(
        execution
        == ExecutionPlanDigestV1.parse(plan.authorized_execution_plan_digest)
        == ExecutionPlanDigestV1.parse(signed.execution_plan_digest)
        == ExecutionPlanDigestV1.parse(sent.execution_plan_digest),
        "frozen execution plan differs",
    )
    _require(
        frozen_descriptor
        == DescriptorDigestV1.parse(signed.descriptor_digest)
        == DescriptorDigestV1.parse(sent.descriptor_digest),
        "frozen descriptor differs",
    )
    committed = sources.consumption.lookup_in_new_transaction(
        control_consumption_ref=f"control-dispatch:{attempt.id}"
    )
    _require(
        type(committed) is FoundationCommittedConsumptionV1,
        "separate committed consumption required",
    )
    assert isinstance(committed, FoundationCommittedConsumptionV1)
    _require(
        committed.attempt_id == attempt.id
        and committed.dispatch_id == str(attempt.id)
        and committed.control_consumption_ref == f"control-dispatch:{attempt.id}"
        and committed.authorization_envelope_digest == auth_digest
        and committed.dispatch_envelope_digest == dispatch_digest
        and ExecutionPlanDigestV1.parse(committed.execution_plan_digest) == execution,
        "committed consumption differs from retained successful attempt",
    )
    descriptor = sources.descriptors.qualified_v5(frozen_descriptor.canonical)
    _require(
        type(descriptor) is QualifiedDescriptor
        and DescriptorDigestV1.parse(descriptor.descriptor_digest) == frozen_descriptor,
        "exact Foundation-qualified V5 descriptor required",
    )
    _require(
        isinstance(descriptor.roles, tuple)
        and 1 <= len(descriptor.roles) <= 100
        and len(set(descriptor.roles)) == len(descriptor.roles),
        "complete unique bounded active roles required",
    )
    for role in descriptor.roles:
        _text(role)
    _text(descriptor.configuration_ref)
    _text(descriptor.candidate_ref)
    images = tuple(
        (i.service, i.repository, i.digest.canonical) for i in signed.authorized_images
    )
    _require(
        isinstance(descriptor.images, tuple)
        and len(set(descriptor.images)) == len(descriptor.images)
        and set(descriptor.images) == set(images)
        and signed.authorized_images == sent.authorized_images,
        "descriptor images differ from approved images",
    )
    _require(plan.operation == plan.authorized_operation, "frozen operation differs")
    return descriptor


def _current_host(db: Session, target_id: UUID) -> str:
    # Caller already holds the target lock; reuse the host owner's complete
    # history/pointer/uniqueness/Fleet-grammar guard, including its refusal codes.
    return require_current_target_host_locked(db, target_id).host_id


def _checked_time(
    sources: _Sources,
    *,
    sampled_at: datetime,
    assessed_at: datetime,
    start: datetime,
    end: datetime,
) -> datetime:
    """Recheck the trusted clock after I/O against unchanged original bounds."""
    final_now = _instant(sources.clock.now())
    _require(
        start <= assessed_at <= sampled_at <= final_now < end,
        "health evidence expired or trusted clock regressed",
    )
    return final_now


def _evidence(
    sources: _Sources,
    *,
    attempt_id: UUID,
    host_id: str,
    descriptor: QualifiedDescriptor,
    runtime_ref: str,
    custody_ref: str,
    now: datetime,
) -> tuple[
    AuthenticatedRuntimeEvidence,
    AuthenticatedStartupAssignment,
    InstallationSourceBinding,
    datetime,
    datetime,
    datetime,
]:
    _text(runtime_ref)
    _text(custody_ref)
    runtime = sources.runtime.authenticated_lookup(runtime_ref)
    custody = sources.custody.authenticated_lookup(custody_ref)
    binding = sources.installations.authenticated_lookup(
        attempt_id=attempt_id, configuration_ref=descriptor.configuration_ref
    )
    _require(
        type(runtime) is AuthenticatedRuntimeEvidence
        and type(custody) is AuthenticatedStartupAssignment
        and type(binding) is InstallationSourceBinding,
        "typed authenticated owner results required",
    )
    _require(
        runtime.evidence_ref == runtime_ref
        and custody.evidence_ref == custody_ref
        and runtime.attempt_id == custody.attempt_id == attempt_id
        and runtime.host_id == custody.host_id == host_id
        and runtime.host_incarnation == custody.host_incarnation
        and bool(runtime.host_incarnation)
        and custody.runtime_evidence_ref == runtime_ref,
        "authenticated runtime/startup coordinates differ",
    )
    _require(
        runtime.configuration_ref
        == binding.configuration_ref
        == descriptor.configuration_ref
        and runtime.candidate_ref == descriptor.candidate_ref
        and custody.installation == binding,
        "independent owner installation/configuration joins differ",
    )
    for value in asdict(binding).values():
        _text(value)
    _text(runtime.host_incarnation)
    _text(runtime.authority_ref)
    _text(custody.authority_ref)
    _require(
        runtime.authority_ref != custody.authority_ref,
        "runtime and custody require independent authorities",
    )
    _require(
        isinstance(runtime.components, tuple)
        and len(runtime.components) == len(descriptor.roles)
        and {c.role for c in runtime.components} == set(descriptor.roles)
        and len({c.role for c in runtime.components}) == len(runtime.components)
        and isinstance(custody.components, tuple)
        and sorted(custody.components, key=lambda c: c.role)
        == sorted(runtime.components, key=lambda c: c.role),
        "exact complete runtime/startup component roster differs",
    )
    for component in runtime.components:
        _require(
            type(component) is RuntimeComponent, "typed runtime component required"
        )
        _text(component.container_id)
        _require(
            type(component.process_id) is int and component.process_id > 0,
            "exact process identity required",
        )
        _require(
            component.image in descriptor.images
            and component.image[0] == component.role,
            "runtime role image differs from descriptor",
        )
        _require(
            _instant(component.started_at) <= _instant(runtime.observed_at) <= now
            and _instant(custody.assigned_at) <= now,
            "startup assignment/measurement chronology differs",
        )
    sources.runtime.require_current(runtime, at=now)
    sources.custody.require_current(custody, at=now)
    sources.installations.require_current(binding, at=now)
    start = max(_instant(runtime.valid_from), _instant(custody.valid_from))
    end = min(_instant(runtime.valid_until), _instant(custody.valid_until))
    _require(
        start <= now < end, "authenticated evidence validity does not intersect now"
    )
    checked_at = _checked_time(
        sources, sampled_at=now, assessed_at=now, start=start, end=end
    )
    return runtime, custody, binding, start, end, checked_at


def _projection(document: dict[str, object]) -> EnrollmentProjection:
    data: dict[str, Any] = dict(document)
    data["component_codes"] = tuple(data["component_codes"])
    for key in ("eligible_from", "eligible_until"):
        data[key] = datetime.fromisoformat(data[key])
    return EnrollmentProjection(**data)


def _assessment(document: dict[str, object]) -> HealthEligibilityAssessment:
    data: dict[str, Any] = dict(document)
    for key in ("assessed_at", "valid_from", "valid_until"):
        data[key] = datetime.fromisoformat(data[key])
    return HealthEligibilityAssessment(**data)


def _append_assessment(
    db: Session,
    enrollment: DeploymentEnrollment,
    *,
    assessment_ref: str,
    runtime: AuthenticatedRuntimeEvidence,
    custody: AuthenticatedStartupAssignment,
    now: datetime,
    start: datetime,
    end: datetime,
) -> HealthEligibilityAssessment:
    _text(assessment_ref)
    result = HealthEligibilityAssessment(
        assessment_ref,
        enrollment.enrollment_ref,
        enrollment.identity_fingerprint,
        now,
        start,
        end,
        "eligible",
        runtime.evidence_ref,
        runtime.authority_ref,
        custody.evidence_ref,
        custody.authority_ref,
    )
    latest = db.execute(
        select(DeploymentHealthAssessment)
        .where(DeploymentHealthAssessment.enrollment_id == enrollment.id)
        .order_by(DeploymentHealthAssessment.sequence.desc())
        .limit(1)
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    _require(
        latest is None or _assessment(latest.document).assessed_at <= now,
        "assessment time cannot regress behind durable history",
    )
    sequence = 0 if latest is None else latest.sequence
    db.add(
        DeploymentHealthAssessment(
            sequence=sequence + 1,
            id=uuid4(),
            assessment_ref=assessment_ref,
            enrollment_id=enrollment.id,
            assessed_at=now,
            document=result.document(),
        )
    )
    return result


def _enroll_deployment(
    db: Session, command: EnrollDeploymentCommand
) -> tuple[EnrollmentProjection, datetime | None]:
    """Create a new epoch and close the old target epoch atomically; flush only."""
    _require(
        type(command) is EnrollDeploymentCommand, "typed reference command required"
    )
    sources = _sources()
    target, plan, rollout, attempt = _locked_execution(db, command.attempt_id)
    now = _instant(sources.clock.now())
    old = db.execute(
        select(DeploymentEnrollment).where(
            DeploymentEnrollment.attempt_id == attempt.id
        )
    ).scalar_one_or_none()
    if old is not None:
        projection = _projection(old.projection)
        _require(
            projection.runtime_evidence_ref == command.runtime_evidence_ref
            and projection.credential_evidence_ref == command.credential_evidence_ref,
            "attempt already enrolled with different original provenance",
        )
        # Historical replay never reopens a closed/superseded epoch.
        return projection, None
    descriptor = _execution(db, sources, target, plan, rollout, attempt)
    runtime, custody, binding, start, end, checked_at = _evidence(
        sources,
        attempt_id=attempt.id,
        host_id=_current_host(db, target.id),
        descriptor=descriptor,
        runtime_ref=command.runtime_evidence_ref,
        custody_ref=command.credential_evidence_ref,
        now=now,
    )
    now = _checked_time(
        sources, sampled_at=checked_at, assessed_at=checked_at, start=start, end=end
    )
    projection = EnrollmentProjection(
        f"control-health:{attempt.id}",
        binding.installation_ref,
        binding.configuration_ref,
        descriptor.candidate_ref,
        binding.source_ref,
        binding.account_ref,
        binding.transport_ref,
        binding.credential_ref,
        tuple(sorted(_code(attempt.id, role) for role in descriptor.roles)),
        runtime.evidence_ref,
        runtime.authority_ref,
        custody.evidence_ref,
        custody.authority_ref,
        start,
        end,
        "eligible",
    )
    with conflict_savepoint(db):
        enrollment = DeploymentEnrollment(
            id=uuid4(),
            enrollment_ref=projection.enrollment_ref,
            attempt_id=attempt.id,
            target_id=target.id,
            installation_ref=binding.installation_ref,
            identity_fingerprint=projection.identity_fingerprint,
            projection=projection.document(),
            binding={
                "installation": asdict(binding),
                "descriptor_digest": descriptor.descriptor_digest,
                "host_id": runtime.host_id,
                "host_incarnation": runtime.host_incarnation,
                "components": [
                    {
                        "role": c.role,
                        "container_id": c.container_id,
                        "started_at": c.started_at.isoformat(),
                        "process_id": c.process_id,
                        "image": list(c.image),
                    }
                    for c in sorted(runtime.components, key=lambda c: c.role)
                ],
            },
        )
        pointer = db.get(DeploymentCurrentEnrollment, target.id, populate_existing=True)
        history = (
            db.execute(
                select(DeploymentEnrollment).where(
                    DeploymentEnrollment.target_id == target.id
                )
            )
            .scalars()
            .all()
        )
        for prior in history:
            prior_attempt = _one(db, RolloutAttempt, id=prior.attempt_id)
            prior_rollout = _one(db, Rollout, id=prior_attempt.rollout_id)
            _require(
                (rollout.execution_sequence, attempt.attempt_no)
                > (prior_rollout.execution_sequence, prior_attempt.attempt_no),
                "older attempt cannot replace a current epoch",
            )
        db.add(enrollment)
        checked_at = _checked_time(
            sources, sampled_at=now, assessed_at=now, start=start, end=end
        )
        db.flush()
        for role in descriptor.roles:
            db.add(
                DeploymentEnrollmentComponent(
                    component_code=_code(attempt.id, role),
                    enrollment_id=enrollment.id,
                    role=role,
                )
            )
        if pointer is None:
            db.add(
                DeploymentCurrentEnrollment(
                    target_id=target.id, enrollment_id=enrollment.id
                )
            )
        else:
            db.add(
                DeploymentEnrollmentClosure(
                    enrollment_id=pointer.enrollment_id,
                    target_id=target.id,
                    closed_at=now,
                    closure_ref=f"successor:{enrollment.enrollment_ref}",
                    successor_id=enrollment.id,
                )
            )
            pointer.enrollment_id = enrollment.id
        _append_assessment(
            db,
            enrollment,
            assessment_ref=f"initial:{attempt.id}",
            runtime=runtime,
            custody=custody,
            now=now,
            start=start,
            end=end,
        )
        checked_at = _checked_time(
            sources, sampled_at=checked_at, assessed_at=now, start=start, end=end
        )
        db.flush()
        checked_at = _checked_time(
            sources, sampled_at=checked_at, assessed_at=now, start=start, end=end
        )
    return projection, checked_at


def historical_get(db: Session, *, enrollment_ref: str) -> EnrollmentProjection:
    """Read immutable original identity, including closed epochs; no eligibility."""
    row = _one(db, DeploymentEnrollment, enrollment_ref=enrollment_ref)
    result = _projection(row.projection)
    _require(
        result.identity_fingerprint == row.identity_fingerprint,
        "immutable identity differs",
    )
    return result


def _current(db: Session, row: DeploymentEnrollment) -> None:
    pointer = db.get(DeploymentCurrentEnrollment, row.target_id, populate_existing=True)
    _require(
        pointer is not None
        and pointer.enrollment_id == row.id
        and db.get(DeploymentEnrollmentClosure, row.id, populate_existing=True) is None,
        "enrollment is closed or superseded",
    )


def _unchanged(
    row: DeploymentEnrollment,
    runtime: AuthenticatedRuntimeEvidence,
    binding: InstallationSourceBinding,
) -> None:
    components = [
        {
            "role": c.role,
            "container_id": c.container_id,
            "started_at": c.started_at.isoformat(),
            "process_id": c.process_id,
            "image": list(c.image),
        }
        for c in sorted(runtime.components, key=lambda c: c.role)
    ]
    _require(
        row.binding["installation"] == asdict(binding)
        and row.binding["host_id"] == runtime.host_id
        and row.binding["host_incarnation"] == runtime.host_incarnation
        and row.binding["components"] == components,
        "immutable epoch binding changed; new attempt/enrollment required",
    )


def _refresh_evidence(
    db: Session,
    row: DeploymentEnrollment,
    sources: _Sources,
    *,
    runtime_ref: str,
    custody_ref: str,
    now: datetime,
) -> tuple[
    AuthenticatedRuntimeEvidence,
    AuthenticatedStartupAssignment,
    datetime,
    datetime,
    datetime,
]:
    _current(db, row)
    projection = historical_get(db, enrollment_ref=row.enrollment_ref)
    descriptor = sources.descriptors.qualified_v5(row.binding["descriptor_digest"])
    _require(
        DescriptorDigestV1.parse(descriptor.descriptor_digest)
        == DescriptorDigestV1.parse(row.binding["descriptor_digest"])
        and tuple(sorted(_code(row.attempt_id, role) for role in descriptor.roles))
        == projection.component_codes
        and descriptor.configuration_ref == projection.configuration_ref
        and descriptor.candidate_ref == projection.candidate_ref,
        "qualified immutable descriptor identity changed",
    )
    runtime, custody, binding, start, end, checked_at = _evidence(
        sources,
        attempt_id=row.attempt_id,
        host_id=_current_host(db, row.target_id),
        descriptor=descriptor,
        runtime_ref=runtime_ref,
        custody_ref=custody_ref,
        now=now,
    )
    _unchanged(row, runtime, binding)
    return runtime, custody, start, end, checked_at


def _assess_health_eligibility(
    db: Session, command: AssessHealthEligibilityCommand
) -> tuple[HealthEligibilityAssessment, datetime | None]:
    """Explicit authenticated refresh; append, never rewrite baseline identity."""
    _require(
        type(command) is AssessHealthEligibilityCommand,
        "typed reference command required",
    )
    row = _one(db, DeploymentEnrollment, enrollment_ref=command.enrollment_ref)
    _locked_execution(db, row.attempt_id)
    existing = db.execute(
        select(DeploymentHealthAssessment).where(
            DeploymentHealthAssessment.assessment_ref == command.assessment_ref
        )
    ).scalar_one_or_none()
    if existing is not None:
        result = _assessment(existing.document)
        _require(
            existing.enrollment_id == row.id
            and result.runtime_evidence_ref == command.runtime_evidence_ref
            and result.credential_evidence_ref == command.credential_evidence_ref,
            "assessment reference conflict",
        )
        return result, None
    sources = _sources()
    now = _instant(sources.clock.now())
    runtime, custody, start, end, checked_at = _refresh_evidence(
        db,
        row,
        sources,
        runtime_ref=command.runtime_evidence_ref,
        custody_ref=command.credential_evidence_ref,
        now=now,
    )
    now = _checked_time(
        sources, sampled_at=checked_at, assessed_at=checked_at, start=start, end=end
    )
    with conflict_savepoint(db):
        result = _append_assessment(
            db,
            row,
            assessment_ref=command.assessment_ref,
            runtime=runtime,
            custody=custody,
            now=now,
            start=start,
            end=end,
        )
        checked_at = _checked_time(
            sources,
            sampled_at=now,
            assessed_at=result.assessed_at,
            start=result.valid_from,
            end=result.valid_until,
        )
        db.flush()
        checked_at = _checked_time(
            sources,
            sampled_at=checked_at,
            assessed_at=result.assessed_at,
            start=result.valid_from,
            end=result.valid_until,
        )
    return result, checked_at


def current_eligibility_get(
    db: Session, *, enrollment_ref: str
) -> HealthEligibilityAssessment:
    """Check owners now against the last appended assessment; never renew on read."""
    sources = _sources()
    row = _one(db, DeploymentEnrollment, enrollment_ref=enrollment_ref)
    _locked_execution(db, row.attempt_id)
    now = _instant(sources.clock.now())
    latest = db.execute(
        select(DeploymentHealthAssessment)
        .where(DeploymentHealthAssessment.enrollment_id == row.id)
        .order_by(
            DeploymentHealthAssessment.sequence.desc(),
        )
        .limit(1)
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    _require(latest is not None, "health assessment unresolved")
    assert latest is not None
    result = _assessment(latest.document)
    _require(
        result.standing == "eligible"
        and result.identity_fingerprint == row.identity_fingerprint
        and result.enrollment_ref == row.enrollment_ref
        and result.valid_from <= result.assessed_at <= now < result.valid_until,
        "health assessment stale or ineligible",
    )
    runtime, custody, start, end, checked_at = _refresh_evidence(
        db,
        row,
        sources,
        runtime_ref=result.runtime_evidence_ref,
        custody_ref=result.credential_evidence_ref,
        now=now,
    )
    _require(
        result.runtime_authority_ref == runtime.authority_ref
        and result.credential_authority_ref == custody.authority_ref
        and start <= result.valid_from
        and result.valid_until <= end,
        "assessment evidence authority or validity changed",
    )
    _checked_time(
        sources,
        sampled_at=checked_at,
        assessed_at=result.assessed_at,
        start=result.valid_from,
        end=result.valid_until,
    )
    return result


def _close_enrollment(db: Session, command: CloseEnrollmentCommand) -> datetime | None:
    """Append a permanent closure and remove only its current pointer; flush only."""
    _require(
        type(command) is CloseEnrollmentCommand, "typed reference command required"
    )
    _text(command.closure_ref)
    row = _one(db, DeploymentEnrollment, enrollment_ref=command.enrollment_ref)
    _locked_execution(db, row.attempt_id)
    existing = db.get(DeploymentEnrollmentClosure, row.id, populate_existing=True)
    if existing is not None:
        _require(
            existing.closure_ref == command.closure_ref, "closure reference conflict"
        )
        return None
    now = _instant(_sources().clock.now())
    db.add(
        DeploymentEnrollmentClosure(
            enrollment_id=row.id,
            target_id=row.target_id,
            closed_at=now,
            closure_ref=command.closure_ref,
        )
    )
    pointer = db.get(DeploymentCurrentEnrollment, row.target_id, populate_existing=True)
    if pointer is not None and pointer.enrollment_id == row.id:
        db.delete(pointer)
    db.flush()
    return now


_HealthCommand = (
    EnrollDeploymentCommand | AssessHealthEligibilityCommand | CloseEnrollmentCommand
)


def _audit_command(
    db: Session,
    command: _HealthCommand,
    *,
    operation: str,
    enrollment_ref: str,
    reused_domain: bool,
) -> None:
    # Same platform attribution as service.py, without its coupled outbox write.
    actor_admin_id: UUID | None = None
    details: dict[str, object] = {
        "command_id": command.command_id,
        "operation": operation,
        "disposition": "reused_domain" if reused_domain else "applied",
    }
    if command.actor_ref:
        try:
            actor_admin_id = UUID(command.actor_ref)
        except ValueError:
            details["actor_ref"] = command.actor_ref
    write_platform_audit_event(
        db,
        actor_admin_id=actor_admin_id,
        action=AUDIT_ACTION_HEALTH_ENROLLMENT,
        entity_type="deployment_health_enrollment",
        entity_id=enrollment_ref,
        details=details,
    )


def _command_result(
    document: dict[str, object] | None,
    checked_at: datetime | None,
    *,
    assessed_at: datetime | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, object]:
    return {
        "document": document,
        "checked_at": None if checked_at is None else checked_at.isoformat(),
        "assessed_at": None if assessed_at is None else assessed_at.isoformat(),
        "valid_from": None if start is None else start.isoformat(),
        "valid_until": None if end is None else end.isoformat(),
    }


def _execute_health_command(
    db: Session,
    command: _HealthCommand,
    *,
    scope: str,
    operation: Callable[[Session], dict[str, object]],
) -> dict[str, object]:
    _text(command.command_id)
    if command.actor_ref is not None:
        _text(command.actor_ref)
    # The outer savepoint includes the Kernel receipt flush and final clock
    # check; late refusal cannot leave audit/receipt behind when caller commits.
    with conflict_savepoint(db):
        try:
            outcome = execute_once_platform(
                db,
                scope=scope,
                key=command.command_id,
                fingerprint=fingerprint_of(asdict(command)),
                expires_at=None,
                operation_name=scope,
                operation=operation,
            )
        except IdempotencyConflict as exc:
            raise DeploymentEnrollmentRefusedError(
                "command identity already has a different request fingerprint"
            ) from exc
        result = dict(outcome.result)
        if not outcome.replayed and result["checked_at"] is not None:
            sources = _sources()
            sampled = datetime.fromisoformat(cast(str, result["checked_at"]))
            if result["valid_until"] is None:
                _require(
                    _instant(sources.clock.now()) >= sampled, "owner clock regressed"
                )
            else:
                _checked_time(
                    sources,
                    sampled_at=sampled,
                    assessed_at=datetime.fromisoformat(
                        cast(str, result["assessed_at"])
                    ),
                    start=datetime.fromisoformat(cast(str, result["valid_from"])),
                    end=datetime.fromisoformat(cast(str, result["valid_until"])),
                )
        return result


def enroll_deployment(
    db: Session, command: EnrollDeploymentCommand
) -> EnrollmentProjection:
    """At-most-once audited command; replay retains the original projection."""
    _require(
        type(command) is EnrollDeploymentCommand, "typed reference command required"
    )
    command = replace(command)

    def operation(session: Session) -> dict[str, object]:
        projection, checked_at = _enroll_deployment(session, command)
        _audit_command(
            session,
            command,
            operation="enroll",
            enrollment_ref=projection.enrollment_ref,
            reused_domain=checked_at is None,
        )
        return _command_result(
            projection.document(),
            checked_at,
            assessed_at=checked_at,
            start=projection.eligible_from,
            end=projection.eligible_until,
        )

    result = _execute_health_command(
        db, command, scope=_SCOPE_ENROLL, operation=operation
    )
    return _projection(cast(dict[str, object], result["document"]))


def assess_health_eligibility(
    db: Session, command: AssessHealthEligibilityCommand
) -> HealthEligibilityAssessment:
    """At-most-once audited explicit assessment; retry never renews validity."""
    _require(
        type(command) is AssessHealthEligibilityCommand,
        "typed reference command required",
    )
    command = replace(command)

    def operation(session: Session) -> dict[str, object]:
        assessment, checked_at = _assess_health_eligibility(session, command)
        _audit_command(
            session,
            command,
            operation="assess",
            enrollment_ref=assessment.enrollment_ref,
            reused_domain=checked_at is None,
        )
        return _command_result(
            assessment.document(),
            checked_at,
            assessed_at=assessment.assessed_at,
            start=assessment.valid_from,
            end=assessment.valid_until,
        )

    result = _execute_health_command(
        db, command, scope=_SCOPE_ASSESS, operation=operation
    )
    return _assessment(cast(dict[str, object], result["document"]))


def close_enrollment(db: Session, command: CloseEnrollmentCommand) -> None:
    """At-most-once audited closure in the caller's transaction."""
    _require(
        type(command) is CloseEnrollmentCommand, "typed reference command required"
    )
    command = replace(command)

    def operation(session: Session) -> dict[str, object]:
        closed_at = _close_enrollment(session, command)
        _audit_command(
            session,
            command,
            operation="close",
            enrollment_ref=command.enrollment_ref,
            reused_domain=closed_at is None,
        )
        return _command_result(None, closed_at)

    _execute_health_command(db, command, scope=_SCOPE_CLOSE, operation=operation)


__all__ = [
    "AUDIT_ACTION_HEALTH_ENROLLMENT",
    "AssessHealthEligibilityCommand",
    "AuthenticatedRuntimeEvidence",
    "AuthenticatedStartupAssignment",
    "CloseEnrollmentCommand",
    "CommittedConsumptionSource",
    "DeploymentEnrollmentRefusedError",
    "DescriptorSource",
    "EnrollDeploymentCommand",
    "EnrollmentClock",
    "EnrollmentProjection",
    "HealthEligibilityAssessment",
    "InstallationSource",
    "InstallationSourceBinding",
    "PublicCommittedConsumptionReader",
    "QualifiedDescriptor",
    "RuntimeComponent",
    "RuntimeSource",
    "StartupAssignmentSource",
    "assess_health_eligibility",
    "close_enrollment",
    "current_eligibility_get",
    "enroll_deployment",
    "historical_get",
    "install_sources",
]
