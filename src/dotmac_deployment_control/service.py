"""Desired deployment intent, rollout, acknowledgement and reconciliation.

Two source modes, recorded honestly (ADR-0033 § 3):

- The **receipt half** ports the Vendor V6 admission design — the attempt/receipt
  pair, the claim/proof separation, the stable-verdict rule — from branches that
  were never merged and never deployed. A tested reference, not production code.
- The **plan/rollout half** is greenfield, with the absence of any source
  evidenced across every branch, stash, dangling object and reflog of the Vendor
  repository plus seven other repositories.

## The three rules this module exists to hold

**1. What is dispatched is a PLAN, and a plan is frozen.** A rollout names a plan
by id; the intent handed to the Integrator carries the plan's digest. Nothing
reads the target's *current* desired state at dispatch time — otherwise editing
the desired state mid-rollout would silently change what is being deployed, and
the approval would be for something else.

**2. A claim is never a proof.** An observation's authoritative identity is the
one the caller resolved from the SIGNED key (ADR-0007 § 4). What the report says
about itself is stored beside it as evidence and is never promoted.

**3. Every arrival is recorded, including the ones that fail.** An unknown key, a
malformed envelope or a bad signature against a known key is exactly the evidence
an operator needs. A fail-closed system that discards them silently is the worst
of both — closed AND blind.

## What this module never does

- **Talk to a provider.** No SSH, Kubernetes, cloud or panel client; no webhook
  verification; no endpoint, credential reference, transport name or retry
  policy. It emits a provider-neutral `DeliveryIntent` and the Integrator owns
  everything after that (ADR-0024, hard rule 28).
- **Verify a signature.** `dotmac_kernel.licensing.verify_applied_state` owns
  that (ADR-0007); the caller runs it and passes the result in. Re-implementing
  it here would be a second verifier that could disagree with the first.
- **Decide what a deployment may run.** That is `dotmac-licensing`. This module
  records a `licence_ref` and never inspects it.
- **Interpret a deployment spec.** `spec` is opaque. Interpreting it would make
  this module a second authority on what a deployment IS, which belongs to the
  product's deployment profile (ADR-0003).

## Transaction authority (hard rule 8)

Receives a `Session`; only `add` and `flush`. Never commits, never rolls back,
never constructs a session.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from dotmac_kernel.audit import write_platform_audit_event
from dotmac_kernel.messaging import enqueue_platform_event, process_once_platform
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dotmac_deployment_control import facts
from dotmac_deployment_control.models import (
    TERMINAL_ROLLOUT_STATUSES,
    AttemptOutcome,
    CredentialStatus,
    DeploymentPlan,
    DeploymentTarget,
    EligibilityAtReceipt,
    ObservationAttempt,
    ObservationDisposition,
    ObservationReceipt,
    PlanStatus,
    Rollout,
    RolloutAttempt,
    RolloutStatus,
    SignatureStatus,
    TargetCredential,
    TargetStatus,
)
from dotmac_deployment_control.ports import (
    ApprovalEvidence,
    ApprovalRefusedError,
    DeliveryIntent,
    DesiredDeployment,
    ExpectedStateError,
    ObservationRefusedError,
    ObservedState,
    PlanRefusedError,
    TransitionRefusedError,
)

#: The audit actions this module declares and writes. Four, split by SUBJECT
#: rather than by verb: a target's own standing, a credential's standing, a plan
#: or rollout decision, and an inbound observation. An operator reading an audit
#: trail is asking "what changed — the fleet's intent, a deployment's identity,
#: or what a deployment told us?", and those are genuinely different questions.
AUDIT_ACTION_TARGET: str = "deployment.target.changed"
AUDIT_ACTION_CREDENTIAL: str = "deployment.credential.changed"
AUDIT_ACTION_ROLLOUT: str = "deployment.rollout.changed"
AUDIT_ACTION_OBSERVATION: str = "deployment.observation.recorded"

#: Idempotency scopes name the OPERATION, never an HTTP route (ADR-0014).
SCOPE_REGISTER_TARGET = "deployment.register_target"
SCOPE_SET_DESIRED = "deployment.set_desired_state"
SCOPE_SUSPEND_TARGET = "deployment.suspend_target"
SCOPE_DECOMMISSION_TARGET = "deployment.decommission_target"
SCOPE_ENROL_CREDENTIAL = "deployment.enrol_credential"
SCOPE_ACTIVATE_CREDENTIAL = "deployment.activate_credential"
SCOPE_REVOKE_CREDENTIAL = "deployment.revoke_credential"
SCOPE_PROPOSE_PLAN = "deployment.propose_plan"
SCOPE_APPROVE_PLAN = "deployment.approve_plan"
SCOPE_CANCEL_PLAN = "deployment.cancel_plan"
SCOPE_REQUEST_ROLLOUT = "deployment.request_rollout"
SCOPE_DISPATCH = "deployment.dispatch_attempt"
SCOPE_SETTLE = "deployment.settle_attempt"
SCOPE_CANCEL_ROLLOUT = "deployment.cancel_rollout"
SCOPE_OBSERVE = "deployment.record_observation"

_ENTITY_TARGET = "deployment_target"
_ENTITY_CREDENTIAL = "target_credential"
_ENTITY_PLAN = "deployment_plan"
_ENTITY_ROLLOUT = "rollout"
_ENTITY_OBSERVATION = "deployment_observation"


# ── Commands ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RegisterTargetCommand:
    command_id: str
    target_ref: str
    subject_ref: str
    product_code: str
    environment: str
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class SetDesiredStateCommand:
    """Declare what a target should converge on. Bumps `desired_revision`."""

    command_id: str
    target_id: UUID
    desired: DesiredDeployment
    expected_version: int | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class TargetTransitionCommand:
    command_id: str
    target_id: UUID
    reason: str | None = None
    expected_status: str | None = None
    expected_version: int | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class EnrolCredentialCommand:
    """Register a target's own PUBLIC verification key.

    `public_key_fingerprint` is supplied by the caller because computing it means
    decoding base64, and the caller has already done that to validate the key.
    The module checks that it is present and unique; it never holds private
    material and never generates a key.
    """

    command_id: str
    target_id: UUID
    key_id: str
    public_key_b64: str
    public_key_fingerprint: str
    enrollment_authority: str
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class CredentialTransitionCommand:
    command_id: str
    credential_id: UUID
    reason: str | None = None
    at: datetime | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ProposePlanCommand:
    """Freeze the target's CURRENT desired state into an immutable plan."""

    command_id: str
    target_id: UUID
    requires_approval: bool = True
    approval_policy_code: str | None = None
    approval_policy_version: int | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovePlanCommand:
    command_id: str
    plan_id: UUID
    evidence: ApprovalEvidence
    expected_version: int | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class RequestRolloutCommand:
    """Decide to converge a target on an APPROVED (or approval-exempt) plan."""

    command_id: str
    rollout_ref: str
    plan_id: UUID
    reason: str | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class SettleAttemptCommand:
    """Record what an attempt turned into.

    `outcome` drives the rollout's own status: a succeeded attempt succeeds the
    rollout, a failed or timed-out one leaves the rollout open for a retry until
    an operator moves it to manual repair. The rollout is deliberately NOT failed
    by one attempt — that would make a transient transport error look like a
    deployment decision.
    """

    command_id: str
    rollout_id: UUID
    attempt_no: int
    outcome: str
    integrator_ref: str | None = None
    error_code: str | None = None
    detail: str | None = None
    settled_at: datetime | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class RolloutTransitionCommand:
    command_id: str
    rollout_id: UUID
    reason: str | None = None
    expected_status: str | None = None
    expected_version: int | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class RecordObservationCommand:
    """Admit (or refuse, and record) one inbound observation."""

    command_id: str
    observed: ObservedState
    received_at: datetime
    actor_ref: str | None = None


# ── Digests ─────────────────────────────────────────────────────────────────


def plan_snapshot(target: DeploymentTarget) -> dict[str, Any]:
    """The canonical frozen snapshot of a target's desired state.

    Deterministic by construction: `json.dumps(sort_keys=True)` at digest time,
    and every value here is either a scalar or the caller's own spec mapping. A
    digest over a dict whose iteration order is insertion order would change when
    the same plan was rebuilt in a different order, silently invalidating an
    approval nobody changed.
    """
    return {
        "target_ref": target.target_ref,
        "product_code": target.product_code,
        "environment": target.environment,
        "release_ref": target.desired_release_ref,
        "licence_ref": target.licence_ref,
        "brand_profile_ref": target.brand_profile_ref,
        "desired_revision": target.desired_revision,
        "spec": dict(target.desired_spec or {}),
    }


def snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON encoding of a plan snapshot."""
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def spec_digest(spec: Mapping[str, Any]) -> str:
    """SHA-256 over a deployment spec alone.

    Separate from `snapshot_digest` because a target reports what it is RUNNING,
    not which plan produced it — it has no way to know the plan's identity. So
    the comparable value on both sides is the spec's own digest.
    """
    canonical = json.dumps(dict(spec), sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


# ── Internals ───────────────────────────────────────────────────────────────


def _load_target(session: Session, target_id: UUID) -> DeploymentTarget:
    row = session.get(DeploymentTarget, target_id)
    if row is None:
        raise TransitionRefusedError(f"deployment target {target_id} not found")
    return row


def _load_plan(session: Session, plan_id: UUID) -> DeploymentPlan:
    row = session.get(DeploymentPlan, plan_id)
    if row is None:
        raise TransitionRefusedError(f"deployment plan {plan_id} not found")
    return row


def _load_rollout(session: Session, rollout_id: UUID) -> Rollout:
    row = session.get(Rollout, rollout_id)
    if row is None:
        raise TransitionRefusedError(f"rollout {rollout_id} not found")
    return row


def _require_expected(
    subject_ref: str,
    *,
    status: str,
    version: int,
    expected_status: str | None,
    expected_version: int | None,
) -> None:
    status_ok = expected_status is None or status == expected_status
    version_ok = expected_version is None or version == expected_version
    if not (status_ok and version_ok):
        raise ExpectedStateError(
            subject_ref,
            expected_status=expected_status,
            actual_status=status,
            expected_version=expected_version,
            actual_version=version,
        )


def _audit_and_emit(
    session: Session,
    *,
    action: str,
    event_type: str,
    entity_type: str,
    entity_id: str,
    actor_ref: str | None,
    details: Mapping[str, Any],
) -> None:
    """The atomic consequence: a platform audit record AND an outbox fact.

    Both in the caller's transaction, or neither. A state change without the fact
    leaves the Integrator permanently unaware of an intent; a fact without the
    audit leaves an operator unable to say who caused it.

    `actor_ref` is a string and the kernel wants a `UUID | None`. It is parsed
    rather than cast: an actor reference that is not a platform admin id is
    recorded in the details and the audit actor is left null, which is honest
    about who the kernel's audit trail can attribute to.
    """
    actor_admin_id: UUID | None = None
    payload = dict(details)
    if actor_ref:
        try:
            actor_admin_id = UUID(actor_ref)
        except ValueError:
            payload["actor_ref"] = actor_ref
    write_platform_audit_event(
        session,
        actor_admin_id=actor_admin_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=payload,
    )
    enqueue_platform_event(
        session,
        event_type=event_type,
        payload={**payload, "id": entity_id},
        correlation_id=entity_id,
    )


def _target_view(row: DeploymentTarget) -> facts.TargetView:
    return facts.TargetView(
        id=row.id,
        target_ref=row.target_ref,
        subject_ref=row.subject_ref,
        product_code=row.product_code,
        environment=row.environment,
        status=row.status,
        record_version=row.record_version,
        desired_release_ref=row.desired_release_ref,
        desired_revision=row.desired_revision,
        licence_ref=row.licence_ref,
        brand_profile_ref=row.brand_profile_ref,
        observed_release_ref=row.observed_release_ref,
        observed_spec_digest=row.observed_spec_digest,
        observed_revision=row.observed_revision,
        last_observed_at=row.last_observed_at,
        desired_spec=dict(row.desired_spec or {}),
    )


def _plan_view(row: DeploymentPlan) -> facts.PlanView:
    return facts.PlanView(
        id=row.id,
        target_id=row.target_id,
        sequence=row.sequence,
        status=row.status,
        desired_revision=row.desired_revision,
        record_version=row.record_version,
        plan_digest=row.plan_digest,
        requires_approval=row.requires_approval,
        approval_policy_code=row.approval_policy_code,
        approval_policy_version=row.approval_policy_version,
        approval_decision_ref=row.approval_decision_ref,
        approved_at=row.approved_at,
        superseded_by_id=row.superseded_by_id,
        snapshot=dict(row.snapshot or {}),
    )


def _rollout_view(row: Rollout) -> facts.RolloutView:
    return facts.RolloutView(
        id=row.id,
        rollout_ref=row.rollout_ref,
        target_id=row.target_id,
        plan_id=row.plan_id,
        status=row.status,
        record_version=row.record_version,
        reason=row.reason,
        completed_at=row.completed_at,
        attempts=tuple(
            facts.AttemptView(
                attempt_no=attempt.attempt_no,
                outcome=attempt.outcome,
                integrator_ref=attempt.integrator_ref,
                error_code=attempt.error_code,
                detail=attempt.detail,
                dispatched_at=attempt.dispatched_at,
                settled_at=attempt.settled_at,
            )
            for attempt in row.attempts
        ),
    )


# ── Targets ─────────────────────────────────────────────────────────────────


def register_target(db: Session, command: RegisterTargetCommand) -> facts.TargetView:
    """Record a deployment this control plane is responsible for."""

    def handler(session: Session) -> Mapping[str, object]:
        existing = session.execute(
            select(DeploymentTarget).where(
                DeploymentTarget.target_ref == command.target_ref
            )
        ).scalar_one_or_none()
        if existing is not None:
            return {"id": str(existing.id)}
        row = DeploymentTarget(
            target_ref=command.target_ref,
            subject_ref=command.subject_ref,
            product_code=command.product_code,
            environment=command.environment,
            status=TargetStatus.REGISTERED.value,
            desired_revision=0,
            record_version=1,
        )
        session.add(row)
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_TARGET,
            event_type=facts.TARGET_REGISTERED_V1,
            entity_type=_ENTITY_TARGET,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "target_ref": row.target_ref,
                "subject_ref": row.subject_ref,
                "product_code": row.product_code,
                "environment": row.environment,
            },
        )
        return {"id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_REGISTER_TARGET,
        handler=handler,
    )
    return _target_view(_load_target(db, UUID(str(outcome.result["id"]))))


def set_desired_state(db: Session, command: SetDesiredStateCommand) -> facts.TargetView:
    """Declare what a target should converge on, bumping `desired_revision`.

    Bumping unconditionally — even when the values happen to match — is
    deliberate. The revision records that a DECISION was taken, and an operator
    re-declaring the same state after an incident wants a plan they can approve,
    not a silent no-op that leaves the fleet exactly as it was.
    """

    def handler(session: Session) -> Mapping[str, object]:
        row = _load_target(session, command.target_id)
        _require_expected(
            row.target_ref,
            status=row.status,
            version=row.record_version,
            expected_status=None,
            expected_version=command.expected_version,
        )
        if row.status == TargetStatus.DECOMMISSIONED.value:
            raise TransitionRefusedError(
                f"target {row.target_ref} is decommissioned; a desired state for "
                "a retired deployment would be an intent nothing can converge on"
            )
        row.desired_release_ref = command.desired.release_ref
        row.desired_spec = dict(command.desired.spec)
        row.licence_ref = command.desired.licence_ref
        row.brand_profile_ref = command.desired.brand_profile_ref
        row.desired_revision += 1
        if row.status == TargetStatus.REGISTERED.value:
            row.status = TargetStatus.ACTIVE.value
        row.record_version += 1
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_TARGET,
            event_type=facts.TARGET_DESIRED_STATE_SET_V1,
            entity_type=_ENTITY_TARGET,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "target_ref": row.target_ref,
                "release_ref": row.desired_release_ref,
                "licence_ref": row.licence_ref,
                "brand_profile_ref": row.brand_profile_ref,
                "desired_revision": row.desired_revision,
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_SET_DESIRED,
        handler=handler,
    )
    return _target_view(_load_target(db, command.target_id))


def suspend_target(db: Session, command: TargetTransitionCommand) -> facts.TargetView:
    """Exclude a target from rollouts without forgetting it."""
    return _target_transition(
        db,
        command,
        scope=SCOPE_SUSPEND_TARGET,
        allowed=frozenset({TargetStatus.ACTIVE.value}),
        to=TargetStatus.SUSPENDED,
        event_type=facts.TARGET_SUSPENDED_V1,
    )


def decommission_target(
    db: Session, command: TargetTransitionCommand
) -> facts.TargetView:
    """Retire a target. Terminal, and it keeps every plan, rollout and
    observation it had — a decommissioned deployment is exactly the one whose
    history an audit asks about."""
    return _target_transition(
        db,
        command,
        scope=SCOPE_DECOMMISSION_TARGET,
        allowed=frozenset(
            {
                TargetStatus.REGISTERED.value,
                TargetStatus.ACTIVE.value,
                TargetStatus.SUSPENDED.value,
            }
        ),
        to=TargetStatus.DECOMMISSIONED,
        event_type=facts.TARGET_DECOMMISSIONED_V1,
    )


def _target_transition(
    db: Session,
    command: TargetTransitionCommand,
    *,
    scope: str,
    allowed: frozenset[str],
    to: TargetStatus,
    event_type: str,
) -> facts.TargetView:
    def handler(session: Session) -> Mapping[str, object]:
        row = _load_target(session, command.target_id)
        _require_expected(
            row.target_ref,
            status=row.status,
            version=row.record_version,
            expected_status=command.expected_status,
            expected_version=command.expected_version,
        )
        if row.status not in allowed:
            raise TransitionRefusedError(
                f"target {row.target_ref} is {row.status!r}; this transition "
                f"requires one of {sorted(allowed)}"
            )
        previous = row.status
        row.status = to.value
        row.record_version += 1
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_TARGET,
            event_type=event_type,
            entity_type=_ENTITY_TARGET,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "target_ref": row.target_ref,
                "from_status": previous,
                "to_status": row.status,
                "reason": command.reason,
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=scope, handler=handler
    )
    return _target_view(_load_target(db, command.target_id))


# ── Credentials ─────────────────────────────────────────────────────────────


def enrol_credential(db: Session, command: EnrolCredentialCommand) -> UUID:
    """Register a target's own PUBLIC verification key, as `PENDING`.

    `PENDING` rather than `ACTIVE`, and the difference is the whole point: an
    enrolled key is a claim that someone registered it, and only a proven
    possession makes it admit reports (ADR-0007). Enrolling straight to active
    would let anyone who can call the enrollment endpoint impersonate a
    deployment.
    """

    def handler(session: Session) -> Mapping[str, object]:
        target = _load_target(session, command.target_id)
        existing = session.execute(
            select(TargetCredential).where(TargetCredential.key_id == command.key_id)
        ).scalar_one_or_none()
        if existing is not None:
            return {"id": str(existing.id)}
        if not command.public_key_fingerprint:
            raise TransitionRefusedError(
                "a credential needs a fingerprint over the DECODED key bytes; "
                "base64 text is not canonical and two spellings of one key would "
                "each enrol separately"
            )
        row = TargetCredential(
            target_id=target.id,
            key_id=command.key_id,
            public_key_b64=command.public_key_b64,
            public_key_fingerprint=command.public_key_fingerprint,
            status=CredentialStatus.PENDING.value,
            enrollment_authority=command.enrollment_authority,
        )
        session.add(row)
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_CREDENTIAL,
            event_type=facts.CREDENTIAL_ENROLLED_V1,
            entity_type=_ENTITY_CREDENTIAL,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "target_ref": target.target_ref,
                "key_id": row.key_id,
                "fingerprint": row.public_key_fingerprint,
                "enrollment_authority": row.enrollment_authority,
            },
        )
        return {"id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_ENROL_CREDENTIAL,
        handler=handler,
    )
    return UUID(str(outcome.result["id"]))


def activate_credential(db: Session, command: CredentialTransitionCommand) -> None:
    """Admit a credential from `at` onwards, after possession was proven.

    The caller proves possession with `dotmac_kernel.licensing.verify_possession`
    (ADR-0007) and calls this. The proof is not re-run here — the kernel owns it,
    and a second implementation could disagree with the first.
    """

    def handler(session: Session) -> Mapping[str, object]:
        row = session.get(TargetCredential, command.credential_id)
        if row is None:
            raise TransitionRefusedError(
                f"credential {command.credential_id} not found"
            )
        if row.status != CredentialStatus.PENDING.value:
            raise TransitionRefusedError(
                f"credential {row.key_id} is {row.status!r}; only a pending "
                "credential can be activated"
            )
        row.status = CredentialStatus.ACTIVE.value
        row.activated_at = command.at or datetime.now(UTC)
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_CREDENTIAL,
            event_type=facts.CREDENTIAL_ACTIVATED_V1,
            entity_type=_ENTITY_CREDENTIAL,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={"key_id": row.key_id, "activated_at": str(row.activated_at)},
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_ACTIVATE_CREDENTIAL,
        handler=handler,
    )


def revoke_credential(db: Session, command: CredentialTransitionCommand) -> None:
    """Stop a credential admitting reports, from `at` onwards.

    Reports it admitted BEFORE `at` stay admitted. Revocation is not
    retroactive, because retroactively un-admitting a report would rewrite a
    decision that was correct when it was made — and the observation attempts
    that recorded it are append-only precisely so that history survives.
    """

    def handler(session: Session) -> Mapping[str, object]:
        row = session.get(TargetCredential, command.credential_id)
        if row is None:
            raise TransitionRefusedError(
                f"credential {command.credential_id} not found"
            )
        if row.status == CredentialStatus.REVOKED.value:
            return {"id": str(row.id)}
        row.status = CredentialStatus.REVOKED.value
        row.revoked_at = command.at or datetime.now(UTC)
        row.revocation_reason = command.reason
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_CREDENTIAL,
            event_type=facts.CREDENTIAL_REVOKED_V1,
            entity_type=_ENTITY_CREDENTIAL,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={"key_id": row.key_id, "reason": command.reason},
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_REVOKE_CREDENTIAL,
        handler=handler,
    )


def credential_is_eligible(
    db: Session, key_id: str, *, at: datetime
) -> tuple[bool, str | None]:
    """Was this credential admitted at `at`? Returns `(eligible, target_ref)`.

    The timeline predicate, evaluated against the stored window rather than the
    current status, so a report that arrived while a credential was live stays
    evaluable after it is rotated out. Eligibility is `[activated_at, retired_at)`
    and `[activated_at, revoked_at)` — half-open, so the instant of revocation is
    already outside.
    """
    row = db.execute(
        select(TargetCredential).where(TargetCredential.key_id == key_id)
    ).scalar_one_or_none()
    if row is None or row.activated_at is None:
        return False, None
    target = db.get(DeploymentTarget, row.target_id)
    target_ref = target.target_ref if target is not None else None
    activated = _as_utc(row.activated_at)
    if at < activated:
        return False, target_ref
    for closed_at in (row.retired_at, row.revoked_at):
        if closed_at is not None and at >= _as_utc(closed_at):
            return False, target_ref
    return True, target_ref


def _as_utc(value: datetime) -> datetime:
    """Normalise a stored timestamp to aware UTC.

    The columns are `timezone=True`, but a dialect without a tz-aware type
    returns them naive and comparing across the two raises. Stored instants are
    UTC by construction.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


# ── Plans ───────────────────────────────────────────────────────────────────


def propose_plan(db: Session, command: ProposePlanCommand) -> facts.PlanView:
    """Freeze the target's CURRENT desired state into an immutable plan.

    Freezing at proposal — rather than reading the desired state at dispatch —
    is what makes an approval mean something. Between approval and rollout the
    desired state may change many times; the plan does not.
    """

    def handler(session: Session) -> Mapping[str, object]:
        target = _load_target(session, command.target_id)
        if target.status != TargetStatus.ACTIVE.value:
            raise PlanRefusedError(
                f"target {target.target_ref} is {target.status!r}; only an active "
                "target can be planned for"
            )
        if not target.desired_release_ref:
            raise PlanRefusedError(
                f"target {target.target_ref} has no desired release; a plan with "
                "nothing to converge on is not a plan"
            )
        if command.requires_approval and not command.approval_policy_code:
            raise PlanRefusedError(
                "a plan that requires approval must name the policy it will be "
                "approved under, so the decision stays explainable after the "
                "policy changes"
            )

        highest = session.execute(
            select(func.max(DeploymentPlan.sequence)).where(
                DeploymentPlan.target_id == target.id
            )
        ).scalar()
        sequence = int(highest or 0) + 1

        snapshot = plan_snapshot(target)
        row = DeploymentPlan(
            target_id=target.id,
            sequence=sequence,
            status=PlanStatus.PROPOSED.value,
            snapshot=snapshot,
            desired_revision=target.desired_revision,
            plan_digest=snapshot_digest(snapshot),
            requires_approval=command.requires_approval,
            approval_policy_code=command.approval_policy_code,
            approval_policy_version=command.approval_policy_version,
            record_version=1,
        )
        session.add(row)
        session.flush()

        # Supersede any earlier plan still awaiting a decision. Leaving two
        # proposed plans for one target would let an operator approve the older
        # one and roll out state that has since been replaced.
        stale = (
            session.execute(
                select(DeploymentPlan).where(
                    DeploymentPlan.target_id == target.id,
                    DeploymentPlan.id != row.id,
                    DeploymentPlan.status.in_(
                        (PlanStatus.DRAFT.value, PlanStatus.PROPOSED.value)
                    ),
                )
            )
            .scalars()
            .all()
        )
        for plan in stale:
            plan.status = PlanStatus.SUPERSEDED.value
            plan.superseded_by_id = row.id
            plan.record_version += 1
        session.flush()

        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=facts.PLAN_PROPOSED_V1,
            entity_type=_ENTITY_PLAN,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "target_ref": target.target_ref,
                "sequence": row.sequence,
                "plan_digest": row.plan_digest,
                "desired_revision": row.desired_revision,
                "requires_approval": row.requires_approval,
                "superseded": [str(plan.id) for plan in stale],
            },
        )
        return {"id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_PROPOSE_PLAN,
        handler=handler,
    )
    return _plan_view(_load_plan(db, UUID(str(outcome.result["id"]))))


def approve_plan(db: Session, command: ApprovePlanCommand) -> facts.PlanView:
    """`proposed → approved`, on evidence bound to the plan digest.

    ADR-0026 § 2's binding, applied where the blast radius is other people's
    running systems: change the plan and the digest changes, so a prior approval
    is **stale rather than transferable**.
    """

    def handler(session: Session) -> Mapping[str, object]:
        row = _load_plan(session, command.plan_id)
        _require_expected(
            f"plan {row.id}",
            status=row.status,
            version=row.record_version,
            expected_status=PlanStatus.PROPOSED.value,
            expected_version=command.expected_version,
        )
        if not row.requires_approval:
            raise ApprovalRefusedError(
                f"plan {row.id} does not require approval; approving it would "
                "record a decision nothing asked for"
            )
        if not row.plan_digest:
            raise ApprovalRefusedError(
                f"plan {row.id} has no frozen digest; propose it before supplying "
                "approval evidence"
            )
        if command.evidence.content_digest != row.plan_digest:
            raise ApprovalRefusedError(
                f"approval evidence binds to digest "
                f"{command.evidence.content_digest!r} but plan {row.id} froze "
                f"{row.plan_digest!r}; the plan changed after approval, so a new "
                "approval is required"
            )
        if command.evidence.policy_code != (row.approval_policy_code or ""):
            raise ApprovalRefusedError(
                f"approval evidence names policy {command.evidence.policy_code!r} "
                f"but plan {row.id} was proposed under {row.approval_policy_code!r}"
            )
        if command.evidence.policy_version != row.approval_policy_version:
            raise ApprovalRefusedError(
                f"approval evidence names policy version "
                f"{command.evidence.policy_version} but plan {row.id} was proposed "
                f"under {row.approval_policy_version}"
            )
        row.approval_decision_ref = command.evidence.decision_ref
        row.approved_at = command.evidence.decided_at
        row.status = PlanStatus.APPROVED.value
        row.record_version += 1
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=facts.PLAN_APPROVED_V1,
            entity_type=_ENTITY_PLAN,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "plan_digest": row.plan_digest,
                "policy_code": command.evidence.policy_code,
                "policy_version": command.evidence.policy_version,
                "decision_ref": command.evidence.decision_ref,
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_APPROVE_PLAN,
        handler=handler,
    )
    return _plan_view(_load_plan(db, command.plan_id))


def cancel_plan(
    db: Session,
    *,
    command_id: str,
    plan_id: UUID,
    reason: str | None = None,
    actor_ref: str | None = None,
) -> facts.PlanView:
    """`draft | proposed | approved → cancelled`, before any rollout exists."""

    def handler(session: Session) -> Mapping[str, object]:
        row = _load_plan(session, plan_id)
        if row.status in {PlanStatus.SUPERSEDED.value, PlanStatus.CANCELLED.value}:
            raise TransitionRefusedError(
                f"plan {row.id} is {row.status!r} and cannot be cancelled"
            )
        used = session.execute(
            select(Rollout.id).where(Rollout.plan_id == row.id).limit(1)
        ).scalar_one_or_none()
        if used is not None:
            raise TransitionRefusedError(
                f"plan {row.id} already has a rollout; cancel the rollout, not the "
                "plan it was approved as — a cancelled plan with a live rollout "
                "would leave the rollout referencing a decision nobody stands by"
            )
        row.status = PlanStatus.CANCELLED.value
        row.record_version += 1
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=facts.PLAN_CANCELLED_V1,
            entity_type=_ENTITY_PLAN,
            entity_id=str(row.id),
            actor_ref=actor_ref,
            details={"reason": reason},
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command_id, command_type=SCOPE_CANCEL_PLAN, handler=handler
    )
    return _plan_view(_load_plan(db, plan_id))


# ── Rollouts ────────────────────────────────────────────────────────────────


def request_rollout(db: Session, command: RequestRolloutCommand) -> facts.RolloutView:
    """Decide to converge a target on a plan. No transport happens here."""

    def handler(session: Session) -> Mapping[str, object]:
        existing = session.execute(
            select(Rollout).where(Rollout.rollout_ref == command.rollout_ref)
        ).scalar_one_or_none()
        if existing is not None:
            return {"id": str(existing.id)}
        plan = _load_plan(session, command.plan_id)
        if plan.requires_approval and plan.status != PlanStatus.APPROVED.value:
            raise ApprovalRefusedError(
                f"plan {plan.id} is {plan.status!r} and requires approval; a "
                "rollout of an unapproved sensitive plan is the one thing the "
                "approval gate exists to prevent"
            )
        if not plan.requires_approval and plan.status not in {
            PlanStatus.PROPOSED.value,
            PlanStatus.APPROVED.value,
        }:
            raise TransitionRefusedError(
                f"plan {plan.id} is {plan.status!r} and cannot be rolled out"
            )
        target = _load_target(session, plan.target_id)
        if target.status != TargetStatus.ACTIVE.value:
            raise TransitionRefusedError(
                f"target {target.target_ref} is {target.status!r}; a suspended or "
                "decommissioned target is deliberately excluded from rollouts"
            )
        row = Rollout(
            rollout_ref=command.rollout_ref,
            target_id=target.id,
            plan_id=plan.id,
            status=RolloutStatus.REQUESTED.value,
            reason=command.reason,
            record_version=1,
        )
        session.add(row)
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=facts.ROLLOUT_REQUESTED_V1,
            entity_type=_ENTITY_ROLLOUT,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "rollout_ref": row.rollout_ref,
                "target_ref": target.target_ref,
                "plan_id": str(plan.id),
                "plan_digest": plan.plan_digest,
            },
        )
        return {"id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_REQUEST_ROLLOUT,
        handler=handler,
    )
    return _rollout_view(_load_rollout(db, UUID(str(outcome.result["id"]))))


def dispatch_attempt(
    db: Session,
    *,
    command_id: str,
    rollout_id: UUID,
    at: datetime | None = None,
    actor_ref: str | None = None,
) -> DeliveryIntent:
    """Open the next attempt and return the provider-neutral delivery intent.

    Returns the intent rather than sending it. Sending is the Integrator's, and a
    module that both decided and delivered would be the second transport
    authority ADR-0024 exists to prevent.

    Retry and redrive are the same operation: calling this again on an open
    rollout opens attempt N+1. There is no separate `retry()` with different
    rules, because a retry that took a different path from the first attempt is
    a retry that has not been tested.
    """

    def handler(session: Session) -> Mapping[str, object]:
        rollout = _load_rollout(session, rollout_id)
        if rollout.status in TERMINAL_ROLLOUT_STATUSES:
            raise TransitionRefusedError(
                f"rollout {rollout.rollout_ref} is {rollout.status!r}; a settled "
                "rollout is not retried, a new one is requested"
            )
        pending = session.execute(
            select(RolloutAttempt).where(
                RolloutAttempt.rollout_id == rollout.id,
                RolloutAttempt.outcome == AttemptOutcome.PENDING.value,
            )
        ).scalar_one_or_none()
        if pending is not None:
            raise TransitionRefusedError(
                f"rollout {rollout.rollout_ref} already has attempt "
                f"{pending.attempt_no} in flight; settle it before dispatching "
                "another, or two deliveries race to converge one target"
            )
        highest = session.execute(
            select(func.max(RolloutAttempt.attempt_no)).where(
                RolloutAttempt.rollout_id == rollout.id
            )
        ).scalar()
        attempt_no = int(highest or 0) + 1
        attempt = RolloutAttempt(
            rollout_id=rollout.id,
            attempt_no=attempt_no,
            outcome=AttemptOutcome.PENDING.value,
            dispatched_at=at or datetime.now(UTC),
        )
        session.add(attempt)
        if rollout.status == RolloutStatus.REQUESTED.value:
            rollout.status = RolloutStatus.DISPATCHED.value
            rollout.record_version += 1
        session.flush()

        plan = _load_plan(session, rollout.plan_id)
        target = _load_target(session, rollout.target_id)
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=facts.INTENT_DISPATCHED_V1,
            entity_type=_ENTITY_ROLLOUT,
            entity_id=str(rollout.id),
            actor_ref=actor_ref,
            details={
                "rollout_ref": rollout.rollout_ref,
                "target_ref": target.target_ref,
                "attempt_no": attempt_no,
                "plan_digest": plan.plan_digest,
                "release_ref": (plan.snapshot or {}).get("release_ref"),
            },
        )
        return {"attempt_no": attempt_no}

    outcome = process_once_platform(
        db, command_id=command_id, command_type=SCOPE_DISPATCH, handler=handler
    )
    rollout = _load_rollout(db, rollout_id)
    plan = _load_plan(db, rollout.plan_id)
    target = _load_target(db, rollout.target_id)
    snapshot = plan.snapshot or {}
    return DeliveryIntent(
        rollout_ref=rollout.rollout_ref,
        target_ref=target.target_ref,
        release_ref=str(snapshot.get("release_ref") or ""),
        plan_digest=plan.plan_digest or "",
        attempt_no=int(str(outcome.result["attempt_no"])),
        spec=dict(snapshot.get("spec") or {}),
        licence_ref=snapshot.get("licence_ref"),
        brand_profile_ref=snapshot.get("brand_profile_ref"),
    )


def settle_attempt(db: Session, command: SettleAttemptCommand) -> facts.RolloutView:
    """Record what an attempt turned into, and move the rollout if it settled it.

    A SUCCEEDED attempt succeeds the rollout. A FAILED or TIMED_OUT one leaves
    the rollout open, deliberately: one failed attempt is not a failed rollout,
    and treating it as one turns every transient transport error into a
    deployment decision an operator has to undo.
    """

    def handler(session: Session) -> Mapping[str, object]:
        rollout = _load_rollout(session, command.rollout_id)
        attempt = session.execute(
            select(RolloutAttempt).where(
                RolloutAttempt.rollout_id == rollout.id,
                RolloutAttempt.attempt_no == command.attempt_no,
            )
        ).scalar_one_or_none()
        if attempt is None:
            raise TransitionRefusedError(
                f"rollout {rollout.rollout_ref} has no attempt " f"{command.attempt_no}"
            )
        if attempt.outcome != AttemptOutcome.PENDING.value:
            raise TransitionRefusedError(
                f"attempt {command.attempt_no} of rollout {rollout.rollout_ref} "
                f"already settled as {attempt.outcome!r}; an attempt records what "
                "happened once"
            )
        if command.outcome not in {
            AttemptOutcome.SUCCEEDED.value,
            AttemptOutcome.FAILED.value,
            AttemptOutcome.TIMED_OUT.value,
            AttemptOutcome.CANCELLED.value,
        }:
            raise TransitionRefusedError(
                f"{command.outcome!r} is not a settled attempt outcome"
            )
        attempt.outcome = command.outcome
        attempt.integrator_ref = command.integrator_ref
        attempt.error_code = command.error_code
        attempt.detail = command.detail
        attempt.settled_at = command.settled_at or datetime.now(UTC)

        event_type = facts.ROLLOUT_FAILED_V1
        if command.outcome == AttemptOutcome.SUCCEEDED.value:
            rollout.status = RolloutStatus.SUCCEEDED.value
            rollout.completed_at = attempt.settled_at
            rollout.record_version += 1
            event_type = facts.ROLLOUT_SUCCEEDED_V1
        elif command.outcome == AttemptOutcome.TIMED_OUT.value:
            rollout.status = RolloutStatus.TIMED_OUT.value
            rollout.record_version += 1
            event_type = facts.ROLLOUT_TIMED_OUT_V1
        elif command.outcome == AttemptOutcome.FAILED.value:
            rollout.status = RolloutStatus.FAILED.value
            rollout.record_version += 1
        session.flush()

        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=event_type,
            entity_type=_ENTITY_ROLLOUT,
            entity_id=str(rollout.id),
            actor_ref=command.actor_ref,
            details={
                "rollout_ref": rollout.rollout_ref,
                "attempt_no": command.attempt_no,
                "outcome": command.outcome,
                "error_code": command.error_code,
                "status": rollout.status,
                "integrator_ref": command.integrator_ref,
            },
        )
        return {"id": str(rollout.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_SETTLE,
        handler=handler,
    )
    return _rollout_view(_load_rollout(db, command.rollout_id))


def cancel_rollout(db: Session, command: RolloutTransitionCommand) -> facts.RolloutView:
    """Withdraw a rollout before it completes."""
    return _rollout_transition(
        db,
        command,
        scope=SCOPE_CANCEL_ROLLOUT,
        to=RolloutStatus.CANCELLED,
        event_type=facts.ROLLOUT_CANCELLED_V1,
        settle=True,
    )


def require_manual_repair(
    db: Session, command: RolloutTransitionCommand
) -> facts.RolloutView:
    """Stop automated convergence and hand the rollout to a human.

    Distinct from `cancel`: a cancelled rollout is not wanted, a repairing one is
    wanted and stuck. An operator's queue must be able to tell them apart, and a
    model with only `cancelled` forces the operator to choose between abandoning
    the intent and leaving a rollout that looks healthy retrying forever.
    """
    return _rollout_transition(
        db,
        command,
        scope="deployment.require_manual_repair",
        to=RolloutStatus.MANUAL_REPAIR,
        event_type=facts.ROLLOUT_MANUAL_REPAIR_V1,
        settle=False,
    )


def _rollout_transition(
    db: Session,
    command: RolloutTransitionCommand,
    *,
    scope: str,
    to: RolloutStatus,
    event_type: str,
    settle: bool,
) -> facts.RolloutView:
    def handler(session: Session) -> Mapping[str, object]:
        row = _load_rollout(session, command.rollout_id)
        _require_expected(
            row.rollout_ref,
            status=row.status,
            version=row.record_version,
            expected_status=command.expected_status,
            expected_version=command.expected_version,
        )
        if row.status in TERMINAL_ROLLOUT_STATUSES:
            raise TransitionRefusedError(
                f"rollout {row.rollout_ref} is {row.status!r} and is settled"
            )
        previous = row.status
        row.status = to.value
        row.reason = command.reason
        if settle:
            row.completed_at = datetime.now(UTC)
        row.record_version += 1
        # Any in-flight attempt goes with the decision: leaving one PENDING would
        # block the next dispatch forever on a rollout nobody is waiting for.
        for attempt in row.attempts:
            if attempt.outcome == AttemptOutcome.PENDING.value and settle:
                attempt.outcome = AttemptOutcome.CANCELLED.value
                attempt.settled_at = row.completed_at
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=event_type,
            entity_type=_ENTITY_ROLLOUT,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "rollout_ref": row.rollout_ref,
                "from_status": previous,
                "to_status": row.status,
                "reason": command.reason,
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db, command_id=command.command_id, command_type=scope, handler=handler
    )
    return _rollout_view(_load_rollout(db, command.rollout_id))


# ── Observations ────────────────────────────────────────────────────────────


def record_observation(
    db: Session, command: RecordObservationCommand
) -> facts.ObservationVerdict:
    """Record one arrival, whatever happens to it, and update state if admitted.

    **Every path writes an attempt row.** Unknown key, bad signature, ineligible
    credential, contradicted claim, unknown target, replay, conflict — all of
    them. A fail-closed system that discards the failures silently is closed AND
    blind, and the failures are exactly what an operator needs when a deployment
    stops reporting.

    **Only `valid` + `eligible` + a matching target can change anything.** A
    valid-but-ineligible arrival is recorded, attributable, and activates
    nothing.

    **A replay returns the ORIGINAL verdict verbatim.** Recomputing could yield a
    different answer against changed target state for bytes the deployment sent
    once, which would make an at-least-once transport look like a state change.
    """
    observed = command.observed
    if command.received_at.tzinfo is None:
        raise ObservationRefusedError(
            "received_at must be timezone-aware; an eligibility decision against "
            "a naive instant is not reproducible"
        )

    def handler(session: Session) -> Mapping[str, object]:
        attempt = ObservationAttempt(
            received_at=command.received_at,
            raw_body=observed.raw_body,
            raw_body_truncated=observed.raw_body_truncated,
            raw_body_digest=observed.raw_body_digest,
            signature_status=observed.signature_status,
            eligibility_at_receipt=EligibilityAtReceipt.NOT_APPLICABLE.value,
            key_id=observed.key_id,
            claimed_target_ref=observed.claimed_target_ref,
            report_id=observed.report_id,
            disposition=ObservationDisposition.MALFORMED.value,
        )

        # ── Nothing authenticated: record and stop. ─────────────────────────
        if observed.signature_status != SignatureStatus.VALID.value:
            attempt.disposition = (
                ObservationDisposition.UNKNOWN_KEY.value
                if observed.signature_status == SignatureStatus.UNRESOLVED.value
                else ObservationDisposition.BAD_SIGNATURE.value
            )
            session.add(attempt)
            session.flush()
            return _observation_result(session, attempt, command, changed=False)

        # A valid signature MUST have produced an identity. A caller that passes
        # `valid` without one has defeated the claim/proof split, and the CHECK
        # constraint would refuse the row anyway — this raises the clearer error.
        if not observed.authenticated_target_ref:
            raise ObservationRefusedError(
                "a valid signature must resolve to an authenticated target; "
                "passing the report's own claim here would make deployment "
                "binding decorative"
            )
        attempt.authenticated_target_ref = observed.authenticated_target_ref

        eligible, credential_target = credential_is_eligible(
            session, observed.key_id or "", at=command.received_at
        )
        attempt.eligibility_at_receipt = (
            EligibilityAtReceipt.ELIGIBLE.value
            if eligible
            else EligibilityAtReceipt.NOT_ELIGIBLE.value
        )
        if not eligible:
            attempt.disposition = ObservationDisposition.NOT_ELIGIBLE.value
            session.add(attempt)
            session.flush()
            return _observation_result(session, attempt, command, changed=False)

        # ── The claim, compared against the proof. ──────────────────────────
        if (
            observed.claimed_target_ref
            and observed.claimed_target_ref != observed.authenticated_target_ref
        ):
            attempt.disposition = ObservationDisposition.TARGET_MISMATCH.value
            session.add(attempt)
            session.flush()
            return _observation_result(session, attempt, command, changed=False)

        target = session.execute(
            select(DeploymentTarget).where(
                DeploymentTarget.target_ref == observed.authenticated_target_ref
            )
        ).scalar_one_or_none()
        if target is None or target.target_ref != credential_target:
            attempt.disposition = ObservationDisposition.UNKNOWN_TARGET.value
            session.add(attempt)
            session.flush()
            return _observation_result(session, attempt, command, changed=False)

        # ── Idempotency, against the canonical receipt. ─────────────────────
        receipt = session.execute(
            select(ObservationReceipt).where(
                ObservationReceipt.authenticated_target_ref
                == observed.authenticated_target_ref,
                ObservationReceipt.report_id == observed.report_id,
            )
        ).scalar_one_or_none()
        if receipt is not None:
            same_bytes = receipt.payload_digest == observed.raw_body_digest
            attempt.disposition = (
                ObservationDisposition.IDEMPOTENT_REPLAY.value
                if same_bytes
                else ObservationDisposition.CONFLICT.value
            )
            attempt.receipt_id = receipt.id
            session.add(attempt)
            session.flush()
            return _observation_result(
                session,
                attempt,
                command,
                changed=False,
                verdict=receipt.original_verdict,
            )

        receipt = ObservationReceipt(
            authenticated_target_ref=observed.authenticated_target_ref,
            report_id=observed.report_id,
            payload=observed.raw_body,
            payload_digest=observed.raw_body_digest,
            key_id=observed.key_id or "",
            first_received_at=command.received_at,
            original_verdict=ObservationDisposition.ACCEPTED.value,
            observed_release_ref=observed.observed_release_ref,
            observed_spec_digest=observed.observed_spec_digest,
        )
        session.add(receipt)
        session.flush()

        attempt.disposition = ObservationDisposition.ACCEPTED.value
        attempt.receipt_id = receipt.id
        session.add(attempt)

        target.observed_release_ref = observed.observed_release_ref
        target.observed_spec_digest = observed.observed_spec_digest
        target.last_observed_at = observed.reported_at
        target.observed_revision = _revision_for_observation(session, target, observed)
        target.record_version += 1
        session.flush()

        return _observation_result(
            session,
            attempt,
            command,
            changed=True,
            verdict=ObservationDisposition.ACCEPTED.value,
            target=target,
        )

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_OBSERVE,
        handler=handler,
    )
    result = outcome.result
    return facts.ObservationVerdict(
        disposition=str(result["disposition"]),
        changed_state=bool(result["changed_state"]),
        attempt_id=UUID(str(result["attempt_id"])),
        receipt_id=(
            UUID(str(result["receipt_id"])) if result.get("receipt_id") else None
        ),
        verdict=(str(result["verdict"]) if result.get("verdict") else None),
    )


def _revision_for_observation(
    session: Session, target: DeploymentTarget, observed: ObservedState
) -> int | None:
    """Which desired revision does the observed state correspond to?

    Resolved by matching the observed spec digest against the digests of this
    target's plans, newest first. Deliberately NOT "the current desired
    revision": a target reports what it is RUNNING, and assuming that equals what
    was most recently asked for is precisely the assumption that makes drift
    undetectable.

    Returns `None` when the observed state matches no plan this control plane
    produced — which is itself a finding, and a truthful one.
    """
    if not observed.observed_spec_digest:
        return None
    plans = (
        session.execute(
            select(DeploymentPlan)
            .where(DeploymentPlan.target_id == target.id)
            .order_by(DeploymentPlan.sequence.desc())
        )
        .scalars()
        .all()
    )
    for plan in plans:
        snapshot = plan.snapshot or {}
        if spec_digest(snapshot.get("spec") or {}) == observed.observed_spec_digest:
            return plan.desired_revision
    return None


def _observation_result(
    session: Session,
    attempt: ObservationAttempt,
    command: RecordObservationCommand,
    *,
    changed: bool,
    verdict: str | None = None,
    target: DeploymentTarget | None = None,
) -> Mapping[str, object]:
    """Audit, emit, and shape the handler's return value.

    One helper for every path so that no disposition can be reached without an
    audit record — a `return` added later inside a branch would otherwise be a
    silently unaudited outcome.
    """
    details: dict[str, Any] = {
        "report_id": command.observed.report_id,
        "disposition": attempt.disposition,
        "signature_status": attempt.signature_status,
        "eligibility": attempt.eligibility_at_receipt,
        "authenticated_target_ref": attempt.authenticated_target_ref,
        "claimed_target_ref": attempt.claimed_target_ref,
        "key_id": attempt.key_id,
        "changed_state": changed,
    }
    _audit_and_emit(
        session,
        action=AUDIT_ACTION_OBSERVATION,
        event_type=facts.OBSERVATION_RECORDED_V1,
        entity_type=_ENTITY_OBSERVATION,
        entity_id=str(attempt.id),
        actor_ref=command.actor_ref,
        details=details,
    )
    if changed and target is not None:
        report = drift(session, target.id)
        if report is not None and report.drifted:
            _audit_and_emit(
                session,
                action=AUDIT_ACTION_OBSERVATION,
                event_type=facts.DRIFT_DETECTED_V1,
                entity_type=_ENTITY_TARGET,
                entity_id=str(target.id),
                actor_ref=command.actor_ref,
                details={
                    "target_ref": report.target_ref,
                    "rolled_out_release_ref": report.rolled_out_release_ref,
                    "rolled_out_revision": report.rolled_out_revision,
                    "observed_release_ref": report.observed_release_ref,
                    "observed_revision": report.observed_revision,
                },
            )
    return {
        "disposition": attempt.disposition,
        "changed_state": changed,
        "attempt_id": str(attempt.id),
        "receipt_id": str(attempt.receipt_id) if attempt.receipt_id else None,
        "verdict": verdict,
    }


# ── Reconciliation ──────────────────────────────────────────────────────────


def drift(db: Session, target_id: UUID) -> facts.DriftReport | None:
    """Compute the difference between what was rolled out and what is observed.

    Computed on demand and never cached — a cached flag would have to be
    invalidated by every desired-state edit, every observation and every rollout,
    which is three writers for one derived value.

    Compared against the plan that was actually ROLLED OUT, not the target's
    current desired state. Otherwise every desired-state edit would make every
    deployed target look instantly drifted, and the signal would be worthless
    within a week.
    """
    target = db.get(DeploymentTarget, target_id)
    if target is None:
        return None
    succeeded = db.execute(
        select(Rollout)
        .where(
            Rollout.target_id == target.id,
            Rollout.status == RolloutStatus.SUCCEEDED.value,
        )
        .order_by(Rollout.completed_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    rolled_out_release: str | None = None
    rolled_out_revision: int | None = None
    if succeeded is not None:
        plan = db.get(DeploymentPlan, succeeded.plan_id)
        if plan is not None:
            rolled_out_release = str((plan.snapshot or {}).get("release_ref") or "")
            rolled_out_revision = plan.desired_revision
    return facts.DriftReport(
        target_ref=target.target_ref,
        rolled_out_release_ref=rolled_out_release,
        rolled_out_revision=rolled_out_revision,
        observed_release_ref=target.observed_release_ref,
        observed_revision=target.observed_revision,
        last_observed_at=target.last_observed_at,
    )


# ── Reads ───────────────────────────────────────────────────────────────────


def get_target(db: Session, target_id: UUID) -> facts.TargetView | None:
    row = db.get(DeploymentTarget, target_id)
    return _target_view(row) if row is not None else None


def get_plan(db: Session, plan_id: UUID) -> facts.PlanView | None:
    row = db.get(DeploymentPlan, plan_id)
    return _plan_view(row) if row is not None else None


def get_rollout(db: Session, rollout_id: UUID) -> facts.RolloutView | None:
    row = db.get(Rollout, rollout_id)
    return _rollout_view(row) if row is not None else None


def observation_attempts(
    db: Session, *, target_ref: str | None = None
) -> tuple[ObservationAttempt, ...]:
    """The append-only arrival log, oldest first.

    Returns rows rather than views deliberately: this is a triage surface, and an
    operator asking "what arrived and what happened to it" wants every column,
    including the ones a normal caller has no business reading.
    """
    statement = select(ObservationAttempt).order_by(ObservationAttempt.received_at)
    if target_ref is not None:
        statement = statement.where(
            ObservationAttempt.authenticated_target_ref == target_ref
        )
    return tuple(db.execute(statement).scalars().all())


__all__ = [
    "AUDIT_ACTION_CREDENTIAL",
    "AUDIT_ACTION_OBSERVATION",
    "AUDIT_ACTION_ROLLOUT",
    "AUDIT_ACTION_TARGET",
    "SCOPE_ACTIVATE_CREDENTIAL",
    "SCOPE_APPROVE_PLAN",
    "SCOPE_CANCEL_PLAN",
    "SCOPE_CANCEL_ROLLOUT",
    "SCOPE_DECOMMISSION_TARGET",
    "SCOPE_DISPATCH",
    "SCOPE_ENROL_CREDENTIAL",
    "SCOPE_OBSERVE",
    "SCOPE_PROPOSE_PLAN",
    "SCOPE_REGISTER_TARGET",
    "SCOPE_REQUEST_ROLLOUT",
    "SCOPE_REVOKE_CREDENTIAL",
    "SCOPE_SETTLE",
    "SCOPE_SET_DESIRED",
    "SCOPE_SUSPEND_TARGET",
    "ApprovePlanCommand",
    "CredentialTransitionCommand",
    "EnrolCredentialCommand",
    "ProposePlanCommand",
    "RecordObservationCommand",
    "RegisterTargetCommand",
    "RequestRolloutCommand",
    "RolloutTransitionCommand",
    "SetDesiredStateCommand",
    "SettleAttemptCommand",
    "TargetTransitionCommand",
    "activate_credential",
    "approve_plan",
    "cancel_plan",
    "cancel_rollout",
    "credential_is_eligible",
    "decommission_target",
    "dispatch_attempt",
    "drift",
    "enrol_credential",
    "get_plan",
    "get_rollout",
    "get_target",
    "observation_attempts",
    "plan_snapshot",
    "propose_plan",
    "record_observation",
    "register_target",
    "request_rollout",
    "require_manual_repair",
    "revoke_credential",
    "set_desired_state",
    "settle_attempt",
    "snapshot_digest",
    "spec_digest",
    "suspend_target",
]
