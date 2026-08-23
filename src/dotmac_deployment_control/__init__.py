"""DotMac Deployment Control — what should be running, and what actually is.

The owner of **desired deployment intent, rollout planning, acknowledgement and
reconciliation** for licensed Dotmac application deployments.

Built under ADR-0057 § 3 with split historical evidence, recorded honestly rather
than smoothed over: the receipt half ports the never-merged Vendor V6 admission
design (a tested reference, not production-used code), and the plan/rollout half
has no source, evidenced across every branch, stash, dangling object and reflog
of the Vendor repository plus seven others. `EXTRACTION.toml` therefore carries
`source_mode = "greenfield-after-inventory"`: neither half qualifies as a
product-first extraction under rule 24.

## Three rules this module exists to hold

**1. What is dispatched is a PLAN, and a plan is frozen.** Nothing reads the
target's *current* desired state at dispatch time. Otherwise editing the desired
state mid-rollout would silently change what is being deployed, and the approval
would be for something else.

**2. A claim is never a proof.** An observation's authoritative identity is the
one resolved from the SIGNED key (ADR-0007 § 4). What the report says about
itself sits in a different column, and a CHECK constraint makes that structural.

**3. Every arrival is recorded, including the ones that fail.** An unknown key, a
malformed envelope or a bad signature is exactly the evidence an operator needs.
A fail-closed system that discards them is closed AND blind.

## What it owns

Target identity and credentials; product, release, licence and brand-profile
references; the versioned desired specification; environment classification;
immutable plan snapshots and their digests; approval evidence for sensitive
operations; rollout requests and attempts; desired-versus-observed state;
authenticated target acknowledgements; success, failure, timeout, cancellation
and manual-repair; idempotent retry and redrive; drift evidence; append-only
operational history; and the typed delivery intent and observation contracts.

## What it does NOT own

Provider credentials, provider clients, webhook verification, connector retry or
checkpoint state (the **Integrator**, ADR-0024 hard rule 28); the release
catalogue (`dotmac-release-catalog`); licence authority (`dotmac-licensing`);
brand definition; application-domain migrations; billing, entitlement or support
decisions; and general infrastructure observability — this module holds no health
status at all, because ruling A4 keeps health separate from fleet so that "no
mutating consumer of health" stays a checkable dependency direction.

## It verifies nothing itself

`dotmac_kernel.licensing.verify_applied_state` and `verify_possession` own
signature and possession checking (ADR-0007). The caller runs them and passes the
result in as an `ObservedState`. A second verifier here could disagree with the
first, and the disagreement would be invisible until it mattered.

## Transaction authority

Receives a `Session`; only `add` and `flush` (hard rule 8).

## Public surface

Everything importable from this top-level namespace is stable. Submodules are
not: import from here.
"""

from __future__ import annotations

from dotmac_deployment_control.facts import (
    CREDENTIAL_ACTIVATED_V1,
    CREDENTIAL_ENROLLED_V1,
    CREDENTIAL_REVOKED_V1,
    DRIFT_DETECTED_V1,
    INTENT_DISPATCHED_V1,
    OBSERVATION_RECORDED_V1,
    PLAN_APPROVED_V1,
    PLAN_CANCELLED_V1,
    PLAN_PROPOSED_V1,
    PUBLISHED_EVENT_TYPES,
    ROLLOUT_CANCELLED_V1,
    ROLLOUT_FAILED_V1,
    ROLLOUT_MANUAL_REPAIR_V1,
    ROLLOUT_REQUESTED_V1,
    ROLLOUT_SUCCEEDED_V1,
    ROLLOUT_TIMED_OUT_V1,
    TARGET_DECOMMISSIONED_V1,
    TARGET_DESIRED_STATE_SET_V1,
    TARGET_REGISTERED_V1,
    TARGET_SUSPENDED_V1,
    AttemptView,
    DriftReport,
    ObservationVerdict,
    PlanView,
    RolloutView,
    TargetView,
)
from dotmac_deployment_control.manifest import module
from dotmac_deployment_control.migrations import versions_dir
from dotmac_deployment_control.models import (
    SCHEMA,
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
    DeploymentControlError,
    DesiredDeployment,
    ExpectedStateError,
    ObservationRefusedError,
    ObservedState,
    PlanRefusedError,
    TransitionRefusedError,
)
from dotmac_deployment_control.service import (
    AUDIT_ACTION_CREDENTIAL,
    AUDIT_ACTION_OBSERVATION,
    AUDIT_ACTION_ROLLOUT,
    AUDIT_ACTION_TARGET,
    ApprovePlanCommand,
    CredentialTransitionCommand,
    EnrolCredentialCommand,
    ProposePlanCommand,
    RecordObservationCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RolloutTransitionCommand,
    SetDesiredStateCommand,
    SettleAttemptCommand,
    TargetTransitionCommand,
    activate_credential,
    approve_plan,
    cancel_plan,
    cancel_rollout,
    credential_is_eligible,
    decommission_target,
    dispatch_attempt,
    drift,
    enrol_credential,
    get_plan,
    get_rollout,
    get_target,
    observation_attempts,
    plan_snapshot,
    propose_plan,
    record_observation,
    register_target,
    request_rollout,
    require_manual_repair,
    revoke_credential,
    set_desired_state,
    settle_attempt,
    snapshot_digest,
    spec_digest,
    suspend_target,
)

__version__ = "0.1.0a2"

__all__ = [
    "AUDIT_ACTION_CREDENTIAL",
    "AUDIT_ACTION_OBSERVATION",
    "AUDIT_ACTION_ROLLOUT",
    "AUDIT_ACTION_TARGET",
    "CREDENTIAL_ACTIVATED_V1",
    "CREDENTIAL_ENROLLED_V1",
    "CREDENTIAL_REVOKED_V1",
    "DRIFT_DETECTED_V1",
    "INTENT_DISPATCHED_V1",
    "OBSERVATION_RECORDED_V1",
    "PLAN_APPROVED_V1",
    "PLAN_CANCELLED_V1",
    "PLAN_PROPOSED_V1",
    "PUBLISHED_EVENT_TYPES",
    "ROLLOUT_CANCELLED_V1",
    "ROLLOUT_FAILED_V1",
    "ROLLOUT_MANUAL_REPAIR_V1",
    "ROLLOUT_REQUESTED_V1",
    "ROLLOUT_SUCCEEDED_V1",
    "ROLLOUT_TIMED_OUT_V1",
    "SCHEMA",
    "TARGET_DECOMMISSIONED_V1",
    "TARGET_DESIRED_STATE_SET_V1",
    "TARGET_REGISTERED_V1",
    "TARGET_SUSPENDED_V1",
    "TERMINAL_ROLLOUT_STATUSES",
    "ApprovalEvidence",
    "ApprovalRefusedError",
    "ApprovePlanCommand",
    "AttemptOutcome",
    "AttemptView",
    "CredentialStatus",
    "CredentialTransitionCommand",
    "DeliveryIntent",
    "DeploymentControlError",
    "DeploymentPlan",
    "DeploymentTarget",
    "DesiredDeployment",
    "DriftReport",
    "EligibilityAtReceipt",
    "EnrolCredentialCommand",
    "ExpectedStateError",
    "ObservationAttempt",
    "ObservationDisposition",
    "ObservationReceipt",
    "ObservationRefusedError",
    "ObservationVerdict",
    "ObservedState",
    "PlanRefusedError",
    "PlanStatus",
    "PlanView",
    "ProposePlanCommand",
    "RecordObservationCommand",
    "RegisterTargetCommand",
    "RequestRolloutCommand",
    "Rollout",
    "RolloutAttempt",
    "RolloutStatus",
    "RolloutTransitionCommand",
    "RolloutView",
    "SetDesiredStateCommand",
    "SettleAttemptCommand",
    "SignatureStatus",
    "TargetCredential",
    "TargetStatus",
    "TargetTransitionCommand",
    "TargetView",
    "TransitionRefusedError",
    "__version__",
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
    "module",
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
    "versions_dir",
]
