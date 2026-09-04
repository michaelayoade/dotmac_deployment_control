"""Desired deployment intent, rollout, acknowledgement and reconciliation.

Two source modes, recorded honestly (ADR-0057 § 3):

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
one Control resolves from the verified observation key (ADR-0007 § 4). What the
report says about itself is stored beside it as evidence and is never promoted.

**3. Every arrival is recorded, including the ones that fail.** An unknown key, a
malformed envelope or a bad signature against a known key is exactly the evidence
an operator needs. A fail-closed system that discards them silently is the worst
of both — closed AND blind.

## What this module never does

- **Talk to a provider.** No SSH, Kubernetes, cloud or panel client; no webhook
  verification; no endpoint, credential reference, transport name or retry
  policy. It emits a provider-neutral `DeliveryIntent` and the Integrator owns
  everything after that (ADR-0024, hard rule 28).
- **Own cryptographic keys or algorithms.** Control owns the canonical
  authorization, concrete dispatch and execution-observation statements, then
  calls injected, purpose-specific signer/verifier ports. Those three key
  purposes cannot cross through the typed API and Control stores neither
  private key nor provider implementation.
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

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from dotmac_kernel.audit import write_platform_audit_event
from dotmac_kernel.messaging import enqueue_platform_event, process_once_platform

# This module never imports `dotmac_kernel.db` or constructs an engine. Every
# operation receives a caller-owned Session; target-row serialization now owns
# the observation race, so no kernel transaction helper is needed here either.
from sqlalchemy import case, func, literal, select
from sqlalchemy.orm import Session

from dotmac_deployment_control import facts
from dotmac_deployment_control.approvals import (
    ApprovalDecisionStatus,
    require_decision_status,
)
from dotmac_deployment_control.authorization import (
    AuthorizationEnvelopeRefusalCode,
    AuthorizationEnvelopeRefusedError,
    AuthorizationEnvelopeV1,
    AuthorizationEnvelopeV2,
    AuthorizationSigner,
    AuthorizationVerifier,
    issue_authorization_envelope,
    verify_authorization_envelope,
)
from dotmac_deployment_control.counterparty import (
    EXECUTOR_OPERATIONS,
    require_executable_operation,
)
from dotmac_deployment_control.digests import (
    AuthorizationEnvelopeDigestV1,
    DescriptorDigestV1,
    DispatchEnvelopeDigestV1,
    ExecutionPlanDigestV1,
    ObservationEnvelopeDigestV1,
    PlanDigestV1,
    PublicKeyFingerprintV1,
    SpecDigestV1,
    canonical_json,
)
from dotmac_deployment_control.dispatch_envelope import (
    DispatchEnvelopeV1,
    DispatchSigner,
    issue_dispatch_envelope,
)
from dotmac_deployment_control.execution_observation import (
    EXECUTION_OBSERVATION_PURPOSE,
    MAX_EXECUTION_OBSERVATION_ENVELOPE_BYTES,
    ExecutionObservationEnvelopeV1,
    ExecutionObservationOutcome,
    ExecutionObservationRefusedError,
    ExecutionObservationStatementV1,
    ExecutionObservationVerificationKey,
    ExecutionObservationVerifier,
    verify_execution_observation_envelope,
)
from dotmac_deployment_control.images import (
    AuthorizedImage,
    authorized_image_set,
    image_set_from_payload,
    image_set_payload,
)
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
    RecoveryGrant,
    Rollout,
    RolloutAttempt,
    RolloutStatus,
    SignatureStatus,
    TargetCredential,
    TargetStatus,
)
from dotmac_deployment_control.operations import (
    require_operation,
)
from dotmac_deployment_control.ports import (
    ApprovalEvidence,
    ApprovalRefusedError,
    ApprovedPlanRefusedError,
    DeliveryIntent,
    DescriptorBindingError,
    DesiredDeployment,
    DigestEncodingError,
    ExecutionPlanBindingError,
    ExpectedStateError,
    ImageSetRefusedError,
    ObservationRefusedError,
    OperationRefusedError,
    PlanRefusedError,
    TransitionRefusedError,
)
from dotmac_deployment_control.recovery_grant import (
    RecoveryGrantV1,
    RecoveryGrantVerifier,
    RecoveryStandingResult,
    RecoverySubject,
    recovery_standing,
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
SCOPE_REVOKE_PLAN_APPROVAL = "deployment.revoke_plan_approval"
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

    The algorithm is an enrolled fact, not a choice left to a later report.
    Control validates the canonical public-key bytes and derives their
    fingerprint itself. It never holds private material and never generates a
    key.
    """

    command_id: str
    target_id: UUID
    key_id: str
    algorithm: str
    public_key_b64: str
    enrollment_authority: str
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class CredentialTransitionCommand:
    command_id: str
    credential_id: UUID
    reason: str | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ProposePlanCommand:
    """Freeze the target's CURRENT desired state into an immutable plan.

    There is no digest field here, and there never may be. The digest a plan
    carries is derived by this module from state it owns; a field for one would
    let a caller name the thing its own approval is later bound to.

    `expected_desired_revision` is the caller's evidence coordinate and is the
    opposite kind of value: an integer this module issued, identifying WHICH
    desired state the caller was looking at. Supplying it turns "freeze whatever
    is current" into "freeze revision 7, and refuse if it has moved" — which is
    what a human operator actually means when they click a button on a page
    rendered some seconds ago. Optional, because a caller inside one transaction
    has no such gap.

    ## `execution_plan_digest` IS a digest field, and it is the exception the
    ## paragraph above defines rather than a hole in it

    The rule that no caller may name a digest is a rule about digests this
    module DERIVES. `plan_digest` is derived from state Control owns, so a
    caller naming one would be choosing what its own approval binds to.

    `execution_plan_digest` is the opposite situation and admits the opposite
    conclusion. It is `sha256(canonical FoundationExecutionPlanV1 bytes)` — over
    a plan the Deployment Foundation renders from the immutable artifact and the
    authorized environment inventory. Control has no renderer for it, no column
    holding its bytes, and no way to reach either. A value this module cannot
    derive must be supplied, or the binding cannot exist at all.

    Both are REQUIRED, and neither has a default:

    * a default `operation` would infer a deployment from a caller's silence,
      and Michael's ruling is that DEPLOY and ROLLBACK are separately authorized
      operations, never inferred;
    * a default `execution_plan_digest` would be Control inventing the value it
      exists not to invent.

    ## What this means for a browser-originated proposal

    It refuses, and the refusal is the architecture rather than a regression.
    The admin surface's `refuse_client_supplied_digest` dependency rejects any
    digest-shaped value in any browser request, by name AND by shape — correctly,
    because a browser is not the Deployment Foundation and cannot have rendered
    an execution plan. So a browser cannot construct this command, and the route
    returns the module's own words at 400. A proposal that can produce a receipt
    is made by Platform CP's composition adapter, after the Foundation has
    rendered and digested the plan.
    """

    command_id: str
    target_id: UUID
    #: The declared operation, from the closed vocabulary. Validated on
    #: construction so the refusal happens at the caller, before any state is
    #: read — the earliest point at which the absence is known.
    operation: str
    #: The Foundation's canonical descriptor digest. Control reads and freezes
    #: it but has no constructor capable of deriving it.
    descriptor_digest: str
    #: The Foundation's digest, canonical `sha256:<64 lowercase hex>`. Validated
    #: on construction for ENCODING only: this refuses a value that cannot be
    #: read, and it never rewrites one that can.
    execution_plan_digest: str
    requires_approval: bool = True
    approval_policy_code: str | None = None
    approval_policy_version: int | None = None
    expected_desired_revision: int | None = None
    actor_ref: str | None = None

    def __post_init__(self) -> None:
        """Refuse an unusable OPERATION at construction.

        Here rather than in the handler because it is a fault in the command
        alone: no state has to be read to know that `redeploy` is not a member
        of a three-member vocabulary, and a command that cannot be valid should
        not survive long enough to have its refusal mixed with a target's.

        The EXECUTION PLAN DIGEST is deliberately NOT validated here. It is
        checked inside `propose_plan`, after the target-state blockers and the
        evidence-coordinate check, so that the refusal an operator is most
        likely to meet — "the desired state moved since the page you read" —
        still reaches them first. Validating it here would make every stale
        browser submission report the binding instead, which is true but is not
        the finding they need.
        """
        require_operation(self.operation, where="ProposePlanCommand.operation")


@dataclass(frozen=True, slots=True)
class ApprovePlanCommand:
    command_id: str
    plan_id: UUID
    evidence: ApprovalEvidence
    expected_version: int | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class RevokePlanApprovalCommand:
    """Withdraw an approval that was recorded, without erasing that it was.

    The plan's own `status` stays `approved` — it WAS, on evidence, at a
    recorded time, and that is history. What moves is
    `approval_decision_status`, which owns whether the approval still stands.

    `revocation_ref` is REQUIRED and has no default. A revocation is a decision
    somebody took in the approvals authority, and one arriving here with
    nothing to resolve it back to would make an authorization disappear with no
    decision behind it — which reads to an operator exactly like a bug, and
    would be indistinguishable from one afterwards.

    `reason` is optional and is for the human. It is never parsed.
    """

    command_id: str
    plan_id: UUID
    revocation_ref: str
    reason: str | None = None
    expected_version: int | None = None
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class RequestRolloutCommand:
    """Decide to converge a target on an APPROVED (or approval-exempt) plan."""

    command_id: str
    rollout_ref: str
    plan_id: UUID
    authorization_expires_at: datetime
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
    """Admit (or refuse, and record) one inbound observation.

    ## ONE input, and the shape is the repair

    `observation` is the exact bounded wire bytes, and it is the ONLY channel.
    The earlier shape took a parsed envelope beside an `ObservedState` carrying
    `raw_body`/`raw_body_digest` — two inputs that had to agree, held apart so
    nothing forced them to. Control could verify envelope A while storing
    caller-supplied bytes B, and the comparison bolted between the two
    parameters was the only thing standing in the way. That is the
    verify-A-store-B split, the same family as every binding this programme has
    repaired, and the fix is single-input BY CONSTRUCTION: Control derives the
    digest itself, parses these bytes, verifies these bytes, compares these
    bytes, and stores these bytes. There is no second parameter to disagree
    with, and no projection field a caller could use to smuggle a verification
    outcome in.

    `__post_init__` refuses a non-bytes value outright rather than recording
    it: rule 3 is about ARRIVALS — a bad thing a remote party sent — and a
    caller that passes a string or a mapping has not delivered an arrival, it
    has mis-called the API.
    """

    command_id: str
    #: The exact wire bytes as received from the transport, unparsed and
    #: untrusted. Bounded on admission: an oversize body is stored truncated
    #: (digest over the FULL bytes, taken first) and refused as malformed.
    observation: bytes
    actor_ref: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.observation, bytes):
            raise ObservationRefusedError(
                "an observation is the exact wire BYTES as received; this is a "
                f"{type(self.observation).__name__}. Control derives the "
                "digest, parses, verifies and stores that one value — a parsed "
                "or re-encoded form would let what is verified and what is "
                "stored diverge, which is the split this command exists to "
                "remove."
            )


def _control_now() -> datetime:
    """The trusted Control clock. Kept as one seam for deterministic tests."""
    return datetime.now(UTC)


# ── Digests ─────────────────────────────────────────────────────────────────


def plan_snapshot(
    target: DeploymentTarget, *, descriptor_digest: str | None = None
) -> dict[str, Any]:
    """The canonical frozen snapshot of a target's desired state.

    Deterministic by construction: `json.dumps(sort_keys=True)` at digest time,
    and every value here is either a scalar, the caller's own spec mapping, or
    the canonically ordered image set below. A digest over a dict whose
    iteration order is insertion order would change when the same plan was
    rebuilt in a different order, silently invalidating an approval nobody
    changed.

    ## `authorized_images` is HERE, and that placement is the point

    This document is the exact payload `PlanDigestV1` is taken over. Putting
    the authorized image set inside it means an approval, which binds the
    digest, binds the images — change an image and the digest moves, so a prior
    approval goes stale rather than silently covering a different set.

    A sibling `deployment_plans.authorized_images` column would have been the
    tidier-looking design and it is the one that fails: a column is a value an
    `UPDATE` can move while the digest sits still, and "approved" would stop
    meaning what it says with every screen still reading correctly. So there is
    no such column, and `tests/unit/test_authorized_image_set.py` plants an
    image change and requires the digest to move.

    ## Three states for the key, and `None` is not `[]`

    `None` — the target declared no image set; the plan freezes that absence
    honestly and `find_approved_plan` refuses it rather than answering. `[]` —
    it authorizes no images. A list — the set, already canonically ordered by
    `set_desired_state`, re-ordered here anyway because this function's output
    is a digest input and must not depend on a sibling's discipline.

    ## The key is present unconditionally

    Even when the value is `None`, so that "this plan predates the field" and
    "this plan declared nothing" are one state rather than two. Two encodings
    of one absence would be two digests for one plan.
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
        "authorized_images": image_set_payload(
            image_set_from_payload(
                target.desired_images,
                where=f"target {target.target_ref} desired image set",
            )
        ),
        # Present unconditionally so legacy absence has one representation.
        # Every new proposal supplies a canonical value; preview callers use
        # None because they have not received Foundation's descriptor yet.
        "descriptor_digest": descriptor_digest,
    }


def plan_digest_of(snapshot: Mapping[str, Any]) -> PlanDigestV1:
    """The TYPED identity of a plan snapshot — algorithm and digest bytes.

    This, not its rendering, is what the authorization path compares. Through
    `0.1.0a4` the two digest functions in this file returned different
    encodings of the same kind of value — one bare hex, one `sha256:`-prefixed,
    ten lines apart — and `approve_plan` compared the strings. See
    `dotmac_deployment_control.digests` for what that cost.
    """
    return PlanDigestV1.over_json(snapshot)


def snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    """The CANONICAL SERIALIZATION of `plan_digest` — `sha256:<64 hex>`.

    Retained as the rendering helper for storage and for the delivery intent.
    It no longer returns bare hex: a digest that leaves this module now carries
    its own algorithm, so no reader has to infer one from a length.
    """
    return plan_digest_of(snapshot).canonical


def spec_digest_of(spec: Mapping[str, Any]) -> SpecDigestV1:
    """The TYPED identity of a deployment spec alone.

    Separate from `plan_digest` because a target reports what it is RUNNING, not
    which plan produced it — it has no way to know the plan's identity. So the
    comparable value on both sides is the spec's own digest.

    A DIFFERENT TYPE, not merely a different function: a spec digest can never
    satisfy a plan-digest binding by arriving in the right shape, because the
    values compare unequal across types. Comparing strings, as `0.1.0a4` did,
    had no such protection.
    """
    return SpecDigestV1.over_json(spec)


def spec_digest(spec: Mapping[str, Any]) -> str:
    """The canonical serialization of `spec_digest_of`. Unchanged since a4."""
    return spec_digest_of(spec).canonical


# ── Internals ───────────────────────────────────────────────────────────────


def _frozen_plan_digest(row: DeploymentPlan) -> PlanDigestV1:
    """The digest THIS MODULE froze, read back from its own column.

    Tolerant of the `0.1.0a4` bare-hex form because a row written by that
    version carries it, and a stored value this module wrote is not a caller
    error. A value that cannot be read at all is a DATA fault and says so —
    distinct from the caller's encoding and from a changed plan, because the
    person who fixes each of the three is a different person.
    """
    try:
        return PlanDigestV1.parse_accepting_a4_bare_hex(row.plan_digest)
    except DigestEncodingError as exc:
        raise DigestEncodingError(
            f"plan {row.id} has a stored digest this module cannot read: {exc} "
            "This is a data fault in the frozen plan, not a caller error and "
            "not a changed plan. Do not re-approve; investigate the row."
        ) from exc


def _supplied_plan_digest(row: DeploymentPlan, value: str) -> PlanDigestV1:
    """The digest the CALLER bound its approval to.

    The only place in the fleet that normalizes a Control digest. Platform CP
    and the deployment foundation hand the value across as received — a
    consumer that normalizes has forked this parser, and the fork surfaces as a
    false "the plan changed".
    """
    try:
        return PlanDigestV1.parse_accepting_a4_bare_hex(value)
    except DigestEncodingError as exc:
        raise DigestEncodingError(
            f"approval evidence for plan {row.id} does not carry a readable "
            f"plan digest: {exc} No comparison was made against plan {row.id}, "
            "and no claim is made about whether it changed — supply the digest "
            f"as `{PlanDigestV1.__name__}` canonical text "
            "(`sha256:<64 lowercase hex>`) and approve again."
        ) from exc


def _stored_execution_plan_digest(
    row: DeploymentPlan, value: str | None, *, term: str
) -> ExecutionPlanDigestV1 | None:
    """Read back a value this module STORED but never computed.

    `None` in, `None` out: an unbound plan is a real state (`0.1.0a7` rows
    predate the columns) and is not a fault. A value that cannot be READ is a
    data fault in the frozen plan, and it says so — the same three-way split
    `_frozen_plan_digest` makes, for the same reason: the person who repairs an
    unreadable stored value is not the person who repairs a caller's encoding
    and is not the person who re-approves a moved plan.

    Strict: no `parse_accepting_a4_bare_hex`. This value never existed in
    `0.1.0a4`, so there is no legacy shape to tolerate, and tolerating one would
    mean this module normalizing a digest it does not own.

    This RAISES on the observation path too, and that is not a violation of
    rule 3. Rule 3 is about ARRIVALS: a bad thing a remote party sent is
    recorded rather than discarded. An unreadable value in this module's own
    column is not something a remote party sent — nothing in this package can
    write one — so it is a corruption of the binding the acceptance rule is
    decided on, and deciding anything against it would be worse than failing
    loudly. The sender's transport is at-least-once and will re-present the
    report once the row is repaired.
    """
    if value is None:
        return None
    try:
        return ExecutionPlanDigestV1.parse(value)
    except DigestEncodingError as exc:
        raise DigestEncodingError(
            f"plan {row.id} holds a {term} this module cannot read: {exc} This "
            "is a data fault in the stored binding, not a caller error. Control "
            "receives this value and never recomputes it, so it cannot be "
            "repaired by re-deriving one — investigate the row."
        ) from exc


def _supplied_execution_plan_digest_text(
    value: object, *, where: str
) -> ExecutionPlanDigestV1:
    """Read a caller-supplied execution plan digest when there is no row yet.

    `propose_plan` validates before a plan exists, so it cannot name one in the
    refusal. Same parser, same strictness, same refusal-not-normalization rule.
    """
    try:
        return ExecutionPlanDigestV1.parse(value)
    except DigestEncodingError as exc:
        raise DigestEncodingError(
            f"{where} does not carry a readable execution plan digest: {exc} "
            "Supply the Deployment Foundation's `ExecutionPlanDigestV1` exactly "
            "as it issued it (`sha256:<64 lowercase hex>`); Deployment Control "
            "refuses a value it cannot read rather than reshaping one, because "
            "reshaping it here would make this module a second canonicalization "
            "of a plan it does not own."
        ) from exc


def _supplied_execution_plan_digest(
    row: DeploymentPlan, value: object, *, where: str
) -> ExecutionPlanDigestV1:
    """Read a value a CALLER supplied, and refuse rather than tidy it.

    The parser is strict-canonical, so a non-canonical spelling is REFUSED. That
    is deliberate and it is the point of the whole repair: normalizing here
    would make Control a second canonicalizer of the Foundation's value, and two
    canonicalizations that agree about serialization and disagree about payload
    is exactly the defect this binding exists to remove. Refusing is not
    normalizing.
    """
    try:
        return ExecutionPlanDigestV1.parse(value)
    except DigestEncodingError as exc:
        raise DigestEncodingError(
            f"{where} for plan {row.id} does not carry a readable execution "
            f"plan digest: {exc} No comparison was made and no claim is made "
            "about which execution was authorized — supply the Deployment "
            "Foundation's `ExecutionPlanDigestV1` exactly as it issued it "
            "(`sha256:<64 lowercase hex>`); Control will not reshape it."
        ) from exc


def _supplied_descriptor_digest(value: object, *, where: str) -> DescriptorDigestV1:
    """Read the Foundation-owned descriptor digest without reshaping it."""
    if not value:
        raise DescriptorBindingError(
            f"{where} carries no descriptor digest. Deployment Control cannot "
            "derive one because it neither parses nor canonicalizes the "
            "Foundation descriptor; submit the exact DescriptorDigestV1 text."
        )
    try:
        return DescriptorDigestV1.parse(value)
    except DigestEncodingError as exc:
        raise DescriptorBindingError(
            f"{where} does not carry a readable descriptor digest: {exc} "
            "Control refuses rather than normalizes a Foundation-owned value."
        ) from exc


def _frozen_descriptor_digest(row: DeploymentPlan) -> DescriptorDigestV1 | None:
    """Project the received descriptor binding from the digested snapshot."""
    snapshot = row.snapshot or {}
    value = snapshot.get("descriptor_digest")
    if value is None:
        return None
    try:
        return DescriptorDigestV1.parse(value)
    except DigestEncodingError as exc:
        raise DescriptorBindingError(
            f"plan {row.id} holds an unreadable descriptor binding: {exc} This "
            "is stored-data corruption, not a reason to re-derive the value."
        ) from exc


def _frozen_image_set(row: DeploymentPlan) -> tuple[AuthorizedImage, ...] | None:
    """The image set THIS PLAN froze, read back out of its own snapshot.

    Out of the SNAPSHOT and never out of a column, because the snapshot is the
    document `plan_digest` was taken over. Reading a sibling column would mean
    the answer a consumer acts on and the bytes the approval covers were two
    different things — which is exactly the shape this change exists to
    remove, rebuilt one layer up.

    `None` means the plan froze no set: it predates the field, or its target
    declared none. Never `()` for that case; the two are different facts and
    `find_approved_plan` treats them differently.
    """
    snapshot = row.snapshot or {}
    if "authorized_images" not in snapshot:
        return None
    return image_set_from_payload(
        snapshot.get("authorized_images"), where=f"plan {row.id} frozen snapshot"
    )


def _verified_rollout_envelope(
    rollout: Rollout,
    plan: DeploymentPlan,
    target: DeploymentTarget,
    *,
    verifier: AuthorizationVerifier | None,
    at: datetime | None = None,
) -> AuthorizationEnvelopeV2:
    """Verify signature and every database-backed term without rewriting history."""
    if rollout.authorization_envelope is None:
        raise AuthorizationEnvelopeRefusedError(
            AuthorizationEnvelopeRefusalCode.ABSENT,
            f"rollout {rollout.id} predates the portable authorization envelope",
        )
    if verifier is None:
        raise AuthorizationEnvelopeRefusedError(
            AuthorizationEnvelopeRefusalCode.SIGNATURE_INVALID,
            "no AuthorizationVerifier was injected; a stored JSON document is "
            "not evidence that its signature is valid",
        )
    envelope = verify_authorization_envelope(
        rollout.authorization_envelope, verifier=verifier, at=at
    )
    descriptor = _frozen_descriptor_digest(plan)
    images = _frozen_image_set(plan)
    statement = envelope.statement
    expected: dict[str, object] = {
        "authorization_id": str(rollout.id),
        "execution_sequence": rollout.execution_sequence,
        "rollout_ref": rollout.rollout_ref,
        "plan_id": str(plan.id),
        "target_id": str(target.id),
        "target_ref": target.target_ref,
        "product_code": target.product_code,
        "environment": target.environment,
        "operation": plan.authorized_operation or plan.operation,
        "release_ref": str((plan.snapshot or {}).get("release_ref") or ""),
        "authorized_images": images,
        "plan_digest": _frozen_plan_digest(plan).canonical,
        "descriptor_digest": None if descriptor is None else descriptor.canonical,
        "execution_plan_digest": (
            plan.authorized_execution_plan_digest or plan.execution_plan_digest
        ),
        "approval_policy_code": plan.approval_policy_code,
        "approval_policy_version": plan.approval_policy_version,
        "approval_decision_ref": plan.approval_decision_ref,
        "approval_decision_status": (
            ApprovalDecisionStatus.GRANTED.value
            if plan.requires_approval
            else "approval_exempt"
        ),
        "approved_at": plan.approved_at,
    }
    for field, value in expected.items():
        actual = getattr(statement, field)
        if field == "approved_at" and actual is not None and value is not None:
            assert isinstance(actual, datetime)
            assert isinstance(value, datetime)
            actual = _as_utc(actual)
            value = _as_utc(value)
        if actual != value:
            raise AuthorizationEnvelopeRefusedError(
                AuthorizationEnvelopeRefusalCode.SIGNATURE_INVALID,
                f"portable authorization field {field!r} does not match the "
                "immutable Control record. The envelope is retained as issued "
                "and dispatch is refused; history is not rewritten.",
            )
    return envelope


def _plan_blockers(target: DeploymentTarget) -> tuple[str, ...]:
    """Every reason THIS TARGET cannot be planned for, in operator language.

    ONE owner for the target-state half of `propose_plan`'s refusals, because
    two consumers now ask the same question for different purposes:
    `propose_plan` asks it to refuse, and `preview_plan_proposal` asks it to
    decide whether an interactive surface should offer the action at all.

    Written as a list rather than as the first failure, so a screen can show an
    operator everything that is wrong at once instead of one thing per attempt.
    `propose_plan` still raises on the first, because a command has one outcome.

    Deliberately NOT the whole refusal set: the approval-policy rule below is a
    property of the COMMAND (did the caller name a policy?), not of the target,
    and a preview computed before the command exists cannot answer it.
    """
    reasons: list[str] = []
    if target.status != TargetStatus.ACTIVE.value:
        reasons.append(
            f"target {target.target_ref} is {target.status!r}; only an active "
            "target can be planned for"
        )
    if not target.desired_release_ref:
        reasons.append(
            f"target {target.target_ref} has no desired release; a plan with "
            "nothing to converge on is not a plan"
        )
    return tuple(reasons)


def _load_target(session: Session, target_id: UUID) -> DeploymentTarget:
    row = session.get(DeploymentTarget, target_id)
    if row is None:
        raise TransitionRefusedError(f"deployment target {target_id} not found")
    return row


def _load_target_for_update(session: Session, target_id: UUID) -> DeploymentTarget:
    row = session.execute(
        select(DeploymentTarget)
        .where(DeploymentTarget.id == target_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        raise TransitionRefusedError(f"deployment target {target_id} not found")
    return row


def _load_plan(session: Session, plan_id: UUID) -> DeploymentPlan:
    row = session.get(DeploymentPlan, plan_id)
    if row is None:
        raise TransitionRefusedError(f"deployment plan {plan_id} not found")
    return row


def _load_plan_for_update(session: Session, plan_id: UUID) -> DeploymentPlan:
    row = session.execute(
        select(DeploymentPlan)
        .where(DeploymentPlan.id == plan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        raise TransitionRefusedError(f"deployment plan {plan_id} not found")
    return row


def _load_plan_with_target_for_update(
    session: Session, plan_id: UUID
) -> tuple[DeploymentTarget, DeploymentPlan]:
    target_id = session.execute(
        select(DeploymentPlan.target_id).where(DeploymentPlan.id == plan_id)
    ).scalar_one_or_none()
    if target_id is None:
        raise TransitionRefusedError(f"deployment plan {plan_id} not found")
    target = _load_target_for_update(session, target_id)
    return target, _load_plan_for_update(session, plan_id)


def _load_credential_for_update(
    session: Session, credential_id: UUID
) -> TargetCredential:
    target_id = session.execute(
        select(TargetCredential.target_id).where(TargetCredential.id == credential_id)
    ).scalar_one_or_none()
    if target_id is None:
        raise TransitionRefusedError(f"credential {credential_id} not found")
    _load_target_for_update(session, target_id)
    row = session.execute(
        select(TargetCredential)
        .where(TargetCredential.id == credential_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        raise TransitionRefusedError(f"credential {credential_id} not found")
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


#: R4. The current plan's approval standing, as ONE correlated subquery on the
#: statement that lists targets. A per-row lookup would satisfy the field's
#: description and defeat its purpose -- the N+1 relocated into the ORM, passing
#: any test that only checks the value.
#:
#: The outer `coalesce(..., "none")` is NOT the `COALESCE(status, 'granted')`
#: this must never be. That one reads an authorization out of a blank column;
#: this one distinguishes "no plan exists" from every state a plan can be in,
#: and `unrecorded` stays its own answer.
def _approval_standing_subquery() -> Any:
    return func.coalesce(
        select(
            case(
                (
                    DeploymentPlan.approval_revoked_at.is_not(None),
                    literal("revoked"),
                ),
                (
                    DeploymentPlan.approval_decision_status.is_(None),
                    literal("unrecorded"),
                ),
                else_=DeploymentPlan.approval_decision_status,
            )
        )
        .where(DeploymentPlan.target_id == DeploymentTarget.id)
        .order_by(DeploymentPlan.sequence.desc())
        .limit(1)
        .correlate(DeploymentTarget)
        .scalar_subquery(),
        literal("none"),
    )


def _approval_standing_for(db: Session, target_id: UUID) -> str:
    """R4 for ONE target, sharing the CASE with the paged projection.

    Written from `_approval_standing_subquery()` rather than beside it, so the
    single read and the page cannot answer the same question differently.
    """
    return str(
        db.execute(
            select(_approval_standing_subquery())
            .select_from(DeploymentTarget)
            .where(DeploymentTarget.id == target_id)
        ).scalar_one()
    )


def _target_view(row: DeploymentTarget, *, approval_standing: str) -> facts.TargetView:
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
        # R1. Through the parser that already owns the three states, so
        # `None` (undeclared) cannot collapse into `()` (declared empty).
        # The defence is that there is ONE implementation of the contract,
        # not that this call site handles `None` correctly.
        desired_images=image_set_from_payload(
            row.desired_images, where=f"target {row.id} desired images"
        ),
        current_plan_approval_status=approval_standing,
    )


def _operation_is_executable(row: DeploymentPlan) -> bool | None:
    """R3. Can the counterparty perform what this plan names?

    SET MEMBERSHIP, deliberately, and never `require_executable_operation`:
    that is the freeze/sign/dispatch gate and its own signature says "never for
    reading". Calling it here would make every historical `recover` plan raise
    on the plans page -- a record that becomes unreadable when a counterparty
    changes is a record that rewrites itself.

    `None` when no operation is declared. An undeclared operation is not an
    inexecutable one, and `False` would say a plan nobody has described is one
    nobody can run.
    """
    operation = row.authorized_operation or row.operation
    if operation is None:
        return None
    return operation in EXECUTOR_OPERATIONS


def _plan_view(row: DeploymentPlan) -> facts.PlanView:
    descriptor = _frozen_descriptor_digest(row)
    return facts.PlanView(
        id=row.id,
        target_id=row.target_id,
        sequence=row.sequence,
        status=row.status,
        desired_revision=row.desired_revision,
        record_version=row.record_version,
        plan_digest=row.plan_digest,
        descriptor_digest=None if descriptor is None else descriptor.canonical,
        operation=row.operation,
        execution_plan_digest=row.execution_plan_digest,
        authorized_operation=row.authorized_operation,
        authorized_execution_plan_digest=row.authorized_execution_plan_digest,
        requires_approval=row.requires_approval,
        approval_policy_code=row.approval_policy_code,
        approval_policy_version=row.approval_policy_version,
        approval_decision_ref=row.approval_decision_ref,
        approved_at=row.approved_at,
        approval_decision_status=row.approval_decision_status,
        approval_revoked_at=row.approval_revoked_at,
        approval_revocation_ref=row.approval_revocation_ref,
        approval_revocation_reason=row.approval_revocation_reason,
        superseded_by_id=row.superseded_by_id,
        snapshot=dict(row.snapshot or {}),
        authorized_images=_frozen_image_set(row),
        operation_is_executable=_operation_is_executable(row),
    )


def _rollout_view(row: Rollout) -> facts.RolloutView:
    envelope = (
        None
        if row.authorization_envelope is None
        else _parse_historical_authorization_envelope(row.authorization_envelope)
    )
    return facts.RolloutView(
        id=row.id,
        rollout_ref=row.rollout_ref,
        target_id=row.target_id,
        plan_id=row.plan_id,
        status=row.status,
        record_version=row.record_version,
        authorization_envelope=envelope,
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


def _parse_historical_authorization_envelope(
    value: object,
) -> AuthorizationEnvelopeV1 | AuthorizationEnvelopeV2:
    """Read a stored envelope at its own version without upgrading it.

    V1 remains operator-visible history. Dispatch and approval lookup call the
    V2-only verifier instead, so this reader cannot turn old bytes into current
    permission.
    """
    if isinstance(value, AuthorizationEnvelopeV1 | AuthorizationEnvelopeV2):
        return value
    if isinstance(value, Mapping):
        statement = value.get("statement")
        if isinstance(statement, Mapping) and statement.get("version") == 1:
            return AuthorizationEnvelopeV1.parse(value)
    return AuthorizationEnvelopeV2.parse(value)


def _observation_attempt_view(row: ObservationAttempt) -> facts.ObservationAttemptView:
    """Project an arrival. The raw body never crosses this boundary."""
    return facts.ObservationAttemptView(
        id=row.id,
        received_at=row.received_at,
        disposition=row.disposition,
        signature_status=row.signature_status,
        eligibility_at_receipt=row.eligibility_at_receipt,
        key_id=row.key_id,
        authenticated_target_ref=row.authenticated_target_ref,
        claimed_target_ref=row.claimed_target_ref,
        report_id=row.report_id,
        raw_body_digest=row.raw_body_digest,
        raw_body_truncated=row.raw_body_truncated,
        receipt_id=row.receipt_id,
    )


def _observation_receipt_view(row: ObservationReceipt) -> facts.ObservationReceiptView:
    """Project safe typed evidence; the signed raw payload never crosses."""
    statement: ExecutionObservationStatementV1 | None = None
    signed_evidence_status = "legacy_absent"
    if row.payload is not None:
        try:
            decoded = json.loads(row.payload.decode("utf-8"))
            statement = ExecutionObservationEnvelopeV1.parse(decoded).statement
            signed_evidence_status = "verified_at_receipt"
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ExecutionObservationRefusedError,
        ):
            signed_evidence_status = "unreadable"
    return facts.ObservationReceiptView(
        id=row.id,
        authenticated_target_ref=row.authenticated_target_ref,
        report_id=row.report_id,
        key_id=row.key_id,
        first_received_at=row.first_received_at,
        original_verdict=row.original_verdict,
        observed_release_ref=row.observed_release_ref,
        observed_spec_digest=row.observed_spec_digest,
        payload_digest=row.payload_digest,
        execution_sequence=row.execution_sequence,
        attempt_no=row.attempt_no,
        observed_state_digest=row.observed_state_digest,
        signed_evidence_status=signed_evidence_status,
        authorization_id=(None if statement is None else statement.authorization_id),
        authorization_plan_id=(
            None if statement is None else statement.authorization_plan_id
        ),
        authorization_control_version=(
            None if statement is None else statement.authorization_control_version
        ),
        authorization_envelope_digest=(
            None if statement is None else statement.authorization_envelope_digest
        ),
        rollout_ref=(None if statement is None else statement.rollout_ref),
        operation=(None if statement is None else statement.operation),
        release_ref=(None if statement is None else statement.release_ref),
        authorized_images=(() if statement is None else statement.authorized_images),
        observed_images=(() if statement is None else statement.observed_images),
        plan_digest=(None if statement is None else statement.plan_digest),
        descriptor_digest=(None if statement is None else statement.descriptor_digest),
        execution_plan_digest=(
            None if statement is None else statement.execution_plan_digest
        ),
        observed_revision=(None if statement is None else statement.observed_revision),
        runtime_identity_kind=(
            None if statement is None else statement.runtime_identity.kind
        ),
        runtime_identity_identifier=(
            None if statement is None else statement.runtime_identity.identifier
        ),
        outcome=(None if statement is None else statement.outcome.value),
        observed_at=(None if statement is None else statement.observed_at),
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
    target = _load_target(db, UUID(str(outcome.result["id"])))
    return _target_view(target, approval_standing=_approval_standing_for(db, target.id))


def set_desired_state(db: Session, command: SetDesiredStateCommand) -> facts.TargetView:
    """Declare what a target should converge on, bumping `desired_revision`.

    Bumping unconditionally — even when the values happen to match — is
    deliberate. The revision records that a DECISION was taken, and an operator
    re-declaring the same state after an incident wants a plan they can approve,
    not a silent no-op that leaves the fleet exactly as it was.
    """

    def handler(session: Session) -> Mapping[str, object]:
        row = _load_target_for_update(session, command.target_id)
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
        # CANONICALIZED ON THE WAY IN, refused if it is not a set. Ordering and
        # duplicate-checking here rather than at proposal means the refusal
        # reaches whoever declared the images, at the moment they declared
        # them — not an operator three screens later who cannot fix it.
        #
        # `None` passes through as `None`: no image set declared is a real
        # state and is not an empty set (see `DesiredDeployment.images`).
        row.desired_images = image_set_payload(
            authorized_image_set(
                command.desired.images,
                where=f"desired state for target {row.target_ref}",
            )
        )
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
                # The COUNT, never the set. An audit detail is read far more
                # often than it is needed in full, and the images are already
                # recoverable from the row and from every plan frozen after
                # this. `None` here is the declared absence, and it stays
                # distinguishable from `0`.
                "authorized_image_count": (
                    None if row.desired_images is None else len(row.desired_images)
                ),
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_SET_DESIRED,
        handler=handler,
    )
    return _target_view(
        _load_target(db, command.target_id),
        approval_standing=_approval_standing_for(db, command.target_id),
    )


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
        row = _load_target_for_update(session, command.target_id)
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
    return _target_view(
        _load_target(db, command.target_id),
        approval_standing=_approval_standing_for(db, command.target_id),
    )


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
        target = _load_target_for_update(session, command.target_id)
        existing = session.execute(
            select(TargetCredential).where(TargetCredential.key_id == command.key_id)
        ).scalar_one_or_none()
        if existing is not None:
            expected_fingerprint = PublicKeyFingerprintV1.from_public_key_b64(
                command.public_key_b64
            ).canonical
            if (
                existing.target_id != target.id
                or existing.algorithm != command.algorithm
                or existing.purpose != EXECUTION_OBSERVATION_PURPOSE
                or existing.public_key_b64 != command.public_key_b64
                or existing.public_key_fingerprint != expected_fingerprint
            ):
                raise TransitionRefusedError(
                    f"credential key id {command.key_id!r} is already bound to a "
                    "different target or verification identity; rotate under a "
                    "new key id rather than reinterpreting enrolled bytes"
                )
            return {"id": str(existing.id)}
        fingerprint = PublicKeyFingerprintV1.from_public_key_b64(
            command.public_key_b64
        ).canonical
        row = TargetCredential(
            target_id=target.id,
            key_id=command.key_id,
            public_key_b64=command.public_key_b64,
            public_key_fingerprint=fingerprint,
            algorithm=command.algorithm,
            purpose=EXECUTION_OBSERVATION_PURPOSE,
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

    effective_at = _control_now()

    def handler(session: Session) -> Mapping[str, object]:
        row = _load_credential_for_update(session, command.credential_id)
        if row.status != CredentialStatus.PENDING.value:
            raise TransitionRefusedError(
                f"credential {row.key_id} is {row.status!r}; only a pending "
                "credential can be activated"
            )
        row.status = CredentialStatus.ACTIVE.value
        row.activated_at = effective_at
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

    effective_at = _control_now()

    def handler(session: Session) -> Mapping[str, object]:
        row = _load_credential_for_update(session, command.credential_id)
        if row.status == CredentialStatus.REVOKED.value:
            return {"id": str(row.id)}
        row.status = CredentialStatus.REVOKED.value
        row.revoked_at = effective_at
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
    if row is None:
        return False, None
    target = db.get(DeploymentTarget, row.target_id)
    target_ref = target.target_ref if target is not None else None
    return _credential_row_is_eligible(row, at=at), target_ref


def _credential_row_is_eligible(row: TargetCredential, *, at: datetime) -> bool:
    if row.activated_at is None:
        return False
    instant = _as_utc(at)
    if instant < _as_utc(row.activated_at):
        return False
    return not any(
        closed_at is not None and instant >= _as_utc(closed_at)
        for closed_at in (row.retired_at, row.revoked_at)
    )


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
        target = _load_target_for_update(session, command.target_id)
        blockers = _plan_blockers(target)
        if blockers:
            # One outcome per command, so the first is the one raised; the
            # preview is where an operator sees all of them at once.
            raise PlanRefusedError(blockers[0])
        if (
            command.expected_desired_revision is not None
            and command.expected_desired_revision != target.desired_revision
        ):
            # The caller was looking at a different desired state. Freezing the
            # current one instead would produce a plan nobody asked for and a
            # digest nobody saw — and the approval that followed would be for
            # that. Refusing here is what makes "created from the coordinates
            # the operator was shown" a property rather than a hope.
            raise PlanRefusedError(
                f"target {target.target_ref} was at desired revision "
                f"{command.expected_desired_revision} when this was requested "
                f"and is now at {target.desired_revision}. The plan you were "
                "shown is not the plan this would freeze; review the current "
                "desired state and propose again."
            )
        if command.requires_approval and not command.approval_policy_code:
            raise PlanRefusedError(
                "a plan that requires approval must name the policy it will be "
                "approved under, so the decision stays explainable after the "
                "policy changes"
            )
        if not command.execution_plan_digest:
            raise ExecutionPlanBindingError(
                "a plan must be bound to the execution plan digest the "
                "Deployment Foundation rendered and computed; this proposal "
                "carries none, and Deployment Control cannot supply one — it "
                "has no renderer for a FoundationExecutionPlanV1 and no way to "
                "reach its bytes. Submit the digest the Foundation issued, "
                "through Platform CP's composition adapter."
            )
        # ENCODING ONLY, and a refusal rather than a repair. `parse` accepts the
        # canonical spelling and nothing else, so a value that survives here is
        # byte-identical to the one that arrives — which is what lets the row
        # below store the caller's own text rather than a rendering of it.
        _supplied_execution_plan_digest_text(
            command.execution_plan_digest, where="this proposal"
        )
        _supplied_descriptor_digest(command.descriptor_digest, where="this proposal")

        highest = session.execute(
            select(func.max(DeploymentPlan.sequence)).where(
                DeploymentPlan.target_id == target.id
            )
        ).scalar()
        sequence = int(highest or 0) + 1

        snapshot = plan_snapshot(target, descriptor_digest=command.descriptor_digest)
        row = DeploymentPlan(
            target_id=target.id,
            sequence=sequence,
            status=PlanStatus.PROPOSED.value,
            snapshot=snapshot,
            desired_revision=target.desired_revision,
            plan_digest=plan_digest_of(snapshot).canonical,
            # FROZEN AS RECEIVED. `command.operation` and
            # `command.execution_plan_digest` are stored as the caller sent
            # them, not as this module would render them: the command's
            # `__post_init__` already refused anything that was not exactly a
            # vocabulary member and exactly the canonical digest form, so
            # "validated" and "unchanged" are the same bytes here. Writing
            # `parsed.canonical` instead would be indistinguishable today and
            # would quietly become a normalization the day the parser grew a
            # tolerance.
            operation=command.operation,
            execution_plan_digest=command.execution_plan_digest,
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
                "descriptor_digest": command.descriptor_digest,
                "operation": row.operation,
                "execution_plan_digest": row.execution_plan_digest,
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
        _target, row = _load_plan_with_target_for_update(session, command.plan_id)
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

        # THREE OUTCOMES, and separating them is the whole of this change.
        #
        # `0.1.0a4` had two: equal, or "the plan changed after approval". A
        # caller who supplied the SAME digest in the other encoding got the
        # second one — a security refusal standing in for a formatting bug,
        # which is the worst failure shape available because it looks like the
        # system working.
        frozen = _frozen_plan_digest(row)
        supplied = _supplied_plan_digest(row, command.evidence.content_digest)
        if supplied != frozen:
            # TYPED comparison. Two `PlanDigestV1` values are equal when the
            # algorithm and the raw bytes are equal, which no encoding can
            # change — so reaching here means the plan really did move.
            raise ApprovalRefusedError(
                f"approval evidence binds to plan digest {supplied.canonical} "
                f"but plan {row.id} froze {frozen.canonical}. Both values were "
                f"read as well-formed {supplied.algorithm} digests and their "
                "bytes differ, so this is a genuine mismatch and not an "
                "encoding difference: the plan changed after approval, and a "
                "new approval is required."
            )
        # ── The DECISION term ───────────────────────────────────────────────
        #
        # Checked BEFORE the policy and binding terms below, because it is the
        # cheapest question with the largest answer: if the decision does not
        # stand, nothing about which policy or which execution it named
        # matters. A revoked decision replayed here is the arrival this refusal
        # exists for — far more likely than a mistyped word, and the one that
        # would otherwise be recorded as a live approval.
        if command.evidence.decision_status is None:
            raise ApprovalRefusedError(
                f"approval evidence for plan {row.id} does not say what the "
                "decision was. Reaching this function is not evidence that a "
                "decision granted anything — that inference is the same shape "
                "as a defaulted operation, a caller's silence deciding an "
                "authorization. State the standing "
                f"({sorted(ApprovalDecisionStatus)!r} spelled exactly)."
            )
        decision_status = require_decision_status(
            command.evidence.decision_status,
            where=f"approval evidence for plan {row.id}",
        )
        if decision_status is not ApprovalDecisionStatus.GRANTED:
            raise ApprovalRefusedError(
                f"approval evidence for plan {row.id} carries decision "
                f"{command.evidence.decision_ref!r} with standing "
                f"{decision_status.value!r}. A decision that does not grant "
                "authorizes nothing, and recording it as an approval would put "
                "a withdrawn authorization behind a rollout."
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

        # ── The AUTHORIZATION term of the three-term binding ────────────────
        #
        # Recorded here, in its own columns, and refused unless it equals what
        # was proposed. Two separate refusals, because they are two findings:
        # an approval over the wrong EXECUTION PLAN authorizes a different
        # deployment, and an approval of the wrong OPERATION authorizes the
        # right deployment as the wrong kind of act. A rollback signed under a
        # deploy's approval is invisible to a digest-only check, which is why
        # the operation is compared separately rather than folded into it.
        frozen_execution = _stored_execution_plan_digest(
            row, row.execution_plan_digest, term="execution plan digest"
        )
        if frozen_execution is None or row.operation is None:
            # A `0.1.0a7` plan, proposed before the binding existed. Approving
            # it would produce an authorization naming no execution, which no
            # report could ever satisfy — so it is refused here rather than at
            # the report, where the operator would be reading a receipt failure
            # for a plan that was never bindable.
            raise ExecutionPlanBindingError(
                f"plan {row.id} carries no execution plan binding (operation="
                f"{row.operation!r}); it was proposed before Deployment Control "
                "held one, and an approval over it would authorize no execution "
                "any executor could verify. Propose a new plan through the "
                "Deployment Foundation's rendered execution plan."
            )
        if command.evidence.execution_plan_digest is None:
            raise ExecutionPlanBindingError(
                f"approval evidence for plan {row.id} names no execution plan "
                "digest. The acceptance rule is a THREE-term one — proposal, "
                "authorization, report — and an approval that binds no "
                "execution reduces it to two terms while still reading as three."
            )
        supplied_execution = _supplied_execution_plan_digest(
            row, command.evidence.execution_plan_digest, where="approval evidence"
        )
        if supplied_execution != frozen_execution:
            raise ExecutionPlanBindingError(
                f"approval evidence authorizes execution plan "
                f"{supplied_execution.canonical} but plan {row.id} froze "
                f"{frozen_execution.canonical}. Both were read as well-formed "
                "digests and their bytes differ, so this is an approval of a "
                "different execution — not an encoding difference. Deployment "
                "Control never recomputes this value and cannot reconcile them; "
                "the two must be made equal by whoever submitted them."
            )
        if command.evidence.operation is None:
            raise ExecutionPlanBindingError(
                f"approval evidence for plan {row.id} names no operation. DEPLOY "
                "and ROLLBACK are separately authorized operations, so an "
                "approval that does not say which one it authorizes authorizes "
                "neither."
            )
        frozen_operation = require_operation(
            row.operation, where=f"plan {row.id} frozen operation"
        )
        supplied_operation = require_operation(
            command.evidence.operation, where="approval evidence operation"
        )
        if supplied_operation is not frozen_operation:
            raise ExecutionPlanBindingError(
                f"approval evidence authorizes {supplied_operation.value!r} but "
                f"plan {row.id} was proposed as {frozen_operation.value!r}. These "
                "are separately authorized operations: an approval of one is not "
                "an approval of the other, and neither is inferred from the "
                "other."
            )
        # THE FENCE, at the moment the operation stops being a proposal. An
        # operation the executor has not published support for is refused here
        # rather than at dispatch, because a frozen authorization is what every
        # later screen reads as settled.
        require_executable_operation(
            supplied_operation, where=f"plan {row.id} authorized operation"
        )
        row.authorized_operation = supplied_operation.value
        # STORED AS RECEIVED, like the proposal above. `supplied_execution
        # .canonical` is provably the same text — the parser accepted only the
        # canonical spelling — and writing it would still be Control rendering
        # somebody else's value. Same bytes today, different property forever.
        row.authorized_execution_plan_digest = command.evidence.execution_plan_digest

        row.approval_decision_ref = command.evidence.decision_ref
        # The STANDING, written from the validated member rather than from the
        # caller's text: this one IS Control's own column about Control's own
        # record, so writing the canonical spelling is not reshaping somebody
        # else's value — contrast the two digest columns above, which are
        # stored exactly as received.
        row.approval_decision_status = decision_status.value
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
                "authorized_operation": row.authorized_operation,
                "authorized_execution_plan_digest": (
                    row.authorized_execution_plan_digest
                ),
                "policy_code": command.evidence.policy_code,
                "policy_version": command.evidence.policy_version,
                "decision_ref": command.evidence.decision_ref,
                "decision_status": row.approval_decision_status,
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


def revoke_plan_approval(
    db: Session, command: RevokePlanApprovalCommand
) -> facts.PlanView:
    """Withdraw a recorded approval, so nothing downstream still reads it as one.

    ## Why this is not `cancel_plan`

    A cancelled plan is not wanted. A plan whose approval was revoked is still
    wanted and is no longer authorized — often because the approval was given
    against information that has since changed, and the plan itself is fine.
    Collapsing them would make an operator's queue unable to say which of the
    two happened, and would throw away a plan somebody may re-approve.

    ## What it reaches

    `request_rollout` refuses a plan whose approval does not stand, and
    `find_approved_plan` refuses it with `APPROVAL_REVOKED`. That second one is
    the important half: revocation is reachable from the LOOKUP a consumer
    already calls, not from a separate query it has to remember. A consumer
    asking "is this approved?" and being told yes for a revoked plan is worse
    than having no lookup at all, because a consumer with no lookup goes and
    asks a person.

    ## What it cannot reach

    A rollout already dispatched. Revoking an approval does not un-deploy
    anything and this function does not pretend otherwise — it moves the
    authorization, and converging the fleet back is a new plan and a new
    decision. Saying so here rather than leaving a reader to assume the
    stronger thing.
    """

    effective_at = _control_now()

    def handler(session: Session) -> Mapping[str, object]:
        _target, row = _load_plan_with_target_for_update(session, command.plan_id)
        _require_expected(
            f"plan {row.id}",
            status=row.status,
            version=row.record_version,
            expected_status=PlanStatus.APPROVED.value,
            expected_version=command.expected_version,
        )
        if row.approval_decision_status == ApprovalDecisionStatus.REVOKED.value:
            raise TransitionRefusedError(
                f"plan {row.id}'s approval was already revoked at "
                f"{row.approval_revoked_at} under "
                f"{row.approval_revocation_ref!r}. Recording a second "
                "revocation would overwrite which decision withdrew the "
                "authorization, and that first one is the one an incident "
                "review needs."
            )
        if not command.revocation_ref:
            raise ApprovalRefusedError(
                f"revoking plan {row.id}'s approval requires the reference of "
                "the decision that withdrew it. An authorization that "
                "disappears with no decision behind it is indistinguishable "
                "from a defect afterwards."
            )
        row.approval_decision_status = ApprovalDecisionStatus.REVOKED.value
        row.approval_revoked_at = effective_at
        row.approval_revocation_ref = command.revocation_ref
        row.approval_revocation_reason = command.reason
        row.record_version += 1
        session.flush()
        _audit_and_emit(
            session,
            action=AUDIT_ACTION_ROLLOUT,
            event_type=facts.PLAN_APPROVAL_REVOKED_V1,
            entity_type=_ENTITY_PLAN,
            entity_id=str(row.id),
            actor_ref=command.actor_ref,
            details={
                "plan_digest": row.plan_digest,
                # BOTH decisions. The one that granted and the one that
                # withdrew, because an incident review reading this event needs
                # to reach either, and a detail carrying only the second makes
                # the first a second query nobody makes.
                "decision_ref": row.approval_decision_ref,
                "revocation_ref": row.approval_revocation_ref,
                "reason": row.approval_revocation_reason,
                "revoked_at": row.approval_revoked_at.isoformat(),
            },
        )
        return {"id": str(row.id)}

    process_once_platform(
        db,
        command_id=command.command_id,
        command_type=SCOPE_REVOKE_PLAN_APPROVAL,
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


def request_rollout(
    db: Session,
    command: RequestRolloutCommand,
    *,
    signer: AuthorizationSigner | None = None,
) -> facts.RolloutView:
    """Decide to converge a target on a plan. No transport happens here."""

    issued_at = _control_now()

    def handler(session: Session) -> Mapping[str, object]:
        existing = session.execute(
            select(Rollout).where(Rollout.rollout_ref == command.rollout_ref)
        ).scalar_one_or_none()
        if existing is not None:
            return {"id": str(existing.id)}
        plan_target_id = session.execute(
            select(DeploymentPlan.target_id).where(DeploymentPlan.id == command.plan_id)
        ).scalar_one_or_none()
        if plan_target_id is None:
            raise TransitionRefusedError(f"deployment plan {command.plan_id} not found")
        target = _load_target_for_update(session, plan_target_id)
        plan = _load_plan_for_update(session, command.plan_id)
        if plan.requires_approval and plan.status != PlanStatus.APPROVED.value:
            raise ApprovalRefusedError(
                f"plan {plan.id} is {plan.status!r} and requires approval; a "
                "rollout of an unapproved sensitive plan is the one thing the "
                "approval gate exists to prevent"
            )
        # A SECOND GATE, and it is not redundant with the one above. `status`
        # says the plan WAS approved and keeps saying so after the decision is
        # withdrawn — deliberately, because that is history. So the standing is
        # checked separately, and a plan whose approval no longer stands is
        # refused a rollout even though it still reads `approved`.
        if plan.approval_decision_status == ApprovalDecisionStatus.REVOKED.value:
            raise ApprovalRefusedError(
                f"plan {plan.id} reads {plan.status!r}, and the decision that "
                f"approved it was revoked at {plan.approval_revoked_at} under "
                f"{plan.approval_revocation_ref!r}. The status records that it "
                "was approved once; it is not an authorization now. Roll out a "
                "plan with a standing approval."
            )
        if not plan.requires_approval and plan.status not in {
            PlanStatus.PROPOSED.value,
            PlanStatus.APPROVED.value,
        }:
            raise TransitionRefusedError(
                f"plan {plan.id} is {plan.status!r} and cannot be rolled out"
            )
        # NOTHING UNBOUND REACHES THE FLEET. A plan carrying no execution plan
        # digest or no operation cannot produce a receipt: the executor
        # recomputes the plan digest before running and carries it back, and a
        # report Control cannot bind to an authorization is quarantined rather
        # than accepted. Dispatching such a plan would put an execution into
        # somebody's running system that this control plane could never
        # acknowledge — the rollout would time out and read as a transport
        # fault. This is where `0.1.0a7` plans stop.
        if not plan.execution_plan_digest or not plan.operation:
            raise ExecutionPlanBindingError(
                f"plan {plan.id} carries no execution plan binding (operation="
                f"{plan.operation!r}); it cannot be rolled out. An execution "
                "nothing authorized cannot return a receipt this control plane "
                "will accept, so it is refused here rather than dispatched and "
                "left to time out. Propose a plan bound to the execution plan "
                "the Deployment Foundation rendered."
            )
        descriptor = _frozen_descriptor_digest(plan)
        if descriptor is None:
            raise DescriptorBindingError(
                f"plan {plan.id} carries no descriptor binding. It predates "
                "0.1.0a9 and cannot produce a portable authorization; propose "
                "a new plan with the Foundation descriptor digest."
            )
        images = _frozen_image_set(plan)
        if images is None:
            raise ImageSetRefusedError(
                f"plan {plan.id} carries no authorized image set and cannot "
                "produce a portable authorization"
            )
        if signer is None:
            raise AuthorizationEnvelopeRefusedError(
                AuthorizationEnvelopeRefusalCode.ABSENT,
                "request_rollout requires an injected AuthorizationSigner; "
                "a live database row is not a portable signed authorization",
            )
        if target.status != TargetStatus.ACTIVE.value:
            raise TransitionRefusedError(
                f"target {target.target_ref} is {target.status!r}; a suspended or "
                "decommissioned target is deliberately excluded from rollouts"
            )
        previous_execution_sequence = session.execute(
            select(func.max(Rollout.execution_sequence)).where(
                Rollout.target_id == target.id
            )
        ).scalar_one()
        execution_sequence = int(previous_execution_sequence or 0) + 1
        row = Rollout(
            id=uuid4(),
            rollout_ref=command.rollout_ref,
            target_id=target.id,
            plan_id=plan.id,
            status=RolloutStatus.REQUESTED.value,
            reason=command.reason,
            record_version=1,
            execution_sequence=execution_sequence,
        )
        operation = plan.authorized_operation or plan.operation
        # THE FENCE, at signing. A signature is the point past which this
        # control plane's word travels on its own, so an operation no executor
        # can honour must not acquire one.
        require_executable_operation(
            operation, where=f"authorization for plan {plan.id}"
        )
        execution = plan.authorized_execution_plan_digest or plan.execution_plan_digest
        decision_status = (
            plan.approval_decision_status
            if plan.requires_approval
            else "approval_exempt"
        )
        envelope = issue_authorization_envelope(
            {
                "authorization_id": str(row.id),
                "execution_sequence": execution_sequence,
                "rollout_ref": row.rollout_ref,
                "plan_id": str(plan.id),
                "target_id": str(target.id),
                "target_ref": target.target_ref,
                "product_code": target.product_code,
                "environment": target.environment,
                "operation": operation,
                "release_ref": str((plan.snapshot or {}).get("release_ref") or ""),
                "authorized_images": image_set_payload(images),
                "plan_digest": _frozen_plan_digest(plan).canonical,
                "descriptor_digest": descriptor.canonical,
                "execution_plan_digest": execution,
                "approval_policy_code": plan.approval_policy_code,
                "approval_policy_version": plan.approval_policy_version,
                "approval_decision_ref": plan.approval_decision_ref,
                "approval_decision_status": decision_status,
                "approved_at": (
                    None if plan.approved_at is None else _as_utc(plan.approved_at)
                ),
                "issued_at": issued_at,
                "expires_at": command.authorization_expires_at,
            },
            signer=signer,
        )
        row.authorization_envelope = envelope.as_mapping()
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
                "descriptor_digest": descriptor.canonical,
                "operation": plan.operation,
                "execution_plan_digest": plan.execution_plan_digest,
                "authorization_key_id": envelope.statement.key_id,
                "authorization_algorithm": envelope.statement.algorithm,
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
    actor_ref: str | None = None,
    verifier: AuthorizationVerifier | None = None,
    dispatch_signer: DispatchSigner,
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

    dispatched_at = _control_now()

    def handler(session: Session) -> Mapping[str, object]:
        locator = session.execute(
            select(Rollout.target_id, Rollout.plan_id).where(Rollout.id == rollout_id)
        ).one_or_none()
        if locator is None:
            raise TransitionRefusedError(f"rollout {rollout_id} not found")
        target = _load_target_for_update(session, locator.target_id)
        plan = _load_plan_for_update(session, locator.plan_id)
        rollout = session.execute(
            select(Rollout)
            .where(Rollout.id == rollout_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        if rollout.status in TERMINAL_ROLLOUT_STATUSES:
            raise TransitionRefusedError(
                f"rollout {rollout.rollout_ref} is {rollout.status!r}; a settled "
                "rollout is not retried, a new one is requested"
            )
        if plan.approval_decision_status == ApprovalDecisionStatus.REVOKED.value:
            raise ApprovalRefusedError(
                f"plan {plan.id}'s approval was revoked after authorization. "
                "The rollout and signed envelope remain immutable history, but "
                "dispatch is no longer permitted."
            )
        authorization = _verified_rollout_envelope(
            rollout, plan, target, verifier=verifier, at=dispatched_at
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
        attempt_id = uuid4()
        # THE FENCE, at dispatch. The last of the three points the vocabulary
        # docstring names. An authorization frozen and signed before this
        # release could still carry an operation the executor never gained, so
        # the check is repeated here rather than assumed discharged upstream.
        require_executable_operation(
            authorization.statement.operation,
            where=f"dispatch of rollout {rollout.id}",
        )
        dispatch_envelope = issue_dispatch_envelope(
            authorization_envelope=authorization,
            dispatch_id=str(attempt_id),
            attempt_no=attempt_no,
            issued_at=dispatched_at,
            signer=dispatch_signer,
        )
        attempt = RolloutAttempt(
            id=attempt_id,
            rollout_id=rollout.id,
            attempt_no=attempt_no,
            outcome=AttemptOutcome.PENDING.value,
            dispatched_at=dispatched_at,
            dispatch_envelope=dispatch_envelope.as_mapping(),
        )
        session.add(attempt)
        if rollout.status == RolloutStatus.REQUESTED.value:
            rollout.status = RolloutStatus.DISPATCHED.value
            rollout.record_version += 1
        session.flush()

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
                "operation": plan.operation,
                "execution_plan_digest": plan.execution_plan_digest,
                "release_ref": (plan.snapshot or {}).get("release_ref"),
                "dispatch_envelope_digest": DispatchEnvelopeDigestV1.over_bytes(
                    dispatch_envelope.canonical_bytes
                ).canonical,
                "dispatch_key_id": dispatch_envelope.statement.key_id,
            },
        )
        return {"attempt_id": str(attempt_id)}

    outcome = process_once_platform(
        db, command_id=command_id, command_type=SCOPE_DISPATCH, handler=handler
    )
    rollout = _load_rollout(db, rollout_id)
    result_keys = set(outcome.result)
    if result_keys == {"attempt_no"}:
        legacy_attempt_no = outcome.result["attempt_no"]
        if (
            not isinstance(legacy_attempt_no, int)
            or isinstance(legacy_attempt_no, bool)
            or legacy_attempt_no < 1
        ):
            raise TransitionRefusedError(
                "the pre-a11 dispatch idempotency record carries an invalid "
                "attempt number"
            )
        legacy_attempt = db.execute(
            select(RolloutAttempt).where(
                RolloutAttempt.rollout_id == rollout.id,
                RolloutAttempt.attempt_no == legacy_attempt_no,
            )
        ).scalar_one_or_none()
        if legacy_attempt is None:
            raise TransitionRefusedError(
                "the pre-a11 dispatch idempotency record names no attempt in "
                "this rollout"
            )
        raise TransitionRefusedError(
            "the dispatch attempt predates the signed dispatch contract and cannot "
            "be returned as executable intent"
        )
    if result_keys != {"attempt_id"}:
        raise TransitionRefusedError(
            "the dispatch idempotency result has an unsupported shape; expected "
            "exactly attempt_id, or the pre-a11 attempt_no shape"
        )
    try:
        attempt_id = UUID(str(outcome.result["attempt_id"]))
    except (AttributeError, TypeError, ValueError) as exc:
        raise TransitionRefusedError(
            "the dispatch idempotency result carries an invalid attempt_id"
        ) from exc
    plan = _load_plan(db, rollout.plan_id)
    target = _load_target(db, rollout.target_id)
    attempt = db.get(RolloutAttempt, attempt_id)
    if attempt is None or attempt.rollout_id != rollout.id:
        raise TransitionRefusedError(
            "the idempotency record names a dispatch attempt outside this rollout"
        )
    if attempt.dispatch_envelope is None:
        raise TransitionRefusedError(
            "the dispatch attempt predates the signed dispatch contract and cannot "
            "be returned as executable intent"
        )
    dispatch_envelope = DispatchEnvelopeV1.parse(attempt.dispatch_envelope)
    snapshot = plan.snapshot or {}
    envelope = _verified_rollout_envelope(
        rollout,
        plan,
        target,
        verifier=verifier,
        at=(
            _as_utc(attempt.dispatched_at)
            if attempt.dispatched_at is not None
            else None
        ),
    )
    descriptor = _frozen_descriptor_digest(plan)
    assert descriptor is not None
    return DeliveryIntent(
        rollout_ref=rollout.rollout_ref,
        target_ref=target.target_ref,
        release_ref=str(snapshot.get("release_ref") or ""),
        plan_digest=plan.plan_digest or "",
        descriptor_digest=descriptor.canonical,
        # Echoed, never re-derived. These are the values `request_rollout`
        # already refused to dispatch without, so they are present here by that
        # gate rather than by a fallback — the `or ""` is for the type checker's
        # `str | None`, not a state this line can actually be reached in.
        operation=plan.authorized_operation or plan.operation or "",
        execution_plan_digest=(
            plan.authorized_execution_plan_digest or plan.execution_plan_digest or ""
        ),
        authorization_envelope=envelope,
        dispatch_envelope=dispatch_envelope,
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
                f"rollout {rollout.rollout_ref} has no attempt {command.attempt_no}"
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
    db: Session,
    command: RecordObservationCommand,
    *,
    observation_verifier: ExecutionObservationVerifier | None = None,
    authorization_verifier: AuthorizationVerifier | None = None,
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

    **A byte-identical replay returns the ORIGINAL verdict verbatim.** Recomputing
    could yield a different answer against changed target state for bytes the
    deployment sent once, which would make an at-least-once transport look like a
    state change. Reusing the report id with different signed bytes is a conflict.

    **A report is accepted only when proposal, authorization and report bind the
    same execution plan and the same operation.** Step 8 of the flow, and the
    reason this module holds an execution plan digest at all. Three separate
    quarantines — `execution_plan_mismatch`, `operation_mismatch`,
    `unbound_report` — because they are three findings with three readers; see
    `_execution_binding_disposition`.
    """
    wire = command.observation
    received_at = _control_now()

    # THE DIGEST IS DERIVED HERE, inside Control, over the FULL body exactly as
    # received and BEFORE any truncation — so two truncated attempts remain
    # distinguishable, and no caller-supplied digest exists to disagree with
    # the bytes it allegedly describes.
    raw_body_digest = ObservationEnvelopeDigestV1.over_bytes(wire).canonical
    raw_body_truncated = len(wire) > MAX_EXECUTION_OBSERVATION_ENVELOPE_BYTES
    stored_body = (
        wire[:MAX_EXECUTION_OBSERVATION_ENVELOPE_BYTES] if raw_body_truncated else wire
    )

    parsed_observation: ExecutionObservationEnvelopeV1 | None = None
    try:
        # `parse_bytes`, never `parse`: the thing parsed is the thing stored,
        # byte for byte. An oversize body is refused here (and recorded as a
        # truncated MALFORMED attempt below); ambiguous JSON — duplicate keys,
        # non-JSON numbers — is refused rather than resolved, because a
        # verifier and an operator must never read two values out of one wire
        # document.
        parsed_observation = ExecutionObservationEnvelopeV1.parse_bytes(wire)
    except ExecutionObservationRefusedError:
        # The exact inbound bytes still become an attempt below. Parsing before
        # the handler is only a bounded syntax operation; trust begins after
        # Control selects the enrolled verification identity inside it.
        pass

    def handler(session: Session) -> Mapping[str, object]:
        attempt = ObservationAttempt(
            received_at=received_at,
            raw_body=stored_body,
            raw_body_truncated=raw_body_truncated,
            raw_body_digest=raw_body_digest,
            signature_status=SignatureStatus.UNRESOLVED.value,
            eligibility_at_receipt=EligibilityAtReceipt.NOT_APPLICABLE.value,
            # Identity fields are EVIDENCE parsed out of the bytes above, and
            # nothing else: an arrival that never parsed has no claim to record,
            # rather than a caller-typed one that could disagree with the body.
            key_id=None,
            claimed_target_ref=None,
            report_id=None,
            disposition=ObservationDisposition.MALFORMED.value,
        )

        if parsed_observation is None:
            attempt.disposition = ObservationDisposition.MALFORMED.value
            session.add(attempt)
            session.flush()
            return _observation_result(session, attempt, command, changed=False)

        statement = parsed_observation.statement
        attempt.key_id = statement.key_id
        attempt.claimed_target_ref = statement.target_ref
        attempt.report_id = statement.report_id

        # Locate without trusting or locking the key, then take the global
        # consequence lock order: target -> credential -> plan. Re-read each
        # locked row with populate_existing so a preloaded identity-map value
        # cannot overwrite a concurrent record_version.
        credential_target_id = session.execute(
            select(TargetCredential.target_id).where(
                TargetCredential.key_id == statement.key_id
            )
        ).scalar_one_or_none()
        if credential_target_id is None:
            attempt.disposition = ObservationDisposition.UNKNOWN_KEY.value
            session.add(attempt)
            session.flush()
            return _observation_result(
                session, attempt, command, changed=False, statement=statement
            )
        target = _load_target_for_update(session, credential_target_id)
        credential = session.execute(
            select(TargetCredential)
            .where(TargetCredential.key_id == statement.key_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if credential is None:
            attempt.disposition = ObservationDisposition.UNKNOWN_KEY.value
            session.add(attempt)
            session.flush()
            return _observation_result(
                session, attempt, command, changed=False, statement=statement
            )
        if observation_verifier is None:
            attempt.signature_status = SignatureStatus.INVALID.value
            attempt.disposition = ObservationDisposition.BAD_SIGNATURE.value
            session.add(attempt)
            session.flush()
            return _observation_result(
                session, attempt, command, changed=False, statement=statement
            )
        try:
            verification_key = ExecutionObservationVerificationKey(
                key_id=credential.key_id,
                algorithm=credential.algorithm or "",
                purpose=credential.purpose or "",
                public_key_b64=credential.public_key_b64,
                public_key_fingerprint=credential.public_key_fingerprint,
            )
            verified_observation = verify_execution_observation_envelope(
                parsed_observation,
                verifier=observation_verifier,
                verification_key=verification_key,
            )
        except ExecutionObservationRefusedError:
            attempt.signature_status = SignatureStatus.INVALID.value
            attempt.disposition = ObservationDisposition.BAD_SIGNATURE.value
            session.add(attempt)
            session.flush()
            return _observation_result(
                session, attempt, command, changed=False, statement=statement
            )
        attempt.signature_status = SignatureStatus.VALID.value

        # There is deliberately NO projection comparison here. The earlier
        # shape checked a caller-supplied ObservedState field by field against
        # the signed statement — a comparison that only existed because there
        # were two inputs able to disagree. With one bytes input the statement
        # IS the report, so a `signed_report_mismatch` is not a rare outcome,
        # it is an unrepresentable one, and the disposition member is gone with
        # the input that could have produced it.

        # This is the PROVEN identity. The caller's similarly named field is
        # compared below and never assigned here.
        attempt.authenticated_target_ref = target.target_ref
        eligible = _credential_row_is_eligible(credential, at=received_at)
        attempt.eligibility_at_receipt = (
            EligibilityAtReceipt.ELIGIBLE.value
            if eligible
            else EligibilityAtReceipt.NOT_ELIGIBLE.value
        )

        # A canonical receipt is historical evidence about an arrival that was
        # eligible when Control first saw it.  A later key revocation cannot
        # make those exact bytes stop being a replay, or make different bytes
        # under the same report id stop being a conflict.  Signature and exact
        # caller projection are still re-verified above with the enrolled
        # public identity; only the MOVING eligibility decision is deliberately
        # below this immutable receipt boundary.
        receipt = session.execute(
            select(ObservationReceipt).where(
                ObservationReceipt.authenticated_target_ref == target.target_ref,
                ObservationReceipt.report_id == statement.report_id,
            )
        ).scalar_one_or_none()
        if receipt is not None:
            return _replay_observation(
                session,
                attempt,
                command,
                receipt,
                statement=statement,
                canonical_payload=verified_observation.canonical_bytes,
            )

        if not eligible:
            attempt.disposition = ObservationDisposition.NOT_ELIGIBLE.value
            session.add(attempt)
            session.flush()
            return _observation_result(
                session, attempt, command, changed=False, statement=statement
            )

        # From here the envelope is verified, exactly projected, eligible and
        # attributable. Its first verdict is therefore canonical even when it
        # is a quarantine rather than an acceptance.
        disposition, coordinate, desired_revision = _execution_observation_disposition(
            session,
            target,
            verified_observation,
            authorization_verifier=authorization_verifier,
            received_at=received_at,
        )
        # ADR-0007's claim/proof split survives with one claimant fewer: the
        # SIGNED statement's own target_ref is the claim, the credential-locked
        # target is the proof, and there is no longer a third, caller-typed
        # account that could contradict both.
        if statement.target_ref != target.target_ref:
            disposition = ObservationDisposition.TARGET_MISMATCH.value

        changed = False
        state_digest = statement.substantive_state_digest.canonical
        advances_high_water = disposition in {
            ObservationDisposition.ACCEPTED.value,
            ObservationDisposition.EXECUTION_FAILED.value,
        }
        if advances_high_water and coordinate is not None:
            current_coordinate = (
                (
                    target.last_execution_sequence,
                    target.last_execution_attempt_no,
                )
                if target.last_execution_sequence is not None
                and target.last_execution_attempt_no is not None
                else None
            )
            if current_coordinate is not None and coordinate < current_coordinate:
                disposition = ObservationDisposition.STALE_OBSERVATION.value
                advances_high_water = False
            elif current_coordinate == coordinate:
                if target.last_execution_state_digest != state_digest:
                    disposition = (
                        ObservationDisposition.EXECUTION_COORDINATE_CONFLICT.value
                    )
                advances_high_water = False

        if advances_high_water and coordinate is not None:
            target.last_execution_sequence = coordinate[0]
            target.last_execution_attempt_no = coordinate[1]
            target.last_execution_state_digest = state_digest
            changed = True
            if disposition == ObservationDisposition.ACCEPTED.value:
                target.observed_release_ref = statement.observed_release_ref
                target.observed_spec_digest = statement.observed_spec_digest
                target.last_observed_at = received_at
                # The signed authorization names one immutable plan.  Its
                # desired revision is the only revision this execution can
                # prove. Re-resolving by spec digest here would select the
                # newest plan with matching content and could project an older
                # authorized execution as a newer plan that never ran.
                target.observed_revision = desired_revision
            target.record_version += 1

        canonical_payload = verified_observation.canonical_bytes
        receipt = ObservationReceipt(
            authenticated_target_ref=target.target_ref,
            report_id=statement.report_id,
            payload=canonical_payload,
            payload_digest=ObservationEnvelopeDigestV1.over_bytes(
                canonical_payload
            ).canonical,
            key_id=statement.key_id,
            first_received_at=received_at,
            original_verdict=disposition,
            observed_release_ref=statement.observed_release_ref,
            observed_spec_digest=statement.observed_spec_digest,
            execution_sequence=(coordinate[0] if coordinate is not None else None),
            attempt_no=(coordinate[1] if coordinate is not None else None),
            observed_state_digest=(state_digest if coordinate is not None else None),
        )
        session.add(receipt)
        session.flush()

        attempt.disposition = disposition
        attempt.receipt_id = receipt.id
        session.add(attempt)

        session.flush()

        return _observation_result(
            session,
            attempt,
            command,
            changed=changed,
            statement=statement,
            verdict=disposition,
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


def _execution_observation_disposition(
    session: Session,
    target: DeploymentTarget,
    observation: ExecutionObservationEnvelopeV1,
    *,
    authorization_verifier: AuthorizationVerifier | None,
    received_at: datetime,
) -> tuple[str, tuple[int, int] | None, int | None]:
    """Decide one verified attributable observation at a trusted instant."""
    statement = observation.statement
    try:
        authorization_id = UUID(statement.authorization_id)
    except ValueError:
        return ObservationDisposition.UNBOUND_REPORT.value, None, None
    rollout = session.get(Rollout, authorization_id)
    if (
        rollout is None
        or rollout.rollout_ref != statement.rollout_ref
        or rollout.target_id != target.id
    ):
        return ObservationDisposition.UNBOUND_REPORT.value, None, None
    if (
        rollout.execution_sequence is None
        or rollout.execution_sequence != statement.execution_sequence
    ):
        return ObservationDisposition.AUTHORIZATION_MISMATCH.value, None, None
    execution_attempt = session.execute(
        select(RolloutAttempt).where(
            RolloutAttempt.rollout_id == rollout.id,
            RolloutAttempt.attempt_no == statement.attempt_no,
        )
    ).scalar_one_or_none()
    if execution_attempt is None:
        return ObservationDisposition.UNBOUND_REPORT.value, None, None
    coordinate = (rollout.execution_sequence, execution_attempt.attempt_no)
    plan = session.execute(
        select(DeploymentPlan)
        .where(DeploymentPlan.id == rollout.plan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if plan is None:
        return ObservationDisposition.UNBOUND_REPORT.value, coordinate, None
    # The authorization names one exact plan. Matching by spec across every
    # plan would let a later, unexecuted revision borrow this execution merely
    # because its spec happened to be equal. Conversely, a target that reports
    # a different spec has not proved ANY desired revision even when the
    # executor itself reports success.
    reported_spec = SpecDigestV1.parse(statement.observed_spec_digest)
    frozen_spec = spec_digest_of((plan.snapshot or {}).get("spec") or {})
    observed_revision = plan.desired_revision if reported_spec == frozen_spec else None
    if plan.approval_decision_status == ApprovalDecisionStatus.REVOKED.value:
        if plan.approval_revoked_at is None:
            return ObservationDisposition.AUTHORIZATION_INVALID.value, coordinate, None
        if _as_utc(received_at) >= _as_utc(plan.approval_revoked_at):
            return (
                ObservationDisposition.AUTHORIZATION_REVOKED.value,
                coordinate,
                observed_revision,
            )
    if authorization_verifier is None:
        return ObservationDisposition.AUTHORIZATION_INVALID.value, coordinate, None
    try:
        authorization = _verified_rollout_envelope(
            rollout,
            plan,
            target,
            verifier=authorization_verifier,
            # Standing is decided at Control's trusted receipt instant. A target
            # cannot revive expired authority by backdating its own clock.
            at=received_at,
        )
    except AuthorizationEnvelopeRefusedError as exc:
        if exc.code is AuthorizationEnvelopeRefusalCode.EXPIRED:
            return (
                ObservationDisposition.AUTHORIZATION_EXPIRED.value,
                coordinate,
                observed_revision,
            )
        return (
            ObservationDisposition.AUTHORIZATION_INVALID.value,
            coordinate,
            observed_revision,
        )

    authorized = authorization.statement
    if authorized.public_key_fingerprint == statement.public_key_fingerprint:
        return (
            ObservationDisposition.SIGNER_PURPOSE_REUSED.value,
            coordinate,
            observed_revision,
        )
    authorization_digest = AuthorizationEnvelopeDigestV1.over_bytes(
        authorization.canonical_bytes
    ).canonical
    expected: dict[str, object] = {
        "authorization_id": authorized.authorization_id,
        "authorization_plan_id": authorized.plan_id,
        "authorization_control_version": authorized.control_version,
        "authorization_envelope_digest": authorization_digest,
        "rollout_ref": authorized.rollout_ref,
        "target_id": authorized.target_id,
        "target_ref": authorized.target_ref,
        "product_code": authorized.product_code,
        "environment": authorized.environment,
        "operation": authorized.operation,
        "release_ref": authorized.release_ref,
        "authorized_images": authorized.authorized_images,
        "plan_digest": authorized.plan_digest,
        "descriptor_digest": authorized.descriptor_digest,
        "execution_plan_digest": authorized.execution_plan_digest,
    }
    for field, wanted in expected.items():
        if getattr(statement, field) != wanted:
            if field == "execution_plan_digest":
                return (
                    ObservationDisposition.EXECUTION_PLAN_MISMATCH.value,
                    coordinate,
                    observed_revision,
                )
            if field == "operation":
                return (
                    ObservationDisposition.OPERATION_MISMATCH.value,
                    coordinate,
                    observed_revision,
                )
            return (
                ObservationDisposition.AUTHORIZATION_MISMATCH.value,
                coordinate,
                observed_revision,
            )
    if statement.observed_release_ref != authorized.release_ref:
        return (
            ObservationDisposition.AUTHORIZATION_MISMATCH.value,
            coordinate,
            observed_revision,
        )
    if statement.observed_images != authorized.authorized_images:
        return (
            ObservationDisposition.AUTHORIZATION_MISMATCH.value,
            coordinate,
            observed_revision,
        )
    if _as_utc(statement.observed_at) > _as_utc(received_at):
        return (
            ObservationDisposition.AUTHORIZATION_MISMATCH.value,
            coordinate,
            observed_revision,
        )
    binding = _execution_binding_disposition(plan, statement)
    if binding is not None:
        return binding, coordinate, observed_revision
    if statement.outcome is ExecutionObservationOutcome.FAILED:
        return (
            ObservationDisposition.EXECUTION_FAILED.value,
            coordinate,
            observed_revision,
        )
    return ObservationDisposition.ACCEPTED.value, coordinate, observed_revision


def _execution_binding_disposition(
    plan: DeploymentPlan, statement: ExecutionObservationStatementV1
) -> str | None:
    """Step 8: accept only when proposal, authorization and report agree.

    Returns the DISPOSITION that quarantines the arrival, or `None` when the
    binding holds. A disposition rather than an exception because rule 3 governs
    here: every arrival is recorded, and a report that binds the wrong execution
    is precisely the evidence an operator needs — raising would discard it.

    ## Three terms, and each mismatch is its own finding

    * **proposal** — `plan.operation` / `plan.execution_plan_digest`, frozen
      when Platform CP submitted what the Foundation had rendered and digested.
    * **authorization** — `plan.authorized_operation` /
      `plan.authorized_execution_plan_digest`, written once at `approve_plan`.
    * **report** — what the executor recomputed before running and carried back.

    An approval-exempt plan has no authorization term, and this says so rather
    than manufacturing one: a copy of the proposal in the authorization's
    columns would make a two-term check read as a three-term one, which is the
    exact weakening `require_same_digest` refuses on the Foundation's side. Such
    a plan is compared on two terms, and its empty `authorized_*` columns —
    carried on `PlanView` and rendered — are what say so, rather than a count
    this function would have to be trusted to report honestly.

    ## Why the digest is compared before the operation

    A wrong digest means a DIFFERENT execution plan ran, and the operation of a
    plan nobody authorized is not a meaningful comparison — reporting
    `operation_mismatch` for it would send an operator to the approvals system
    when the finding is in the executor. So the digest decides first, and the
    operation is decided only among reports that named the right execution.
    """
    #: Nothing to bind against. An ABSENCE, not a contradiction — the sender
    #: never said which authorization it was executing, so no plan was consulted
    #: and none is named in the finding.
    if not plan.execution_plan_digest or not plan.operation:
        return ObservationDisposition.UNBOUND_REPORT.value

    proposed = _stored_execution_plan_digest(
        plan, plan.execution_plan_digest, term="execution plan digest"
    )
    authorized = _stored_execution_plan_digest(
        plan, plan.authorized_execution_plan_digest, term="authorized execution plan"
    )
    try:
        reported = ExecutionPlanDigestV1.parse(statement.execution_plan_digest)
    except DigestEncodingError:
        # NOT raised, and not a mismatch either. An unreadable digest is a
        # finding about the REPORT's encoding; calling it a mismatch would say
        # the executor ran the wrong plan, which nothing here established.
        return ObservationDisposition.UNBOUND_REPORT.value

    # EVERY stored term, not the first one that exists. If the proposal and the
    # authorization ever disagreed — nothing in this module can write that, but
    # a database edit can — a report matching whichever one it happened to match
    # would be accepted on a coin toss. Comparing against all of them means a
    # binding whose own terms disagree can satisfy nothing, which is the correct
    # answer to a data fault and needs no branch of its own.
    digests = [term for term in (proposed, authorized) if term is not None]
    if any(reported != term for term in digests):
        return ObservationDisposition.EXECUTION_PLAN_MISMATCH.value

    try:
        reported_operation = require_operation(
            statement.operation, where="observation operation"
        )
    except OperationRefusedError:
        # A word outside the closed vocabulary. Never coerced, and never read as
        # the operation the plan happens to name.
        return ObservationDisposition.OPERATION_MISMATCH.value
    operations = [
        require_operation(value, where=f"plan {plan.id}")
        for value in (plan.operation, plan.authorized_operation)
        if value is not None
    ]
    if any(reported_operation is not term for term in operations):
        return ObservationDisposition.OPERATION_MISMATCH.value
    return None


def _replay_observation(
    session: Session,
    attempt: ObservationAttempt,
    command: RecordObservationCommand,
    receipt: ObservationReceipt,
    *,
    statement: ExecutionObservationStatementV1,
    canonical_payload: bytes,
) -> Mapping[str, object]:
    """Retain a replay and preserve the first verdict as immutable history."""
    # The digest is a coordinate for operators; equality is over the exact
    # signed bytes. A corrupted/replaced digest column cannot make different
    # evidence idempotent.
    same_bytes = receipt.payload == canonical_payload
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
        statement=statement,
        verdict=receipt.original_verdict,
    )


def _observation_result(
    session: Session,
    attempt: ObservationAttempt,
    command: RecordObservationCommand,
    *,
    changed: bool,
    statement: ExecutionObservationStatementV1 | None = None,
    verdict: str | None = None,
    target: DeploymentTarget | None = None,
) -> Mapping[str, object]:
    """Audit, emit, and shape the handler's return value.

    One helper for every path so that no disposition can be reached without an
    audit record — a `return` added later inside a branch would otherwise be a
    silently unaudited outcome.
    """
    details: dict[str, Any] = {
        "report_id": attempt.report_id,
        "disposition": attempt.disposition,
        "signature_status": attempt.signature_status,
        "eligibility": attempt.eligibility_at_receipt,
        "authenticated_target_ref": attempt.authenticated_target_ref,
        "claimed_target_ref": attempt.claimed_target_ref,
        "key_id": attempt.key_id,
        "changed_state": changed,
        # The report's OWN account of what it executed, read out of the parsed
        # bytes and nowhere else. Evidence, never authority — the same rule
        # `claimed_target_ref` is held to — and recorded on every path that
        # parsed, so a quarantined arrival can be triaged without reaching for
        # the signed body. None on the one path that could not parse, because
        # an unreadable body HAS no account to record.
        "reported_rollout_ref": (
            statement.rollout_ref if statement is not None else None
        ),
        "reported_operation": (statement.operation if statement is not None else None),
        "reported_execution_plan_digest": (
            statement.execution_plan_digest if statement is not None else None
        ),
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


def list_targets(
    db: Session, filter: facts.TargetFilter | None = None
) -> facts.TargetPage:
    """One page of targets matching a typed filter.

    The list contract the fleet screen needs, and the reason it lives here: a
    consuming assembly must never build this query itself. Platform CP owns the
    operator workflow and this module owns its tables; the moment a consumer
    writes `select(DeploymentTarget)` it has taken a second read authority over
    a schema it does not own, and every future column rename becomes a
    cross-repository break.

    Ordering is by `target_ref`, not by insertion or by `id`. A pager over an
    unstable order shows a row twice and skips another when the fleet changes
    under it, which reads as data loss rather than as a sorting bug.
    """
    criteria = filter if filter is not None else facts.TargetFilter()
    conditions = []
    if criteria.product_code is not None:
        conditions.append(DeploymentTarget.product_code == criteria.product_code)
    if criteria.environment is not None:
        conditions.append(DeploymentTarget.environment == criteria.environment)
    if criteria.status is not None:
        conditions.append(DeploymentTarget.status == criteria.status)
    if criteria.never_observed is True:
        conditions.append(DeploymentTarget.last_observed_at.is_(None))
    elif criteria.never_observed is False:
        conditions.append(DeploymentTarget.last_observed_at.is_not(None))

    total = db.execute(
        select(func.count()).select_from(DeploymentTarget).where(*conditions)
    ).scalar_one()
    # ONE statement for the page AND its standing. A per-row lookup here would
    # be the N+1 this projection exists to remove, relocated into the ORM --
    # correct in value and wrong in shape, and invisible to any test that only
    # checks the value.
    rows = db.execute(
        select(DeploymentTarget, _approval_standing_subquery())
        .where(*conditions)
        .order_by(DeploymentTarget.target_ref)
        .offset((criteria.page - 1) * criteria.page_size)
        .limit(criteria.page_size)
    ).all()
    return facts.TargetPage(
        targets=tuple(
            _target_view(row, approval_standing=str(standing)) for row, standing in rows
        ),
        total=int(total),
        page=criteria.page,
        page_size=criteria.page_size,
    )


def _latest_recovery_grant_row(db: Session, target_id: UUID) -> RecoveryGrant | None:
    """The target's most recent recovery grant ROW, or none.

    One statement of "which grant is current", so the parsed reader and the
    standing check cannot end up looking at different grants for one target.
    """
    return db.execute(
        select(RecoveryGrant)
        .where(RecoveryGrant.target_id == target_id)
        .order_by(RecoveryGrant.issued_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def grant_for_target(db: Session, target_id: UUID) -> RecoveryGrantV1 | None:
    """R6. The target's most recent recovery grant, PARSED.

    Returns the type, never the stored mapping: a caller holding a raw envelope
    would be one restringification away from verifying a restatement instead of
    the document. `None` means no grant has ever been recorded for this target,
    which is a different fact from one that exists and does not authorize.
    """
    row = _latest_recovery_grant_row(db, target_id)
    return None if row is None else RecoveryGrantV1.parse(row.grant_envelope)


def revoked_grant_ids_for_target(db: Session, target_id: UUID) -> frozenset[str]:
    """R6. Which of this target's grants have been withdrawn.

    Derived from THIS module's own rows and never taken as a caller argument.
    A revocation set supplied by a consumer would let the consumer decide
    whether a withdrawal counted, which is the decision the `revoked_at` column
    exists to own.
    """
    rows = db.execute(
        select(RecoveryGrant.grant_id).where(
            RecoveryGrant.target_id == target_id,
            RecoveryGrant.revoked_at.is_not(None),
        )
    ).scalars()
    return frozenset(str(value) for value in rows)


def recovery_standing_for_target(
    db: Session,
    target_id: UUID,
    *,
    verifier: RecoveryGrantVerifier,
    subject: RecoverySubject,
) -> RecoveryStandingResult:
    """R6. May THIS recovery run against this target, and if not, why not.

    The session-taking read a surface needs, so no consumer assembles the answer
    from parts. It reads only `recovery_grants`: a deployment authorization
    cannot appear here even indirectly, which is why an expired deployment
    authorization with no recovery grant reads ABSENT and never EXPIRED.
    EXPIRED would say a recovery grant existed and timed out.

    `subject` is the CALLER's. There is deliberately no builder for it: the
    bundle and prestate digests are the Foundation's values and Control must not
    invent them -- a subject this module assembled would be Control deciding
    what is being recovered.

    The verdict is `recovery_standing`'s, returned unchanged. One decision, one
    owner; this function supplies the stored document and the revocation set and
    decides nothing itself.

    It reads the row rather than reusing `grant_for_target`, deliberately: that
    reader PARSES, and a stored envelope that no longer parses would raise here
    instead of reading UNRESOLVED. A surface that crashes on a malformed grant
    has lost the ability to say the grant is malformed.

    `at` is this module's clock, not the default `datetime.now`. Two clocks in
    one module means the standing a surface displays and the standing a writer
    records can disagree about the same instant.
    """
    row = _latest_recovery_grant_row(db, target_id)
    return recovery_standing(
        None if row is None else row.grant_envelope,
        verifier=verifier,
        subject=subject,
        at=_control_now(),
        revoked_grant_ids=revoked_grant_ids_for_target(db, target_id),
    )


def preview_plan_proposal(
    db: Session, target_id: UUID
) -> facts.PlanProposalPreview | None:
    """What proposing a plan for this target would freeze — derived, never taken.

    A read. It computes the canonical snapshot and its digest exactly as
    `propose_plan` does, so an operator can see what they are about to approve
    before they commit to it.

    There is deliberately no way to pass a digest in. `ProposePlanCommand` has
    no digest field and this function takes only a target id, so neither the
    write path nor the read path can accept one from a client. The digest a plan
    carries is always the one this module derived from state it owns.
    """
    target = db.get(DeploymentTarget, target_id)
    if target is None:
        return None

    snapshot = plan_snapshot(target)
    derived = plan_digest_of(snapshot)

    current = db.execute(
        select(DeploymentPlan)
        .where(
            DeploymentPlan.target_id == target_id,
            DeploymentPlan.status == PlanStatus.APPROVED.value,
        )
        .order_by(DeploymentPlan.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()

    blockers = _plan_blockers(target)
    return facts.PlanProposalPreview(
        target_id=target.id,
        target_ref=target.target_ref,
        desired_revision=target.desired_revision,
        canonical_plan=snapshot,
        plan_digest=derived.canonical,
        # The bytes the digest is over, from the one function that produces
        # them, so the preview cannot describe a different serialization than
        # the one `PlanDigestV1.over_json` hashed a line earlier.
        canonical_plan_json=canonical_json(snapshot).decode("utf-8"),
        would_supersede_plan_id=current.id if current is not None else None,
        blocking_reasons=blockers,
        can_propose=not blockers,
        # Typed values, never the stored TEXT. Comparing digest strings is the
        # a4 defect exactly, and `_frozen_plan_digest` is the helper that reads
        # a stored digest — including a4's bare-hex form — as a value.
        digest_matches_current=(
            current is None or _frozen_plan_digest(current) == derived
        ),
    )


# ── The approved-plan lookup: READ-ONLY, and it refuses rather than guesses ──
#
# The gap this closes was measured by the Observability lane, not supposed:
# there was no read API for an approved plan here. No fetch-by-digest, no
# verify-approved — only the WRITE path, which compares an expected digest
# while an approval is being recorded. A promotion in another system was
# therefore HANDED an authorization and could not confirm one, so its receipt
# compared what ran against terms its own caller had supplied. That proves a
# caller consistent with itself, which is not a verification.


def _lookup_refusal(
    code: facts.ApprovedPlanRefusalCode,
    detail: str,
    *,
    plan: DeploymentPlan | None = None,
) -> facts.ApprovedPlanLookup:
    """One place that builds a refusal, so every one carries the same terms."""
    return facts.ApprovedPlanLookup(
        refusal=facts.ApprovedPlanRefusal(
            code=code,
            detail=detail,
            plan_id=None if plan is None else plan.id,
            plan_status=None if plan is None else plan.status,
        )
    )


def find_approved_plan(
    db: Session,
    *,
    plan_digest: str,
    authorization_id: UUID | str | None = None,
    expected_descriptor_digest: str | None = None,
    expected_execution_plan_digest: str | None = None,
    verifier: AuthorizationVerifier | None = None,
    at: datetime | None = None,
) -> facts.ApprovedPlanLookup:
    """Resolve a plan digest to a STANDING authorization, or to a typed refusal.

    A READ. It opens no transaction of its own, writes nothing, and derives
    nothing: every term it returns was frozen at proposal or written at
    approval. In particular it does NOT reconstruct or re-hash anything —
    `execution_plan_digest` is handed back exactly as the Deployment Foundation
    issued it and Control froze it, because Control is structurally unable to
    recompute that value and this function does not become the place it starts
    trying.

    ## Total, and never ambiguous

    Every path returns an `ApprovedPlanLookup` carrying EXACTLY one of an
    authorization or a typed refusal — never an empty answer, and never a bare
    `None` that a caller could read as either "not approved" or "nothing came
    back". The result is falsy for every refusal (see
    `ApprovedPlanLookup.__bool__`), so `if find_approved_plan(...)` cannot pass
    on a no.

    ## Revocation is answered HERE

    A consumer asking "is this plan approved?" gets `APPROVAL_REVOKED` for a
    plan whose decision was withdrawn — from this one call, not from a second
    query it has to remember to make. That is the whole reason revocation is
    reachable from the lookup: a consumer that gets a yes for a revoked plan is
    worse off than one with no API, because the one with no API asks a person.

    ## `expected_execution_plan_digest` is optional and is compared as a VALUE

    Supply it and the lookup confirms the authorization binds that exact
    Foundation execution; omit it and no such claim is made. The comparison is
    between two `ExecutionPlanDigestV1` values, never between two strings —
    see `digests` for what a string comparison of these costs.

    Raises `DigestEncodingError` for nothing and `ApprovalRefusedError` for
    nothing: this function has no failure mode that is not a refusal. The
    raising entry point is `require_approved_plan`.
    """
    # ── 1. Can the caller's digest be READ at all? ──────────────────────────
    #
    # Its own outcome, separate from "no plan holds it", and the separation is
    # the `0.1.0a4` lesson applied to the read path. "I cannot read what you
    # sent" is a fault in the caller's encoding and says nothing about any
    # plan; "nothing holds that digest" is a statement about this database.
    # Collapsing them would hand an operator a security-shaped answer for a
    # formatting bug — the failure shape that looks exactly like the system
    # working.
    try:
        wanted = PlanDigestV1.parse_accepting_a4_bare_hex(plan_digest)
    except DigestEncodingError as exc:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.DIGEST_UNREADABLE,
            f"the plan digest supplied to this lookup cannot be read: {exc} "
            "NOTHING was looked up and no claim is made about any plan — this "
            "is an encoding fault in the caller, not a statement that the plan "
            "is unapproved or missing.",
        )

    # A VALUE lookup, expressed as the two encodings that value can be stored
    # in. `0.1.0a4` wrote bare hex and everything since writes canonical, so a
    # single equality against the caller's text would silently miss half the
    # rows — and would be a string comparison of a digest, which is the defect
    # `test_digest_comparison_is_typed.py` exists to keep out. Both renderings
    # come from the parsed VALUE, so neither is the caller's spelling.
    row = (
        db.execute(
            select(DeploymentPlan).where(
                DeploymentPlan.plan_digest.in_((wanted.canonical, wanted.a4_bare_hex))
            )
        )
        .scalars()
        .one_or_none()
    )
    if row is None:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.DIGEST_UNRESOLVED,
            f"no plan in this control plane holds digest {wanted.canonical}. "
            "The value was read as a well-formed digest, so this is an answer "
            "about this database and not about the caller's encoding.",
        )

    # ── 2. Is it approved? ─────────────────────────────────────────────────
    if row.status != PlanStatus.APPROVED.value:
        exempt = (
            " This plan is approval-EXEMPT (`requires_approval` is false), so "
            "it will never reach `approved`: it may be rolled out without an "
            "approval, and there is correspondingly no authorization for this "
            "lookup to return."
            if not row.requires_approval
            else ""
        )
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.NOT_APPROVED,
            f"plan {row.id} holds digest {wanted.canonical} and its status is "
            f"{row.status!r}, not {PlanStatus.APPROVED.value!r}.{exempt}",
            plan=row,
        )

    # ── 3. Does the approval still STAND? ──────────────────────────────────
    #
    # Before the binding and image terms, because if the decision does not
    # stand then nothing it named matters, and an operator triaging a live
    # rollout needs this answer first.
    #
    # Read ONCE into a local, here, and used for both the refusals below and
    # the value returned at the end. Not a style preference: what a consumer is
    # told must be the value these refusals were decided against, and a second
    # read of the attribute is a second chance for the two to differ.
    decision_status = row.approval_decision_status
    if decision_status == ApprovalDecisionStatus.REVOKED.value:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.APPROVAL_REVOKED,
            f"plan {row.id} was approved under decision "
            f"{row.approval_decision_ref!r} and that decision was REVOKED at "
            f"{row.approval_revoked_at} under "
            f"{row.approval_revocation_ref!r}"
            + (
                f" ({row.approval_revocation_reason})"
                if row.approval_revocation_reason
                else ""
            )
            + ". The plan's status still reads 'approved' because it was — "
            "that is history — but there is no standing authorization here.",
            plan=row,
        )
    if decision_status is None:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.APPROVAL_STANDING_UNRECORDED,
            f"plan {row.id} reads 'approved' and the standing of decision "
            f"{row.approval_decision_ref!r} was never recorded — it was "
            "approved before Deployment Control held the column. Control "
            "cannot confirm the approval still stands, and reading 'granted' "
            "out of a blank would be inferring an authorization from an "
            "absence. Re-approve the plan, or propose a new one.",
            plan=row,
        )

    # ── 4. Is there an execution to authorize? ─────────────────────────────
    authorized_execution = _stored_execution_plan_digest(
        row,
        row.authorized_execution_plan_digest,
        term="authorized execution plan digest",
    )
    # Same rule as the decision standing above: read once, use everywhere.
    authorized_operation = row.authorized_operation
    if authorized_execution is None or authorized_operation is None:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.EXECUTION_BINDING_ABSENT,
            f"plan {row.id} is approved and carries no execution binding "
            f"(authorized_operation={authorized_operation!r}); it was "
            "approved before Deployment Control held one. An authorization "
            "naming no execution is one no executor could verify, so it is "
            "refused here rather than returned for a receipt to fail against "
            "later.",
            plan=row,
        )

    # ── 5. Which images does it authorize? ─────────────────────────────────
    #
    # THE ORIGINAL DEFECT, refused rather than answered around. An
    # authorization that cannot say which images it covers is one a consumer
    # would have to fill in from its own caller — the thing this whole surface
    # exists to stop. Note `()` is NOT this case: a plan authorizing no images
    # resolves normally, and a receipt recording any image contradicts it.
    images = _frozen_image_set(row)
    if images is None:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.IMAGE_SET_UNDECLARED,
            f"plan {row.id} is approved and its frozen snapshot declares no "
            "authorized image set, so this control plane cannot say which "
            "images the approval covers. That is an ABSENCE and not an empty "
            "set: a plan authorizing no images resolves normally. Declare the "
            "image set on the target's desired state and propose again — "
            "answering this with a blank is what let a consumer verify a "
            "receipt against images it had supplied to itself.",
            plan=row,
        )

    descriptor = _frozen_descriptor_digest(row)
    if descriptor is None:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.DESCRIPTOR_BINDING_ABSENT,
            f"plan {row.id} is approved and carries no Foundation descriptor "
            "binding. It predates 0.1.0a9; Control cannot infer a canonical "
            "descriptor digest from the execution plan or its own plan digest.",
            plan=row,
        )
    if expected_descriptor_digest is not None:
        try:
            expected_descriptor = DescriptorDigestV1.parse(expected_descriptor_digest)
        except DigestEncodingError as exc:
            return _lookup_refusal(
                facts.ApprovedPlanRefusalCode.DIGEST_UNREADABLE,
                f"the expected descriptor digest cannot be read: {exc}",
                plan=row,
            )
        if expected_descriptor != descriptor:
            return _lookup_refusal(
                facts.ApprovedPlanRefusalCode.DESCRIPTOR_MISMATCH,
                f"plan {row.id} binds descriptor {descriptor.canonical} and "
                f"the caller expected {expected_descriptor.canonical}.",
                plan=row,
            )

    # ── 6. Optionally, is it the execution the caller expected? ────────────
    if expected_execution_plan_digest is not None:
        try:
            expected = ExecutionPlanDigestV1.parse(expected_execution_plan_digest)
        except DigestEncodingError as exc:
            return _lookup_refusal(
                facts.ApprovedPlanRefusalCode.DIGEST_UNREADABLE,
                "the expected execution plan digest supplied to this lookup "
                f"cannot be read: {exc} NO comparison was made against plan "
                f"{row.id}, and no claim is made about which execution it "
                "authorizes.",
                plan=row,
            )
        # TYPED. Two `ExecutionPlanDigestV1` values are equal when the
        # algorithm and the raw bytes are, which no encoding can change.
        if expected != authorized_execution:
            return _lookup_refusal(
                facts.ApprovedPlanRefusalCode.EXECUTION_PLAN_MISMATCH,
                f"plan {row.id} authorizes execution plan "
                f"{authorized_execution.canonical} and the caller expected "
                f"{expected.canonical}. Both were read as well-formed digests "
                "and their bytes differ, so this is a different execution and "
                "not an encoding difference. Deployment Control never "
                "recomputes this value and cannot reconcile the two.",
                plan=row,
            )

    if authorization_id is None:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.AUTHORIZATION_ENVELOPE_ABSENT,
            "no rollout authorization id was supplied. A plan approval is not "
            "itself a portable signed authorization.",
            plan=row,
        )
    try:
        wanted_authorization_id = UUID(str(authorization_id))
    except ValueError:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.AUTHORIZATION_UNRESOLVED,
            f"authorization id {authorization_id!r} is not a UUID",
            plan=row,
        )
    rollout = db.get(Rollout, wanted_authorization_id)
    if rollout is None or rollout.plan_id != row.id:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.AUTHORIZATION_UNRESOLVED,
            f"authorization {wanted_authorization_id} does not name a rollout "
            f"for plan {row.id}",
            plan=row,
        )
    if verifier is None:
        return _lookup_refusal(
            facts.ApprovedPlanRefusalCode.AUTHORIZATION_VERIFIER_ABSENT,
            "no portable authorization verifier was supplied; reading JSON "
            "from this database is not signature verification",
            plan=row,
        )
    target = _load_target(db, row.target_id)
    try:
        envelope = _verified_rollout_envelope(
            rollout, row, target, verifier=verifier, at=at
        )
    except AuthorizationEnvelopeRefusedError as exc:
        code = (
            facts.ApprovedPlanRefusalCode.AUTHORIZATION_ENVELOPE_ABSENT
            if exc.code is AuthorizationEnvelopeRefusalCode.ABSENT
            else facts.ApprovedPlanRefusalCode.AUTHORIZATION_ENVELOPE_INVALID
        )
        return _lookup_refusal(code, str(exc), plan=row)

    snapshot = row.snapshot or {}
    return facts.ApprovedPlanLookup(
        authorization=facts.ApprovedPlanAuthorization(
            plan_id=row.id,
            target_id=row.target_id,
            target_ref=str(snapshot.get("target_ref") or ""),
            sequence=row.sequence,
            desired_revision=row.desired_revision,
            # RENDERED FROM THE VALUE, not echoed from the caller's text and
            # not read back out of the column: a `0.1.0a4` row holds bare hex,
            # and a consumer must receive one spelling of one digest whichever
            # version wrote the row.
            plan_digest=wanted.canonical,
            descriptor_digest=descriptor.canonical,
            # Handed back AS FROZEN. Control received this from the Foundation
            # and has no constructor that could rebuild it.
            execution_plan_digest=authorized_execution.canonical,
            operation=authorized_operation,
            approval_policy_code=row.approval_policy_code,
            approval_policy_version=row.approval_policy_version,
            approval_decision_ref=row.approval_decision_ref,
            approval_decision_status=decision_status,
            approved_at=row.approved_at,
            control_version=envelope.statement.control_version,
            authorized_images=images,
            authorization_envelope=envelope,
            release_ref=snapshot.get("release_ref"),
            licence_ref=snapshot.get("licence_ref"),
            brand_profile_ref=snapshot.get("brand_profile_ref"),
        )
    )


def require_approved_plan(
    db: Session,
    *,
    plan_digest: str,
    authorization_id: UUID | str | None = None,
    expected_descriptor_digest: str | None = None,
    expected_execution_plan_digest: str | None = None,
    verifier: AuthorizationVerifier | None = None,
    at: datetime | None = None,
) -> facts.ApprovedPlanAuthorization:
    """`find_approved_plan`, for a caller that must not proceed without one.

    Same decision, one function, no second copy of the rules: this calls
    `find_approved_plan` and raises its refusal. A promotion that would deploy
    into somebody's running system cannot be handed a falsy object it might
    forget to check, and the only way past this function is a standing
    `ApprovedPlanAuthorization`.

    `ApprovedPlanRefusedError` carries the typed `refusal`, so a caller that
    must distinguish "revoked" from "never approved" branches on
    `exc.refusal.code` rather than reading a sentence.
    """
    lookup = find_approved_plan(
        db,
        plan_digest=plan_digest,
        authorization_id=authorization_id,
        expected_descriptor_digest=expected_descriptor_digest,
        expected_execution_plan_digest=expected_execution_plan_digest,
        verifier=verifier,
        at=at,
    )
    if lookup.authorization is None:
        raise ApprovedPlanRefusedError(lookup.refusal)
    return lookup.authorization


def get_target(db: Session, target_id: UUID) -> facts.TargetView | None:
    row = db.get(DeploymentTarget, target_id)
    if row is None:
        return None
    return _target_view(row, approval_standing=_approval_standing_for(db, row.id))


def get_plan(db: Session, plan_id: UUID) -> facts.PlanView | None:
    row = db.get(DeploymentPlan, plan_id)
    return _plan_view(row) if row is not None else None


def get_rollout(db: Session, rollout_id: UUID) -> facts.RolloutView | None:
    row = db.get(Rollout, rollout_id)
    return _rollout_view(row) if row is not None else None


def plans_for_target(db: Session, target_id: UUID) -> tuple[facts.PlanView, ...]:
    """Every plan for one target, newest sequence first.

    Newest first because a plan's whole purpose is to be the thing currently
    awaiting a decision or currently rolled out; the history below it is
    context. Ordered by `sequence`, which this module issues, rather than by a
    timestamp two rows can share.
    """
    rows = (
        db.execute(
            select(DeploymentPlan)
            .where(DeploymentPlan.target_id == target_id)
            .order_by(DeploymentPlan.sequence.desc())
        )
        .scalars()
        .all()
    )
    return tuple(_plan_view(row) for row in rows)


def rollouts_for_target(db: Session, target_id: UUID) -> tuple[facts.RolloutView, ...]:
    """Every rollout for one target, newest first, each with its attempts.

    The attempt history comes with the rollout rather than as a second call,
    because "what did we try, and what happened" is one question. A surface
    that fetched them separately would render a rollout whose attempts belong
    to a different read of the database.
    """
    rows = (
        db.execute(
            select(Rollout)
            .where(Rollout.target_id == target_id)
            # `rollout_ref` breaks the tie. Two rollouts created inside one
            # transaction share a `created_at` to the database's resolution, and
            # an unstable order is how a list shows a row twice.
            .order_by(Rollout.created_at.desc(), Rollout.rollout_ref.desc())
        )
        .scalars()
        .all()
    )
    return tuple(_rollout_view(row) for row in rows)


def observation_log(
    db: Session, *, target_ref: str | None = None, limit: int = 100
) -> tuple[facts.ObservationAttemptView, ...]:
    """The append-only arrival log as VIEWS, newest first.

    The projected sibling of `observation_attempts`, and both exist on purpose.
    That one returns rows for a caller inside this module's transaction that
    legitimately wants every column. This one is for a consumer outside it —
    notably a presentation surface, which must never be handed a live ORM
    object — and it is bounded, because the arrival log is the one table an
    unauthenticated sender can grow.

    Newest first, which is the opposite of `observation_attempts`: triage starts
    at what just arrived, whereas a caller reconstructing a sequence starts at
    the beginning.

    An arrival that never resolved to an identity has no `target_ref` to filter
    on and therefore appears only in the unfiltered log. That is not an
    oversight — it is the missing-evidence case, and it is exactly the row a
    per-target screen structurally cannot show.
    """
    statement = select(ObservationAttempt).order_by(
        ObservationAttempt.received_at.desc()
    )
    if target_ref is not None:
        statement = statement.where(
            ObservationAttempt.authenticated_target_ref == target_ref
        )
    rows = db.execute(statement.limit(max(1, limit))).scalars().all()
    return tuple(_observation_attempt_view(row) for row in rows)


def observation_receipts(
    db: Session, *, target_ref: str | None = None, limit: int = 100
) -> tuple[facts.ObservationReceiptView, ...]:
    """The canonical receipts as VIEWS, newest first, bounded the same way."""
    statement = select(ObservationReceipt).order_by(
        ObservationReceipt.first_received_at.desc()
    )
    if target_ref is not None:
        statement = statement.where(
            ObservationReceipt.authenticated_target_ref == target_ref
        )
    rows = db.execute(statement.limit(max(1, limit))).scalars().all()
    return tuple(_observation_receipt_view(row) for row in rows)


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
    "SCOPE_REVOKE_PLAN_APPROVAL",
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
    "RevokePlanApprovalCommand",
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
    "find_approved_plan",
    "get_plan",
    "get_rollout",
    "get_target",
    "list_targets",
    "observation_attempts",
    "observation_log",
    "observation_receipts",
    "plan_digest_of",
    "plan_snapshot",
    "plans_for_target",
    "preview_plan_proposal",
    "propose_plan",
    "record_observation",
    "register_target",
    "request_rollout",
    "require_approved_plan",
    "require_manual_repair",
    "revoke_credential",
    "revoke_plan_approval",
    "rollouts_for_target",
    "set_desired_state",
    "settle_attempt",
    "snapshot_digest",
    "spec_digest",
    "spec_digest_of",
    "suspend_target",
]
