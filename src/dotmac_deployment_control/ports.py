"""The module's inbound contract: intent in, provider-neutral observations back.

This module sits between two things it must not become. On one side is the
Integrator, which moves bytes and speaks to providers. On the other is
`dotmac-licensing`, which decides what a deployment is authorised to run. This
module decides only what SHOULD be deployed, whether it HAS been, and what to do
about the difference.

## Two historical evidence modes, one rule-24 source mode

ADR-0057 § 3 splits this module's historical evidence, while `EXTRACTION.toml`
records the rule-24 classification as `greenfield-after-inventory`: a source
must be production-used to qualify as product-first, and neither half has one.

- **The receipt half is a tested reference.** Vendor's V6 slices
  (`admission.py`, `admission_models.py`, `credentials.py`,
  `credential_models.py`) are ported with their design, including the two
  decisions below that are easy to get wrong and expensive to get wrong twice.
  Those branches were never merged and never deployed, and their migration slots
  were later reused by different work on Vendor `main` — so they are a *tested
  reference*, not a production-used implementation.
- **The plan/rollout half is greenfield**, with the absence of any source
  evidenced across every branch, stash, dangling object and reflog of the Vendor
  repository plus seven other repositories.

## Two decisions ported from the reference, because both are counter-intuitive

**1. A claim is not a proof, and they get separate columns.**

An inbound report names a deployment. That name is EVIDENCE and never authority.
The authoritative identity is the one resolved from the *signed* `key_id` by
`dotmac_kernel.licensing.verify_applied_state` (ADR-0007 § 4). Storing both in
one column would make "did we actually verify this?" unanswerable after the
fact — and would make deployment binding decorative, since anyone reaching the
endpoint could activate any target's deployment by naming it.

**2. Attempts and reports are two tables, not one.**

A single append-only table keyed uniquely on `(identity, report_id)` cannot work:
the SECOND arrival under a key is exactly the row worth keeping — the replay, or
the conflicting bytes — and the unique constraint forbids inserting it. Updating
the first row instead breaks append-only semantics AND discards the conflicting
bytes, destroying the evidence the table exists to preserve. It also leaves
nowhere to record an arrival that never resolved to an identity at all: an
unknown key, a malformed envelope, a bad signature. Those are the tripwires, and
a fail-closed system that discards them silently is the worst of both.

So: an append-only log of ATTEMPTS, and one canonical REPORT per idempotency key.

## What this module refuses to hold

- **Provider credentials.** `TargetCredential` holds a deployment's own PUBLIC
  verification key — the target's identity, not a way to reach a provider. There
  is no private material and no provider secret anywhere in this package.
- **A provider client.** No SSH, Kubernetes, cloud or panel client; no webhook
  verification; no connector retry or checkpoint state. All of it is the
  Integrator's (ADR-0024, hard rule 28).
- **A release catalogue, a licence, or a brand definition.** `release_ref`,
  `licence_ref` and `brand_profile_ref` are opaque strings with no foreign key.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dotmac_deployment_control.authorization import AuthorizationEnvelopeV1

# ── Errors ──────────────────────────────────────────────────────────────────


class DeploymentControlError(ValueError):
    """Base: this command cannot be applied to this target, plan or rollout."""


class TransitionRefusedError(DeploymentControlError):
    """The subject is not in a state from which this transition is legal."""


class ExpectedStateError(DeploymentControlError):
    """The caller's expected status or record version does not match.

    Distinct from `TransitionRefusedError`: this one means the caller's view is
    stale, that one means the command is wrong for the subject.
    """

    def __init__(
        self,
        subject_ref: str,
        *,
        expected_status: str | None,
        actual_status: str,
        expected_version: int | None,
        actual_version: int,
    ) -> None:
        self.subject_ref = subject_ref
        self.expected_status = expected_status
        self.actual_status = actual_status
        self.expected_version = expected_version
        self.actual_version = actual_version
        super().__init__(
            f"{subject_ref} has moved: caller expected "
            f"status={expected_status!r} version={expected_version} but it is "
            f"status={actual_status!r} version={actual_version}"
        )


class PlanRefusedError(DeploymentControlError):
    """A plan cannot be built or approved as asked."""


class ApprovalRefusedError(DeploymentControlError):
    """Approval evidence does not bind to the plan snapshot it claims to cover.

    ADR-0026 § 2's digest binding, applied to a rollout: change the plan and the
    digest changes, which makes a prior approval **stale rather than
    transferable**. Without it, "approved" would be a token movable onto a wider
    blast radius than anyone reviewed — and for a deployment plan the blast
    radius is other people's running systems.
    """


class OperationRefusedError(DeploymentControlError):
    """The operation named is not one this control plane can authorize.

    Separate from every other refusal here, because it is a VOCABULARY fault
    and the reader is whoever wrote the caller. `deploy` and `rollback` are the
    closed set (`dotmac_deployment_control.operations`); an unknown word is
    refused rather than defaulted, coerced or inferred, and this exception is
    what "refused" means.
    """


class ImageSetRefusedError(DeploymentControlError):
    """An authorized image set cannot be read, or is not a set.

    Its own exception rather than a `PlanRefusedError`, because the reader is
    whoever composed the image set and the repair is in their declaration —
    a tag where a digest belongs, two digests for one service, a missing term.
    None of those is a statement about a target's state or a plan's standing,
    and reporting one as a plan refusal would send an operator to look at a
    deployment when the fault is in a manifest.
    """


class ApprovedPlanRefusedError(DeploymentControlError):
    """`require_approved_plan` did not find a standing authorization.

    Carries the typed `ApprovedPlanRefusalCode` that
    `service.find_approved_plan` decided, so a caller that must distinguish
    "revoked" from "never approved" reads a member rather than a message.

    An exception rather than a return value on that entry point ON PURPOSE. A
    promotion that must not proceed without an authorization cannot be handed
    a falsy object it might forget to check; the only way past this function is
    an `ApprovedPlanAuthorization`. `find_approved_plan` is the total sibling
    for callers that genuinely want to ASK rather than to require.
    """

    def __init__(self, refusal: object) -> None:
        #: The `facts.ApprovedPlanRefusal`. Typed as `object` here because
        #: `facts` imports nothing from this module and this module must not
        #: import `facts` — the refusal travels as its own value and callers
        #: read `.code`.
        self.refusal = refusal
        super().__init__(str(getattr(refusal, "detail", refusal)))


class ExecutionPlanBindingError(DeploymentControlError):
    """Proposal, authorization and report do not bind the same execution.

    Raised where an approval is being recorded. The report path does NOT raise
    it — rule 3 says every arrival is recorded, so a report that binds the wrong
    execution plan or the wrong operation becomes an attempt row with its own
    disposition instead of an exception.

    Distinct from `ApprovalRefusedError`, which is about Control's OWN plan
    snapshot moving under an approval. This one is about the FOUNDATION's
    execution plan: the two answer different questions and send the reader to
    different systems.
    """


class DescriptorBindingError(DeploymentControlError):
    """A Foundation descriptor binding is absent or unreadable.

    The descriptor and execution plan are different documents. Keeping this
    refusal distinct prevents an operator from repairing the wrong producer.
    """


class DigestEncodingError(DeploymentControlError):
    """A digest could not be READ. Deliberately not an `ApprovalRefusedError`.

    THE DISTINCTION IS THE POINT, and it is the defect `0.1.0a5` was cut for.
    Through `0.1.0a4` a caller who supplied the right digest in the other
    encoding — bare hex where the plan had been stored prefixed, or the
    reverse — was refused with *"the plan changed after approval, so a new
    approval is required"*. That is a security finding standing in for a
    formatting bug, and it is the worst available failure shape because it
    looks exactly like the system working: the operator re-runs an approval
    that was never stale.

    So the two outcomes are two exceptions, and neither is a subclass of the
    other:

    * `DigestEncodingError` — "I cannot read the value you sent." Nothing was
      compared. No claim is made about the plan. The repair is the caller's
      encoding, and the reader is whoever wrote the caller.
    * `ApprovalRefusedError` — "I read it, and it is not this plan's digest."
      The plan moved under the approval. The repair is a new approval, and the
      reader is whoever approves deployments.

    Callers that must treat both as a refusal still can: both derive from
    `DeploymentControlError`.
    """


class ObservationRefusedError(DeploymentControlError):
    """An observation cannot be admitted.

    Deliberately narrow: almost every bad arrival is RECORDED as an attempt with
    a disposition rather than raised, because the record is the point. This is
    raised only when the caller's own inputs are unusable — no bytes at all, or
    a receipt time that is not timezone-aware.
    """


# ── Inbound values ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DesiredDeployment:
    """The specification a target should converge on.

    `spec` is opaque to this module. It carries whatever the product's own
    deployment shape needs — module set, provider selections, resource sizing —
    and nothing here interprets it. Interpreting it would make this module a
    second authority on what a deployment IS, which belongs to the product's
    deployment profile (`dotmac_kernel.profiles`, ADR-0003).

    What this module DOES own is that the spec is versioned, that a plan freezes
    one exact version of it, and that an observation is compared against the
    version that was actually rolled out rather than the newest one.
    """

    release_ref: str
    spec: Mapping[str, Any] = field(default_factory=dict)
    licence_ref: str | None = None
    brand_profile_ref: str | None = None
    #: THE AUTHORIZED IMAGE SET, declared rather than buried in `spec`.
    #:
    #: `spec` above stays opaque and Control still interprets nothing inside
    #: it. This is the separate, typed term that a plan freezes INSIDE the
    #: document its digest is taken over, so an approval covers which images
    #: may run — the gap that made a consumer's `authorized_images` a value the
    #: consumer supplied to itself.
    #:
    #: THREE STATES, and the middle one is the one a caller loses by accident:
    #:
    #: * `None` — no image set has been declared for this target. A consumer
    #:   must not read it as "no images"; `find_approved_plan` refuses rather
    #:   than answering, so the absence cannot be silently promoted.
    #: * `()` — this target authorizes NO images, declared deliberately.
    #: * a sequence — the set, canonicalized and duplicate-checked by
    #:   `images.authorized_image_set` before it is frozen.
    #:
    #: Accepts either `AuthorizedImage` values or the three-key mappings they
    #: parse from, so an assembly deserializing JSON does not have to construct
    #: the type before this module can refuse a bad one.
    images: Sequence[Any] | None = None


@dataclass(frozen=True, slots=True)
class ApprovalEvidence:
    """Proof, supplied by the assembly, that `dotmac-approvals` decided.

    Identical in shape and intent to `dotmac-commercial-agreements`'s, and for
    the same reason: this module never calls approvals and never implements a
    second approval lifecycle (ADR-0026 § 6, ADR-0024). `content_digest` is
    checked against the plan digest this module computed itself.
    """

    policy_code: str
    policy_version: int
    decision_ref: str
    content_digest: str
    decided_at: datetime
    approver_refs: tuple[str, ...] = ()
    #: WHAT THE DECISION SAID, in the approvals authority's own vocabulary.
    #:
    #: `decision_ref` says WHICH decision; this says what that decision's
    #: standing was when the evidence was assembled. Two facts, and the second
    #: was previously inferred from the first — reaching `approve_plan` at all
    #: was treated as meaning "granted". That inference is the same shape as a
    #: defaulted `operation`: a caller's silence deciding an authorization.
    #:
    #: Optional in the dataclass and REQUIRED by `approve_plan`, exactly like
    #: `operation` and `execution_plan_digest` above. The default exists for
    #: the `0.1.0a7` shape, not as a way to approve without saying what the
    #: decision was.
    #:
    #: The vocabulary is `approvals.ApprovalDecisionStatus` and it is closed.
    #: `approve_plan` accepts only `granted`: a decision that has been REVOKED
    #: authorizes nothing, and replaying its evidence is precisely the arrival
    #: that must be refused rather than recorded as an approval.
    decision_status: str | None = None
    #: WHICH OPERATION was authorized, and over WHICH execution plan.
    #:
    #: Both, and both independent of `content_digest`, because a three-term
    #: gate cannot be satisfied by two terms. `content_digest` says which of
    #: Control's plan snapshots was approved; these say which Foundation
    #: execution the approver was authorizing over it. An approval that named
    #: only the snapshot would authorize a DEPLOY and a ROLLBACK of it
    #: identically, and Michael's ruling is that those are separately
    #: authorized operations.
    #:
    #: Optional in the dataclass and REQUIRED by `approve_plan` for any plan
    #: that froze them, which is every plan proposed from `0.1.0a8`. The default
    #: exists for the `0.1.0a7` rows that predate the columns, not as a way to
    #: approve a modern plan without saying what is being approved.
    operation: str | None = None
    execution_plan_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ObservedState:
    """What a target reports about itself, already verified by the caller.

    The caller runs `dotmac_kernel.licensing.verify_applied_state` (ADR-0007) and
    passes the RESULT in. This module does not re-verify a signature — the kernel
    owns that — but it does insist on the distinction the verification produces:

    - `authenticated_target_ref` is the identity resolved from the SIGNED key. It
      is `None` when nothing authenticated, and a `None` here can never become an
      admitted observation.
    - `claimed_target_ref` is what the report said about itself. Evidence only.

    A caller that puts the claim in both fields has defeated the whole design,
    which is why they are separate parameters rather than one with a flag.
    """

    report_id: str
    observed_release_ref: str | None
    observed_spec_digest: str | None
    reported_at: datetime
    authenticated_target_ref: str | None = None
    claimed_target_ref: str | None = None
    key_id: str | None = None
    #: The exact bytes as received, so the report stays portable evidence a third
    #: party can verify — the property ADR-0007 § 1 justifies Ed25519 with in the
    #: first place. Bounded by the caller before it reaches here.
    raw_body: bytes | None = None
    raw_body_digest: str | None = None
    raw_body_truncated: bool = False
    #: `unresolved` | `invalid` | `valid` — the kernel verifier's outcome.
    signature_status: str = "unresolved"
    #: WHAT THE REPORT BINDS ITSELF TO. Three fields, and none of them is
    #: authority: like `claimed_target_ref`, they are the report's own account
    #: of itself, compared against what Control froze and authorized.
    #:
    #: `rollout_ref` says which authorization this report claims to be executing
    #: — without it there is nothing to compare against, because a target may
    #: hold many plans. `operation` and `execution_plan_digest` are what the
    #: executor recomputed before running (step 6 of the flow) and carried into
    #: the report (step 7).
    #:
    #: All three default to `None` so a caller cannot be forced to invent one,
    #: and a report that supplies none is quarantined as UNBOUND rather than
    #: accepted — an absence is a finding, not a pass.
    rollout_ref: str | None = None
    operation: str | None = None
    execution_plan_digest: str | None = None


@dataclass(frozen=True, slots=True)
class DeliveryIntent:
    """What this module hands the Integrator: WHAT, never HOW.

    Provider-neutral by construction. There is no endpoint, no credential
    reference, no transport name and no retry policy — those are the
    Integrator's, and a field for any of them here would make this module a
    second transport authority (ADR-0024, hard rule 28).

    `plan_digest` is included so the Integrator's own evidence can be tied back
    to the exact plan that was approved, without this module having to trust a
    correlation id round-tripping through a system it does not own.
    """

    rollout_ref: str
    target_ref: str
    release_ref: str
    plan_digest: str
    descriptor_digest: str
    #: The AUTHORIZED operation and the AUTHORIZED execution plan, carried out
    #: so the executor can do steps 6 and 7 of the flow: recompute the plan
    #: digest before executing, and carry the same two values back in its
    #: report. Neither is a transport detail and neither says HOW — they say
    #: WHICH execution was authorized, which is the same kind of fact
    #: `plan_digest` already is.
    operation: str
    execution_plan_digest: str
    authorization_envelope: AuthorizationEnvelopeV1
    attempt_no: int
    spec: Mapping[str, Any] = field(default_factory=dict)
    licence_ref: str | None = None
    brand_profile_ref: str | None = None


__all__ = [
    "ApprovalEvidence",
    "ApprovalRefusedError",
    "ApprovedPlanRefusedError",
    "DeliveryIntent",
    "DeploymentControlError",
    "DescriptorBindingError",
    "DesiredDeployment",
    "DigestEncodingError",
    "ExecutionPlanBindingError",
    "ExpectedStateError",
    "ImageSetRefusedError",
    "ObservationRefusedError",
    "ObservedState",
    "OperationRefusedError",
    "PlanRefusedError",
    "TransitionRefusedError",
]
