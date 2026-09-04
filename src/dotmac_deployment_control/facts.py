"""The versioned facts this module publishes, and the views it returns.

An adopting assembly reads these off the platform outbox and reacts: the
Integrator picks up a `deployment.intent.dispatched.v1` and delivers, an operator
console surfaces `deployment.drift.detected.v1`, a support queue picks up
`deployment.rollout.manual_repair.v1`. **This module calls none of them**
(ADR-0024): it records a decision and emits the fact; the assembly routes it.

## The version is in the event type

`deployment.rollout.succeeded.v1`, not `deployment.rollout.succeeded`. A consumer
pins a shape; when it changes incompatibly, `v2` is emitted alongside `v1` for a
migration window. An unversioned type makes that impossible to do safely.

## Drift is a FACT, not a status column

There is no `is_drifted` boolean anywhere in this module. Drift is the computed
difference between what a plan rolled out and what the target last reported, and
computing it on demand means it cannot go stale. A cached flag would have to be
invalidated by every desired-state edit, every observation and every rollout —
three writers for one derived value, which is the shape ADR-0010 exists to
prevent.

`DriftReport` is what that computation returns, and `deployment.drift.detected.v1`
is emitted when an observation makes it non-empty.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Final
from uuid import UUID

from dotmac_deployment_control.authorization import (
    AuthorizationEnvelopeV1,
    AuthorizationEnvelopeV2,
)
from dotmac_deployment_control.images import AuthorizedImage

# ── Event types ─────────────────────────────────────────────────────────────

TARGET_REGISTERED_V1: Final[str] = "deployment.target.registered.v1"
TARGET_DESIRED_STATE_SET_V1: Final[str] = "deployment.target.desired_state_set.v1"
TARGET_SUSPENDED_V1: Final[str] = "deployment.target.suspended.v1"
TARGET_DECOMMISSIONED_V1: Final[str] = "deployment.target.decommissioned.v1"
CREDENTIAL_ENROLLED_V1: Final[str] = "deployment.credential.enrolled.v1"
CREDENTIAL_ACTIVATED_V1: Final[str] = "deployment.credential.activated.v1"
CREDENTIAL_REVOKED_V1: Final[str] = "deployment.credential.revoked.v1"
PLAN_PROPOSED_V1: Final[str] = "deployment.plan.proposed.v1"
PLAN_APPROVED_V1: Final[str] = "deployment.plan.approved.v1"
#: An approval WITHDRAWN. Its own fact rather than a second
#: `plan.cancelled`: a cancelled plan is not wanted, a plan whose approval
#: was revoked is still wanted and is no longer authorized, and a consumer
#: that has already dispatched needs to tell those apart.
PLAN_APPROVAL_REVOKED_V1: Final[str] = "deployment.plan.approval_revoked.v1"
PLAN_CANCELLED_V1: Final[str] = "deployment.plan.cancelled.v1"
ROLLOUT_REQUESTED_V1: Final[str] = "deployment.rollout.requested.v1"
INTENT_DISPATCHED_V1: Final[str] = "deployment.intent.dispatched.v1"
ROLLOUT_SUCCEEDED_V1: Final[str] = "deployment.rollout.succeeded.v1"
ROLLOUT_FAILED_V1: Final[str] = "deployment.rollout.failed.v1"
ROLLOUT_TIMED_OUT_V1: Final[str] = "deployment.rollout.timed_out.v1"
ROLLOUT_CANCELLED_V1: Final[str] = "deployment.rollout.cancelled.v1"
ROLLOUT_MANUAL_REPAIR_V1: Final[str] = "deployment.rollout.manual_repair.v1"
OBSERVATION_RECORDED_V1: Final[str] = "deployment.observation.recorded.v1"
DRIFT_DETECTED_V1: Final[str] = "deployment.drift.detected.v1"

#: Every type this module can emit. A consumer building a subscription set reads
#: this rather than a hand-kept list that drifts, and the module's own test
#: asserts the set matches what the service actually emits.
PUBLISHED_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        TARGET_REGISTERED_V1,
        TARGET_DESIRED_STATE_SET_V1,
        TARGET_SUSPENDED_V1,
        TARGET_DECOMMISSIONED_V1,
        CREDENTIAL_ENROLLED_V1,
        CREDENTIAL_ACTIVATED_V1,
        CREDENTIAL_REVOKED_V1,
        PLAN_PROPOSED_V1,
        PLAN_APPROVED_V1,
        PLAN_APPROVAL_REVOKED_V1,
        PLAN_CANCELLED_V1,
        ROLLOUT_REQUESTED_V1,
        INTENT_DISPATCHED_V1,
        ROLLOUT_SUCCEEDED_V1,
        ROLLOUT_FAILED_V1,
        ROLLOUT_TIMED_OUT_V1,
        ROLLOUT_CANCELLED_V1,
        ROLLOUT_MANUAL_REPAIR_V1,
        OBSERVATION_RECORDED_V1,
        DRIFT_DETECTED_V1,
    }
)


# ── Views ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TargetView:
    """A deployment target, with desired and observed side by side.

    Both, deliberately. A view that returned only the desired state would make
    the most common operator question — *is this deployment actually running what
    we asked for?* — a second query, and a caller that forgot it would render a
    reassuring screen about a target that has not converged in a month.
    """

    id: UUID
    target_ref: str
    subject_ref: str
    product_code: str
    environment: str
    status: str
    record_version: int
    desired_release_ref: str | None = None
    desired_revision: int = 0
    licence_ref: str | None = None
    brand_profile_ref: str | None = None
    observed_release_ref: str | None = None
    observed_spec_digest: str | None = None
    observed_revision: int | None = None
    last_observed_at: datetime | None = None
    desired_spec: Mapping[str, Any] = field(default_factory=dict)
    #: R1. THE DECLARED IMAGE SET, projected so a consumer never parses a plan
    #: document to learn it.
    #:
    #: Three states, and the defence is that there is only ONE implementation
    #: of them: this is read through `images.image_set_from_payload`, the same
    #: parser the plan's frozen set goes through, rather than re-derived here.
    #: `None` means no set has been declared and must not be read as "no
    #: images"; `()` means it authorizes none, deliberately; a tuple is the set.
    desired_images: tuple[AuthorizedImage, ...] | None = None
    #: R4. The approval standing of this target's CURRENT plan, projected in the
    #: same statement that lists targets. Without it, "which targets hold a
    #: revoked approval?" is an N+1 join performed by the consumer.
    #:
    #: Four states and they are not interchangeable: `"none"` (no plan at all),
    #: `"unrecorded"` (a plan exists and carries no decision), `"revoked"`, or
    #: the recorded status itself. `unrecorded` must never collapse into
    #: `granted` -- that is reading an authorization out of a blank column.
    current_plan_approval_status: str = "none"


class ExecutionBindingStanding(StrEnum):
    """Whether a plan's PROPOSED execution binding and its AUTHORIZED one agree.

    Computed by the OWNER, because the alternative is every surface computing it
    from four columns -- and the obvious way to do that is
    `proposed != authorized`, which is wrong in a way that reads as an incident.

    FOUR members, and the pair that must never merge is `UNAUTHORIZED` and
    `DIVERGES`. A two-valued comparison puts them together: a plan nobody has
    approved yet has no authorized digest, so `!=` says "differs", and "differs"
    on an execution binding reads as *the executor was authorized for something
    other than what was proposed* -- a tampering-shaped finding about a plan
    that is simply waiting for a decision. They send an operator to different
    systems: `UNAUTHORIZED` to the approvals authority, `DIVERGES` to whoever
    can edit this database.

    `UNBOUND` is the third that a boolean loses. A `0.1.0a7` plan names no
    execution at all; it is not a plan whose binding failed, and rendering it as
    one would report a schema-era absence as a mismatch.
    """

    #: The plan names no execution to bind -- no operation, or no execution plan
    #: digest. A `0.1.0a7` row. Refused a rollout, and not a fault.
    UNBOUND = "unbound"
    #: The plan is bound and nothing has authorized that binding yet. Also the
    #: honest answer for an APPROVAL-EXEMPT plan: such a plan has no
    #: authorization term, and copying the proposal into the authorized columns
    #: to make the check look three-termed is exactly the weakening the
    #: Foundation's `require_same_digest` refuses.
    UNAUTHORIZED = "unauthorized"
    #: Both terms present, both equal. The only member that authorizes anything.
    MATCHES = "matches"
    #: Both terms present and not equal. Nothing in this package can write this
    #: -- `approve_plan` refuses evidence that does not match what was proposed
    #: -- so a plan reading DIVERGES was edited outside the module.
    DIVERGES = "diverges"


@dataclass(frozen=True, slots=True)
class PlanView:
    """A plan and its approval standing."""

    id: UUID
    target_id: UUID
    sequence: int
    status: str
    desired_revision: int
    record_version: int
    plan_digest: str | None = None
    descriptor_digest: str | None = None
    #: The execution binding, in two pairs: what was PROPOSED and what was
    #: AUTHORIZED. Both are surfaced because they are the terms an operator
    #: needs to read when a report is quarantined — "which execution did we
    #: authorize, and as what kind of act?" — and a view that showed only one
    #: pair would make a two-term check look like a three-term one on screen.
    #:
    #: `None` on a `0.1.0a7` plan, which is a bindable-never state rather than a
    #: pending one; such a plan is refused a rollout.
    operation: str | None = None
    execution_plan_digest: str | None = None
    authorized_operation: str | None = None
    authorized_execution_plan_digest: str | None = None
    requires_approval: bool = True
    approval_policy_code: str | None = None
    approval_policy_version: int | None = None
    approval_decision_ref: str | None = None
    approved_at: datetime | None = None
    #: WHETHER THE APPROVAL STILL STANDS, and under what. `status` above says
    #: the plan WAS approved and keeps saying so forever; these four say
    #: whether that decision is still good. A surface that showed only `status`
    #: would render a revoked authorization as an approved plan.
    approval_decision_status: str | None = None
    approval_revoked_at: datetime | None = None
    approval_revocation_ref: str | None = None
    approval_revocation_reason: str | None = None
    superseded_by_id: UUID | None = None
    snapshot: Mapping[str, Any] = field(default_factory=dict)
    #: The frozen image set, projected out of `snapshot` rather than stored
    #: beside it — the snapshot is where it lives, because that is the document
    #: `plan_digest` covers.
    #:
    #: `None` means this plan froze no image set: either it predates the field,
    #: or its target never declared one. A caller must not read that as an
    #: empty set, which is why the lookup refuses it rather than answering.
    authorized_images: tuple[AuthorizedImage, ...] | None = None
    #: R3. Whether the counterparty has published support for this plan's
    #: operation, so a surface can say "this can never produce a receipt"
    #: without re-deriving a pin whose whole purpose is not to drift.
    #:
    #: Derived by SET MEMBERSHIP against `EXECUTOR_OPERATIONS`, never by calling
    #: `require_executable_operation` -- that is the write-path gate and its own
    #: signature says "never for reading". Calling it here would make every
    #: historical `recover` plan raise on the plans page.
    #:
    #: `None` when no operation is declared: an undeclared operation is not an
    #: inexecutable one.
    operation_is_executable: bool | None = None
    #: R5. Whether the four binding columns above agree, decided ONCE, here.
    #:
    #: The four terms are already on this view and a surface could compare them
    #: -- which is the problem. `proposed != authorized` is the comparison a
    #: reader reaches for, and it reports an unapproved plan as a diverged one.
    #: See `ExecutionBindingStanding` for why that pair must stay apart.
    #:
    #: Defaulted to `UNBOUND` rather than `None`: a view built without this term
    #: describes a plan that binds nothing, which is the safe reading and the
    #: one a `0.1.0a7` row actually has. There is no fifth "not computed" state
    #: to render.
    execution_binding: ExecutionBindingStanding = ExecutionBindingStanding.UNBOUND


# ── The approved-plan lookup ────────────────────────────────────────────────
#
# THE DEFECT THIS ANSWERS, measured rather than supposed. There was no read API
# for an approved plan here: no fetch-by-digest and no verify-approved. Only a
# WRITE path existed, comparing an expected digest while an approval was being
# recorded. So a promotion in another system was HANDED an authorization and
# could not confirm one — it verified a receipt against terms its own caller
# had supplied, which proves a caller consistent with itself and nothing else.


class ApprovedPlanRefusalCode(StrEnum):
    """WHY the lookup did not return an authorization. Typed, never one "no".

    These members have different readers and repairs; a lookup that answered
    only "no" would leave each of them opening the wrong system.

    The first two are the a4 lesson applied to the read path, and they are the
    pair most worth keeping apart: *I could not read the digest you sent* is a
    fault in the caller's encoding and says nothing about any plan, while
    *nothing holds that digest* is a statement about this database. Collapsing
    them would hand an operator a security-shaped answer for a formatting bug.
    """

    #: The supplied plan digest is not readable as a `PlanDigestV1`. NOTHING
    #: was looked up and no claim is made about any plan.
    DIGEST_UNREADABLE = "digest_unreadable"
    #: Well-formed, and no plan in this control plane holds it.
    DIGEST_UNRESOLVED = "digest_unresolved"
    #: A plan holds it and it is not approved. `detail` names the actual status,
    #: because "draft", "superseded" and "cancelled" send an operator three
    #: different places.
    NOT_APPROVED = "not_approved"
    #: It WAS approved and the decision has since been revoked. Deliberately
    #: not folded into `NOT_APPROVED`: a plan that was never approved is a
    #: process that has not happened, and a revoked one is a decision somebody
    #: took — and if a rollout is already in flight, that difference is the
    #: whole of what an operator needs to know.
    APPROVAL_REVOKED = "approval_revoked"
    #: It reads approved and the STANDING of its decision was never recorded —
    #: an approval taken before Control held the column.
    #:
    #: Its own member rather than a shade of `NOT_APPROVED`, because the two
    #: send an operator to opposite conclusions: `NOT_APPROVED` means no
    #: approval happened, and this means one did and Control cannot say whether
    #: it still stands. Answering it as `granted` would be reading an
    #: authorization out of a blank column, which is the exact inference the
    #: column exists to remove.
    APPROVAL_STANDING_UNRECORDED = "approval_standing_unrecorded"
    #: Approved, but carrying no execution-plan binding — a `0.1.0a7` plan. An
    #: authorization no executor can verify, so it is refused here rather than
    #: returned for something to fail against later.
    EXECUTION_BINDING_ABSENT = "execution_binding_absent"
    #: Approved and bound, and its frozen snapshot declares no authorized image
    #: set. THIS IS THE ORIGINAL DEFECT, refused rather than answered: an
    #: authorization that cannot say which images it covers is one a consumer
    #: would have to fill in from its own caller, which is the thing this whole
    #: surface exists to stop. Absent is not empty — a plan authorizing NO
    #: images resolves normally, with `()`.
    IMAGE_SET_UNDECLARED = "image_set_undeclared"
    #: The caller named an expected execution-plan digest and the authorization
    #: binds a different one. Only reachable when the caller supplied one; the
    #: lookup never invents a term to compare.
    EXECUTION_PLAN_MISMATCH = "execution_plan_mismatch"
    #: The plan predates the required Foundation canonical-descriptor binding.
    DESCRIPTOR_BINDING_ABSENT = "descriptor_binding_absent"
    #: A caller expected another Foundation descriptor.
    DESCRIPTOR_MISMATCH = "descriptor_mismatch"
    #: No rollout-scoped portable authorization was named or stored.
    AUTHORIZATION_ENVELOPE_ABSENT = "authorization_envelope_absent"
    #: A stored envelope is malformed, mismatched, expired or fails signature.
    AUTHORIZATION_ENVELOPE_INVALID = "authorization_envelope_invalid"
    #: The named rollout authorization does not exist or belongs to another plan.
    AUTHORIZATION_UNRESOLVED = "authorization_unresolved"
    #: Cryptographic verification is injected; silence cannot mean verified.
    AUTHORIZATION_VERIFIER_ABSENT = "authorization_verifier_absent"


@dataclass(frozen=True, slots=True)
class ApprovedPlanRefusal:
    """A typed NO, which a caller cannot read as a yes.

    `code` is the member; `detail` is the sentence for a human. A caller
    branching on the code never has to parse the sentence, and a sentence that
    changes never breaks a caller.
    """

    code: ApprovedPlanRefusalCode
    detail: str
    #: The plan the digest resolved to, when it resolved to one. `None` for the
    #: two digest refusals, where naming a plan would be inventing one.
    plan_id: UUID | None = None
    #: The plan's own status at the moment of the refusal, for the codes where
    #: it is the finding. Never a substitute for `code`.
    plan_status: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovedPlanAuthorization:
    """A STANDING authorization, read from the frozen plan and nothing else.

    Every field here was frozen at proposal or written at approval. Nothing is
    re-derived: notably `execution_plan_digest`, which Control receives from
    the Deployment Foundation and is structurally unable to recompute (its type
    does not inherit a constructor that takes a payload). This view hands back
    what was frozen; it does not reconstruct a Foundation plan.

    `authorized_images` is a tuple and never `None`. A plan with no declared
    image set is REFUSED by the lookup rather than returned with a blank, so no
    consumer can write `for image in auth.authorized_images or ():` and promote
    with nothing checked.
    """

    plan_id: UUID
    target_id: UUID
    target_ref: str
    sequence: int
    desired_revision: int
    #: WHICH approved plan record this is — Control's own snapshot digest, and
    #: the key the lookup was made by.
    plan_digest: str
    #: The Foundation's canonical descriptor digest, preserved byte-identically.
    descriptor_digest: str
    #: WHAT THE FOUNDATION RENDERED, as authorized. A third value, distinct
    #: from `plan_digest` and from a spec digest; see `digests`.
    execution_plan_digest: str
    #: DEPLOY or ROLLBACK — separately authorized operations, never inferred
    #: from one another.
    operation: str
    #: UNDER WHICH POLICY, and which version of it. Both, because a decision
    #: stays explainable only if the policy it was taken under is identified;
    #: a policy code alone reads as current when the policy has since moved.
    approval_policy_code: str | None
    approval_policy_version: int | None
    #: WHICH DECISION, and its STANDING. The standing is always `granted` here
    #: — a revoked one is refused — and it is carried anyway so a receipt can
    #: record what was read rather than what the reader assumed.
    approval_decision_ref: str | None
    approval_decision_status: str
    approved_at: datetime | None
    #: The installed Control distribution that issued and signed the envelope.
    #: Derived by Control from package metadata, never supplied by the caller.
    control_version: str
    #: WHAT MAY RUN. Inside `plan_digest` above, not beside it: the set is part
    #: of the document the digest is taken over, so an approval that binds the
    #: digest binds these images, and an image cannot change without the digest
    #: changing.
    authorized_images: tuple[AuthorizedImage, ...]
    #: Portable authorization whose signature can be verified without this DB.
    authorization_envelope: AuthorizationEnvelopeV2
    release_ref: str | None = None
    licence_ref: str | None = None
    brand_profile_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovedPlanLookup:
    """The lookup's answer: EXACTLY one of an authorization or a refusal.

    ## Why this type has a `__bool__`

    A dataclass is always truthy. `if lookup:` on a plain result object is
    therefore `True` for a refusal, and that is the precise shape of the false
    success this whole surface exists to remove — a consumer asking "is this
    plan approved?" and proceeding because the answer object existed.

    So truthiness IS approval here. `if lookup:` and `if lookup.is_authorized:`
    are the same question, and there is no way to write the check that passes
    on a refusal.

    ## Why absent and negative cannot be confused

    `authorization is None` never stands alone: a lookup with no authorization
    always carries a `refusal` with a typed code, enforced on construction. So
    there is no "empty" answer to mistake for a negative one, and no negative
    one that fails to say why.
    """

    authorization: ApprovedPlanAuthorization | None = None
    refusal: ApprovedPlanRefusal | None = None

    def __post_init__(self) -> None:
        if (self.authorization is None) == (self.refusal is None):
            raise ValueError(
                "an ApprovedPlanLookup carries exactly one of an authorization "
                "or a refusal: both would be a contradiction and neither would "
                "be an empty answer a caller could read as either."
            )

    @property
    def is_authorized(self) -> bool:
        return self.authorization is not None

    def __bool__(self) -> bool:
        """Truthy ONLY for a standing authorization — see the class docstring."""
        return self.is_authorized


@dataclass(frozen=True, slots=True)
class AttemptView:
    """One execution of a rollout."""

    attempt_no: int
    outcome: str
    integrator_ref: str | None
    error_code: str | None
    detail: str | None
    dispatched_at: datetime | None
    settled_at: datetime | None


@dataclass(frozen=True, slots=True)
class RolloutView:
    """A rollout decision and every attempt at it.

    Historical a9 rows retain their exact V1 envelope type for reading. Only a
    V2 envelope is dispatchable; preserving V1 here is history, never promotion.
    """

    id: UUID
    rollout_ref: str
    target_id: UUID
    plan_id: UUID
    status: str
    record_version: int
    authorization_envelope: AuthorizationEnvelopeV1 | AuthorizationEnvelopeV2 | None = (
        None
    )
    reason: str | None = None
    completed_at: datetime | None = None
    attempts: tuple[AttemptView, ...] = ()


@dataclass(frozen=True, slots=True)
class TargetFilter:
    """What an operator may narrow a target list by.

    A closed set of typed fields rather than free text. A browser surface that
    accepted a predicate — a SQL fragment, a sort column, a raw `where` — would
    make every future query the client's decision, and the module could no
    longer say what its own read surface is.

    Every field is optional and they AND together. `page_size` is bounded here
    rather than by the caller, because an unbounded list is how a fleet screen
    becomes a full-table scan the day the fleet grows.
    """

    product_code: str | None = None
    environment: str | None = None
    status: str | None = None
    never_observed: bool | None = None
    page: int = 1
    page_size: int = 50

    MAX_PAGE_SIZE: ClassVar[int] = 200

    def __post_init__(self) -> None:
        if self.page < 1:
            raise ValueError("page is 1-based")
        if not 1 <= self.page_size <= self.MAX_PAGE_SIZE:
            raise ValueError(f"page_size must be 1..{self.MAX_PAGE_SIZE}")


@dataclass(frozen=True, slots=True)
class TargetPage:
    """One page of targets, and enough to render a pager honestly.

    `total` is the count matching the FILTER, not the page, so a surface can say
    "showing 50 of 412" without a second query and without guessing.
    """

    targets: tuple[TargetView, ...]
    total: int
    page: int
    page_size: int

    @property
    def has_more(self) -> bool:
        return self.page * self.page_size < self.total


@dataclass(frozen=True, slots=True)
class PlanProposalPreview:
    """What proposing a plan for this target WOULD freeze, computed server-side.

    This exists so a browser can show an operator the canonical plan and its
    digest before they commit to it — and it is a READ. The digest is derived
    here from the target's current desired state, exactly as `propose_plan`
    derives it, and there is nowhere for a caller to put one of their own.

    That is the structural half of "the browser may never submit its own
    PlanDigest". `ProposePlanCommand` carries no PLAN digest field, so the write
    path cannot accept one; this type carries no input at all, so the read path
    cannot either. A shape where the client COULD supply a digest is a shape
    where someone eventually will, and an approval bound to a client-supplied
    digest is an approval for whatever the client chose to describe.

    The rule is about digests Control DERIVES, and it is unchanged by
    `ProposePlanCommand.execution_plan_digest`, which is the Deployment
    Foundation's value over bytes Control cannot reach. A preview cannot show it
    for exactly that reason: this module has nothing to compute it from, which
    is the same absence that makes it safe to accept from the one caller that
    does.

    `digest_matches_current` is why the preview is not just decoration: a plan
    proposed after the desired state moved is a different plan, and an operator
    looking at a stale preview should be told rather than left to notice.
    """

    target_id: UUID
    target_ref: str
    desired_revision: int
    canonical_plan: Mapping[str, Any]
    plan_digest: str
    #: The EXACT bytes `plan_digest` is taken over, as text.
    #:
    #: Not a convenience rendering of `canonical_plan`. A screen that showed an
    #: operator a pretty-printed mapping beside a digest would be showing them
    #: two things and asking them to believe the second describes the first;
    #: this is the serialization the digest is computed from, so what they read
    #: and what was hashed are one artefact.
    canonical_plan_json: str = ""
    would_supersede_plan_id: UUID | None = None
    digest_matches_current: bool = True
    #: Why proposing would be refused RIGHT NOW, computed from the same
    #: predicates `propose_plan` applies. Empty means the target-state half of
    #: the refusal set is clear; it says nothing about the caller's own command.
    #:
    #: It exists because a browser surface has to decide whether to offer the
    #: action, and that decision is this module's, not a template's. A screen
    #: that worked it out from `status` and `desired_release_ref` in Jinja would
    #: be a second, untested copy of `propose_plan`'s refusals — and the copy
    #: would be the one operators see.
    blocking_reasons: tuple[str, ...] = ()
    #: The same fact as an answer rather than a collection, so no caller has to
    #: turn "is this tuple empty" into an eligibility rule of its own.
    can_propose: bool = True


@dataclass(frozen=True, slots=True)
class ObservationAttemptView:
    """One ARRIVAL, projected for reading — never the row.

    `observation_attempts` returns ORM rows on purpose: it is a triage helper for
    a caller inside this module's transaction. A presentation surface is a
    different consumer with a different rule — a live ORM object handed to a
    template can lazy-load, can be mutated by a render, and ties the screen to a
    schema it does not own — so the browser read path goes through this instead.

    The raw body is deliberately ABSENT. It is attacker-controlled,
    unauthenticated at the moment it was stored, and unbounded in kind; the
    digest and the truncation flag are what an operator triaging an arrival
    needs, and they are safe to render.
    """

    id: UUID
    received_at: datetime
    disposition: str
    signature_status: str
    eligibility_at_receipt: str
    key_id: str | None
    authenticated_target_ref: str | None
    claimed_target_ref: str | None
    report_id: str | None
    raw_body_digest: str | None
    raw_body_truncated: bool
    receipt_id: UUID | None

    @property
    def identity_is_proven(self) -> bool:
        """Derived from the fields rather than stored, so it cannot disagree
        with them — and named for the claim/proof split rather than for the
        column, because `authenticated_target_ref is not None` is the whole of
        what "we know who this was" means here."""
        return self.authenticated_target_ref is not None


@dataclass(frozen=True, slots=True)
class ObservationReceiptView:
    """The canonical receipt for one idempotency key, projected for reading.

    `original_verdict` is returned verbatim to every later replay, so this view
    is the operator-visible half of the stable-verdict rule: what was decided
    about these bytes, when, and under which proven identity.

    Carries `payload_digest` and never `payload`, for the reason
    `ObservationAttemptView` omits the body.
    """

    id: UUID
    authenticated_target_ref: str
    report_id: str
    key_id: str
    first_received_at: datetime
    original_verdict: str
    observed_release_ref: str | None
    observed_spec_digest: str | None
    payload_digest: str | None
    execution_sequence: int | None = None
    attempt_no: int | None = None
    observed_state_digest: str | None = None
    signed_evidence_status: str = "legacy_absent"
    authorization_id: str | None = None
    authorization_plan_id: str | None = None
    authorization_control_version: str | None = None
    authorization_envelope_digest: str | None = None
    rollout_ref: str | None = None
    operation: str | None = None
    release_ref: str | None = None
    authorized_images: tuple[AuthorizedImage, ...] = ()
    observed_images: tuple[AuthorizedImage, ...] = ()
    plan_digest: str | None = None
    descriptor_digest: str | None = None
    execution_plan_digest: str | None = None
    observed_revision: str | None = None
    runtime_identity_kind: str | None = None
    runtime_identity_identifier: str | None = None
    outcome: str | None = None
    observed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ObservationVerdict:
    """What happened to one arrival, and whether it changed anything.

    `disposition` is always set. `changed_state` is the field a caller acts on:
    a replay and a conflict both have a disposition and neither should cause the
    caller to do anything, which is easy to get wrong from the disposition alone.
    """

    disposition: str
    changed_state: bool
    attempt_id: UUID
    receipt_id: UUID | None = None
    verdict: str | None = None


@dataclass(frozen=True, slots=True)
class DriftReport:
    """The computed difference between rolled-out and observed state.

    Computed on demand, never cached — see the module docstring. `drifted` is
    derived from the fields rather than stored, so it cannot disagree with them.

    `never_observed` is distinct from `drifted`: a target that has never reported
    is not known to be wrong, it is unknown, and an operator triaging a fleet
    needs those in different columns. A model that collapsed them would show a
    freshly registered target as a drift incident.
    """

    target_ref: str
    rolled_out_release_ref: str | None
    rolled_out_revision: int | None
    observed_release_ref: str | None
    observed_revision: int | None
    last_observed_at: datetime | None

    @property
    def never_observed(self) -> bool:
        return self.last_observed_at is None

    @property
    def drifted(self) -> bool:
        """True only when something was rolled out AND something was observed
        AND they disagree. Silence is not drift."""
        if self.never_observed or self.rolled_out_revision is None:
            return False
        return (
            self.observed_release_ref != self.rolled_out_release_ref
            or self.observed_revision != self.rolled_out_revision
        )


__all__ = [
    "CREDENTIAL_ACTIVATED_V1",
    "CREDENTIAL_ENROLLED_V1",
    "CREDENTIAL_REVOKED_V1",
    "DRIFT_DETECTED_V1",
    "INTENT_DISPATCHED_V1",
    "OBSERVATION_RECORDED_V1",
    "PLAN_APPROVAL_REVOKED_V1",
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
    "TARGET_DECOMMISSIONED_V1",
    "TARGET_DESIRED_STATE_SET_V1",
    "TARGET_REGISTERED_V1",
    "TARGET_SUSPENDED_V1",
    "ApprovedPlanAuthorization",
    "ApprovedPlanLookup",
    "ApprovedPlanRefusal",
    "ApprovedPlanRefusalCode",
    "AttemptView",
    "AuthorizedImage",
    "DriftReport",
    "ObservationAttemptView",
    "ObservationReceiptView",
    "ObservationVerdict",
    "PlanProposalPreview",
    "PlanView",
    "RolloutView",
    "TargetFilter",
    "TargetPage",
    "TargetView",
]
