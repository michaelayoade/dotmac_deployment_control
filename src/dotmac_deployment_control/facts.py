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
from typing import Any, ClassVar, Final
from uuid import UUID

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
    requires_approval: bool = True
    approval_policy_code: str | None = None
    approval_policy_version: int | None = None
    approval_decision_ref: str | None = None
    approved_at: datetime | None = None
    superseded_by_id: UUID | None = None
    snapshot: Mapping[str, Any] = field(default_factory=dict)


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
    """A rollout decision and every attempt at it."""

    id: UUID
    rollout_ref: str
    target_id: UUID
    plan_id: UUID
    status: str
    record_version: int
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
    PlanDigest". `ProposePlanCommand` carries no digest field, so the write path
    cannot accept one; this type carries no input at all, so the read path
    cannot either. A shape where the client COULD supply a digest is a shape
    where someone eventually will, and an approval bound to a client-supplied
    digest is an approval for whatever the client chose to describe.

    `digest_matches_current` is why the preview is not just decoration: a plan
    proposed after the desired state moved is a different plan, and an operator
    looking at a stale preview should be told rather than left to notice.
    """

    target_id: UUID
    target_ref: str
    desired_revision: int
    canonical_plan: Mapping[str, Any]
    plan_digest: str
    would_supersede_plan_id: UUID | None = None
    digest_matches_current: bool = True


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
    "AttemptView",
    "DriftReport",
    "ObservationVerdict",
    "PlanView",
    "RolloutView",
    "TargetView",
]
