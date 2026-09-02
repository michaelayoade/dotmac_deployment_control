"""The standing of an approval DECISION: `granted`, or granted-then-`revoked`.

## Why the standing needs a column at all

`deployment_plans` already recorded `approval_decision_ref` — WHICH decision
approved the plan — and `approved_at`, and the plan's own `status` moving to
`approved`. What it did not record is whether that decision still STANDS.

The gap is not academic. A consumer asking "is this plan approved?" got the
plan's status, and a plan whose approval had been withdrawn still read
`approved` — a yes for a revoked authorization, which is worse than no answer
at all, because a caller who is refused goes and looks.

## Two members, and the set is closed

`GRANTED` and `REVOKED`, and there is deliberately no `REJECTED`, `PENDING` or
`EXPIRED`.

Control does not run an approval lifecycle — `dotmac-approvals` does (ADR-0026
§ 6, ADR-0024), and this module never calls it. What Control holds is the
standing of a decision it was HANDED, and a decision it was handed is one that
granted; a rejection produces no record here because there is nothing to
record it against. Adding the members an approvals system has would make this
enum look like a second copy of that lifecycle, and a second copy is a thing
that eventually disagrees.

So: a decision arrives `granted`, and may later become `revoked`. That is the
whole vocabulary, and every other state belongs to the system that owns it.

## Never inferred, in either direction

`approve_plan` REQUIRES the status on the evidence. Treating "this evidence
reached `approve_plan`" as meaning granted is the same inference a defaulted
`operation` makes — a caller's silence deciding an authorization — and it is
the one this module already refuses everywhere else.

And `revoked` evidence is refused rather than absorbed. A replayed revocation
arriving at the approve path is exactly the arrival that must not become an
approval, and it is far more likely than a hand-typed wrong word.

## Why the plan's own `status` does not move on revocation

One fact, one owner. `PlanStatus.APPROVED` is history — the plan WAS approved,
on evidence, at a recorded time — and rewriting it would delete that. This
column owns "does the approval still stand", `request_rollout` refuses a plan
whose approval does not, and `find_approved_plan` refuses it with its own code.
A second `PlanStatus.REVOKED` member would be a derived copy of this column
with a second writer, which is the shape ADR-0010 exists to prevent.
"""

from __future__ import annotations

from enum import StrEnum

from dotmac_deployment_control.ports import ApprovalRefusedError

__all__ = [
    "APPROVAL_DECISION_STATUSES",
    "ApprovalDecisionStatus",
    "require_decision_status",
]


class ApprovalDecisionStatus(StrEnum):
    """`GRANTED` — the decision authorizes the plan. `REVOKED` — it no longer does."""

    GRANTED = "granted"
    REVOKED = "revoked"


#: The closed set as text, written FROM the enum so a member cannot exist in
#: one and not the other.
APPROVAL_DECISION_STATUSES: frozenset[str] = frozenset(
    member.value for member in ApprovalDecisionStatus
)


def require_decision_status(value: object, *, where: str) -> ApprovalDecisionStatus:
    """The ONE gate. Exactly a member, exactly spelled, or refused.

    An `ApprovalRefusedError` and not a vocabulary error of its own: unlike an
    unknown OPERATION — which is a fault in whoever wrote the caller — an
    unreadable decision status arrives on approval evidence, and the reader is
    whoever approves deployments. The refusals stay in that person's inbox.
    """
    if isinstance(value, ApprovalDecisionStatus):
        return value
    if not isinstance(value, str):
        raise ApprovalRefusedError(
            f"{where}: an approval decision status must be one of "
            f"{sorted(APPROVAL_DECISION_STATUSES)}, and this is a "
            f"{type(value).__name__}. There is no default: a decision's "
            "standing is stated by the authority that decided, never inferred "
            "from the evidence having arrived."
        )
    if value not in APPROVAL_DECISION_STATUSES:
        hint = ""
        if value.strip().lower() in APPROVAL_DECISION_STATUSES:
            hint = (
                f" {value.strip().lower()!r} is a member and {value!r} is not; "
                "the spelling is exact, because one decision standing with two "
                "spellings is one standing with two identities."
            )
        raise ApprovalRefusedError(
            f"{where}: {value!r} is not a decision standing this control plane "
            f"records. The vocabulary is closed to "
            f"{sorted(APPROVAL_DECISION_STATUSES)} — Control holds the standing "
            "of a decision it was handed, not a second copy of the approvals "
            f"lifecycle that owns every other state.{hint}"
        )
    return ApprovalDecisionStatus(value)
