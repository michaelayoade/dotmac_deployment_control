"""The CLOSED operation vocabulary: `deploy` and `rollback`, and nothing else.

## Why this one vocabulary is closed when every other one here is open

`models.py` says it plainly: status, environment and disposition are text with
no CHECK, because ADR-0008's rule is that adding a lifecycle member should cost
a module release and not an `ALTER TYPE` on every deployment. That rule is
right, and this is not an exception to it — it is a different situation.

A status is a word Control says to itself. An OPERATION is a word Control says
to an executor that has already decided which words it will accept: the
Deployment Foundation refuses any receipt whose operation is not `deploy` or
`rollback`. So an open vocabulary here would let Control freeze, sign and
dispatch an authorization the executor is structurally unable to honour — an
approval that reads as valid on every screen in this system and can never
produce a receipt. The closure is not a taste for enums; it is Control agreeing
to speak only in the vocabulary its counterparty already published.

Adding a third member is therefore a change to BOTH systems, coordinated, and
that is exactly the cost it should carry.

## Never inferred

There is no default and no fallback. `require_operation` refuses `None`, the
empty string, an unknown word and a differently-cased spelling of a known one.
It refuses rather than coercing, because every coercion is an inference:

* a DEFAULT infers the operation from the caller's silence;
* a CASE FOLD infers that `Deploy` meant `deploy`, which is the same guess the
  digest parser refuses for the same reason — one value with two spellings is
  one value with two identities;
* a DIFF or a COMMAND NAME infers it from the shape of a change, and a rollback
  that looks like a deploy because the artifact happens to be older is the
  precise failure this closure exists to prevent.

DEPLOY and ROLLBACK are separately authorized operations. Whoever decided one
did not thereby decide the other, and no rule in this module may quietly turn
one into the other.
"""

from __future__ import annotations

from enum import StrEnum

from dotmac_deployment_control.ports import OperationRefusedError

__all__ = [
    "OPERATIONS",
    "DeploymentOperation",
    "require_operation",
]


class DeploymentOperation(StrEnum):
    """What an authorization authorizes. Two members, and the set is closed.

    `DEPLOY` — converge a target on the plan's artifact. `ROLLBACK` — return it
    to a previously deployed one. They are separate authorizations: an approval
    of one is never an approval of the other, and nothing in this module derives
    one from the other.
    """

    DEPLOY = "deploy"
    ROLLBACK = "rollback"


#: The closed set, as text. Written from the enum rather than beside it, so a
#: member can never exist in one and not the other.
OPERATIONS: frozenset[str] = frozenset(member.value for member in DeploymentOperation)


def require_operation(value: object, *, where: str) -> DeploymentOperation:
    """The ONE gate. Anything that is not exactly a member is refused.

    Returns the enum member so callers hold a VALUE rather than a string, for
    the same reason `PlanDigestV1` exists: a comparison over text is a
    comparison that can be got wrong quietly, and this one decides whether a
    deployment or a rollback was authorized.
    """
    if isinstance(value, DeploymentOperation):
        return value
    if not isinstance(value, str):
        raise OperationRefusedError(
            f"{where}: an operation must be one of {sorted(OPERATIONS)}, and "
            f"this is a {type(value).__name__}. There is no default: an "
            "operation is declared, never inferred from a diff, a command name "
            "or a caller's silence."
        )
    if value not in OPERATIONS:
        hint = ""
        if value.strip().lower() in OPERATIONS:
            hint = (
                f" {value.strip().lower()!r} is a member and {value!r} is not; "
                "the spelling is exact, because one operation with two "
                "spellings is one operation with two identities."
            )
        raise OperationRefusedError(
            f"{where}: {value!r} is not an operation this control plane can "
            f"authorize. The vocabulary is closed to {sorted(OPERATIONS)} "
            "because the executor refuses anything else — an unknown value "
            "signed here would be an authorization that can never produce a "
            f"receipt.{hint}"
        )
    return DeploymentOperation(value)
