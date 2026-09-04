"""What the EXECUTOR can honour — pinned here, because Control cannot import it.

`operations.py` argues that Control's vocabulary is closed so that it cannot
*"freeze, sign and dispatch an authorization the executor is structurally unable
to honour — an approval that reads as valid on every screen in this system and
can never produce a receipt."* That argument was true and unenforced. `recover`
entered at `0.1.0a10` on the stated premise that the Deployment Foundation's
`a5` was being built against the same three members; the Foundation withdrew
`recover` and recorded the reversal, which falsified the premise, and nothing on
this side refused the word afterwards.

This module is the enforcement the argument always implied.

## Why a pinned literal and not an import

Control does not depend on the Foundation and must not start: they are released
independently, and a control plane that imported its executor to find out what
it may authorize would be unable to answer the question at all when the executor
is absent. But the alternative usually chosen — import it if installed, skip the
check otherwise — is worse than nothing here. **A guard that skips is a guard
that is off**, and this repository's CI does not install the Foundation, so a
skipping check would have been silent for exactly the releases that needed it.

So the counterparty's published vocabulary is a literal with provenance. The
primary refusal always runs. When the Foundation IS importable,
`tests/unit/test_counterparty_vocabulary.py` additionally compares this pin
against the installed distribution, so the pin cannot drift from the thing it
claims to mirror without something saying so.

## Provenance, stated rather than implied

Read on 2026-09-04 from
`packages/dotmac-deployment-foundation/src/dotmac_deployment_foundation/authorization.py`
in `michaelayoade/dotmac_starter_mt` at commit
`5dcb3d1184d0e5ee7544966f77ead47cdd020e64`, where the package declares version
`0.4.0a1` and `OPERATIONS = ("deploy", "rollback")`. The same two members hold
at `0.3.0a6`, per the withdrawal note recorded in that same file.

This is a claim about SOURCE at an immutable commit. It is deliberately not a
claim that a particular wheel is published, which this repository cannot verify
without an oracle it does not have here.
"""

from __future__ import annotations

from typing import Final

from dotmac_deployment_control.operations import (
    OPERATIONS,
    DeploymentOperation,
    require_operation,
)
from dotmac_deployment_control.ports import OperationNotExecutableError

__all__ = [
    "EXECUTOR_DISTRIBUTION",
    "EXECUTOR_OPERATIONS",
    "EXECUTOR_SOURCE_COMMIT",
    "EXECUTOR_SOURCE_REPOSITORY",
    "EXECUTOR_SOURCE_VERSION",
    "require_executable_operation",
    "unexecutable_operations",
]

EXECUTOR_DISTRIBUTION: Final = "dotmac-deployment-foundation"
EXECUTOR_SOURCE_REPOSITORY: Final = "michaelayoade/dotmac_starter_mt"
EXECUTOR_SOURCE_COMMIT: Final = "5dcb3d1184d0e5ee7544966f77ead47cdd020e64"
EXECUTOR_SOURCE_VERSION: Final = "0.4.0a1"

#: The operations the executor has published support for. A member of this
#: control plane's vocabulary that is absent here can be NAMED but not acted on.
EXECUTOR_OPERATIONS: Final[frozenset[str]] = frozenset({"deploy", "rollback"})


def unexecutable_operations() -> frozenset[str]:
    """Members this control plane can name and the executor cannot honour.

    Derived from both sets rather than listed, so it cannot say `recover` after
    the executor gains it, or stay empty after this vocabulary grows.
    """
    return frozenset(OPERATIONS) - EXECUTOR_OPERATIONS


def require_executable_operation(value: object, *, where: str) -> DeploymentOperation:
    """The gate for FREEZING, SIGNING and DISPATCHING. Never for reading.

    An operation still has to be a member of this vocabulary, so this begins
    with `require_operation` and keeps its refusal. It then adds the question
    that vocabulary membership never answered: can the counterparty perform it?

    Read paths deliberately do NOT call this. A plan written by an earlier
    version may carry an operation the executor has since stopped supporting,
    and that row must stay readable -- an authorization trail that becomes
    unparsable when a counterparty changes is a record that rewrites itself.
    """
    operation = require_operation(value, where=where)
    if operation.value in EXECUTOR_OPERATIONS:
        return operation
    raise OperationNotExecutableError(
        f"{where}: {operation.value!r} is an operation this control plane can "
        f"name and {EXECUTOR_DISTRIBUTION} has not published support for. Its "
        f"vocabulary is {sorted(EXECUTOR_OPERATIONS)}, read from "
        f"{EXECUTOR_SOURCE_REPOSITORY} at {EXECUTOR_SOURCE_COMMIT}. Freezing, "
        "signing or dispatching it would produce an authorization that reads "
        "as valid on every screen in this system and can never produce a "
        "receipt. A recovery is authorized by a RecoveryGrantV1, which binds "
        "what a deployment authorization cannot."
    )
