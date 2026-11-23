"""Control's decision about a reconcile observation: does it clear the host?

The agent reports FACTS (which containers are configured, which image each runs).
Control decides. The decision is a pure function over those facts and what Control
knows of the expired plan and the last committed release:

* every configured container runs a digest from the EXPIRED plan: the marker is
  issued and recorded as `reconciled` (the interrupted deploy left the host in
  the state it was authorised to reach);
* every configured container runs a digest of the LAST COMMITTED release and the
  expired dispatch was never consumed: the marker is issued as `not_needed` (the
  host never left the committed state);
* anything else: NO marker. The host is in a state nobody authorised, and the
  target goes to the attended restore-and-fix-forward path.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any, Final

from dotmac_deployment_control.agent_observation import (
    ReconcileContainerV2,
    parse_reconcile_details,
)
from dotmac_deployment_control.execution_observation import (
    ExecutionObservationRefusedError,
)

MARKER_RECONCILED: Final = "reconciled"
MARKER_NOT_NEEDED: Final = "not_needed"


def container_digests(container: ReconcileContainerV2) -> frozenset[str]:
    """The sha256 digests a container's image is known by: the digest part of each
    `repo@sha256:...` and the image id when it is itself a sha256."""
    found = {d.split("@", 1)[1] for d in container.repo_digests if "@" in d}
    if container.image_id.startswith("sha256:"):
        found.add(container.image_id)
    return frozenset(found)


def decide_reconcile(
    details: Mapping[str, Any],
    *,
    expired_dispatch_id: str,
    expired_plan_digests: Collection[str],
    last_committed_digests: Collection[str],
    expired_dispatch_consumed: bool,
) -> str | None:
    """`reconciled`, `not_needed` or None (no marker). Malformed facts are None."""
    try:
        facts = parse_reconcile_details(details)
    except ExecutionObservationRefusedError:
        return None
    if facts.expired_dispatch_id != expired_dispatch_id or not facts.configured:
        return None
    by_name = {c.name: c for c in facts.containers}
    if len(by_name) != len(facts.containers) or any(
        name not in by_name for name in facts.configured
    ):
        return None  # a configured container the agent did not observe
    observed = [container_digests(by_name[name]) for name in facts.configured]
    expired, committed = set(expired_plan_digests), set(last_committed_digests)
    if expired and all(digests & expired for digests in observed):
        return MARKER_RECONCILED
    if (
        not expired_dispatch_consumed
        and committed
        and all(digests & committed for digests in observed)
    ):
        return MARKER_NOT_NEEDED
    return None
