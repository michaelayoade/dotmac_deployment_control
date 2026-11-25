"""The reconcile-marker issue rule for a persistent host's expired lease.

A lease that expired UNRELEASED leaves the host standing `EXPIRED_UNRELEASED`:
nobody knows whether a run mutated it. The next acquire needs a reconcile
marker. This rule lets that self-heal without a staff queue:

* the agent posts a signed, READ-ONLY reconcile observation of what runs;
* if the observed release equals the last committed release or the planned
  release, Control issues the marker automatically;
* otherwise the target goes to the existing restore-and-fix-forward path under
  the operator's next set approval, and NO marker is issued.

A marker is never issued without a verified, read-only observation, and never
for any standing other than `EXPIRED_UNRELEASED`. Pure decision: no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from dotmac_deployment_control.deploy_unit import DeployUnitError

EXPIRED_UNRELEASED: Final = "EXPIRED_UNRELEASED"
MARKER_ISSUED: Final = "marker_issued"
RESTORE_AND_FIX_FORWARD: Final = "restore_and_fix_forward"


class ReconcileRefusedError(DeployUnitError):
    """The observation cannot be used to decide; nothing is issued."""


@dataclass(frozen=True, slots=True)
class ReconcileObservation:
    """The agent's signed read-only observation, already signature-verified."""

    observed_release_ref: str
    signature_verified: bool
    read_only: bool


@dataclass(frozen=True, slots=True)
class ReconcileDecision:
    outcome: str
    reason: str

    @property
    def issue_marker(self) -> bool:
        return self.outcome == MARKER_ISSUED


def decide_reconcile_marker(
    *,
    standing: str,
    observation: ReconcileObservation,
    last_committed_release_ref: str | None,
    planned_release_ref: str,
) -> ReconcileDecision:
    if standing != EXPIRED_UNRELEASED:
        raise ReconcileRefusedError(
            "a reconcile marker applies only to a lease that expired unreleased"
        )
    if not observation.signature_verified:
        raise ReconcileRefusedError("the reconcile observation is not verified")
    if not observation.read_only:
        raise ReconcileRefusedError("the reconcile observation must be read-only")
    observed = observation.observed_release_ref
    if not observed.strip() or not planned_release_ref.strip():
        raise ReconcileRefusedError("an observed and a planned release are required")
    if observed == last_committed_release_ref or observed == planned_release_ref:
        return ReconcileDecision(MARKER_ISSUED, "observed release matches")
    return ReconcileDecision(
        RESTORE_AND_FIX_FORWARD,
        "observed release matches neither the last committed nor the planned one",
    )
