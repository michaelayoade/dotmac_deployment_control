"""Private staged rehearsal consumption; only a post-commit adapter may launch."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_deployment_control.models import RehearsalGrant, RehearsalGrantState
from dotmac_deployment_control.ports import DeploymentControlError


class _Refused(DeploymentControlError):
    pass


@dataclass(frozen=True, slots=True)
class _StagedRehearsalConsumption:
    grant_id: str
    single_use_reference: str


def _locked(db: Session, grant_id: str, reference: str) -> RehearsalGrant:
    row = db.execute(
        select(RehearsalGrant)
        .where(
            RehearsalGrant.grant_id == grant_id,
            RehearsalGrant.single_use_reference == reference,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        raise _Refused("unknown rehearsal grant reference")
    return row


def _stage_rehearsal_consumption(
    db: Session, *, grant_id: str, single_use_reference: str
) -> _StagedRehearsalConsumption:
    """Flush a permanent cut-off in caller transaction; this is NOT launch authority."""
    row = _locked(db, grant_id, single_use_reference)
    if row.state == RehearsalGrantState.REVOKED.value:
        raise _Refused("rehearsal grant revoked")
    if row.state == RehearsalGrantState.SPENT.value:
        raise _Refused("rehearsal grant already spent")
    row.state = RehearsalGrantState.SPENT.value
    row.spent_at = datetime.now(UTC)
    db.flush()
    return _StagedRehearsalConsumption(grant_id, single_use_reference)


def _revoke_rehearsal_grant(
    db: Session, *, grant_id: str, single_use_reference: str, revocation_ref: str
) -> None:
    """Same lock; a committed spend wins over a concurrent revocation."""
    if not revocation_ref.strip():
        raise _Refused("rehearsal revocation requires a non-empty reference")
    if len(revocation_ref) > 200:
        raise _Refused("rehearsal revocation reference exceeds 200 characters")
    row = _locked(db, grant_id, single_use_reference)
    if row.state != RehearsalGrantState.ISSUED.value:
        raise _Refused("grant is not revocable")
    row.state, row.revoked_at, row.revocation_ref = (
        RehearsalGrantState.REVOKED.value,
        datetime.now(UTC),
        revocation_ref,
    )
    db.flush()
