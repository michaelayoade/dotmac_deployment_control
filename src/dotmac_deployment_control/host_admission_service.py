"""Control-owned append-only host binding and admission-policy services.

Association and policy rows plus their closure rows are durable truth. The
``target_current_*`` tables are mutable accelerators only. Every admission read
derives the open row from history and refuses absence, ambiguity, or projection
drift; it never repairs a projection as a side effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_deployment_control.host_attester_enrolment import (
    HostAttesterEnrolmentRefusedError,
    require_host_id,
)
from dotmac_deployment_control.models import (
    DeploymentTarget,
    TargetAdmissionPolicy,
    TargetAdmissionPolicyClosure,
    TargetCurrentAdmissionPolicy,
    TargetCurrentHost,
    TargetHostAssociation,
    TargetHostAssociationClosure,
)
from dotmac_deployment_control.ports import TransitionRefusedError


class HostAdmissionStateRefusalCode(StrEnum):
    HOST_ABSENT = "target_host_association_absent"
    HOST_AMBIGUOUS = "target_host_association_ambiguous"
    HOST_DRIFT = "target_host_association_projection_drift"
    HOST_ALREADY_BOUND = "target_host_association_already_bound"
    POLICY_ABSENT = "target_admission_policy_absent"
    POLICY_AMBIGUOUS = "target_admission_policy_ambiguous"
    POLICY_DRIFT = "target_admission_policy_projection_drift"
    POLICY_ALREADY_SET = "target_admission_policy_already_set"
    MALFORMED = "target_admission_state_malformed"


class HostAdmissionStateRefusedError(TransitionRefusedError):
    def __init__(self, code: HostAdmissionStateRefusalCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


@dataclass(frozen=True, slots=True)
class BindTargetHostCommand:
    target_id: UUID
    host_id: str
    authority: str


@dataclass(frozen=True, slots=True)
class SetTargetAdmissionPolicyCommand:
    target_id: UUID
    candidate_root_subject: str
    candidate_audience: str
    installed_audience: str
    expected_foundation_package: str
    authority: str


@dataclass(frozen=True, slots=True)
class TargetHostAssociationView:
    association_id: UUID
    target_id: UUID
    host_id: str
    bound_at: datetime
    authority: str


@dataclass(frozen=True, slots=True)
class TargetAdmissionPolicyView:
    policy_id: UUID
    target_id: UUID
    host_association_id: UUID
    candidate_root_subject: str
    candidate_audience: str
    installed_audience: str
    expected_foundation_package: str
    effective_at: datetime
    authority: str


def _refuse(
    code: HostAdmissionStateRefusalCode, detail: str
) -> HostAdmissionStateRefusedError:
    return HostAdmissionStateRefusedError(code, detail)


def _text(value: str, *, where: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _refuse(
            HostAdmissionStateRefusalCode.MALFORMED,
            f"{where} must be non-empty exact text",
        )
    return value


def _control_now() -> datetime:
    return datetime.now(UTC)


def lock_target(db: Session, target_id: UUID) -> DeploymentTarget:
    """Acquire the first lock in every host-admission mutation/read order."""
    row = db.execute(
        select(DeploymentTarget)
        .where(DeploymentTarget.id == target_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        raise TransitionRefusedError(f"deployment target {target_id} not found")
    return row


def _open_host_associations(
    db: Session, target_id: UUID
) -> list[TargetHostAssociation]:
    closed = select(TargetHostAssociationClosure.association_id)
    return list(
        db.execute(
            select(TargetHostAssociation).where(
                TargetHostAssociation.target_id == target_id,
                TargetHostAssociation.id.not_in(closed),
            )
        ).scalars()
    )


def _current_host_pointer(db: Session, target_id: UUID) -> TargetCurrentHost | None:
    return db.execute(
        select(TargetCurrentHost)
        .where(TargetCurrentHost.target_id == target_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()


def require_current_target_host_locked(
    db: Session, target_id: UUID
) -> TargetHostAssociationView:
    """Resolve history after the caller has locked the target first."""
    open_rows = _open_host_associations(db, target_id)
    pointer = _current_host_pointer(db, target_id)
    if not open_rows:
        if pointer is not None:
            raise _refuse(
                HostAdmissionStateRefusalCode.HOST_DRIFT,
                "current-host projection exists but append-only truth is closed",
            )
        raise _refuse(
            HostAdmissionStateRefusalCode.HOST_ABSENT,
            "target has no open host association",
        )
    if len(open_rows) != 1:
        raise _refuse(
            HostAdmissionStateRefusalCode.HOST_AMBIGUOUS,
            f"target has {len(open_rows)} open host associations",
        )
    row = open_rows[0]
    if pointer is None or pointer.association_id != row.id:
        raise _refuse(
            HostAdmissionStateRefusalCode.HOST_DRIFT,
            "current-host projection disagrees with append-only truth",
        )
    # `bind_target_host`/`rotate_target_host` both validate `host_id` through
    # `require_host_id` before writing it; re-validating here treats the
    # stored value as a CLAIM, not a fact, the same way `resolve_current_root`
    # recomputes the fingerprint rather than trusting the stored column. A
    # `platform_api` write that bypassed the ORM service (an `INSERT` is not
    # constrained by the append-only trigger the way `UPDATE`/`DELETE` are)
    # cannot forge a coherent-looking association with a host_id that fails
    # Fleet's own grammar.
    try:
        host_id = require_host_id(row.host_id, where="current target host")
    except HostAttesterEnrolmentRefusedError as exc:
        raise _refuse(
            HostAdmissionStateRefusalCode.MALFORMED,
            f"stored host association {row.id} failed re-validation: {exc}",
        ) from exc
    return TargetHostAssociationView(
        association_id=row.id,
        target_id=row.target_id,
        host_id=host_id,
        bound_at=row.bound_at,
        authority=row.authority,
    )


def resolve_current_target_host(
    db: Session, *, target_id: UUID
) -> TargetHostAssociationView:
    lock_target(db, target_id)
    return require_current_target_host_locked(db, target_id)


def _open_policies(db: Session, target_id: UUID) -> list[TargetAdmissionPolicy]:
    closed = select(TargetAdmissionPolicyClosure.policy_id)
    return list(
        db.execute(
            select(TargetAdmissionPolicy).where(
                TargetAdmissionPolicy.target_id == target_id,
                TargetAdmissionPolicy.id.not_in(closed),
            )
        ).scalars()
    )


def _current_policy_pointer(
    db: Session, target_id: UUID
) -> TargetCurrentAdmissionPolicy | None:
    return db.execute(
        select(TargetCurrentAdmissionPolicy)
        .where(TargetCurrentAdmissionPolicy.target_id == target_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()


def _policy_view(row: TargetAdmissionPolicy) -> TargetAdmissionPolicyView:
    return TargetAdmissionPolicyView(
        policy_id=row.id,
        target_id=row.target_id,
        host_association_id=row.host_association_id,
        candidate_root_subject=row.candidate_root_subject,
        candidate_audience=row.candidate_audience,
        installed_audience=row.installed_audience,
        expected_foundation_package=row.expected_foundation_package,
        effective_at=row.effective_at,
        authority=row.authority,
    )


def require_current_target_admission_policy_locked(
    db: Session, target_id: UUID
) -> TargetAdmissionPolicyView:
    """Resolve policy history after the caller has locked the target first."""
    open_rows = _open_policies(db, target_id)
    pointer = _current_policy_pointer(db, target_id)
    if not open_rows:
        if pointer is not None:
            raise _refuse(
                HostAdmissionStateRefusalCode.POLICY_DRIFT,
                "current-policy projection exists but append-only truth is closed",
            )
        raise _refuse(
            HostAdmissionStateRefusalCode.POLICY_ABSENT,
            "target has no open admission policy",
        )
    if len(open_rows) != 1:
        raise _refuse(
            HostAdmissionStateRefusalCode.POLICY_AMBIGUOUS,
            f"target has {len(open_rows)} open admission policies",
        )
    row = open_rows[0]
    if pointer is None or pointer.policy_id != row.id:
        raise _refuse(
            HostAdmissionStateRefusalCode.POLICY_DRIFT,
            "current-policy projection disagrees with append-only truth",
        )
    return _policy_view(row)


def resolve_current_target_admission_policy(
    db: Session, *, target_id: UUID
) -> TargetAdmissionPolicyView:
    lock_target(db, target_id)
    return require_current_target_admission_policy_locked(db, target_id)


def bind_target_host(db: Session, command: BindTargetHostCommand) -> UUID:
    lock_target(db, command.target_id)
    host_id = require_host_id(command.host_id, where="target host association")
    authority = _text(command.authority, where="association authority")
    open_rows = _open_host_associations(db, command.target_id)
    pointer = _current_host_pointer(db, command.target_id)
    if open_rows or pointer is not None:
        if len(open_rows) == 1 and pointer is not None:
            raise _refuse(
                HostAdmissionStateRefusalCode.HOST_ALREADY_BOUND,
                "target already has a current host; rotate it explicitly",
            )
        raise _refuse(
            HostAdmissionStateRefusalCode.HOST_DRIFT,
            "host history and current projection disagree before bind",
        )
    row = TargetHostAssociation(
        id=uuid4(),
        target_id=command.target_id,
        host_id=host_id,
        bound_at=_control_now(),
        authority=authority,
    )
    db.add(row)
    # The projection's FK is immediate on PostgreSQL.  Flush append-only truth
    # before its mutable pointer; do not rely on ORM unit-of-work ordering for
    # two separately mapped rows with no relationship property between them.
    db.flush([row])
    db.add(TargetCurrentHost(target_id=command.target_id, association_id=row.id))
    db.flush()
    return row.id


def rotate_target_host(db: Session, command: BindTargetHostCommand) -> UUID:
    lock_target(db, command.target_id)
    current = require_current_target_host_locked(db, command.target_id)
    authority = _text(command.authority, where="association authority")
    row = TargetHostAssociation(
        id=uuid4(),
        target_id=command.target_id,
        host_id=require_host_id(command.host_id, where="target host association"),
        bound_at=_control_now(),
        authority=authority,
    )
    db.add(row)
    # Both the closure successor and the projection point at this row.
    db.flush([row])
    db.add(
        TargetHostAssociationClosure(
            association_id=current.association_id,
            closed_at=row.bound_at,
            authority=authority,
            successor_id=row.id,
        )
    )
    pointer = _current_host_pointer(db, command.target_id)
    assert pointer is not None
    pointer.association_id = row.id
    db.flush()
    return row.id


def revoke_target_host(db: Session, *, target_id: UUID, authority: str) -> None:
    lock_target(db, target_id)
    current = require_current_target_host_locked(db, target_id)
    db.add(
        TargetHostAssociationClosure(
            association_id=current.association_id,
            closed_at=_control_now(),
            authority=_text(authority, where="association authority"),
            successor_id=None,
        )
    )
    pointer = _current_host_pointer(db, target_id)
    assert pointer is not None
    db.delete(pointer)
    db.flush()


def _validated_policy_values(
    command: SetTargetAdmissionPolicyCommand,
) -> tuple[str, str, str, str, str]:
    return (
        _text(command.candidate_root_subject, where="candidate root subject"),
        _text(command.candidate_audience, where="candidate audience"),
        _text(command.installed_audience, where="installed audience"),
        _text(command.expected_foundation_package, where="Foundation package"),
        _text(command.authority, where="policy authority"),
    )


def _new_policy(
    command: SetTargetAdmissionPolicyCommand,
    *,
    host_association_id: UUID,
    effective_at: datetime,
) -> TargetAdmissionPolicy:
    candidate_subject, candidate_audience, installed_audience, package, authority = (
        _validated_policy_values(command)
    )
    return TargetAdmissionPolicy(
        id=uuid4(),
        target_id=command.target_id,
        host_association_id=host_association_id,
        candidate_root_subject=candidate_subject,
        candidate_audience=candidate_audience,
        installed_audience=installed_audience,
        expected_foundation_package=package,
        effective_at=effective_at,
        authority=authority,
    )


def set_target_admission_policy(
    db: Session, command: SetTargetAdmissionPolicyCommand
) -> UUID:
    lock_target(db, command.target_id)
    association = require_current_target_host_locked(db, command.target_id)
    open_rows = _open_policies(db, command.target_id)
    pointer = _current_policy_pointer(db, command.target_id)
    if open_rows or pointer is not None:
        if len(open_rows) == 1 and pointer is not None:
            raise _refuse(
                HostAdmissionStateRefusalCode.POLICY_ALREADY_SET,
                "target already has a current policy; revise it explicitly",
            )
        raise _refuse(
            HostAdmissionStateRefusalCode.POLICY_DRIFT,
            "policy history and current projection disagree before set",
        )
    row = _new_policy(
        command,
        host_association_id=association.association_id,
        effective_at=_control_now(),
    )
    db.add(row)
    db.flush([row])
    db.add(TargetCurrentAdmissionPolicy(target_id=command.target_id, policy_id=row.id))
    db.flush()
    return row.id


def revise_target_admission_policy(
    db: Session, command: SetTargetAdmissionPolicyCommand
) -> UUID:
    lock_target(db, command.target_id)
    association = require_current_target_host_locked(db, command.target_id)
    current = require_current_target_admission_policy_locked(db, command.target_id)
    when = _control_now()
    row = _new_policy(
        command, host_association_id=association.association_id, effective_at=when
    )
    db.add(row)
    # Both the closure successor and the projection point at this row.
    db.flush([row])
    db.add(
        TargetAdmissionPolicyClosure(
            policy_id=current.policy_id,
            closed_at=when,
            authority=row.authority,
            successor_id=row.id,
        )
    )
    pointer = _current_policy_pointer(db, command.target_id)
    assert pointer is not None
    pointer.policy_id = row.id
    db.flush()
    return row.id


def revoke_target_admission_policy(
    db: Session, *, target_id: UUID, authority: str
) -> None:
    lock_target(db, target_id)
    current = require_current_target_admission_policy_locked(db, target_id)
    db.add(
        TargetAdmissionPolicyClosure(
            policy_id=current.policy_id,
            closed_at=_control_now(),
            authority=_text(authority, where="policy authority"),
            successor_id=None,
        )
    )
    pointer = _current_policy_pointer(db, target_id)
    assert pointer is not None
    db.delete(pointer)
    db.flush()


__all__ = [
    "BindTargetHostCommand",
    "HostAdmissionStateRefusalCode",
    "HostAdmissionStateRefusedError",
    "SetTargetAdmissionPolicyCommand",
    "TargetAdmissionPolicyView",
    "TargetHostAssociationView",
    "bind_target_host",
    "lock_target",
    "require_current_target_admission_policy_locked",
    "require_current_target_host_locked",
    "resolve_current_target_admission_policy",
    "resolve_current_target_host",
    "revise_target_admission_policy",
    "revoke_target_admission_policy",
    "revoke_target_host",
    "rotate_target_host",
    "set_target_admission_policy",
]
