"""Control's own durable attestation trust registry.

## The defect this module closes

`host_attester_enrolment.evaluate_enrolment` and `host_attester_standing` are
pure functions over a caller-supplied `active_by_host` mapping and a
caller-supplied `known_fingerprints` mapping -- that module's docstring says
plainly: "the caller currently supplies the registry that decides whether the
caller's key is trusted", and "no table added here." Foundation and Platform
need Control-RESOLVED trust roots for both custody domains an attester key can
hold (`models.AttestationCustodyDomain`): the Foundation release-signer root,
and a per-host attester incarnation. Neither can be resolved from a durable
table today, because none exists. This module is that table's one writer and
one reader.

## Three tables, one derived projection, and why the projection is not a
## fourth persistence owner

`AttestationEnrolment` (append-only) and `AttestationFingerprintClosure`
(append-only, `fingerprint` PRIMARY KEY -- the ordering arbiter) are the
durable TRUTH. `AttestationCurrentRoot` is a DERIVED PROJECTION over those
two -- not a fourth source of fact -- kept only because "at most one open
enrolment per subject" needs a database-enforced lock (its primary key and
its compare-and-swap update), never because it knows anything the other two
tables do not. `fingerprint_standing` and `resolve_current_root` read it
directly for that reason; `reconcile_current_root` recomputes the same
answer straight from the append-only tables and reports disagreement, and
`repair_current_root` performs the idempotent write that removes it. Nothing
in this module stores a `status` column anywhere -- exactly what
`host_attester_enrolment`'s own docstring asks for when it says
`FingerprintRecord` must become "a typed value / projection, not a second
persistence owner," extended here to the current-root pointer as well.

## Vocabulary: reused, not reinvented, with one tension named plainly

Every returned standing uses `host_attester_enrolment.HostAttesterStanding`'s
existing members (`VALID`, `ABSENT`, `WRONG_HOST`, `NOT_ACTIVE_FOR_HOST`,
`REGISTRY_DISAGREEMENT`, `SUPERSEDED`, `REVOKED`) and every closure uses
`host_attester_enrolment.FingerprintStatus`'s existing members (`ACTIVE`,
`SUPERSEDED`, `REVOKED`). Neither enum is redefined here.

**The tension, named rather than resolved:** `HostAttesterStanding` is named
for the host-attester custody domain specifically (`WRONG_HOST`,
`NOT_ACTIVE_FOR_HOST`), and this module also returns it for the
candidate-release-signer domain, where "host" is not the right word for what
disagreed. Michael's instruction was to reuse existing vocabulary rather than
invent a parallel set of names for the same states, and that is what this
module does -- the members' MEANING (this fingerprint is active for a
different subject than asked / this subject has no active root / the two
signals disagree) transfers cleanly across both domains even though the
member names were coined for one of them. Renaming the enum to a
domain-neutral vocabulary, or introducing a second enum, is a call this
module does not make; it is reported as open in the task's final report.

## What this module does NOT do

It does not verify a signature over an enrolment envelope -- that is
`host_attester_enrolment.verify_host_attester_enrolment`'s job for the
host-attester domain, and no equivalent exists yet for the candidate-release
domain. `enrol_root`/`rotate_root` accept an already-authenticated statement's
terms as plain keyword arguments; wiring a verified envelope's `.statement`
into these calls, for both domains, is the caller's obligation, stated here
because nothing in the type system enforces it -- the identical caveat
`host_attester_enrolment.evaluate_enrolment` states about its own `statement`
parameter.

It does not expose a public HTTP/RPC surface. That is a separate, sibling
branch's territory (`HostAttesterBindingV1`); this module is what such a
surface would call, never a network boundary itself.

## Concurrency, by table

- Two sessions racing to `enrol_root` the same brand-new fingerprint: refused
  by `uq_attestation_enrolments_fingerprint` (global, cross-domain).
- Two sessions racing to `enrol_root` two DIFFERENT fresh fingerprints for the
  SAME `(custody_domain, subject)` with no prior root: refused by
  `attestation_current_roots`' primary key.
- Two sessions racing to `rotate_root` away from the SAME prior fingerprint
  with two different new fingerprints: refused by the enrolments table's
  partial unique index on `supersedes_fingerprint`.
- A `rotate_root` racing a `revoke_root` against the SAME prior fingerprint:
  refused by `attestation_fingerprint_closures`' primary key on `fingerprint`
  -- whichever commits first wins permanently, exactly Michael's ruling.

Every conflict is caught with `dotmac_kernel.transactions.conflict_savepoint`,
the same pattern `service.py` already uses for `settle_attempt` and rollout
transitions, so a losing caller's outer transaction stays usable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from dotmac_kernel.transactions import conflict_savepoint
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dotmac_deployment_control.digests import PublicKeyFingerprintV1
from dotmac_deployment_control.host_attester_enrolment import (
    FingerprintStatus,
    HostAttesterStanding,
    require_custody_pointer,
)
from dotmac_deployment_control.models import (
    AttestationCurrentRoot,
    AttestationEnrolment,
    AttestationFingerprintClosure,
)
from dotmac_deployment_control.ports import DeploymentControlError

__all__ = [
    "AttestationCurrentRootDrift",
    "AttestationRefusalCode",
    "AttestationRefusedError",
    "AttestationRootView",
    "enrol_root",
    "fingerprint_standing",
    "reconcile_current_root",
    "repair_current_root",
    "resolve_current_root",
    "revoke_root",
    "rotate_root",
]


class AttestationRefusalCode(StrEnum):
    """Why an enrol/rotate/revoke call was refused. One code per condition."""

    ALREADY_ENROLLED = "attestation_fingerprint_already_enrolled"
    NO_ACTIVE_ROOT_TO_ROTATE = "attestation_no_active_root_to_rotate"
    SUPERSEDES_MISMATCH = "attestation_supersedes_mismatch"
    FINGERPRINT_REVOKED = "attestation_fingerprint_revoked"
    FINGERPRINT_SUPERSEDED = "attestation_fingerprint_superseded"
    UNKNOWN_FINGERPRINT = "attestation_unknown_fingerprint"
    LOST_ROTATION_RACE = "attestation_lost_rotation_race"


class AttestationRefusedError(DeploymentControlError):
    """An enrol/rotate/revoke call the registry cannot admit, and why."""

    def __init__(self, code: AttestationRefusalCode, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _refused(code: AttestationRefusalCode, detail: str) -> AttestationRefusedError:
    return AttestationRefusedError(code, detail)


@dataclass(frozen=True, slots=True)
class AttestationRootView:
    """A typed, read-only projection. No ORM object, session or raw row ever
    crosses this boundary -- every field here is a plain string, bool or
    datetime, copied out of the mapped row before it is returned."""

    custody_domain: str
    subject: str
    public_key_fingerprint: str
    public_key_b64: str
    algorithm: str
    enrolled_at: datetime
    standing: str  # HostAttesterStanding.value


def _closure(
    session: Session, fingerprint: str
) -> AttestationFingerprintClosure | None:
    return session.execute(
        select(AttestationFingerprintClosure).where(
            AttestationFingerprintClosure.fingerprint == fingerprint
        )
    ).scalar_one_or_none()


def _enrolment(session: Session, fingerprint: str) -> AttestationEnrolment | None:
    return session.execute(
        select(AttestationEnrolment).where(
            AttestationEnrolment.public_key_fingerprint == fingerprint
        )
    ).scalar_one_or_none()


def _current_fingerprint(
    session: Session, *, custody_domain: str, subject: str
) -> str | None:
    return session.execute(
        select(AttestationCurrentRoot.current_fingerprint).where(
            AttestationCurrentRoot.custody_domain == custody_domain,
            AttestationCurrentRoot.subject == subject,
        )
    ).scalar_one_or_none()


def _derive_current_fingerprint(
    session: Session, *, custody_domain: str, subject: str
) -> str | None:
    """The TRUTH, computed from the two append-only tables alone -- never
    from `AttestationCurrentRoot`. This is what `reconcile_current_root`
    compares the projection against, and what `repair_current_root` writes
    back when they disagree.

    An enrolment is "open" (a current-root candidate) when no closure row
    names its fingerprint. Ordered by `enrolled_at` descending so that if
    more than one open row exists -- itself a drift symptom this module's
    own writers should never produce, but not something a raw-SQL repair
    script is prevented from causing -- the most recently enrolled one is
    treated as authoritative, and `reconcile_current_root` still reports the
    anomaly rather than resolving it silently.
    """
    closed = select(AttestationFingerprintClosure.fingerprint)
    row = session.execute(
        select(AttestationEnrolment.public_key_fingerprint)
        .where(
            AttestationEnrolment.custody_domain == custody_domain,
            AttestationEnrolment.subject == subject,
            AttestationEnrolment.public_key_fingerprint.not_in(closed),
        )
        .order_by(AttestationEnrolment.enrolled_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    return row


def _count_open_enrolments(
    session: Session, *, custody_domain: str, subject: str
) -> int:
    closed = select(AttestationFingerprintClosure.fingerprint)
    return session.execute(
        select(func.count(AttestationEnrolment.id)).where(
            AttestationEnrolment.custody_domain == custody_domain,
            AttestationEnrolment.subject == subject,
            AttestationEnrolment.public_key_fingerprint.not_in(closed),
        )
    ).scalar_one()


@dataclass(frozen=True, slots=True)
class AttestationCurrentRootDrift:
    """What `reconcile_current_root` found. `drifted` is the ONE question a
    caller needs; the two fingerprints are kept for the operator triaging it."""

    custody_domain: str
    subject: str
    expected_fingerprint: str | None
    recorded_fingerprint: str | None
    open_enrolment_count: int

    @property
    def drifted(self) -> bool:
        return (
            self.expected_fingerprint != self.recorded_fingerprint
            or self.open_enrolment_count > 1
        )


def reconcile_current_root(
    db: Session, *, custody_domain: str, subject: str
) -> AttestationCurrentRootDrift:
    """Compare the durable projection against the append-only truth.

    Read-only. Never writes; `repair_current_root` is the separate, explicit
    write path -- a caller that only wants to KNOW about drift never performs
    one by asking."""
    expected = _derive_current_fingerprint(
        db, custody_domain=custody_domain, subject=subject
    )
    recorded = _current_fingerprint(db, custody_domain=custody_domain, subject=subject)
    open_count = _count_open_enrolments(
        db, custody_domain=custody_domain, subject=subject
    )
    return AttestationCurrentRootDrift(
        custody_domain=custody_domain,
        subject=subject,
        expected_fingerprint=expected,
        recorded_fingerprint=recorded,
        open_enrolment_count=open_count,
    )


def repair_current_root(db: Session, *, custody_domain: str, subject: str) -> None:
    """Make `AttestationCurrentRoot` agree with the append-only truth.

    Idempotent: repairing an already-correct projection is a no-op write.
    Deletes the row when there is no open enrolment (an ABSENT/REVOKED
    subject has no valid current root); upserts it otherwise. Raises nothing
    of its own -- a genuine multi-open-enrolment anomaly
    (`AttestationCurrentRootDrift.open_enrolment_count > 1`) is a fact for the
    caller to act on, not a decision this function is positioned to make for
    them, so it repairs to the same most-recent-wins choice
    `_derive_current_fingerprint` reports and lets the caller decide whether
    that anomaly needs a human.
    """
    expected = _derive_current_fingerprint(
        db, custody_domain=custody_domain, subject=subject
    )
    if expected is None:
        db.execute(
            delete(AttestationCurrentRoot).where(
                AttestationCurrentRoot.custody_domain == custody_domain,
                AttestationCurrentRoot.subject == subject,
            )
        )
        db.flush()
        return
    existing = db.get(AttestationCurrentRoot, (custody_domain, subject))
    if existing is None:
        db.add(
            AttestationCurrentRoot(
                custody_domain=custody_domain,
                subject=subject,
                current_fingerprint=expected,
            )
        )
    elif existing.current_fingerprint != expected:
        existing.current_fingerprint = expected
    db.flush()


def _view_from_enrolment(
    enrolment: AttestationEnrolment, *, standing: HostAttesterStanding
) -> AttestationRootView:
    return AttestationRootView(
        custody_domain=enrolment.custody_domain,
        subject=enrolment.subject,
        public_key_fingerprint=enrolment.public_key_fingerprint,
        public_key_b64=enrolment.public_key_b64,
        algorithm=enrolment.algorithm,
        enrolled_at=enrolment.enrolled_at,
        standing=standing.value,
    )


def fingerprint_standing(db: Session, *, fingerprint: str) -> HostAttesterStanding:
    """What `fingerprint` is RIGHT NOW, derived from the durable registry.

    Mirrors `host_attester_enrolment.host_attester_standing` exactly, with the
    two caller-supplied mappings replaced by this module's own tables. See the
    module docstring for the naming tension in reusing `HostAttesterStanding`
    for the candidate-release domain too.
    """
    enrolment = _enrolment(db, fingerprint)
    if enrolment is None:
        return HostAttesterStanding.ABSENT
    closure = _closure(db, fingerprint)
    if closure is not None:
        if closure.closure_kind == FingerprintStatus.REVOKED.value:
            return HostAttesterStanding.REVOKED
        return HostAttesterStanding.SUPERSEDED
    current = _current_fingerprint(
        db, custody_domain=enrolment.custody_domain, subject=enrolment.subject
    )
    if current is None:
        # No closure AND no current pointer for this subject at all. Not
        # reachable through this module's own functions under ordinary
        # caller discipline (a lost race raises before the transaction
        # commits, and the caller is documented to roll back on refusal --
        # see `enrol_root`/`rotate_root`), but a raw-SQL write or a caller
        # that commits despite a raised refusal could produce it. Reported
        # rather than treated as an internal error, on the same "never trust
        # one signal alone" principle the rest of this module follows.
        return HostAttesterStanding.NOT_ACTIVE_FOR_HOST
    if current != fingerprint:
        return HostAttesterStanding.WRONG_HOST
    return HostAttesterStanding.VALID


def resolve_current_root(
    db: Session, *, custody_domain: str, subject: str
) -> AttestationRootView | None:
    """The typed projection a Foundation/Platform verifier resolves against.

    Returns `None` (`ABSENT`) rather than raising -- absence is a fact, not a
    failure, exactly as `host_attester_enrolment`'s own docstring rules for
    `HostAttesterStanding.ABSENT`.

    `AttestationCurrentRoot` ACCELERATES this read; it does not DECIDE it.
    Standing is derived from the append-only tables -- enrolment minus
    closure -- every time, so a projection row that names a fingerprint the
    closures table has since revoked or superseded is refused HERE, before
    any reconciliation runs. Under this module's own writers that row would
    already have been deleted (`revoke_root`) or moved
    (`rotate_root`), but a raw-SQL write, a restored backup, or a corrupted
    projection row must not be trusted to have kept that invariant -- the
    same "never trust one signal alone" principle `fingerprint_standing`
    already applies by checking the closures table directly rather than
    inferring REVOKED from the pointer's absence.
    """
    fingerprint = _current_fingerprint(
        db, custody_domain=custody_domain, subject=subject
    )
    if fingerprint is None:
        return None
    enrolment = _enrolment(db, fingerprint)
    if enrolment is None:  # pragma: no cover - FK makes this unreachable
        return None
    if _closure(db, fingerprint) is not None:
        # The projection points at a CLOSED fingerprint. The projection is
        # not authoritative, so this is a refusal, not a report of the stale
        # standing the closed fingerprint used to have.
        return None
    return _view_from_enrolment(enrolment, standing=HostAttesterStanding.VALID)


def enrol_root(
    db: Session,
    *,
    custody_domain: str,
    subject: str,
    public_key_b64: str,
    algorithm: str,
    key_custody_pointer: str,
    enrolment_authority: str,
    enrolled_at: datetime | None = None,
) -> AttestationRootView:
    """Enrol a brand-new root: either the FIRST root for this subject, or a
    recovery attempt after the prior one was revoked (never a rotation --
    `rotate_root` is the only path that names `supersedes_fingerprint`).

    Only a Control service may call this; it is not reachable from any
    inbound envelope-verification path in this module.
    """
    fingerprint = PublicKeyFingerprintV1.from_public_key_b64(public_key_b64).canonical
    when = enrolled_at or datetime.now(UTC)
    # Reused, not reimplemented: `require_custody_pointer` already carries the
    # `bao://` shape check (`host_attester_enrolment.py`). A pointer that
    # fails this is refused before anything is written -- the column type
    # (`str`) could not otherwise distinguish a real pointer from an
    # arbitrary string.
    key_custody_pointer = require_custody_pointer(
        key_custody_pointer, where="enrol_root"
    )

    try:
        with conflict_savepoint(db):
            enrolment = AttestationEnrolment(
                id=uuid4(),
                custody_domain=custody_domain,
                subject=subject,
                public_key_b64=public_key_b64,
                public_key_fingerprint=fingerprint,
                algorithm=algorithm,
                key_custody_pointer=key_custody_pointer,
                supersedes_fingerprint=None,
                enrolled_at=when,
                enrolment_authority=enrolment_authority,
            )
            db.add(enrolment)
            db.flush()
    except IntegrityError as exc:
        raise _refused(
            AttestationRefusalCode.ALREADY_ENROLLED,
            f"fingerprint {fingerprint!r} is already enrolled, in this or the "
            "other custody domain",
        ) from exc

    try:
        with conflict_savepoint(db):
            db.add(
                AttestationCurrentRoot(
                    custody_domain=custody_domain,
                    subject=subject,
                    current_fingerprint=fingerprint,
                )
            )
            db.flush()
    except IntegrityError as exc:
        raise _refused(
            AttestationRefusalCode.ALREADY_ENROLLED,
            f"{custody_domain!r} subject {subject!r} already has a current "
            "root; use rotate_root, or revoke_root first for a genuine "
            "recovery",
        ) from exc

    return _view_from_enrolment(enrolment, standing=HostAttesterStanding.VALID)


def rotate_root(
    db: Session,
    *,
    custody_domain: str,
    subject: str,
    supersedes_fingerprint: str,
    public_key_b64: str,
    algorithm: str,
    key_custody_pointer: str,
    enrolment_authority: str,
    enrolled_at: datetime | None = None,
) -> AttestationRootView:
    """Retire `supersedes_fingerprint` and make a new fingerprint current.

    Only legal against the subject's actual current fingerprint -- checked
    against `AttestationCurrentRoot` before anything is written, then enforced
    again by that same table's compare-and-swap UPDATE below, which is the
    real race arbiter.
    """
    fingerprint = PublicKeyFingerprintV1.from_public_key_b64(public_key_b64).canonical
    if fingerprint == supersedes_fingerprint:
        raise _refused(
            AttestationRefusalCode.SUPERSEDES_MISMATCH,
            "a rotation must name a NEW fingerprint",
        )
    when = enrolled_at or datetime.now(UTC)
    key_custody_pointer = require_custody_pointer(
        key_custody_pointer, where="rotate_root"
    )

    current = _current_fingerprint(db, custody_domain=custody_domain, subject=subject)
    if current is None:
        raise _refused(
            AttestationRefusalCode.NO_ACTIVE_ROOT_TO_ROTATE,
            f"{custody_domain!r} subject {subject!r} has no current root to "
            "rotate away from; use enrol_root",
        )
    if current != supersedes_fingerprint:
        raise _refused(
            AttestationRefusalCode.SUPERSEDES_MISMATCH,
            f"{custody_domain!r} subject {subject!r}'s current root is "
            f"{current!r}; this rotation names {supersedes_fingerprint!r}",
        )

    # 1. The new enrolment. Its own global-fingerprint uniqueness, PLUS the
    #    partial unique index on supersedes_fingerprint, are the database
    #    arbiter for two concurrent rotations both retiring the same prior
    #    fingerprint.
    try:
        with conflict_savepoint(db):
            enrolment = AttestationEnrolment(
                id=uuid4(),
                custody_domain=custody_domain,
                subject=subject,
                public_key_b64=public_key_b64,
                public_key_fingerprint=fingerprint,
                algorithm=algorithm,
                key_custody_pointer=key_custody_pointer,
                supersedes_fingerprint=supersedes_fingerprint,
                enrolled_at=when,
                enrolment_authority=enrolment_authority,
            )
            db.add(enrolment)
            db.flush()
    except IntegrityError as exc:
        raise _refused(
            AttestationRefusalCode.LOST_ROTATION_RACE,
            f"another rotation already claimed {supersedes_fingerprint!r}, or "
            f"{fingerprint!r} is already enrolled elsewhere",
        ) from exc

    # 2. Close the OLD fingerprint. The PRIMARY KEY on `fingerprint` is
    #    Michael's ordering rule made structural: whichever of this
    #    supersession and a concurrent revocation commits first wins.
    try:
        with conflict_savepoint(db):
            db.add(
                AttestationFingerprintClosure(
                    fingerprint=supersedes_fingerprint,
                    closure_kind=FingerprintStatus.SUPERSEDED.value,
                    closed_at=when,
                    closure_authority=enrolment_authority,
                    superseded_by_fingerprint=fingerprint,
                )
            )
            db.flush()
    except IntegrityError as exc:
        existing = _closure(db, supersedes_fingerprint)
        if existing is not None and existing.closure_kind == (
            FingerprintStatus.REVOKED.value
        ):
            raise _refused(
                AttestationRefusalCode.FINGERPRINT_REVOKED,
                f"{supersedes_fingerprint!r} was revoked before this "
                "rotation's supersession committed; revocation is permanent "
                "and this rotation is refused",
            ) from exc
        raise _refused(
            AttestationRefusalCode.LOST_ROTATION_RACE,
            f"{supersedes_fingerprint!r} was already closed by a concurrent operation",
        ) from exc

    # 3. Move the current-root pointer with a compare-and-swap. If this loses
    #    (0 rows updated), some other transition already moved it, and it is
    #    the case that step 2's own primary key should already have caught --
    #    kept as a defensive second check, on the principle every other
    #    binding check in this package already applies: never trust one
    #    signal alone.
    result = db.execute(
        update(AttestationCurrentRoot)
        .where(
            AttestationCurrentRoot.custody_domain == custody_domain,
            AttestationCurrentRoot.subject == subject,
            AttestationCurrentRoot.current_fingerprint == supersedes_fingerprint,
        )
        .values(current_fingerprint=fingerprint)
    )
    if result.rowcount != 1:  # pragma: no cover - defensive; step 2 should catch first
        raise _refused(
            AttestationRefusalCode.LOST_ROTATION_RACE,
            f"the current-root pointer for {custody_domain!r}/{subject!r} "
            "moved before this rotation could apply",
        )
    db.flush()

    return _view_from_enrolment(enrolment, standing=HostAttesterStanding.VALID)


def revoke_root(
    db: Session,
    *,
    fingerprint: str,
    revocation_authority: str,
    revocation_reason: str | None = None,
    revoked_at: datetime | None = None,
) -> None:
    """Permanently close `fingerprint`. There is no un-revoke in this module.

    If `fingerprint` was the current root for its subject, the current-root
    pointer is deleted -- there is no valid current root until a NEW signed
    attempt recovers one (`enrol_root`); recovery never resurrects the old
    marker.
    """
    enrolment = _enrolment(db, fingerprint)
    if enrolment is None:
        raise _refused(
            AttestationRefusalCode.UNKNOWN_FINGERPRINT,
            f"{fingerprint!r} has never been enrolled",
        )
    when = revoked_at or datetime.now(UTC)

    try:
        with conflict_savepoint(db):
            db.add(
                AttestationFingerprintClosure(
                    fingerprint=fingerprint,
                    closure_kind=FingerprintStatus.REVOKED.value,
                    closed_at=when,
                    closure_authority=revocation_authority,
                    closure_reason=revocation_reason,
                )
            )
            db.flush()
    except IntegrityError as exc:
        existing = _closure(db, fingerprint)
        if existing is not None and existing.closure_kind == (
            FingerprintStatus.SUPERSEDED.value
        ):
            raise _refused(
                AttestationRefusalCode.FINGERPRINT_SUPERSEDED,
                f"{fingerprint!r} was already rotated away before this "
                "revocation committed; the rotation is permanent and this "
                "revocation is refused -- the successor fingerprint is the "
                "one to revoke, if that is what is intended",
            ) from exc
        raise _refused(
            AttestationRefusalCode.FINGERPRINT_REVOKED,
            f"{fingerprint!r} was already revoked",
        ) from exc

    # Delete the current-root pointer ONLY if it still names the fingerprint
    # being revoked -- conditioned, never unconditional, so a pointer some
    # later rotation already moved on cannot be erased by a late revocation
    # of the OLD fingerprint.
    db.execute(
        delete(AttestationCurrentRoot).where(
            AttestationCurrentRoot.custody_domain == enrolment.custody_domain,
            AttestationCurrentRoot.subject == enrolment.subject,
            AttestationCurrentRoot.current_fingerprint == fingerprint,
        )
    )
    db.flush()
