"""ADR-0073 (amended) three-phase host-admission boundary.

`resolve_host_admission_context` authenticates the presentation and resolves
every current fact needed for Foundation verification WITHOUT taking any
database row lock -- the out-of-process Foundation verification call the
caller makes between the two functions in this module therefore holds zero
locks for its entire duration. The returned context is a plain, freely
copyable value: nothing about possessing it grants anything, and it carries no
Session or transaction affinity. `admit_and_consume_host_admission`
re-authenticates, re-locks everything fresh in the same canonical order the
prior single-transaction design used, re-derives every fact from the locked
rows, requires exact equality against the resolved context and against
Foundation's echoed verification evidence, and stages Control's existing
replay marker. Neither function commits or rolls back.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock
from typing import Protocol
from uuid import UUID

from sqlalchemy.orm import Session

from dotmac_deployment_control.attestation_trust_registry import (
    AttestationAdmissionRootView,
    lock_attestation_subjects,
    resolve_admission_root,
)
from dotmac_deployment_control.digests import (
    PublicKeyFingerprintV1,
    compute_host_admission_context_digest,
    compute_host_admission_presentation_digest,
)
from dotmac_deployment_control.host_admission import (
    CANDIDATE_ATTESTATION_PURPOSE,
    HOST_ADMISSION_PRESENTATION_PURPOSE,
    INSTALLED_OBSERVATION_PURPOSE,
    HostAdmissionPresentationV1,
    HostAdmissionPresentationVerifier,
    foundation_public_key_base64,
    verify_host_admission_presentation,
)
from dotmac_deployment_control.host_admission_service import (
    lock_target,
    require_current_target_admission_policy_locked,
    require_current_target_host_locked,
    resolve_current_target_admission_policy_unlocked,
    resolve_current_target_host_unlocked,
)
from dotmac_deployment_control.models import (
    CredentialStatus,
    DeploymentTarget,
    TargetCredential,
)
from dotmac_deployment_control.ports import DeploymentControlError
from dotmac_deployment_control.service import (
    _credential_by_key_id,
    _ExpectedDispatchTarget,
    _load_credential_for_update,
    _stage_dispatch_consumption,
    _StagedDispatchConsumption,
    _stored_dispatch_coordinate,
    _StoredDispatchCoordinate,
)


class HostAdmissionClock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class _HostAdmissionSecurity:
    verifier: HostAdmissionPresentationVerifier
    clock: HostAdmissionClock


_SECURITY_INSTALL_LOCK = Lock()
_installed_security: _HostAdmissionSecurity | None = None


def install_host_admission_security(
    *, verifier: HostAdmissionPresentationVerifier, clock: HostAdmissionClock
) -> None:
    """Install the trusted authentication dependencies exactly once at startup."""
    if not isinstance(verifier, HostAdmissionPresentationVerifier) or not callable(
        getattr(clock, "now", None)
    ):
        raise TypeError("host-admission verifier and clock must satisfy their ports")
    global _installed_security
    with _SECURITY_INSTALL_LOCK:
        if _installed_security is not None:
            raise RuntimeError("host-admission security is already installed")
        _installed_security = _HostAdmissionSecurity(verifier=verifier, clock=clock)


def _require_installed_security() -> _HostAdmissionSecurity:
    security = _installed_security
    if security is None:
        raise _refuse(
            HostAdmissionRefusalCode.AUTHENTICATION_FAILED,
            "host-admission security was not installed at startup",
        )
    return security


def _reset_host_admission_security_for_tests() -> None:
    """Remove startup composition between tests; never exported to products."""
    global _installed_security
    with _SECURITY_INSTALL_LOCK:
        _installed_security = None


class HostAdmissionRefusalCode(StrEnum):
    AUTHENTICATION_FAILED = "host_admission_authentication_failed"
    CREDENTIAL_CHANGED = "host_admission_credential_changed"
    CREDENTIAL_NOT_ACTIVE = "host_admission_credential_not_active"
    CREDENTIAL_PURPOSE_MISMATCH = "host_admission_credential_purpose_mismatch"
    TARGET_MISMATCH = "host_admission_target_mismatch"
    POLICY_HOST_MISMATCH = "host_admission_policy_host_mismatch"
    DISPATCH_MISMATCH = "host_admission_dispatch_mismatch"
    ROOT_REFUSED = "host_admission_root_refused"
    ROOT_NOT_YET_VALID = "host_admission_root_not_yet_valid"
    ROOT_EXPIRED = "host_admission_root_expired"
    ROOT_PURPOSE_MISMATCH = "host_admission_root_purpose_mismatch"
    CONTEXT_EXPIRED = "host_admission_context_expired"
    EVIDENCE_CHANGED = "host_admission_evidence_changed"
    FOREIGN_EVIDENCE_CONTEXT_MISMATCH = (
        "host_admission_foreign_evidence_context_mismatch"
    )
    PREPARED_STATE_CHANGED = "host_admission_prepared_state_changed"


class HostAdmissionRefusedError(DeploymentControlError):
    def __init__(self, code: HostAdmissionRefusalCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


@dataclass(frozen=True, slots=True)
class HostAdmissionRootContextV1:
    custody_domain: str
    subject: str
    issuer: str
    key_id: str
    purpose: str
    root_version: str
    not_before: datetime
    not_after: datetime
    algorithm: str
    public_key_base64: str
    public_key_fingerprint: str
    standing: str
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class HostAdmissionForeignVerificationEvidenceV1:
    """What Control accepts as Foundation's verification result -- Control does
    NOT import dotmac_deployment_foundation's actual result type (the two
    packages never import each other, per ADR-0073). The CP adapter is the sole
    mapper from Foundation's `AttestationPairVerificationResultV1` into this
    Control-owned shape."""

    candidate_attestation_envelope_digest: str
    installed_attestation_envelope_digest: str
    verification_context_digest: str


@dataclass(frozen=True, slots=True)
class HostAdmissionVerificationContextV1:
    """Non-authorizing, freely copyable -- no opaque capability, no held lock,
    no session/transaction affinity. Every field here is a plain value; nothing
    about possessing this object grants anything. `context_digest` is Control's
    own optimistic-concurrency fingerprint over every field below (see
    compute_host_admission_context_digest); admit_and_consume_host_admission
    recomputes it from FRESH state and requires equality -- this object's own
    copy of the digest is never trusted at that point, only compared against."""

    attempt_id: UUID
    dispatch_id: str
    dispatch_envelope_digest: str
    target_id: UUID
    target_ref: str
    host_id: str
    credential_id: UUID
    credential_key_id: str
    credential_fingerprint: str
    credential_algorithm: str
    credential_purpose: str
    association_id: UUID
    policy_id: UUID
    candidate_root: HostAdmissionRootContextV1
    installed_root: HostAdmissionRootContextV1
    candidate_audience: str
    installed_audience: str
    expected_foundation_package: str
    presentation: HostAdmissionPresentationV1
    context_digest: str


def _refuse(code: HostAdmissionRefusalCode, detail: str) -> HostAdmissionRefusedError:
    return HostAdmissionRefusedError(code, detail)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise _refuse(
            HostAdmissionRefusalCode.AUTHENTICATION_FAILED,
            "trusted clock returned a naive instant",
        )
    return value.astimezone(UTC)


def _credential_is_active(row: TargetCredential, *, now: datetime) -> bool:
    if (
        row.status != CredentialStatus.ACTIVE.value
        or row.activated_at is None
        or now < _aware(row.activated_at)
    ):
        return False
    return not any(
        value is not None and now >= _aware(value)
        for value in (row.retired_at, row.revoked_at)
    )


def _aware(value: datetime) -> datetime:
    return (
        value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    )


def _credential_identity(row: TargetCredential) -> tuple[object, ...]:
    return (
        row.id,
        row.target_id,
        row.key_id,
        row.algorithm,
        row.purpose,
        row.public_key_b64,
        row.public_key_fingerprint,
    )


def _root_context(
    root: AttestationAdmissionRootView,
    *,
    expected_domain: str,
    expected_purpose: str,
    now: datetime,
) -> HostAdmissionRootContextV1:
    if (
        root.custody_domain != expected_domain
        or root.evidence_purpose != expected_purpose
    ):
        raise _refuse(
            HostAdmissionRefusalCode.ROOT_PURPOSE_MISMATCH,
            "resolved root custody domain or evidence purpose is wrong",
        )
    not_before, not_after = _aware(root.enrolled_at), _aware(root.not_after)
    if now < not_before:
        raise _refuse(
            HostAdmissionRefusalCode.ROOT_NOT_YET_VALID,
            f"{expected_domain} root is not yet valid",
        )
    if now >= not_after:
        raise _refuse(
            HostAdmissionRefusalCode.ROOT_EXPIRED,
            f"{expected_domain} root has expired",
        )
    return HostAdmissionRootContextV1(
        custody_domain=root.custody_domain,
        subject=root.subject,
        issuer=root.issuer,
        key_id=root.attestation_key_id,
        purpose=root.evidence_purpose,
        root_version=root.root_version,
        not_before=not_before,
        not_after=not_after,
        algorithm=root.algorithm,
        public_key_base64=foundation_public_key_base64(
            public_key_b64=root.public_key_b64,
            fingerprint=root.public_key_fingerprint,
        ),
        public_key_fingerprint=root.public_key_fingerprint,
        standing=root.standing,
    )


def _resolve_root_context(
    db: Session,
    *,
    custody_domain: str,
    subject: str,
    purpose: str,
    now: datetime,
) -> HostAdmissionRootContextV1:
    root, refusal = resolve_admission_root(
        db, custody_domain=custody_domain, subject=subject
    )
    if root is None:
        assert refusal is not None
        raise _refuse(
            HostAdmissionRefusalCode.ROOT_REFUSED,
            f"{custody_domain}/{subject} refused: {refusal.value}",
        )
    return _root_context(
        root,
        expected_domain=custody_domain,
        expected_purpose=purpose,
        now=now,
    )


def _render_instant(value: datetime) -> str:
    """Same rendering `host_admission.py`'s own `_render` uses for a signed
    instant -- an isoformat string with a literal `Z` rather than `+00:00` --
    so a root's `not_before`/`not_after` fold into the context digest through
    the one convention this package already uses for a datetime, rather than a
    second one invented here. `canonical_json` -> `json.dumps` cannot encode a
    raw `datetime` at all, so this conversion is required, not cosmetic."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _root_context_for_digest(root: HostAdmissionRootContextV1) -> dict[str, object]:
    payload = asdict(root)
    payload["not_before"] = _render_instant(root.not_before)
    payload["not_after"] = _render_instant(root.not_after)
    return payload


def _context_digest(
    *,
    presentation: HostAdmissionPresentationV1,
    dispatch: _StoredDispatchCoordinate,
    target_id: UUID,
    target_ref: str,
    host_id: str,
    credential: TargetCredential,
    association_id: UUID,
    policy_id: UUID,
    candidate_audience: str,
    installed_audience: str,
    expected_foundation_package: str,
    candidate_root: HostAdmissionRootContextV1,
    installed_root: HostAdmissionRootContextV1,
) -> str:
    return compute_host_admission_context_digest(
        presentation_canonical_digest=compute_host_admission_presentation_digest(
            presentation.as_mapping()
        ),
        dispatch_id=dispatch.dispatch_id,
        dispatch_envelope_digest=dispatch.dispatch_envelope_digest,
        target_id=str(target_id),
        target_ref=target_ref,
        host_id=host_id,
        credential_id=str(credential.id),
        credential_key_id=credential.key_id,
        credential_fingerprint=credential.public_key_fingerprint,
        credential_algorithm=credential.algorithm,
        credential_purpose=credential.purpose,
        association_id=str(association_id),
        policy_id=str(policy_id),
        candidate_audience=candidate_audience,
        installed_audience=installed_audience,
        expected_foundation_package=expected_foundation_package,
        candidate_root=_root_context_for_digest(candidate_root),
        installed_root=_root_context_for_digest(installed_root),
    )


def _require_stored_dispatch(
    db: Session, *, attempt_id: UUID, target_id: UUID
) -> _StoredDispatchCoordinate:
    try:
        coordinate = _stored_dispatch_coordinate(db, attempt_id)
    except DeploymentControlError as exc:
        raise _refuse(
            HostAdmissionRefusalCode.DISPATCH_MISMATCH,
            "stored dispatch envelope is malformed",
        ) from exc
    if coordinate is None:
        raise _refuse(
            HostAdmissionRefusalCode.DISPATCH_MISMATCH,
            "dispatch attempt is absent or has no signed envelope",
        )
    if coordinate.target_id != target_id:
        raise _refuse(
            HostAdmissionRefusalCode.TARGET_MISMATCH,
            "authenticated credential target differs from dispatch target",
        )
    return coordinate


def resolve_host_admission_context(
    db: Session,
    *,
    attempt_id: UUID,
    presentation: HostAdmissionPresentationV1,
) -> HostAdmissionVerificationContextV1:
    """Authenticate the presentation and resolve every current fact needed for
    Foundation verification, WITHOUT taking any row lock. The caller is
    responsible for this being a short, read-only transaction that it commits
    or closes immediately on return -- this function itself does not commit or
    roll back (same non-transaction-owning discipline every other function in
    this module already follows)."""
    if not isinstance(presentation, HostAdmissionPresentationV1):
        raise _refuse(
            HostAdmissionRefusalCode.AUTHENTICATION_FAILED,
            "presentation must be parsed by Control's versioned contract",
        )
    security = _require_installed_security()
    now = _utc(security.clock.now())
    candidate = _credential_by_key_id(db, presentation.statement.key_id)
    if candidate is None or candidate.algorithm is None or candidate.purpose is None:
        raise _refuse(
            HostAdmissionRefusalCode.AUTHENTICATION_FAILED,
            "presentation key is unknown or lacks immutable verification terms",
        )
    verify_host_admission_presentation(
        presentation,
        verifier=security.verifier,
        algorithm=candidate.algorithm,
        public_key_fingerprint=candidate.public_key_fingerprint,
        public_key_b64=candidate.public_key_b64,
        now=now,
    )

    target = db.get(DeploymentTarget, candidate.target_id)
    if target is None:
        raise _refuse(
            HostAdmissionRefusalCode.TARGET_MISMATCH,
            "authenticated credential names a deployment target that no longer exists",
        )
    # A plain, non-locking re-read of the SAME row the authenticated `candidate`
    # was just resolved from -- this is the resolver's whole point: it takes no
    # lock, so it cannot protect against a concurrent write the way the old
    # design's `_load_credential_for_update` did. That protection now lives
    # entirely in `admit_and_consume_host_admission`, which re-locks and
    # re-derives every one of these facts from scratch.
    credential = db.get(TargetCredential, candidate.id)
    if credential is None:
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_CHANGED,
            "credential disappeared before resolution completed",
        )
    if credential.purpose != HOST_ADMISSION_PRESENTATION_PURPOSE:
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_PURPOSE_MISMATCH,
            "credential is not enrolled for host-admission presentations",
        )
    if not _credential_is_active(credential, now=now):
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_NOT_ACTIVE,
            "credential is not active at the trusted resolution instant",
        )
    recomputed = PublicKeyFingerprintV1.from_public_key_b64(
        credential.public_key_b64
    ).canonical
    if recomputed != credential.public_key_fingerprint:
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_CHANGED,
            "credential public material disagrees with its fingerprint",
        )

    association = resolve_current_target_host_unlocked(db, target.id)
    policy = resolve_current_target_admission_policy_unlocked(db, target.id)
    if policy.host_association_id != association.association_id:
        raise _refuse(
            HostAdmissionRefusalCode.POLICY_HOST_MISMATCH,
            "current admission policy does not bind the current host association",
        )
    candidate_root = _resolve_root_context(
        db,
        custody_domain="candidate_release_signer",
        subject=policy.candidate_root_subject,
        purpose=CANDIDATE_ATTESTATION_PURPOSE,
        now=now,
    )
    installed_root = _resolve_root_context(
        db,
        custody_domain="host_attester",
        subject=association.host_id,
        purpose=INSTALLED_OBSERVATION_PURPOSE,
        now=now,
    )
    dispatch = _require_stored_dispatch(db, attempt_id=attempt_id, target_id=target.id)
    statement = presentation.statement
    if statement.dispatch_id != dispatch.dispatch_id:
        raise _refuse(
            HostAdmissionRefusalCode.DISPATCH_MISMATCH,
            "presentation does not name the signed stored dispatch id",
        )

    context_digest = _context_digest(
        presentation=presentation,
        dispatch=dispatch,
        target_id=target.id,
        target_ref=target.target_ref,
        host_id=association.host_id,
        credential=credential,
        association_id=association.association_id,
        policy_id=policy.policy_id,
        candidate_audience=policy.candidate_audience,
        installed_audience=policy.installed_audience,
        expected_foundation_package=policy.expected_foundation_package,
        candidate_root=candidate_root,
        installed_root=installed_root,
    )
    return HostAdmissionVerificationContextV1(
        attempt_id=attempt_id,
        dispatch_id=dispatch.dispatch_id,
        dispatch_envelope_digest=dispatch.dispatch_envelope_digest,
        target_id=target.id,
        target_ref=target.target_ref,
        host_id=association.host_id,
        credential_id=credential.id,
        credential_key_id=credential.key_id,
        credential_fingerprint=credential.public_key_fingerprint,
        credential_algorithm=credential.algorithm,
        credential_purpose=credential.purpose,
        association_id=association.association_id,
        policy_id=policy.policy_id,
        candidate_root=candidate_root,
        installed_root=installed_root,
        candidate_audience=policy.candidate_audience,
        installed_audience=policy.installed_audience,
        expected_foundation_package=policy.expected_foundation_package,
        presentation=presentation,
        context_digest=context_digest,
    )


def admit_and_consume_host_admission(
    db: Session,
    *,
    context: HostAdmissionVerificationContextV1,
    foreign_evidence: HostAdmissionForeignVerificationEvidenceV1,
) -> _StagedDispatchConsumption:
    """Re-authenticate, re-lock everything fresh, re-derive every fact from
    locked state, require exact equality against `context` and against
    `foreign_evidence`, then stage exactly one consumption. `context` and
    `foreign_evidence` are both untrusted, non-authorizing data -- everything
    here is re-derived from Control's own locked rows before being trusted."""
    security = _require_installed_security()
    now = _utc(security.clock.now())
    # Checked BEFORE re-authentication, and with Control's own named refusal
    # code: `verify_host_admission_presentation` below would otherwise raise
    # its own (differently-typed) expiry refusal first, which would hide the
    # specific "the gap between resolve and admit outlived the presentation"
    # finding this redesign exists to surface.
    if now >= context.presentation.statement.expires_at:
        raise _refuse(
            HostAdmissionRefusalCode.CONTEXT_EXPIRED,
            "resolved admission context outlived the presentation's liveness window",
        )
    # Same unlocked re-authentication shape `resolve_host_admission_context`
    # itself used: verify against a plain, unlocked read of the credential
    # named by the presentation's own key id, before any lock is taken. The
    # locked, authoritative credential is re-loaded and re-checked below.
    reauthenticated = _credential_by_key_id(db, context.presentation.statement.key_id)
    if (
        reauthenticated is None
        or reauthenticated.algorithm is None
        or reauthenticated.purpose is None
    ):
        raise _refuse(
            HostAdmissionRefusalCode.AUTHENTICATION_FAILED,
            "presentation key is unknown or lacks immutable verification terms",
        )
    verify_host_admission_presentation(
        context.presentation,
        verifier=security.verifier,
        algorithm=reauthenticated.algorithm,
        public_key_fingerprint=reauthenticated.public_key_fingerprint,
        public_key_b64=reauthenticated.public_key_b64,
        now=now,
    )

    target = lock_target(db, context.target_id)
    if target.target_ref != context.target_ref:
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "target reference differs from resolution",
        )
    try:
        credential = _load_credential_for_update(db, context.credential_id)
    except DeploymentControlError as exc:
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "credential disappeared after resolution",
        ) from exc
    if (
        credential.key_id != context.credential_key_id
        or credential.public_key_fingerprint != context.credential_fingerprint
        or credential.purpose != context.credential_purpose
        or not _credential_is_active(credential, now=now)
    ):
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "credential differs from resolution",
        )
    association = require_current_target_host_locked(db, target.id)
    policy = require_current_target_admission_policy_locked(db, target.id)
    if (
        association.association_id != context.association_id
        or policy.policy_id != context.policy_id
    ):
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "host association or admission policy differs from resolution",
        )
    subjects = (
        ("candidate_release_signer", policy.candidate_root_subject),
        ("host_attester", association.host_id),
    )
    lock_attestation_subjects(db, subjects=subjects)
    candidate_root = _resolve_root_context(
        db,
        custody_domain="candidate_release_signer",
        subject=policy.candidate_root_subject,
        purpose=CANDIDATE_ATTESTATION_PURPOSE,
        now=now,
    )
    installed_root = _resolve_root_context(
        db,
        custody_domain="host_attester",
        subject=association.host_id,
        purpose=INSTALLED_OBSERVATION_PURPOSE,
        now=now,
    )
    if (
        candidate_root != context.candidate_root
        or installed_root != context.installed_root
    ):
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "attestation root coordinate differs from resolution",
        )
    dispatch = _require_stored_dispatch(
        db, attempt_id=context.attempt_id, target_id=target.id
    )
    if (
        dispatch.dispatch_id != context.dispatch_id
        or dispatch.dispatch_envelope_digest != context.dispatch_envelope_digest
    ):
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "stored dispatch differs from resolution",
        )

    recomputed_digest = _context_digest(
        presentation=context.presentation,
        dispatch=dispatch,
        target_id=target.id,
        target_ref=target.target_ref,
        host_id=association.host_id,
        credential=credential,
        association_id=association.association_id,
        policy_id=policy.policy_id,
        candidate_audience=policy.candidate_audience,
        installed_audience=policy.installed_audience,
        expected_foundation_package=policy.expected_foundation_package,
        candidate_root=candidate_root,
        installed_root=installed_root,
    )
    if recomputed_digest != context.context_digest:
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "freshly re-derived context digest differs from the resolved context",
        )
    if foreign_evidence.verification_context_digest != context.context_digest:
        raise _refuse(
            HostAdmissionRefusalCode.FOREIGN_EVIDENCE_CONTEXT_MISMATCH,
            "Foundation's echoed verification context digest does not match "
            "Control's own resolved context",
        )
    statement = context.presentation.statement
    if (
        foreign_evidence.candidate_attestation_envelope_digest
        != statement.candidate_attestation_envelope_digest
        or foreign_evidence.installed_attestation_envelope_digest
        != statement.installed_attestation_envelope_digest
    ):
        raise _refuse(
            HostAdmissionRefusalCode.EVIDENCE_CHANGED,
            "verified attestation digests differ from the signed presentation",
        )
    return _stage_dispatch_consumption(
        db,
        attempt_id=context.attempt_id,
        expected_target=_ExpectedDispatchTarget(
            target_id=context.target_id, target_ref=context.target_ref
        ),
        candidate_attestation_envelope_digest=(
            foreign_evidence.candidate_attestation_envelope_digest
        ),
        installed_attestation_envelope_digest=(
            foreign_evidence.installed_attestation_envelope_digest
        ),
    )


__all__ = [
    "HostAdmissionClock",
    "HostAdmissionForeignVerificationEvidenceV1",
    "HostAdmissionRefusalCode",
    "HostAdmissionRefusedError",
    "HostAdmissionRootContextV1",
    "HostAdmissionVerificationContextV1",
    "admit_and_consume_host_admission",
    "install_host_admission_security",
    "resolve_host_admission_context",
]
