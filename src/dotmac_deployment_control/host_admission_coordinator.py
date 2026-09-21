"""ADR-0073 authenticated prepare/finalize transaction boundary.

The preparation result is deliberately non-serializable: it carries the exact
caller-owned Session and root transaction whose locks protect the facts in the
public fields. Foundation verifies those facts without either repository
importing the other. Finalization accepts only the two verified envelope
digests, rechecks the locked coordinate, and stages Control's existing replay
marker. Neither function commits or rolls back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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
from dotmac_deployment_control.digests import PublicKeyFingerprintV1
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
    TargetAdmissionPolicyView,
    TargetHostAssociationView,
    lock_target,
    require_current_target_admission_policy_locked,
    require_current_target_host_locked,
)
from dotmac_deployment_control.models import CredentialStatus, TargetCredential
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
    TRANSACTION_CHANGED = "host_admission_transaction_changed"
    EVIDENCE_CHANGED = "host_admission_evidence_changed"
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
class HostAdmissionVerificationFactsV1:
    """Non-authorizing facts supplied to Foundation for stateless verification."""

    attempt_id: UUID
    dispatch_id: str
    dispatch_envelope_digest: str
    candidate_attestation_envelope_digest: str
    installed_attestation_envelope_digest: str
    target_id: UUID
    target_ref: str
    host_id: str
    public_key_fingerprint: str
    trust_root_version: str
    candidate_root: HostAdmissionRootContextV1
    installed_root: HostAdmissionRootContextV1
    candidate_audience: str
    installed_audience: str
    expected_foundation_package: str


_PREPARED_MINT = object()
_PREPARED_SESSION_KEY = object()


class _PreparedHostAdmission:
    """Opaque capability minted only by :func:`prepare_host_admission`.

    The public ``facts`` are not authority and may be copied freely.  Finalize
    accepts this opaque object and resolves its authoritative state from the
    caller-owned Session registry populated by prepare in the same root
    transaction.  Constructing or copying facts therefore cannot manufacture
    a dispatch-consumption capability.
    """

    __slots__ = ("_facts",)

    def __init__(
        self, *, mint: object, facts: HostAdmissionVerificationFactsV1
    ) -> None:
        if mint is not _PREPARED_MINT:
            raise TypeError("prepared host admission is minted by prepare only")
        self._facts = facts

    @property
    def facts(self) -> HostAdmissionVerificationFactsV1:
        return self._facts


@dataclass(frozen=True, slots=True)
class _PreparedHostAdmissionState:
    facts: HostAdmissionVerificationFactsV1
    credential_id: UUID
    credential_key_id: str
    credential_fingerprint: str
    association: TargetHostAssociationView
    policy: TargetAdmissionPolicyView
    prepared_at: datetime
    session: Session = field(repr=False, compare=False)
    transaction: object = field(repr=False, compare=False)


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


def prepare_host_admission(
    db: Session,
    *,
    attempt_id: UUID,
    presentation: HostAdmissionPresentationV1,
) -> _PreparedHostAdmission:
    """Authenticate, lock and return immutable verification facts only."""
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
    initial_identity = _credential_identity(candidate)
    verify_host_admission_presentation(
        presentation,
        verifier=security.verifier,
        algorithm=candidate.algorithm,
        public_key_fingerprint=candidate.public_key_fingerprint,
        public_key_b64=candidate.public_key_b64,
        now=now,
    )

    target = lock_target(db, candidate.target_id)
    try:
        credential = _load_credential_for_update(db, candidate.id)
    except DeploymentControlError as exc:
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_CHANGED,
            "credential disappeared before the lock was acquired",
        ) from exc
    if _credential_identity(credential) != initial_identity:
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_CHANGED,
            "credential verification terms changed before the lock was acquired",
        )
    if credential.purpose != HOST_ADMISSION_PRESENTATION_PURPOSE:
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_PURPOSE_MISMATCH,
            "credential is not enrolled for host-admission presentations",
        )
    if not _credential_is_active(credential, now=now):
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_NOT_ACTIVE,
            "credential is not active at the trusted preparation instant",
        )
    recomputed = PublicKeyFingerprintV1.from_public_key_b64(
        credential.public_key_b64
    ).canonical
    if recomputed != credential.public_key_fingerprint:
        raise _refuse(
            HostAdmissionRefusalCode.CREDENTIAL_CHANGED,
            "credential public material disagrees with its fingerprint",
        )

    association = require_current_target_host_locked(db, target.id)
    policy = require_current_target_admission_policy_locked(db, target.id)
    if policy.host_association_id != association.association_id:
        raise _refuse(
            HostAdmissionRefusalCode.POLICY_HOST_MISMATCH,
            "current admission policy does not bind the current host association",
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
    dispatch = _require_stored_dispatch(db, attempt_id=attempt_id, target_id=target.id)
    statement = presentation.statement
    if statement.dispatch_id != dispatch.dispatch_id:
        raise _refuse(
            HostAdmissionRefusalCode.DISPATCH_MISMATCH,
            "presentation does not name the signed stored dispatch id",
        )
    transaction = db.get_transaction()
    if transaction is None or not transaction.is_active:
        raise _refuse(
            HostAdmissionRefusalCode.TRANSACTION_CHANGED,
            "preparation has no active caller-owned root transaction",
        )
    facts = HostAdmissionVerificationFactsV1(
        attempt_id=attempt_id,
        dispatch_id=dispatch.dispatch_id,
        dispatch_envelope_digest=dispatch.dispatch_envelope_digest,
        candidate_attestation_envelope_digest=(
            statement.candidate_attestation_envelope_digest
        ),
        installed_attestation_envelope_digest=(
            statement.installed_attestation_envelope_digest
        ),
        target_id=target.id,
        target_ref=target.target_ref,
        host_id=association.host_id,
        public_key_fingerprint=installed_root.public_key_fingerprint,
        trust_root_version=installed_root.root_version,
        candidate_root=candidate_root,
        installed_root=installed_root,
        candidate_audience=policy.candidate_audience,
        installed_audience=policy.installed_audience,
        expected_foundation_package=policy.expected_foundation_package,
    )
    prepared = _PreparedHostAdmission(mint=_PREPARED_MINT, facts=facts)
    state = _PreparedHostAdmissionState(
        facts=facts,
        credential_id=credential.id,
        credential_key_id=credential.key_id,
        credential_fingerprint=credential.public_key_fingerprint,
        association=association,
        policy=policy,
        prepared_at=now,
        session=db,
        transaction=transaction,
    )
    registry = db.info.setdefault(_PREPARED_SESSION_KEY, {})
    assert isinstance(registry, dict)
    registry[id(prepared)] = (prepared, state)
    return prepared


def _require_prepared_state(
    db: Session, prepared: object
) -> _PreparedHostAdmissionState:
    registry = db.info.get(_PREPARED_SESSION_KEY)
    entry = registry.get(id(prepared)) if isinstance(registry, dict) else None
    if (
        not isinstance(prepared, _PreparedHostAdmission)
        or not isinstance(entry, tuple)
        or len(entry) != 2
        or entry[0] is not prepared
        or not isinstance(entry[1], _PreparedHostAdmissionState)
    ):
        raise _refuse(
            HostAdmissionRefusalCode.AUTHENTICATION_FAILED,
            "prepared capability was not minted by authentication in this session",
        )
    state = entry[1]
    current = db.get_transaction()
    if (
        state.session is not db
        or current is None
        or current is not state.transaction
        or not current.is_active
    ):
        raise _refuse(
            HostAdmissionRefusalCode.TRANSACTION_CHANGED,
            "prepare and finalize must share one still-active root transaction",
        )
    return state


def finalize_host_admission(
    db: Session,
    *,
    prepared: object,
    candidate_attestation_envelope_digest: str,
    installed_attestation_envelope_digest: str,
) -> _StagedDispatchConsumption:
    """Recheck the prepared coordinate and stage exactly one consumption."""
    state = _require_prepared_state(db, prepared)
    facts = state.facts
    if (
        candidate_attestation_envelope_digest
        != facts.candidate_attestation_envelope_digest
        or installed_attestation_envelope_digest
        != facts.installed_attestation_envelope_digest
    ):
        raise _refuse(
            HostAdmissionRefusalCode.EVIDENCE_CHANGED,
            "verified attestation digests differ from the signed presentation",
        )
    target = lock_target(db, facts.target_id)
    if target.target_ref != facts.target_ref:
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "target reference differs from preparation",
        )
    try:
        credential = _load_credential_for_update(db, state.credential_id)
    except DeploymentControlError as exc:
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "credential disappeared after preparation",
        ) from exc
    if (
        credential.key_id != state.credential_key_id
        or credential.public_key_fingerprint != state.credential_fingerprint
        or credential.purpose != HOST_ADMISSION_PRESENTATION_PURPOSE
        or not _credential_is_active(credential, now=state.prepared_at)
    ):
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "credential differs from preparation",
        )
    association = require_current_target_host_locked(db, target.id)
    policy = require_current_target_admission_policy_locked(db, target.id)
    if association != state.association or policy != state.policy:
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "host association or admission policy differs from preparation",
        )
    candidate_root = _resolve_root_context(
        db,
        custody_domain="candidate_release_signer",
        subject=policy.candidate_root_subject,
        purpose=CANDIDATE_ATTESTATION_PURPOSE,
        now=state.prepared_at,
    )
    installed_root = _resolve_root_context(
        db,
        custody_domain="host_attester",
        subject=association.host_id,
        purpose=INSTALLED_OBSERVATION_PURPOSE,
        now=state.prepared_at,
    )
    if candidate_root != facts.candidate_root or installed_root != facts.installed_root:
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "attestation root coordinate differs from preparation",
        )
    dispatch = _require_stored_dispatch(
        db, attempt_id=facts.attempt_id, target_id=target.id
    )
    if (
        dispatch.dispatch_id != facts.dispatch_id
        or dispatch.dispatch_envelope_digest != facts.dispatch_envelope_digest
    ):
        raise _refuse(
            HostAdmissionRefusalCode.PREPARED_STATE_CHANGED,
            "stored dispatch differs from preparation",
        )
    staged = _stage_dispatch_consumption(
        db,
        attempt_id=facts.attempt_id,
        expected_target=_ExpectedDispatchTarget(
            target_id=facts.target_id, target_ref=facts.target_ref
        ),
        candidate_attestation_envelope_digest=(candidate_attestation_envelope_digest),
        installed_attestation_envelope_digest=(installed_attestation_envelope_digest),
    )
    registry = db.info.get(_PREPARED_SESSION_KEY)
    assert isinstance(registry, dict)
    registry.pop(id(prepared), None)
    return staged


__all__ = [
    "HostAdmissionClock",
    "HostAdmissionRefusalCode",
    "HostAdmissionRefusedError",
    "HostAdmissionRootContextV1",
    "HostAdmissionVerificationFactsV1",
    "finalize_host_admission",
    "install_host_admission_security",
    "prepare_host_admission",
]
