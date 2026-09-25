"""Startup-fixed V3 pair verification and committed recovery for one finalizer.

The signed pair is verified before any Control row is locked.  A request carries
no verifier, clock, or authority to select a target: the two purpose-specific
verifiers and clock are installed once by the composing assembly at startup.
The sole public host-admission finalizer stages the existing permanent dispatch
marker; the assembly commits its Session before returning to Foundation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol
from uuid import UUID

from dotmac_kernel.idempotency_models import (
    IdempotencyStatus,
    PlatformIdempotencyRecord,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_deployment_control.authorization import (
    AuthorizationEnvelopeV2,
    AuthorizationVerifier,
)
from dotmac_deployment_control.digests import (
    AuthorizationEnvelopeDigestV1,
    DispatchEnvelopeDigestV1,
    ExecutionPlanDigestV1,
    canonical_json,
)
from dotmac_deployment_control.dispatch_envelope import (
    DispatchEnvelopeV1,
    DispatchVerifier,
    verify_dispatch_envelope,
)
from dotmac_deployment_control.host_admission import admission_consumption_fingerprint
from dotmac_deployment_control.ports import DeploymentControlError
from dotmac_deployment_control.service import (
    _SCOPE_CONSUME_DISPATCH_CHALLENGE,
    _ExpectedFoundationConsumption,
)


class FoundationConsumptionRefusedError(DeploymentControlError):
    """The exact signed pair or its fresh Control standing cannot be consumed."""


class FoundationConsumptionClock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class _Security:
    authorization_verifier: AuthorizationVerifier
    dispatch_verifier: DispatchVerifier
    clock: FoundationConsumptionClock


_INSTALL_LOCK = Lock()
_installed_security: _Security | None = None


def install_foundation_consumption_security(
    *,
    authorization_verifier: AuthorizationVerifier,
    dispatch_verifier: DispatchVerifier,
    clock: FoundationConsumptionClock,
) -> None:
    """Install purpose-specific verification and time once during startup."""
    if not isinstance(authorization_verifier, AuthorizationVerifier):
        raise TypeError("authorization_verifier does not satisfy its port")
    if not isinstance(dispatch_verifier, DispatchVerifier):
        raise TypeError("dispatch_verifier does not satisfy its port")
    if not callable(getattr(clock, "now", None)):
        raise TypeError("clock does not satisfy its port")
    global _installed_security
    with _INSTALL_LOCK:
        if _installed_security is not None:
            raise RuntimeError("Foundation consumption security is already installed")
        _installed_security = _Security(
            authorization_verifier=authorization_verifier,
            dispatch_verifier=dispatch_verifier,
            clock=clock,
        )


def _reset_foundation_consumption_security_for_tests() -> None:
    global _installed_security
    with _INSTALL_LOCK:
        _installed_security = None


def _security() -> _Security:
    if _installed_security is None:
        raise FoundationConsumptionRefusedError(
            "Foundation consumption security was not installed at startup"
        )
    return _installed_security


@dataclass(frozen=True, slots=True)
class FoundationExecutionContextV1:
    """Control-owned part of CP's independently observed V3 execution context.

    Controller and host facts are checked by CP/F2; Control cannot read their
    owners' databases and therefore does not accept them as Control evidence.
    """

    product_code: str
    environment: str
    target_id: str
    target_ref: str
    operation: str
    release_ref: str
    rollout_ref: str
    plan_id: str
    approval_decision_ref: str
    control_plan_digest: str
    execution_sequence: int
    attempt_no: int


@dataclass(frozen=True, slots=True)
class FoundationSignedReceiptV2:
    authorization_envelope_digest: str
    dispatch_envelope_digest: str
    authorization_id: str
    dispatch_id: str
    authorization_signer_key_id: str
    authorization_signer_algorithm: str
    authorization_signer_public_key_fingerprint: str
    dispatch_signer_key_id: str
    dispatch_signer_algorithm: str
    dispatch_signer_public_key_fingerprint: str
    product_code: str
    environment: str
    target_id: str
    target_ref: str
    operation: str
    release_ref: str
    rollout_ref: str
    plan_id: str
    approval_decision_ref: str
    authorization_issued_at: str
    authorization_expires_at: str
    dispatch_issued_at: str
    execution_sequence: int
    attempt_no: int
    descriptor_digest: str
    execution_plan_digest: str
    control_plan_digest: str


@dataclass(frozen=True, slots=True)
class FoundationDispatchConsumptionV1:
    authorization_material_json: bytes
    dispatch_material_json: bytes
    expected_context: FoundationExecutionContextV1
    expected_execution_plan_digest: str
    control_consumption_ref: str


@dataclass(frozen=True, slots=True)
class FoundationCommittedConsumptionV1:
    control_consumption_ref: str
    attempt_id: UUID
    dispatch_id: str
    authorization_envelope_digest: str
    dispatch_envelope_digest: str
    execution_plan_digest: str
    candidate_attestation_envelope_digest: str
    installed_attestation_envelope_digest: str


def _document(raw: bytes, *, name: str) -> object:
    if not isinstance(raw, bytes):
        raise FoundationConsumptionRefusedError(f"{name} must be JSON bytes")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise FoundationConsumptionRefusedError(f"{name} repeats {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise FoundationConsumptionRefusedError(f"{name} is not valid JSON") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise FoundationConsumptionRefusedError(f"{name} is not canonical JSON")
    return document


def _instant(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _receipt_from_pair(
    authorization: AuthorizationEnvelopeV2, dispatch: DispatchEnvelopeV1
) -> FoundationSignedReceiptV2:
    auth = authorization.statement
    sent = dispatch.statement
    if auth.approval_decision_ref is None:
        raise FoundationConsumptionRefusedError(
            "Foundation execution requires a decision"
        )
    return FoundationSignedReceiptV2(
        authorization_envelope_digest=AuthorizationEnvelopeDigestV1.over_bytes(
            authorization.canonical_bytes
        ).canonical,
        dispatch_envelope_digest=DispatchEnvelopeDigestV1.over_bytes(
            dispatch.canonical_bytes
        ).canonical,
        authorization_id=auth.authorization_id,
        dispatch_id=sent.dispatch_id,
        authorization_signer_key_id=auth.key_id,
        authorization_signer_algorithm=auth.algorithm,
        authorization_signer_public_key_fingerprint=auth.public_key_fingerprint,
        dispatch_signer_key_id=sent.key_id,
        dispatch_signer_algorithm=sent.algorithm,
        dispatch_signer_public_key_fingerprint=sent.public_key_fingerprint,
        product_code=auth.product_code,
        environment=auth.environment,
        target_id=auth.target_id,
        target_ref=auth.target_ref,
        operation=auth.operation,
        release_ref=auth.release_ref,
        rollout_ref=auth.rollout_ref,
        plan_id=auth.plan_id,
        approval_decision_ref=auth.approval_decision_ref,
        authorization_issued_at=_instant(auth.issued_at),
        authorization_expires_at=_instant(auth.expires_at),
        dispatch_issued_at=_instant(sent.issued_at),
        execution_sequence=auth.execution_sequence,
        attempt_no=sent.attempt_no,
        descriptor_digest=auth.descriptor_digest,
        execution_plan_digest=auth.execution_plan_digest,
        control_plan_digest=auth.plan_digest,
    )


def attest_foundation_execution_pair(
    *,
    authorization_material: Mapping[str, object],
    dispatch_material: Mapping[str, object],
) -> FoundationSignedReceiptV2:
    """Verify both signed purposes with the startup-installed trust bindings."""
    security = _security()
    now = security.clock.now()
    if now.tzinfo is None:
        raise FoundationConsumptionRefusedError("startup clock returned naive time")
    dispatch = verify_dispatch_envelope(
        dispatch_material,
        authorization_envelope=authorization_material,
        authorization_verifier=security.authorization_verifier,
        dispatch_verifier=security.dispatch_verifier,
        at=now,
    )
    authorization = AuthorizationEnvelopeV2.parse(authorization_material)
    return _receipt_from_pair(authorization, dispatch)


def _verify_foundation_execution_request(
    request: FoundationDispatchConsumptionV1,
) -> _ExpectedFoundationConsumption:
    """Verify exact canonical signed pair before the finalizer locks rows."""
    if type(request) is not FoundationDispatchConsumptionV1:
        raise FoundationConsumptionRefusedError(
            "a typed consumption request is required"
        )
    security = _security()
    now = security.clock.now()
    if now.tzinfo is None:
        raise FoundationConsumptionRefusedError("startup clock returned naive time")
    authorization_document = _document(
        request.authorization_material_json, name="authorization material"
    )
    dispatch_document = _document(
        request.dispatch_material_json, name="dispatch material"
    )
    dispatch = verify_dispatch_envelope(
        dispatch_document,
        authorization_envelope=authorization_document,
        authorization_verifier=security.authorization_verifier,
        dispatch_verifier=security.dispatch_verifier,
        at=now,
    )
    authorization = AuthorizationEnvelopeV2.parse(authorization_document)
    receipt = _receipt_from_pair(authorization, dispatch)
    if request.control_consumption_ref != f"control-dispatch:{receipt.dispatch_id}":
        raise FoundationConsumptionRefusedError("Control recovery coordinate differs")
    if request.expected_execution_plan_digest != receipt.execution_plan_digest:
        raise FoundationConsumptionRefusedError("execution plan digest differs")
    context = request.expected_context
    if not isinstance(context, FoundationExecutionContextV1):
        raise FoundationConsumptionRefusedError("typed execution context is required")
    for field in fields(context):
        if hasattr(receipt, field.name) and getattr(context, field.name) != getattr(
            receipt, field.name
        ):
            raise FoundationConsumptionRefusedError(
                f"execution context {field.name} differs from signed pair"
            )
    try:
        UUID(receipt.dispatch_id)
        UUID(context.target_id)
    except ValueError as exc:
        raise FoundationConsumptionRefusedError(
            "signed dispatch IDs are not UUIDs"
        ) from exc
    return _ExpectedFoundationConsumption(
        authorization=authorization,
        dispatch=dispatch,
        context=context,
        execution_plan_digest=request.expected_execution_plan_digest,
    )


def lookup_foundation_execution_consumption(
    db: Session, *, control_consumption_ref: str
) -> FoundationCommittedConsumptionV1 | None:
    """Read committed evidence in a NEW transaction after the caller commits.

    An uncommitted marker is visible to its writing Session; callers must use a
    separate post-commit Session for crash recovery.
    """
    prefix = "control-dispatch:"
    if not isinstance(
        control_consumption_ref, str
    ) or not control_consumption_ref.startswith(prefix):
        raise FoundationConsumptionRefusedError("invalid Control recovery coordinate")
    dispatch_id = control_consumption_ref[len(prefix) :]
    try:
        if str(UUID(dispatch_id)) != dispatch_id:
            raise ValueError("dispatch ID is not canonical")
    except ValueError as exc:
        raise FoundationConsumptionRefusedError("invalid dispatch ID") from exc
    record = db.execute(
        select(PlatformIdempotencyRecord).where(
            PlatformIdempotencyRecord.scope == _SCOPE_CONSUME_DISPATCH_CHALLENGE,
            PlatformIdempotencyRecord.key == dispatch_id,
        )
    ).scalar_one_or_none()
    if record is None:
        return None
    result = record.result
    if not isinstance(result, dict) or result.get("kind") != "foundation_v3":
        return None
    if result.get("dispatch_id") != dispatch_id:
        raise FoundationConsumptionRefusedError("stored consumption identity differs")
    try:
        attempt_id = UUID(result["attempt_id"])
        auth_digest = AuthorizationEnvelopeDigestV1.parse(
            result["authorization_envelope_digest"]
        ).canonical
        dispatch_digest = DispatchEnvelopeDigestV1.parse(
            result["dispatch_digest"]
        ).canonical
        plan_digest = ExecutionPlanDigestV1.parse(
            result["execution_plan_digest"]
        ).canonical
        candidate_digest = result["candidate_attestation_envelope_digest"]
        installed_digest = result["installed_attestation_envelope_digest"]
        if not all(
            isinstance(value, str) for value in (candidate_digest, installed_digest)
        ):
            raise ValueError("stored attestation digests must be strings")
    except (KeyError, TypeError, ValueError, DeploymentControlError) as exc:
        raise FoundationConsumptionRefusedError(
            "stored consumption is malformed"
        ) from exc
    try:
        expected_fingerprint = admission_consumption_fingerprint(
            dispatch_envelope_digest=dispatch_digest,
            candidate_attestation_envelope_digest=candidate_digest,
            installed_attestation_envelope_digest=installed_digest,
        )
    except DeploymentControlError as exc:
        raise FoundationConsumptionRefusedError(
            "stored attestation coordinate is malformed"
        ) from exc
    if (
        str(attempt_id) != dispatch_id
        or record.status != IdempotencyStatus.EXECUTED.value
        or record.operation != _SCOPE_CONSUME_DISPATCH_CHALLENGE
        or record.expires_at is not None
        or record.fingerprint != expected_fingerprint
    ):
        raise FoundationConsumptionRefusedError("stored consumption evidence differs")
    return FoundationCommittedConsumptionV1(
        control_consumption_ref=control_consumption_ref,
        attempt_id=attempt_id,
        dispatch_id=dispatch_id,
        authorization_envelope_digest=auth_digest,
        dispatch_envelope_digest=dispatch_digest,
        execution_plan_digest=plan_digest,
        candidate_attestation_envelope_digest=candidate_digest,
        installed_attestation_envelope_digest=installed_digest,
    )


__all__ = [
    "FoundationCommittedConsumptionV1",
    "FoundationConsumptionClock",
    "FoundationConsumptionRefusedError",
    "FoundationDispatchConsumptionV1",
    "FoundationExecutionContextV1",
    "FoundationSignedReceiptV2",
    "attest_foundation_execution_pair",
    "install_foundation_consumption_security",
    "lookup_foundation_execution_consumption",
]
