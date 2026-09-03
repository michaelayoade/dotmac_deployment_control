"""Purpose-separated Control-to-executor dispatch envelopes.

The authorization says *what may run*.  A dispatch says *which concrete
attempt Control is asking an executor to run*.  The latter adds the attempt
coordinate and therefore needs its own signature: an unsigned ``attempt_no``
beside a signed authorization can be changed without invalidating anything.

Control owns the canonical document but not a signing implementation.  The
injected signer/verifier use method names and identity types that are
deliberately incompatible with both authorization and target-observation keys.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version
from typing import Any, Protocol, runtime_checkable

from dotmac_deployment_control.authorization import (
    AuthorizationEnvelopeV2,
    AuthorizationVerifier,
    verify_authorization_envelope,
)
from dotmac_deployment_control.digests import (
    AuthorizationEnvelopeDigestV1,
    DescriptorDigestV1,
    ExecutionPlanDigestV1,
    PlanDigestV1,
    PublicKeyFingerprintV1,
    canonical_json,
)
from dotmac_deployment_control.images import (
    AuthorizedImage,
    authorized_image_set,
    image_set_payload,
)
from dotmac_deployment_control.ports import DeploymentControlError

DISPATCH_SCHEMA = "dotmac.deployment-dispatch"
DISPATCH_VERSION = 1
DISPATCH_PURPOSE = "deployment_dispatch"
_DISTRIBUTION = "dotmac-deployment-control"


class DispatchEnvelopeRefusalCode(StrEnum):
    ABSENT = "dispatch_envelope_absent"
    MALFORMED = "dispatch_envelope_malformed"
    UNSUPPORTED_VERSION = "dispatch_envelope_unsupported_version"
    UNSIGNED = "dispatch_envelope_unsigned"
    SIGNER_IDENTITY_MISMATCH = "dispatch_signer_identity_mismatch"
    SIGNATURE_INVALID = "dispatch_signature_invalid"
    SIGNER_PURPOSE_REUSED = "dispatch_signer_purpose_reused"
    AUTHORIZATION_MISMATCH = "dispatch_authorization_mismatch"
    CONTROL_VERSION_UNAVAILABLE = "dispatch_control_version_unavailable"
    PURPOSE_MISMATCH = "dispatch_purpose_mismatch"
    NOT_YET_VALID = "dispatch_not_yet_valid"


class DispatchEnvelopeRefusedError(DeploymentControlError):
    """A typed refusal that cannot be mistaken for a verified dispatch."""

    def __init__(self, code: DispatchEnvelopeRefusalCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


@dataclass(frozen=True, slots=True)
class DispatchSignerIdentity:
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = DISPATCH_PURPOSE

    def __post_init__(self) -> None:
        _bounded_text(self.key_id, field="key_id")
        _bounded_text(self.algorithm, field="algorithm")
        PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        if self.purpose != DISPATCH_PURPOSE:
            raise _refused(
                DispatchEnvelopeRefusalCode.PURPOSE_MISMATCH,
                "a dispatch signer must declare the deployment dispatch purpose",
            )


@dataclass(frozen=True, slots=True)
class DispatchSignature:
    key_id: str
    algorithm: str
    purpose: str
    public_key_fingerprint: str
    signature: str


@runtime_checkable
class DispatchSigner(Protocol):
    """Control-side signer; intentionally unlike the authorization signer."""

    @property
    def dispatch_identity(self) -> DispatchSignerIdentity: ...

    def sign_dispatch(self, canonical_bytes: bytes) -> DispatchSignature: ...


@runtime_checkable
class DispatchVerifier(Protocol):
    """Executor-side verifier for the dispatch purpose only."""

    def verify_dispatch(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class DispatchStatementV1:
    dispatch_id: str
    authorization_id: str
    authorization_plan_id: str
    authorization_control_version: str
    authorization_key_id: str
    authorization_public_key_fingerprint: str
    authorization_envelope_digest: str
    execution_sequence: int
    attempt_no: int
    rollout_ref: str
    target_id: str
    target_ref: str
    product_code: str
    environment: str
    operation: str
    release_ref: str
    authorized_images: tuple[AuthorizedImage, ...]
    plan_digest: str
    descriptor_digest: str
    execution_plan_digest: str
    issued_at: datetime
    control_version: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = DISPATCH_PURPOSE

    def __post_init__(self) -> None:
        for field in (
            "dispatch_id",
            "authorization_id",
            "authorization_plan_id",
            "authorization_control_version",
            "authorization_key_id",
            "rollout_ref",
            "target_id",
            "target_ref",
            "product_code",
            "environment",
            "operation",
            "release_ref",
            "control_version",
            "key_id",
            "algorithm",
        ):
            _bounded_text(getattr(self, field), field=field)
        if self.purpose != DISPATCH_PURPOSE:
            raise _refused(
                DispatchEnvelopeRefusalCode.PURPOSE_MISMATCH,
                "the statement does not carry the deployment dispatch purpose",
            )
        for field in ("execution_sequence", "attempt_no"):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise _refused(
                    DispatchEnvelopeRefusalCode.MALFORMED,
                    f"{field} must be a positive integer",
                )
        AuthorizationEnvelopeDigestV1.parse(self.authorization_envelope_digest)
        PublicKeyFingerprintV1.parse(self.authorization_public_key_fingerprint)
        PlanDigestV1.parse(self.plan_digest)
        DescriptorDigestV1.parse(self.descriptor_digest)
        ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        canonical = authorized_image_set(
            self.authorized_images, where="dispatch authorized image set"
        )
        if canonical is None or canonical != self.authorized_images:
            raise _refused(
                DispatchEnvelopeRefusalCode.MALFORMED,
                "authorized_images must be the canonical ordered image set",
            )
        _aware_utc(self.issued_at, field="issued_at")

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": DISPATCH_SCHEMA,
            "version": DISPATCH_VERSION,
            "purpose": self.purpose,
            "dispatch_id": self.dispatch_id,
            "authorization_id": self.authorization_id,
            "authorization_plan_id": self.authorization_plan_id,
            "authorization_control_version": self.authorization_control_version,
            "authorization_key_id": self.authorization_key_id,
            "authorization_public_key_fingerprint": (
                self.authorization_public_key_fingerprint
            ),
            "authorization_envelope_digest": self.authorization_envelope_digest,
            "execution_sequence": self.execution_sequence,
            "attempt_no": self.attempt_no,
            "rollout_ref": self.rollout_ref,
            "target_id": self.target_id,
            "target_ref": self.target_ref,
            "product_code": self.product_code,
            "environment": self.environment,
            "operation": self.operation,
            "release_ref": self.release_ref,
            "authorized_images": image_set_payload(self.authorized_images),
            "plan_digest": self.plan_digest,
            "descriptor_digest": self.descriptor_digest,
            "execution_plan_digest": self.execution_plan_digest,
            "issued_at": _timestamp(self.issued_at),
            "control_version": self.control_version,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_fingerprint": self.public_key_fingerprint,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class DispatchEnvelopeV1:
    statement: DispatchStatementV1
    signature: str

    def __post_init__(self) -> None:
        _bounded_text(self.signature, field="signature", maximum=16_384)

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())

    @classmethod
    def parse(cls, value: object) -> DispatchEnvelopeV1:
        if isinstance(value, cls):
            return value
        row = _exact_mapping(value, {"statement", "signature"}, where="envelope")
        signature = row["signature"]
        if not isinstance(signature, str) or not signature:
            raise _refused(
                DispatchEnvelopeRefusalCode.UNSIGNED,
                "the deployment dispatch carries no signature",
            )
        try:
            statement = _parse_statement(row["statement"])
        except DispatchEnvelopeRefusedError:
            raise
        except DeploymentControlError as exc:
            raise _refused(
                DispatchEnvelopeRefusalCode.MALFORMED,
                f"the signed statement contains an unreadable typed value: {exc}",
            ) from exc
        return cls(statement=statement, signature=signature)


def issue_dispatch_envelope(
    *,
    authorization_envelope: AuthorizationEnvelopeV2,
    dispatch_id: str,
    attempt_no: int,
    issued_at: datetime,
    signer: DispatchSigner,
) -> DispatchEnvelopeV1:
    """Derive every authorized term from one already-verified envelope."""
    if not isinstance(signer, DispatchSigner):
        raise _refused(
            DispatchEnvelopeRefusalCode.PURPOSE_MISMATCH,
            "the injected signer does not implement the deployment dispatch purpose",
        )
    identity = signer.dispatch_identity
    if not isinstance(identity, DispatchSignerIdentity):
        raise _refused(
            DispatchEnvelopeRefusalCode.PURPOSE_MISMATCH,
            "the signer did not expose a dispatch identity",
        )
    authorization = AuthorizationEnvelopeV2.parse(authorization_envelope)
    authorized = authorization.statement
    if identity.public_key_fingerprint == authorized.public_key_fingerprint:
        raise _refused(
            DispatchEnvelopeRefusalCode.SIGNER_PURPOSE_REUSED,
            "the authorization signing key cannot also sign deployment dispatches",
        )
    dispatch_issued_at = _aware_utc(issued_at, field="issued_at")
    authorization_issued_at = _aware_utc(
        authorized.issued_at, field="authorization issued_at"
    )
    authorization_expires_at = _aware_utc(
        authorized.expires_at, field="authorization expires_at"
    )
    if not authorization_issued_at <= dispatch_issued_at < authorization_expires_at:
        raise _refused(
            DispatchEnvelopeRefusalCode.AUTHORIZATION_MISMATCH,
            "the dispatch issued_at falls outside the signed authorization lifetime",
        )
    statement = DispatchStatementV1(
        dispatch_id=_bounded_text(dispatch_id, field="dispatch_id"),
        authorization_id=authorized.authorization_id,
        authorization_plan_id=authorized.plan_id,
        authorization_control_version=authorized.control_version,
        authorization_key_id=authorized.key_id,
        authorization_public_key_fingerprint=authorized.public_key_fingerprint,
        authorization_envelope_digest=AuthorizationEnvelopeDigestV1.over_bytes(
            authorization.canonical_bytes
        ).canonical,
        execution_sequence=authorized.execution_sequence,
        attempt_no=attempt_no,
        rollout_ref=authorized.rollout_ref,
        target_id=authorized.target_id,
        target_ref=authorized.target_ref,
        product_code=authorized.product_code,
        environment=authorized.environment,
        operation=authorized.operation,
        release_ref=authorized.release_ref,
        authorized_images=authorized.authorized_images,
        plan_digest=authorized.plan_digest,
        descriptor_digest=authorized.descriptor_digest,
        execution_plan_digest=authorized.execution_plan_digest,
        issued_at=dispatch_issued_at,
        control_version=_installed_control_version(),
        key_id=identity.key_id,
        algorithm=identity.algorithm,
        public_key_fingerprint=identity.public_key_fingerprint,
        purpose=identity.purpose,
    )
    signed = signer.sign_dispatch(statement.canonical_bytes)
    if (
        signed.key_id != statement.key_id
        or signed.algorithm != statement.algorithm
        or signed.purpose != statement.purpose
        or signed.public_key_fingerprint != statement.public_key_fingerprint
    ):
        raise _refused(
            DispatchEnvelopeRefusalCode.SIGNER_IDENTITY_MISMATCH,
            "the signer returned an identity different from the values already "
            "bound into the signed dispatch bytes",
        )
    if not signed.signature:
        raise _refused(
            DispatchEnvelopeRefusalCode.UNSIGNED,
            "the dispatch signer returned an empty signature",
        )
    return DispatchEnvelopeV1(statement=statement, signature=signed.signature)


def verify_dispatch_envelope(
    value: object,
    *,
    authorization_envelope: object,
    authorization_verifier: AuthorizationVerifier,
    dispatch_verifier: DispatchVerifier,
    at: datetime | None = None,
) -> DispatchEnvelopeV1:
    """Verify both signatures and the exact authorization-to-dispatch binding."""
    if not isinstance(dispatch_verifier, DispatchVerifier):
        raise _refused(
            DispatchEnvelopeRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier does not implement dispatch verification",
        )
    dispatch = DispatchEnvelopeV1.parse(value)
    now = _aware_utc(at or datetime.now(UTC), field="at")
    if now < dispatch.statement.issued_at:
        raise _refused(
            DispatchEnvelopeRefusalCode.NOT_YET_VALID,
            "the dispatch was presented before its issued_at instant",
        )
    authorization = verify_authorization_envelope(
        authorization_envelope, verifier=authorization_verifier, at=now
    )
    if (
        dispatch.statement.public_key_fingerprint
        == authorization.statement.public_key_fingerprint
    ):
        raise _refused(
            DispatchEnvelopeRefusalCode.SIGNER_PURPOSE_REUSED,
            "the authorization signing key cannot also sign deployment dispatches",
        )
    authorization_issued_at = _aware_utc(
        authorization.statement.issued_at, field="authorization issued_at"
    )
    authorization_expires_at = _aware_utc(
        authorization.statement.expires_at, field="authorization expires_at"
    )
    if not (
        authorization_issued_at
        <= dispatch.statement.issued_at
        < authorization_expires_at
    ):
        raise _refused(
            DispatchEnvelopeRefusalCode.AUTHORIZATION_MISMATCH,
            "the dispatch issued_at falls outside the signed authorization lifetime",
        )
    expected = _authorization_projection(authorization)
    actual = _dispatch_authorization_projection(dispatch.statement)
    if actual != expected:
        raise _refused(
            DispatchEnvelopeRefusalCode.AUTHORIZATION_MISMATCH,
            "the signed dispatch does not bind the exact verified authorization",
        )
    statement = dispatch.statement
    if not dispatch_verifier.verify_dispatch(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_fingerprint=statement.public_key_fingerprint,
        canonical_bytes=statement.canonical_bytes,
        signature=dispatch.signature,
    ):
        raise _refused(
            DispatchEnvelopeRefusalCode.SIGNATURE_INVALID,
            "the injected dispatch verifier refused the signature",
        )
    return dispatch


def _authorization_projection(envelope: AuthorizationEnvelopeV2) -> tuple[object, ...]:
    statement = envelope.statement
    return (
        statement.authorization_id,
        statement.plan_id,
        statement.control_version,
        statement.key_id,
        statement.public_key_fingerprint,
        AuthorizationEnvelopeDigestV1.over_bytes(envelope.canonical_bytes).canonical,
        statement.execution_sequence,
        statement.rollout_ref,
        statement.target_id,
        statement.target_ref,
        statement.product_code,
        statement.environment,
        statement.operation,
        statement.release_ref,
        statement.authorized_images,
        statement.plan_digest,
        statement.descriptor_digest,
        statement.execution_plan_digest,
    )


def _dispatch_authorization_projection(
    statement: DispatchStatementV1,
) -> tuple[object, ...]:
    return (
        statement.authorization_id,
        statement.authorization_plan_id,
        statement.authorization_control_version,
        statement.authorization_key_id,
        statement.authorization_public_key_fingerprint,
        statement.authorization_envelope_digest,
        statement.execution_sequence,
        statement.rollout_ref,
        statement.target_id,
        statement.target_ref,
        statement.product_code,
        statement.environment,
        statement.operation,
        statement.release_ref,
        statement.authorized_images,
        statement.plan_digest,
        statement.descriptor_digest,
        statement.execution_plan_digest,
    )


_STATEMENT_KEYS = {
    "schema",
    "version",
    "purpose",
    "dispatch_id",
    "authorization_id",
    "authorization_plan_id",
    "authorization_control_version",
    "authorization_key_id",
    "authorization_public_key_fingerprint",
    "authorization_envelope_digest",
    "execution_sequence",
    "attempt_no",
    "rollout_ref",
    "target_id",
    "target_ref",
    "product_code",
    "environment",
    "operation",
    "release_ref",
    "authorized_images",
    "plan_digest",
    "descriptor_digest",
    "execution_plan_digest",
    "issued_at",
    "control_version",
    "key_id",
    "algorithm",
    "public_key_fingerprint",
}


def _parse_statement(value: object) -> DispatchStatementV1:
    row = _exact_mapping(value, _STATEMENT_KEYS, where="dispatch statement")
    if row["schema"] != DISPATCH_SCHEMA:
        raise _refused(
            DispatchEnvelopeRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported dispatch schema {row['schema']!r}",
        )
    if (
        not isinstance(row["version"], int)
        or isinstance(row["version"], bool)
        or row["version"] != DISPATCH_VERSION
    ):
        raise _refused(
            DispatchEnvelopeRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported dispatch version {row['version']!r}",
        )
    images = authorized_image_set(
        _sequence(row["authorized_images"], field="authorized_images"),
        where="dispatch authorized image set",
    )
    assert images is not None
    return DispatchStatementV1(
        dispatch_id=_text(row, "dispatch_id"),
        authorization_id=_text(row, "authorization_id"),
        authorization_plan_id=_text(row, "authorization_plan_id"),
        authorization_control_version=_text(row, "authorization_control_version"),
        authorization_key_id=_text(row, "authorization_key_id"),
        authorization_public_key_fingerprint=_text(
            row, "authorization_public_key_fingerprint"
        ),
        authorization_envelope_digest=_text(row, "authorization_envelope_digest"),
        execution_sequence=_positive_int(row, "execution_sequence"),
        attempt_no=_positive_int(row, "attempt_no"),
        rollout_ref=_text(row, "rollout_ref"),
        target_id=_text(row, "target_id"),
        target_ref=_text(row, "target_ref"),
        product_code=_text(row, "product_code"),
        environment=_text(row, "environment"),
        operation=_text(row, "operation"),
        release_ref=_text(row, "release_ref"),
        authorized_images=images,
        plan_digest=_text(row, "plan_digest"),
        descriptor_digest=_text(row, "descriptor_digest"),
        execution_plan_digest=_text(row, "execution_plan_digest"),
        issued_at=_datetime(row, "issued_at"),
        control_version=_text(row, "control_version"),
        key_id=_text(row, "key_id"),
        algorithm=_text(row, "algorithm"),
        public_key_fingerprint=_text(row, "public_key_fingerprint"),
        purpose=_text(row, "purpose"),
    )


def _exact_mapping(value: object, keys: set[str], *, where: str) -> Mapping[str, Any]:
    if value is None:
        raise _refused(DispatchEnvelopeRefusalCode.ABSENT, f"{where} is absent")
    if not isinstance(value, Mapping):
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{where} must be a mapping, not {type(value).__name__}",
        )
    if any(not isinstance(key, str) for key in value):
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{where} keys must all be strings",
        )
    actual = set(value)
    if actual != keys:
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{where} keys differ: missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}",
        )
    return value


def _text(row: Mapping[str, Any], field: str) -> str:
    value = row[field]
    if not isinstance(value, str):
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a string",
        )
    return value


def _sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a sequence",
        )
    return value


def _positive_int(row: Mapping[str, Any], field: str) -> int:
    value = row[field]
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a positive integer",
        )
    return value


def _datetime(row: Mapping[str, Any], field: str) -> datetime:
    value = _text(row, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{field} is not an ISO-8601 timestamp",
        ) from exc
    return _aware_utc(parsed, field=field)


def _timestamp(value: datetime) -> str:
    return _aware_utc(value, field="timestamp").isoformat().replace("+00:00", "Z")


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{field} must carry a timezone",
        )
    return value.astimezone(UTC)


def _bounded_text(value: object, *, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a non-empty, whitespace-exact string",
        )
    if len(value) > maximum:
        raise _refused(
            DispatchEnvelopeRefusalCode.MALFORMED,
            f"{field} exceeds {maximum} characters",
        )
    return value


def _installed_control_version() -> str:
    try:
        value = _distribution_version(_DISTRIBUTION)
    except PackageNotFoundError as exc:
        raise _refused(
            DispatchEnvelopeRefusalCode.CONTROL_VERSION_UNAVAILABLE,
            "the issuing distribution is not installed; Control will not guess "
            "its version from a source checkout",
        ) from exc
    return _bounded_text(value, field="control_version")


def _refused(
    code: DispatchEnvelopeRefusalCode, detail: str
) -> DispatchEnvelopeRefusedError:
    return DispatchEnvelopeRefusedError(code, detail)


__all__ = [
    "DISPATCH_PURPOSE",
    "DISPATCH_SCHEMA",
    "DISPATCH_VERSION",
    "DispatchEnvelopeRefusalCode",
    "DispatchEnvelopeRefusedError",
    "DispatchEnvelopeV1",
    "DispatchSignature",
    "DispatchSigner",
    "DispatchSignerIdentity",
    "DispatchStatementV1",
    "DispatchVerifier",
    "issue_dispatch_envelope",
    "verify_dispatch_envelope",
]
