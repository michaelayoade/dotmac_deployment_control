"""Portable, provider-neutral authorization envelopes.

Control owns the statement and its canonical bytes.  A caller injects the
cryptographic signer/verifier; this package stores no private key, imports no
provider SDK, and does not reuse the target-to-Control observation signer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version
from typing import Any, Protocol, runtime_checkable

from dotmac_deployment_control.digests import (
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

AUTHORIZATION_SCHEMA = "dotmac.deployment-authorization"
AUTHORIZATION_VERSION = 2
AUTHORIZATION_PURPOSE = "deployment_authorization"
_DISTRIBUTION = "dotmac-deployment-control"


class AuthorizationEnvelopeRefusalCode(StrEnum):
    ABSENT = "authorization_envelope_absent"
    MALFORMED = "authorization_envelope_malformed"
    UNSUPPORTED_VERSION = "authorization_envelope_unsupported_version"
    UNSIGNED = "authorization_envelope_unsigned"
    SIGNER_IDENTITY_MISMATCH = "authorization_signer_identity_mismatch"
    SIGNATURE_INVALID = "authorization_signature_invalid"
    APPROVAL_NOT_STANDING = "authorization_approval_not_standing"
    EXPIRED = "authorization_envelope_expired"
    NOT_YET_VALID = "authorization_envelope_not_yet_valid"
    CONTROL_VERSION_UNAVAILABLE = "authorization_control_version_unavailable"
    PURPOSE_MISMATCH = "authorization_purpose_mismatch"


class AuthorizationEnvelopeRefusedError(DeploymentControlError):
    """A typed refusal that can never be mistaken for an authorization."""

    def __init__(self, code: AuthorizationEnvelopeRefusalCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


@dataclass(frozen=True, slots=True)
class AuthorizationSignerIdentity:
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = AUTHORIZATION_PURPOSE

    def __post_init__(self) -> None:
        _bounded_text(self.key_id, field="key_id")
        _bounded_text(self.algorithm, field="algorithm")
        PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        if self.purpose != AUTHORIZATION_PURPOSE:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.PURPOSE_MISMATCH,
                "an authorization signer must declare the deployment authorization "
                "purpose",
            )


@dataclass(frozen=True, slots=True)
class AuthorizationSignature:
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    signature: str
    purpose: str = AUTHORIZATION_PURPOSE


@runtime_checkable
class AuthorizationSigner(Protocol):
    """Injected signer whose identity is known before bytes are constructed."""

    @property
    def identity(self) -> AuthorizationSignerIdentity: ...

    def sign(self, canonical_bytes: bytes) -> AuthorizationSignature: ...


@runtime_checkable
class AuthorizationVerifier(Protocol):
    """Injected verifier; Control chooses no algorithm or key provider."""

    def verify(
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
class AuthorizationStatementV1:
    authorization_id: str
    rollout_ref: str
    plan_id: str
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
    approval_policy_code: str | None
    approval_policy_version: int | None
    approval_decision_ref: str | None
    approval_decision_status: str
    approved_at: datetime | None
    issued_at: datetime
    expires_at: datetime
    key_id: str
    algorithm: str

    def __post_init__(self) -> None:
        for field in (
            "authorization_id",
            "rollout_ref",
            "plan_id",
            "target_id",
            "target_ref",
            "product_code",
            "environment",
            "operation",
            "release_ref",
            "approval_decision_status",
            "key_id",
            "algorithm",
        ):
            _bounded_text(getattr(self, field), field=field)
        # Portable authorizations are an a9 contract.  They never carry the
        # historical a4 spelling accepted only when reading old database rows.
        PlanDigestV1.parse(self.plan_digest)
        DescriptorDigestV1.parse(self.descriptor_digest)
        ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        canonical = authorized_image_set(
            self.authorized_images, where="authorization statement image set"
        )
        if canonical is None or canonical != self.authorized_images:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.MALFORMED,
                "authorized_images must be the canonical ordered image set",
            )
        issued = _aware_utc(self.issued_at, field="issued_at")
        expires = _aware_utc(self.expires_at, field="expires_at")
        if expires <= issued:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.MALFORMED,
                "expires_at must be later than issued_at",
            )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": AUTHORIZATION_SCHEMA,
            "version": 1,
            "authorization_id": self.authorization_id,
            "rollout_ref": self.rollout_ref,
            "plan_id": self.plan_id,
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
            "approval_policy_code": self.approval_policy_code,
            "approval_policy_version": self.approval_policy_version,
            "approval_decision_ref": self.approval_decision_ref,
            "approval_decision_status": self.approval_decision_status,
            "approved_at": _timestamp(self.approved_at),
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
            "key_id": self.key_id,
            "algorithm": self.algorithm,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class AuthorizationStatementV2:
    """The a10 authorization contract, including its issuing Control version."""

    authorization_id: str
    execution_sequence: int
    rollout_ref: str
    plan_id: str
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
    approval_policy_code: str | None
    approval_policy_version: int | None
    approval_decision_ref: str | None
    approval_decision_status: str
    approved_at: datetime | None
    issued_at: datetime
    expires_at: datetime
    control_version: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = AUTHORIZATION_PURPOSE

    def __post_init__(self) -> None:
        for field in (
            "authorization_id",
            "rollout_ref",
            "plan_id",
            "target_id",
            "target_ref",
            "product_code",
            "environment",
            "operation",
            "release_ref",
            "approval_decision_status",
            "control_version",
            "key_id",
            "algorithm",
        ):
            _bounded_text(getattr(self, field), field=field)
        if self.purpose != AUTHORIZATION_PURPOSE:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.PURPOSE_MISMATCH,
                "the statement does not carry the deployment authorization purpose",
            )
        PlanDigestV1.parse(self.plan_digest)
        DescriptorDigestV1.parse(self.descriptor_digest)
        ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        if (
            not isinstance(self.execution_sequence, int)
            or isinstance(self.execution_sequence, bool)
            or self.execution_sequence < 1
        ):
            raise _refused(
                AuthorizationEnvelopeRefusalCode.MALFORMED,
                "execution_sequence must be a positive integer",
            )
        canonical = authorized_image_set(
            self.authorized_images, where="authorization statement image set"
        )
        if canonical is None or canonical != self.authorized_images:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.MALFORMED,
                "authorized_images must be the canonical ordered image set",
            )
        issued = _aware_utc(self.issued_at, field="issued_at")
        expires = _aware_utc(self.expires_at, field="expires_at")
        if expires <= issued:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.MALFORMED,
                "expires_at must be later than issued_at",
            )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": AUTHORIZATION_SCHEMA,
            "version": AUTHORIZATION_VERSION,
            "purpose": self.purpose,
            "authorization_id": self.authorization_id,
            "execution_sequence": self.execution_sequence,
            "rollout_ref": self.rollout_ref,
            "plan_id": self.plan_id,
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
            "approval_policy_code": self.approval_policy_code,
            "approval_policy_version": self.approval_policy_version,
            "approval_decision_ref": self.approval_decision_ref,
            "approval_decision_status": self.approval_decision_status,
            "approved_at": _timestamp(self.approved_at),
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
            "control_version": self.control_version,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_fingerprint": self.public_key_fingerprint,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class AuthorizationEnvelopeV1:
    statement: AuthorizationStatementV1
    signature: str

    def __post_init__(self) -> None:
        _bounded_text(self.signature, field="signature", maximum=16_384)

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())

    @classmethod
    def parse(cls, value: object) -> AuthorizationEnvelopeV1:
        if isinstance(value, cls):
            return value
        mapping = _exact_mapping(value, {"statement", "signature"}, where="envelope")
        statement = _parse_statement(mapping["statement"])
        signature = mapping["signature"]
        if not isinstance(signature, str) or not signature:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.UNSIGNED,
                "the portable authorization carries no signature",
            )
        return cls(statement=statement, signature=signature)


@dataclass(frozen=True, slots=True)
class AuthorizationEnvelopeV2:
    statement: AuthorizationStatementV2
    signature: str

    def __post_init__(self) -> None:
        _bounded_text(self.signature, field="signature", maximum=16_384)

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())

    @classmethod
    def parse(cls, value: object) -> AuthorizationEnvelopeV2:
        if isinstance(value, cls):
            return value
        mapping = _exact_mapping(value, {"statement", "signature"}, where="envelope")
        statement = _parse_statement_v2(mapping["statement"])
        signature = mapping["signature"]
        if not isinstance(signature, str) or not signature:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.UNSIGNED,
                "the portable authorization carries no signature",
            )
        return cls(statement=statement, signature=signature)


def issue_authorization_envelope(
    statement_fields: Mapping[str, Any], *, signer: AuthorizationSigner
) -> AuthorizationEnvelopeV2:
    """Bind the signer's immutable identity into bytes before signing them."""
    identity = signer.identity
    fields = dict(statement_fields)
    for forbidden in (
        "schema",
        "version",
        "control_version",
        "key_id",
        "algorithm",
        "public_key_fingerprint",
        "purpose",
    ):
        if forbidden in fields:
            raise _refused(
                AuthorizationEnvelopeRefusalCode.MALFORMED,
                f"{forbidden} is derived inside Control and cannot be supplied",
            )
    for field in ("approved_at", "issued_at", "expires_at"):
        value = fields.get(field)
        if isinstance(value, datetime):
            fields[field] = _timestamp(value)
    statement = _parse_statement_v2(
        {
            "schema": AUTHORIZATION_SCHEMA,
            "version": AUTHORIZATION_VERSION,
            **fields,
            "control_version": _installed_control_version(),
            "key_id": identity.key_id,
            "algorithm": identity.algorithm,
            "public_key_fingerprint": identity.public_key_fingerprint,
            "purpose": identity.purpose,
        }
    )
    _require_standing_approval(statement)
    signed = signer.sign(statement.canonical_bytes)
    if (
        signed.key_id != statement.key_id
        or signed.algorithm != statement.algorithm
        or signed.public_key_fingerprint != statement.public_key_fingerprint
        or signed.purpose != statement.purpose
    ):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.SIGNER_IDENTITY_MISMATCH,
            "the signer returned a key identity or algorithm different from the "
            "identity already bound into the signed bytes",
        )
    if not signed.signature:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.UNSIGNED,
            "the signer returned an empty signature",
        )
    return AuthorizationEnvelopeV2(statement=statement, signature=signed.signature)


def verify_authorization_envelope(
    value: object,
    *,
    verifier: AuthorizationVerifier,
    at: datetime | None = None,
) -> AuthorizationEnvelopeV2:
    """Verify portable bytes without a live Control database lookup."""
    envelope = AuthorizationEnvelopeV2.parse(value)
    now = _aware_utc(at or datetime.now(UTC), field="at")
    issued = _aware_utc(envelope.statement.issued_at, field="issued_at")
    expires = _aware_utc(envelope.statement.expires_at, field="expires_at")
    if now < issued:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.NOT_YET_VALID,
            "the authorization was presented before its issued_at instant",
        )
    if now >= expires:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.EXPIRED,
            "the authorization has reached its expires_at instant",
        )
    if not verifier.verify(
        key_id=envelope.statement.key_id,
        algorithm=envelope.statement.algorithm,
        purpose=envelope.statement.purpose,
        public_key_fingerprint=envelope.statement.public_key_fingerprint,
        canonical_bytes=envelope.statement.canonical_bytes,
        signature=envelope.signature,
    ):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.SIGNATURE_INVALID,
            "the injected verifier refused the signature over the canonical statement",
        )
    _require_standing_approval(envelope.statement)
    return envelope


def _require_standing_approval(
    statement: AuthorizationStatementV1 | AuthorizationStatementV2,
) -> None:
    """A portable authorization can preserve a past decision, never revive it."""
    if statement.approval_decision_status not in {"granted", "approval_exempt"}:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.APPROVAL_NOT_STANDING,
            "the portable authorization does not carry a standing approval; "
            "a signed historical decision is not permission to dispatch",
        )


_STATEMENT_KEYS = {
    "schema",
    "version",
    "authorization_id",
    "rollout_ref",
    "plan_id",
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
    "approval_policy_code",
    "approval_policy_version",
    "approval_decision_ref",
    "approval_decision_status",
    "approved_at",
    "issued_at",
    "expires_at",
    "key_id",
    "algorithm",
}

_STATEMENT_KEYS_V2 = _STATEMENT_KEYS | {
    "purpose",
    "control_version",
    "public_key_fingerprint",
    "execution_sequence",
}


def _parse_statement(value: object) -> AuthorizationStatementV1:
    row = _exact_mapping(value, _STATEMENT_KEYS, where="authorization statement")
    if not isinstance(row["schema"], str) or row["schema"] != AUTHORIZATION_SCHEMA:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported authorization schema {row['schema']!r}",
        )
    if (
        not isinstance(row["version"], int)
        or isinstance(row["version"], bool)
        or row["version"] != 1
    ):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported authorization version {row['version']!r}",
        )
    images = authorized_image_set(
        _sequence(row["authorized_images"], field="authorized_images"),
        where="authorization statement image set",
    )
    assert images is not None
    return AuthorizationStatementV1(
        authorization_id=_text(row, "authorization_id"),
        rollout_ref=_text(row, "rollout_ref"),
        plan_id=_text(row, "plan_id"),
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
        approval_policy_code=_optional_text(row, "approval_policy_code"),
        approval_policy_version=_optional_int(row, "approval_policy_version"),
        approval_decision_ref=_optional_text(row, "approval_decision_ref"),
        approval_decision_status=_text(row, "approval_decision_status"),
        approved_at=_optional_datetime(row, "approved_at"),
        issued_at=_datetime(row, "issued_at"),
        expires_at=_datetime(row, "expires_at"),
        key_id=_text(row, "key_id"),
        algorithm=_text(row, "algorithm"),
    )


def _parse_statement_v2(value: object) -> AuthorizationStatementV2:
    row = _exact_mapping(value, _STATEMENT_KEYS_V2, where="authorization statement")
    if not isinstance(row["schema"], str) or row["schema"] != AUTHORIZATION_SCHEMA:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported authorization schema {row['schema']!r}",
        )
    if (
        not isinstance(row["version"], int)
        or isinstance(row["version"], bool)
        or row["version"] != AUTHORIZATION_VERSION
    ):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported authorization version {row['version']!r}",
        )
    images = authorized_image_set(
        _sequence(row["authorized_images"], field="authorized_images"),
        where="authorization statement image set",
    )
    assert images is not None
    return AuthorizationStatementV2(
        authorization_id=_text(row, "authorization_id"),
        execution_sequence=_required_positive_int(row, "execution_sequence"),
        rollout_ref=_text(row, "rollout_ref"),
        plan_id=_text(row, "plan_id"),
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
        approval_policy_code=_optional_text(row, "approval_policy_code"),
        approval_policy_version=_optional_int(row, "approval_policy_version"),
        approval_decision_ref=_optional_text(row, "approval_decision_ref"),
        approval_decision_status=_text(row, "approval_decision_status"),
        approved_at=_optional_datetime(row, "approved_at"),
        issued_at=_datetime(row, "issued_at"),
        expires_at=_datetime(row, "expires_at"),
        control_version=_text(row, "control_version"),
        key_id=_text(row, "key_id"),
        algorithm=_text(row, "algorithm"),
        public_key_fingerprint=_text(row, "public_key_fingerprint"),
        purpose=_text(row, "purpose"),
    )


def _installed_control_version() -> str:
    """One authority: the metadata of the installed distribution issuing bytes."""
    try:
        value = _distribution_version(_DISTRIBUTION)
    except PackageNotFoundError as exc:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.CONTROL_VERSION_UNAVAILABLE,
            "the issuing dotmac-deployment-control distribution is not installed; "
            "Control will not guess its version from a source checkout",
        ) from exc
    return _bounded_text(value, field="control_version")


def _exact_mapping(value: object, keys: set[str], *, where: str) -> Mapping[str, Any]:
    if value is None:
        raise _refused(AuthorizationEnvelopeRefusalCode.ABSENT, f"{where} is absent")
    if not isinstance(value, Mapping):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{where} must be a mapping, not {type(value).__name__}",
        )
    if any(not isinstance(key, str) for key in value):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{where} keys must all be strings",
        )
    actual = set(value)
    if actual != keys:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{where} keys differ: missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}",
        )
    return value


def _text(row: Mapping[str, Any], field: str) -> str:
    value = row[field]
    if not isinstance(value, str):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a string",
        )
    return value


def _optional_text(row: Mapping[str, Any], field: str) -> str | None:
    value = row[field]
    if value is None:
        return None
    return _text(row, field)


def _optional_int(row: Mapping[str, Any], field: str) -> int | None:
    value = row[field]
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} must be an integer or null",
        )
    return value


def _required_positive_int(row: Mapping[str, Any], field: str) -> int:
    value = row[field]
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a positive integer",
        )
    return value


def _sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a sequence",
        )
    return value


def _datetime(row: Mapping[str, Any], field: str) -> datetime:
    value = _text(row, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} is not an ISO-8601 timestamp",
        ) from exc
    return _aware_utc(parsed, field=field)


def _optional_datetime(row: Mapping[str, Any], field: str) -> datetime | None:
    if row[field] is None:
        return None
    return _datetime(row, field)


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware_utc(value, field="timestamp").isoformat().replace("+00:00", "Z")


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} must carry a timezone",
        )
    return value.astimezone(UTC)


def _bounded_text(value: object, *, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} must be a non-empty, whitespace-exact string",
        )
    if len(value) > maximum:
        raise _refused(
            AuthorizationEnvelopeRefusalCode.MALFORMED,
            f"{field} exceeds {maximum} characters",
        )
    return value


def _refused(
    code: AuthorizationEnvelopeRefusalCode, detail: str
) -> AuthorizationEnvelopeRefusedError:
    return AuthorizationEnvelopeRefusedError(code, detail)


__all__ = [
    "AUTHORIZATION_PURPOSE",
    "AUTHORIZATION_SCHEMA",
    "AUTHORIZATION_VERSION",
    "AuthorizationEnvelopeRefusalCode",
    "AuthorizationEnvelopeRefusedError",
    "AuthorizationEnvelopeV1",
    "AuthorizationEnvelopeV2",
    "AuthorizationSignature",
    "AuthorizationSigner",
    "AuthorizationSignerIdentity",
    "AuthorizationStatementV1",
    "AuthorizationStatementV2",
    "AuthorizationVerifier",
    "issue_authorization_envelope",
    "verify_authorization_envelope",
]
