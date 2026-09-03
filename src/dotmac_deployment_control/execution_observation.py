"""Provider-neutral, purpose-separated target execution observations.

Control owns the statement and its canonical bytes.  The target owns the
private observation key, while Control receives an injected verifier for the
corresponding public key.  This seam is deliberately not structurally
compatible with :class:`AuthorizationSigner` or :class:`AuthorizationVerifier`:
the two trust directions must never share a signing identity by accident.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from dotmac_deployment_control.digests import (
    DescriptorDigestV1,
    ExecutionPlanDigestV1,
    PlanDigestV1,
    SpecDigestV1,
    canonical_json,
)
from dotmac_deployment_control.images import (
    AuthorizedImage,
    authorized_image_set,
    image_set_payload,
)
from dotmac_deployment_control.ports import DeploymentControlError

EXECUTION_OBSERVATION_SCHEMA = "dotmac.target-execution-observation"
EXECUTION_OBSERVATION_VERSION = 1
EXECUTION_OBSERVATION_PURPOSE = "target_execution_observation"


class ExecutionObservationRefusalCode(StrEnum):
    ABSENT = "execution_observation_absent"
    MALFORMED = "execution_observation_malformed"
    UNSUPPORTED_VERSION = "execution_observation_unsupported_version"
    UNSIGNED = "execution_observation_unsigned"
    SIGNER_IDENTITY_MISMATCH = "execution_observation_signer_identity_mismatch"
    SIGNATURE_INVALID = "execution_observation_signature_invalid"
    PURPOSE_MISMATCH = "execution_observation_purpose_mismatch"


class ExecutionObservationRefusedError(DeploymentControlError):
    """A typed refusal that cannot be mistaken for a verified observation."""

    def __init__(self, code: ExecutionObservationRefusalCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


class ExecutionObservationOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ExecutionObservationSignerIdentity:
    key_id: str
    algorithm: str
    purpose: str = EXECUTION_OBSERVATION_PURPOSE

    def __post_init__(self) -> None:
        _bounded_text(self.key_id, field="key_id")
        _bounded_text(self.algorithm, field="algorithm")
        if self.purpose != EXECUTION_OBSERVATION_PURPOSE:
            raise _refused(
                ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
                "an execution-observation signer must declare the target "
                "execution observation purpose",
            )


@dataclass(frozen=True, slots=True)
class ExecutionObservationSignature:
    key_id: str
    algorithm: str
    purpose: str
    signature: str


@runtime_checkable
class ExecutionObservationSigner(Protocol):
    """Target-side signer; intentionally unlike the authorization signer."""

    @property
    def execution_observation_identity(
        self,
    ) -> ExecutionObservationSignerIdentity: ...

    def sign_execution_observation(
        self, canonical_bytes: bytes
    ) -> ExecutionObservationSignature: ...


@runtime_checkable
class ExecutionObservationVerifier(Protocol):
    """Control-side public verifier for the target observation purpose only."""

    def verify_execution_observation(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class RuntimeIdentityV1:
    """The exact runtime instance that produced an execution result."""

    kind: str
    identifier: str

    def __post_init__(self) -> None:
        _bounded_text(self.kind, field="runtime_identity.kind")
        _bounded_text(self.identifier, field="runtime_identity.identifier")

    def as_mapping(self) -> dict[str, str]:
        return {"kind": self.kind, "identifier": self.identifier}

    @classmethod
    def parse(cls, value: object) -> RuntimeIdentityV1:
        if isinstance(value, cls):
            return value
        row = _exact_mapping(value, {"kind", "identifier"}, where="runtime_identity")
        return cls(kind=_text(row, "kind"), identifier=_text(row, "identifier"))


@dataclass(frozen=True, slots=True)
class ExecutionObservationStatementV1:
    report_id: str
    authorization_id: str
    rollout_ref: str
    target_id: str
    target_ref: str
    product_code: str
    environment: str
    operation: str
    release_ref: str
    observed_release_ref: str
    authorized_images: tuple[AuthorizedImage, ...]
    observed_images: tuple[AuthorizedImage, ...]
    plan_digest: str
    descriptor_digest: str
    execution_plan_digest: str
    observed_spec_digest: str
    observed_revision: str
    runtime_identity: RuntimeIdentityV1
    outcome: ExecutionObservationOutcome
    observed_at: datetime
    key_id: str
    algorithm: str
    purpose: str = EXECUTION_OBSERVATION_PURPOSE

    def __post_init__(self) -> None:
        for field in (
            "report_id",
            "authorization_id",
            "rollout_ref",
            "target_id",
            "target_ref",
            "product_code",
            "environment",
            "operation",
            "release_ref",
            "observed_release_ref",
            "observed_revision",
            "key_id",
            "algorithm",
        ):
            _bounded_text(getattr(self, field), field=field)
        if self.purpose != EXECUTION_OBSERVATION_PURPOSE:
            raise _refused(
                ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
                "the statement does not carry the target execution observation purpose",
            )
        PlanDigestV1.parse(self.plan_digest)
        DescriptorDigestV1.parse(self.descriptor_digest)
        ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        SpecDigestV1.parse(self.observed_spec_digest)
        for name, images in (
            ("authorized_images", self.authorized_images),
            ("observed_images", self.observed_images),
        ):
            canonical = authorized_image_set(images, where=f"observation {name}")
            if canonical is None or canonical != images:
                raise _refused(
                    ExecutionObservationRefusalCode.MALFORMED,
                    f"{name} must be the canonical ordered image set",
                )
        _aware_utc(self.observed_at, field="observed_at")

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": EXECUTION_OBSERVATION_SCHEMA,
            "version": EXECUTION_OBSERVATION_VERSION,
            "purpose": self.purpose,
            "report_id": self.report_id,
            "authorization_id": self.authorization_id,
            "rollout_ref": self.rollout_ref,
            "target_id": self.target_id,
            "target_ref": self.target_ref,
            "product_code": self.product_code,
            "environment": self.environment,
            "operation": self.operation,
            "release_ref": self.release_ref,
            "observed_release_ref": self.observed_release_ref,
            "authorized_images": image_set_payload(self.authorized_images),
            "observed_images": image_set_payload(self.observed_images),
            "plan_digest": self.plan_digest,
            "descriptor_digest": self.descriptor_digest,
            "execution_plan_digest": self.execution_plan_digest,
            "observed_spec_digest": self.observed_spec_digest,
            "observed_revision": self.observed_revision,
            "runtime_identity": self.runtime_identity.as_mapping(),
            "outcome": self.outcome.value,
            "observed_at": _timestamp(self.observed_at),
            "key_id": self.key_id,
            "algorithm": self.algorithm,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class ExecutionObservationEnvelopeV1:
    statement: ExecutionObservationStatementV1
    signature: str

    def __post_init__(self) -> None:
        _bounded_text(self.signature, field="signature", maximum=16_384)

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())

    @classmethod
    def parse(cls, value: object) -> ExecutionObservationEnvelopeV1:
        if isinstance(value, cls):
            return value
        row = _exact_mapping(value, {"statement", "signature"}, where="envelope")
        signature = row["signature"]
        if not isinstance(signature, str) or not signature:
            raise _refused(
                ExecutionObservationRefusalCode.UNSIGNED,
                "the execution observation carries no signature",
            )
        try:
            statement = _parse_statement(row["statement"])
        except ExecutionObservationRefusedError:
            raise
        except DeploymentControlError as exc:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                f"the signed statement contains an unreadable typed value: {exc}",
            ) from exc
        return cls(statement=statement, signature=signature)


def issue_execution_observation_envelope(
    statement_fields: Mapping[str, Any], *, signer: ExecutionObservationSigner
) -> ExecutionObservationEnvelopeV1:
    """Bind the target's purpose-typed identity before signing."""
    if not isinstance(signer, ExecutionObservationSigner):
        raise _refused(
            ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
            "the injected signer does not implement the target execution "
            "observation signing purpose",
        )
    identity = signer.execution_observation_identity
    if not isinstance(identity, ExecutionObservationSignerIdentity):
        raise _refused(
            ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
            "the signer did not expose an execution-observation identity",
        )
    fields = dict(statement_fields)
    for forbidden in ("key_id", "algorithm", "purpose"):
        if forbidden in fields:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                f"{forbidden} is derived from the injected signer and cannot "
                "be supplied",
            )
    if isinstance(fields.get("observed_at"), datetime):
        fields["observed_at"] = _timestamp(fields["observed_at"])
    try:
        statement = _parse_statement(
            {
                "schema": EXECUTION_OBSERVATION_SCHEMA,
                "version": EXECUTION_OBSERVATION_VERSION,
                **fields,
                "purpose": identity.purpose,
                "key_id": identity.key_id,
                "algorithm": identity.algorithm,
            }
        )
    except ExecutionObservationRefusedError:
        raise
    except DeploymentControlError as exc:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"the statement contains an unreadable typed value: {exc}",
        ) from exc
    signed = signer.sign_execution_observation(statement.canonical_bytes)
    if (
        signed.key_id != statement.key_id
        or signed.algorithm != statement.algorithm
        or signed.purpose != statement.purpose
    ):
        raise _refused(
            ExecutionObservationRefusalCode.SIGNER_IDENTITY_MISMATCH,
            "the signer returned an identity, algorithm or purpose different from "
            "the values already bound into the signed bytes",
        )
    if not signed.signature:
        raise _refused(
            ExecutionObservationRefusalCode.UNSIGNED,
            "the execution observation signer returned an empty signature",
        )
    return ExecutionObservationEnvelopeV1(statement, signed.signature)


def verify_execution_observation_envelope(
    value: object, *, verifier: ExecutionObservationVerifier
) -> ExecutionObservationEnvelopeV1:
    if not isinstance(verifier, ExecutionObservationVerifier):
        raise _refused(
            ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier does not implement the target execution "
            "observation verification purpose",
        )
    envelope = ExecutionObservationEnvelopeV1.parse(value)
    statement = envelope.statement
    if not verifier.verify_execution_observation(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        canonical_bytes=statement.canonical_bytes,
        signature=envelope.signature,
    ):
        raise _refused(
            ExecutionObservationRefusalCode.SIGNATURE_INVALID,
            "the injected target-observation verifier refused the signature",
        )
    return envelope


_STATEMENT_KEYS = {
    "schema",
    "version",
    "purpose",
    "report_id",
    "authorization_id",
    "rollout_ref",
    "target_id",
    "target_ref",
    "product_code",
    "environment",
    "operation",
    "release_ref",
    "observed_release_ref",
    "authorized_images",
    "observed_images",
    "plan_digest",
    "descriptor_digest",
    "execution_plan_digest",
    "observed_spec_digest",
    "observed_revision",
    "runtime_identity",
    "outcome",
    "observed_at",
    "key_id",
    "algorithm",
}


def _parse_statement(value: object) -> ExecutionObservationStatementV1:
    row = _exact_mapping(value, _STATEMENT_KEYS, where="execution observation")
    if row["schema"] != EXECUTION_OBSERVATION_SCHEMA:
        raise _refused(
            ExecutionObservationRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported execution observation schema {row['schema']!r}",
        )
    if row["version"] != EXECUTION_OBSERVATION_VERSION:
        raise _refused(
            ExecutionObservationRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported execution observation version {row['version']!r}",
        )
    authorized = authorized_image_set(
        _sequence(row["authorized_images"], field="authorized_images"),
        where="observation authorized_images",
    )
    observed = authorized_image_set(
        _sequence(row["observed_images"], field="observed_images"),
        where="observation observed_images",
    )
    assert authorized is not None and observed is not None
    try:
        outcome = ExecutionObservationOutcome(_text(row, "outcome"))
    except ValueError as exc:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"unsupported execution outcome {row['outcome']!r}",
        ) from exc
    return ExecutionObservationStatementV1(
        report_id=_text(row, "report_id"),
        authorization_id=_text(row, "authorization_id"),
        rollout_ref=_text(row, "rollout_ref"),
        target_id=_text(row, "target_id"),
        target_ref=_text(row, "target_ref"),
        product_code=_text(row, "product_code"),
        environment=_text(row, "environment"),
        operation=_text(row, "operation"),
        release_ref=_text(row, "release_ref"),
        observed_release_ref=_text(row, "observed_release_ref"),
        authorized_images=authorized,
        observed_images=observed,
        plan_digest=_text(row, "plan_digest"),
        descriptor_digest=_text(row, "descriptor_digest"),
        execution_plan_digest=_text(row, "execution_plan_digest"),
        observed_spec_digest=_text(row, "observed_spec_digest"),
        observed_revision=_text(row, "observed_revision"),
        runtime_identity=RuntimeIdentityV1.parse(row["runtime_identity"]),
        outcome=outcome,
        observed_at=_datetime(row, "observed_at"),
        key_id=_text(row, "key_id"),
        algorithm=_text(row, "algorithm"),
        purpose=_text(row, "purpose"),
    )


def _exact_mapping(value: object, keys: set[str], *, where: str) -> Mapping[str, Any]:
    if value is None:
        raise _refused(ExecutionObservationRefusalCode.ABSENT, f"{where} is absent")
    if not isinstance(value, Mapping):
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{where} must be a mapping, not {type(value).__name__}",
        )
    actual = set(value)
    if any(not isinstance(key, str) for key in actual) or actual != keys:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{where} keys differ: missing={sorted(keys - actual)}, "
            f"unknown={sorted(str(key) for key in actual - keys)}",
        )
    return value


def _text(row: Mapping[str, Any], field: str) -> str:
    value = row[field]
    if not isinstance(value, str):
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{field} must be a string",
        )
    return value


def _sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{field} must be a sequence",
        )
    return value


def _datetime(row: Mapping[str, Any], field: str) -> datetime:
    value = _text(row, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{field} is not an ISO-8601 timestamp",
        ) from exc
    return _aware_utc(parsed, field=field)


def _timestamp(value: datetime) -> str:
    return _aware_utc(value, field="timestamp").isoformat().replace("+00:00", "Z")


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{field} must carry a timezone",
        )
    return value.astimezone(UTC)


def _bounded_text(value: object, *, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{field} must be a non-empty, whitespace-exact string",
        )
    if len(value) > maximum:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{field} exceeds {maximum} characters",
        )
    return value


def _refused(
    code: ExecutionObservationRefusalCode, detail: str
) -> ExecutionObservationRefusedError:
    return ExecutionObservationRefusedError(code, detail)


__all__ = [
    "EXECUTION_OBSERVATION_PURPOSE",
    "EXECUTION_OBSERVATION_SCHEMA",
    "EXECUTION_OBSERVATION_VERSION",
    "ExecutionObservationEnvelopeV1",
    "ExecutionObservationOutcome",
    "ExecutionObservationRefusalCode",
    "ExecutionObservationRefusedError",
    "ExecutionObservationSignature",
    "ExecutionObservationSigner",
    "ExecutionObservationSignerIdentity",
    "ExecutionObservationStatementV1",
    "ExecutionObservationVerifier",
    "RuntimeIdentityV1",
    "issue_execution_observation_envelope",
    "verify_execution_observation_envelope",
]
