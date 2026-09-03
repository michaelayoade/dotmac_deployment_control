"""Provider-neutral, purpose-separated target execution observations.

Control owns the statement and its canonical bytes.  The target owns the
private observation key, while Control receives an injected verifier for the
corresponding public key.  This seam is deliberately not structurally
compatible with :class:`AuthorizationSigner` or :class:`AuthorizationVerifier`:
the two trust directions must never share a signing identity by accident.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from dotmac_deployment_control.digests import (
    AuthorizationEnvelopeDigestV1,
    DescriptorDigestV1,
    ExecutionPlanDigestV1,
    ObservedExecutionStateDigestV1,
    PlanDigestV1,
    PublicKeyFingerprintV1,
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
MAX_EXECUTION_OBSERVATION_ENVELOPE_BYTES = 262_144


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
    public_key_fingerprint: str
    purpose: str = EXECUTION_OBSERVATION_PURPOSE

    def __post_init__(self) -> None:
        _bounded_text(self.key_id, field="key_id")
        _bounded_text(self.algorithm, field="algorithm")
        PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
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
    public_key_fingerprint: str
    signature: str


@dataclass(frozen=True, slots=True)
class ExecutionObservationVerificationKey:
    """The exact enrolled public verification identity Control selected."""

    key_id: str
    algorithm: str
    public_key_b64: str
    public_key_fingerprint: str
    purpose: str = EXECUTION_OBSERVATION_PURPOSE

    def __post_init__(self) -> None:
        _bounded_text(self.key_id, field="verification_key.key_id")
        _bounded_text(self.algorithm, field="verification_key.algorithm")
        if self.purpose != EXECUTION_OBSERVATION_PURPOSE:
            raise _refused(
                ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
                "an enrolled execution-observation key must be purpose-bound",
            )
        derived = PublicKeyFingerprintV1.from_public_key_b64(self.public_key_b64)
        recorded = PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        if derived != recorded:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "the enrolled public-key fingerprint does not match the canonical key",
            )


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
        public_key_b64: str,
        public_key_fingerprint: str,
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
    authorization_plan_id: str
    authorization_control_version: str
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
    public_key_fingerprint: str
    purpose: str = EXECUTION_OBSERVATION_PURPOSE

    def __post_init__(self) -> None:
        for field in (
            "report_id",
            "authorization_id",
            "authorization_plan_id",
            "authorization_control_version",
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
        AuthorizationEnvelopeDigestV1.parse(self.authorization_envelope_digest)
        DescriptorDigestV1.parse(self.descriptor_digest)
        ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        SpecDigestV1.parse(self.observed_spec_digest)
        PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        for field in ("execution_sequence", "attempt_no"):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise _refused(
                    ExecutionObservationRefusalCode.MALFORMED,
                    f"{field} must be a positive integer",
                )
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
            "authorization_plan_id": self.authorization_plan_id,
            "authorization_control_version": self.authorization_control_version,
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
            "public_key_fingerprint": self.public_key_fingerprint,
        }

    def substantive_state_mapping(self) -> dict[str, Any]:
        """State at the execution coordinate, excluding retry/transport facts."""
        return {
            "authorization_id": self.authorization_id,
            "authorization_plan_id": self.authorization_plan_id,
            "authorization_control_version": self.authorization_control_version,
            "authorization_envelope_digest": self.authorization_envelope_digest,
            "rollout_ref": self.rollout_ref,
            "execution_sequence": self.execution_sequence,
            "attempt_no": self.attempt_no,
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
        }

    @property
    def substantive_state_digest(self) -> ObservedExecutionStateDigestV1:
        return ObservedExecutionStateDigestV1.over_json(
            self.substantive_state_mapping()
        )

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

    @classmethod
    def parse_bytes(cls, value: bytes) -> ExecutionObservationEnvelopeV1:
        """Parse the exact bounded wire bytes, refusing ambiguous JSON.

        The caller supplies one byte string. Control stores and hashes those
        bytes and parses this same value, so a malformed or bad-signature
        attempt cannot carry evidence from a different alleged request.
        Duplicate JSON keys are refused because a verifier and an operator may
        otherwise select different values from one wire document.
        """
        if not isinstance(value, bytes):
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "the execution observation wire value must be bytes",
            )
        if len(value) > MAX_EXECUTION_OBSERVATION_ENVELOPE_BYTES:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "the execution observation exceeds the bounded wire size of "
                f"{MAX_EXECUTION_OBSERVATION_ENVELOPE_BYTES} bytes",
            )
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "the execution observation is not UTF-8 JSON",
            ) from exc
        try:
            decoded = json.loads(
                text,
                object_pairs_hook=_mapping_without_duplicate_keys,
                parse_constant=_refuse_non_json_number,
            )
        except json.JSONDecodeError as exc:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "the execution observation is not valid JSON",
            ) from exc
        return cls.parse(decoded)


def _mapping_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """`object_pairs_hook`: one key, one value, or the document is refused.

    Python's default resolution keeps the LAST duplicate silently, and other
    readers keep the first — so one wire document could show a verifier one
    value and an operator another. Refusing is the only reading under which
    "the signed bytes said X" has a single answer.

    Raised as the module's own refusal rather than a JSONDecodeError: this is
    not a syntax fault, it is a document whose meaning is ambiguous, and the
    caller records it as MALFORMED either way.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                f"the execution observation repeats JSON key {key!r}; a "
                "document with two values for one key lets two readers read "
                "two different reports out of one signature",
            )
        seen[key] = value
    return seen


def _refuse_non_json_number(constant: str) -> Any:
    """`parse_constant`: NaN and the infinities are not JSON and not evidence.

    They cannot round-trip through the canonical encoder, so bytes carrying one
    could never equal their own re-rendering — accepting them would create a
    document that verifies once and can never be reproduced.
    """
    raise _refused(
        ExecutionObservationRefusalCode.MALFORMED,
        f"the execution observation carries {constant!r}, which is not a JSON "
        "value and cannot round-trip through the canonical encoding",
    )


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
    for forbidden in (
        "schema",
        "version",
        "key_id",
        "algorithm",
        "public_key_fingerprint",
        "purpose",
    ):
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
                "public_key_fingerprint": identity.public_key_fingerprint,
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
        or signed.public_key_fingerprint != statement.public_key_fingerprint
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
    value: object,
    *,
    verifier: ExecutionObservationVerifier,
    verification_key: ExecutionObservationVerificationKey,
) -> ExecutionObservationEnvelopeV1:
    if not isinstance(verifier, ExecutionObservationVerifier):
        raise _refused(
            ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier does not implement the target execution "
            "observation verification purpose",
        )
    envelope = ExecutionObservationEnvelopeV1.parse(value)
    statement = envelope.statement
    if (
        statement.key_id != verification_key.key_id
        or statement.algorithm != verification_key.algorithm
        or statement.purpose != verification_key.purpose
        or statement.public_key_fingerprint != verification_key.public_key_fingerprint
    ):
        raise _refused(
            ExecutionObservationRefusalCode.SIGNATURE_INVALID,
            "the signed key identity does not equal the enrolled verification identity",
        )
    if not verifier.verify_execution_observation(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_b64=verification_key.public_key_b64,
        public_key_fingerprint=verification_key.public_key_fingerprint,
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
    "authorization_plan_id",
    "authorization_control_version",
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
    "public_key_fingerprint",
}


def _parse_statement(value: object) -> ExecutionObservationStatementV1:
    row = _exact_mapping(value, _STATEMENT_KEYS, where="execution observation")
    if (
        not isinstance(row["schema"], str)
        or row["schema"] != EXECUTION_OBSERVATION_SCHEMA
    ):
        raise _refused(
            ExecutionObservationRefusalCode.UNSUPPORTED_VERSION,
            f"unsupported execution observation schema {row['schema']!r}",
        )
    if (
        not isinstance(row["version"], int)
        or isinstance(row["version"], bool)
        or row["version"] != EXECUTION_OBSERVATION_VERSION
    ):
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
        authorization_plan_id=_text(row, "authorization_plan_id"),
        authorization_control_version=_text(row, "authorization_control_version"),
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
        public_key_fingerprint=_text(row, "public_key_fingerprint"),
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


def _positive_int(row: Mapping[str, Any], field: str) -> int:
    value = row[field]
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"{field} must be a positive integer",
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
    "ExecutionObservationVerificationKey",
    "ExecutionObservationVerifier",
    "RuntimeIdentityV1",
    "issue_execution_observation_envelope",
    "verify_execution_observation_envelope",
]
