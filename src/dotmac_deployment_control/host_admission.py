"""Versioned, purpose-separated host-admission presentation contract.

This is a Control library contract.  The composing control plane supplies the
purpose-specific verifier and clock; callers cannot select either.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from dotmac_deployment_control.digests import (
    PublicKeyFingerprintV1,
    canonical_json,
    compute_host_admission_consumption_fingerprint,
)
from dotmac_deployment_control.ports import DeploymentControlError

HOST_ADMISSION_PRESENTATION_SCHEMA = "dotmac.control.host-admission-presentation"
HOST_ADMISSION_PRESENTATION_VERSION = 1
HOST_ADMISSION_PRESENTATION_PURPOSE = "dotmac.control.host-admission-presentation.v1"
HOST_ADMISSION_PRESENTATION_AUDIENCE = "dotmac.deployment-control"
CANDIDATE_ATTESTATION_PURPOSE = "dotmac.foundation.candidate-artifact.v2"
INSTALLED_OBSERVATION_PURPOSE = "dotmac.foundation.installed-host.v2"
_MAX_LIFETIME = timedelta(minutes=5)


class HostAdmissionPresentationRefusalCode(StrEnum):
    MALFORMED = "host_admission_presentation_malformed"
    UNSUPPORTED_VERSION = "host_admission_presentation_unsupported_version"
    PURPOSE_MISMATCH = "host_admission_presentation_purpose_mismatch"
    AUDIENCE_MISMATCH = "host_admission_presentation_audience_mismatch"
    SIGNATURE_ENCODING = "host_admission_presentation_signature_encoding"
    SIGNATURE_INVALID = "host_admission_presentation_signature_invalid"
    NOT_YET_VALID = "host_admission_presentation_not_yet_valid"
    EXPIRED = "host_admission_presentation_expired"
    LIFETIME_INVALID = "host_admission_presentation_lifetime_invalid"


class HostAdmissionPresentationRefusedError(DeploymentControlError):
    def __init__(self, code: HostAdmissionPresentationRefusalCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


@dataclass(frozen=True, slots=True)
class HostAdmissionPresentationStatementV1:
    presentation_id: str
    key_id: str
    dispatch_id: str
    candidate_attestation_envelope_digest: str
    installed_attestation_envelope_digest: str
    issued_at: datetime
    expires_at: datetime
    purpose: str = HOST_ADMISSION_PRESENTATION_PURPOSE
    audience: str = HOST_ADMISSION_PRESENTATION_AUDIENCE

    def __post_init__(self) -> None:
        for value in (
            self.presentation_id,
            self.key_id,
            self.dispatch_id,
            self.candidate_attestation_envelope_digest,
            self.installed_attestation_envelope_digest,
        ):
            if not isinstance(value, str) or not value or value != value.strip():
                raise _refuse(
                    HostAdmissionPresentationRefusalCode.MALFORMED,
                    "required text is malformed",
                )
        for digest in (
            self.candidate_attestation_envelope_digest,
            self.installed_attestation_envelope_digest,
        ):
            if not _is_digest(digest):
                raise _refuse(
                    HostAdmissionPresentationRefusalCode.MALFORMED,
                    "attestation digest is not canonical sha256",
                )
        if self.purpose != HOST_ADMISSION_PRESENTATION_PURPOSE:
            raise _refuse(
                HostAdmissionPresentationRefusalCode.PURPOSE_MISMATCH, "wrong purpose"
            )
        if self.audience != HOST_ADMISSION_PRESENTATION_AUDIENCE:
            raise _refuse(
                HostAdmissionPresentationRefusalCode.AUDIENCE_MISMATCH, "wrong audience"
            )
        _utc(self.issued_at)
        _utc(self.expires_at)

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": HOST_ADMISSION_PRESENTATION_SCHEMA,
            "version": HOST_ADMISSION_PRESENTATION_VERSION,
            "purpose": self.purpose,
            "audience": self.audience,
            "presentation_id": self.presentation_id,
            "key_id": self.key_id,
            "dispatch_id": self.dispatch_id,
            "candidate_attestation_envelope_digest": (
                self.candidate_attestation_envelope_digest
            ),
            "installed_attestation_envelope_digest": (
                self.installed_attestation_envelope_digest
            ),
            "issued_at": _render(self.issued_at),
            "expires_at": _render(self.expires_at),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class HostAdmissionPresentationV1:
    statement: HostAdmissionPresentationStatementV1
    signature: str

    def __post_init__(self) -> None:
        _decode_signature(self.signature)

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @classmethod
    def parse(cls, value: object) -> HostAdmissionPresentationV1:
        if not isinstance(value, Mapping) or set(value) != {"statement", "signature"}:
            raise _refuse(
                HostAdmissionPresentationRefusalCode.MALFORMED,
                "presentation must contain exactly statement and signature",
            )
        statement = value["statement"]
        if not isinstance(statement, Mapping):
            raise _refuse(
                HostAdmissionPresentationRefusalCode.MALFORMED,
                "statement must be a mapping",
            )
        required = {
            "schema",
            "version",
            "purpose",
            "audience",
            "presentation_id",
            "key_id",
            "dispatch_id",
            "candidate_attestation_envelope_digest",
            "installed_attestation_envelope_digest",
            "issued_at",
            "expires_at",
        }
        if set(statement) != required:
            raise _refuse(
                HostAdmissionPresentationRefusalCode.MALFORMED,
                "statement fields differ from v1",
            )
        version = statement["version"]
        if (
            statement["schema"] != HOST_ADMISSION_PRESENTATION_SCHEMA
            or type(version) is not int
            or version != HOST_ADMISSION_PRESENTATION_VERSION
        ):
            raise _refuse(
                HostAdmissionPresentationRefusalCode.UNSUPPORTED_VERSION,
                "unsupported schema or version",
            )
        try:
            return cls(
                statement=HostAdmissionPresentationStatementV1(
                    presentation_id=_text(statement, "presentation_id"),
                    key_id=_text(statement, "key_id"),
                    dispatch_id=_text(statement, "dispatch_id"),
                    candidate_attestation_envelope_digest=_text(
                        statement, "candidate_attestation_envelope_digest"
                    ),
                    installed_attestation_envelope_digest=_text(
                        statement, "installed_attestation_envelope_digest"
                    ),
                    issued_at=_parse_instant(statement, "issued_at"),
                    expires_at=_parse_instant(statement, "expires_at"),
                    purpose=_text(statement, "purpose"),
                    audience=_text(statement, "audience"),
                ),
                signature=_text(value, "signature"),
            )
        except HostAdmissionPresentationRefusedError:
            raise
        except (TypeError, ValueError) as exc:
            raise _refuse(
                HostAdmissionPresentationRefusalCode.MALFORMED,
                "invalid presentation value",
            ) from exc


@runtime_checkable
class HostAdmissionPresentationVerifier(Protocol):
    def verify_host_admission_presentation(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        public_key_b64: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool: ...


def verify_host_admission_presentation(
    presentation: HostAdmissionPresentationV1,
    *,
    verifier: HostAdmissionPresentationVerifier,
    algorithm: str,
    public_key_fingerprint: str,
    now: datetime,
    public_key_b64: str,
) -> HostAdmissionPresentationStatementV1:
    instant = _utc(now)
    statement = presentation.statement
    issued, expires = _utc(statement.issued_at), _utc(statement.expires_at)
    if not verifier.verify_host_admission_presentation(
        key_id=statement.key_id,
        algorithm=algorithm,
        purpose=HOST_ADMISSION_PRESENTATION_PURPOSE,
        public_key_fingerprint=public_key_fingerprint,
        public_key_b64=public_key_b64,
        canonical_bytes=statement.canonical_bytes,
        signature=presentation.signature,
    ):
        raise _refuse(
            HostAdmissionPresentationRefusalCode.SIGNATURE_INVALID,
            "signature did not verify",
        )
    if expires <= issued or expires - issued > _MAX_LIFETIME:
        raise _refuse(
            HostAdmissionPresentationRefusalCode.LIFETIME_INVALID,
            "lifetime must be positive and at most five minutes",
        )
    if instant < issued:
        raise _refuse(
            HostAdmissionPresentationRefusalCode.NOT_YET_VALID,
            "presentation is not yet valid",
        )
    if instant >= expires:
        raise _refuse(
            HostAdmissionPresentationRefusalCode.EXPIRED, "presentation has expired"
        )
    return statement


def admission_consumption_fingerprint(
    *,
    dispatch_envelope_digest: str,
    candidate_attestation_envelope_digest: str,
    installed_attestation_envelope_digest: str,
) -> str:
    """Return Kernel's bare-hex fingerprint for one evidence coordinate."""
    values = (
        dispatch_envelope_digest,
        candidate_attestation_envelope_digest,
        installed_attestation_envelope_digest,
    )
    if not all(isinstance(value, str) and _is_digest(value) for value in values):
        raise _refuse(
            HostAdmissionPresentationRefusalCode.MALFORMED,
            "digest is not canonical sha256",
        )
    return compute_host_admission_consumption_fingerprint(
        dispatch_envelope_digest=dispatch_envelope_digest,
        candidate_attestation_envelope_digest=(candidate_attestation_envelope_digest),
        installed_attestation_envelope_digest=(installed_attestation_envelope_digest),
    )


def foundation_public_key_base64(*, public_key_b64: str, fingerprint: str) -> str:
    """Convert Control's canonical base64url material to Foundation wire text."""
    actual = PublicKeyFingerprintV1.from_public_key_b64(public_key_b64).canonical
    if actual != fingerprint:
        raise _refuse(
            HostAdmissionPresentationRefusalCode.MALFORMED,
            "stored key fingerprint differs from key material",
        )
    raw = base64.urlsafe_b64decode(public_key_b64 + "=" * (-len(public_key_b64) % 4))
    return base64.b64encode(raw).decode("ascii")


def _refuse(
    code: HostAdmissionPresentationRefusalCode, detail: str
) -> HostAdmissionPresentationRefusedError:
    return HostAdmissionPresentationRefusedError(code, detail)


def _text(row: Mapping[str, object], key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise ValueError(key)
    return value


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _refuse(
            HostAdmissionPresentationRefusalCode.MALFORMED,
            "instant must be timezone-aware",
        )
    return value.astimezone(UTC)


def _render(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _parse_instant(row: Mapping[str, object], key: str) -> datetime:
    value = _text(row, key)
    if not value.endswith("Z"):
        raise ValueError(key)
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if _render(parsed) != value:
        raise ValueError(key)
    return parsed


def _decode_signature(value: object) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or value != value.strip()
    ):
        raise _refuse(
            HostAdmissionPresentationRefusalCode.SIGNATURE_ENCODING,
            "signature must be unpadded base64url",
        )
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise _refuse(
            HostAdmissionPresentationRefusalCode.SIGNATURE_ENCODING,
            "signature is not base64url",
        ) from exc
    if not raw or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise _refuse(
            HostAdmissionPresentationRefusalCode.SIGNATURE_ENCODING,
            "signature is non-canonical",
        )
    return raw


def _is_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(c in "0123456789abcdef" for c in value[7:])
    )
