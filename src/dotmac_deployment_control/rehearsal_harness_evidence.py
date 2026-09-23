"""Fresh, signed evidence that the disposable rehearsal harness — not the CP
instance under rehearsal — is the one presenting a lease for issuance or
consumption.

## Why this module exists

The prior CP-side design tried to derive its own comparison subject from a
same-process "harness witness" object. That object was empirically forgeable:
`dataclasses.replace()` on a legitimate binding produced a second, equally
"valid" witness, and the "private" sentinel guarding it was importable from
outside the module that defined it. Neither failure is a bug in that object's
implementation — they are the structural consequence of trusting anything a
same-process Python value merely *asserts* about its own provenance.

This module replaces that with the same discipline
`authorization_v3.HealthEvidenceVerifier` already applies to Platform Health:
evidence the harness SIGNS with a key Control has independently enrolled, and
Control verifies with an INJECTED verifier before ever comparing anything the
document claims against ledger state. A same-process object cannot forge a
verifier's `True` return the way it can forge a dataclass field.

## Pure, no I/O

This module performs no I/O, mints nothing, and holds no key material. See
`authorization_v3.py`'s own docstring for why: the split between "verifies a
signature" and "look up a live database row" belongs to the assembly-supplied
verifier, not here.

## `purpose` is supplied by Control, never read off the wire

Exactly the discipline `HealthEvidenceVerifier.verify_health_evidence` and
`RehearsalIssuerAuthorizationVerifier.verify_rehearsal_issuer_authorization`
already use: `REHEARSAL_HARNESS_EVIDENCE_PURPOSE` is a constant this module
passes to the injected verifier, never a field trusted from the document
itself — a document cannot claim to satisfy a purpose it never carries.

## `environment` is checked here too, structurally, not by convention

Mirroring `rehearsal_issuer_authorization.REHEARSAL_ONLY_ENVIRONMENT`: fresh
harness evidence naming any environment other than the one rehearsal value is
refused, so a forged or misconfigured harness cannot present evidence that
would, on its face, describe a production act.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from dotmac_deployment_control.digests import RehearsalHarnessEvidenceDigestV1
from dotmac_deployment_control.ports import DeploymentControlError
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    REHEARSAL_ONLY_ENVIRONMENT,
)

__all__ = [
    "REHEARSAL_HARNESS_EVIDENCE_PURPOSE",
    "REHEARSAL_HARNESS_EVIDENCE_SCHEMA",
    "REHEARSAL_HARNESS_EVIDENCE_VERSION",
    "ParsedRehearsalHarnessEvidence",
    "RehearsalHarnessEvidenceRefusalCode",
    "RehearsalHarnessEvidenceRefusedError",
    "RehearsalHarnessEvidenceVerifier",
    "parse_signed_rehearsal_harness_evidence",
    "verify_rehearsal_harness_evidence_signature",
]

#: Distinct from every other signer/verifier purpose in this package, on the
#: identical doctrine `rehearsal_issuer_authorization.REHEARSAL_ISSUER_PURPOSE`
#: and `authorization_v3.HEALTH_EVIDENCE_PURPOSE` document: one key answering
#: two questions cannot be used to contradict itself. Re-exported from the
#: top-level package (see `__init__.py`) so
#: `test_rehearsal_issuer_authorization.py`'s derived purpose-inventory scan
#: covers this purpose automatically.
REHEARSAL_HARNESS_EVIDENCE_PURPOSE: Final = "deployment_rehearsal_harness_evidence"
REHEARSAL_HARNESS_EVIDENCE_SCHEMA: Final = (
    "dotmac.deployment_control.rehearsal_harness_evidence"
)
REHEARSAL_HARNESS_EVIDENCE_VERSION: Final = 1

_MAX_TEXT = 512
_DOCUMENT_KEYS = frozenset(
    {
        "schema",
        "version",
        "lease_id",
        "controller_fingerprint",
        "target_ref",
        "environment",
        "issued_at",
        "valid_until",
    }
)


class RehearsalHarnessEvidenceRefusalCode(StrEnum):
    """Why presented rehearsal-harness evidence does not stand, and why."""

    MALFORMED = "rehearsal_harness_evidence_malformed"
    SCHEMA_MISMATCH = "rehearsal_harness_evidence_schema_mismatch"
    UNSIGNED = "rehearsal_harness_evidence_unsigned"
    VERIFIER_PURPOSE_MISMATCH = "rehearsal_harness_evidence_verifier_purpose_mismatch"
    SIGNATURE_INVALID = "rehearsal_harness_evidence_signature_invalid"
    #: The evidence's own `environment` field is not
    #: `REHEARSAL_ONLY_ENVIRONMENT` — the structural non-production guard,
    #: mirrored from `rehearsal_issuer_authorization`.
    NOT_A_REHEARSAL_ENVIRONMENT = (
        "rehearsal_harness_evidence_not_a_rehearsal_environment"
    )
    EXPIRED = "rehearsal_harness_evidence_expired"
    FUTURE_DATED = "rehearsal_harness_evidence_future_dated"


class RehearsalHarnessEvidenceRefusedError(DeploymentControlError):
    """Presented rehearsal-harness evidence is not authority, and why."""

    def __init__(self, code: RehearsalHarnessEvidenceRefusalCode, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _refused(
    code: RehearsalHarnessEvidenceRefusalCode, detail: str
) -> RehearsalHarnessEvidenceRefusedError:
    return RehearsalHarnessEvidenceRefusedError(code, detail)


@runtime_checkable
class RehearsalHarnessEvidenceVerifier(Protocol):
    """Verifies the disposable rehearsal harness's signature over evidence
    bytes.

    Control chooses no algorithm or key provider and holds no key material —
    identical restraint to `authorization_v3.HealthEvidenceVerifier`. An
    assembly's concrete implementation resolves `key_id` against its OWN
    enrolled rehearsal-harness-key registry and returns `False` for an
    unenrolled key.

    `purpose` is supplied by CONTROL (`REHEARSAL_HARNESS_EVIDENCE_PURPOSE`),
    never read off the wire.
    """

    def verify_rehearsal_harness_evidence(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class ParsedRehearsalHarnessEvidence:
    """The result of reading the harness's wire document — NEVER re-built.

    `canonical_bytes` is carried unchanged from what Control received; every
    other field is read OUT of those same bytes via `json.loads`, never
    re-serialized. `controller_fingerprint`/`lease_id` are only ever
    extractable through `parse_signed_rehearsal_harness_evidence` — no other
    code path may produce this type.
    """

    canonical_bytes: bytes
    lease_id: str
    controller_fingerprint: str
    target_ref: str
    environment: str
    issued_at: datetime
    valid_until: datetime
    key_id: str
    algorithm: str
    signature: bytes

    @property
    def digest(self) -> RehearsalHarnessEvidenceDigestV1:
        return RehearsalHarnessEvidenceDigestV1.over_bytes(self.canonical_bytes)


def _aware_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            f"{field} must be a datetime, got {type(value).__name__}",
        )
    if value.tzinfo is None:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            f"{field} is naive; an instant without a zone is not an instant",
        )
    return value.astimezone(UTC)


def _parse_instant(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            f"{field} must be a non-empty string",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            f"{field} is not an ISO-8601 timestamp",
        ) from exc
    return _aware_utc(parsed, field=field)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            f"{field} must be a non-empty, whitespace-exact string",
        )
    if len(value) > _MAX_TEXT:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            f"{field} exceeds {_MAX_TEXT} characters",
        )
    return value


def parse_signed_rehearsal_harness_evidence(
    value: object,
) -> ParsedRehearsalHarnessEvidence:
    """Read Control's OWN wire contract for signed rehearsal-harness evidence.

    `{"canonical_bytes": <str, base64>, "signature": {"key_id": <str>,
    "algorithm": <str>, "signature": <str, base64>}}`.

    `canonical_bytes` decodes to the exact bytes the harness signed. Fields
    are read OUT of those decoded bytes with `json.loads` and never
    reconstructed or re-encoded — the same receiving-parser discipline
    `authorization_v3.parse_signed_health_evidence_document` uses.
    """
    if not isinstance(value, Mapping) or set(value) != {"canonical_bytes", "signature"}:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            "signed rehearsal-harness evidence is exactly "
            "{canonical_bytes, signature}",
        )
    raw_b64 = value["canonical_bytes"]
    if not isinstance(raw_b64, str) or not raw_b64:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            "canonical_bytes must be a non-empty base64 string",
        )
    try:
        canonical_bytes = base64.b64decode(raw_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            "canonical_bytes is not valid base64",
        ) from exc

    signature_block = value["signature"]
    if not isinstance(signature_block, Mapping) or set(signature_block) != {
        "key_id",
        "algorithm",
        "signature",
    }:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.UNSIGNED,
            "a rehearsal-harness-evidence signature block is exactly "
            "{key_id, algorithm, signature}",
        )
    key_id = signature_block["key_id"]
    algorithm = signature_block["algorithm"]
    signature_b64 = signature_block["signature"]
    if not isinstance(key_id, str) or not key_id:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            "signature.key_id must be a non-empty string",
        )
    if not isinstance(algorithm, str) or not algorithm:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            "signature.algorithm must be a non-empty string",
        )
    if not isinstance(signature_b64, str) or not signature_b64:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.UNSIGNED,
            "signature.signature must be a non-empty base64 string",
        )
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            "signature.signature is not valid base64",
        ) from exc

    try:
        document = json.loads(canonical_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            "canonical_bytes does not decode as UTF-8 JSON",
        ) from exc
    if not isinstance(document, dict) or set(document) != _DOCUMENT_KEYS:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.MALFORMED,
            f"rehearsal-harness evidence document keys differ from "
            f"{sorted(_DOCUMENT_KEYS)}",
        )
    if document.get("schema") != REHEARSAL_HARNESS_EVIDENCE_SCHEMA:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.SCHEMA_MISMATCH,
            f"{document.get('schema')!r} is not "
            f"{REHEARSAL_HARNESS_EVIDENCE_SCHEMA!r}",
        )
    if document.get("version") != REHEARSAL_HARNESS_EVIDENCE_VERSION:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.SCHEMA_MISMATCH,
            f"unsupported rehearsal-harness evidence version "
            f"{document.get('version')!r}",
        )

    lease_id = _text(document.get("lease_id"), "lease_id")
    controller_fingerprint = _text(
        document.get("controller_fingerprint"), "controller_fingerprint"
    )
    target_ref = _text(document.get("target_ref"), "target_ref")
    environment = _text(document.get("environment"), "environment")
    issued_at = _parse_instant(document.get("issued_at"), field="issued_at")
    valid_until = _parse_instant(document.get("valid_until"), field="valid_until")

    if environment != REHEARSAL_ONLY_ENVIRONMENT:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.NOT_A_REHEARSAL_ENVIRONMENT,
            f"environment must be {REHEARSAL_ONLY_ENVIRONMENT!r}, not "
            f"{environment!r}",
        )

    return ParsedRehearsalHarnessEvidence(
        canonical_bytes=canonical_bytes,
        lease_id=lease_id,
        controller_fingerprint=controller_fingerprint,
        target_ref=target_ref,
        environment=environment,
        issued_at=issued_at,
        valid_until=valid_until,
        key_id=key_id,
        algorithm=algorithm,
        signature=signature,
    )


def verify_rehearsal_harness_evidence_signature(
    parsed: ParsedRehearsalHarnessEvidence,
    *,
    verifier: RehearsalHarnessEvidenceVerifier,
    at: datetime | None = None,
) -> None:
    """The genuine cryptographic check, plus the freshness window.

    `at` is injected, never the wall clock read directly — the same
    discipline every other time-checked type in this package already uses,
    so a test can assert exact refusal boundaries without sleeping.
    """
    if not isinstance(verifier, RehearsalHarnessEvidenceVerifier):
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.VERIFIER_PURPOSE_MISMATCH,
            "the injected verifier does not implement rehearsal-harness-"
            "evidence verification",
        )
    ok = verifier.verify_rehearsal_harness_evidence(
        key_id=parsed.key_id,
        algorithm=parsed.algorithm,
        purpose=REHEARSAL_HARNESS_EVIDENCE_PURPOSE,
        canonical_bytes=parsed.canonical_bytes,
        signature=parsed.signature,
    )
    if not ok:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.SIGNATURE_INVALID,
            "the injected verifier refused the rehearsal harness's signature "
            "over the evidence's canonical bytes",
        )

    now = _aware_utc(at or datetime.now(UTC), field="at")
    if now >= parsed.valid_until:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.EXPIRED,
            f"the rehearsal-harness evidence window closed at "
            f"{parsed.valid_until.isoformat()}",
        )
    if now < parsed.issued_at:
        raise _refused(
            RehearsalHarnessEvidenceRefusalCode.FUTURE_DATED,
            f"the rehearsal-harness evidence is issued at "
            f"{parsed.issued_at.isoformat()}, which is in the future",
        )
