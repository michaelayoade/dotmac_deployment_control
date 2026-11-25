"""Server-side verification of a host-admission attestation pair, owned by Control.

Control already owns the trust roots (`HostAdmissionRootContextV1`, resolved from
its durable registry) and the admission context. This module adds the missing
half: given that RESOLUTION and the pair a target PRESENTED, decide - in process,
with no Foundation dependency - whether the pair verifies. The Ed25519 primitive
is injected (kernel-backed in the composing control plane), so Control keeps its
no-crypto-dependency rule.

The pair FORMAT is Foundation's `TrustedHostAttestation.v2` (a signed candidate
attestation and a signed installed-host attestation). This module mirrors it and
is replayed against format vectors (`contract/target_api_v2.json`,
`attestation_pair`), the same mirror-plus-vectors pattern as `target_api`. The
refusal codes are Foundation's own strings so both sides agree on them.

Non-authorizing: success returns evidence Control compares against its own freshly
derived context; it is never a capability.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from dotmac_deployment_control.digests import (
    AttestationDigestV1,
    AttestationKeyFingerprintV1,
    canonical_json,
    is_canonical_digest,
)
from dotmac_deployment_control.ports import DeploymentControlError

if TYPE_CHECKING:  # the real type; this module needs only its attributes
    from dotmac_deployment_control.host_admission_coordinator import (
        HostAdmissionVerificationContextV1,
    )

ATTESTATION_SCHEMA: Final = "TrustedHostAttestation.v2"
CANDIDATE_PURPOSE: Final = "dotmac.foundation.candidate-artifact.v2"
INSTALLED_PURPOSE: Final = "dotmac.foundation.installed-host.v2"

#: Foundation's refusal codes, verbatim.
OBSERVATION_ABSENT: Final = "trusted-host-source-attestation-absent"
OBSERVATION_MALFORMED: Final = "trusted-host-source-attestation-malformed"
TRUST_ROOTS_NOT_DISTINCT: Final = "trusted-host-source-trust-roots-not-distinct"
SAME_KEY_SIGNED_BOTH: Final = "trusted-host-source-same-key-signed-both"
KEY_NOT_TRUSTED: Final = "trusted-host-source-key-not-trusted"
SIGNATURE_INVALID: Final = "trusted-host-source-signature-invalid"
ATTESTATIONS_DISAGREE: Final = "trusted-host-source-attestations-disagree"
OBSERVATION_ID_MISMATCH: Final = "trusted-host-source-observation-id-mismatch"
PACKAGE_MISMATCH: Final = "trusted-host-source-package-mismatch"
ROOT_PURPOSE_MISMATCH: Final = "trusted-host-source-root-purpose-mismatch"
ROOT_BINDING_MISMATCH: Final = "trusted-host-source-root-binding-mismatch"
ROOT_REVOKED: Final = "trusted-host-source-root-revoked"
ROOT_NOT_VALID: Final = "trusted-host-source-root-not-valid"
AUDIENCE_MISMATCH: Final = "trusted-host-source-audience-mismatch"
STALE: Final = "trusted-host-source-stale"
FUTURE: Final = "trusted-host-source-future"
SUBJECT_MISMATCH: Final = "trusted-host-source-subject-mismatch"

_UTC_RFC3339: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_REVISION: Final = re.compile(r"[0-9a-f]{40}")
_ENVELOPE_FIELDS: Final = (
    "schema",
    "purpose",
    "issuer",
    "key_id",
    "algorithm",
    "public_key_fingerprint",
    "custody_domain",
    "trust_root_version",
    "issued_at",
    "expires_at",
    "audience",
    "observation_id",
    "subject",
    "signature",
)
_CANDIDATE_SUBJECT: Final = frozenset(
    {
        "package",
        "version",
        "wheel_sha256",
        "source_revision",
        "repository",
        "run_id",
        "artifact_id",
    }
)
_INSTALLED_SUBJECT: Final = frozenset(
    {"host_identity", "package", "version", "wheel_sha256", "candidate_subject_digest"}
)


class AttestationPairRefusedError(DeploymentControlError):
    """A pair was refused; `code` is Foundation's own reason string."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


@runtime_checkable
class AttestationVerifier(Protocol):
    """The injected crypto seam (the kernel's Ed25519 in production)."""

    def verify(
        self, *, public_key: bytes, algorithm: str, message: bytes, signature: str
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class AttestationPairRootV1:
    """The root that authenticated one half. Field-for-field the same as
    `HostAdmissionForeignRootV1` (a test pins that), so the caller maps by name."""

    public_key_fingerprint: str
    root_version: str
    key_id: str
    algorithm: str
    purpose: str
    custody_domain: str
    issuer: str


@dataclass(frozen=True, slots=True)
class AttestationPairEvidenceV1:
    """What a verified pair reports. Field-for-field the same as
    `HostAdmissionForeignVerificationEvidenceV1`. Non-authorizing: Control compares
    every field with its own freshly derived context before consuming anything."""

    candidate_attestation_envelope_digest: str
    installed_attestation_envelope_digest: str
    verification_context_digest: str
    verified_host_identity: str
    verified_observation_id: str
    verified_package: str
    verified_candidate_audience: str
    verified_installed_audience: str
    verified_candidate_root: AttestationPairRootV1
    verified_installed_root: AttestationPairRootV1


@dataclass(frozen=True, slots=True)
class PresentedAttestationPairV1:
    """What the target presented: two parsed envelope documents, either absent."""

    candidate: Mapping[str, Any] | None
    installed: Mapping[str, Any] | None


def _malformed(detail: str) -> AttestationPairRefusedError:
    return AttestationPairRefusedError(OBSERVATION_MALFORMED, detail)


def _required(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _malformed(f"{name} is required")
    return value


def _instant(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not _UTC_RFC3339.fullmatch(value):
        raise _malformed(f"{name} must be canonical UTC RFC3339")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _wire_digest(value: object, name: str) -> str:
    text = _required(value, name)
    if not is_canonical_digest(text):
        raise _malformed(f"{name} must use canonical sha256:<hex> form")
    return text


@dataclass(frozen=True, slots=True)
class _Envelope:
    document: Mapping[str, Any]

    def __getitem__(self, name: str) -> Any:
        return self.document[name]

    def signed_bytes_document(self) -> dict[str, Any]:
        return {k: v for k, v in self.document.items() if k != "signature"}


def _parse_envelope(value: Mapping[str, Any] | None, role: str) -> _Envelope:
    if value is None:
        raise AttestationPairRefusedError(
            OBSERVATION_ABSENT, f"{role} attestation is missing"
        )
    if not isinstance(value, Mapping) or set(value) != set(_ENVELOPE_FIELDS):
        raise _malformed(f"{role} envelope has missing or unknown members")
    for name in _ENVELOPE_FIELDS:
        if name != "subject":
            _required(value[name], f"{role} {name}")
    if value["schema"] != ATTESTATION_SCHEMA:
        raise _malformed(f"{role} schema must be {ATTESTATION_SCHEMA}")
    if not is_canonical_digest(value["public_key_fingerprint"]):
        raise _malformed(f"{role} fingerprint must be sha256:<hex>")
    if not isinstance(value["subject"], Mapping):
        raise _malformed(f"{role} subject must be an object")
    if _instant(value["expires_at"], "expires_at") <= _instant(
        value["issued_at"], "issued_at"
    ):
        raise _malformed("expires_at must follow issued_at")
    return _Envelope(value)


def _check_root(root: Any, role: str) -> None:
    try:
        derived = AttestationKeyFingerprintV1.from_standard_base64(
            root.public_key_base64
        ).canonical
    except DeploymentControlError as exc:
        raise _malformed(f"{role} root public key is not strict base64") from exc
    if derived != root.public_key_fingerprint:
        raise _malformed(f"{role} root material does not match its fingerprint")
    if root.not_after <= root.not_before:
        raise _malformed(f"{role} root not_after must follow not_before")


def _verify(
    envelope: _Envelope,
    verifier: AttestationVerifier,
    root: Any,
    purpose: str,
    audience: str,
    now: datetime,
) -> None:
    if envelope["public_key_fingerprint"] != root.public_key_fingerprint:
        raise AttestationPairRefusedError(
            KEY_NOT_TRUSTED, "attestation public-key material is unknown"
        )
    if root.revoked:
        raise AttestationPairRefusedError(ROOT_REVOKED, "attestation root is revoked")
    if not root.not_before <= now < root.not_after:
        raise AttestationPairRefusedError(
            ROOT_NOT_VALID, "attestation root is not currently valid"
        )
    if envelope["purpose"] != purpose or root.purpose != purpose:
        raise AttestationPairRefusedError(
            ROOT_PURPOSE_MISMATCH, "attestation purpose does not match its role"
        )
    pairs = (
        ("issuer", root.issuer),
        ("key_id", root.key_id),
        ("algorithm", root.algorithm),
        ("custody_domain", root.custody_domain),
        ("trust_root_version", root.root_version),
    )
    differs = [name for name, expected in pairs if envelope[name] != expected]
    if differs:
        raise AttestationPairRefusedError(
            ROOT_BINDING_MISMATCH,
            f"attestation root binding differs in {', '.join(differs)}",
        )
    if envelope["audience"] != audience:
        raise AttestationPairRefusedError(
            AUDIENCE_MISMATCH, f"attestation audience is not {audience!r}"
        )
    issued = _instant(envelope["issued_at"], "issued_at")
    expires = _instant(envelope["expires_at"], "expires_at")
    if issued > now:
        raise AttestationPairRefusedError(FUTURE, "attestation is issued in the future")
    if now >= expires:
        raise AttestationPairRefusedError(STALE, "attestation is stale or expired")
    if not root.not_before <= issued < root.not_after or expires > root.not_after:
        raise AttestationPairRefusedError(
            ROOT_NOT_VALID, "attestation lifetime is outside its root validity"
        )
    try:
        verified = verifier.verify(
            public_key=base64.b64decode(root.public_key_base64, validate=True),
            algorithm=str(envelope["algorithm"]),
            message=_signed_message(envelope),
            signature=str(envelope["signature"]),
        )
    except (binascii.Error, ValueError, TypeError, AttributeError):
        raise AttestationPairRefusedError(
            SIGNATURE_INVALID, "attestation signature verification failed"
        ) from None
    if not verified:
        raise AttestationPairRefusedError(
            SIGNATURE_INVALID, "attestation signature is invalid"
        )


def _signed_message(envelope: _Envelope) -> bytes:
    return canonical_json(envelope.signed_bytes_document())


def _candidate_subject(envelope: _Envelope) -> Mapping[str, Any]:
    subject = envelope["subject"]
    if set(subject) != _CANDIDATE_SUBJECT:
        raise _malformed("candidate subject is incomplete or widened")
    for name in _CANDIDATE_SUBJECT:
        _required(subject[name], f"candidate {name}")
    _wire_digest(subject["wheel_sha256"], "candidate wheel_sha256")
    if not _REVISION.fullmatch(subject["source_revision"]):
        raise _malformed("candidate source_revision must be a 40-hex commit")
    return subject


def _installed_subject(envelope: _Envelope) -> Mapping[str, Any]:
    subject = envelope["subject"]
    if set(subject) != _INSTALLED_SUBJECT:
        raise _malformed("installed subject is incomplete or widened")
    for name in _INSTALLED_SUBJECT:
        _required(subject[name], f"installed {name}")
    _wire_digest(subject["wheel_sha256"], "installed wheel_sha256")
    _wire_digest(subject["candidate_subject_digest"], "installed candidate digest")
    return subject


def verify_attestation_pair(
    resolution: HostAdmissionVerificationContextV1,
    presented: PresentedAttestationPairV1,
    *,
    verifier: AttestationVerifier,
    now: datetime,
) -> AttestationPairEvidenceV1:
    """Verify the presented pair against Control's resolved roots and context.

    `resolution` is Control's own `HostAdmissionVerificationContextV1` (roots,
    audiences, the expected package, host and dispatch, its context digest); only
    its attributes are read. The pair must be signed by two DIFFERENT keys, each
    matching Control's root for its role, within lifetime, with matching audience,
    and must agree on the package bytes and bind each other.
    """
    if not isinstance(verifier, AttestationVerifier):
        raise _malformed("verifier must implement AttestationVerifier")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise _malformed("verification now must be timezone-aware")
    now = now.astimezone(UTC)
    candidate = _parse_envelope(presented.candidate, "candidate")
    installed = _parse_envelope(presented.installed, "installed")
    cand_root, inst_root = resolution.candidate_root, resolution.installed_root
    _check_root(cand_root, "candidate")
    _check_root(inst_root, "installed")
    if (
        cand_root.public_key_fingerprint == inst_root.public_key_fingerprint
        or cand_root.custody_domain == inst_root.custody_domain
    ):
        raise AttestationPairRefusedError(
            TRUST_ROOTS_NOT_DISTINCT, "trust roots overlap in material or custody"
        )
    if candidate["public_key_fingerprint"] == installed["public_key_fingerprint"]:
        raise AttestationPairRefusedError(
            SAME_KEY_SIGNED_BOTH,
            "candidate and installed attestations use the same signing key",
        )
    _verify(
        candidate,
        verifier,
        cand_root,
        CANDIDATE_PURPOSE,
        resolution.candidate_audience,
        now,
    )
    expected_host = _required(resolution.host_id, "expected host identity")
    if resolution.installed_audience != expected_host:
        raise AttestationPairRefusedError(
            AUDIENCE_MISMATCH, "installed audience is not the expected host identity"
        )
    _verify(installed, verifier, inst_root, INSTALLED_PURPOSE, expected_host, now)
    cand_subject = _candidate_subject(candidate)
    inst_subject = _installed_subject(installed)
    expected_id = _required(resolution.dispatch_id, "expected observation id")
    if installed["observation_id"] != expected_id:
        raise AttestationPairRefusedError(
            OBSERVATION_ID_MISMATCH,
            "installed observation does not match the expected dispatch",
        )
    package = _required(resolution.expected_foundation_package, "expected package")
    if cand_subject["package"] != package or inst_subject["package"] != package:
        raise AttestationPairRefusedError(
            PACKAGE_MISMATCH, "a package differs from the expected package"
        )
    if (
        inst_subject["candidate_subject_digest"]
        != AttestationDigestV1.over_document(dict(cand_subject)).canonical
    ):
        raise AttestationPairRefusedError(
            SUBJECT_MISMATCH, "installed host does not bind the candidate subject"
        )
    if inst_subject["host_identity"] != expected_host:
        raise AttestationPairRefusedError(
            SUBJECT_MISMATCH, "installed host subject is not the expected host"
        )
    if any(
        cand_subject[name] != inst_subject[name]
        for name in ("package", "version", "wheel_sha256")
    ):
        raise AttestationPairRefusedError(
            ATTESTATIONS_DISAGREE, "candidate and host attest different package bytes"
        )

    def foreign(root: Any) -> AttestationPairRootV1:
        return AttestationPairRootV1(
            public_key_fingerprint=root.public_key_fingerprint,
            root_version=root.root_version,
            key_id=root.key_id,
            algorithm=root.algorithm,
            purpose=root.purpose,
            custody_domain=root.custody_domain,
            issuer=root.issuer,
        )

    return AttestationPairEvidenceV1(
        candidate_attestation_envelope_digest=AttestationDigestV1.over_document(
            dict(candidate.document)
        ).canonical,
        installed_attestation_envelope_digest=AttestationDigestV1.over_document(
            dict(installed.document)
        ).canonical,
        verification_context_digest=resolution.context_digest,
        verified_host_identity=expected_host,
        verified_observation_id=expected_id,
        verified_package=package,
        verified_candidate_audience=resolution.candidate_audience,
        verified_installed_audience=resolution.installed_audience,
        verified_candidate_root=foreign(cand_root),
        verified_installed_root=foreign(inst_root),
    )


__all__ = [
    "AttestationPairEvidenceV1",
    "AttestationPairRefusedError",
    "AttestationPairRootV1",
    "AttestationVerifier",
    "PresentedAttestationPairV1",
    "verify_attestation_pair",
]
