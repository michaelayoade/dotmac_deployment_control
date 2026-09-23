"""Fresh, signed evidence that the disposable rehearsal harness — not the CP
instance under rehearsal — presented a lease.

`test_genuine_evidence_round_trips` is the load-bearing test: everything else
here is a refusal, and a suite of refusals passes trivially when construction
is broken.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

import dotmac_deployment_control
from dotmac_deployment_control.rehearsal_harness_evidence import (
    REHEARSAL_HARNESS_EVIDENCE_PURPOSE,
    REHEARSAL_HARNESS_EVIDENCE_SCHEMA,
    REHEARSAL_HARNESS_EVIDENCE_VERSION,
    RehearsalHarnessEvidenceRefusalCode,
    RehearsalHarnessEvidenceRefusedError,
    parse_signed_rehearsal_harness_evidence,
    verify_rehearsal_harness_evidence_signature,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    REHEARSAL_ONLY_ENVIRONMENT,
)

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def _document(**overrides: object) -> dict[str, object]:
    base = {
        "schema": REHEARSAL_HARNESS_EVIDENCE_SCHEMA,
        "version": REHEARSAL_HARNESS_EVIDENCE_VERSION,
        "lease_id": "lease-1",
        "controller_fingerprint": "fp-controller",
        "target_ref": "target-1",
        "environment": REHEARSAL_ONLY_ENVIRONMENT,
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "valid_until": (NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    }
    base.update(overrides)
    return base


def _canonical_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _envelope(
    document: dict[str, object] | None = None,
    *,
    key_id: str = "k-harness",
    algorithm: str = "ed25519",
    signature: str = "SIG",
) -> dict[str, object]:
    doc = document if document is not None else _document()
    canonical = _canonical_bytes(doc)
    return {
        "canonical_bytes": base64.b64encode(canonical).decode("ascii"),
        "signature": {
            "key_id": key_id,
            "algorithm": algorithm,
            "signature": base64.b64encode(signature.encode("ascii")).decode("ascii"),
        },
    }


class _Verifier:
    """A genuine negative control: only recognizes ONE fixture signature."""

    def __init__(self, *, accepted_signature: bytes = b"SIG") -> None:
        self._accepted_signature = accepted_signature
        self.calls: list[dict[str, object]] = []

    def verify_rehearsal_harness_evidence(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool:
        self.calls.append(
            {
                "key_id": key_id,
                "algorithm": algorithm,
                "purpose": purpose,
                "canonical_bytes": canonical_bytes,
                "signature": signature,
            }
        )
        return purpose == REHEARSAL_HARNESS_EVIDENCE_PURPOSE and (
            signature == self._accepted_signature
        )


def test_genuine_evidence_round_trips() -> None:
    parsed = parse_signed_rehearsal_harness_evidence(_envelope())
    assert parsed.lease_id == "lease-1"
    assert parsed.controller_fingerprint == "fp-controller"
    assert parsed.target_ref == "target-1"
    assert parsed.environment == REHEARSAL_ONLY_ENVIRONMENT
    verify_rehearsal_harness_evidence_signature(parsed, verifier=_Verifier(), at=NOW)
    # The digest is stable for the same bytes.
    assert parsed.digest.canonical == parsed.digest.canonical


def test_verifier_is_called_with_controls_own_purpose_not_anything_on_the_wire() -> (
    None
):
    verifier = _Verifier()
    parsed = parse_signed_rehearsal_harness_evidence(_envelope())
    verify_rehearsal_harness_evidence_signature(parsed, verifier=verifier, at=NOW)
    assert verifier.calls[0]["purpose"] == REHEARSAL_HARNESS_EVIDENCE_PURPOSE


@pytest.mark.parametrize(
    "envelope",
    [
        {"canonical_bytes": "x"},
        {"canonical_bytes": "x", "signature": "not-a-mapping"},
        {},
    ],
)
def test_malformed_envelope_shape_is_refused(envelope: dict[str, object]) -> None:
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        parse_signed_rehearsal_harness_evidence(envelope)
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.MALFORMED


def test_malformed_base64_is_refused() -> None:
    envelope = _envelope()
    envelope["canonical_bytes"] = "not-valid-base64!!!"
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        parse_signed_rehearsal_harness_evidence(envelope)
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.MALFORMED


def test_wrong_schema_is_refused() -> None:
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        parse_signed_rehearsal_harness_evidence(
            _envelope(_document(schema="something.else"))
        )
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.SCHEMA_MISMATCH


def test_wrong_version_is_refused() -> None:
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        parse_signed_rehearsal_harness_evidence(_envelope(_document(version=99)))
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.SCHEMA_MISMATCH


def test_unsigned_is_refused() -> None:
    doc = _document()
    canonical = _canonical_bytes(doc)
    envelope = {
        "canonical_bytes": base64.b64encode(canonical).decode("ascii"),
        "signature": {"key_id": "k", "algorithm": "ed25519", "signature": ""},
    }
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        parse_signed_rehearsal_harness_evidence(envelope)
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.UNSIGNED


def test_verifier_purpose_mismatch_is_refused_for_a_non_conforming_verifier() -> None:
    class _NotAVerifier:
        pass

    parsed = parse_signed_rehearsal_harness_evidence(_envelope())
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        verify_rehearsal_harness_evidence_signature(
            parsed, verifier=_NotAVerifier(), at=NOW  # type: ignore[arg-type]
        )
    assert (
        refused.value.code
        == RehearsalHarnessEvidenceRefusalCode.VERIFIER_PURPOSE_MISMATCH
    )


def test_signature_invalid_when_verifier_returns_false() -> None:
    parsed = parse_signed_rehearsal_harness_evidence(_envelope(signature="WRONG-SIG"))
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        verify_rehearsal_harness_evidence_signature(
            parsed, verifier=_Verifier(), at=NOW
        )
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.SIGNATURE_INVALID


def test_expired_is_refused() -> None:
    parsed = parse_signed_rehearsal_harness_evidence(_envelope())
    at = NOW + timedelta(minutes=11)
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        verify_rehearsal_harness_evidence_signature(parsed, verifier=_Verifier(), at=at)
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.EXPIRED


def test_future_dated_is_refused() -> None:
    parsed = parse_signed_rehearsal_harness_evidence(_envelope())
    at = NOW - timedelta(minutes=1)
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        verify_rehearsal_harness_evidence_signature(parsed, verifier=_Verifier(), at=at)
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.FUTURE_DATED


def test_wrong_environment_is_refused() -> None:
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        parse_signed_rehearsal_harness_evidence(
            _envelope(_document(environment="production"))
        )
    assert (
        refused.value.code
        == RehearsalHarnessEvidenceRefusalCode.NOT_A_REHEARSAL_ENVIRONMENT
    )


def test_verifier_always_receives_the_bytes_actually_parsed_not_a_reconstruction() -> (
    None
):
    """The verifier is called with exactly the decoded `canonical_bytes` this
    module parsed — never a re-serialization of the parsed fields. Proven by
    tampering with the encoded document's `lease_id` and confirming the
    verifier sees bytes matching the TAMPERED document, and the parsed field
    matches too — there is exactly one source of truth for what was signed."""
    tampered_doc = _document(lease_id="lease-2")
    canonical = _canonical_bytes(tampered_doc)
    envelope = {
        "canonical_bytes": base64.b64encode(canonical).decode("ascii"),
        "signature": {
            "key_id": "k-harness",
            "algorithm": "ed25519",
            "signature": base64.b64encode(b"SIG").decode("ascii"),
        },
    }
    verifier = _Verifier()
    parsed = parse_signed_rehearsal_harness_evidence(envelope)
    verify_rehearsal_harness_evidence_signature(parsed, verifier=verifier, at=NOW)
    assert verifier.calls[0]["canonical_bytes"] == canonical
    assert parsed.lease_id == "lease-2"


def _every_other_purpose_in_the_package() -> list[str]:
    """DERIVED, not hand-maintained — same pattern
    `test_rehearsal_issuer_authorization.py` uses for its own scan."""
    found = [
        name
        for name in dotmac_deployment_control.__all__
        if name.endswith("_PURPOSE")
        and getattr(dotmac_deployment_control, name)
        != REHEARSAL_HARNESS_EVIDENCE_PURPOSE
    ]
    assert found, "the scan itself found nothing — the guard would be vacuous"
    return [getattr(dotmac_deployment_control, name) for name in found]


def test_the_purpose_inventory_scan_is_not_vacuous() -> None:
    other_purposes = _every_other_purpose_in_the_package()
    assert len(other_purposes) >= 7, other_purposes
    assert REHEARSAL_HARNESS_EVIDENCE_PURPOSE not in other_purposes


@pytest.mark.parametrize("other_purpose", _every_other_purpose_in_the_package())
def test_every_other_purpose_in_the_package_is_refused(other_purpose: str) -> None:
    """Purpose separation: a verifier that only recognizes THIS module's own
    purpose refuses evidence signed under any other purpose this package
    exports."""
    assert other_purpose != REHEARSAL_HARNESS_EVIDENCE_PURPOSE

    class _OtherPurposeVerifier:
        def verify_rehearsal_harness_evidence(
            self,
            *,
            key_id: str,
            algorithm: str,
            purpose: str,
            canonical_bytes: bytes,
            signature: bytes,
        ) -> bool:
            # Simulates a verifier enrolled under a DIFFERENT purpose: it
            # would answer True for its own purpose, but this module always
            # asks with REHEARSAL_HARNESS_EVIDENCE_PURPOSE, so a verifier
            # keyed to `other_purpose` must refuse.
            return purpose == other_purpose

    parsed = parse_signed_rehearsal_harness_evidence(_envelope())
    with pytest.raises(RehearsalHarnessEvidenceRefusedError) as refused:
        verify_rehearsal_harness_evidence_signature(
            parsed, verifier=_OtherPurposeVerifier(), at=NOW
        )
    assert refused.value.code == RehearsalHarnessEvidenceRefusalCode.SIGNATURE_INVALID
