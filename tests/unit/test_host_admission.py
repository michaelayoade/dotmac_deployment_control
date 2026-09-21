"""Focused host-admission presentation contract tests."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from dotmac_deployment_control.digests import PublicKeyFingerprintV1
from dotmac_deployment_control.host_admission import (
    HostAdmissionPresentationRefusalCode,
    HostAdmissionPresentationRefusedError,
    HostAdmissionPresentationStatementV1,
    HostAdmissionPresentationV1,
    admission_consumption_fingerprint,
    foundation_public_key_base64,
    verify_host_admission_presentation,
)
from tests.unit.ed25519_reference import public_key, sign, verify

_NOW = datetime(2026, 9, 21, 12, tzinfo=UTC)
_KEY = b"two-independent-test-key"
_KEY_B64 = base64.urlsafe_b64encode(_KEY).decode().rstrip("=")
_FINGERPRINT = PublicKeyFingerprintV1.from_public_key_b64(_KEY_B64).canonical


class Verifier:
    def __init__(self, valid: bool = True) -> None:
        self.valid = valid

    def verify_host_admission_presentation(self, **values: object) -> bool:
        return self.valid and values["key_id"] == "key-1"


class ReferenceEd25519Verifier:
    def verify_host_admission_presentation(self, **values: object) -> bool:
        if (
            values["algorithm"] != "ed25519"
            or values["purpose"] != "dotmac.control.host-admission-presentation.v1"
            or not isinstance(values["public_key_b64"], str)
            or not isinstance(values["public_key_fingerprint"], str)
            or not isinstance(values["canonical_bytes"], bytes)
            or not isinstance(values["signature"], str)
        ):
            return False
        key_text = values["public_key_b64"]
        fingerprint = values["public_key_fingerprint"]
        signature_text = values["signature"]
        try:
            key = base64.urlsafe_b64decode(key_text + "=" * (-len(key_text) % 4))
            signature = base64.urlsafe_b64decode(
                signature_text + "=" * (-len(signature_text) % 4)
            )
        except ValueError:
            return False
        return PublicKeyFingerprintV1.from_public_key_b64(
            key_text
        ).canonical == fingerprint and verify(key, values["canonical_bytes"], signature)


def _presentation(
    *, issued: datetime = _NOW, expires: datetime = _NOW + timedelta(minutes=5)
) -> HostAdmissionPresentationV1:
    statement = HostAdmissionPresentationStatementV1(
        presentation_id="presentation-1",
        key_id="key-1",
        dispatch_id="signed-dispatch-1",
        candidate_attestation_envelope_digest="sha256:" + "2" * 64,
        installed_attestation_envelope_digest="sha256:" + "3" * 64,
        issued_at=issued,
        expires_at=expires,
    )
    return HostAdmissionPresentationV1(
        statement=statement,
        signature=base64.urlsafe_b64encode(b"signature").decode().rstrip("="),
    )


def test_positive_verifier_and_exact_boundary_are_admitted() -> None:
    presentation = _presentation()
    assert (
        verify_host_admission_presentation(
            presentation,
            verifier=Verifier(),
            algorithm="ed25519",
            public_key_fingerprint=_FINGERPRINT,
            public_key_b64=_KEY_B64,
            now=_NOW,
        )
        is presentation.statement
    )


def test_reference_ed25519_matches_rfc_8032_vector() -> None:
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60"
    )
    expected_public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a" "0ee172f3daa62325af021a68f707511a"
    )
    expected_signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )
    assert public_key(seed) == expected_public
    assert sign(seed, b"") == expected_signature
    assert verify(expected_public, b"", expected_signature)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("dispatch_id", "signed-dispatch-substituted"),
        ("candidate_attestation_envelope_digest", "sha256:" + "4" * 64),
        ("installed_attestation_envelope_digest", "sha256:" + "5" * 64),
    ],
)
def test_two_independent_real_keys_bind_every_evidence_coordinate_field(
    field: str, replacement: str
) -> None:
    seeds = (
        bytes.fromhex("1f" * 32),
        hashlib.sha256(b"independent-host-admission-test-key").digest(),
    )
    verifier = ReferenceEd25519Verifier()
    for index, seed in enumerate(seeds, start=1):
        key = public_key(seed)
        key_text = base64.urlsafe_b64encode(key).decode().rstrip("=")
        fingerprint = PublicKeyFingerprintV1.from_public_key_b64(key_text).canonical
        statement = HostAdmissionPresentationStatementV1(
            presentation_id=f"presentation-{index}",
            key_id=f"key-{index}",
            dispatch_id="signed-dispatch-1",
            candidate_attestation_envelope_digest="sha256:" + "2" * 64,
            installed_attestation_envelope_digest="sha256:" + "3" * 64,
            issued_at=_NOW,
            expires_at=_NOW + timedelta(minutes=5),
        )
        signature = (
            base64.urlsafe_b64encode(sign(seed, statement.canonical_bytes))
            .decode()
            .rstrip("=")
        )
        presentation = HostAdmissionPresentationV1(
            statement=statement, signature=signature
        )
        assert (
            verify_host_admission_presentation(
                presentation,
                verifier=verifier,
                algorithm="ed25519",
                public_key_fingerprint=fingerprint,
                public_key_b64=key_text,
                now=_NOW,
            )
            is statement
        )
        changed_mapping = statement.as_mapping()
        changed_mapping[field] = replacement
        changed = HostAdmissionPresentationV1.parse(
            {"statement": changed_mapping, "signature": signature}
        )
        with pytest.raises(HostAdmissionPresentationRefusedError) as caught:
            verify_host_admission_presentation(
                changed,
                verifier=verifier,
                algorithm="ed25519",
                public_key_fingerprint=fingerprint,
                public_key_b64=key_text,
                now=_NOW,
            )
        assert (
            caught.value.code is HostAdmissionPresentationRefusalCode.SIGNATURE_INVALID
        )


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (
            {"signature": "bad="},
            HostAdmissionPresentationRefusalCode.SIGNATURE_ENCODING,
        ),
        (
            {"statement": {"schema": "wrong"}},
            HostAdmissionPresentationRefusalCode.MALFORMED,
        ),
    ],
)
def test_parse_refuses_noncanonical_or_incomplete_input(
    change: dict[str, object], code: HostAdmissionPresentationRefusalCode
) -> None:
    raw = _presentation().as_mapping()
    raw.update(change)
    with pytest.raises(HostAdmissionPresentationRefusedError) as caught:
        HostAdmissionPresentationV1.parse(raw)
    assert caught.value.code is code


@pytest.mark.parametrize("version", [True, 1.0])
def test_parse_requires_an_exact_integer_schema_version(version: object) -> None:
    raw = _presentation().as_mapping()
    statement = dict(raw["statement"])
    statement["version"] = version
    raw["statement"] = statement
    with pytest.raises(HostAdmissionPresentationRefusedError) as caught:
        HostAdmissionPresentationV1.parse(raw)
    assert caught.value.code is HostAdmissionPresentationRefusalCode.UNSUPPORTED_VERSION


@pytest.mark.parametrize(
    ("issued", "expires", "now", "code"),
    [
        (
            _NOW + timedelta(seconds=1),
            _NOW + timedelta(minutes=1),
            _NOW,
            HostAdmissionPresentationRefusalCode.NOT_YET_VALID,
        ),
        (
            _NOW - timedelta(minutes=5),
            _NOW,
            _NOW,
            HostAdmissionPresentationRefusalCode.EXPIRED,
        ),
        (
            _NOW,
            _NOW + timedelta(minutes=5, seconds=1),
            _NOW,
            HostAdmissionPresentationRefusalCode.LIFETIME_INVALID,
        ),
    ],
)
def test_liveness_refusals_are_exact(
    issued: datetime,
    expires: datetime,
    now: datetime,
    code: HostAdmissionPresentationRefusalCode,
) -> None:
    with pytest.raises(HostAdmissionPresentationRefusedError) as caught:
        verify_host_admission_presentation(
            _presentation(issued=issued, expires=expires),
            verifier=Verifier(),
            algorithm="ed25519",
            public_key_fingerprint=_FINGERPRINT,
            public_key_b64=_KEY_B64,
            now=now,
        )
    assert caught.value.code is code


def test_invalid_signature_refuses() -> None:
    with pytest.raises(HostAdmissionPresentationRefusedError) as caught:
        verify_host_admission_presentation(
            _presentation(),
            verifier=Verifier(False),
            algorithm="ed25519",
            public_key_fingerprint=_FINGERPRINT,
            now=_NOW,
            public_key_b64=_KEY_B64,
        )
    assert caught.value.code is HostAdmissionPresentationRefusalCode.SIGNATURE_INVALID


@pytest.mark.parametrize("field", ["purpose", "audience"])
def test_purpose_and_audience_are_not_caller_selectable(field: str) -> None:
    raw = _presentation().as_mapping()
    statement = dict(raw["statement"])
    statement[field] = "wrong"
    raw["statement"] = statement
    with pytest.raises(HostAdmissionPresentationRefusedError):
        HostAdmissionPresentationV1.parse(raw)


def test_composite_fingerprint_is_fixed_and_coordinate_bound() -> None:
    values = {
        "dispatch_envelope_digest": "sha256:" + "1" * 64,
        "candidate_attestation_envelope_digest": "sha256:" + "2" * 64,
        "installed_attestation_envelope_digest": "sha256:" + "3" * 64,
    }
    assert (
        admission_consumption_fingerprint(**values)
        == "5ca5893ad04ef5d18fc8a18ca90f1d1d2ebd84f98d6c9d7a9bcc9f2c2198e404"
    )
    assert admission_consumption_fingerprint(
        **(values | {"installed_attestation_envelope_digest": "sha256:" + "4" * 64})
    ) != admission_consumption_fingerprint(**values)


def test_foundation_key_conversion_preserves_exact_bytes() -> None:
    assert (
        foundation_public_key_base64(public_key_b64=_KEY_B64, fingerprint=_FINGERPRINT)
        == base64.b64encode(_KEY).decode()
    )
    with pytest.raises(HostAdmissionPresentationRefusedError):
        foundation_public_key_base64(
            public_key_b64=_KEY_B64, fingerprint="sha256:" + "0" * 64
        )
