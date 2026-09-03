"""The signed dispatch binds one concrete attempt to one authorization."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

import dotmac_deployment_control.dispatch_envelope as dispatch_contract
from dotmac_deployment_control import (
    AuthorizationEnvelopeDigestV1,
    DispatchEnvelopeRefusalCode,
    DispatchEnvelopeRefusedError,
    DispatchEnvelopeV1,
    issue_authorization_envelope,
    issue_dispatch_envelope,
    verify_dispatch_envelope,
)
from tests.authorization_support import (
    AUTHORIZATION_PUBLIC_KEY_FINGERPRINT,
    SIGNER,
    VERIFIER,
)
from tests.dispatch_support import TestDispatchSigner, TestDispatchVerifier

_NOW = datetime(2026, 9, 3, 10, 0, tzinfo=UTC)
_PLAN = "sha256:" + "1a" * 32
_DESCRIPTOR = "sha256:" + "2b" * 32
_EXECUTION = "sha256:" + "3c" * 32


@pytest.fixture(autouse=True)
def _installed_successor_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dispatch_contract, "_distribution_version", lambda _name: "0.1.0a11"
    )


def _authorization(*, plan_id: str = "plan-1"):
    return issue_authorization_envelope(
        {
            "authorization_id": "authorization-1",
            "execution_sequence": 7,
            "rollout_ref": "rollout-1",
            "plan_id": plan_id,
            "target_id": "target-id-1",
            "target_ref": "target-1",
            "product_code": "dotmac_sub",
            "environment": "production",
            "operation": "deploy",
            "release_ref": "dotmac_sub@7.187.1",
            "authorized_images": [],
            "plan_digest": _PLAN,
            "descriptor_digest": _DESCRIPTOR,
            "execution_plan_digest": _EXECUTION,
            "approval_policy_code": "deployment.production",
            "approval_policy_version": 4,
            "approval_decision_ref": "decision-1",
            "approval_decision_status": "granted",
            "approved_at": _NOW - timedelta(minutes=2),
            "issued_at": _NOW - timedelta(minutes=1),
            "expires_at": _NOW + timedelta(minutes=30),
        },
        signer=SIGNER,
    )


def _issued(*, signer=None):
    return issue_dispatch_envelope(
        authorization_envelope=_authorization(),
        dispatch_id="dispatch-1",
        attempt_no=3,
        issued_at=_NOW,
        signer=signer or TestDispatchSigner(),
    )


def test_the_dispatch_binds_the_exact_authorization_and_attempt() -> None:
    authorization = _authorization()
    envelope = issue_dispatch_envelope(
        authorization_envelope=authorization,
        dispatch_id="dispatch-1",
        attempt_no=3,
        issued_at=_NOW,
        signer=TestDispatchSigner(),
    )

    verified = verify_dispatch_envelope(
        envelope,
        authorization_envelope=authorization,
        authorization_verifier=VERIFIER,
        dispatch_verifier=TestDispatchVerifier(),
        at=_NOW,
    )

    assert verified == envelope
    assert verified.statement.attempt_no == 3
    assert verified.statement.execution_sequence == 7
    assert verified.statement.control_version == "0.1.0a11"
    assert verified.statement.authorization_envelope_digest == (
        AuthorizationEnvelopeDigestV1.over_bytes(
            authorization.canonical_bytes
        ).canonical
    )


def test_changing_only_attempt_no_invalidates_the_signature() -> None:
    authorization = _authorization()
    payload = copy.deepcopy(
        issue_dispatch_envelope(
            authorization_envelope=authorization,
            dispatch_id="dispatch-1",
            attempt_no=3,
            issued_at=_NOW,
            signer=TestDispatchSigner(),
        ).as_mapping()
    )
    payload["statement"]["attempt_no"] = 4

    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        verify_dispatch_envelope(
            payload,
            authorization_envelope=authorization,
            authorization_verifier=VERIFIER,
            dispatch_verifier=TestDispatchVerifier(),
            at=_NOW,
        )

    assert caught.value.code is DispatchEnvelopeRefusalCode.SIGNATURE_INVALID


def test_a_different_valid_authorization_cannot_satisfy_the_dispatch() -> None:
    envelope = _issued()

    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        verify_dispatch_envelope(
            envelope,
            authorization_envelope=_authorization(plan_id="plan-2"),
            authorization_verifier=VERIFIER,
            dispatch_verifier=TestDispatchVerifier(),
            at=_NOW,
        )

    assert caught.value.code is DispatchEnvelopeRefusalCode.AUTHORIZATION_MISMATCH


def test_dispatch_cannot_be_issued_outside_the_authorization_lifetime() -> None:
    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        issue_dispatch_envelope(
            authorization_envelope=_authorization(),
            dispatch_id="dispatch-1",
            attempt_no=3,
            issued_at=_NOW + timedelta(minutes=30),
            signer=TestDispatchSigner(),
        )

    assert caught.value.code is DispatchEnvelopeRefusalCode.AUTHORIZATION_MISMATCH


def test_dispatch_is_not_accepted_before_its_signed_issued_at() -> None:
    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        verify_dispatch_envelope(
            _issued(),
            authorization_envelope=_authorization(),
            authorization_verifier=VERIFIER,
            dispatch_verifier=TestDispatchVerifier(),
            at=_NOW - timedelta(seconds=1),
        )

    assert caught.value.code is DispatchEnvelopeRefusalCode.NOT_YET_VALID


def test_a_verifier_that_refuses_everything_cannot_pass_the_positive_case() -> None:
    class RefusingVerifier:
        def verify_dispatch(self, **_fields: object) -> bool:
            return False

    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        verify_dispatch_envelope(
            _issued(),
            authorization_envelope=_authorization(),
            authorization_verifier=VERIFIER,
            dispatch_verifier=RefusingVerifier(),
            at=_NOW,
        )

    assert caught.value.code is DispatchEnvelopeRefusalCode.SIGNATURE_INVALID


def test_authorization_signer_cannot_cross_into_dispatch_purpose() -> None:
    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        _issued(signer=SIGNER)

    assert caught.value.code is DispatchEnvelopeRefusalCode.PURPOSE_MISMATCH


def test_authorization_physical_key_cannot_hide_behind_dispatch_protocol() -> None:
    signer = TestDispatchSigner(
        public_key_fingerprint=AUTHORIZATION_PUBLIC_KEY_FINGERPRINT
    )

    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        _issued(signer=signer)

    assert caught.value.code is DispatchEnvelopeRefusalCode.SIGNER_PURPOSE_REUSED
    assert signer.calls == 0


def test_verifier_refuses_a_signed_document_that_reuses_authorization_key() -> None:
    payload = copy.deepcopy(_issued().as_mapping())
    payload["statement"]["public_key_fingerprint"] = (
        AUTHORIZATION_PUBLIC_KEY_FINGERPRINT
    )
    payload["signature"] = "signature-accepted-by-the-injected-test-verifier"

    class AcceptingDispatchVerifier:
        def verify_dispatch(self, **_fields: object) -> bool:
            return True

    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        verify_dispatch_envelope(
            payload,
            authorization_envelope=_authorization(),
            authorization_verifier=VERIFIER,
            dispatch_verifier=AcceptingDispatchVerifier(),
            at=_NOW,
        )

    assert caught.value.code is DispatchEnvelopeRefusalCode.SIGNER_PURPOSE_REUSED


def test_authorization_verifier_cannot_cross_into_dispatch_purpose() -> None:
    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        verify_dispatch_envelope(
            _issued(),
            authorization_envelope=_authorization(),
            authorization_verifier=VERIFIER,
            dispatch_verifier=VERIFIER,
            at=_NOW,
        )

    assert caught.value.code is DispatchEnvelopeRefusalCode.PURPOSE_MISMATCH


def test_exact_parse_refuses_an_unknown_signed_field() -> None:
    payload = copy.deepcopy(_issued().as_mapping())
    payload["statement"]["transport"] = "ssh"

    with pytest.raises(DispatchEnvelopeRefusedError) as caught:
        DispatchEnvelopeV1.parse(payload)

    assert caught.value.code is DispatchEnvelopeRefusalCode.MALFORMED
