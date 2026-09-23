"""Control's real issuance boundary for the rehearsal-issuer contract.

Scoped to what does not require a live database: request-shape refusals (all
fire before the database is ever touched), the protected-composition
install-once contract, and a REGRESSION test for the exact bypass class this
module exists to close (no public function here accepts a verifier as a
per-call parameter). PostgreSQL concurrency and raw-DB-constraint tests live
in `tests/test_deployment_control_platform_isolation.py`.
"""

from __future__ import annotations

import inspect
from collections.abc import Generator
from datetime import timedelta

import pytest

import dotmac_deployment_control.rehearsal_issuer_issuance as issuance
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    _STATEMENT_KEYS as _C1_STATEMENT_KEYS,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    REHEARSAL_ISSUER_PURPOSE,
    RehearsalIssuerAuthorizationSignature,
    RehearsalIssuerAuthorizationSignerIdentity,
)
from dotmac_deployment_control.rehearsal_issuer_issuance import (
    RehearsalIssuerIssuanceRefusalCode,
    RehearsalIssuerIssuanceRefusedError,
    install_rehearsal_issuer_security,
    issue_rehearsal_issuer_authorization_for_plan,
    rehearsal_issuer_standing_for,
    revoke_rehearsal_issuer_authorization,
    stage_rehearsal_issuer_consumption,
)


class _Signer:
    @property
    def rehearsal_issuer_identity(self) -> RehearsalIssuerAuthorizationSignerIdentity:
        return RehearsalIssuerAuthorizationSignerIdentity("k-issuer", "ed25519", "fp")

    def sign_rehearsal_issuer_authorization(
        self, canonical_bytes: bytes
    ) -> RehearsalIssuerAuthorizationSignature:
        return RehearsalIssuerAuthorizationSignature(
            "k-issuer", "ed25519", REHEARSAL_ISSUER_PURPOSE, "fp", "SIG"
        )


class _AuthorizationVerifier:
    def verify_rehearsal_issuer_authorization(self, **kwargs: object) -> bool:
        return kwargs["signature"] == "SIG"


class _HarnessVerifier:
    def verify_rehearsal_harness_evidence(self, **kwargs: object) -> bool:
        return True


@pytest.fixture(autouse=True)
def _reset_security() -> Generator[None, None, None]:
    """Every test starts and ends with no installed security."""
    issuance._reset_rehearsal_issuer_security_for_tests()
    yield
    issuance._reset_rehearsal_issuer_security_for_tests()


# ── Request-shape refusals (fire before the database is ever touched) ──────


def test_forbidden_fields_matches_c1_statement_keys() -> None:
    """SENSITIVITY: this constant must be DERIVED from C1's own `_STATEMENT_KEYS`,
    never hand-copied -- a hand-copy is exactly the drift risk this correction
    exists to close."""
    assert issuance._FORBIDDEN_REQUEST_FIELDS == _C1_STATEMENT_KEYS | {
        "schema",
        "version",
    }
    # Non-vacuity: the set is large and contains fields a naive caller might
    # plausibly try to supply.
    assert len(issuance._FORBIDDEN_REQUEST_FIELDS) >= 20
    assert "authorization_id" in issuance._FORBIDDEN_REQUEST_FIELDS
    assert "immutable_reference" in issuance._FORBIDDEN_REQUEST_FIELDS


@pytest.mark.parametrize(
    "forbidden_field",
    sorted(issuance._FORBIDDEN_REQUEST_FIELDS),
)
def test_every_forbidden_field_is_refused_by_name(forbidden_field: str) -> None:
    request = {
        "command_id": "cmd-1",
        "plan_id": "11111111-1111-1111-1111-111111111111",
        forbidden_field: "anything",
    }
    with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
        issue_rehearsal_issuer_authorization_for_plan(
            db=None,  # never reached: the refusal fires before any DB use
            request=request,
            harness_evidence_document=None,
        )
    assert refused.value.code == RehearsalIssuerIssuanceRefusalCode.MALFORMED
    assert forbidden_field in str(refused.value)


def test_an_unexpected_non_forbidden_field_is_also_refused() -> None:
    request = {
        "command_id": "cmd-1",
        "plan_id": "11111111-1111-1111-1111-111111111111",
        "some_other_field": "x",
    }
    with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
        issue_rehearsal_issuer_authorization_for_plan(
            db=None, request=request, harness_evidence_document=None
        )
    assert refused.value.code == RehearsalIssuerIssuanceRefusalCode.MALFORMED


def test_a_missing_required_field_is_refused() -> None:
    with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
        issue_rehearsal_issuer_authorization_for_plan(
            db=None, request={"command_id": "cmd-1"}, harness_evidence_document=None
        )
    assert refused.value.code == RehearsalIssuerIssuanceRefusalCode.MALFORMED


def test_actor_ref_alone_is_not_forbidden_or_unexpected() -> None:
    """`actor_ref` is optional but ALLOWED -- only security-not-installed
    should fire past the shape checks."""
    request = {
        "command_id": "cmd-1",
        "plan_id": "11111111-1111-1111-1111-111111111111",
        "actor_ref": "admin-1",
    }
    with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
        issue_rehearsal_issuer_authorization_for_plan(
            db=None, request=request, harness_evidence_document=None
        )
    assert (
        refused.value.code
        == RehearsalIssuerIssuanceRefusalCode.SECURITY_NOT_INSTALLED
    )


# ── Protected composition ───────────────────────────────────────────────────


def test_uninstalled_security_refuses_before_evidence_or_database() -> None:
    request = {
        "command_id": "cmd-1",
        "plan_id": "11111111-1111-1111-1111-111111111111",
    }
    with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
        issue_rehearsal_issuer_authorization_for_plan(
            db=None, request=request, harness_evidence_document=None
        )
    assert (
        refused.value.code
        == RehearsalIssuerIssuanceRefusalCode.SECURITY_NOT_INSTALLED
    )


def test_a_second_install_raises() -> None:
    install_rehearsal_issuer_security(
        signer=_Signer(),
        authorization_verifier=_AuthorizationVerifier(),
        harness_verifier=_HarnessVerifier(),
        authorization_ttl=timedelta(hours=1),
    )
    with pytest.raises(RuntimeError, match="already installed"):
        install_rehearsal_issuer_security(
            signer=_Signer(),
            authorization_verifier=_AuthorizationVerifier(),
            harness_verifier=_HarnessVerifier(),
            authorization_ttl=timedelta(hours=1),
        )


@pytest.mark.parametrize(
    "ttl",
    [timedelta(0), timedelta(seconds=-1), timedelta(hours=24, seconds=1)],
)
def test_install_refuses_a_non_positive_or_excessive_ttl(ttl: timedelta) -> None:
    with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
        install_rehearsal_issuer_security(
            signer=_Signer(),
            authorization_verifier=_AuthorizationVerifier(),
            harness_verifier=_HarnessVerifier(),
            authorization_ttl=ttl,
        )
    assert refused.value.code == RehearsalIssuerIssuanceRefusalCode.MALFORMED


def test_install_accepts_the_boundary_ttl_of_exactly_24_hours() -> None:
    install_rehearsal_issuer_security(
        signer=_Signer(),
        authorization_verifier=_AuthorizationVerifier(),
        harness_verifier=_HarnessVerifier(),
        authorization_ttl=timedelta(hours=24),
    )


def test_install_refuses_a_non_conforming_signer() -> None:
    class _NotASigner:
        pass

    with pytest.raises(TypeError):
        install_rehearsal_issuer_security(
            signer=_NotASigner(),
            authorization_verifier=_AuthorizationVerifier(),
            harness_verifier=_HarnessVerifier(),
            authorization_ttl=timedelta(hours=1),
        )


# ── Regression: no per-call verifier parameter anywhere in this module ─────


def test_no_public_function_accepts_a_verifier_as_a_per_call_parameter() -> None:
    """THE regression test for the exact bypass class this whole correction
    exists to close: a per-call verifier parameter would let a caller pass a
    permissive stub and the type would never know. `install_rehearsal_issuer_security`
    is the ONE place a verifier is ever supplied, and only at startup."""
    guarded_functions = [
        issue_rehearsal_issuer_authorization_for_plan,
        revoke_rehearsal_issuer_authorization,
        stage_rehearsal_issuer_consumption,
        rehearsal_issuer_standing_for,
    ]
    for fn in guarded_functions:
        parameters = inspect.signature(fn).parameters
        offenders = [name for name in parameters if "verifier" in name.lower()]
        assert offenders == [], (fn.__name__, offenders)

    # install_rehearsal_issuer_security is the sole, deliberate exception.
    install_parameters = inspect.signature(install_rehearsal_issuer_security).parameters
    assert "authorization_verifier" in install_parameters
    assert "harness_verifier" in install_parameters


def test_a_near_miss_sensitivity_check() -> None:
    """SENSITIVITY for the regression test above: plant a near-miss (a
    parameter that mentions 'verify' but not 'verifier') and confirm the
    detector's own substring match is exercised deliberately, not vacuous."""

    def _fn_with_verify_param(*, verify_mode: bool) -> None:  # pragma: no cover
        del verify_mode

    parameters = inspect.signature(_fn_with_verify_param).parameters
    offenders = [name for name in parameters if "verifier" in name.lower()]
    assert offenders == []  # "verify_mode" does not contain "verifier"

    def _fn_with_real_offender(*, my_verifier: object) -> None:  # pragma: no cover
        del my_verifier

    offenders = [
        name
        for name in inspect.signature(_fn_with_real_offender).parameters
        if "verifier" in name.lower()
    ]
    assert offenders == ["my_verifier"]
