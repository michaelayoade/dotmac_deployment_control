"""Control's real issuance boundary for the rehearsal-issuer contract.

Scoped to what does not require a LIVE (Postgres) database: request-shape
refusals (all fire before the database is ever touched), the
protected-composition install-once contract, a REGRESSION test for the exact
bypass class this module exists to close (no public function here accepts a
verifier as a per-call parameter), and a set of in-memory-SQLite-backed
boundary tests (mirroring `test_execution_plan_binding.py`'s own `db`
fixture) proving the five gaps closed after an independent review of commit
range `a41d142..e410c66`: (1) the ledger row, not the presented statement's
own claimed plan/target, is the sole source of truth for standing; (2) the
two mutating functions no longer accept a caller-controlled clock; (3)
consumption evidence must be fresh, not a replay of issuance's own evidence;
(4) issuance genuinely re-verifies its own freshly minted envelope through
the installed verifier rather than comparing a statement against itself; and
(5) a suspended/decommissioned target is refused at both issuance and
consumption. PostgreSQL concurrency and raw-DB-constraint tests live in
`tests/test_deployment_control_platform_isolation.py`.
"""

from __future__ import annotations

import base64
import inspect
import json
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.rehearsal_issuer_issuance as issuance
import dotmac_deployment_control.service as control_service
from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    DesiredDeployment,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    SetDesiredStateCommand,
    TargetTransitionCommand,
    approve_plan,
    find_approved_plan,
    module,
    propose_plan,
    register_target,
    request_rollout,
    set_desired_state,
    suspend_target,
)
from dotmac_deployment_control.models import (
    DeploymentPlan,
    RehearsalIssuerAuthorizationRecord,
    Rollout,
    RolloutAttempt,
)
from dotmac_deployment_control.ports import PlanRefusedError, TransitionRefusedError
from dotmac_deployment_control.rehearsal_harness_evidence import (
    REHEARSAL_HARNESS_EVIDENCE_SCHEMA,
    REHEARSAL_HARNESS_EVIDENCE_VERSION,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    _STATEMENT_KEYS as _C1_STATEMENT_KEYS,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    REHEARSAL_ISSUER_PURPOSE,
    REHEARSAL_ONLY_ENVIRONMENT,
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
from dotmac_deployment_control.service import (
    _DispatchConsumptionRefusedError,
    _ExpectedDispatchTarget,
    _stage_dispatch_consumption,
    _stored_dispatch_coordinate,
    _verified_rollout_envelope,
    dispatch_attempt,
)
from tests.authorization_support import SIGNER, VERIFIER
from tests.dispatch_support import DISPATCH_SIGNER


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
        refused.value.code == RehearsalIssuerIssuanceRefusalCode.SECURITY_NOT_INSTALLED
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
        refused.value.code == RehearsalIssuerIssuanceRefusalCode.SECURITY_NOT_INSTALLED
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


# ── In-memory-SQLite boundary tests (fixes 1, 3, 4, 5) ──────────────────────
#
# Mirrors `test_execution_plan_binding.py`'s own `db` fixture shape. These do
# NOT require a live Postgres -- only a real, migrated `Session` so the
# module under test can actually query/lock/insert a ledger row, which is
# exactly the boundary each of these five gaps lives on.

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_DESCRIPTOR = "sha256:" + "3c" * 32
_EXECUTION_PLAN = "sha256:" + "1a" * 32


class _FailingAuthorizationVerifier:
    """Refuses EVERY signature -- a genuine negative control. If issuance's
    self-verification were still the old dead metadata comparison, installing
    this verifier would change nothing, because that comparison never calls
    a verifier at all. Only a REAL self-verification call can be made to fail
    by swapping the installed verifier out from under it."""

    def verify_rehearsal_issuer_authorization(self, **kwargs: object) -> bool:
        return False


@pytest.fixture
def db() -> Generator[Session, None, None]:
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _emit_begin(connection):  # type: ignore[no-untyped-def]
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[
            table
            for table in Base.metadata.tables.values()
            if table.schema == "mod_deploy"
            or table.name
            in {
                "platform_idempotency_records",
                "platform_audit_events",
                "platform_admins",
                "platform_outbox_events",
            }
        ],
    )
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


def _cmd() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _seed_rehearsal_target_and_plan(
    db: Session,
    suffix: str,
    *,
    purpose: str = "rehearsal_issuer_operation",
    proposal_command_id: str | None = None,
    environment: str = REHEARSAL_ONLY_ENVIRONMENT,
    operation: str = "deploy",
):  # type: ignore[no-untyped-def]
    """A REHEARSAL-environment, ACTIVE target with one standing, deploy
    approval -- committed so it survives a later rollback of unrelated work."""
    target_ref = f"rehearsal-issuer-target-{suffix}"
    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref=target_ref,
            subject_ref=f"subject-{suffix}",
            product_code="dotmac_sub",
            environment=environment,
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=target.id,
            desired=DesiredDeployment(
                release_ref="dotmac_sub@1", spec={"replicas": 1}, images=[]
            ),
        ),
    )
    plan = propose_plan(
        db,
        ProposePlanCommand(
            command_id=proposal_command_id or _cmd(),
            target_id=target.id,
            operation=operation,
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            purpose=purpose,
            requires_approval=True,
            approval_policy_code="deployment.production",
            approval_policy_version=1,
        ),
    )
    plan = approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_cmd(),
            plan_id=plan.id,
            evidence=ApprovalEvidence(
                policy_code="deployment.production",
                policy_version=1,
                decision_ref=f"decision-{suffix}",
                content_digest=plan.plan_digest or "",
                decided_at=_NOW,
                operation=operation,
                execution_plan_digest=_EXECUTION_PLAN,
                decision_status="granted",
            ),
        ),
    )
    db.commit()
    return target, plan


def test_issuer_plan_can_be_approved_but_cannot_be_found_as_execution_authority(
    db: Session,
) -> None:
    target, plan = _seed_rehearsal_target_and_plan(db, uuid.uuid4().hex)
    assert plan.status == "approved"
    assert plan.approval_decision_status == "granted"
    assert plan.purpose == "rehearsal_issuer_operation"
    assert plan.snapshot["plan_purpose"] == plan.purpose
    lookup = find_approved_plan(db, plan_digest=plan.plan_digest or "")
    assert not lookup.is_authorized
    assert lookup.refusal is not None
    assert lookup.refusal.code.value == "wrong_plan_purpose"

    with pytest.raises(PlanRefusedError, match="rehearsal-issuer"):
        request_rollout(
            db,
            RequestRolloutCommand(
                command_id=_cmd(),
                rollout_ref=f"issuer-rollout-{uuid.uuid4().hex}",
                plan_id=plan.id,
                authorization_expires_at=_NOW + timedelta(hours=1),
            ),
        )
    assert target.environment == REHEARSAL_ONLY_ENVIRONMENT


def test_foundation_plan_is_refused_at_issuer_issuance_even_on_rehearsal_target(
    db: Session,
) -> None:
    suffix = uuid.uuid4().hex
    target, plan = _seed_rehearsal_target_and_plan(
        db, suffix, purpose="foundation_execution"
    )
    _install_security()
    evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=target.target_ref,
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            issue_rehearsal_issuer_authorization_for_plan(
                db,
                {"command_id": _cmd(), "plan_id": str(plan.id)},
                harness_evidence_document=evidence,
            )
    assert refused.value.code == RehearsalIssuerIssuanceRefusalCode.WRONG_PLAN_PURPOSE


def test_legacy_purpose_is_refused_on_issuance_replay_standing_and_consumption(
    db: Session,
) -> None:
    suffix = uuid.uuid4().hex
    target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    _install_security()
    command_id = _cmd()
    issuance_evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=target.target_ref,
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        envelope = issue_rehearsal_issuer_authorization_for_plan(
            db,
            {"command_id": command_id, "plan_id": str(plan.id)},
            harness_evidence_document=issuance_evidence,
        )
    db.commit()
    stored = db.get(DeploymentPlan, plan.id)
    assert stored is not None
    legacy_snapshot = dict(stored.snapshot)
    legacy_snapshot.pop("plan_purpose")
    stored.snapshot = legacy_snapshot
    stored.purpose = "foundation_execution"
    db.commit()  # SQLite simulates a row written before the migration trigger.

    later = _NOW + timedelta(minutes=1)
    fresh_evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=target.target_ref,
        issued_at=later,
        valid_until=later + timedelta(minutes=30),
        nonce="fresh",
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: later)
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as replay:
            issue_rehearsal_issuer_authorization_for_plan(
                db,
                {"command_id": command_id, "plan_id": str(plan.id)},
                harness_evidence_document=issuance_evidence,
            )
        assert (
            replay.value.code == RehearsalIssuerIssuanceRefusalCode.WRONG_PLAN_PURPOSE
        )
        db.rollback()
        standing = rehearsal_issuer_standing_for(
            db,
            authorization_document=envelope.as_mapping(),
            harness_evidence_document=fresh_evidence,
            now=later,
        )
        assert not standing.authorizes
        db.rollback()
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as consumption:
            stage_rehearsal_issuer_consumption(
                db,
                authorization_document=envelope.as_mapping(),
                harness_evidence_document=fresh_evidence,
            )
        assert (
            consumption.value.code
            == RehearsalIssuerIssuanceRefusalCode.WRONG_PLAN_PURPOSE
        )


@pytest.mark.parametrize(
    ("environment", "operation", "expected"),
    [
        (
            "production",
            "deploy",
            RehearsalIssuerIssuanceRefusalCode.NOT_A_REHEARSAL_TARGET,
        ),
        (
            REHEARSAL_ONLY_ENVIRONMENT,
            "rollback",
            RehearsalIssuerIssuanceRefusalCode.WRONG_AUTHORIZED_OPERATION,
        ),
    ],
)
def test_issuer_purpose_still_requires_rehearsal_target_and_deploy_operation(
    db: Session,
    environment: str,
    operation: str,
    expected: RehearsalIssuerIssuanceRefusalCode,
) -> None:
    suffix = uuid.uuid4().hex
    target, plan = _seed_rehearsal_target_and_plan(
        db, suffix, environment=environment, operation=operation
    )
    _install_security()
    evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=target.target_ref,
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            issue_rehearsal_issuer_authorization_for_plan(
                db,
                {"command_id": _cmd(), "plan_id": str(plan.id)},
                harness_evidence_document=evidence,
            )
    assert refused.value.code == expected


def test_planted_issuer_plan_is_refused_at_each_lower_execution_boundary(
    db: Session,
) -> None:
    """The lower guards fire even if a rollout and attempt were planted."""
    target, plan = _seed_rehearsal_target_and_plan(db, uuid.uuid4().hex)
    rollout = Rollout(
        id=uuid.uuid4(),
        rollout_ref=f"planted-{uuid.uuid4().hex}",
        target_id=target.id,
        plan_id=plan.id,
        status="requested",
        execution_sequence=1,
        record_version=1,
    )
    attempt = RolloutAttempt(
        id=uuid.uuid4(),
        rollout_id=rollout.id,
        attempt_no=1,
        outcome="pending",
        dispatch_envelope={},
    )
    db.add_all((rollout, attempt))
    db.flush()
    stored = db.get(DeploymentPlan, plan.id)
    assert stored is not None

    with pytest.raises(PlanRefusedError, match="rehearsal-issuer"):
        _verified_rollout_envelope(rollout, stored, target, verifier=None)
    with pytest.raises(PlanRefusedError, match="rehearsal-issuer"):
        _stored_dispatch_coordinate(db, attempt.id)
    with pytest.raises(PlanRefusedError, match="rehearsal-issuer"):
        dispatch_attempt(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            dispatch_signer=None,  # type: ignore[arg-type] -- guard fires first
        )
    with pytest.raises(_DispatchConsumptionRefusedError, match="non-Foundation"):
        _stage_dispatch_consumption(
            db,
            attempt_id=attempt.id,
            expected_target=_ExpectedDispatchTarget(target.id, target.target_ref),
            candidate_attestation_envelope_digest="sha256:" + "a" * 64,
            installed_attestation_envelope_digest="sha256:" + "b" * 64,
        )


def test_foundation_plan_still_rolls_out_and_dispatches(db: Session) -> None:
    _target, plan = _seed_rehearsal_target_and_plan(
        db, uuid.uuid4().hex, purpose="foundation_execution"
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(control_service, "_control_now", lambda: _NOW)
        rollout = request_rollout(
            db,
            RequestRolloutCommand(
                command_id=_cmd(),
                rollout_ref=f"foundation-{uuid.uuid4().hex}",
                plan_id=plan.id,
                authorization_expires_at=_NOW + timedelta(hours=1),
            ),
            signer=SIGNER,
        )
        intent = dispatch_attempt(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
    assert intent.operation == "deploy"
    assert intent.execution_plan_digest == _EXECUTION_PLAN


def test_rollout_reference_and_command_replay_cannot_substitute_issuer_plan(
    db: Session,
) -> None:
    _target, foundation = _seed_rehearsal_target_and_plan(
        db, uuid.uuid4().hex, purpose="foundation_execution"
    )
    _other_target, issuer = _seed_rehearsal_target_and_plan(db, uuid.uuid4().hex)
    command_id = _cmd()
    rollout_ref = f"foundation-{uuid.uuid4().hex}"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(control_service, "_control_now", lambda: _NOW)
        request_rollout(
            db,
            RequestRolloutCommand(
                command_id=command_id,
                rollout_ref=rollout_ref,
                plan_id=foundation.id,
                authorization_expires_at=_NOW + timedelta(hours=1),
            ),
            signer=SIGNER,
        )
        with pytest.raises(TransitionRefusedError, match="another frozen plan"):
            request_rollout(
                db,
                RequestRolloutCommand(
                    command_id=_cmd(),
                    rollout_ref=rollout_ref,
                    plan_id=issuer.id,
                    authorization_expires_at=_NOW + timedelta(hours=1),
                ),
                signer=SIGNER,
            )
        with pytest.raises(TransitionRefusedError, match="replay resolved another"):
            request_rollout(
                db,
                RequestRolloutCommand(
                    command_id=command_id,
                    rollout_ref=f"other-{uuid.uuid4().hex}",
                    plan_id=issuer.id,
                    authorization_expires_at=_NOW + timedelta(hours=1),
                ),
                signer=SIGNER,
            )


def test_proposal_replay_cannot_change_the_frozen_purpose(db: Session) -> None:
    proposal_command_id = _cmd()
    target, plan = _seed_rehearsal_target_and_plan(
        db, uuid.uuid4().hex, proposal_command_id=proposal_command_id
    )
    with pytest.raises(PlanRefusedError, match="replay.*another purpose"):
        propose_plan(
            db,
            ProposePlanCommand(
                command_id=proposal_command_id,
                target_id=target.id,
                operation="deploy",
                descriptor_digest=_DESCRIPTOR,
                execution_plan_digest=_EXECUTION_PLAN,
                purpose="foundation_execution",
                approval_policy_code="deployment.production",
                approval_policy_version=1,
            ),
        )
    assert db.get(DeploymentPlan, plan.id).purpose == "rehearsal_issuer_operation"


def test_snapshot_purpose_substitution_is_refused(db: Session) -> None:
    _target, plan = _seed_rehearsal_target_and_plan(db, uuid.uuid4().hex)
    row = db.get(DeploymentPlan, plan.id)
    assert row is not None
    row.purpose = "foundation_execution"
    db.flush()  # SQLite has no migration trigger; the read guard still refuses.
    with pytest.raises(PlanRefusedError, match="frozen snapshot purpose"):
        control_service._frozen_plan_purpose(row)


def test_historical_foundation_snapshot_without_purpose_remains_readable(
    db: Session,
) -> None:
    _target, plan = _seed_rehearsal_target_and_plan(
        db, uuid.uuid4().hex, purpose="foundation_execution"
    )
    row = db.get(DeploymentPlan, plan.id)
    assert row is not None
    snapshot = dict(row.snapshot)
    snapshot.pop("plan_purpose")
    row.snapshot = snapshot
    row.plan_digest = control_service.plan_digest_of(snapshot).canonical
    db.flush()
    assert control_service._frozen_plan_purpose(row).value == "foundation_execution"
    assert control_service.get_plan(db, plan.id).purpose == "foundation_execution"


def test_unknown_and_approval_exempt_issuer_purposes_are_refused() -> None:
    fields = {
        "command_id": _cmd(),
        "target_id": uuid.uuid4(),
        "operation": "deploy",
        "descriptor_digest": _DESCRIPTOR,
        "execution_plan_digest": _EXECUTION_PLAN,
    }
    with pytest.raises(TypeError, match="purpose"):
        ProposePlanCommand(**fields)  # type: ignore[arg-type]
    with pytest.raises(PlanRefusedError, match="unknown deployment plan purpose"):
        ProposePlanCommand(**fields, purpose="other")
    with pytest.raises(PlanRefusedError, match="requires standing approval"):
        ProposePlanCommand(
            **fields, purpose="rehearsal_issuer_operation", requires_approval=False
        )


def _harness_evidence(
    *,
    lease_id: str,
    controller_fingerprint: str,
    target_ref: str,
    issued_at: datetime,
    valid_until: datetime,
    nonce: str = "",
) -> dict[str, object]:
    document = {
        "schema": REHEARSAL_HARNESS_EVIDENCE_SCHEMA,
        "version": REHEARSAL_HARNESS_EVIDENCE_VERSION,
        "lease_id": lease_id,
        "controller_fingerprint": controller_fingerprint,
        "target_ref": target_ref,
        "environment": REHEARSAL_ONLY_ENVIRONMENT,
        "issued_at": issued_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "valid_until": valid_until.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        "canonical_bytes": base64.b64encode(canonical).decode("ascii"),
        "signature": {
            "key_id": "k-harness",
            "algorithm": "ed25519",
            # `nonce` only ever affects the OUTER signature envelope here,
            # never the parsed evidence fields -- `_HarnessVerifier` accepts
            # anything, so this is purely a knob to make two evidence
            # documents byte-DIFFERENT without changing what they mean.
            "signature": base64.b64encode(f"SIG{nonce}".encode()).decode("ascii"),
        },
    }


def _install_security(ttl: timedelta = timedelta(hours=1)) -> None:
    install_rehearsal_issuer_security(
        signer=_Signer(),
        authorization_verifier=_AuthorizationVerifier(),
        harness_verifier=_HarnessVerifier(),
        authorization_ttl=ttl,
    )


# ── Fix 1: the ledger row is the sole source of truth for standing ─────────


def test_a_signed_but_never_recorded_envelope_does_not_authorize_standing(
    db: Session,
) -> None:
    """SENSITIVITY: before the fix, `rehearsal_issuer_standing_for` resolved
    plan/target/terms straight from the PRESENTED statement's own claimed
    `immutable_reference` whenever they happened to still resolve -- so a
    correctly signed envelope that was never actually recorded in the ledger
    (e.g. the issuing transaction never committed) would read as VALID
    standing, which is exactly the bypass this fix closes."""
    suffix = uuid.uuid4().hex
    _target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    _install_security()
    lease_id = f"lease-{suffix}"
    evidence = _harness_evidence(
        lease_id=lease_id,
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        envelope = issue_rehearsal_issuer_authorization_for_plan(
            db,
            {"command_id": _cmd(), "plan_id": str(plan.id)},
            harness_evidence_document=evidence,
        )
        # Discard the ledger insert WITHOUT ever committing it -- the plan and
        # target above were already committed by the seed helper, so they
        # still resolve; only the ledger row vanishes.
        db.rollback()

        result = rehearsal_issuer_standing_for(
            db,
            authorization_document=envelope.as_mapping(),
            harness_evidence_document=evidence,
            now=_NOW,
        )
    assert not result.authorizes, (
        "a signed envelope with no matching ledger row must never authorize, "
        f"got standing={result.standing!r}"
    )


def test_standing_refuses_uncommitted_issuance_then_accepts_commit(db: Session) -> None:
    """The issuing session cannot validate its own uncommitted ledger row."""
    suffix = uuid.uuid4().hex
    _target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    _install_security()
    evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        envelope = issue_rehearsal_issuer_authorization_for_plan(
            db,
            {"command_id": _cmd(), "plan_id": str(plan.id)},
            harness_evidence_document=evidence,
        )
        assert db.in_transaction()
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            rehearsal_issuer_standing_for(
                db,
                authorization_document=envelope.as_mapping(),
                harness_evidence_document=evidence,
                now=_NOW,
            )
        assert (
            refused.value.code
            == RehearsalIssuerIssuanceRefusalCode.STANDING_REQUIRES_COMMITTED_SESSION
        )
        db.commit()
        assert not db.in_transaction()
        result = rehearsal_issuer_standing_for(
            db,
            authorization_document=envelope.as_mapping(),
            harness_evidence_document=evidence,
            now=_NOW,
        )
    assert result.authorizes


# ── Fix 3: consumption evidence must be fresh, never a replay of issuance's ─


def test_replaying_the_exact_issuance_evidence_at_consumption_is_refused(
    db: Session,
) -> None:
    """SENSITIVITY: before the fix, consumption never compared its presented
    harness evidence against the ledger's own `harness_evidence_digest` or
    `issued_at` at all, so re-presenting issuance's own evidence verbatim
    would proceed straight through to a successful consumption."""
    suffix = uuid.uuid4().hex
    _target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    _install_security()
    lease_id = f"lease-{suffix}"
    evidence = _harness_evidence(
        lease_id=lease_id,
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        envelope = issue_rehearsal_issuer_authorization_for_plan(
            db,
            {"command_id": _cmd(), "plan_id": str(plan.id)},
            harness_evidence_document=evidence,
        )
        db.commit()

        mp.setattr(issuance, "_control_now", lambda: _NOW + timedelta(minutes=5))
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            stage_rehearsal_issuer_consumption(
                db,
                authorization_document=envelope.as_mapping(),
                # The EXACT SAME evidence document presented at issuance.
                harness_evidence_document=evidence,
            )
    assert (
        refused.value.code == RehearsalIssuerIssuanceRefusalCode.STALE_HARNESS_EVIDENCE
    )


def test_distinct_evidence_at_equal_issuance_time_is_stale(db: Session) -> None:
    """Different canonical bytes at an equal timestamp are not later evidence."""
    suffix = uuid.uuid4().hex
    _target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    _install_security()
    evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    distinct_evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=31),
    )
    assert distinct_evidence["canonical_bytes"] != evidence["canonical_bytes"]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        envelope = issue_rehearsal_issuer_authorization_for_plan(
            db,
            {"command_id": _cmd(), "plan_id": str(plan.id)},
            harness_evidence_document=evidence,
        )
        db.commit()
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            stage_rehearsal_issuer_consumption(
                db,
                authorization_document=envelope.as_mapping(),
                harness_evidence_document=distinct_evidence,
            )
    assert (
        refused.value.code == RehearsalIssuerIssuanceRefusalCode.STALE_HARNESS_EVIDENCE
    )


# ── Fix 4: issuance genuinely re-verifies its own envelope ──────────────────


def test_a_failing_installed_verifier_makes_signer_identity_mismatch_reachable(
    db: Session,
) -> None:
    """SENSITIVITY: before the fix, `SIGNER_IDENTITY_MISMATCH` compared
    `envelope.statement` (the SAME object used to build it from `identity`)
    against `identity` itself -- unreachable by construction. Swapping in a
    verifier that refuses everything can only make this refusal fire if
    issuance is genuinely calling that verifier."""
    suffix = uuid.uuid4().hex
    _target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    install_rehearsal_issuer_security(
        signer=_Signer(),
        authorization_verifier=_FailingAuthorizationVerifier(),
        harness_verifier=_HarnessVerifier(),
        authorization_ttl=timedelta(hours=1),
    )
    lease_id = f"lease-{suffix}"
    evidence = _harness_evidence(
        lease_id=lease_id,
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            issue_rehearsal_issuer_authorization_for_plan(
                db,
                {"command_id": _cmd(), "plan_id": str(plan.id)},
                harness_evidence_document=evidence,
            )
    assert (
        refused.value.code
        == RehearsalIssuerIssuanceRefusalCode.SIGNER_IDENTITY_MISMATCH
    )
    # No ledger row was committed -- the refusal fired before the insert.
    assert (
        db.execute(select(RehearsalIssuerAuthorizationRecord)).scalar_one_or_none()
        is None
    )


# ── Fix 5: a non-ACTIVE target is refused at both issuance and consumption ──


def test_issuance_refuses_a_suspended_target(db: Session) -> None:
    suffix = uuid.uuid4().hex
    target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    suspend_target(db, TargetTransitionCommand(command_id=_cmd(), target_id=target.id))
    db.commit()
    _install_security()
    evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            issue_rehearsal_issuer_authorization_for_plan(
                db,
                {"command_id": _cmd(), "plan_id": str(plan.id)},
                harness_evidence_document=evidence,
            )
    assert refused.value.code == RehearsalIssuerIssuanceRefusalCode.TARGET_NOT_ACTIVE


def test_consumption_refuses_a_target_suspended_after_issuance(db: Session) -> None:
    suffix = uuid.uuid4().hex
    target, plan = _seed_rehearsal_target_and_plan(db, suffix)
    _install_security()
    issuance_evidence = _harness_evidence(
        lease_id=f"lease-{suffix}",
        controller_fingerprint="fp-controller",
        target_ref=f"rehearsal-issuer-target-{suffix}",
        issued_at=_NOW,
        valid_until=_NOW + timedelta(minutes=30),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(issuance, "_control_now", lambda: _NOW)
        envelope = issue_rehearsal_issuer_authorization_for_plan(
            db,
            {"command_id": _cmd(), "plan_id": str(plan.id)},
            harness_evidence_document=issuance_evidence,
        )
        db.commit()

        suspend_target(
            db, TargetTransitionCommand(command_id=_cmd(), target_id=target.id)
        )
        db.commit()

        # A GENUINELY different, later piece of consumption evidence -- see
        # `test_replaying_the_exact_issuance_evidence_at_consumption_is_refused`
        # for why it must differ from issuance's own evidence.
        consumption_evidence = _harness_evidence(
            lease_id=f"lease-{suffix}",
            controller_fingerprint="fp-controller",
            target_ref=f"rehearsal-issuer-target-{suffix}",
            issued_at=_NOW + timedelta(minutes=5),
            valid_until=_NOW + timedelta(minutes=30),
            nonce="-consume",
        )
        mp.setattr(issuance, "_control_now", lambda: _NOW + timedelta(minutes=5))
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as refused:
            stage_rehearsal_issuer_consumption(
                db,
                authorization_document=envelope.as_mapping(),
                harness_evidence_document=consumption_evidence,
            )
    assert refused.value.code == RehearsalIssuerIssuanceRefusalCode.TARGET_NOT_ACTIVE
