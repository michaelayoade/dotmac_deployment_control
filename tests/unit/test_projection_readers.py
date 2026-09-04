"""What the owner projects, and the shapes a value-only test cannot see.

Four readers moved into this module in one change, each replacing a derivation
a consumer was performing for itself. Three of them are wrong in ways that a
test asserting only the returned value passes anyway:

* the approval standing can be correct per row and be an N+1 while it is
  correct, so `TestTheApprovalStandingIsOneStatement` counts STATEMENTS across
  a page of two and a page of six;
* the executability flag can be computed by calling the freeze-time gate, which
  returns the right answer for every plan the gate does not refuse and raises on
  the ones it does, so `TestARecoverPlanStillReads` puts a `recover` plan and a
  `deploy` plan on one target and asserts the gate refuses the same value the
  reader answered for;
* the recovery standing can be assembled from a deployment authorization, which
  produces a plausible EXPIRED where the truth is ABSENT, so
  `TestNoDeploymentAuthorizationLeaksIntoRecovery` expires a deployment
  authorization and requires the recovery answer to be ABSENT.

The image set is the fourth, and its failure mode is the ordinary one: `None`
collapsing into `()`.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.service as control_service
from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    AuthorizedImage,
    DesiredDeployment,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RevokePlanApprovalCommand,
    SetDesiredStateCommand,
    TargetFilter,
    approve_plan,
    get_plan,
    get_target,
    grant_for_target,
    list_targets,
    module,
    propose_plan,
    recovery_standing_for_target,
    register_target,
    request_rollout,
    revoke_plan_approval,
    revoked_grant_ids_for_target,
    set_desired_state,
)
from dotmac_deployment_control.authorization import (
    AuthorizationEnvelopeRefusalCode,
    AuthorizationEnvelopeRefusedError,
    verify_authorization_envelope,
)
from dotmac_deployment_control.counterparty import (
    OperationNotExecutableError,
    require_executable_operation,
)
from dotmac_deployment_control.models import (
    DeploymentPlan,
    RecoveryGrant,
    Rollout,
)
from dotmac_deployment_control.recovery_grant import (
    RECOVERY_PURPOSE,
    RecoveryGrantRefusalCode,
    RecoveryGrantSignature,
    RecoveryGrantSignerIdentity,
    RecoveryGrantStatementV1,
    RecoveryStanding,
    RecoverySubject,
    issue_recovery_grant,
)
from tests.authorization_support import SIGNER, VERIFIER

#: Deliberately not close to the wall clock. Every window in this file is
#: expressed relative to it, so a reader that fell back to `datetime.now`
#: instead of the module clock reads the valid grant as NOT_YET_VALID and
#: the expired one as NOT_YET_VALID too -- both fail, loudly, here.
_NOW = datetime(2027, 3, 5, 12, 0, tzinfo=UTC)
_POLICY = "deployment.production"
_POLICY_VERSION = 4
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32
_IMAGE_A = "sha256:" + "aa" * 32
_RECOVERY_PLAN = "sha256:" + "d1" * 32
_BUNDLE = "sha256:" + "d2" * 32
_PRESTATE = "sha256:" + "d3" * 32


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


@pytest.fixture(autouse=True)
def _fixed_control_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """ONE clock. `recovery_standing_for_target` passes `_control_now()` rather
    than letting the grant module default to the wall clock, and `_NOW` is far
    enough from the wall clock that the difference is a failure rather than a
    coincidence."""
    monkeypatch.setattr(control_service, "_control_now", lambda: _NOW)


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


def _cmd() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _target(db: Session, **overrides: object):  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "command_id": _cmd(),
        "target_ref": f"tgt-{uuid.uuid4().hex[:8]}",
        "subject_ref": "acme-operator",
        "product_code": "dotmac_sub",
        "environment": "production",
    }
    fields.update(overrides)
    return register_target(db, RegisterTargetCommand(**fields))  # type: ignore[arg-type]


def _desired(db: Session, target_id, images: object, release: str = "7.187.1"):  # type: ignore[no-untyped-def]
    """Set desired state and return the target. `release` is a parameter because
    a plan's digest is taken over the frozen snapshot and `plan_digest` is
    UNIQUE: two plans frozen from an unchanged desired state are one plan, and
    the second insert is a constraint violation rather than a test."""
    return set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=target_id,
            desired=DesiredDeployment(
                release_ref=f"dotmac_sub@{release}",
                spec={"replicas": 2},
                images=images,  # type: ignore[arg-type]
            ),
        ),
    )


def _planned_target(db: Session, target_ref: str):  # type: ignore[no-untyped-def]
    """A target a plan can actually be proposed for: ACTIVE, with a desired
    release and a declared image set."""
    target = _target(db, target_ref=target_ref)
    _desired(db, target.id, [_image("api", _IMAGE_A)])
    return target


def _plan(db: Session, target_id, operation: str = "deploy"):  # type: ignore[no-untyped-def]
    return propose_plan(
        db,
        ProposePlanCommand(
            command_id=_cmd(),
            target_id=target_id,
            operation=operation,
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            requires_approval=True,
            approval_policy_code=_POLICY,
            approval_policy_version=_POLICY_VERSION,
        ),
    )


def _approve(db: Session, plan, decision_status: str = "granted"):  # type: ignore[no-untyped-def]
    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_cmd(),
            plan_id=plan.id,
            evidence=ApprovalEvidence(
                policy_code=_POLICY,
                policy_version=_POLICY_VERSION,
                decision_ref=f"apr-{uuid.uuid4().hex[:8]}",
                content_digest=plan.plan_digest or "",
                decided_at=_NOW,
                operation="deploy",
                execution_plan_digest=_EXECUTION_PLAN,
                decision_status=decision_status,
            ),
        ),
    )


def _rollout(db: Session, plan_id):  # type: ignore[no-untyped-def]
    return request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_cmd(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan_id,
            authorization_expires_at=_NOW + timedelta(hours=4),
        ),
        signer=SIGNER,
    )


def _image(service: str, digest: str) -> dict[str, str]:
    return {
        "service": service,
        "repository": f"registry.dotmac.io/{service}",
        "digest": digest,
    }


# ── R1: the declared image set, three states ────────────────────────────────


class TestTheDeclaredImageSetKeepsItsThreeStates:
    """`None` is not `()`. The projection is read through the parser that
    already owns the distinction, so there is one implementation of it and not
    a second one at this call site."""

    def test_a_target_with_no_declared_set_reads_none_not_empty(
        self, db: Session
    ) -> None:
        view = get_target(db, _target(db).id)
        assert view is not None
        assert view.desired_images is None, (
            "an undeclared image set read as a declared empty one; a consumer "
            "would take 'authorizes nothing' from a target that has said nothing"
        )

    def test_a_deliberately_empty_set_reads_as_empty_not_absent(
        self, db: Session
    ) -> None:
        target = _target(db)
        _desired(db, target.id, [])
        view = get_target(db, target.id)
        assert view is not None
        assert view.desired_images == ()
        assert view.desired_images is not None

    def test_a_declared_set_reads_back_as_the_type(self, db: Session) -> None:
        target = _target(db)
        _desired(db, target.id, [_image("api", _IMAGE_A)])
        view = get_target(db, target.id)
        assert view is not None
        assert view.desired_images is not None
        assert all(
            isinstance(image, AuthorizedImage) for image in view.desired_images
        ), "the projection handed back raw mappings; a consumer would parse them"
        assert [image.service for image in view.desired_images] == ["api"]

    def test_the_page_agrees_with_the_single_read_on_all_three(
        self, db: Session
    ) -> None:
        absent = _target(db, target_ref="img-absent")
        empty = _target(db, target_ref="img-empty")
        _desired(db, empty.id, [])
        declared = _target(db, target_ref="img-declared")
        _desired(db, declared.id, [_image("api", _IMAGE_A)])

        page = {
            view.target_ref: view.desired_images
            for view in list_targets(db, TargetFilter(page_size=50)).targets
        }
        assert page["img-absent"] is None
        assert page["img-empty"] == ()
        assert page["img-declared"] is not None
        for ref, target_id in (
            ("img-absent", absent.id),
            ("img-empty", empty.id),
            ("img-declared", declared.id),
        ):
            single = get_target(db, target_id)
            assert single is not None
            assert page[ref] == single.desired_images


# ── R3: executability is read, never gated ──────────────────────────────────


class TestARecoverPlanStillReads:
    """THE test that separates the two implementations of R3.

    `require_executable_operation` and `operation in EXECUTOR_OPERATIONS` return
    the same answer for every operation the gate admits. They differ on exactly
    one input -- an operation the counterparty cannot perform -- and there the
    gate raises. A reader built on the gate therefore passes every test written
    with `deploy` plans and takes down the plans page the first time somebody
    looks at a historical `recover`.
    """

    def test_a_recover_plan_and_a_deploy_plan_both_read_on_one_target(
        self, db: Session
    ) -> None:
        target = _planned_target(db, "r3-both")
        recover = _plan(db, target.id, operation="recover")
        _desired(db, target.id, [_image("api", _IMAGE_A)], release="7.188.0")
        deploy = _plan(db, target.id, operation="deploy")

        recover_view = get_plan(db, recover.id)
        deploy_view = get_plan(db, deploy.id)

        assert recover_view is not None, "reading a recover plan raised or vanished"
        assert deploy_view is not None
        assert recover_view.operation_is_executable is False
        assert deploy_view.operation_is_executable is True

    def test_the_gate_refuses_the_value_the_reader_answered_for(self) -> None:
        """SENSITIVITY. Without this the test above is satisfied by a `recover`
        the counterparty happens to support, and proves nothing about which
        implementation the reader chose."""
        with pytest.raises(OperationNotExecutableError):
            require_executable_operation("recover", where="sensitivity proof")
        assert require_executable_operation("deploy", where="sensitivity proof")

    def test_an_undeclared_operation_reads_none_not_false(self, db: Session) -> None:
        """`False` would say a plan nobody has described is one nobody can run.
        The column is nullable, so this row is reachable without a fixture lie."""
        plan = _plan(db, _planned_target(db, "r3-undeclared").id)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.operation = None
        row.authorized_operation = None
        db.flush()

        view = get_plan(db, plan.id)
        assert view is not None
        assert view.operation_is_executable is None


# ── R4: the approval standing, and its shape ────────────────────────────────


def _plan_statements(db: Session, work: Callable[[], Any]) -> tuple[Any, int]:
    """Run `work` and count the statements that touch `deployment_plans`.

    Scoped to that one table on purpose. Counting everything would also count
    the `BEGIN` this fixture emits by hand and whatever the session does around
    a transaction boundary, and the assertion would then be about the harness.
    The correlated subquery reads plans ONCE, inside the page statement; a
    per-row lookup reads them once per target and is otherwise identical --
    every value it returns is correct, which is exactly why the shape has to be
    asserted separately from the values.
    """
    counted: list[str] = []

    def _record(_conn, _cursor, statement, *_rest):  # type: ignore[no-untyped-def]
        if "deployment_plans" in statement:
            counted.append(statement)

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", _record)
    try:
        result = work()
    finally:
        event.remove(engine, "before_cursor_execute", _record)
    return result, len(counted)


class TestTheApprovalStandingIsOneStatement:
    def test_the_page_does_not_issue_a_statement_per_target(self, db: Session) -> None:
        """THE shape assertion. A correlated subquery is constant in N; a
        per-row lookup grows with it and is otherwise indistinguishable, because
        every value it returns is right."""
        for index in range(2):
            _approve(db, _plan(db, _planned_target(db, f"small-{index}").id))
        db.flush()
        small, small_statements = _plan_statements(
            db, lambda: list_targets(db, TargetFilter(page_size=50))
        )

        for index in range(4):
            _approve(db, _plan(db, _planned_target(db, f"large-{index}").id))
        db.flush()
        large, large_statements = _plan_statements(
            db, lambda: list_targets(db, TargetFilter(page_size=50))
        )

        assert len(small.targets) == 2
        assert len(large.targets) == 6
        assert small_statements == large_statements == 1, (
            f"listing 2 targets read deployment_plans {small_statements} times "
            f"and listing 6 read it {large_statements} times; the standing is "
            "being looked up per row. Every value would still be correct, which "
            "is why this is a shape assertion and not a value one."
        )

    def test_the_four_states_are_four_answers(self, db: Session) -> None:
        no_plan = _target(db, target_ref="std-none")

        unrecorded = _planned_target(db, "std-unrecorded")
        _plan(db, unrecorded.id)

        granted = _planned_target(db, "std-granted")
        _approve(db, _plan(db, granted.id))

        revoked = _planned_target(db, "std-revoked")
        revoked_plan = _approve(db, _plan(db, revoked.id))
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(),
                plan_id=revoked_plan.id,
                revocation_ref="apr-rev-1",
                reason="withdrawn",
            ),
        )

        page = {
            view.target_ref: view.current_plan_approval_status
            for view in list_targets(db, TargetFilter(page_size=50)).targets
        }
        assert page == {
            "std-none": "none",
            "std-unrecorded": "unrecorded",
            "std-granted": "granted",
            "std-revoked": "revoked",
        }
        assert page["std-unrecorded"] != page["std-granted"], (
            "a plan carrying no decision read as an approved one -- an "
            "authorization taken out of a blank column"
        )
        assert (
            page["std-none"] != page["std-unrecorded"]
        ), "no plan at all read the same as a plan awaiting a decision"

        for ref, target_id in (
            ("std-none", no_plan.id),
            ("std-unrecorded", unrecorded.id),
            ("std-granted", granted.id),
            ("std-revoked", revoked.id),
        ):
            single = get_target(db, target_id)
            assert single is not None
            assert single.current_plan_approval_status == page[ref], (
                f"the page and the single read disagree about {ref}; two "
                "statements of one rule have drifted"
            )

    def test_the_standing_follows_the_current_plan_not_the_first(
        self, db: Session
    ) -> None:
        """`ORDER BY sequence DESC LIMIT 1`. A reader taking any matching plan
        would report a stale approval for a target whose newest plan is
        unapproved -- the exact case an operator is looking at the page to
        find."""
        target = _planned_target(db, "std-superseded")
        _approve(db, _plan(db, target.id))
        _desired(db, target.id, [_image("api", _IMAGE_A)], release="7.188.0")
        _plan(db, target.id)

        view = get_target(db, target.id)
        assert view is not None
        assert view.current_plan_approval_status == "unrecorded"


# ── R6: recovery standing reads recovery grants and nothing else ────────────


class _Signer:
    @property
    def recovery_identity(self) -> RecoveryGrantSignerIdentity:
        return RecoveryGrantSignerIdentity("k-rec", "ed25519", "fp-rec")

    def sign_recovery(self, canonical_bytes: bytes) -> RecoveryGrantSignature:
        assert canonical_bytes
        return RecoveryGrantSignature(
            "k-rec", "ed25519", RECOVERY_PURPOSE, "fp-rec", "SIG"
        )


class _Verifier:
    def verify_recovery(self, **kwargs: object) -> bool:
        return kwargs["signature"] == "SIG"


def _recovery_statement(target, **overrides: object) -> RecoveryGrantStatementV1:  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "grant_id": f"g-{uuid.uuid4().hex[:8]}",
        "product_code": target.product_code,
        "target_id": str(target.id),
        "target_ref": target.target_ref,
        "environment": target.environment,
        "recovery_execution_plan_digest": _RECOVERY_PLAN,
        "recovery_bundle_digest": _BUNDLE,
        "incumbent_prestate_digest": _PRESTATE,
        "approval_policy_code": "recovery.standard",
        "approval_policy_version": 1,
        "approval_decision_ref": "dec-rec-1",
        "approval_decision_status": "granted",
        "approved_at": _NOW - timedelta(hours=1),
        "not_before": _NOW - timedelta(minutes=5),
        "issued_at": _NOW,
        "expires_at": _NOW + timedelta(hours=2),
        "control_version": "0.1.0a12",
        "key_id": "k-rec",
        "algorithm": "ed25519",
        "public_key_fingerprint": "fp-rec",
    }
    fields.update(overrides)
    return RecoveryGrantStatementV1(**fields)  # type: ignore[arg-type]


def _store_grant(
    db: Session,
    target,  # type: ignore[no-untyped-def]
    statement: RecoveryGrantStatementV1,
    *,
    revoked: bool = False,
) -> RecoveryGrant:
    envelope = issue_recovery_grant(statement, signer=_Signer()).as_mapping()
    row = RecoveryGrant(
        grant_id=statement.grant_id,
        target_id=target.id,
        product_code=statement.product_code,
        environment=statement.environment,
        recovery_execution_plan_digest=statement.recovery_execution_plan_digest,
        recovery_bundle_digest=statement.recovery_bundle_digest,
        incumbent_prestate_digest=statement.incumbent_prestate_digest,
        grant_envelope=envelope,
        not_before=statement.not_before,
        issued_at=statement.issued_at,
        expires_at=statement.expires_at,
        revoked_at=_NOW if revoked else None,
        revocation_ref="rev-1" if revoked else None,
        record_version=1,
    )
    db.add(row)
    db.flush()
    return row


class TestNoDeploymentAuthorizationLeaksIntoRecovery:
    """The failure this exists to catch is not a crash; it is a plausible
    answer. A surface that reached for the deployment authorization when no
    recovery grant existed would show EXPIRED for a target nobody has ever
    authorized a recovery on -- and EXPIRED reads as 'renew it', which is a
    different and much shorter conversation than 'nobody approved this'."""

    def test_an_expired_deployment_authorization_reads_absent_not_expired(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = _planned_target(db, "r6-expired-auth")
        plan = _approve(db, _plan(db, target.id))
        rollout = _rollout(db, plan.id)
        row = db.get(Rollout, rollout.id)
        assert row is not None
        assert row.authorization_envelope is not None

        # Past the authorization's own signed expiry. The clock moves rather
        # than the document: editing `expires_at` in the envelope would break
        # the signature, and the refusal would then be SIGNATURE_INVALID -- a
        # fixture that proves something other than what it claims.
        later = _NOW + timedelta(hours=8)
        monkeypatch.setattr(control_service, "_control_now", lambda: later)

        # SENSITIVITY. The deployment authorization really is dead, and dead of
        # EXPIRY specifically -- which is the verdict that must NOT reappear as
        # the recovery answer below.
        with pytest.raises(AuthorizationEnvelopeRefusedError) as refused:
            verify_authorization_envelope(
                row.authorization_envelope, verifier=VERIFIER, at=later
            )
        assert refused.value.code is AuthorizationEnvelopeRefusalCode.EXPIRED

        result = recovery_standing_for_target(
            db,
            target.id,
            verifier=_Verifier(),
            subject=_recovery_statement(target).subject,
        )
        assert result.standing is RecoveryStanding.ABSENT, (
            f"read {result.standing}; EXPIRED here would claim a recovery grant "
            "existed and timed out, when none was ever issued -- and EXPIRED "
            "reads to an operator as 'renew it', not 'nobody approved this'"
        )
        assert result.authorizes is False
        assert grant_for_target(db, target.id) is None

    def test_a_revoked_deployment_approval_reads_absent_not_revoked(
        self, db: Session
    ) -> None:
        """The other flavour of dead, and the same answer. A withdrawn
        permission to deploy is not a withdrawn permission to recover."""
        target = _planned_target(db, "r6-revoked-approval")
        plan = _approve(db, _plan(db, target.id))
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(),
                plan_id=plan.id,
                revocation_ref="apr-rev-recovery",
                reason="withdrawn",
            ),
        )
        single = get_target(db, target.id)
        assert single is not None
        assert single.current_plan_approval_status == "revoked"

        result = recovery_standing_for_target(
            db,
            target.id,
            verifier=_Verifier(),
            subject=_recovery_statement(target).subject,
        )
        assert result.standing is RecoveryStanding.ABSENT


class TestARealRecoveryGrantIsAdmitted:
    """NON-VACUITY. Every assertion above is a refusal, and a suite of refusals
    passes when nothing can be stored or read at all."""

    def test_a_stored_valid_grant_reads_valid(self, db: Session) -> None:
        target = _target(db)
        statement = _recovery_statement(target)
        _store_grant(db, target, statement)

        result = recovery_standing_for_target(
            db, target.id, verifier=_Verifier(), subject=statement.subject
        )
        assert result.standing is RecoveryStanding.VALID
        assert result.authorizes is True
        assert result.refusal is None

    def test_the_reader_hands_back_the_parsed_type(self, db: Session) -> None:
        """Not the stored mapping. A caller holding a raw envelope is one
        restringification away from verifying a restatement of the grant rather
        than the grant."""
        target = _target(db)
        statement = _recovery_statement(target)
        _store_grant(db, target, statement)

        grant = grant_for_target(db, target.id)
        assert grant is not None
        assert grant.statement.grant_id == statement.grant_id
        assert grant.statement.purpose == RECOVERY_PURPOSE
        assert grant.statement.subject == statement.subject


class TestTheUnavailableStatesAreDistinguishable:
    """Four different next actions, so four different answers."""

    def test_a_revoked_grant_reads_revoked_not_absent(self, db: Session) -> None:
        target = _target(db)
        statement = _recovery_statement(target)
        _store_grant(db, target, statement, revoked=True)

        assert revoked_grant_ids_for_target(db, target.id) == frozenset(
            {statement.grant_id}
        )
        result = recovery_standing_for_target(
            db, target.id, verifier=_Verifier(), subject=statement.subject
        )
        assert result.standing is RecoveryStanding.REVOKED
        assert result.refusal is RecoveryGrantRefusalCode.REVOKED

    def test_an_expired_grant_reads_expired_not_absent(self, db: Session) -> None:
        target = _target(db)
        statement = _recovery_statement(
            target,
            not_before=_NOW - timedelta(hours=6),
            issued_at=_NOW - timedelta(hours=5),
            expires_at=_NOW - timedelta(hours=4),
        )
        _store_grant(db, target, statement)

        result = recovery_standing_for_target(
            db, target.id, verifier=_Verifier(), subject=statement.subject
        )
        assert result.standing is RecoveryStanding.EXPIRED
        assert result.refusal is RecoveryGrantRefusalCode.EXPIRED

    def test_a_grant_for_a_different_recovery_reads_unresolved(
        self, db: Session
    ) -> None:
        """It exists, it is signed, it is in date -- and it is not authority for
        THIS recovery. Distinct from ABSENT, EXPIRED and REVOKED."""
        target = _target(db)
        statement = _recovery_statement(target)
        _store_grant(db, target, statement)

        other = RecoverySubject(
            product_code=statement.product_code,
            target_id=statement.target_id,
            target_ref=statement.target_ref,
            environment=statement.environment,
            recovery_execution_plan_digest=_RECOVERY_PLAN,
            recovery_bundle_digest="sha256:" + "ee" * 32,
            incumbent_prestate_digest=_PRESTATE,
        )
        result = recovery_standing_for_target(
            db, target.id, verifier=_Verifier(), subject=other
        )
        assert result.standing is RecoveryStanding.UNRESOLVED
        # THE CODE, not the prose. UNRESOLVED is one verdict over many
        # causes, and the cause is the half an operator can act on.
        assert result.refusal is RecoveryGrantRefusalCode.BUNDLE_MISMATCH

    def test_the_revocation_set_is_this_module_s_own(self, db: Session) -> None:
        """`revoked_grant_ids_for_target` derives the set from rows and takes no
        caller argument. A consumer able to supply it could decide a withdrawal
        did not count."""
        target = _target(db)
        live = _recovery_statement(target, grant_id="g-live")
        _store_grant(db, target, live)
        assert revoked_grant_ids_for_target(db, target.id) == frozenset()

        row = db.execute(
            select(RecoveryGrant).where(RecoveryGrant.grant_id == "g-live")
        ).scalar_one()
        row.revoked_at = _NOW
        row.revocation_ref = "rev-late"
        db.flush()
        assert revoked_grant_ids_for_target(db, target.id) == frozenset({"g-live"})
