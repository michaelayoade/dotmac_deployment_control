"""Observation admission: a claim is never a proof, and every arrival is recorded.

Three invariants, each with a failure mode worth stating:

1. **Only a valid signature, an eligible credential and a matching target can
   change anything.** Without all three, deployment binding is decorative:
   anyone reaching the endpoint could activate any target's deployment by naming
   it in a body.
2. **Every arrival is written, including the ones that fail before an identity
   exists.** An unknown key or a bad signature against a known one is precisely
   the evidence an operator needs, and a fail-closed system that discards it is
   closed AND blind.
3. **A replay is refused while preserving the ORIGINAL verdict.** Recomputing
   could yield a different answer against changed target state for bytes the
   deployment sent once, which would make an at-least-once transport look like
   a state change.

Every rejection path below is asserted to WRITE an attempt row, not just to
return a disposition. That is the half a "does it refuse?" suite misses, and it
is the half an incident review depends on.

In-memory SQLite. The two CHECK constraints that make the claim/proof split
structural are proven against real Postgres in
`tests/test_deployment_control_platform_isolation.py`.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    AttemptOutcome,
    CredentialTransitionCommand,
    DesiredDeployment,
    EnrolCredentialCommand,
    ExecutionObservationEnvelopeV1,
    ExecutionObservationRefusedError,
    ObservationDisposition,
    ObservationRefusedError,
    ObservedState,
    ProposePlanCommand,
    RecordObservationCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RuntimeIdentityV1,
    SetDesiredStateCommand,
    SettleAttemptCommand,
    SignatureStatus,
    activate_credential,
    credential_is_eligible,
    dispatch_attempt,
    drift,
    enrol_credential,
    get_target,
    issue_execution_observation_envelope,
    module,
    observation_attempts,
    propose_plan,
    record_observation,
    register_target,
    request_rollout,
    revoke_credential,
    set_desired_state,
    settle_attempt,
    spec_digest,
)
from dotmac_deployment_control.models import DeploymentPlan, DeploymentTarget, Rollout
from tests.authorization_support import SIGNER, VERIFIER
from tests.execution_observation_support import (
    OBSERVATION_VERIFIER,
    TestExecutionObservationSigner,
)

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_SPEC = {"replicas": 2}
_RELEASE = "dotmac_sub@7.187.1"

#: A stand-in for the Deployment Foundation's `ExecutionPlanDigestV1`. Written
#: out rather than computed: Control cannot compute one, and a fixture that
#: derived it would be exercising a capability the module does not have.
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


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


@pytest.fixture
def enrolled(db: Session):
    """A target with an ACTIVE credential, ready to be reported to."""
    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref="tgt-acme-1",
            subject_ref="acme-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=target.id,
            desired=DesiredDeployment(release_ref=_RELEASE, spec=_SPEC, images=[]),
        ),
    )
    credential_id = enrol_credential(
        db,
        EnrolCredentialCommand(
            command_id=_cmd(),
            target_id=target.id,
            key_id="key-acme-1",
            public_key_b64="AAAA",
            public_key_fingerprint="sha256:aaaa",
            enrollment_authority="platform_admin_policy",
        ),
    )
    activate_credential(
        db,
        CredentialTransitionCommand(
            command_id=_cmd(),
            credential_id=credential_id,
            at=_NOW - timedelta(days=1),
        ),
    )
    return target, credential_id


def _bound_rollout_ref(db: Session, target_ref: object) -> str | None:
    """The rollout an accepted report binds to — reused, or created on demand.

    Step 8 makes an accepted report a THREE-party fact: a report is admitted
    only when the plan Control froze, the approval that authorized it and the
    report itself name the same execution plan and the same operation. So a
    fixture that wants an ACCEPTED verdict has to supply something to bind
    against, and this is it.

    Reuses an existing rollout when the test already made one (the drift tests
    do), so the report binds to the plan whose revision they are asserting about
    rather than to a second plan that would supersede it.

    Returns `None` for a target that does not exist — the unknown-target and
    claim/proof tests pass a ref nothing was ever registered under, and they
    quarantine before the binding is reached anyway.
    """
    target = db.execute(
        select(DeploymentTarget).where(DeploymentTarget.target_ref == target_ref)
    ).scalar_one_or_none()
    if target is None:
        return None
    rollout = (
        db.execute(select(Rollout).where(Rollout.target_id == target.id))
        .scalars()
        .first()
    )
    if rollout is not None:
        return rollout.rollout_ref
    plan = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_cmd(),
            target_id=target.id,
            operation="deploy",
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            requires_approval=False,
        ),
    )
    return request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_cmd(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan.id,
            authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            authorization_issued_at=_NOW,
        ),
        signer=SIGNER,
    ).rollout_ref


def _observe(
    db: Session,
    *,
    received_at: datetime | None = None,
    observed_revision: str = "git:0123456789abcdef",
    **overrides: object,
):
    fields: dict[str, object] = {
        "report_id": f"rep-{uuid.uuid4().hex[:8]}",
        "observed_release_ref": _RELEASE,
        "observed_spec_digest": spec_digest(_SPEC),
        "reported_at": _NOW,
        "authenticated_target_ref": "tgt-acme-1",
        "claimed_target_ref": "tgt-acme-1",
        "key_id": "key-acme-1",
        "raw_body": None,
        "raw_body_digest": None,
        "signature_status": SignatureStatus.VALID.value,
        "operation": "deploy",
        "execution_plan_digest": _EXECUTION_PLAN,
    }
    fields.update(overrides)
    if fields["signature_status"] == SignatureStatus.UNRESOLVED.value:
        fields["key_id"] = "unknown-observation-key"
    if "rollout_ref" not in fields:
        fields["rollout_ref"] = _bound_rollout_ref(
            db, fields["authenticated_target_ref"]
        )
    rollout = db.execute(
        select(Rollout).where(Rollout.rollout_ref == fields["rollout_ref"])
    ).scalar_one_or_none()
    plan = None if rollout is None else db.get(DeploymentPlan, rollout.plan_id)
    target = (
        None
        if fields["authenticated_target_ref"] is None
        else db.execute(
            select(DeploymentTarget).where(
                DeploymentTarget.target_ref == fields["authenticated_target_ref"]
            )
        ).scalar_one_or_none()
    )
    snapshot = {} if plan is None else dict(plan.snapshot or {})
    statement_fields: dict[str, object] = {
        "report_id": fields["report_id"],
        "authorization_id": (
            str(rollout.id)
            if rollout is not None
            else "00000000-0000-0000-0000-000000000000"
        ),
        "rollout_ref": fields["rollout_ref"] or "unbound-rollout",
        "target_id": (
            str(target.id)
            if target is not None
            else "00000000-0000-0000-0000-000000000000"
        ),
        "target_ref": fields["claimed_target_ref"] or "unclaimed-target",
        "product_code": target.product_code if target is not None else "unknown",
        "environment": target.environment if target is not None else "unknown",
        "operation": fields["operation"],
        "release_ref": snapshot.get("release_ref") or _RELEASE,
        "observed_release_ref": fields["observed_release_ref"],
        "authorized_images": snapshot.get("authorized_images") or [],
        "observed_images": snapshot.get("authorized_images") or [],
        "plan_digest": (
            plan.plan_digest if plan is not None else "sha256:" + "0a" * 32
        ),
        "descriptor_digest": snapshot.get("descriptor_digest") or _DESCRIPTOR,
        "execution_plan_digest": fields["execution_plan_digest"],
        "observed_spec_digest": fields["observed_spec_digest"],
        "observed_revision": observed_revision,
        "runtime_identity": RuntimeIdentityV1(
            kind="oci_container", identifier="container:abcdef"
        ),
        "outcome": "succeeded",
        "observed_at": fields["reported_at"],
    }
    envelope = issue_execution_observation_envelope(
        statement_fields,
        signer=TestExecutionObservationSigner(str(fields["key_id"] or "unknown-key")),
    )
    if fields["signature_status"] != SignatureStatus.VALID.value:
        envelope = ExecutionObservationEnvelopeV1(
            statement=envelope.statement, signature="invalid-signature"
        )
    fields["raw_body"] = envelope.canonical_bytes
    fields["raw_body_digest"] = (
        f"sha256:{hashlib.sha256(envelope.canonical_bytes).hexdigest()}"
    )
    return record_observation(
        db,
        RecordObservationCommand(
            command_id=_cmd(),
            observed=ObservedState(**fields),  # type: ignore[arg-type]
            execution_observation_envelope=envelope,
            received_at=received_at or _NOW,
        ),
        observation_verifier=OBSERVATION_VERIFIER,
        authorization_verifier=VERIFIER,
    )


# ── The admitted path ───────────────────────────────────────────────────────


class TestAnAdmittedObservationUpdatesState:
    def test_a_valid_eligible_matching_report_is_accepted(self, db, enrolled) -> None:
        target, _ = enrolled
        verdict = _observe(db)
        assert verdict.disposition == ObservationDisposition.ACCEPTED.value
        assert verdict.changed_state is True
        assert verdict.receipt_id is not None

        view = get_target(db, target.id)
        assert view is not None
        assert view.observed_release_ref == _RELEASE
        assert view.last_observed_at is not None

    def test_the_arrival_is_written_as_an_attempt(self, db, enrolled) -> None:
        _observe(db)
        attempts = observation_attempts(db, target_ref="tgt-acme-1")
        assert len(attempts) == 1
        assert attempts[0].disposition == ObservationDisposition.ACCEPTED.value
        assert attempts[0].authenticated_target_ref == "tgt-acme-1"
        assert attempts[0].eligibility_at_receipt == "eligible"


# ── Nothing authenticated ───────────────────────────────────────────────────


class TestUnauthenticatedArrivalsChangeNothingAndAreRecorded:
    @pytest.mark.parametrize(
        ("status", "disposition"),
        [
            (
                SignatureStatus.UNRESOLVED.value,
                ObservationDisposition.UNKNOWN_KEY.value,
            ),
            (SignatureStatus.INVALID.value, ObservationDisposition.BAD_SIGNATURE.value),
        ],
    )
    def test_an_unverified_arrival_is_recorded_and_changes_nothing(
        self, db, enrolled, status: str, disposition: str
    ) -> None:
        target, _ = enrolled
        verdict = _observe(db, signature_status=status, authenticated_target_ref=None)
        assert verdict.disposition == disposition
        assert verdict.changed_state is False
        view = get_target(db, target.id)
        assert view is not None
        assert view.observed_release_ref is None

        attempts = observation_attempts(db)
        assert len(attempts) == 1, "the tripwire must be recorded, not discarded"
        assert attempts[0].authenticated_target_ref is None
        assert (
            attempts[0].eligibility_at_receipt == "n/a"
        ), "the eligibility of an unproven claim is not a meaningful question"

    def test_a_valid_signature_with_no_resolved_identity_is_refused(
        self, db, enrolled
    ) -> None:
        """A caller cannot project a signed report into an unauthenticated row."""
        verdict = _observe(db, authenticated_target_ref=None)
        assert (
            verdict.disposition == ObservationDisposition.SIGNED_REPORT_MISMATCH.value
        )


# ── Claim versus proof ──────────────────────────────────────────────────────


class TestTheClaimIsComparedAgainstTheProof:
    def test_a_report_claiming_a_different_target_is_quarantined(
        self, db, enrolled
    ) -> None:
        """The attack the whole design exists for: naming someone else's
        deployment in a body you signed with your own key."""
        target, _ = enrolled
        verdict = _observe(db, claimed_target_ref="tgt-someone-else")
        assert verdict.disposition == ObservationDisposition.TARGET_MISMATCH.value
        assert verdict.changed_state is False
        view = get_target(db, target.id)
        assert view is not None
        assert view.observed_release_ref is None

    def test_the_contradiction_is_recorded_with_both_values(self, db, enrolled) -> None:
        """One column holding both would make this incident unreconstructable."""
        _observe(db, claimed_target_ref="tgt-someone-else")
        attempt = observation_attempts(db)[0]
        assert attempt.authenticated_target_ref == "tgt-acme-1"
        assert attempt.claimed_target_ref == "tgt-someone-else"

    def test_a_report_for_a_target_we_do_not_know_is_quarantined(
        self, db, enrolled
    ) -> None:
        verdict = _observe(
            db,
            authenticated_target_ref="tgt-ghost",
            claimed_target_ref="tgt-ghost",
            key_id="key-acme-1",
        )
        assert (
            verdict.disposition == ObservationDisposition.SIGNED_REPORT_MISMATCH.value
        )
        assert verdict.changed_state is False


# ── Eligibility ─────────────────────────────────────────────────────────────


class TestEligibilityIsATimelinePredicate:
    def test_a_pending_credential_admits_nothing(self, db) -> None:
        """An enrolled key is a claim. Only a proven possession makes it admit
        reports (ADR-0007)."""
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=_cmd(),
                target_ref="tgt-acme-1",
                subject_ref="acme",
                product_code="dotmac_sub",
                environment="production",
            ),
        )
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=target.id,
                desired=DesiredDeployment(release_ref=_RELEASE, spec=_SPEC, images=[]),
            ),
        )
        enrol_credential(
            db,
            EnrolCredentialCommand(
                command_id=_cmd(),
                target_id=target.id,
                key_id="key-acme-1",
                public_key_b64="AAAA",
                public_key_fingerprint="sha256:aaaa",
                enrollment_authority="platform_admin_policy",
            ),
        )
        verdict = _observe(db)
        assert verdict.disposition == ObservationDisposition.NOT_ELIGIBLE.value
        assert verdict.changed_state is False

    def test_a_report_from_before_activation_is_ineligible(self, db, enrolled) -> None:
        verdict = _observe(db, received_at=_NOW - timedelta(days=30))
        assert verdict.disposition == ObservationDisposition.NOT_ELIGIBLE.value

    def test_revocation_is_not_retroactive(self, db, enrolled) -> None:
        """Reports admitted BEFORE revocation stay admitted. Retroactively
        un-admitting one would rewrite a decision that was correct when it was
        made, and the append-only attempts exist so that history survives."""
        target, credential_id = enrolled
        _observe(db)
        before = get_target(db, target.id)
        assert before is not None and before.observed_release_ref == _RELEASE

        revoke_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
                at=_NOW + timedelta(hours=1),
                reason="compromise",
            ),
        )
        after = get_target(db, target.id)
        assert after is not None
        assert (
            after.observed_release_ref == _RELEASE
        ), "an earlier admitted observation is not undone by a later revocation"

    def test_a_report_after_revocation_is_ineligible(self, db, enrolled) -> None:
        _, credential_id = enrolled
        revoke_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
                at=_NOW,
                reason="compromise",
            ),
        )
        verdict = _observe(db, received_at=_NOW + timedelta(minutes=1))
        assert verdict.disposition == ObservationDisposition.NOT_ELIGIBLE.value

    def test_the_window_is_half_open_at_the_revocation_instant(
        self, db, enrolled
    ) -> None:
        """`[activated_at, revoked_at)`. The instant of revocation is already
        outside — a closed interval would admit one more report from a key that
        has just been declared compromised."""
        _, credential_id = enrolled
        revoke_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(), credential_id=credential_id, at=_NOW
            ),
        )
        eligible, _ = credential_is_eligible(db, "key-acme-1", at=_NOW)
        assert eligible is False

    def test_an_unknown_key_is_never_eligible(self, db) -> None:
        eligible, target_ref = credential_is_eligible(db, "no-such-key", at=_NOW)
        assert eligible is False
        assert target_ref is None


# ── Idempotency ─────────────────────────────────────────────────────────────


class TestReplaysAndConflicts:
    def test_the_same_report_id_with_the_same_bytes_is_a_replay(
        self, db, enrolled
    ) -> None:
        report_id = "rep-fixed"
        first = _observe(db, report_id=report_id)
        second = _observe(db, report_id=report_id)
        assert first.disposition == ObservationDisposition.ACCEPTED.value
        assert second.disposition == ObservationDisposition.IDEMPOTENT_REPLAY.value
        assert second.changed_state is False
        assert second.receipt_id == first.receipt_id

    def test_a_replay_returns_the_original_verdict_verbatim(self, db, enrolled) -> None:
        """Recomputing could yield a different answer against changed target
        state for bytes the deployment sent once."""
        report_id = "rep-fixed"
        _observe(db, report_id=report_id)
        replay = _observe(db, report_id=report_id)
        assert replay.verdict == ObservationDisposition.ACCEPTED.value

    def test_the_same_report_id_with_different_bytes_is_a_conflict(
        self, db, enrolled
    ) -> None:
        """The row worth keeping — and the one a single uniquely-keyed table
        could not have stored."""
        report_id = "rep-fixed"
        _observe(db, report_id=report_id, observed_revision="git:first")
        conflict = _observe(db, report_id=report_id, observed_revision="git:second")
        assert conflict.disposition == ObservationDisposition.CONFLICT.value
        assert conflict.changed_state is False

    def test_both_arrivals_are_recorded_and_point_at_the_winner(
        self, db, enrolled
    ) -> None:
        report_id = "rep-fixed"
        _observe(db, report_id=report_id, observed_revision="git:first")
        _observe(db, report_id=report_id, observed_revision="git:second")
        attempts = observation_attempts(db, target_ref="tgt-acme-1")
        assert len(attempts) == 2
        assert attempts[0].receipt_id == attempts[1].receipt_id

    def test_two_targets_may_use_the_same_report_id(self, db, enrolled) -> None:
        """The receipt key is scoped to the PROVEN identity, so one target's
        `report_id` can never collide with another's."""
        second = register_target(
            db,
            RegisterTargetCommand(
                command_id=_cmd(),
                target_ref="tgt-acme-2",
                subject_ref="acme",
                product_code="dotmac_sub",
                environment="production",
            ),
        )
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=second.id,
                desired=DesiredDeployment(release_ref=_RELEASE, spec=_SPEC, images=[]),
            ),
        )
        credential_id = enrol_credential(
            db,
            EnrolCredentialCommand(
                command_id=_cmd(),
                target_id=second.id,
                key_id="key-acme-2",
                public_key_b64="BBBB",
                public_key_fingerprint="sha256:bbbb",
                enrollment_authority="platform_admin_policy",
            ),
        )
        activate_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
                at=_NOW - timedelta(days=1),
            ),
        )
        first = _observe(db, report_id="shared")
        other = _observe(
            db,
            report_id="shared",
            authenticated_target_ref="tgt-acme-2",
            claimed_target_ref="tgt-acme-2",
            key_id="key-acme-2",
        )
        assert first.disposition == ObservationDisposition.ACCEPTED.value
        assert other.disposition == ObservationDisposition.ACCEPTED.value
        assert first.receipt_id != other.receipt_id


class TestCallerInputsThatCannotBeUsed:
    def test_a_naive_received_at_is_refused(self, db, enrolled) -> None:
        """An eligibility decision against a naive instant is not reproducible."""
        with pytest.raises(ObservationRefusedError, match="timezone-aware"):
            record_observation(
                db,
                RecordObservationCommand(
                    command_id=_cmd(),
                    observed=ObservedState(
                        report_id="r1",
                        observed_release_ref=_RELEASE,
                        observed_spec_digest=spec_digest(_SPEC),
                        reported_at=_NOW,
                        authenticated_target_ref="tgt-acme-1",
                        key_id="key-acme-1",
                        signature_status=SignatureStatus.VALID.value,
                    ),
                    execution_observation_envelope={},
                    received_at=datetime(2026, 9, 1, 12, 0),
                ),
            )


# ── Drift ───────────────────────────────────────────────────────────────────


class TestDriftIsMeasuredAgainstWhatWasRolledOut:
    def _rolled_out(self, db, target_id):  # type: ignore[no-untyped-def]
        plan = propose_plan(
            db,
            ProposePlanCommand(
                command_id=_cmd(),
                target_id=target_id,
                operation="deploy",
                descriptor_digest=_DESCRIPTOR,
                execution_plan_digest=_EXECUTION_PLAN,
                requires_approval=False,
            ),
        )
        rollout = request_rollout(
            db,
            RequestRolloutCommand(
                command_id=_cmd(),
                rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
                plan_id=plan.id,
                authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                authorization_issued_at=_NOW,
            ),
            signer=SIGNER,
        )
        dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.SUCCEEDED.value,
            ),
        )
        return plan

    def test_a_target_running_what_was_rolled_out_is_not_drifted(
        self, db, enrolled
    ) -> None:
        target, _ = enrolled
        self._rolled_out(db, target.id)
        _observe(db)
        report = drift(db, target.id)
        assert report is not None
        assert report.drifted is False

    def test_editing_the_desired_state_does_not_create_drift(
        self, db, enrolled
    ) -> None:
        """Comparing against the CURRENT desired state instead would make every
        edit look like fleet-wide drift, and the signal would be worthless
        within a week."""
        target, _ = enrolled
        self._rolled_out(db, target.id)
        _observe(db)
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=target.id,
                desired=DesiredDeployment(
                    release_ref="dotmac_sub@9.0.0", spec={"replicas": 9}
                ),
            ),
        )
        report = drift(db, target.id)
        assert report is not None
        assert (
            report.drifted is False
        ), "an unrolled-out desired-state edit is intent, not drift"

    def test_a_target_running_something_else_is_drifted(self, db, enrolled) -> None:
        target, _ = enrolled
        self._rolled_out(db, target.id)
        _observe(
            db,
            observed_release_ref="dotmac_sub@6.0.0",
            observed_spec_digest=spec_digest({"replicas": 99}),
        )
        report = drift(db, target.id)
        assert report is not None
        assert report.drifted is False
        assert report.rolled_out_release_ref == _RELEASE
        assert report.observed_release_ref is None
        assert observation_attempts(db)[0].disposition == (
            ObservationDisposition.AUTHORIZATION_MISMATCH.value
        )

    def test_an_observation_matching_no_plan_reports_no_revision(
        self, db, enrolled
    ) -> None:
        """Truthful rather than convenient: a target running something this
        control plane never planned has no revision, and saying so is itself a
        finding."""
        target, _ = enrolled
        self._rolled_out(db, target.id)
        # WELL-FORMED and unmatched. `"sha256:unrecognised"` used to stand in
        # here, and since `0.1.0a5` that value is not a readable digest at all —
        # it would exercise the encoding path and report no revision for the
        # wrong reason, which is a test passing by accident.
        _observe(db, observed_spec_digest=spec_digest({"never": "planned"}))
        view = get_target(db, target.id)
        assert view is not None
        assert view.observed_revision is None

    def test_the_local_signer_refuses_an_unreadable_spec_digest(
        self, db, enrolled
    ) -> None:
        """A local producer cannot issue malformed typed statement bytes."""
        target, _ = enrolled
        self._rolled_out(db, target.id)
        with pytest.raises(ExecutionObservationRefusedError, match="unreadable"):
            _observe(db, observed_spec_digest="sha256:NOT-LOWERCASE-HEX")

    def test_a_malformed_wire_envelope_is_recorded_not_raised(
        self, db, enrolled
    ) -> None:
        """Every ARRIVAL is retained, even when its statement cannot parse."""
        target, _ = enrolled
        self._rolled_out(db, target.id)
        observed = ObservedState(
            report_id="malformed-report",
            observed_release_ref=_RELEASE,
            observed_spec_digest=spec_digest(_SPEC),
            reported_at=_NOW,
            authenticated_target_ref=None,
            claimed_target_ref="tgt-acme-1",
            key_id="unknown-malformed-key",
            raw_body=b'{"statement":{},"signature":"x"}',
            raw_body_digest="sha256:" + "ab" * 32,
            signature_status=SignatureStatus.UNRESOLVED.value,
            rollout_ref=None,
            operation=None,
            execution_plan_digest=None,
        )
        verdict = record_observation(
            db,
            RecordObservationCommand(
                command_id=_cmd(),
                observed=observed,
                execution_observation_envelope={"statement": {}, "signature": "x"},
                received_at=_NOW,
            ),
            observation_verifier=OBSERVATION_VERIFIER,
            authorization_verifier=VERIFIER,
        )
        assert verdict.disposition == ObservationDisposition.MALFORMED.value
        assert verdict.changed_state is False
        assert len(observation_attempts(db)) == 1
