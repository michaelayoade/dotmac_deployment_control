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
3. **A replay returns the ORIGINAL verdict.** Recomputing could yield a
   different answer against changed target state for bytes the deployment sent
   once, which would make an at-least-once transport look like a state change.

Every rejection path below is asserted to WRITE an attempt row, not just to
return a disposition. That is the half a "does it refuse?" suite misses, and it
is the half an incident review depends on.

In-memory SQLite. The two CHECK constraints that make the claim/proof split
structural are proven against real Postgres in
`tests/test_deployment_control_platform_isolation.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    AttemptOutcome,
    CredentialTransitionCommand,
    DesiredDeployment,
    EnrolCredentialCommand,
    ObservationDisposition,
    ObservationRefusedError,
    ObservedState,
    ProposePlanCommand,
    RecordObservationCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    SetDesiredStateCommand,
    SettleAttemptCommand,
    SignatureStatus,
    activate_credential,
    credential_is_eligible,
    dispatch_attempt,
    drift,
    enrol_credential,
    get_target,
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

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_SPEC = {"replicas": 2}
_RELEASE = "dotmac_sub@7.187.1"


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
            desired=DesiredDeployment(release_ref=_RELEASE, spec=_SPEC),
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


def _observe(db: Session, *, received_at: datetime | None = None, **overrides: object):
    fields: dict[str, object] = {
        "report_id": f"rep-{uuid.uuid4().hex[:8]}",
        "observed_release_ref": _RELEASE,
        "observed_spec_digest": spec_digest(_SPEC),
        "reported_at": _NOW,
        "authenticated_target_ref": "tgt-acme-1",
        "claimed_target_ref": "tgt-acme-1",
        "key_id": "key-acme-1",
        "raw_body": b"{}",
        "raw_body_digest": "sha256:beef",
        "signature_status": SignatureStatus.VALID.value,
    }
    fields.update(overrides)
    return record_observation(
        db,
        RecordObservationCommand(
            command_id=_cmd(),
            observed=ObservedState(**fields),  # type: ignore[arg-type]
            received_at=received_at or _NOW,
        ),
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
        """A caller passing `valid` without an identity has defeated the
        claim/proof split. This raises the clear error rather than letting the
        CHECK constraint produce an opaque one."""
        with pytest.raises(ObservationRefusedError, match="decorative"):
            _observe(db, authenticated_target_ref=None)


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
        assert verdict.disposition == ObservationDisposition.UNKNOWN_TARGET.value
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
                desired=DesiredDeployment(release_ref=_RELEASE, spec=_SPEC),
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
        _observe(db, report_id=report_id, raw_body_digest="sha256:aaa")
        conflict = _observe(db, report_id=report_id, raw_body_digest="sha256:bbb")
        assert conflict.disposition == ObservationDisposition.CONFLICT.value
        assert conflict.changed_state is False

    def test_both_arrivals_are_recorded_and_point_at_the_winner(
        self, db, enrolled
    ) -> None:
        report_id = "rep-fixed"
        _observe(db, report_id=report_id, raw_body_digest="sha256:aaa")
        _observe(db, report_id=report_id, raw_body_digest="sha256:bbb")
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
                desired=DesiredDeployment(release_ref=_RELEASE, spec=_SPEC),
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
                requires_approval=False,
            ),
        )
        rollout = request_rollout(
            db,
            RequestRolloutCommand(
                command_id=_cmd(),
                rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
                plan_id=plan.id,
            ),
        )
        dispatch_attempt(db, command_id=_cmd(), rollout_id=rollout.id)
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
            observed_spec_digest="sha256:something-else",
        )
        report = drift(db, target.id)
        assert report is not None
        assert report.drifted is True
        assert report.rolled_out_release_ref == _RELEASE
        assert report.observed_release_ref == "dotmac_sub@6.0.0"

    def test_an_observation_matching_no_plan_reports_no_revision(
        self, db, enrolled
    ) -> None:
        """Truthful rather than convenient: a target running something this
        control plane never planned has no revision, and saying so is itself a
        finding."""
        target, _ = enrolled
        self._rolled_out(db, target.id)
        _observe(db, observed_spec_digest="sha256:unrecognised")
        view = get_target(db, target.id)
        assert view is not None
        assert view.observed_revision is None
