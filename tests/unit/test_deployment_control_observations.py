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
from unittest.mock import patch

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.service as control_service
from dotmac_deployment_control import (
    AttemptOutcome,
    AuthorizationEnvelopeDigestV1,
    AuthorizationEnvelopeV2,
    CredentialTransitionCommand,
    DesiredDeployment,
    DigestEncodingError,
    EligibilityAtReceipt,
    EnrolCredentialCommand,
    ExecutionObservationEnvelopeV1,
    ExecutionObservationRefusedError,
    ObservationDisposition,
    ObservationRefusedError,
    ProposePlanCommand,
    RecordObservationCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RuntimeIdentityV1,
    SetDesiredStateCommand,
    SettleAttemptCommand,
    SignatureStatus,
    TransitionRefusedError,
    activate_credential,
    credential_is_eligible,
    dispatch_attempt,
    drift,
    enrol_credential,
    get_target,
    issue_execution_observation_envelope,
    module,
    observation_attempts,
    observation_receipts,
    propose_plan,
    record_observation,
    register_target,
    request_rollout,
    revoke_credential,
    set_desired_state,
    settle_attempt,
    spec_digest,
)
from dotmac_deployment_control.models import (
    DeploymentPlan,
    DeploymentTarget,
    ObservationReceipt,
    Rollout,
    RolloutAttempt,
    TargetCredential,
)
from tests.authorization_support import SIGNER, VERIFIER
from tests.execution_observation_support import (
    OBSERVATION_VERIFIER,
    TestExecutionObservationSigner,
    observation_public_key_b64,
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


@pytest.fixture(autouse=True)
def _fixed_control_clock(monkeypatch: pytest.MonkeyPatch) -> None:
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
            algorithm="test-sha256",
            public_key_b64=observation_public_key_b64("key-acme-1"),
            enrollment_authority="platform_admin_policy",
        ),
    )
    activate_credential(
        db,
        CredentialTransitionCommand(
            command_id=_cmd(),
            credential_id=credential_id,
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
        if not db.execute(
            select(RolloutAttempt).where(RolloutAttempt.rollout_id == rollout.id)
        ).scalar_one_or_none():
            dispatch_attempt(
                db,
                command_id=_cmd(),
                rollout_id=rollout.id,
                verifier=VERIFIER,
            )
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
    rollout = request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_cmd(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan.id,
            authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        ),
        signer=SIGNER,
    )
    dispatch_attempt(
        db,
        command_id=_cmd(),
        rollout_id=rollout.id,
        verifier=VERIFIER,
    )
    return rollout.rollout_ref


def _observe(
    db: Session,
    *,
    received_at: datetime | None = None,
    observed_revision: str = "git:0123456789abcdef",
    **overrides: object,
):
    statement_overrides = dict(
        overrides.pop("_statement_overrides", {})  # type: ignore[arg-type]
    )
    signer_public_key_b64 = overrides.pop("_signer_public_key_b64", None)
    wire_override = overrides.pop("_wire_override", None)
    fields: dict[str, object] = {
        "report_id": f"rep-{uuid.uuid4().hex[:8]}",
        "observed_release_ref": _RELEASE,
        "observed_spec_digest": spec_digest(_SPEC),
        "reported_at": _NOW,
        "authenticated_target_ref": "tgt-acme-1",
        "claimed_target_ref": "tgt-acme-1",
        "key_id": "key-acme-1",
        "signature_status": SignatureStatus.VALID.value,
        "operation": "deploy",
        "execution_plan_digest": _EXECUTION_PLAN,
        "outcome": "succeeded",
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
    authorization = (
        None
        if rollout is None or rollout.authorization_envelope is None
        else AuthorizationEnvelopeV2.parse(rollout.authorization_envelope)
    )
    attempt = (
        None
        if rollout is None
        else db.execute(
            select(RolloutAttempt)
            .where(RolloutAttempt.rollout_id == rollout.id)
            .order_by(RolloutAttempt.attempt_no.desc())
        )
        .scalars()
        .first()
    )
    statement_fields: dict[str, object] = {
        "report_id": fields["report_id"],
        "authorization_id": (
            str(rollout.id)
            if rollout is not None
            else "00000000-0000-0000-0000-000000000000"
        ),
        "authorization_plan_id": (
            authorization.statement.plan_id
            if authorization is not None
            else "00000000-0000-0000-0000-000000000000"
        ),
        "authorization_control_version": (
            authorization.statement.control_version
            if authorization is not None
            else "0.1.0a10"
        ),
        "authorization_envelope_digest": (
            AuthorizationEnvelopeDigestV1.over_bytes(
                authorization.canonical_bytes
            ).canonical
            if authorization is not None
            else "sha256:" + "09" * 32
        ),
        "execution_sequence": (
            rollout.execution_sequence
            if rollout is not None and rollout.execution_sequence is not None
            else 1
        ),
        "attempt_no": attempt.attempt_no if attempt is not None else 1,
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
        "outcome": fields["outcome"],
        "observed_at": fields["reported_at"],
    }
    statement_fields.update(statement_overrides)
    envelope = issue_execution_observation_envelope(
        statement_fields,
        signer=TestExecutionObservationSigner(
            str(fields["key_id"] or "unknown-key"),
            public_key_b64=(
                str(signer_public_key_b64)
                if signer_public_key_b64 is not None
                else None
            ),
        ),
    )
    if fields["signature_status"] != SignatureStatus.VALID.value:
        envelope = ExecutionObservationEnvelopeV1(
            statement=envelope.statement, signature="invalid-signature"
        )
    # ONE INPUT. The helper hands Control the wire bytes and nothing else —
    # there is no ObservedState to keep consistent, because there is no second
    # channel for one to disagree through. `_wire_override` lets a test present
    # bytes that are deliberately NOT the envelope's canonical rendering.
    wire = wire_override if wire_override is not None else envelope.canonical_bytes
    with patch.object(
        control_service, "_control_now", return_value=received_at or _NOW
    ):
        return record_observation(
            db,
            RecordObservationCommand(command_id=_cmd(), observation=wire),
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

        receipt = observation_receipts(db)[0]
        assert receipt.signed_evidence_status == "verified_at_receipt"
        assert receipt.authorization_id is not None
        assert receipt.authorization_plan_id is not None
        assert receipt.authorization_control_version == "0.1.0a10"
        assert receipt.authorization_envelope_digest is not None
        assert receipt.rollout_ref is not None
        assert receipt.operation == "deploy"
        assert receipt.plan_digest is not None
        assert receipt.descriptor_digest == _DESCRIPTOR
        assert receipt.execution_plan_digest == _EXECUTION_PLAN
        assert receipt.observed_revision == "git:0123456789abcdef"
        assert receipt.runtime_identity_kind == "oci_container"
        assert receipt.runtime_identity_identifier == "container:abcdef"
        assert receipt.outcome == "succeeded"
        assert receipt.observed_at == _NOW
        assert not hasattr(receipt, "payload")

    def test_a_quarantined_receipt_is_diagnosable_without_raw_payload(
        self, db, enrolled
    ) -> None:
        verdict = _observe(db, report_id="failed-diagnostic", outcome="failed")
        assert verdict.disposition == ObservationDisposition.EXECUTION_FAILED.value
        receipt = observation_receipts(db)[0]
        assert receipt.original_verdict == ObservationDisposition.EXECUTION_FAILED
        assert receipt.outcome == "failed"
        assert receipt.execution_sequence == 1
        assert receipt.attempt_no == 1
        assert receipt.observed_state_digest is not None
        assert receipt.signed_evidence_status == "verified_at_receipt"
        assert not hasattr(receipt, "payload")

    def test_same_key_id_signed_by_unenrolled_material_is_refused(
        self, db, enrolled
    ) -> None:
        verdict = _observe(
            db,
            _signer_public_key_b64=observation_public_key_b64(
                "attacker-reusing-key-id"
            ),
        )
        assert verdict.disposition == ObservationDisposition.BAD_SIGNATURE.value
        target = db.execute(select(DeploymentTarget)).scalar_one()
        assert target.observed_release_ref is None

    def test_signed_algorithm_must_equal_the_enrolled_algorithm(
        self, db, enrolled
    ) -> None:
        target, credential_id = enrolled
        credential = db.get(TargetCredential, credential_id)
        assert credential is not None
        credential.algorithm = "other-algorithm"
        db.flush()

        verdict = _observe(db)
        assert verdict.disposition == ObservationDisposition.BAD_SIGNATURE.value
        assert db.get(DeploymentTarget, target.id).observed_release_ref is None

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

    def test_there_is_no_projection_channel_left_to_contradict_the_bytes(
        self,
    ) -> None:
        """The refusal this replaces asserted `signed_report_mismatch` — a
        caller projection disagreeing with the signed bytes. That disposition
        is GONE, and this asserts why it could go: the command's whole input
        surface is one bytes value, so a projection cannot disagree with the
        body because a projection cannot be supplied at all. The comparison was
        removed by removing the second parameter, not by trusting the caller
        more.
        """
        import dataclasses

        fields = {f.name for f in dataclasses.fields(RecordObservationCommand)}
        assert fields == {"command_id", "observation", "actor_ref"}, fields
        assert not hasattr(ObservationDisposition, "SIGNED_REPORT_MISMATCH")
        with pytest.raises(ObservationRefusedError, match="exact wire BYTES"):
            RecordObservationCommand(command_id=_cmd(), observation="not-bytes")  # type: ignore[arg-type]


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
        # The statement claims a target nothing ever registered, signed with a
        # key that PROVES a different one. With the caller's projection gone
        # this is exactly the claim/proof contradiction, decided from the
        # signed bytes alone.
        verdict = _observe(
            db,
            authenticated_target_ref="tgt-ghost",
            claimed_target_ref="tgt-ghost",
            key_id="key-acme-1",
        )
        assert verdict.disposition == ObservationDisposition.TARGET_MISMATCH.value
        assert verdict.changed_state is False


class TestControlStoresTheBytesItVerified:
    def test_non_canonical_wire_bytes_are_stored_exactly_as_received(
        self, db, enrolled
    ) -> None:
        """Verify these bytes, store THESE bytes — even when they are not the
        rendering Control itself would produce.

        The wire value here is the same JSON document with whitespace the
        canonical encoder would never emit. The signature still verifies —
        it is over the statement's canonical bytes, which whitespace cannot
        move — so the report is ACCEPTED, and the attempt must hold the wire
        bytes verbatim with a digest over them. Storing the canonical
        re-rendering instead would be the verify-A-store-B split rebuilt
        INSIDE Control: evidence that verifies but is not what arrived.
        """
        target, _ = enrolled
        rollout_ref = _bound_rollout_ref(db, "tgt-acme-1")

        # Build the envelope exactly as the helper would, then reflow it.
        import json as _json

        probe = _observe(db, rollout_ref=rollout_ref)
        assert probe.disposition == ObservationDisposition.ACCEPTED.value
        canonical = db.get(ObservationReceipt, probe.receipt_id).payload  # type: ignore[union-attr]
        reflowed = _json.dumps(_json.loads(canonical), indent=2).encode()
        assert reflowed != canonical, "the reflow must actually change bytes"

        verdict = record_observation(
            db,
            RecordObservationCommand(command_id=_cmd(), observation=reflowed),
            observation_verifier=OBSERVATION_VERIFIER,
            authorization_verifier=VERIFIER,
        )
        # Same signed statement, same report id: a REPLAY, decided over the
        # canonical signed bytes — while the attempt row keeps the reflowed
        # wire exactly as received.
        assert verdict.disposition == ObservationDisposition.IDEMPOTENT_REPLAY.value
        attempt = observation_attempts(db)[-1]
        assert attempt.raw_body == reflowed
        assert attempt.raw_body_digest == (
            "sha256:" + hashlib.sha256(reflowed).hexdigest()
        )

    def test_an_oversize_body_is_truncated_stored_and_refused_as_malformed(
        self, db, enrolled
    ) -> None:
        """Bounded on admission, with the digest taken FIRST, over everything.

        The digest is computed before truncation so two oversize attempts that
        differ only past the bound remain distinguishable — the rule the
        attempt model has carried since V6, now enforced by the one place that
        can hold it because no caller supplies either value.
        """
        from dotmac_deployment_control import (
            MAX_EXECUTION_OBSERVATION_ENVELOPE_BYTES as MAX_BYTES,
        )

        wire = b'{"pad":"' + b"a" * MAX_BYTES + b'"}'
        verdict = record_observation(
            db,
            RecordObservationCommand(command_id=_cmd(), observation=wire),
            observation_verifier=OBSERVATION_VERIFIER,
            authorization_verifier=VERIFIER,
        )
        assert verdict.disposition == ObservationDisposition.MALFORMED.value
        attempt = observation_attempts(db)[-1]
        assert attempt.raw_body_truncated is True
        assert len(attempt.raw_body) == MAX_BYTES
        assert attempt.raw_body == wire[:MAX_BYTES]
        assert attempt.raw_body_digest == (
            "sha256:" + hashlib.sha256(wire).hexdigest()
        ), "the digest is over the FULL body, taken before the truncation"


# ── Eligibility ─────────────────────────────────────────────────────────────


class TestEligibilityIsATimelinePredicate:
    def test_enrolment_derives_fingerprint_and_refuses_malformed_key_bytes(
        self, db
    ) -> None:
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=_cmd(),
                target_ref="tgt-malformed-key",
                subject_ref="acme",
                product_code="dotmac_sub",
                environment="production",
            ),
        )
        with pytest.raises(DigestEncodingError):
            enrol_credential(
                db,
                EnrolCredentialCommand(
                    command_id=_cmd(),
                    target_id=target.id,
                    key_id="malformed-key",
                    algorithm="test-sha256",
                    public_key_b64="not+base64url",
                    enrollment_authority="platform_admin_policy",
                ),
            )

    def test_an_enrolled_key_id_cannot_be_rebound_to_other_material(
        self, db, enrolled
    ) -> None:
        target, _credential_id = enrolled
        with pytest.raises(TransitionRefusedError, match="already bound"):
            enrol_credential(
                db,
                EnrolCredentialCommand(
                    command_id=_cmd(),
                    target_id=target.id,
                    key_id="key-acme-1",
                    algorithm="test-sha256",
                    public_key_b64=observation_public_key_b64("different-key"),
                    enrollment_authority="platform_admin_policy",
                ),
            )

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
                algorithm="test-sha256",
                public_key_b64=observation_public_key_b64("key-acme-1"),
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

        with patch.object(
            control_service, "_control_now", return_value=_NOW + timedelta(hours=1)
        ):
            revoke_credential(
                db,
                CredentialTransitionCommand(
                    command_id=_cmd(),
                    credential_id=credential_id,
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
            CredentialTransitionCommand(command_id=_cmd(), credential_id=credential_id),
        )
        eligible, _ = credential_is_eligible(db, "key-acme-1", at=_NOW)
        assert eligible is False

    def test_an_unknown_key_is_never_eligible(self, db) -> None:
        eligible, target_ref = credential_is_eligible(db, "no-such-key", at=_NOW)
        assert eligible is False
        assert target_ref is None


# ── Idempotency ─────────────────────────────────────────────────────────────


class TestReplaysAndConflicts:
    def test_a_failed_execution_is_canonical_and_identical_bytes_replay_it(
        self, db, enrolled
    ) -> None:
        report_id = "rep-failed"
        first = _observe(db, report_id=report_id, outcome="failed")
        replay = _observe(db, report_id=report_id, outcome="failed")
        assert first.disposition == ObservationDisposition.EXECUTION_FAILED.value
        assert replay.disposition == ObservationDisposition.IDEMPOTENT_REPLAY.value
        assert replay.verdict == ObservationDisposition.EXECUTION_FAILED.value
        assert replay.receipt_id == first.receipt_id

    def test_failed_execution_cannot_be_retried_as_success(self, db, enrolled) -> None:
        report_id = "rep-failed-to-success"
        first = _observe(db, report_id=report_id, outcome="failed")
        changed = _observe(db, report_id=report_id, outcome="succeeded")
        assert first.disposition == ObservationDisposition.EXECUTION_FAILED.value
        assert changed.disposition == ObservationDisposition.CONFLICT.value
        assert changed.verdict == ObservationDisposition.EXECUTION_FAILED.value

    def test_an_authorization_mismatch_cannot_be_corrected_under_the_same_id(
        self, db, enrolled
    ) -> None:
        report_id = "rep-auth-mismatch"
        first = _observe(
            db,
            report_id=report_id,
            _statement_overrides={"authorization_control_version": "0.1.0a999"},
        )
        changed = _observe(db, report_id=report_id)
        assert first.disposition == ObservationDisposition.AUTHORIZATION_MISMATCH.value
        assert changed.disposition == ObservationDisposition.CONFLICT.value
        assert changed.verdict == ObservationDisposition.AUTHORIZATION_MISMATCH.value

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

    def test_a_later_credential_revocation_cannot_change_an_exact_replay(
        self, db, enrolled
    ) -> None:
        _target, credential_id = enrolled
        report_id = "rep-revoked-key-replay"
        first = _observe(db, report_id=report_id)
        revoke_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
                reason="rotate after the canonical arrival",
            ),
        )

        replay = _observe(db, report_id=report_id)

        assert first.disposition == ObservationDisposition.ACCEPTED.value
        assert replay.disposition == ObservationDisposition.IDEMPOTENT_REPLAY.value
        assert replay.verdict == ObservationDisposition.ACCEPTED.value
        assert replay.receipt_id == first.receipt_id
        replay_attempt = next(
            row for row in observation_attempts(db) if row.id == replay.attempt_id
        )
        assert (
            replay_attempt.eligibility_at_receipt
            == EligibilityAtReceipt.NOT_ELIGIBLE.value
        )

    def test_a_later_credential_revocation_cannot_hide_changed_report_bytes(
        self, db, enrolled
    ) -> None:
        _target, credential_id = enrolled
        report_id = "rep-revoked-key-conflict"
        first = _observe(db, report_id=report_id, observed_revision="git:canonical")
        revoke_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
                reason="rotate after the canonical arrival",
            ),
        )

        conflict = _observe(db, report_id=report_id, observed_revision="git:changed")

        assert first.disposition == ObservationDisposition.ACCEPTED.value
        assert conflict.disposition == ObservationDisposition.CONFLICT.value
        assert conflict.verdict == ObservationDisposition.ACCEPTED.value
        assert conflict.receipt_id == first.receipt_id
        conflict_attempt = next(
            row for row in observation_attempts(db) if row.id == conflict.attempt_id
        )
        assert (
            conflict_attempt.eligibility_at_receipt
            == EligibilityAtReceipt.NOT_ELIGIBLE.value
        )

    def test_a_quarantined_receipt_still_replays_after_credential_revocation(
        self, db, enrolled
    ) -> None:
        _target, credential_id = enrolled
        report_id = "rep-quarantine-revoked-key-replay"
        first = _observe(
            db,
            report_id=report_id,
            _statement_overrides={"authorization_control_version": "0.1.0a999"},
        )
        revoke_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
                reason="rotate after the quarantined arrival",
            ),
        )

        replay = _observe(
            db,
            report_id=report_id,
            _statement_overrides={"authorization_control_version": "0.1.0a999"},
        )

        assert first.disposition == ObservationDisposition.AUTHORIZATION_MISMATCH.value
        assert replay.disposition == ObservationDisposition.IDEMPOTENT_REPLAY.value
        assert replay.verdict == ObservationDisposition.AUTHORIZATION_MISMATCH.value
        assert replay.receipt_id == first.receipt_id
        replay_attempt = next(
            row for row in observation_attempts(db) if row.id == replay.attempt_id
        )
        assert (
            replay_attempt.eligibility_at_receipt
            == EligibilityAtReceipt.NOT_ELIGIBLE.value
        )

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

    def test_replay_compares_exact_payload_even_when_digest_text_matches(
        self, db, enrolled
    ) -> None:
        report_id = "rep-payload-not-digest"
        first = _observe(db, report_id=report_id)
        receipt = db.get(ObservationReceipt, first.receipt_id)
        assert receipt is not None
        original_digest = receipt.payload_digest
        receipt.payload = b'{"different":"canonical envelope bytes"}'
        db.flush()

        replay = _observe(db, report_id=report_id)
        assert receipt.payload_digest == original_digest
        assert replay.disposition == ObservationDisposition.CONFLICT.value
        assert replay.verdict == ObservationDisposition.ACCEPTED.value

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
                algorithm="test-sha256",
                public_key_b64=observation_public_key_b64("key-acme-2"),
                enrollment_authority="platform_admin_policy",
            ),
        )
        activate_credential(
            db,
            CredentialTransitionCommand(
                command_id=_cmd(),
                credential_id=credential_id,
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


class TestExecutionCoordinatesAreMonotonic:
    def _open_second_attempt(self, db: Session) -> Rollout:
        rollout = db.execute(select(Rollout)).scalar_one()
        settle_attempt(
            db,
            SettleAttemptCommand(
                command_id=_cmd(),
                rollout_id=rollout.id,
                attempt_no=1,
                outcome=AttemptOutcome.FAILED.value,
            ),
        )
        dispatch_attempt(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=VERIFIER,
        )
        return rollout

    def test_a_delayed_older_attempt_cannot_regress_newer_state(
        self, db, enrolled
    ) -> None:
        _bound_rollout_ref(db, "tgt-acme-1")
        rollout = self._open_second_attempt(db)
        newer = _observe(
            db,
            report_id="rep-newer",
            rollout_ref=rollout.rollout_ref,
            _statement_overrides={"observed_revision": "git:newer"},
        )
        older = _observe(
            db,
            report_id="rep-older",
            rollout_ref=rollout.rollout_ref,
            _statement_overrides={"attempt_no": 1, "observed_revision": "git:older"},
        )
        target = db.execute(select(DeploymentTarget)).scalar_one()
        assert newer.disposition == ObservationDisposition.ACCEPTED.value
        assert older.disposition == ObservationDisposition.STALE_OBSERVATION.value
        assert (target.last_execution_sequence, target.last_execution_attempt_no) == (
            1,
            2,
        )

    def test_older_then_newer_advances_twice_and_finishes_on_newer_state(
        self, db, enrolled
    ) -> None:
        _bound_rollout_ref(db, "tgt-acme-1")
        rollout = self._open_second_attempt(db)
        target = db.execute(select(DeploymentTarget)).scalar_one()
        starting_version = target.record_version

        older = _observe(
            db,
            report_id="rep-older-first",
            rollout_ref=rollout.rollout_ref,
            _statement_overrides={"attempt_no": 1, "observed_revision": "git:older"},
        )
        newer = _observe(
            db,
            report_id="rep-newer-second",
            rollout_ref=rollout.rollout_ref,
            _statement_overrides={"observed_revision": "git:newer"},
        )
        db.refresh(target)
        assert older.disposition == ObservationDisposition.ACCEPTED.value
        assert newer.disposition == ObservationDisposition.ACCEPTED.value
        assert target.record_version == starting_version + 2
        newer_receipt = db.execute(
            select(ObservationReceipt).where(
                ObservationReceipt.report_id == "rep-newer-second"
            )
        ).scalar_one()
        assert target.last_execution_state_digest == newer_receipt.observed_state_digest
        assert (target.last_execution_sequence, target.last_execution_attempt_no) == (
            1,
            2,
        )

    def test_newer_failure_blocks_an_older_success_from_projecting_state(
        self, db, enrolled
    ) -> None:
        _bound_rollout_ref(db, "tgt-acme-1")
        rollout = self._open_second_attempt(db)
        failed = _observe(
            db,
            report_id="rep-newer-failed",
            rollout_ref=rollout.rollout_ref,
            outcome="failed",
        )
        older = _observe(
            db,
            report_id="rep-older-success",
            rollout_ref=rollout.rollout_ref,
            _statement_overrides={"attempt_no": 1},
        )
        target = db.execute(select(DeploymentTarget)).scalar_one()
        assert failed.disposition == ObservationDisposition.EXECUTION_FAILED.value
        assert older.disposition == ObservationDisposition.STALE_OBSERVATION.value
        assert target.observed_release_ref is None
        assert (target.last_execution_sequence, target.last_execution_attempt_no) == (
            1,
            2,
        )

    def test_same_coordinate_and_same_substantive_state_is_no_change(
        self, db, enrolled
    ) -> None:
        rollout_ref = _bound_rollout_ref(db, "tgt-acme-1")
        first = _observe(db, report_id="same-state-a", rollout_ref=rollout_ref)
        second = _observe(db, report_id="same-state-b", rollout_ref=rollout_ref)
        assert first.disposition == ObservationDisposition.ACCEPTED.value
        assert first.changed_state is True
        assert second.disposition == ObservationDisposition.ACCEPTED.value
        assert second.changed_state is False

    def test_the_same_coordinate_with_different_state_is_a_conflict(
        self, db, enrolled
    ) -> None:
        rollout_ref = _bound_rollout_ref(db, "tgt-acme-1")
        first = _observe(
            db,
            report_id="rep-coordinate-a",
            rollout_ref=rollout_ref,
            _statement_overrides={"observed_revision": "git:first"},
        )
        conflict = _observe(
            db,
            report_id="rep-coordinate-b",
            rollout_ref=rollout_ref,
            _statement_overrides={"observed_revision": "git:second"},
        )
        assert first.disposition == ObservationDisposition.ACCEPTED.value
        assert (
            conflict.disposition
            == ObservationDisposition.EXECUTION_COORDINATE_CONFLICT.value
        )
        assert conflict.receipt_id is not None


class TestCallerInputsThatCannotBeUsed:
    def test_a_caller_cannot_supply_received_at(self, db, enrolled) -> None:
        """The instant deciding eligibility is stamped by Control, not the target."""
        with pytest.raises(TypeError, match="received_at"):
            RecordObservationCommand(  # type: ignore[call-arg]
                command_id=_cmd(),
                observation=b"{}",
                received_at=datetime(2026, 9, 1, 12, 0),
            )

    def test_a_caller_cannot_supply_a_digest_for_its_own_bytes(self) -> None:
        """The digest is DERIVED inside Control, so there is no field for one.

        A supplied digest is a claim about bytes, and a claim beside the bytes
        it describes is the verify-A-store-B split in miniature: nothing forces
        the two to agree. Control hashes what it was handed, full-length and
        before truncation, and the caller has nowhere to say otherwise.
        """
        with pytest.raises(TypeError, match="raw_body_digest"):
            RecordObservationCommand(  # type: ignore[call-arg]
                command_id=_cmd(),
                observation=b"{}",
                raw_body_digest="sha256:" + "ab" * 32,
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

    def test_observed_revision_comes_from_the_exact_authorized_plan(
        self, db, enrolled
    ) -> None:
        """Two plans can freeze identical product specs at different revisions.

        The signed authorization identifies which one executed; searching by
        spec digest would select the newer unexecuted plan and turn equal
        content into false execution evidence.
        """
        target, _ = enrolled
        executed_plan = self._rolled_out(db, target.id)
        executed_rollout = db.execute(
            select(Rollout).where(Rollout.plan_id == executed_plan.id)
        ).scalar_one()
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=target.id,
                desired=DesiredDeployment(
                    release_ref=_RELEASE,
                    spec=_SPEC,
                    images=[],
                ),
            ),
        )
        unexecuted_plan = propose_plan(
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
        assert executed_plan.desired_revision != unexecuted_plan.desired_revision

        verdict = _observe(db, rollout_ref=executed_rollout.rollout_ref)

        observed = get_target(db, target.id)
        receipt = observation_receipts(db)[0]
        assert verdict.disposition == ObservationDisposition.ACCEPTED.value
        assert observed is not None
        assert observed.observed_revision == executed_plan.desired_revision
        assert observed.observed_revision != unexecuted_plan.desired_revision
        assert receipt.authorization_plan_id == str(executed_plan.id)

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
        """A bound execution can still report bytes matching no known plan."""
        target, _ = enrolled
        self._rolled_out(db, target.id)
        # WELL-FORMED and unmatched. `"sha256:unrecognised"` used to stand in
        # here, and since `0.1.0a5` that value is not a readable digest at all —
        # it would exercise the encoding path and report no revision for the
        # wrong reason, which is a test passing by accident.
        verdict = _observe(db, observed_spec_digest=spec_digest({"never": "planned"}))
        view = get_target(db, target.id)
        report = drift(db, target.id)
        assert verdict.disposition == ObservationDisposition.ACCEPTED.value
        assert view is not None
        assert view.observed_revision is None
        assert report is not None
        assert report.drifted is True

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
        wire = b'{"statement":{},"signature":"x"}'
        verdict = record_observation(
            db,
            RecordObservationCommand(command_id=_cmd(), observation=wire),
            observation_verifier=OBSERVATION_VERIFIER,
            authorization_verifier=VERIFIER,
        )
        assert verdict.disposition == ObservationDisposition.MALFORMED.value
        assert verdict.changed_state is False
        attempts = observation_attempts(db)
        assert len(attempts) == 1
        # THE SAME BYTES, and a digest Control derived. The attempt holds the
        # exact wire value — not a canonical re-rendering, not a caller copy —
        # and its digest is over those bytes, because no other digest was ever
        # in the room.
        assert attempts[0].raw_body == wire
        assert attempts[0].raw_body_digest == (
            "sha256:" + hashlib.sha256(wire).hexdigest()
        )
        assert attempts[0].raw_body_truncated is False
        # Identity fields are parsed EVIDENCE; a body that did not parse into a
        # statement leaves none, rather than whatever a caller typed.
        assert attempts[0].key_id is None
        assert attempts[0].report_id is None
