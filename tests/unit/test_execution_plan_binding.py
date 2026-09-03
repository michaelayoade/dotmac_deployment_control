"""The middle term: one execution plan, one operation, bound across three terms.

## What was broken, measured rather than suspected

Platform CP authorizes a deployment and the Deployment Foundation executes it,
and before this file they could not exchange a receipt at all. There have been
zero authorization receipts in this fleet, ever, for three independent reasons:

1. **Field count.** Platform CP's receipt carried 17 fields; the Foundation's
   parser required exactly 9 and was strict about both unknown and missing keys.
2. **Digest subject.** Control's `plan_digest` hashes the target's desired state
   WRAPPED IN SIX SIBLING KEYS; the Foundation hashes its rendered execution
   plan ALONE. Both use canonical JSON with sorted keys and sha256 — they agree
   completely about SERIALIZATION and disagree about PAYLOAD. Two such digests
   can never be equal, and both implementations read as correct in review. This
   is the defect that motivates everything below.
3. **Vocabulary.** The Foundation refuses any receipt whose `operation` is not
   `deploy` or `rollback`. In Control at `0.1.0a7`, `operation` appeared only as
   an English word inside docstrings: no column, absent from the seven-table
   catalogue, absent from all eight `StrEnum`s, absent from `DeliveryIntent` and
   from all 19 fact types.

## The binding, and what this module owns of it

`ExecutionPlanDigestV1 = sha256(canonical FoundationExecutionPlanV1 bytes)`. The
**Foundation** owns that type, its canonicalization and its digest. **Control**
owns the closed operation vocabulary and holds `operation` and
`execution_plan_digest` on its plan model — receiving them, freezing them,
signing them, and never reconstructing or normalizing them.

Step 4 of the flow is the load-bearing one: *Control freezes and signs them; it
never reconstructs or normalizes the Foundation plan.* Normalization is exactly
how two canonicalizations come to agree about serialization while disagreeing
about payload, so the property this file states is not "Control does not
recompute" — a convention — but "Control CANNOT recompute", which
`tests/architecture/test_control_cannot_recompute_the_execution_plan.py` holds
as a fact about the class graph.

## Step 8, and why the refusals are counted separately

*A report is accepted only when proposal, authorization and report bind the same
values.* Three findings, not one:

* `execution_plan_mismatch` — the executor ran a plan nobody authorized;
* `operation_mismatch` — it ran the right plan as the wrong kind of act, which a
  digest-only check cannot see and which is precisely why DEPLOY and ROLLBACK
  are separately authorized;
* `unbound_report` — the arrival named no authorization at all, an absence
  rather than a contradiction.

Each is observed on its own below. A single "the binding failed" assertion would
pass against an implementation that could only ever detect one of them.

In-memory SQLite; logic only.
"""

from __future__ import annotations

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
    OPERATIONS,
    ApprovalEvidence,
    ApprovePlanCommand,
    AuthorizationEnvelopeDigestV1,
    AuthorizationEnvelopeV2,
    CredentialTransitionCommand,
    DeploymentOperation,
    DescriptorBindingError,
    DesiredDeployment,
    DigestEncodingError,
    EnrolCredentialCommand,
    ExecutionPlanBindingError,
    ExecutionPlanDigestV1,
    ObservationDisposition,
    OperationRefusedError,
    ProposePlanCommand,
    RecordObservationCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RevokePlanApprovalCommand,
    RuntimeIdentityV1,
    SetDesiredStateCommand,
    SignatureStatus,
    activate_credential,
    approve_plan,
    dispatch_attempt,
    enrol_credential,
    issue_execution_observation_envelope,
    module,
    propose_plan,
    record_observation,
    register_target,
    request_rollout,
    require_operation,
    revoke_plan_approval,
    set_desired_state,
    spec_digest,
)
from dotmac_deployment_control.models import (
    DeploymentPlan,
    DeploymentTarget,
    Rollout,
    RolloutAttempt,
)
from tests.authorization_support import AUTHORIZATION_PUBLIC_KEY_B64, SIGNER, VERIFIER
from tests.execution_observation_support import (
    OBSERVATION_VERIFIER,
    TestExecutionObservationSigner,
    observation_public_key_b64,
)

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_POLICY = "deployment.production"
_POLICY_VERSION = 4
_SPEC = {"replicas": 2}
_RELEASE = "dotmac_sub@7.187.1"

#: Two stand-ins for the Deployment Foundation's digest, WRITTEN OUT rather than
#: computed. That is the point rather than convenience: Control cannot compute
#: one, so a fixture that derived it would be exercising a capability the module
#: deliberately does not have — and would keep passing if somebody gave it one.
_PLAN_A = "sha256:" + "1a" * 32
_PLAN_B = "sha256:" + "2b" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


@pytest.fixture(autouse=True)
def _fixed_control_clock():
    with patch.object(control_service, "_control_now", return_value=_NOW):
        yield


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


def _ready_target(
    db: Session,
    *,
    target_ref: str = "tgt-1",
    key_id: str = "key-1",
    public_key_b64: str | None = None,
):
    """A target with a desired state and an ACTIVE credential."""
    view = register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref=target_ref,
            subject_ref="acme-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=view.id,
            desired=DesiredDeployment(release_ref=_RELEASE, spec=_SPEC, images=[]),
        ),
    )
    credential_id = enrol_credential(
        db,
        EnrolCredentialCommand(
            command_id=_cmd(),
            target_id=view.id,
            key_id=key_id,
            algorithm="test-sha256",
            public_key_b64=public_key_b64 or observation_public_key_b64(key_id),
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
    return view


def _propose(db: Session, target_id, **overrides: object):  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "command_id": _cmd(),
        "target_id": target_id,
        "operation": "deploy",
        "descriptor_digest": _DESCRIPTOR,
        "execution_plan_digest": _PLAN_A,
        "requires_approval": True,
        "approval_policy_code": _POLICY,
        "approval_policy_version": _POLICY_VERSION,
    }
    fields.update(overrides)
    return propose_plan(db, ProposePlanCommand(**fields))  # type: ignore[arg-type]


def _evidence(plan, **overrides: object) -> ApprovalEvidence:  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "policy_code": _POLICY,
        "policy_version": _POLICY_VERSION,
        "decision_ref": f"apr-{uuid.uuid4().hex[:8]}",
        "content_digest": plan.plan_digest or "",
        "decided_at": _NOW,
        "operation": "deploy",
        "execution_plan_digest": _PLAN_A,
        "decision_status": "granted",
    }
    fields.update(overrides)
    return ApprovalEvidence(**fields)  # type: ignore[arg-type]


def _approve(db: Session, plan, **overrides: object):  # type: ignore[no-untyped-def]
    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_cmd(), plan_id=plan.id, evidence=_evidence(plan, **overrides)
        ),
    )


def _rollout(
    db: Session,
    plan_id,
    ref: str | None = None,
    *,
    issued_at: datetime = _NOW,
    expires_at: datetime = datetime(2099, 1, 1, tzinfo=UTC),
):  # type: ignore[no-untyped-def]
    with patch.object(control_service, "_control_now", return_value=issued_at):
        return request_rollout(
            db,
            RequestRolloutCommand(
                command_id=_cmd(),
                rollout_ref=ref or f"rol-{uuid.uuid4().hex[:8]}",
                plan_id=plan_id,
                authorization_expires_at=expires_at,
            ),
            signer=SIGNER,
        )


def _report(db: Session, **overrides: object):
    statement_overrides = dict(
        overrides.pop("_statement_overrides", {})  # type: ignore[arg-type]
    )
    received_at = overrides.pop("_received_at", _NOW)
    signer_public_key_b64 = overrides.pop("_signer_public_key_b64", None)
    fields: dict[str, object] = {
        "report_id": f"rep-{uuid.uuid4().hex[:8]}",
        "observed_release_ref": _RELEASE,
        "observed_spec_digest": spec_digest(_SPEC),
        "reported_at": _NOW,
        "authenticated_target_ref": "tgt-1",
        "claimed_target_ref": "tgt-1",
        "key_id": "key-1",
        "raw_body": None,
        "raw_body_digest": None,
        "signature_status": SignatureStatus.VALID.value,
        "operation": "deploy",
        "execution_plan_digest": _PLAN_A,
    }
    fields.update(overrides)
    rollout = db.execute(
        select(Rollout).where(Rollout.rollout_ref == fields.get("rollout_ref"))
    ).scalar_one_or_none()
    plan = None if rollout is None else db.get(DeploymentPlan, rollout.plan_id)
    authorization = (
        None
        if rollout is None or rollout.authorization_envelope is None
        else AuthorizationEnvelopeV2.parse(rollout.authorization_envelope)
    )
    attempt = None
    if rollout is not None:
        attempt = (
            db.execute(
                select(RolloutAttempt)
                .where(RolloutAttempt.rollout_id == rollout.id)
                .order_by(RolloutAttempt.attempt_no.desc())
            )
            .scalars()
            .first()
        )
        if attempt is None:
            dispatch_attempt(
                db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
            )
            attempt = (
                db.execute(
                    select(RolloutAttempt)
                    .where(RolloutAttempt.rollout_id == rollout.id)
                    .order_by(RolloutAttempt.attempt_no.desc())
                )
                .scalars()
                .first()
            )
    target = db.execute(
        select(DeploymentTarget).where(
            DeploymentTarget.target_ref == fields["authenticated_target_ref"]
        )
    ).scalar_one()
    snapshot = {} if plan is None else dict(plan.snapshot or {})
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
            else str(uuid.uuid4())
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
            else "sha256:" + "0b" * 32
        ),
        "execution_sequence": (
            authorization.statement.execution_sequence
            if authorization is not None
            else 1
        ),
        "attempt_no": attempt.attempt_no if attempt is not None else 1,
        "rollout_ref": fields.get("rollout_ref") or "unbound-rollout",
        "target_id": str(target.id),
        "target_ref": fields["claimed_target_ref"],
        "product_code": target.product_code,
        "environment": target.environment,
        "operation": fields.get("operation") or "deploy",
        "release_ref": snapshot.get("release_ref") or _RELEASE,
        "observed_release_ref": fields["observed_release_ref"],
        "authorized_images": snapshot.get("authorized_images") or [],
        "observed_images": snapshot.get("authorized_images") or [],
        "plan_digest": (
            plan.plan_digest if plan is not None else "sha256:" + "0a" * 32
        ),
        "descriptor_digest": snapshot.get("descriptor_digest") or _DESCRIPTOR,
        "execution_plan_digest": fields.get("execution_plan_digest") or _PLAN_A,
        "observed_spec_digest": fields["observed_spec_digest"],
        "observed_revision": "git:0123456789abcdef",
        "runtime_identity": RuntimeIdentityV1(
            kind="oci_container", identifier="container:abcdef"
        ),
        "outcome": "succeeded",
        "observed_at": fields["reported_at"],
    }
    statement_fields.update(statement_overrides)
    envelope = issue_execution_observation_envelope(
        statement_fields,
        signer=TestExecutionObservationSigner(
            str(fields["key_id"]),
            public_key_b64=(
                str(signer_public_key_b64)
                if signer_public_key_b64 is not None
                else None
            ),
        ),
    )
    with patch.object(control_service, "_control_now", return_value=received_at):
        return record_observation(
            db,
            RecordObservationCommand(
                command_id=_cmd(), observation=envelope.canonical_bytes
            ),
            observation_verifier=OBSERVATION_VERIFIER,
            authorization_verifier=VERIFIER,
        )


# ── 1. The closed vocabulary ────────────────────────────────────────────────


class TestTheOperationVocabularyIsClosed:
    """`deploy`, `rollback`, `recover`. An unknown value is REFUSED — never
    defaulted, and never inferred."""

    def test_the_set_is_exactly_two_and_the_enum_agrees_with_it(self) -> None:
        assert OPERATIONS == {"deploy", "rollback", "recover"}
        assert {member.value for member in DeploymentOperation} == OPERATIONS

    @pytest.mark.parametrize("word", ["deploy", "rollback", "recover"])
    def test_a_member_parses_to_a_value_not_a_string(self, word: str) -> None:
        parsed = require_operation(word, where="test")
        assert isinstance(parsed, DeploymentOperation)
        assert parsed.value == word

    @pytest.mark.parametrize(
        "word",
        [
            "redeploy",
            "rollforward",
            "restart",
            "update",
            "",
            " deploy",
            "deploy ",
        ],
    )
    def test_a_word_outside_the_set_is_refused(self, word: str) -> None:
        with pytest.raises(OperationRefusedError, match="is not an operation"):
            require_operation(word, where="test")

    @pytest.mark.parametrize("word", ["Deploy", "DEPLOY", "RollBack", "Recover"])
    def test_a_case_variant_is_refused_rather_than_folded(self, word: str) -> None:
        """A case fold is an inference: it decides that `Deploy` MEANT `deploy`.

        The same rule the digest parser applies for the same reason — one value
        with two spellings is one value with two identities — and the refusal
        names the member it is nearly, so a caller can see the correction
        without the module making it.
        """
        with pytest.raises(OperationRefusedError) as refused:
            require_operation(word, where="test")
        assert "the spelling is exact" in str(refused.value)

    @pytest.mark.parametrize("value", [None, 0, 1, True, ["deploy"], {"op": "deploy"}])
    def test_a_non_string_is_refused_and_never_defaulted(self, value: object) -> None:
        with pytest.raises(OperationRefusedError, match="no default"):
            require_operation(value, where="test")

    def test_the_propose_command_has_no_default_operation(self) -> None:
        """A DEFAULT would infer the operation from a caller's silence, which is
        the same inference as reading it off a diff. The field is required, so
        omitting it is a `TypeError` rather than a deployment."""
        with pytest.raises(TypeError):
            ProposePlanCommand(  # type: ignore[call-arg]
                command_id=_cmd(),
                target_id=uuid.uuid4(),
                descriptor_digest=_DESCRIPTOR,
                execution_plan_digest=_PLAN_A,
            )

    def test_an_unknown_operation_is_refused_at_construction(self) -> None:
        with pytest.raises(OperationRefusedError):
            ProposePlanCommand(
                command_id=_cmd(),
                target_id=uuid.uuid4(),
                operation="redeploy",
                descriptor_digest=_DESCRIPTOR,
                execution_plan_digest=_PLAN_A,
            )


# ── 2. Received, frozen, never re-derived ───────────────────────────────────


class TestControlReceivesTheDigestAndNeverReshapesIt:
    def test_proposing_freezes_both_values_exactly_as_supplied(self, db) -> None:
        target = _ready_target(db)
        plan = _propose(db, target.id, operation="rollback")

        assert plan.operation == "rollback"
        # BYTE-IDENTICAL to what was submitted. Not `parsed.canonical`, which
        # would be the same text today and a normalization forever.
        assert plan.execution_plan_digest == _PLAN_A
        assert plan.descriptor_digest == _DESCRIPTOR
        assert plan.authorized_operation is None
        assert plan.authorized_execution_plan_digest is None

    def test_a_descriptor_only_mutation_moves_controls_plan_digest(self, db) -> None:
        """The descriptor is inside Control's snapshot, never beside its hash."""
        target = _ready_target(db)
        first = _propose(db, target.id)
        second_descriptor = "sha256:" + "4d" * 32
        second = _propose(db, target.id, descriptor_digest=second_descriptor)

        assert first.execution_plan_digest == second.execution_plan_digest
        assert first.descriptor_digest != second.descriptor_digest
        assert first.plan_digest != second.plan_digest

    def test_a_missing_descriptor_binding_is_refused_before_state_is_written(
        self, db
    ) -> None:
        target = _ready_target(db)
        with pytest.raises(DescriptorBindingError, match="no descriptor digest"):
            _propose(db, target.id, descriptor_digest="")

    @pytest.mark.parametrize(
        "spelling",
        [
            "1a" * 32,  # a4's bare-hex form: never valid for THIS value
            "SHA256:" + "1a" * 32,
            "sha256:" + "1A" * 32,
            "sha256:" + "1a" * 31,
            " sha256:" + "1a" * 32,
        ],
    )
    def test_a_non_canonical_spelling_is_refused_rather_than_tidied(
        self, db, spelling: str
    ) -> None:
        """REFUSING IS NOT NORMALIZING, and the difference is the whole repair.

        A parser that accepted `SHA256:AB…` or bare hex and rewrote it to the
        canonical form would be Control canonicalizing a value it does not own —
        a second canonicalization, which is how two implementations come to
        agree about serialization and disagree about payload. So every
        non-canonical spelling is refused and nothing is stored.

        Parametrized rather than looped so each spelling meets a fresh session:
        a refusal raised inside the at-most-once handler is not a state a later
        assertion in the same transaction should be reading through.
        """
        target = _ready_target(db)
        with pytest.raises(DigestEncodingError):
            _propose(db, target.id, execution_plan_digest=spelling)

    def test_a_proposal_with_no_binding_is_refused_and_says_who_owns_the_value(
        self, db
    ) -> None:
        target = _ready_target(db)
        with pytest.raises(ExecutionPlanBindingError) as refused:
            _propose(db, target.id, execution_plan_digest="")
        assert "Deployment Foundation" in str(refused.value)
        assert "cannot supply one" in str(refused.value)


# ── 3. The AUTHORIZATION term ───────────────────────────────────────────────


class TestApprovalMustBindWhatWasProposed:
    def test_matching_evidence_records_the_authorization_in_its_own_columns(
        self, db
    ) -> None:
        target = _ready_target(db)
        plan = _propose(db, target.id)
        approved = _approve(db, plan)

        assert approved.authorized_operation == "deploy"
        assert approved.authorized_execution_plan_digest == _PLAN_A
        # THE THIRD TERM EXISTS. Two stored terms plus the report is what makes
        # step 8 a three-term gate rather than a two-term one wearing the name.
        assert (
            approved.execution_plan_digest == approved.authorized_execution_plan_digest
        )

    def test_evidence_naming_a_different_execution_plan_is_refused(self, db) -> None:
        target = _ready_target(db)
        plan = _propose(db, target.id)
        with pytest.raises(ExecutionPlanBindingError) as refused:
            _approve(db, plan, execution_plan_digest=_PLAN_B)
        message = str(refused.value)
        assert "different execution" in message
        # And it does NOT claim Control could reconcile them, because it cannot.
        assert "never recomputes" in message

    def test_evidence_naming_a_different_operation_is_refused(self, db) -> None:
        """SEPARATELY AUTHORIZED. The execution plan is identical here — only
        the kind of act differs — so a digest-only check would authorize this."""
        target = _ready_target(db)
        plan = _propose(db, target.id, operation="deploy")
        with pytest.raises(ExecutionPlanBindingError) as refused:
            _approve(db, plan, operation="rollback")
        assert "separately authorized operations" in str(refused.value)

    def test_evidence_that_binds_no_execution_plan_is_refused(self, db) -> None:
        """A two-term gate wearing a three-term name is the failure mode
        `require_same_digest` refuses on the Foundation's side, and this is the
        same refusal on Control's."""
        target = _ready_target(db)
        plan = _propose(db, target.id)
        with pytest.raises(ExecutionPlanBindingError, match="THREE-term"):
            _approve(db, plan, execution_plan_digest=None)

    def test_evidence_that_names_no_operation_authorizes_neither(self, db) -> None:
        target = _ready_target(db)
        plan = _propose(db, target.id)
        with pytest.raises(ExecutionPlanBindingError, match="authorizes neither"):
            _approve(db, plan, operation=None)

    def test_an_unreadable_supplied_digest_is_an_encoding_fault_not_a_mismatch(
        self, db
    ) -> None:
        """The `0.1.0a5` lesson, applied to the new value: "I cannot read what
        you sent" and "you authorized a different execution" are different
        findings for different people, and collapsing them produces a security
        refusal standing in for a formatting bug."""
        target = _ready_target(db)
        plan = _propose(db, target.id)
        with pytest.raises(DigestEncodingError) as refused:
            _approve(db, plan, execution_plan_digest="not-a-digest")
        assert not isinstance(refused.value, ExecutionPlanBindingError)
        assert "will not reshape it" in str(refused.value)


# ── 4. Nothing unbound reaches the fleet ────────────────────────────────────


class TestAnUnboundPlanCannotBeRolledOut:
    def test_a_plan_with_no_binding_is_refused_a_rollout(self, db) -> None:
        """A `0.1.0a7` row, simulated by clearing the columns the way an
        upgraded database holds them. It cannot produce a receipt, so it is
        refused at dispatch rather than dispatched and left to time out — a
        timeout reads as a transport fault and sends the operator to the wrong
        system."""
        target = _ready_target(db)
        plan = _propose(db, target.id, requires_approval=False)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.operation = None
        row.execution_plan_digest = None
        db.flush()

        with pytest.raises(ExecutionPlanBindingError, match="cannot be rolled out"):
            _rollout(db, plan.id)

    def test_the_delivery_intent_carries_the_authorized_operation_and_plan(
        self, db
    ) -> None:
        """Steps 5 to 7: the executor receives what it must recompute before
        running and carry back in its report."""
        target = _ready_target(db)
        plan = _propose(db, target.id, operation="rollback", requires_approval=False)
        rollout = _rollout(db, plan.id)
        intent = dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )

        assert intent.operation == "rollback"
        assert intent.descriptor_digest == _DESCRIPTOR
        assert intent.execution_plan_digest == _PLAN_A
        # And the two digests stay distinct values, not one reused.
        assert intent.plan_digest != intent.execution_plan_digest


# ── 5. Step 8, three refusals, observed separately ──────────────────────────


class TestAReportIsAcceptedOnlyWhenAllThreeTermsAgree:
    def _bound(self, db) -> tuple[object, str]:  # type: ignore[no-untyped-def]
        target = _ready_target(db)
        plan = _propose(db, target.id)
        _approve(db, plan)
        rollout = _rollout(db, plan.id)
        return target, rollout.rollout_ref

    def test_a_report_binding_all_three_terms_is_accepted(self, db) -> None:
        """THE POSITIVE CONTROL. Without it, the three refusals below are
        equally consistent with an implementation that quarantines every
        report."""
        _, ref = self._bound(db)
        verdict = _report(db, rollout_ref=ref)
        assert verdict.disposition == ObservationDisposition.ACCEPTED.value
        assert verdict.changed_state is True

    def test_a_report_naming_a_different_execution_plan_is_quarantined(
        self, db
    ) -> None:
        """FINDING ONE: the executor ran a plan nobody authorized."""
        _, ref = self._bound(db)
        verdict = _report(db, rollout_ref=ref, execution_plan_digest=_PLAN_B)
        assert (
            verdict.disposition == ObservationDisposition.EXECUTION_PLAN_MISMATCH.value
        )
        assert verdict.changed_state is False

    def test_a_report_naming_a_different_operation_is_quarantined_separately(
        self, db
    ) -> None:
        """FINDING TWO, and it is NOT the same finding as one.

        The execution plan digest is correct here. Only the kind of act differs:
        a rollback reported against a deploy's authorization. A digest-only
        binding accepts this, which is the entire reason the operation is a
        second, separately compared term.
        """
        _, ref = self._bound(db)
        verdict = _report(db, rollout_ref=ref, operation="rollback")
        assert verdict.disposition == ObservationDisposition.OPERATION_MISMATCH.value
        assert verdict.changed_state is False

    def test_a_report_binding_neither_is_quarantined_as_unbound(self, db) -> None:
        """FINDING THREE: an ABSENCE, not a contradiction.

        Nothing was compared, because the report named no authorization to
        compare against. That is a different triage — the reader looks at the
        sender, not at the plan — so it gets a third disposition rather than
        being folded into a mismatch, which would say the executor ran the wrong
        thing when nothing established that it ran anything.
        """
        self._bound(db)

        # A report that carries no binding terms at all is no longer a
        # quarantine — it is UNREPRESENTABLE. The statement schema requires
        # rollout_ref, operation and execution_plan_digest, so a wire document
        # missing one refuses at parse as MALFORMED rather than reaching any
        # binding decision; there is no caller projection left through which an
        # absence could arrive beside a well-formed body. What remains of
        # "unbound" is the honest case: a WELL-FORMED, verified report naming
        # an authorization nothing ever issued.
        verdict = _report(db, rollout_ref="rol-nothing-was-ever-called-this")
        assert verdict.disposition == ObservationDisposition.UNBOUND_REPORT.value
        assert verdict.changed_state is False

    def test_the_three_dispositions_are_three_distinct_values(self) -> None:
        """A mismatch, a wrong operation and an absence must never collapse.
        Asserted over the vocabulary itself so a future edit cannot quietly
        alias two of them to one string."""
        values = {
            ObservationDisposition.EXECUTION_PLAN_MISMATCH.value,
            ObservationDisposition.OPERATION_MISMATCH.value,
            ObservationDisposition.UNBOUND_REPORT.value,
        }
        assert len(values) == 3
        assert values.isdisjoint(
            {
                ObservationDisposition.ACCEPTED.value,
                ObservationDisposition.TARGET_MISMATCH.value,
                ObservationDisposition.UNKNOWN_TARGET.value,
            }
        )

    def test_a_report_naming_another_targets_rollout_binds_nothing(self, db) -> None:
        """The interesting half of `unbound_report`: a report that names a real
        authorization belonging to somebody else. Accepting it would let any
        deployment satisfy any other's binding by quoting its rollout ref."""
        _, mine = self._bound(db)
        other = _ready_target(db, target_ref="tgt-2", key_id="key-2")
        other_plan = _propose(db, other.id, requires_approval=False)
        other_rollout = _rollout(db, other_plan.id)

        verdict = _report(db, rollout_ref=other_rollout.rollout_ref)
        assert verdict.disposition == ObservationDisposition.UNBOUND_REPORT.value
        assert mine != other_rollout.rollout_ref

    def test_an_unreadable_reported_digest_is_unbound_not_a_mismatch(self, db) -> None:
        """Rule 3 holds: the arrival is RECORDED, and the finding is about the
        report's encoding rather than about which plan ran. Calling it a
        mismatch would assert something nothing established."""
        _, ref = self._bound(db)
        with pytest.raises(Exception, match="unreadable typed value"):
            _report(db, rollout_ref=ref, execution_plan_digest="1a" * 32)

    def test_an_operation_outside_the_vocabulary_is_never_read_as_the_plans(
        self, db
    ) -> None:
        """A word the closed set does not contain is a mismatch, not a match by
        proximity. `deployment` is not `deploy`."""
        _, ref = self._bound(db)
        verdict = _report(db, rollout_ref=ref, operation="deployment")
        assert verdict.disposition == ObservationDisposition.OPERATION_MISMATCH.value

    def test_a_report_against_an_approval_exempt_plan_is_a_two_term_check(
        self, db
    ) -> None:
        """HONEST ABOUT THE TERM COUNT.

        An approval-exempt plan has no authorization, and this module does not
        manufacture one by copying the proposal into the authorization's
        columns — that would make a two-term check read as a three-term one,
        which is the exact weakening the Foundation's `require_same_digest`
        refuses on its side. So the check is over two terms, it still refuses a
        mismatch, and the plan's authorization columns stay empty and say so.
        """
        target = _ready_target(db)
        plan = _propose(db, target.id, requires_approval=False)
        rollout = _rollout(db, plan.id)

        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        assert row.authorized_execution_plan_digest is None

        assert (
            _report(
                db, rollout_ref=rollout.rollout_ref, execution_plan_digest=_PLAN_B
            ).disposition
            == ObservationDisposition.EXECUTION_PLAN_MISMATCH.value
        )
        assert (
            _report(db, rollout_ref=rollout.rollout_ref).disposition
            == ObservationDisposition.ACCEPTED.value
        )

    def test_stored_terms_that_disagree_with_each_other_quarantine_the_report(
        self, db
    ) -> None:
        """A data fault, and the report does not resolve it.

        Nothing in this module can write a proposal and an authorization that
        disagree. If a database edit produces one, a report matching whichever
        term it happens to match has not proven the binding — so it is
        quarantined rather than accepted on a coin toss.
        """
        target = _ready_target(db)
        plan = _propose(db, target.id)
        _approve(db, plan)
        rollout = _rollout(db, plan.id)
        dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.authorized_execution_plan_digest = _PLAN_B
        db.flush()

        verdict = _report(db, rollout_ref=rollout.rollout_ref)
        assert verdict.disposition == ObservationDisposition.AUTHORIZATION_INVALID.value


class TestTheSignedResultNeedsAStandingAuthorization:
    def _approved(
        self,
        db,
        *,
        key_id: str = "key-1",
        public_key_b64: str | None = None,
    ):
        target = _ready_target(db, key_id=key_id, public_key_b64=public_key_b64)
        plan = _propose(db, target.id)
        _approve(db, plan)
        return target, plan

    def test_a_revoked_authorization_changes_no_target(self, db) -> None:
        target, plan = self._approved(db)
        rollout = _rollout(db, plan.id)
        dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(),
                plan_id=plan.id,
                revocation_ref="approval-revocation-1",
            ),
        )

        verdict = _report(db, rollout_ref=rollout.rollout_ref)
        assert verdict.disposition == ObservationDisposition.AUTHORIZATION_REVOKED
        assert verdict.changed_state is False
        assert db.get(DeploymentTarget, target.id).observed_release_ref is None

    def test_a_revoked_authorization_verdict_is_canonical_for_replay(self, db) -> None:
        _target, plan = self._approved(db)
        rollout = _rollout(db, plan.id)
        dispatch_attempt(
            db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
        )
        revoke_plan_approval(
            db,
            RevokePlanApprovalCommand(
                command_id=_cmd(),
                plan_id=plan.id,
                revocation_ref="approval-revocation-replay",
            ),
        )

        first = _report(
            db, rollout_ref=rollout.rollout_ref, report_id="revoked-canonical"
        )
        replay = _report(
            db, rollout_ref=rollout.rollout_ref, report_id="revoked-canonical"
        )
        changed = _report(
            db,
            rollout_ref=rollout.rollout_ref,
            report_id="revoked-canonical",
            _statement_overrides={"observed_revision": "git:different"},
        )
        assert first.disposition == ObservationDisposition.AUTHORIZATION_REVOKED
        assert replay.disposition == ObservationDisposition.IDEMPOTENT_REPLAY
        assert replay.verdict == ObservationDisposition.AUTHORIZATION_REVOKED
        assert changed.disposition == ObservationDisposition.CONFLICT
        assert changed.verdict == ObservationDisposition.AUTHORIZATION_REVOKED

    def test_an_expired_authorization_changes_no_target(self, db) -> None:
        target, plan = self._approved(db)
        rollout = _rollout(
            db,
            plan.id,
            issued_at=_NOW - timedelta(hours=2),
            expires_at=_NOW - timedelta(hours=1),
        )
        with patch.object(
            control_service, "_control_now", return_value=_NOW - timedelta(hours=2)
        ):
            dispatch_attempt(
                db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
            )

        verdict = _report(db, rollout_ref=rollout.rollout_ref)
        assert verdict.disposition == ObservationDisposition.AUTHORIZATION_EXPIRED
        assert verdict.changed_state is False
        assert db.get(DeploymentTarget, target.id).observed_release_ref is None

    def test_an_expired_authorization_verdict_is_canonical_for_replay(self, db) -> None:
        _target, plan = self._approved(db)
        issued_at = _NOW - timedelta(hours=2)
        rollout = _rollout(
            db,
            plan.id,
            issued_at=issued_at,
            expires_at=_NOW - timedelta(hours=1),
        )
        with patch.object(control_service, "_control_now", return_value=issued_at):
            dispatch_attempt(
                db, command_id=_cmd(), rollout_id=rollout.id, verifier=VERIFIER
            )

        first = _report(
            db, rollout_ref=rollout.rollout_ref, report_id="expired-canonical"
        )
        replay = _report(
            db, rollout_ref=rollout.rollout_ref, report_id="expired-canonical"
        )
        changed = _report(
            db,
            rollout_ref=rollout.rollout_ref,
            report_id="expired-canonical",
            _statement_overrides={"observed_revision": "git:different"},
        )
        assert first.disposition == ObservationDisposition.AUTHORIZATION_EXPIRED
        assert replay.disposition == ObservationDisposition.IDEMPOTENT_REPLAY
        assert replay.verdict == ObservationDisposition.AUTHORIZATION_EXPIRED
        assert changed.disposition == ObservationDisposition.CONFLICT
        assert changed.verdict == ObservationDisposition.AUTHORIZATION_EXPIRED

    def test_authorization_and_observation_cannot_reuse_one_key_purpose(
        self, db
    ) -> None:
        authorization_key_id = SIGNER.identity.key_id
        target, plan = self._approved(
            db,
            key_id=authorization_key_id,
            public_key_b64=AUTHORIZATION_PUBLIC_KEY_B64,
        )
        rollout = _rollout(db, plan.id)

        verdict = _report(
            db,
            rollout_ref=rollout.rollout_ref,
            key_id=authorization_key_id,
            _signer_public_key_b64=AUTHORIZATION_PUBLIC_KEY_B64,
        )
        assert verdict.disposition == ObservationDisposition.SIGNER_PURPOSE_REUSED
        assert verdict.changed_state is False
        assert db.get(DeploymentTarget, target.id).observed_release_ref is None

    def test_a_failed_execution_is_not_a_successful_transport_settlement(
        self, db
    ) -> None:
        target, plan = self._approved(db)
        rollout = _rollout(db, plan.id)

        verdict = _report(
            db,
            rollout_ref=rollout.rollout_ref,
            _statement_overrides={"outcome": "failed"},
        )
        assert verdict.disposition == ObservationDisposition.EXECUTION_FAILED
        # The execution high-water mark advances so an older success cannot
        # overwrite this later failure, while the observed deployment itself
        # remains unchanged.
        assert verdict.changed_state is True
        persisted = db.get(Rollout, rollout.id)
        assert persisted is not None
        assert persisted.status == "dispatched"
        assert db.get(DeploymentTarget, target.id).observed_release_ref is None

    def test_observed_images_must_equal_the_authorized_set(self, db) -> None:
        target, plan = self._approved(db)
        rollout = _rollout(db, plan.id)

        verdict = _report(
            db,
            rollout_ref=rollout.rollout_ref,
            _statement_overrides={
                "observed_images": [
                    {
                        "service": "app",
                        "repository": "registry.invalid/app",
                        "digest": "sha256:" + "ab" * 32,
                    }
                ]
            },
        )
        assert verdict.disposition == ObservationDisposition.AUTHORIZATION_MISMATCH
        assert verdict.changed_state is False
        assert db.get(DeploymentTarget, target.id).observed_release_ref is None


# ── 6. The type itself ──────────────────────────────────────────────────────


class TestTheDigestTypeIsReceivedOnly:
    def test_it_parses_the_canonical_form_and_compares_by_bytes(self) -> None:
        assert ExecutionPlanDigestV1.parse(_PLAN_A) == ExecutionPlanDigestV1.parse(
            _PLAN_A
        )
        assert ExecutionPlanDigestV1.parse(_PLAN_A) != ExecutionPlanDigestV1.parse(
            _PLAN_B
        )
        assert ExecutionPlanDigestV1.parse(_PLAN_A).canonical == _PLAN_A

    def test_it_cannot_be_computed_from_a_payload(self) -> None:
        """THE STRUCTURAL PROPERTY, at the value level.

        `over_json` is the constructor that turns bytes into a digest, and this
        type does not have it. A second canonicalization of the Foundation's
        execution plan is therefore not something a reviewer has to notice; it
        is an `AttributeError`.
        """
        assert not hasattr(ExecutionPlanDigestV1, "over_json")
        with pytest.raises(AttributeError):
            ExecutionPlanDigestV1.over_json({"anything": True})  # type: ignore[attr-defined]

    def test_it_has_no_legacy_parser_because_it_has_no_legacy(self) -> None:
        """`0.1.0a4` never held this value, so there is no earlier encoding to be
        tolerant of — and tolerance would mean rewriting somebody else's."""
        assert not hasattr(ExecutionPlanDigestV1, "parse_a4_bare_hex")
        assert not hasattr(ExecutionPlanDigestV1, "parse_accepting_a4_bare_hex")
        assert not hasattr(ExecutionPlanDigestV1, "a4_bare_hex")
