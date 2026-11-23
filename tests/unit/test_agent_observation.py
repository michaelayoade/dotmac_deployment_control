"""The agent observation envelope (target_api v2) through `record_observation`.

One ingestion path, owned by Control: the envelope is parsed with Control's strict
parser, the signature is verified against the ENROLLED credential selected by
`key_id`, the statement's `target_ref` is compared with the credential's target,
and the kind must agree with the plan operation. Every arrival writes an attempt.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from sqlalchemy import select

import dotmac_deployment_control.service as control_service
from dotmac_deployment_control import (
    ObservationDisposition,
    RecordObservationCommand,
    SignatureStatus,
    get_target,
    observation_attempts,
    record_observation,
)
from dotmac_deployment_control.agent_observation import (
    AgentObservationEnvelopeV2,
    issue_agent_observation_envelope,
)
from dotmac_deployment_control.models import Rollout, RolloutAttempt
from tests.authorization_support import VERIFIER
from tests.execution_observation_support import (
    OBSERVATION_VERIFIER,
    TestExecutionObservationSigner,
)
from tests.unit import test_deployment_control_observations as _obs

# The shared fixtures (in-memory SQLite, an enrolled target), re-exported by name.
db = _obs.db
enrolled = _obs.enrolled
_installed_module_audit_actions = _obs._installed_module_audit_actions
_fixed_control_clock = _obs._fixed_control_clock
_NOW = _obs._NOW
_bound_rollout_ref = _obs._bound_rollout_ref
_cmd = _obs._cmd


def _dispatch_id(db) -> str:  # type: ignore[no-untyped-def]
    ref = _bound_rollout_ref(db, "tgt-acme-1")
    rollout = db.execute(select(Rollout).where(Rollout.rollout_ref == ref)).scalar_one()
    attempt = db.execute(
        select(RolloutAttempt).where(RolloutAttempt.rollout_id == rollout.id)
    ).scalar_one()
    return str(attempt.id)


def _wire(dispatch_id: str, **over: object) -> bytes:
    fields: dict[str, object] = {
        "kind": "deploy",
        "dispatch_id": dispatch_id,
        "target_ref": "tgt-acme-1",
        "key_id": "key-acme-1",
        "outcome": "succeeded",
        "reason": "",
        "details": {},
        "observed_at": "2026-09-01T12:00:00Z",
    }
    fields.update(over)
    signer = TestExecutionObservationSigner(str(fields["key_id"]))
    envelope = issue_agent_observation_envelope(
        fields, sign=lambda raw: signer.sign_execution_observation(raw).signature
    )
    return envelope.canonical_bytes


def _send(db, wire: bytes):  # type: ignore[no-untyped-def]
    with patch.object(control_service, "_control_now", return_value=_NOW):
        return record_observation(
            db,
            RecordObservationCommand(command_id=_cmd(), observation=wire),
            observation_verifier=OBSERVATION_VERIFIER,
            authorization_verifier=VERIFIER,
        )


def test_a_valid_agent_observation_is_accepted_and_changes_no_state(
    db, enrolled
) -> None:  # type: ignore[no-untyped-def]
    target, _ = enrolled
    before = get_target(db, target.id)
    dispatch = _dispatch_id(db)
    verdict = _send(db, _wire(dispatch))
    assert verdict.disposition == ObservationDisposition.ACCEPTED.value
    assert verdict.changed_state is False
    attempt = observation_attempts(db)[-1]
    assert attempt.report_id == f"agent:deploy:{dispatch}"
    assert attempt.signature_status == SignatureStatus.VALID.value
    assert attempt.authenticated_target_ref == "tgt-acme-1"
    after = get_target(db, target.id)
    assert (after.observed_release_ref, after.observed_revision) == (
        before.observed_release_ref,
        before.observed_revision,
    )


def test_every_kind_the_plan_allows_is_accepted(db, enrolled) -> None:  # type: ignore[no-untyped-def]
    dispatch = _dispatch_id(db)
    for kind, outcome in (("reconcile", "reconciled"), ("deploy", "failed")):
        verdict = _send(db, _wire(dispatch, kind=kind, outcome=outcome))
        assert verdict.disposition == ObservationDisposition.ACCEPTED.value, kind


def test_a_kind_that_disagrees_with_the_plan_operation_is_a_mismatch(
    db, enrolled
) -> None:  # type: ignore[no-untyped-def]
    """N-1: a `job` report of a deploy plan is refused as operation_mismatch."""
    dispatch = _dispatch_id(db)
    verdict = _send(db, _wire(dispatch, kind="job"))
    assert verdict.disposition == ObservationDisposition.OPERATION_MISMATCH.value
    assert observation_attempts(db)[-1].report_id == f"agent:job:{dispatch}"


def test_the_statement_target_must_be_the_credentials_target(db, enrolled) -> None:  # type: ignore[no-untyped-def]
    dispatch = _dispatch_id(db)
    verdict = _send(db, _wire(dispatch, target_ref="tgt-other"))
    assert verdict.disposition == ObservationDisposition.TARGET_MISMATCH.value


def test_a_dispatch_that_is_not_this_targets_is_unbound(db, enrolled) -> None:  # type: ignore[no-untyped-def]
    _dispatch_id(db)
    for dispatch in (str(uuid.uuid4()), "not-a-uuid"):
        verdict = _send(db, _wire(dispatch))
        assert verdict.disposition == ObservationDisposition.UNBOUND_REPORT.value


def test_an_unknown_key_and_a_bad_signature_are_recorded_not_trusted(
    db, enrolled
) -> None:  # type: ignore[no-untyped-def]
    dispatch = _dispatch_id(db)
    before = len(observation_attempts(db))
    unknown = _send(db, _wire(dispatch, key_id="key-unknown"))
    assert unknown.disposition == ObservationDisposition.UNKNOWN_KEY.value
    good = AgentObservationEnvelopeV2.parse_bytes(_wire(dispatch))
    forged = AgentObservationEnvelopeV2(
        statement=good.statement, signature="invalid-signature"
    ).canonical_bytes
    bad = _send(db, forged)
    assert bad.disposition == ObservationDisposition.BAD_SIGNATURE.value
    assert len(observation_attempts(db)) == before + 2  # every arrival is written


def test_a_repeat_is_a_replay_and_different_bytes_under_one_report_id_conflict(
    db, enrolled
) -> None:  # type: ignore[no-untyped-def]
    dispatch = _dispatch_id(db)
    first = _wire(dispatch)
    assert _send(db, first).disposition == ObservationDisposition.ACCEPTED.value
    assert (
        _send(db, first).disposition == ObservationDisposition.IDEMPOTENT_REPLAY.value
    )
    other = _wire(dispatch, outcome="failed", reason="changed my mind")
    assert _send(db, other).disposition == ObservationDisposition.CONFLICT.value


def test_garbage_is_still_recorded_as_malformed(db, enrolled) -> None:  # type: ignore[no-untyped-def]
    before = len(observation_attempts(db))
    verdict = _send(db, b'{"statement":{"schema":"dotmac.agent-observation/2"}}')
    assert verdict.disposition == ObservationDisposition.MALFORMED.value
    assert len(observation_attempts(db)) == before + 1


# ── The reconcile marker (the port CP 5c reads) ─────────────────────────────


def test_an_accepted_reconcile_observation_leaves_the_marker_for_that_dispatch(
    db, enrolled
) -> None:  # type: ignore[no-untyped-def]
    from dotmac_deployment_control import reconcile_marker

    dispatch = _dispatch_id(db)
    assert reconcile_marker(db, target_ref="tgt-acme-1", dispatch_id=dispatch) is None
    verdict = _send(db, _wire(dispatch, kind="reconcile", outcome="reconciled"))
    assert verdict.disposition == ObservationDisposition.ACCEPTED.value
    marker = reconcile_marker(db, target_ref="tgt-acme-1", dispatch_id=dispatch)
    assert marker is not None
    assert (marker.dispatch_id, marker.outcome) == (dispatch, "reconciled")
    assert marker.attempt_id == observation_attempts(db)[-1].id
    # A replay does not make a second marker; the first stands.
    _send(db, _wire(dispatch, kind="reconcile", outcome="reconciled"))
    again = reconcile_marker(db, target_ref="tgt-acme-1", dispatch_id=dispatch)
    assert again is not None and again.attempt_id == marker.attempt_id


def test_only_a_settled_reconcile_of_the_named_dispatch_and_target_is_a_marker(
    db, enrolled
) -> None:  # type: ignore[no-untyped-def]
    from dotmac_deployment_control import reconcile_marker

    dispatch = _dispatch_id(db)
    # A failed reconcile settles nothing; a deploy report is not a reconcile.
    _send(db, _wire(dispatch, kind="reconcile", outcome="failed", reason="busy"))
    _send(db, _wire(dispatch, kind="deploy", outcome="succeeded"))
    assert reconcile_marker(db, target_ref="tgt-acme-1", dispatch_id=dispatch) is None
    # Refused arrivals leave nothing: a mismatched target, an unbound dispatch.
    _send(
        db, _wire(dispatch, kind="reconcile", outcome="reconciled", target_ref="tgt-x")
    )
    other = str(uuid.uuid4())
    _send(db, _wire(other, kind="reconcile", outcome="reconciled"))
    assert reconcile_marker(db, target_ref="tgt-acme-1", dispatch_id=dispatch) is None
    assert reconcile_marker(db, target_ref="tgt-acme-1", dispatch_id=other) is None
    # `not_needed` settles it, and the marker is per target and per dispatch.
    # A retry carries its own observed_at, so the failed one does not block it.
    retry = _wire(
        dispatch,
        kind="reconcile",
        outcome="not_needed",
        observed_at="2026-09-01T12:05:00Z",
    )
    assert _send(db, retry).disposition == ObservationDisposition.ACCEPTED.value
    assert reconcile_marker(db, target_ref="tgt-acme-1", dispatch_id=dispatch)
    assert reconcile_marker(db, target_ref="tgt-other", dispatch_id=dispatch) is None
