"""Unit wiring only; PostgreSQL lock contention belongs in integration CI."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from dotmac_deployment_control.models import RehearsalGrant, RehearsalGrantState
from dotmac_deployment_control.rehearsal_grant_lifecycle import (
    _Refused,
    _revoke_rehearsal_grant,
    _stage_rehearsal_consumption,
)


class _Result:
    def __init__(self, row):
        self.row = row

    def scalar_one_or_none(self):
        return self.row


class _Db:
    def __init__(self, row):
        self.row, self.flushed = row, False

    def execute(self, _):
        return _Result(self.row)

    def flush(self):
        self.flushed = True


def test_stage_is_private_non_admitting_and_flushes_only() -> None:
    db = _Db(SimpleNamespace(state="issued", spent_at=None))
    staged = _stage_rehearsal_consumption(db, grant_id="g", single_use_reference="r")
    assert type(staged).__name__ == "_StagedRehearsalConsumption"
    assert db.flushed and db.row.state == RehearsalGrantState.SPENT.value


def test_replay_and_revocation_refuse() -> None:
    for state in ("spent", "revoked"):
        with pytest.raises(_Refused):
            _stage_rehearsal_consumption(
                _Db(SimpleNamespace(state=state, spent_at=None)),
                grant_id="g",
                single_use_reference="r",
            )


def test_revoke_requires_a_nonempty_reference_before_mutation() -> None:
    db = _Db(SimpleNamespace(state="issued", revoked_at=None, revocation_ref=None))
    with pytest.raises(_Refused, match="non-empty reference"):
        _revoke_rehearsal_grant(
            db, grant_id="g", single_use_reference="r", revocation_ref="  "
        )
    assert db.row.state == "issued"
    assert not db.flushed


def test_revoke_refuses_a_reference_wider_than_its_persisted_column() -> None:
    db = _Db(SimpleNamespace(state="issued", revoked_at=None, revocation_ref=None))
    with pytest.raises(_Refused, match="exceeds 200"):
        _revoke_rehearsal_grant(
            db, grant_id="g", single_use_reference="r", revocation_ref="x" * 201
        )
    assert db.row.state == "issued"
    assert not db.flushed


def test_sqlite_model_constraint_refuses_whitespace_revocation_reference() -> None:
    """The model's portable CHECK must not break every SQLite fixture."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with engine.begin() as conn:
            conn.execute(text("ATTACH DATABASE ':memory:' AS mod_deploy"))
            RehearsalGrant.__table__.create(conn)
            with pytest.raises(
                IntegrityError, match="ck_rehearsal_grants_state_evidence"
            ):
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.rehearsal_grants "
                        "(id, grant_id, single_use_reference, state, "
                        "revoked_at, revocation_ref) VALUES "
                        "(:id, 'grant', 'single-use', 'revoked', "
                        "CURRENT_TIMESTAMP, :ref)"
                    ),
                    {"id": uuid4().hex, "ref": " \t\n"},
                )
    finally:
        engine.dispose()
