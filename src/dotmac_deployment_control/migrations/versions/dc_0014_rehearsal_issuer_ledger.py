"""Durable ledger for rehearsal-issuer authorization -- a different authority
than `rehearsal_grants`.

`dc_0012` records the replay coordinate for a provoked-rollback grant -- a
rehearsal ACT already under way. This revision adds a SIBLING table for a
different act: authority to OPERATE the disposable rehearsal issuer for one
bounded lease in the first place (the C1 contract in
`rehearsal_issuer_authorization.py`). The two never share a table: a
compromise of one authority must not silently extend to the other, and a
shared table would make that separation a naming convention rather than a
structural fact.

The lifecycle SHAPE is cloned from `dc_0012` deliberately: one row per lease,
`issued -> spent | revoked`, a trigger making a terminal row immutable, and a
CHECK tying `state` to the presence/absence of its evidence columns.

`lease_id` carries its own UNIQUE constraint (D4): a revoked lease is not
reusable, and a genuine retry presents a new lease id.

Revision ID: dc_0014_rehearsal_issuer_ledger
Revises: dc_0013_host_admission
Create Date: 2026-09-23
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0014_rehearsal_issuer_ledger"
down_revision = "dc_0013_host_admission"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_TABLE = "rehearsal_issuer_authorizations"


def _grant(privileges: str, table: str, role: str) -> None:
    op.execute(f"GRANT {privileges} ON {_SCHEMA}.{table} TO {role};")


def _revoke(table: str) -> None:
    op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM app_user;")


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("authorization_id", sa.String(length=512), nullable=False),
        sa.Column("single_use_reference", sa.String(length=512), nullable=False),
        sa.Column("lease_id", sa.String(length=512), nullable=False),
        sa.Column(
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.deployment_plans.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.deployment_targets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("controller_fingerprint", sa.String(length=512), nullable=False),
        sa.Column("harness_evidence_digest", sa.String(length=128), nullable=False),
        #: The exact signed C1 envelope. NOT NULL: a row without one is a
        #: claim of authority with nothing behind it.
        sa.Column("authorization_envelope", postgresql.JSONB(), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revocation_ref", sa.String(length=200)),
        sa.Column("spent_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "authorization_id",
            name="uq_rehearsal_issuer_authorizations_authorization_id",
        ),
        sa.UniqueConstraint(
            "single_use_reference",
            name="uq_rehearsal_issuer_authorizations_single_use_reference",
        ),
        sa.UniqueConstraint(
            "lease_id", name="uq_rehearsal_issuer_authorizations_lease_id"
        ),
        sa.CheckConstraint(
            "state IN ('issued', 'revoked', 'spent')",
            name="ck_rehearsal_issuer_authorizations_state",
        ),
        sa.CheckConstraint(
            "(state = 'issued' AND revoked_at IS NULL AND revocation_ref IS NULL AND spent_at IS NULL) "  # noqa: E501
            "OR (state = 'revoked' AND revoked_at IS NOT NULL AND revocation_ref IS NOT NULL AND revocation_ref ~ '[^[:space:]]' AND spent_at IS NULL) "  # noqa: E501
            "OR (state = 'spent' AND spent_at IS NOT NULL AND revoked_at IS NULL AND revocation_ref IS NULL)",  # noqa: E501
            name="ck_rehearsal_issuer_authorizations_state_evidence",
        ),
        #: A backstop matching `RehearsalIssuerAuthorizationStatementV1
        #: .__post_init__`'s identical predicate -- a row that cannot be true
        #: should not be storable even if some future caller bypasses the
        #: type.
        sa.CheckConstraint(
            "not_before <= issued_at AND issued_at < expires_at",
            name="ck_rehearsal_issuer_authorizations_window",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rehearsal_issuer_authorizations_plan_id",
        _TABLE,
        ["plan_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rehearsal_issuer_authorizations_target_id",
        _TABLE,
        ["target_id"],
        schema=_SCHEMA,
    )

    # THE ACCESS SURFACE. No DELETE granted to anyone: revocation and spend
    # are UPDATEs, and a role able to DELETE could erase the record of one.
    #
    # Literal table-name strings here, not the `_TABLE` constant: the
    # architecture test that checks every declared platform table is
    # granted/revoked correctly (`test_deployment_control_module.py`)
    # statically scans this file's own SOURCE TEXT for the exact call
    # shape `_grant("...", "<table>", "<role>")` / `_revoke("<table>")` —
    # it cannot resolve a variable, only match a literal, matching
    # `dc_0012_rehearsal_lifecycle.py`'s own exact convention.
    _grant("SELECT, INSERT, UPDATE", "rehearsal_issuer_authorizations", "platform_api")
    _grant("SELECT, INSERT, UPDATE", "rehearsal_issuer_authorizations", "app_admin")
    _revoke("rehearsal_issuer_authorizations")

    _FN = f"{_SCHEMA}.prevent_rehearsal_issuer_terminal_reset"
    op.execute(
        f"""
CREATE FUNCTION {_FN}()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state <> 'issued' THEN
        RAISE EXCEPTION 'rehearsal-issuer authorization row is immutable';
    END IF;
    IF NEW.state NOT IN ('spent', 'revoked') THEN
        RAISE EXCEPTION 'rehearsal-issuer authorization must leave issued state';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
        OR NEW.single_use_reference IS DISTINCT FROM OLD.single_use_reference
        OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
        OR NEW.plan_id IS DISTINCT FROM OLD.plan_id
        OR NEW.target_id IS DISTINCT FROM OLD.target_id
        OR NEW.controller_fingerprint IS DISTINCT FROM OLD.controller_fingerprint
        OR NEW.harness_evidence_digest IS DISTINCT FROM OLD.harness_evidence_digest
        OR NEW.authorization_envelope IS DISTINCT FROM OLD.authorization_envelope
        OR NEW.not_before IS DISTINCT FROM OLD.not_before
        OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'rehearsal-issuer authorization identity is immutable';
    END IF;
    RETURN NEW;
END;
$$
        """
    )
    op.execute(
        f"""
CREATE TRIGGER rehearsal_issuer_authorizations_terminal_state_guard
BEFORE UPDATE ON {_SCHEMA}.{_TABLE}
FOR EACH ROW EXECUTE FUNCTION {_FN}()
        """
    )


def downgrade() -> None:
    # A rehearsal-issuer spend or revocation is an irreversible cut-off. A
    # downgrade must not erase its only durable record while rows remain.
    op.execute(f"LOCK TABLE {_SCHEMA}.{_TABLE} IN ACCESS EXCLUSIVE MODE")
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS "
                "(SELECT 1 FROM mod_deploy.rehearsal_issuer_authorizations)"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError(
            "dc_0014_rehearsal_issuer_ledger refuses to discard rehearsal-"
            "issuer authorization lifecycle evidence"
        )
    op.execute(
        f"DROP TRIGGER rehearsal_issuer_authorizations_terminal_state_guard "
        f"ON {_SCHEMA}.{_TABLE}"
    )
    op.execute(f"DROP FUNCTION {_SCHEMA}.prevent_rehearsal_issuer_terminal_reset()")
    op.drop_index(
        "ix_rehearsal_issuer_authorizations_target_id", _TABLE, schema=_SCHEMA
    )
    op.drop_index("ix_rehearsal_issuer_authorizations_plan_id", _TABLE, schema=_SCHEMA)
    op.drop_table(_TABLE, schema=_SCHEMA)
