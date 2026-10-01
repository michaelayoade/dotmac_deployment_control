"""Permanently bind each rehearsal-issuer controller fingerprint to one lease.

The unique constraint covers every ledger state and every target. PostgreSQL
creates it transactionally: existing duplicate fingerprints make upgrade fail
without rewriting or discarding historical authorizations.

Revision ID: dc_0016_controller_key_nonreuse
Revises: dc_0015_plan_purpose
"""

from __future__ import annotations

from alembic import op

revision = "dc_0016_controller_key_nonreuse"
down_revision = "dc_0015_plan_purpose"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_TABLE = "rehearsal_issuer_authorizations"
_CONSTRAINT = "uq_rehearsal_issuer_authorizations_controller_fingerprint"


def upgrade() -> None:
    op.create_unique_constraint(
        _CONSTRAINT, _TABLE, ["controller_fingerprint"], schema=_SCHEMA
    )


def downgrade() -> None:
    # Removing the only cross-lease guard while ledger history exists would
    # permit reuse of a controller key whose previous authority is terminal.
    op.execute(f"LOCK TABLE {_SCHEMA}.{_TABLE} IN ACCESS EXCLUSIVE MODE")
    if (
        op.get_bind()
        .exec_driver_sql(
            "SELECT EXISTS (SELECT 1 FROM mod_deploy.rehearsal_issuer_authorizations)"
        )
        .scalar_one()
    ):
        raise RuntimeError(
            "dc_0016_controller_key_nonreuse refuses to discard "
            "controller-key nonreuse while rehearsal-issuer history exists"
        )
    op.drop_constraint(_CONSTRAINT, _TABLE, schema=_SCHEMA, type_="unique")
