"""Append immutable terminal settlement evidence beside immutable issuance.

``rollout_attempts`` has always been append-only evidence, but its original
outcome columns made the service attempt to UPDATE that evidence at settlement.
This revision deliberately leaves every one of those historical rows untouched.
Instead it creates one append-only settlement row per attempt.  Its unique
``attempt_id`` is both the one-terminal-outcome invariant and the database
arbiter when different command ids race to settle one delivery.

Terminal legacy rows are copied as settlement evidence. The copy preserves the
stored outcome, correlation fields and exact settlement timestamp; a missing
timestamp remains NULL because creation time is not settlement provenance.
Pending legacy issuance gets no row, so the post-migration projection remains
pending. No UPDATE is issued against ``rollout_attempts``: provenance is
retained rather than manufactured.

The UPDATE/DELETE/TRUNCATE triggers refuse ordinary rewrites, but a migration or
table owner remains a higher authority that can deliberately alter or drop those
controls. This slice does not claim to close that ownership boundary.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0010_attempt_settlements"
down_revision = "dc_0009_prestate_discriminator"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_TABLE = "rollout_attempt_settlements"


def _grant(privileges: str, table: str, role: str) -> None:
    op.execute(f"GRANT {privileges} ON mod_deploy.{table} TO {role}")


def _revoke(table: str) -> None:
    op.execute(f"REVOKE ALL PRIVILEGES ON mod_deploy.{table} FROM app_user")


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("integrator_ref", sa.String(length=200), nullable=True),
        sa.Column("error_code", sa.String(length=60), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["attempt_id"],
            ["mod_deploy.rollout_attempts.id"],
            name="fk_rollout_attempt_settlements_attempt_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "attempt_id", name="uq_rollout_attempt_settlements_attempt"
        ),
        sa.CheckConstraint(
            "outcome <> 'pending'", name="ck_attempt_settlements_terminal"
        ),
        schema=_SCHEMA,
    )
    op.execute(
        """
        CREATE TRIGGER refuse_evidence_rewrite
        BEFORE UPDATE OR DELETE ON mod_deploy.rollout_attempt_settlements
        FOR EACH ROW EXECUTE FUNCTION mod_deploy.refuse_evidence_rewrite();
        """
    )
    op.execute(
        """
        CREATE TRIGGER refuse_evidence_truncate
        BEFORE TRUNCATE ON mod_deploy.rollout_attempt_settlements
        FOR EACH STATEMENT EXECUTE FUNCTION mod_deploy.refuse_evidence_rewrite();
        """
    )
    op.execute(
        """
        INSERT INTO mod_deploy.rollout_attempt_settlements
            (id, attempt_id, outcome, integrator_ref, error_code, detail,
             settled_at, created_at, updated_at)
        SELECT id, id, outcome, integrator_ref, error_code, detail,
               settled_at, created_at, updated_at
        FROM mod_deploy.rollout_attempts
        WHERE outcome <> 'pending';
        """
    )
    _grant("SELECT, INSERT", "rollout_attempt_settlements", "platform_api")
    _grant("SELECT, INSERT", "rollout_attempt_settlements", "app_admin")
    _revoke("rollout_attempt_settlements")


def downgrade() -> None:
    # The check and drop must share an ACCESS EXCLUSIVE lock: without it a
    # concurrent settlement could arrive after the empty check and be erased.
    op.execute(
        "LOCK TABLE mod_deploy.rollout_attempt_settlements IN ACCESS EXCLUSIVE MODE"
    )
    remaining = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM mod_deploy.rollout_attempt_settlements)"
            )
        )
        .scalar_one()
    )
    if remaining:
        raise RuntimeError(
            "dc_0010_attempt_settlements refuses to discard append-only "
            "settlement evidence"
        )
    op.drop_table(_TABLE, schema=_SCHEMA)
