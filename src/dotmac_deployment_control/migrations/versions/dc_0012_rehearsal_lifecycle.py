"""Rehearsal replay-coordinate ledger; staged consumption is not a launch grant."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0012_rehearsal_lifecycle"
down_revision = "dc_0011_attestation_registry"
branch_labels = None
depends_on = None


def _grant(privileges: str, table: str, role: str) -> None:
    op.execute(f"GRANT {privileges} ON mod_deploy.{table} TO {role};")


def _revoke(table: str) -> None:
    op.execute(f"REVOKE ALL ON mod_deploy.{table} FROM app_user;")


def upgrade() -> None:
    op.create_table(
        "rehearsal_grants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("grant_id", sa.String(512), nullable=False),
        sa.Column("single_use_reference", sa.String(512), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revocation_ref", sa.String(200)),
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
        sa.UniqueConstraint("grant_id", name="uq_rehearsal_grants_grant_id"),
        sa.UniqueConstraint(
            "single_use_reference", name="uq_rehearsal_grants_single_use_reference"
        ),
        sa.CheckConstraint(
            "state IN ('issued', 'revoked', 'spent')", name="ck_rehearsal_grants_state"
        ),
        sa.CheckConstraint(
            "(state = 'issued' AND revoked_at IS NULL AND revocation_ref IS NULL AND spent_at IS NULL) "  # noqa: E501
            "OR (state = 'revoked' AND revoked_at IS NOT NULL AND revocation_ref IS NOT NULL AND revocation_ref ~ '[^[:space:]]' AND spent_at IS NULL) "  # noqa: E501
            "OR (state = 'spent' AND spent_at IS NOT NULL AND revoked_at IS NULL AND revocation_ref IS NULL)",  # noqa: E501
            name="ck_rehearsal_grants_state_evidence",
        ),
        schema="mod_deploy",
    )
    _grant("SELECT, INSERT, UPDATE", "rehearsal_grants", "platform_api")
    _grant("SELECT, INSERT, UPDATE", "rehearsal_grants", "app_admin")
    _revoke("rehearsal_grants")
    op.execute(
        """
        CREATE FUNCTION mod_deploy.prevent_rehearsal_terminal_reset()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF OLD.state <> 'issued' THEN
                RAISE EXCEPTION 'rehearsal grant terminal row is immutable';
            END IF;
            IF NEW.state NOT IN ('spent', 'revoked') THEN
                RAISE EXCEPTION 'rehearsal grant transition must leave issued state';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
                OR NEW.grant_id IS DISTINCT FROM OLD.grant_id
                OR NEW.single_use_reference IS DISTINCT FROM OLD.single_use_reference
                OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'rehearsal grant identity is immutable';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER rehearsal_grants_terminal_state_guard
        BEFORE UPDATE ON mod_deploy.rehearsal_grants
        FOR EACH ROW EXECUTE FUNCTION mod_deploy.prevent_rehearsal_terminal_reset()
        """
    )


def downgrade() -> None:
    # A rehearsal spend is an irreversible cut-off. A downgrade must not erase
    # its only durable record (or a revocation) while rows remain.
    op.execute("LOCK TABLE mod_deploy.rehearsal_grants IN ACCESS EXCLUSIVE MODE")
    if (
        op.get_bind()
        .execute(sa.text("SELECT EXISTS (SELECT 1 FROM mod_deploy.rehearsal_grants)"))
        .scalar_one()
    ):
        raise RuntimeError(
            "dc_0012_rehearsal_lifecycle refuses to discard rehearsal grant "
            "lifecycle evidence"
        )
    op.drop_table("rehearsal_grants", schema="mod_deploy")
    op.execute("DROP FUNCTION mod_deploy.prevent_rehearsal_terminal_reset()")
