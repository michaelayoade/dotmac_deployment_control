"""Bind target observation keys to algorithm/purpose and freeze auth bytes.

Existing credentials remain nullable because Control did not record which
algorithm interpreted their bytes.  Guessing would turn an old opaque key into
a newly authorized verification identity.  They are refused by the a10
observation path and must rotate under a new key id.

Revision ID: dc_0006_observation_key_identity
Revises: dc_0005_portable_authorization
Create Date: 2026-09-03
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "dc_0006_observation_key_identity"
down_revision = "dc_0005_portable_authorization"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"


def upgrade() -> None:
    op.add_column(
        "target_credentials",
        sa.Column("algorithm", sa.String(length=60), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "deployment_targets",
        sa.Column("last_execution_sequence", sa.Integer(), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "deployment_targets",
        sa.Column("last_execution_attempt_no", sa.Integer(), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "deployment_targets",
        sa.Column("last_execution_state_digest", sa.String(length=128), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "rollouts",
        sa.Column("execution_sequence", sa.Integer(), nullable=True),
        schema=_SCHEMA,
    )
    op.create_unique_constraint(
        "uq_rollouts_target_execution",
        "rollouts",
        ["target_id", "execution_sequence"],
        schema=_SCHEMA,
    )
    op.create_check_constraint(
        "ck_rollouts_execution_sequence",
        "rollouts",
        "execution_sequence IS NULL OR execution_sequence >= 1",
        schema=_SCHEMA,
    )
    op.create_check_constraint(
        "ck_targets_execution_coordinate_complete",
        "deployment_targets",
        "((last_execution_sequence IS NULL) = "
        "(last_execution_attempt_no IS NULL)) AND "
        "((last_execution_attempt_no IS NULL) = "
        "(last_execution_state_digest IS NULL))",
        schema=_SCHEMA,
    )
    op.create_check_constraint(
        "ck_targets_execution_coordinate_positive",
        "deployment_targets",
        "last_execution_sequence IS NULL OR "
        "(last_execution_sequence >= 1 AND last_execution_attempt_no >= 1)",
        schema=_SCHEMA,
    )
    for name, column in (
        ("execution_sequence", sa.Integer()),
        ("attempt_no", sa.Integer()),
        ("observed_state_digest", sa.String(length=128)),
    ):
        op.add_column(
            "observation_receipts",
            sa.Column(name, column, nullable=True),
            schema=_SCHEMA,
        )
    op.create_check_constraint(
        "ck_observation_receipts_execution_coordinate_complete",
        "observation_receipts",
        "((execution_sequence IS NULL) = (attempt_no IS NULL)) AND "
        "((attempt_no IS NULL) = (observed_state_digest IS NULL))",
        schema=_SCHEMA,
    )
    op.create_check_constraint(
        "ck_observation_receipts_execution_coordinate_positive",
        "observation_receipts",
        "execution_sequence IS NULL OR "
        "(execution_sequence >= 1 AND attempt_no >= 1)",
        schema=_SCHEMA,
    )
    op.add_column(
        "target_credentials",
        sa.Column("purpose", sa.String(length=60), nullable=True),
        schema=_SCHEMA,
    )
    op.execute(
        """
        CREATE FUNCTION mod_deploy.refuse_rollout_issuance_rewrite()
        RETURNS trigger AS $$
        BEGIN
            IF OLD.authorization_envelope IS DISTINCT FROM NEW.authorization_envelope
               OR OLD.execution_sequence IS DISTINCT FROM NEW.execution_sequence THEN
                RAISE EXCEPTION
                    'immutable issuance evidence: rollout envelope/sequence'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER refuse_rollout_issuance_rewrite
        BEFORE UPDATE OF authorization_envelope, execution_sequence
        ON mod_deploy.rollouts
        FOR EACH ROW
        EXECUTE FUNCTION mod_deploy.refuse_rollout_issuance_rewrite();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER refuse_rollout_issuance_rewrite " "ON mod_deploy.rollouts")
    op.execute("DROP FUNCTION mod_deploy.refuse_rollout_issuance_rewrite()")
    for name in (
        "ck_observation_receipts_execution_coordinate_positive",
        "ck_observation_receipts_execution_coordinate_complete",
    ):
        op.drop_constraint(name, "observation_receipts", schema=_SCHEMA, type_="check")
    for name in ("observed_state_digest", "attempt_no", "execution_sequence"):
        op.drop_column("observation_receipts", name, schema=_SCHEMA)
    op.drop_constraint(
        "ck_rollouts_execution_sequence",
        "rollouts",
        schema=_SCHEMA,
        type_="check",
    )
    op.drop_constraint(
        "uq_rollouts_target_execution",
        "rollouts",
        schema=_SCHEMA,
        type_="unique",
    )
    op.drop_column("rollouts", "execution_sequence", schema=_SCHEMA)
    for name in (
        "ck_targets_execution_coordinate_positive",
        "ck_targets_execution_coordinate_complete",
    ):
        op.drop_constraint(name, "deployment_targets", schema=_SCHEMA, type_="check")
    for name in (
        "last_execution_state_digest",
        "last_execution_attempt_no",
        "last_execution_sequence",
    ):
        op.drop_column("deployment_targets", name, schema=_SCHEMA)
    op.drop_column("target_credentials", "purpose", schema=_SCHEMA)
    op.drop_column("target_credentials", "algorithm", schema=_SCHEMA)
