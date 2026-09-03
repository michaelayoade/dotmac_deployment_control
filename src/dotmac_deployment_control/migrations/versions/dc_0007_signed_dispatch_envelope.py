"""Persist the signed Control-to-executor dispatch on its append-only attempt.

NULL is retained for pre-a11 history. New dispatches populate the column on the
initial INSERT, and the root lineage's evidence trigger already refuses every
UPDATE or DELETE of ``rollout_attempts``.

Revision ID: dc_0007_signed_dispatch_envelope
Revises: dc_0006_observation_key_identity
Create Date: 2026-09-03
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0007_signed_dispatch_envelope"
down_revision = "dc_0006_observation_key_identity"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"


def upgrade() -> None:
    op.add_column(
        "rollout_attempts",
        sa.Column("dispatch_envelope", postgresql.JSONB(), nullable=True),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column("rollout_attempts", "dispatch_envelope", schema=_SCHEMA)
