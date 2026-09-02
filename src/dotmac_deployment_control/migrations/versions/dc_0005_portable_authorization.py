"""Store the immutable portable authorization on each rollout.

The envelope is JSONB because its versioned schema belongs to Control and its
signature covers canonical bytes, not PostgreSQL's JSON representation.  It is
nullable only for legacy rows; every a9 rollout refuses to proceed without one.

Revision ID: dc_0005_portable_authorization
Revises: dc_0004_authorized_image_set
Create Date: 2026-09-02
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0005_portable_authorization"
down_revision = "dc_0004_authorized_image_set"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_ROLLOUTS = "rollouts"


def upgrade() -> None:
    op.add_column(
        _ROLLOUTS,
        sa.Column("authorization_envelope", postgresql.JSONB(), nullable=True),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    # Destructive: this discards portable proof for every issued rollout. Use
    # only after all affected authorizations have expired and been archived.
    op.drop_column(_ROLLOUTS, "authorization_envelope", schema=_SCHEMA)
