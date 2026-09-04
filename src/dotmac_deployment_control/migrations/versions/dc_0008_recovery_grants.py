"""Persist recovery grants, so recovery authority is a thing that can be read.

`RecoveryGrantV1` verifies a document. Until this revision nobody stored one, so
`recovery_standing` was a pure function over bytes a consumer had to be holding
already -- which meant a console asking "may this target be recovered?" had
nowhere to look, and would have had to assemble the answer itself. That is the
shape this table removes.

## The envelope is stored VERBATIM

`grant_envelope` holds the exact signed document. The subject terms beside it --
product, environment and the three digests -- are a projection FOR LOOKUP and
are never the authority: verification re-derives canonical bytes from the
envelope and checks the signature over those. Reading a sibling column instead
would mean the value acted on and the bytes the signature covers were two
different things, which is the defect `_frozen_image_set` already avoids one
layer down.

## Revocation is a state change, never a delete

`revoked_at` marks a grant withdrawn and the row stays. A revoked grant must
remain readable for the same reason a stored `recover` operation must: an
authorization trail that erases its own withdrawn entries cannot answer "who
revoked this, and when" -- and that question is asked precisely when something
has gone wrong. `RecoveryStanding.REVOKED` is a verdict about a row that exists,
not the absence of one.

Revision ID: dc_0008_recovery_grants
Revises: dc_0007_signed_dispatch_envelope
Create Date: 2026-09-04
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0008_recovery_grants"
down_revision = "dc_0007_signed_dispatch_envelope"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_TABLE = "recovery_grants"


def _grant(privileges: str, role: str) -> None:
    """One GRANT, spelled out at the call site.

    Same shape as `dc_0001`'s: the call sites stay literal so the module's
    access-control surface remains greppable and statically checkable, which a
    loop over a table tuple would not be.
    """
    op.execute(f"GRANT {privileges} ON {_SCHEMA}.{_TABLE} TO {role};")


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        #: The grant's own identifier, carried inside the signed statement.
        #: Unique, because two grants under one id would make a revocation
        #: ambiguous about which it withdrew.
        sa.Column("grant_id", sa.String(length=200), nullable=False),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.deployment_targets.id"),
            nullable=False,
        ),
        sa.Column("product_code", sa.String(length=120), nullable=False),
        sa.Column("environment", sa.String(length=60), nullable=False),
        sa.Column(
            "recovery_execution_plan_digest", sa.String(length=128), nullable=False
        ),
        sa.Column("recovery_bundle_digest", sa.String(length=128), nullable=False),
        sa.Column("incumbent_prestate_digest", sa.String(length=128), nullable=False),
        #: The exact signed document. NOT NULL: a row without one is a claim of
        #: authority with nothing behind it, and there is no history here to
        #: preserve -- this table begins at this revision.
        sa.Column("grant_envelope", postgresql.JSONB(), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_ref", sa.String(length=200), nullable=True),
        sa.Column("revocation_reason", sa.String(length=500), nullable=True),
        sa.Column("record_version", sa.Integer(), nullable=False),
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
        sa.UniqueConstraint("grant_id", name="uq_recovery_grants_grant_id"),
        sa.CheckConstraint(
            "record_version >= 1", name="ck_recovery_grants_record_version"
        ),
        #: The window is a property of the grant and is checked here as well as
        #: in `verify_recovery_grant`, because a row that cannot be true should
        #: not be storable even if some future caller bypasses the type.
        sa.CheckConstraint(
            "not_before <= issued_at AND issued_at < expires_at",
            name="ck_recovery_grants_window",
        ),
        #: A revocation has a moment or it has not happened. `revocation_ref`
        #: without `revoked_at` would be a withdrawal nobody can date.
        sa.CheckConstraint(
            "(revoked_at IS NULL AND revocation_ref IS NULL)"
            " OR (revoked_at IS NOT NULL AND revocation_ref IS NOT NULL)",
            name="ck_recovery_grants_revocation_is_dated",
        ),
        schema=_SCHEMA,
    )
    op.create_index("ix_recovery_grants_target", _TABLE, ["target_id"], schema=_SCHEMA)
    #: The standing read asks for a target's LIVE grants. Indexed on the two
    #: columns that question filters by, so the reader stays one statement.
    op.create_index(
        "ix_recovery_grants_target_window",
        _TABLE,
        ["target_id", "expires_at"],
        schema=_SCHEMA,
    )

    # THE ACCESS SURFACE, stated here because creating a table without one
    # leaves it readable by whatever the schema default allows. On this plane
    # the REVOKE is the isolation (hard rule 27), and the online role's grant
    # is what makes the table reachable at request time.
    #
    # SELECT, INSERT and UPDATE, and deliberately no DELETE: revocation is an
    # UPDATE that sets `revoked_at`, and a role able to DELETE could erase the
    # record of a withdrawal rather than make one.
    _grant("SELECT, INSERT", "platform_api")
    _grant("UPDATE", "platform_api")
    _grant("SELECT, INSERT, UPDATE", "app_admin")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.{_TABLE} FROM app_user;")


def downgrade() -> None:
    op.drop_index("ix_recovery_grants_target_window", _TABLE, schema=_SCHEMA)
    op.drop_index("ix_recovery_grants_target", _TABLE, schema=_SCHEMA)
    op.drop_table(_TABLE, schema=_SCHEMA)
