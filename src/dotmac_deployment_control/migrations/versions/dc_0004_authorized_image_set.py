"""Declare the authorized image set, and whether an approval still stands.

Two unrelated-looking additions in one revision, and they belong together
because they answer one consumer's one question: *is this plan approved, and
what does that approval authorize?* Before this revision Deployment Control
could not answer either half.

## The image set: a column on the TARGET and none on the PLAN

`deployment_targets.desired_images` is the declared set. There is deliberately
**no** `deployment_plans.authorized_images` column, and the absence is the
design rather than an omission.

A plan's authorized image set lives inside `deployment_plans.snapshot` — the
exact document `plan_digest` is computed over. That placement is the whole
property. A sibling column would be a value an `UPDATE` can move while the
digest sits still, so an image could change under a live approval with the
digest, the approval evidence and every screen still agreeing. The approval
binds the digest; anything the digest does not cover is not authorized by it.

So the migration that exposes the image set adds a column to the target (where
desired state is mutable and revisioned, as it should be) and adds nothing to
the plan (where the frozen document already carries it, inside the digest).

What this repairs, measured rather than supposed: the images a deployment runs
sat inside `desired_spec`, which this module declares OPAQUE and never
interprets. A consumer verifying that what ran was what was approved therefore
had to be TOLD the authorized set by whoever was asking it, and its check
proved a caller consistent with itself.

`desired_spec` stays opaque. This is a separate, declared, Control-owned term
with a shape Control validates — which is the difference between "the images
are in there somewhere" and "these are the images this plan authorizes".

## The approval standing: four columns on `deployment_plans`

`approval_decision_ref` already recorded WHICH decision approved a plan and
`approved_at` recorded when. Neither recorded whether that decision still
STANDS, and nothing else did either: a consumer asking "is this approved?" read
`status`, which stays `approved` forever, and got a yes for a withdrawn
authorization.

`approval_decision_status` owns that fact. `approval_revoked_at`,
`approval_revocation_ref` and `approval_revocation_reason` record the
withdrawal — the reference required, because an authorization that disappears
with no decision behind it is indistinguishable from a defect afterwards.

The plan's own `status` deliberately does not move on revocation. It WAS
approved, on evidence, at a recorded time; rewriting that would delete the
record. A `PlanStatus` member for the same fact would be a second writer.

## Nullable, and with no server default

Every one, for the two reasons `dc_0003` gave and one more.

NULLABLE because rows exist that predate the contract. Backfilling
`desired_images` would mean this migration inventing an authorized image set —
asserting which images an existing approval covered, which is exactly the
assertion nobody is entitled to make.

NO SERVER DEFAULT because a default is an inference. `DEFAULT '[]'` on
`desired_images` would make every existing target claim to authorize NO images,
which is a declaration and not an absence — and the two are treated
differently on purpose, since a consumer must be refused on an absence and
answered on an empty set. `DEFAULT 'granted'` on `approval_decision_status`
would be worse: every plan approved before this revision would assert a
standing decision nobody recorded.

A row holding NULL is refused by `find_approved_plan` with its own typed code
(`IMAGE_SET_UNDECLARED`, `APPROVAL_STANDING_UNRECORDED`) rather than answered,
which is a refusal an operator can read instead of a fiction they cannot see.

## Widths and types

`JSONB` for `desired_images`, matching `desired_spec` and `snapshot` on this
plane. `VARCHAR(24)` for the decision standing, matching the other short
vocabulary columns (`deployment_plans.status`). `VARCHAR(200)` for the two
references, matching `target_credentials.revocation_reason` and every other
opaque reference here.

No CHECK on `approval_decision_status`, consistent with `dc_0001`'s rule for
`status`, `environment` and `disposition` (ADR-0008). The vocabulary IS closed
— `granted` and `revoked` — but the closure lives in
`dotmac_deployment_control.approvals`, where a refusal can explain itself and
where changing it costs a module release rather than an `ALTER TABLE` on every
deployment.

## Grants and isolation are unchanged

Column privileges follow the table. `dc_0001` granted `platform_api` and
`app_admin` at table level and REVOKEd ALL from `app_user`; a column added to
an already-revoked table carries no grant to the tenant role, so hard rule 27's
"revoked across every table and column privilege" continues to hold without a
statement here. Adding one would be a second, drifting copy of `dc_0001`'s
access-control surface.

## ADD COLUMN is metadata-only

All five are nullable with no default, so PostgreSQL 11+ performs no table
rewrite and takes only the brief `ACCESS EXCLUSIVE` the catalog update needs.

No `require_prerequisites` call: `dc_0001` proved both effects before creating
these tables, and a revision inside the same lineage cannot run before its own
root.

Revision ID: dc_0004_authorized_image_set
Revises: dc_0003_execution_plan_binding
Create Date: 2026-09-02
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0004_authorized_image_set"
down_revision = "dc_0003_execution_plan_binding"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_PLANS = "deployment_plans"
_TARGETS = "deployment_targets"


def upgrade() -> None:
    # The order of these statements is the physical column order the published
    # catalogue declares. PostgreSQL assigns `attnum` in ADD COLUMN order, and
    # `test_source_owned_catalogue_equals_the_clean_room_migration_result`
    # compares this lineage's result with the declaration column by column, so
    # reordering them here is a catalogue change.
    op.add_column(
        _TARGETS,
        sa.Column("desired_images", postgresql.JSONB(), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _PLANS,
        sa.Column("approval_decision_status", sa.String(length=24), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _PLANS,
        sa.Column("approval_revoked_at", sa.DateTime(timezone=True), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _PLANS,
        sa.Column("approval_revocation_ref", sa.String(length=200), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _PLANS,
        sa.Column("approval_revocation_reason", sa.String(length=200), nullable=True),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    # DESTRUCTIVE, and it says so rather than being reversible-looking.
    #
    # Dropping the three revocation columns discards which decision withdrew an
    # authorization and when — after which a revoked approval is
    # indistinguishable from a standing one, and every consumer's lookup starts
    # answering yes for plans somebody deliberately withdrew. That is the
    # failure this revision was written to remove, restored silently.
    #
    # Dropping `desired_images` discards the declared authorized image set. A
    # plan's frozen set survives inside `deployment_plans.snapshot` (it is
    # inside the plan digest and cannot be dropped without invalidating every
    # approval), so plans already proposed keep answering — but no NEW plan can
    # declare a set, and every proposal after this point freezes an absence.
    #
    # Reverse this only on a database whose approvals have all settled and
    # whose promotions nobody will need to verify.
    op.drop_column(_PLANS, "approval_revocation_reason", schema=_SCHEMA)
    op.drop_column(_PLANS, "approval_revocation_ref", schema=_SCHEMA)
    op.drop_column(_PLANS, "approval_revoked_at", schema=_SCHEMA)
    op.drop_column(_PLANS, "approval_decision_status", schema=_SCHEMA)
    op.drop_column(_TARGETS, "desired_images", schema=_SCHEMA)
