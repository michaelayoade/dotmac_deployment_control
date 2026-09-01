"""Bind a plan to the Foundation's execution plan and to a declared operation.

`dc_0001` and `dc_0002` gave `deployment_plans` one digest: `plan_digest`,
Control's own snapshot digest. That value cannot bind an execution, and the
reason is worth stating precisely because it is invisible in review.

Control's `plan_digest` hashes the target's desired state WRAPPED IN SIX SIBLING
KEYS (`target_ref`, `product_code`, `environment`, `release_ref`, `licence_ref`,
`brand_profile_ref`, `desired_revision`, `spec`). The Deployment Foundation
hashes its rendered execution plan ALONE. Both use canonical JSON with sorted
keys and both use sha256 — they agree completely about serialization and
disagree about payload. Two such digests can never be equal, and every line of
both implementations reads as correct.

So a THIRD value is added rather than either side changing: the Foundation's
`ExecutionPlanDigestV1`, received here and never recomputed. `plan_digest` and
`spec_digest` are untouched by this revision.

## Four columns, in two pairs

`operation` / `execution_plan_digest` are the PROPOSAL — what Platform CP
submitted and this control plane froze.

`authorized_operation` / `authorized_execution_plan_digest` are the
AUTHORIZATION — what the approval evidence bound, written once when the plan is
approved.

Two pairs because the acceptance rule is a THREE-term one: proposal,
authorization and report must bind the same values. Storing one pair and
comparing the report against it is a two-term gate wearing a three-term name,
and a gate is always weakened by quietly passing fewer terms than it names.

## Nullable, and with no server default

Both, deliberately, and for different reasons.

NULLABLE because `0.1.0a7` rows exist and were proposed before this contract.
Backfilling them would mean inventing an operation and an execution-plan digest
for plans nobody bound — this migration would be asserting an authorization. A
plan holding NULL here is refused a rollout by `request_rollout` instead, which
is a refusal an operator can read rather than a fiction they cannot see.

NO SERVER DEFAULT because a default is an inference. `DEFAULT 'deploy'` would
make every unbound legacy row claim to be an authorized deployment, and would
make a caller's silence mean `deploy` forever after. Michael's ruling is that an
operation is never inferred — not from a diff, not from a command name, and not
from an omission.

## Widths, and why `operation` is not a CHECK

`VARCHAR(128)` for the digest, matching every other digest column on this plane
(`dc_0002`'s reason: one width per plane means the next algorithm is a code
change and not another migration). `VARCHAR(20)` for the operation, matching
`target_credentials.status` and the other short vocabulary columns.

No CHECK on `operation`, consistent with `dc_0001`'s rule for `status`,
`environment` and `disposition` (ADR-0008). The vocabulary IS closed — `deploy`
and `rollback`, and an unknown value is refused — but the closure lives in
`dotmac_deployment_control.operations`, where a refusal can explain itself and
where a coordinated change with the executor costs a module release rather than
an `ALTER TABLE` on every deployment.

## Grants and isolation are unchanged

Column privileges follow the table. `dc_0001` granted `platform_api` and
`app_admin` at table level and REVOKEd ALL from `app_user`; a column added to an
already-revoked table carries no grant to the tenant role, so hard rule 27's
"revoked across every table and column privilege" continues to hold without a
statement here. Adding one would be a second, drifting copy of `dc_0001`'s
access-control surface.

## ADD COLUMN is metadata-only

All four are nullable with no default, so PostgreSQL 11+ performs no table
rewrite and takes only the brief `ACCESS EXCLUSIVE` the catalog update needs.

No `require_prerequisites` call: `dc_0001` proved both effects before creating
this table, and a revision inside the same lineage cannot run before its own
root.

Revision ID: dc_0003_execution_plan_binding
Revises: dc_0002_canonical_plan_digest
Create Date: 2026-09-01
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "dc_0003_execution_plan_binding"
down_revision = "dc_0002_canonical_plan_digest"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_PLANS = "deployment_plans"


def upgrade() -> None:
    # The order of these four statements is the physical column order the
    # published catalogue declares (ordinals 17 through 20). PostgreSQL assigns
    # `attnum` in ADD COLUMN order, and
    # `test_source_owned_catalogue_equals_the_clean_room_migration_result`
    # compares this lineage's result with the declaration column by column, so
    # reordering them here is a catalogue change.
    op.add_column(
        _PLANS,
        sa.Column("operation", sa.String(length=20), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _PLANS,
        sa.Column("execution_plan_digest", sa.String(length=128), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _PLANS,
        sa.Column("authorized_operation", sa.String(length=20), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        _PLANS,
        sa.Column(
            "authorized_execution_plan_digest", sa.String(length=128), nullable=True
        ),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    # DESTRUCTIVE, and it says so rather than being reversible-looking. Dropping
    # these columns discards the record of which execution each plan was
    # authorized for, which is the evidence the acceptance rule is decided on.
    # Every plan bound after this revision becomes indistinguishable from a
    # `0.1.0a7` plan that was never bound at all, and no later upgrade can tell
    # the two apart. Reverse this only on a database whose bound plans have all
    # settled and whose receipts nobody will need to re-decide.
    op.drop_column(_PLANS, "authorized_execution_plan_digest", schema=_SCHEMA)
    op.drop_column(_PLANS, "authorized_operation", schema=_SCHEMA)
    op.drop_column(_PLANS, "execution_plan_digest", schema=_SCHEMA)
    op.drop_column(_PLANS, "operation", schema=_SCHEMA)
