"""Widen `deployment_plans.plan_digest` so a digest can name its own algorithm.

`dc_0001` declared `plan_digest VARCHAR(64)` — exactly the width of 64 bare
hexadecimal characters, and that width is a fair summary of why `0.1.0a4`
stored bare hex: the column could not hold a value that said which algorithm
produced it. `sha256:<64 lowercase hex>` is 71 characters, so the canonical
`PlanDigestV1` serialization did not fit.

128, matching `observation_receipts.payload_digest`,
`observation_attempts.raw_body_digest` and
`deployment_targets.observed_spec_digest`, which `dc_0001` already sized for a
prefixed digest. One width for every digest column on this plane means the next
algorithm is a code change and not a second migration.

## Widening only, and no data rewrite

`VARCHAR(64) -> VARCHAR(128)` is a metadata-only change in PostgreSQL: no table
rewrite, no lock beyond the brief `ACCESS EXCLUSIVE` the catalog update takes,
and every existing value remains valid.

Existing rows are deliberately **not** rewritten to the canonical form. A row
written by `0.1.0a4` holds bare hex; `_frozen_plan_digest` reads it through the
named legacy parser and compares it as a typed value, so it keeps working
unchanged. Rewriting them here would be this migration silently restating other
people's frozen approval bindings, which is the opposite of what a frozen plan
means — and `uq_plans_digest` would have to be trusted to survive a bulk
`UPDATE` on its own column. The compatibility lives in one named parser instead,
where it can be found and eventually retired.

## The unique constraint is unaffected

`uq_plans_digest` is a UNIQUE constraint on this column. PostgreSQL rebuilds the
backing index as part of the type change; it is not dropped and recreated here,
because doing so by hand would open a window in which two plans could share a
digest — the exact ambiguity the constraint exists to remove.

No `require_prerequisites` call: `dc_0001` proved both effects before creating
this table, and a revision inside the same lineage cannot run before its own
root.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "dc_0002_canonical_plan_digest"
down_revision = "dc_0001_deployment_control"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "deployment_plans",
        "plan_digest",
        existing_type=sa.String(length=64),
        type_=sa.String(length=128),
        existing_nullable=True,
        schema="mod_deploy",
    )


def downgrade() -> None:
    # NARROWING, and it can fail — correctly. Any plan proposed by `0.1.0a5` or
    # later holds a 71-character canonical digest, and PostgreSQL refuses to
    # truncate it rather than silently cutting the value in half. A digest
    # truncated to fit would compare unequal to itself forever, and it would do
    # so through the `approve_plan` message that says the plan changed — the
    # precise defect this lineage step exists to remove. Failing loudly here is
    # the correct behaviour; the repair is to not downgrade past canonical
    # digests.
    op.alter_column(
        "deployment_plans",
        "plan_digest",
        existing_type=sa.String(length=128),
        type_=sa.String(length=64),
        existing_nullable=True,
        schema="mod_deploy",
    )
