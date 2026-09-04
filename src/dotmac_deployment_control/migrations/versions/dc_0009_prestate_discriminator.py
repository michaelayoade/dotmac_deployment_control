"""Carry Foundation's prestate encoding identity beside the digest it explains.

`dc_0008` gave `recovery_grants` an `incumbent_prestate_digest`, `NOT NULL`,
128 characters. Control signs that value, compares it, and refuses on mismatch
with `PRESTATE_MISMATCH` -- and computes nothing. Foundation's slice 1 supplied
the missing half: `FailedSystemObservationV1` is now canonicalized and digested
by exactly one authority, and that authority publishes an identity for the rules
it used.

This revision stores that identity. It does not define it, and neither this
migration nor a future `RecoveryGrantV1` version may redefine the encoding --
that would be the second canonicalizer the whole binding exists to prevent,
arriving as a schema change rather than as code.

## Why the column is NULLABLE, which is the point of the revision

`incumbent_prestate_digest NOT NULL` proves only that A STRING EXISTS. It cannot
distinguish a digest produced under rules somebody can name from 128 characters
nobody can account for, because both satisfy the constraint identically. That is
why the original "refuse rows missing the digest" requirement was withdrawn:
no row can be in that state, so the refusal had no subject and would have passed
forever.

Declaring THIS column `NOT NULL` with a default would recreate the same defect
one layer up, and in the same commit that repairs it. Absence has to be a state
the schema can hold, or the refusal below loses its subject exactly as its
predecessor did.

## An undiscriminated row is historical, and is never backfilled

There is no `UPDATE` here filling existing rows with the current identity, and
its absence is deliberate rather than an omission. A row written before this
term did not have its digest produced under rules anyone can name; assuming the
current identity would MANUFACTURE PROVENANCE for a value whose missing
provenance is the entire defect. Such a row stays readable, stays refusable, and
is permanently unexecutable -- `PRESTATE_UNDISCRIMINATED`, which is a different
answer from `PRESTATE_UNKNOWN_DISCRIMINATOR` (a version this deployment does not
have) and from `PRESTATE_MISMATCH` (the host is holding a different incumbent).
Three refusals, three destinations.

Whether any such row exists is not this revision's business either way: `dc_0008`
shipped on 2026-09-04, so there may be none. A refusal proven only against rows
that happen to exist is proven against an accident, which is why the test for it
plants one.

## Isolation

`recovery_grants` is a PLATFORM table -- no `tenant_id`, no RLS, REVOKEd from
the tenant application role, which is the isolation there. Adding a column to it
extends that surface, so the grant/revoke state is re-asserted rather than
assumed to be inherited: a column added after the table's privileges were set
does not acquire them retroactively on every engine.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "dc_0009_prestate_discriminator"
down_revision = "dc_0008_recovery_grants"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_TABLE = "recovery_grants"
_COLUMN = "incumbent_prestate_discriminator"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        # No `server_default`. See the module docstring: a default would fill
        # every historical row with a provenance nobody established.
        sa.Column(_COLUMN, sa.String(length=128), nullable=True),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column(_TABLE, _COLUMN, schema=_SCHEMA)
