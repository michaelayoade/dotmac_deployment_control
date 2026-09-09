"""Durable attestation trust registry: enrolments, closures, current roots.

## The defect this closes

Before this revision, `host_attester_enrolment.evaluate_enrolment` and
`host_attester_standing` took `active_by_host` and `known_fingerprints` as
plain caller-supplied mappings -- "the caller currently supplies the registry
that decides whether the caller's key is trusted." This revision gives
Control its own durable registry so that stops being true, for BOTH custody
domains Foundation needs: the candidate-release signer root and per-host
attester incarnations (`AttestationCustodyDomain`).

## Three tables, three different mutability rules, one invariant tying them

- `attestation_enrolments` -- append-only (like `rollout_attempts`): one row
  per signed enrolment or rotation statement, never edited.
- `attestation_fingerprint_closures` -- append-only, `fingerprint` PRIMARY
  KEY: the ordering arbiter. Whichever of a revocation and a supersession
  commits first for one fingerprint wins that PK slot permanently; there is
  no un-revoke and no un-supersede expressible against this table at all,
  because there is no UPDATE path to it.
- `attestation_current_roots` -- the ONE genuinely mutable table this
  revision adds. Primary key `(custody_domain, subject)` makes two
  concurrent INITIAL enrolments for the same subject a database conflict;
  rotation moves it with a compare-and-swap UPDATE; revocation of the
  current fingerprint DELETEs it (there is no valid current root until a new
  signed attempt recovers one).

The tying invariant: `uq_attestation_enrolments_fingerprint` is UNIQUE across
the WHOLE `attestation_enrolments` table, not scoped by `custody_domain`. A
key enrolled as a host attester cannot also be enrolled as a candidate
release signer -- the second INSERT is refused by the schema itself, which is
what "enforce it in the schema, not only in code" means here.

## Reused, not reinvented

`refuse_evidence_rewrite()` already exists (`dc_0001`). This revision attaches
it to both new append-only tables rather than defining a second trigger
function with the same behaviour. It also attaches the stronger
`refuse_evidence_truncate` per-statement guard `dc_0010` introduced --
`attestation_enrolments` and `attestation_fingerprint_closures` get it from
their first day, rather than inheriting `dc_0001`'s original three tables'
gap (TRUNCATE was never blocked there; not repaired here, since it is outside
this revision's owned tables).

## Platform-plane grants, same shape as every other table in this schema

`platform_api` gets SELECT+INSERT on the two append-only tables and
SELECT+INSERT+UPDATE+DELETE is deliberately NOT granted anywhere for them.
`attestation_current_roots` is the one table here where `platform_api` needs
UPDATE and DELETE (the compare-and-swap rotation and the revocation-clears-
the-pointer delete), matching how `dc_0001` grants UPDATE on the four mutable
tables. `app_admin` gets the offline-review shape: full DML on the mutable
table, SELECT+INSERT only on the two append-only ones. `app_user` is REVOKEd
everywhere -- the revoke IS the isolation on this platform-only plane.

Revision ID: dc_0011_attestation_registry
Revises: dc_0010_attempt_settlements
Create Date: 2026-09-09
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0011_attestation_registry"
down_revision = "dc_0010_attempt_settlements"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_ENROLMENTS = "attestation_enrolments"
_CLOSURES = "attestation_fingerprint_closures"
_CURRENT_ROOTS = "attestation_current_roots"


def _grant(privileges: str, table: str, role: str) -> None:
    op.execute(f"GRANT {privileges} ON mod_deploy.{table} TO {role};")


def _revoke(table: str) -> None:
    op.execute(f"REVOKE ALL ON mod_deploy.{table} FROM app_user;")


def upgrade() -> None:
    op.create_table(
        _ENROLMENTS,
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("custody_domain", sa.String(length=40), nullable=False),
        sa.Column("subject", sa.String(length=200), nullable=False),
        sa.Column("public_key_b64", sa.String(length=200), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("algorithm", sa.String(length=60), nullable=False),
        sa.Column("key_custody_pointer", sa.String(length=512), nullable=False),
        sa.Column("supersedes_fingerprint", sa.String(length=128), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enrolment_authority", sa.String(length=60), nullable=False),
        sa.Column("enrolment_envelope", postgresql.JSONB(), nullable=True),
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
        # THE headline invariant: global, not scoped by custody_domain. This
        # is what makes one key entering both custody roles a schema
        # violation rather than an application bug waiting to happen.
        sa.UniqueConstraint(
            "public_key_fingerprint", name="uq_attestation_enrolments_fingerprint"
        ),
        sa.CheckConstraint(
            "supersedes_fingerprint IS NULL OR "
            "supersedes_fingerprint <> public_key_fingerprint",
            name="ck_attestation_enrolments_supersedes_not_self",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_attestation_enrolments_custody_domain",
        _ENROLMENTS,
        ["custody_domain"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_attestation_enrolments_subject", _ENROLMENTS, ["subject"], schema=_SCHEMA
    )
    # The database-level arbiter for two concurrent rotations both claiming
    # to retire the SAME prior fingerprint: only one INSERT can hold this
    # slot. Partial (WHERE NOT NULL) so any number of initial enrolments
    # (supersedes_fingerprint IS NULL) coexist across the table's history.
    op.create_index(
        "uq_attestation_enrolments_supersedes",
        _ENROLMENTS,
        ["supersedes_fingerprint"],
        unique=True,
        schema=_SCHEMA,
        postgresql_where=sa.text("supersedes_fingerprint IS NOT NULL"),
    )

    op.create_table(
        _CLOSURES,
        # PRIMARY KEY, not merely UNIQUE -- see the module docstring. This
        # column IS the ordering arbiter Michael ruled on: whichever of a
        # revocation and a supersession commits first for one fingerprint
        # wins the slot permanently.
        sa.Column("fingerprint", sa.String(length=128), primary_key=True),
        sa.Column("closure_kind", sa.String(length=20), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closure_authority", sa.String(length=60), nullable=False),
        sa.Column("closure_reason", sa.String(length=500), nullable=True),
        sa.Column("superseded_by_fingerprint", sa.String(length=128), nullable=True),
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
            ["fingerprint"],
            [f"{_SCHEMA}.{_ENROLMENTS}.public_key_fingerprint"],
            name="fk_attestation_closures_fingerprint",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["superseded_by_fingerprint"],
            [f"{_SCHEMA}.{_ENROLMENTS}.public_key_fingerprint"],
            name="fk_attestation_closures_superseded_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "(closure_kind = 'superseded') = (superseded_by_fingerprint IS NOT NULL)",
            name="ck_attestation_closures_supersession_needs_successor",
        ),
        sa.CheckConstraint(
            "superseded_by_fingerprint IS NULL OR "
            "superseded_by_fingerprint <> fingerprint",
            name="ck_attestation_closures_successor_not_self",
        ),
        schema=_SCHEMA,
    )

    op.create_table(
        _CURRENT_ROOTS,
        sa.Column("custody_domain", sa.String(length=40), primary_key=True),
        sa.Column("subject", sa.String(length=200), primary_key=True),
        sa.Column("current_fingerprint", sa.String(length=128), nullable=False),
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
            ["current_fingerprint"],
            [f"{_SCHEMA}.{_ENROLMENTS}.public_key_fingerprint"],
            name="fk_attestation_current_roots_fingerprint",
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )

    # ── Append-only, reusing dc_0001's trigger function ─────────────────────
    op.execute(
        f"""
        CREATE TRIGGER refuse_evidence_rewrite
        BEFORE UPDATE OR DELETE ON {_SCHEMA}.{_ENROLMENTS}
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.refuse_evidence_rewrite();
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER refuse_evidence_truncate
        BEFORE TRUNCATE ON {_SCHEMA}.{_ENROLMENTS}
        FOR EACH STATEMENT EXECUTE FUNCTION {_SCHEMA}.refuse_evidence_rewrite();
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER refuse_evidence_rewrite
        BEFORE UPDATE OR DELETE ON {_SCHEMA}.{_CLOSURES}
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.refuse_evidence_rewrite();
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER refuse_evidence_truncate
        BEFORE TRUNCATE ON {_SCHEMA}.{_CLOSURES}
        FOR EACH STATEMENT EXECUTE FUNCTION {_SCHEMA}.refuse_evidence_rewrite();
        """
    )

    _grant("SELECT, INSERT", _ENROLMENTS, "platform_api")
    _grant("SELECT, INSERT", _CLOSURES, "platform_api")
    _grant("SELECT, INSERT, UPDATE, DELETE", _CURRENT_ROOTS, "platform_api")

    _grant("SELECT, INSERT", _ENROLMENTS, "app_admin")
    _grant("SELECT, INSERT", _CLOSURES, "app_admin")
    _grant("SELECT, INSERT, UPDATE, DELETE", _CURRENT_ROOTS, "app_admin")

    _revoke(_ENROLMENTS)
    _revoke(_CLOSURES)
    _revoke(_CURRENT_ROOTS)


def downgrade() -> None:
    op.execute(
        f"DROP TRIGGER IF EXISTS refuse_evidence_truncate ON {_SCHEMA}.{_CLOSURES};"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS refuse_evidence_rewrite ON {_SCHEMA}.{_CLOSURES};"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS refuse_evidence_truncate ON {_SCHEMA}.{_ENROLMENTS};"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS refuse_evidence_rewrite ON {_SCHEMA}.{_ENROLMENTS};"
    )
    op.drop_table(_CURRENT_ROOTS, schema=_SCHEMA)
    op.drop_table(_CLOSURES, schema=_SCHEMA)
    op.drop_index("uq_attestation_enrolments_supersedes", _ENROLMENTS, schema=_SCHEMA)
    op.drop_index("ix_attestation_enrolments_subject", _ENROLMENTS, schema=_SCHEMA)
    op.drop_index(
        "ix_attestation_enrolments_custody_domain", _ENROLMENTS, schema=_SCHEMA
    )
    op.drop_table(_ENROLMENTS, schema=_SCHEMA)
