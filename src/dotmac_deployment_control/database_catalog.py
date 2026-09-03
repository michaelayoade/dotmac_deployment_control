"""Build-once database structure owned by Deployment Control.

The declaration is authored from this module's frozen migration lineage, not
from a running Platform CP database.  ``dc_0001_deployment_control`` creates the
seven platform tables, ``dc_0002_canonical_plan_digest`` widens the one column
whose final type differs from the root revision, and
``dc_0003_execution_plan_binding`` appends the four columns that bind a plan to
the Foundation's execution plan and to a declared operation.

Schema, owner and persistence plane are intentionally absent here.  The kernel
derives them from :mod:`dotmac_deployment_control.manifest`, so this contribution
cannot move a table or claim another module's namespace.

Imported from ``dotmac_kernel.product_database_catalog`` rather than from the
kernel's top-level re-export, which is how every other module in this package
names a kernel dependency.  It is also what makes the floor legible: the floor
is the SUBMODULE a kernel alpha first shipped, `scripts/kernel_floor.py` derives
it from these import statements, and the mutation lane requires the failure it
forces to name that submodule.  ``from dotmac_kernel import
DatabaseColumnContractV1`` raises ``ImportError: cannot import name ...``, which
names no module at all and would leave the mutation observing an unattributable
failure.
"""

from __future__ import annotations

from dotmac_kernel.product_database_catalog import (
    DatabaseColumnContractV1,
    DatabaseColumnGeneration,
    DatabaseRelationKind,
    ModuleDatabaseCatalogContributionV1,
    ModuleDatabaseTableContractV1,
    PostgresTypeContractV1,
    PostgresTypeKind,
)


def _base_type(name: str, formatted: str) -> PostgresTypeContractV1:
    return PostgresTypeContractV1(
        kind=PostgresTypeKind.BASE,
        schema="pg_catalog",
        name=name,
        formatted=formatted,
    )


_UUID = _base_type("uuid", "uuid")
_VARCHAR_20 = _base_type("varchar", "character varying(20)")
_VARCHAR_24 = _base_type("varchar", "character varying(24)")
_VARCHAR_40 = _base_type("varchar", "character varying(40)")
_VARCHAR_60 = _base_type("varchar", "character varying(60)")
_VARCHAR_120 = _base_type("varchar", "character varying(120)")
_VARCHAR_128 = _base_type("varchar", "character varying(128)")
_VARCHAR_200 = _base_type("varchar", "character varying(200)")
_INTEGER = _base_type("int4", "integer")
_BOOLEAN = _base_type("bool", "boolean")
_TIMESTAMPTZ = _base_type("timestamptz", "timestamp with time zone")
_JSONB = _base_type("jsonb", "jsonb")
_TEXT = _base_type("text", "text")
_BYTEA = _base_type("bytea", "bytea")


def _column(
    name: str,
    ordinal: int,
    postgres_type: PostgresTypeContractV1,
    *,
    nullable: bool,
    default: str = "",
) -> DatabaseColumnContractV1:
    return DatabaseColumnContractV1(
        name=name,
        ordinal=ordinal,
        postgres_type=postgres_type,
        nullable=nullable,
        generation=(
            DatabaseColumnGeneration.DEFAULT
            if default
            else DatabaseColumnGeneration.NONE
        ),
        expression=default,
    )


def _table(
    name: str, columns: tuple[DatabaseColumnContractV1, ...]
) -> ModuleDatabaseTableContractV1:
    return ModuleDatabaseTableContractV1(
        name=name,
        relation_kind=DatabaseRelationKind.TABLE,
        columns=columns,
    )


database_catalog = ModuleDatabaseCatalogContributionV1(
    lineage_head="dc_0006_observation_key_identity",
    # The contribution contract requires canonical table-name order. Column
    # order remains physical ordinal order inside each table.
    tables=(
        _table(
            "deployment_plans",
            (
                _column("id", 1, _UUID, nullable=False),
                _column("target_id", 2, _UUID, nullable=False),
                _column("sequence", 3, _INTEGER, nullable=False),
                _column("status", 4, _VARCHAR_24, nullable=False),
                _column("snapshot", 5, _JSONB, nullable=True),
                _column("desired_revision", 6, _INTEGER, nullable=False),
                # dc_0001 created VARCHAR(64); dc_0002 establishes this final
                # post-lineage-head width without rewriting existing values.
                _column("plan_digest", 7, _VARCHAR_128, nullable=True),
                _column("requires_approval", 8, _BOOLEAN, nullable=False),
                _column("approval_policy_code", 9, _VARCHAR_120, nullable=True),
                _column("approval_policy_version", 10, _INTEGER, nullable=True),
                _column("approval_decision_ref", 11, _VARCHAR_200, nullable=True),
                _column("approved_at", 12, _TIMESTAMPTZ, nullable=True),
                _column("superseded_by_id", 13, _UUID, nullable=True),
                _column("record_version", 14, _INTEGER, nullable=False),
                _column(
                    "created_at", 15, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                _column(
                    "updated_at", 16, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                # dc_0003 APPENDS these four. PostgreSQL assigns `attnum` in
                # ADD COLUMN order, so they sit after the timestamps rather
                # than beside `plan_digest` where a reader would expect them —
                # this declaration records the physical truth, not the tidy
                # one, because the clean-room comparison is against a migrated
                # database.
                _column("operation", 17, _VARCHAR_20, nullable=True),
                _column("execution_plan_digest", 18, _VARCHAR_128, nullable=True),
                _column("authorized_operation", 19, _VARCHAR_20, nullable=True),
                _column(
                    "authorized_execution_plan_digest",
                    20,
                    _VARCHAR_128,
                    nullable=True,
                ),
                # dc_0004 APPENDS these four, after dc_0003's, for the same
                # physical reason. Deliberately NO image column here: the
                # authorized image set lives inside `snapshot` (ordinal 5),
                # which is the document `plan_digest` covers.
                _column("approval_decision_status", 21, _VARCHAR_24, nullable=True),
                _column("approval_revoked_at", 22, _TIMESTAMPTZ, nullable=True),
                _column("approval_revocation_ref", 23, _VARCHAR_200, nullable=True),
                _column("approval_revocation_reason", 24, _VARCHAR_200, nullable=True),
            ),
        ),
        _table(
            "deployment_targets",
            (
                _column("id", 1, _UUID, nullable=False),
                _column("target_ref", 2, _VARCHAR_200, nullable=False),
                _column("subject_ref", 3, _VARCHAR_200, nullable=False),
                _column("product_code", 4, _VARCHAR_120, nullable=False),
                _column("environment", 5, _VARCHAR_60, nullable=False),
                _column("status", 6, _VARCHAR_24, nullable=False),
                _column("desired_release_ref", 7, _VARCHAR_200, nullable=True),
                _column("desired_spec", 8, _JSONB, nullable=True),
                _column("licence_ref", 9, _VARCHAR_200, nullable=True),
                _column("brand_profile_ref", 10, _VARCHAR_200, nullable=True),
                _column("desired_revision", 11, _INTEGER, nullable=False),
                _column("observed_release_ref", 12, _VARCHAR_200, nullable=True),
                _column("observed_spec_digest", 13, _VARCHAR_128, nullable=True),
                _column("observed_revision", 14, _INTEGER, nullable=True),
                _column("last_observed_at", 15, _TIMESTAMPTZ, nullable=True),
                _column("record_version", 16, _INTEGER, nullable=False),
                _column(
                    "created_at", 17, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                _column(
                    "updated_at", 18, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                # dc_0004 appends the declared authorized image set here, on
                # the TARGET, where desired state is mutable and revisioned.
                _column("desired_images", 19, _JSONB, nullable=True),
                # dc_0006 appends the trusted execution high-water coordinate.
                _column("last_execution_sequence", 20, _INTEGER, nullable=True),
                _column("last_execution_attempt_no", 21, _INTEGER, nullable=True),
                _column("last_execution_state_digest", 22, _VARCHAR_128, nullable=True),
            ),
        ),
        _table(
            "observation_attempts",
            (
                _column("id", 1, _UUID, nullable=False),
                _column("received_at", 2, _TIMESTAMPTZ, nullable=False),
                _column("raw_body", 3, _BYTEA, nullable=True),
                _column("raw_body_truncated", 4, _BOOLEAN, nullable=False),
                _column("raw_body_digest", 5, _VARCHAR_128, nullable=True),
                _column("signature_status", 6, _VARCHAR_20, nullable=False),
                _column("eligibility_at_receipt", 7, _VARCHAR_20, nullable=False),
                _column("key_id", 8, _VARCHAR_200, nullable=True),
                _column("authenticated_target_ref", 9, _VARCHAR_200, nullable=True),
                _column("claimed_target_ref", 10, _VARCHAR_200, nullable=True),
                _column("report_id", 11, _VARCHAR_200, nullable=True),
                _column("disposition", 12, _VARCHAR_40, nullable=False),
                _column("receipt_id", 13, _UUID, nullable=True),
                _column(
                    "created_at", 14, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                _column(
                    "updated_at", 15, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
            ),
        ),
        _table(
            "observation_receipts",
            (
                _column("id", 1, _UUID, nullable=False),
                _column("authenticated_target_ref", 2, _VARCHAR_200, nullable=False),
                _column("report_id", 3, _VARCHAR_200, nullable=False),
                _column("payload", 4, _BYTEA, nullable=True),
                _column("payload_digest", 5, _VARCHAR_128, nullable=True),
                _column("key_id", 6, _VARCHAR_200, nullable=False),
                _column("first_received_at", 7, _TIMESTAMPTZ, nullable=False),
                _column("original_verdict", 8, _VARCHAR_40, nullable=False),
                _column("observed_release_ref", 9, _VARCHAR_200, nullable=True),
                _column("observed_spec_digest", 10, _VARCHAR_128, nullable=True),
                _column(
                    "created_at", 11, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                _column(
                    "updated_at", 12, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                # dc_0006 appends the signed execution coordinate and the
                # substantive-state digest carried by this canonical receipt.
                _column("execution_sequence", 13, _INTEGER, nullable=True),
                _column("attempt_no", 14, _INTEGER, nullable=True),
                _column("observed_state_digest", 15, _VARCHAR_128, nullable=True),
            ),
        ),
        _table(
            "rollout_attempts",
            (
                _column("id", 1, _UUID, nullable=False),
                _column("rollout_id", 2, _UUID, nullable=False),
                _column("attempt_no", 3, _INTEGER, nullable=False),
                _column("outcome", 4, _VARCHAR_20, nullable=False),
                _column("integrator_ref", 5, _VARCHAR_200, nullable=True),
                _column("error_code", 6, _VARCHAR_60, nullable=True),
                _column("detail", 7, _TEXT, nullable=True),
                _column("dispatched_at", 8, _TIMESTAMPTZ, nullable=True),
                _column("settled_at", 9, _TIMESTAMPTZ, nullable=True),
                _column(
                    "created_at", 10, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                _column(
                    "updated_at", 11, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
            ),
        ),
        _table(
            "rollouts",
            (
                _column("id", 1, _UUID, nullable=False),
                _column("rollout_ref", 2, _VARCHAR_200, nullable=False),
                _column("target_id", 3, _UUID, nullable=False),
                _column("plan_id", 4, _UUID, nullable=False),
                _column("status", 5, _VARCHAR_24, nullable=False),
                _column("reason", 6, _TEXT, nullable=True),
                _column("completed_at", 7, _TIMESTAMPTZ, nullable=True),
                _column("record_version", 8, _INTEGER, nullable=False),
                _column("created_at", 9, _TIMESTAMPTZ, nullable=False, default="now()"),
                _column(
                    "updated_at", 10, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                # dc_0005 appends the immutable portable authorization.
                _column("authorization_envelope", 11, _JSONB, nullable=True),
                # dc_0006 appends the per-target monotonic execution coordinate.
                _column("execution_sequence", 12, _INTEGER, nullable=True),
            ),
        ),
        _table(
            "target_credentials",
            (
                _column("id", 1, _UUID, nullable=False),
                _column("target_id", 2, _UUID, nullable=False),
                _column("key_id", 3, _VARCHAR_200, nullable=False),
                _column("public_key_b64", 4, _VARCHAR_200, nullable=False),
                _column("public_key_fingerprint", 5, _VARCHAR_128, nullable=False),
                _column("status", 6, _VARCHAR_20, nullable=False),
                _column("activated_at", 7, _TIMESTAMPTZ, nullable=True),
                _column("retired_at", 8, _TIMESTAMPTZ, nullable=True),
                _column("revoked_at", 9, _TIMESTAMPTZ, nullable=True),
                _column("revocation_reason", 10, _VARCHAR_200, nullable=True),
                _column("enrollment_authority", 11, _VARCHAR_60, nullable=False),
                _column(
                    "created_at", 12, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                _column(
                    "updated_at", 13, _TIMESTAMPTZ, nullable=False, default="now()"
                ),
                # dc_0006 appends the exact verification interpretation. NULL
                # is only for legacy rows whose algorithm was never recorded.
                _column("algorithm", 14, _VARCHAR_60, nullable=True),
                _column("purpose", 15, _VARCHAR_60, nullable=True),
            ),
        ),
    ),
)


__all__ = ["database_catalog"]
