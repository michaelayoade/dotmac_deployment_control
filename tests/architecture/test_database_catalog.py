"""The module publishes one exact post-dc_0013 structure declaration."""

from __future__ import annotations

import pytest
from dotmac_kernel import (
    ComposedDatabaseLineageHeadV1,
    DatabaseCatalogOwnerKind,
    DatabaseCatalogOwnerV1,
    ModuleDatabaseCatalogSnapshot,
    ProductDatabaseCatalogError,
)

from dotmac_deployment_control import (
    build_database_catalog_snapshot,
    database_catalog,
    module,
)


def _snapshot() -> ModuleDatabaseCatalogSnapshot:
    # `module.version` and NOT a literal. The manifest derives its reported
    # version from installed metadata, so a literal here would rebuild the
    # second version authority that derivation removed — one release bump away
    # from a red suite that says nothing about this module's structure.
    # `test_the_reported_version_is_the_installed_distribution` is what pins
    # that derived value to `pyproject.toml`.
    return build_database_catalog_snapshot(
        distribution_version=module.version,
        composed_lineage_head=ComposedDatabaseLineageHeadV1(
            owner=DatabaseCatalogOwnerV1(
                kind=DatabaseCatalogOwnerKind.MODULE,
                code="deployment_control",
            ),
            revision="dc_0014_rehearsal_issuer_ledger",
        ),
    )


def test_manifest_binds_the_source_owned_database_catalogue() -> None:
    assert module.database_catalog is database_catalog
    assert database_catalog.lineage_head == "dc_0014_rehearsal_issuer_ledger"


def test_catalogue_has_exact_twenty_two_table_245_column_extent() -> None:
    """Thirteen tables and 178 columns after `dc_0012`.

    `dc_0008` adds the eighth table, `recovery_grants`, with 18 columns, and
    `dc_0009` appends the nineteenth: Foundation's identity for the encoding
    that produced the prestate digest already sitting beside it.
    Recovery authority is a document rather than a flag, so the table holds
    the signed envelope plus the terms a reader needs to FIND the right
    grant -- and the count is asserted per table as well as in total for the
    same reason as below: a sum kept right by moving a column between tables
    would hide exactly the change worth seeing.

    a7 published 95, `dc_0003` took it to 99. `dc_0004` adds four to
    `deployment_plans` (the approval's standing and its withdrawal) and ONE to
    `deployment_targets` (the declared authorized image set), and the count is
    asserted PER TABLE as well as in total precisely so a future change cannot
    keep the sum right by moving a column between tables.

    The split across two tables is the load-bearing part here and not an
    accident of tidiness: the image set is declared on the TARGET, where
    desired state is mutable and revisioned, and a plan's frozen set lives
    inside `snapshot` rather than in a column of its own. A `deployment_plans`
    count of 25 would mean somebody had added the sibling image column that
    lets an image change without the plan digest moving.

    `dc_0011` adds three tables for the durable attestation trust registry,
    and `dc_0012` adds the nine-column rehearsal grant ledger:
    the append-only `attestation_enrolments` (13 columns), the append-only
    `attestation_fingerprint_closures` (8 columns), and the deliberately
    mutable derived projection `attestation_current_roots` (5 columns) --
    143 + 5 + 13 + 8 + 9 = 178.

    `dc_0013` adds eight host-admission tables and 49 columns: permanent
    attestation-subject locks, immutable root descriptors, append-only host and
    policy revisions plus closure/successor evidence, and two mutable current
    projections. That gave 21 tables and 227 columns.

    `dc_0014` adds one more: the 18-column rehearsal-issuer-authorization
    ledger, a SIBLING of `rehearsal_grants` recording a different authority
    (operate the disposable rehearsal issuer for one lease, rather than the
    provoked-rollback replay coordinate `rehearsal_grants` already records).
    The exact post-revision extent is therefore 22 tables and 245 columns.
    """
    counts = {table.name: len(table.columns) for table in database_catalog.tables}

    assert counts == {
        "attestation_current_roots": 5,
        "attestation_enrolments": 13,
        "attestation_fingerprint_closures": 8,
        "attestation_root_descriptors": 7,
        "attestation_subject_locks": 4,
        "deployment_plans": 24,
        "deployment_targets": 22,
        "observation_attempts": 15,
        "observation_receipts": 15,
        "recovery_grants": 19,
        "rehearsal_grants": 9,
        "rehearsal_issuer_authorizations": 18,
        "rollout_attempts": 12,
        "rollout_attempt_settlements": 9,
        "rollouts": 12,
        "target_credentials": 15,
        "target_admission_policies": 11,
        "target_admission_policy_closures": 6,
        "target_current_admission_policies": 4,
        "target_current_hosts": 4,
        "target_host_association_closures": 6,
        "target_host_associations": 7,
    }
    assert sum(counts.values()) == 245


def test_rehearsal_grants_publishes_the_migration_column_shape() -> None:
    rehearsal = next(
        table for table in database_catalog.tables if table.name == "rehearsal_grants"
    )
    assert [column.name for column in rehearsal.columns] == [
        "id",
        "grant_id",
        "single_use_reference",
        "state",
        "revoked_at",
        "revocation_ref",
        "spent_at",
        "created_at",
        "updated_at",
    ]
    assert [column.ordinal for column in rehearsal.columns] == list(range(1, 10))
    assert [column.nullable for column in rehearsal.columns] == [
        False,
        False,
        False,
        False,
        True,
        True,
        True,
        False,
        False,
    ]
    assert [column.postgres_type.formatted for column in rehearsal.columns][1:3] == [
        "character varying(512)",
        "character varying(512)",
    ]


def test_rehearsal_issuer_authorizations_publishes_the_migration_column_shape() -> None:
    """A SIBLING shape to `rehearsal_grants`, not the same table -- see
    `dc_0014`'s own docstring for why the two authorities never share one."""
    ledger = next(
        table
        for table in database_catalog.tables
        if table.name == "rehearsal_issuer_authorizations"
    )
    assert [column.name for column in ledger.columns] == [
        "id",
        "authorization_id",
        "single_use_reference",
        "lease_id",
        "plan_id",
        "target_id",
        "controller_fingerprint",
        "harness_evidence_digest",
        "authorization_envelope",
        "not_before",
        "issued_at",
        "expires_at",
        "state",
        "revoked_at",
        "revocation_ref",
        "spent_at",
        "created_at",
        "updated_at",
    ]
    assert [column.ordinal for column in ledger.columns] == list(range(1, 19))
    assert [column.nullable for column in ledger.columns] == [
        False,  # id
        False,  # authorization_id
        False,  # single_use_reference
        False,  # lease_id
        False,  # plan_id
        False,  # target_id
        False,  # controller_fingerprint
        False,  # harness_evidence_digest
        False,  # authorization_envelope
        False,  # not_before
        False,  # issued_at
        False,  # expires_at
        False,  # state
        True,  # revoked_at
        True,  # revocation_ref
        True,  # spent_at
        False,  # created_at
        False,  # updated_at
    ]
    assert (
        next(
            c for c in ledger.columns if c.name == "authorization_envelope"
        ).postgres_type.formatted
        == "jsonb"
    )


def test_dc_0005_appends_the_portable_authorization_to_the_rollout() -> None:
    """The envelope is an immutable issuance fact, not mutable plan standing.

    Approval revocation changes whether dispatch is allowed.  It does not
    rewrite the bytes that were issued when the rollout was requested, so the
    portable envelope belongs on the rollout and nowhere else.
    """
    rollouts = next(
        table for table in database_catalog.tables if table.name == "rollouts"
    )
    envelope = next(
        column for column in rollouts.columns if column.name == "authorization_envelope"
    )

    assert envelope.ordinal == 11
    assert envelope.postgres_type.formatted == "jsonb"
    assert envelope.nullable
    assert envelope.expression == ""


def test_no_plan_column_holds_the_authorized_image_set() -> None:
    """The image set is INSIDE the digest, so it is not beside it.

    Stated as a property of the published structure rather than left to the
    migration's prose, because this is the one shape that would quietly undo
    the whole change: a `deployment_plans.authorized_images` column is a value
    an `UPDATE` can move while `plan_digest` sits still, so an image could
    change under a live approval with the digest, the evidence and every screen
    still agreeing.

    `snapshot` is where a plan's frozen set lives, and `snapshot` is the exact
    document `plan_digest` is computed over.
    """
    plans = next(
        table for table in database_catalog.tables if table.name == "deployment_plans"
    )
    names = {column.name for column in plans.columns}

    assert not [name for name in names if "image" in name], sorted(names)
    assert "snapshot" in names


def test_dc_0004_appends_the_approval_standing_and_the_target_image_set() -> None:
    """Five columns, in ADD COLUMN order, across the two tables they belong on."""
    plans = next(
        table for table in database_catalog.tables if table.name == "deployment_plans"
    )
    targets = next(
        table for table in database_catalog.tables if table.name == "deployment_targets"
    )
    tail = {column.name: column for column in plans.columns if column.ordinal > 20}

    assert [
        (name, tail[name].ordinal)
        for name in (
            "approval_decision_status",
            "approval_revoked_at",
            "approval_revocation_ref",
            "approval_revocation_reason",
        )
    ] == [
        ("approval_decision_status", 21),
        ("approval_revoked_at", 22),
        ("approval_revocation_ref", 23),
        ("approval_revocation_reason", 24),
    ]

    images = next(
        column for column in targets.columns if column.name == "desired_images"
    )
    assert images.ordinal == 19
    assert images.postgres_type.formatted == "jsonb"

    # Every one nullable and with NO generated default, and the two defaults
    # that would have been tempting are the two that would lie: `'[]'` would
    # make every existing target claim to authorize no images (a declaration,
    # not an absence), and `'granted'` would make every plan approved before
    # this revision assert a standing decision nobody recorded.
    for column in (*tail.values(), images):
        assert column.nullable, column.name
        assert column.expression == "", column.name


def test_dc_0003_appends_the_execution_binding_in_add_column_order() -> None:
    """The four new columns sit AFTER the timestamps, not beside `plan_digest`.

    PostgreSQL assigns `attnum` in ADD COLUMN order, and the clean-room canary
    compares this declaration against a migrated database. A declaration that
    put them where a reader would expect them would be describing a database
    that does not exist.
    """
    plans = next(
        table for table in database_catalog.tables if table.name == "deployment_plans"
    )
    # BOUNDED AT BOTH ENDS. `> 16` alone was correct while `dc_0003` was the
    # head and silently became a claim about every later revision's columns
    # too: `dc_0004` appends four more to this table, and an open-ended window
    # would report them as `dc_0003`'s. A test whose subject grows with the
    # lineage is a test that stops describing what it is named for.
    tail = {
        column.name: column for column in plans.columns if 16 < column.ordinal <= 20
    }

    assert sorted(tail) == [
        "authorized_execution_plan_digest",
        "authorized_operation",
        "execution_plan_digest",
        "operation",
    ]
    assert [
        tail[name].ordinal
        for name in (
            "operation",
            "execution_plan_digest",
            "authorized_operation",
            "authorized_execution_plan_digest",
        )
    ] == [
        17,
        18,
        19,
        20,
    ]
    # Every one nullable and with no generated default. A default would make a
    # legacy row claim an operation nobody declared — the inference the closed
    # vocabulary exists to refuse.
    for column in tail.values():
        assert column.nullable, column.name
        assert column.expression == "", column.name


def test_dc_0002_final_digest_width_is_declared_not_the_root_width() -> None:
    plans = next(
        table for table in database_catalog.tables if table.name == "deployment_plans"
    )
    digest = next(column for column in plans.columns if column.name == "plan_digest")

    assert digest.ordinal == 7
    assert digest.postgres_type.name == "varchar"
    assert digest.postgres_type.formatted == "character varying(128)"


def test_release_snapshot_keeps_the_three_version_facts_distinct() -> None:
    snapshot = _snapshot()

    assert snapshot.distribution_name == "dotmac-deployment-control"
    assert snapshot.distribution_version == module.version
    assert snapshot.module_code == "deployment_control"
    assert snapshot.module_release_version == module.version
    # The fact that stays genuinely INDEPENDENT once the release version is
    # derived: manifest compatibility is an integer generation, not a release
    # string. The two release coordinates above can no longer disagree by
    # construction, and pinning them to a literal would only assert the
    # distribution's version twice.
    assert snapshot.manifest_contract_version == module.contract_version
    assert isinstance(snapshot.manifest_contract_version, int)
    assert snapshot.manifest_contract_version != snapshot.module_release_version


def test_release_snapshot_refuses_distribution_module_version_drift() -> None:
    with pytest.raises(ProductDatabaseCatalogError, match="must agree"):
        build_database_catalog_snapshot(
            distribution_version="different-release",
            composed_lineage_head=ComposedDatabaseLineageHeadV1(
                owner=DatabaseCatalogOwnerV1(
                    kind=DatabaseCatalogOwnerKind.MODULE,
                    code="deployment_control",
                ),
                revision="dc_0014_rehearsal_issuer_ledger",
            ),
        )


def test_release_snapshot_is_canonical_and_round_trips_with_its_digest() -> None:
    snapshot = _snapshot()
    payload = snapshot.to_json_bytes()

    restored = ModuleDatabaseCatalogSnapshot.from_json_bytes(
        payload,
        expected_digest=snapshot.digest,
    )

    assert restored == snapshot
    assert restored.to_json_bytes() == payload
    assert sum(len(table.columns) for table in restored.tables) == 245
    assert {table.plane.value for table in restored.tables} == {"platform"}
