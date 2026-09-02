"""The module publishes one exact post-dc_0004 structure declaration."""

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
            revision="dc_0004_authorized_image_set",
        ),
    )


def test_manifest_binds_the_source_owned_database_catalogue() -> None:
    assert module.database_catalog is database_catalog
    assert database_catalog.lineage_head == "dc_0004_authorized_image_set"


def test_catalogue_has_the_exact_seven_table_hundred_and_four_column_extent() -> None:
    """Seven tables and 104 columns after `dc_0004`.

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
    """
    counts = {table.name: len(table.columns) for table in database_catalog.tables}

    assert counts == {
        "deployment_plans": 24,
        "deployment_targets": 19,
        "observation_attempts": 15,
        "observation_receipts": 12,
        "rollout_attempts": 11,
        "rollouts": 10,
        "target_credentials": 13,
    }
    assert sum(counts.values()) == 104


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
                revision="dc_0004_authorized_image_set",
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
    assert sum(len(table.columns) for table in restored.tables) == 104
    assert {table.plane.value for table in restored.tables} == {"platform"}
