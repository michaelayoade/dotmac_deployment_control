"""The module publishes one exact post-dc_0002 structure declaration."""

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
            revision="dc_0002_canonical_plan_digest",
        ),
    )


def test_manifest_binds_the_source_owned_database_catalogue() -> None:
    assert module.database_catalog is database_catalog
    assert database_catalog.lineage_head == "dc_0002_canonical_plan_digest"


def test_catalogue_has_the_exact_seven_table_ninety_five_column_extent() -> None:
    counts = {table.name: len(table.columns) for table in database_catalog.tables}

    assert counts == {
        "deployment_plans": 16,
        "deployment_targets": 18,
        "observation_attempts": 15,
        "observation_receipts": 12,
        "rollout_attempts": 11,
        "rollouts": 10,
        "target_credentials": 13,
    }
    assert sum(counts.values()) == 95


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
                revision="dc_0002_canonical_plan_digest",
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
    assert sum(len(table.columns) for table in restored.tables) == 95
    assert {table.plane.value for table in restored.tables} == {"platform"}
