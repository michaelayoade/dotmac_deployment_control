"""Release-bound emission of Deployment Control's database catalogue.

The module owns the structural contribution; a release/composition lane supplies
the exact distribution version and the composed Alembic-head evidence. Keeping
that evidence as an input prevents source code from self-asserting that its
authored head was the head the build actually composed.
"""

from __future__ import annotations

from dotmac_kernel import (
    ComposedDatabaseLineageHeadV1,
    ModuleDatabaseCatalogSnapshot,
    ProductDatabaseCatalogError,
)

from dotmac_deployment_control.manifest import module

_DISTRIBUTION_NAME = "dotmac-deployment-control"


def build_database_catalog_snapshot(
    *,
    distribution_version: str,
    composed_lineage_head: ComposedDatabaseLineageHeadV1,
) -> ModuleDatabaseCatalogSnapshot:
    """Freeze the source-owned contribution for one exact release build."""

    if distribution_version != module.version:
        raise ProductDatabaseCatalogError(
            "Deployment Control's distribution and module release versions "
            f"must agree: distribution={distribution_version!r}, "
            f"module={module.version!r}"
        )
    return ModuleDatabaseCatalogSnapshot.from_manifest(
        module,
        distribution_name=_DISTRIBUTION_NAME,
        distribution_version=distribution_version,
        composed_lineage_head=composed_lineage_head,
    )


__all__ = ["build_database_catalog_snapshot"]
