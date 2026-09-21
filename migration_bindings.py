"""Prerequisite bindings for this repository's standalone migration assembly.

The published module names logical database effects and never foreign revision
ids.  This repository's Alembic harness is the assembly used to prove the
module lineage against a clean Kernel database, so it must bind those effects
to the exact Kernel revisions that complete them before Alembic builds the
revision graph.
"""

from typing import Final

from dotmac_kernel.prerequisites import (
    IDEMPOTENCY_LEDGER_V1,
    PLATFORM_AUDIT_LOG_V1,
    PrerequisiteBinding,
)

ASSEMBLY_PREREQUISITE_BINDINGS: Final[tuple[PrerequisiteBinding, ...]] = (
    PrerequisiteBinding(
        prerequisite=IDEMPOTENCY_LEDGER_V1.name,
        provider_revision="0018_idempotency_one_owner",
        provider_owner="kernel",
    ),
    PrerequisiteBinding(
        prerequisite=PLATFORM_AUDIT_LOG_V1.name,
        provider_revision="0026_platform_audit_log",
        provider_owner="kernel",
    ),
)

__all__ = ["ASSEMBLY_PREREQUISITE_BINDINGS"]
