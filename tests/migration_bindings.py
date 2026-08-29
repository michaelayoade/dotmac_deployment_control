"""This repository's answers to "which revision supplies that effect?".

A module lineage declares the database effects it needs
(`ModuleManifest.requires`) and never names a foreign revision, because the
answer differs per assembly. The assembly answers. **This repository is not an
assembly** — it is the module's own home — so what follows is the answer for the
only composition it ever builds: the one the platform-isolation canary stands up
to test the lineage in isolation.

Scoped to exactly what `dotmac-deployment-control` declares, and no wider. The
manifest requires `idempotency_ledger.v1` and `platform_audit_log.v1`; the
Starter's assembly binds six effects because it composes modules needing the
other four. Copying all six here would bind effects nothing in this repository
requires — noise that reads like a contract.

Binding is not belief. `require_prerequisites` re-proves each effect against the
live catalog before the requiring migration runs, so a wrong revision here fails
at `alembic upgrade` rather than producing a database that looks migrated.
"""

from __future__ import annotations

from typing import Final

from dotmac_kernel.prerequisites import (
    IDEMPOTENCY_LEDGER_V1,
    PLATFORM_AUDIT_LOG_V1,
    PrerequisiteBinding,
)

CANARY_PREREQUISITE_BINDINGS: Final[tuple[PrerequisiteBinding, ...]] = (
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

__all__ = ["CANARY_PREREQUISITE_BINDINGS"]
