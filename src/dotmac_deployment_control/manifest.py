"""Deployment Control's `ModuleManifest` — the sixteenth stateful module.

Must match `DEPLOYMENT_CONTROL_MIGRATION_OWNER` in the kernel ledger exactly or
`NamespaceRegistry.from_manifests` refuses the composition at boot:
`short_code="deploy"` -> `mod_deploy`, `migration_prefix="dc"` -> `dc_0001_...`,
`migration_branch="deployment_control"`, and `platform_tables` bounding what the
composed gate will accept the migration creating.

## Platform plane only, and the reason is close to tautological

A module that decides what a fleet of deployments should run cannot live inside
one of those deployments. `tables=()` is a DECLARATION (ADR-0023 rejects
inferring a plane from a missing `tenant_id`), and ADR-0057 § 7 derives it from
the one consumer that exists today: the vendor control plane.

The deployments themselves are separate applications. They learn what to do
through the Integrator and report back through a signed envelope the kernel
verifies (ADR-0007) — never by reading this schema (ADR-0024).

## Four audit actions, split by SUBJECT

`deployment.target.changed`, `deployment.credential.changed`,
`deployment.rollout.changed`, `deployment.observation.recorded`.

Split by subject rather than by verb, because an operator reading an audit trail
is asking one of four genuinely different questions: did the fleet's INTENT
change, did a deployment's IDENTITY change, did we DECIDE to roll something out,
or did a deployment TELL us something? Collapsing them would make each of those
require opening every detail blob; splitting per verb would put the lifecycle in
two places and let the manifest and the enums drift.

Contrast `dotmac-commercial-agreements`, which declares exactly one because every
transition there is the same actor doing the same kind of thing.

## Two logical prerequisites, both written at REQUEST time

Neither is created by this module's own migrations, and an undeclared runtime
dependency is still a dependency — it just has no DDL to betray it.

- Every command delegates at-most-once to the kernel (hard rule 23, ADR-0014),
  writing `public.platform_idempotency_records`.
- Every command writes `public.platform_audit_events` inside the same operation.

COMMON rather than `platform_requires`: this module has exactly one plane, so the
declared platform plane installs atomically and there is no selection under which
the requirement could lapse.
"""

from __future__ import annotations

from dotmac_kernel.modules import ModuleManifest
from dotmac_kernel.prerequisites import IDEMPOTENCY_LEDGER_V1, PLATFORM_AUDIT_LOG_V1

module = ModuleManifest(
    code="deployment_control",
    #: THE MODULE CONTRACT VERSION, and deliberately not the distribution's.
    #:
    #: A composing assembly reads this to decide contract compatibility, so it
    #: moves when the module's declared surface — code, schema, tables,
    #: prerequisites, audit actions — changes, and NOT when the distribution is
    #: republished. `0.1.0a5` changes behaviour and a column width inside an
    #: already-declared table; it declares no new table, prerequisite or audit
    #: action, so this stays where it is. `0.1.0a6` changes ONLY the declared
    #: `dotmac-kernel` floor and the CI lanes that keep it honest — no source
    #: file under `src/` moved — so moving this would make a metadata repair
    #: read as a contract change to every composing assembly.
    #:
    #: It is a literal, and it is not the second version authority `0.1.0a5`
    #: removed. That one was `__version__`, which duplicated `pyproject.toml`'s
    #: statement of the DISTRIBUTION version and drifted to `0.1.0a2` while the
    #: tree said `0.1.0a4`. `__version__` is now derived from installed
    #: metadata. This field states a different fact and has no other copy.
    #:
    #: Its equality with a4's `__version__` is a coincidence of history, not a
    #: relationship — do not "fix" it by pointing it at the distribution
    #: version, which would make every republication look like a contract change.
    version="0.1.0a2",
    core=False,
    short_code="deploy",
    migration_prefix="dc",
    migration_branch="deployment_control",
    tables=(),
    platform_tables=(
        "deployment_targets",
        "target_credentials",
        "deployment_plans",
        "rollouts",
        "rollout_attempts",
        "observation_receipts",
        "observation_attempts",
    ),
    requires=(IDEMPOTENCY_LEDGER_V1.name, PLATFORM_AUDIT_LOG_V1.name),
    audit_actions=(
        "deployment.target.changed",
        "deployment.credential.changed",
        "deployment.rollout.changed",
        "deployment.observation.recorded",
    ),
)

__all__ = ["module"]
