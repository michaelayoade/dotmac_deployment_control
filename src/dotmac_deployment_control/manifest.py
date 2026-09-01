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

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from dotmac_kernel.modules import ModuleManifest
from dotmac_kernel.prerequisites import IDEMPOTENCY_LEDGER_V1, PLATFORM_AUDIT_LOG_V1

from dotmac_deployment_control.database_catalog import database_catalog
from dotmac_deployment_control.web import DEPLOYMENT_CONTROL_SURFACE

#: The installed distribution's version, derived rather than declared — the same
#: mechanism `__version__` adopted in `0.1.0a5`, applied to the field the module
#: registry actually reports.
#:
#: The kernel calls this "the module's own release version" and puts it in
#: exactly three places: a non-empty check, `ModuleInventoryEntry.version`, and
#: the `as_dict()` diagnostics payload. `_check_contract_versions` reads
#: `contract_version` and never this. So a literal here does not protect
#: contract compatibility; it only decides what health and diagnostics REPORT.
try:  # pragma: no cover - the artifact canary exercises this, not the tree
    _INSTALLED_VERSION = _distribution_version("dotmac-deployment-control")
except PackageNotFoundError:  # pragma: no cover
    #: Same refusal shape as `__version__`: a source tree with no install has no
    #: version to report, and guessing one from `pyproject.toml` would rebuild
    #: the second authority a5 removed.
    _INSTALLED_VERSION = "0.0.0+not-installed"

module = ModuleManifest(
    code="deployment_control",
    #: DERIVED from installed metadata, not declared. See `_INSTALLED_VERSION`.
    #:
    #: This field was the literal `0.1.0a2` from a2 through a6, and the comment
    #: that stood here defended it: moving it, it argued, "would make a metadata
    #: repair read as a contract change to every composing assembly".
    #:
    #: That premise does not hold, and the kernel is where it fails. Contract
    #: compatibility is gated by `_check_contract_versions`, which reads
    #: `contract_version` and NOTHING else — `version` reaches only the module
    #: inventory and the diagnostics payload. So a stale literal here never
    #: protected a composing assembly from anything; it just made every health
    #: surface report `0.1.0a2` while `0.1.0a6` was the installed code.
    #:
    #: `contract_version` below remains a literal and remains the thing that
    #: moves when the declared surface changes. That separation is what the old
    #: comment was reaching for, and it is already expressed by the field built
    #: for it.
    version=_INSTALLED_VERSION,
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
    #: The operator's browser surface, on the kernel's CONTRACT-V2 shape.
    #:
    #: `web_surfaces` and not `web_routers`/`nav`: the manifest contract refuses
    #: to hold both, and the legacy pair would drag in the compatibility adapter,
    #: which requires a `staff_admin` facet carrying an `admission_permission` —
    #: a thing a platform-plane assembly is simultaneously forbidden to declare,
    #: because admission is evaluated against a tenant-scoped `Party` that does
    #: not exist on this plane. A v2 contribution joins the existing
    #: `platform_admin` facet instead and declares no admission at all.
    #:
    #: `contract_version` is unchanged. It is inferred as the kernel's current
    #: manifest contract (2), which `web_surfaces` already requires, and the
    #: declared surface a composing assembly is checked against — tables,
    #: prerequisites, audit actions — did not move.
    web_surfaces=(DEPLOYMENT_CONTROL_SURFACE,),
    audit_actions=(
        "deployment.target.changed",
        "deployment.credential.changed",
        "deployment.rollout.changed",
        "deployment.observation.recorded",
    ),
    database_catalog=database_catalog,
)

__all__ = ["module"]
