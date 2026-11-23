"""What a deploy plan binds, and the deployment set above it.

Everything here goes INSIDE the plan snapshot and therefore inside the plan
digest, so an approval over the digest covers all of it:

* `deploy_unit_digest`, computed by Control over the descriptor bytes;
* `params_env_digest` (design 2.5);
* every image reference and its pinned manifest digest, with `image.source` and
  the loopback repository string (2.7);
* the `[legacy_env_file]` policy version, sha and names (2.8);
* the companion order;
* the lease TTL (2.6.2), capped at one hour.

The binding is OPTIONAL on a plan. A plan proposed without one has a snapshot
byte-identical to before this module existed, so existing plans, digests and
approvals are untouched (additive, off by default).

A `DeploymentSet` gets one approval over `set_digest`; the companion is released
only after the primary's signed observation is `healthy`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from dotmac_deployment_control.deploy_unit import DeployUnitError
from dotmac_deployment_control.digests import (
    DeploymentSetDigestV1,
    is_canonical_digest,
)
from dotmac_deployment_control.image_policy import (
    PullAllowlist,
    check_planned_image,
)
from dotmac_deployment_control.legacy_policy import LegacyPlanBinding

MAX_LEASE_TTL_SECONDS: Final = 3600
#: A plan that dispatches a role job (import-only OpenBao) bounds its lease at 15 min.
MAX_JOB_ROLE_LEASE_TTL_SECONDS: Final = 900
COMPANION_ORDER: Final = "after_primary_ready"
_SEGMENT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SERVICE = re.compile(r"[a-z][a-z0-9_-]{0,63}")


class DeployBindingRefusedError(DeployUnitError):
    """A plan binding was refused."""


@dataclass(frozen=True, slots=True)
class DeployPlanInputs:
    """The only inputs a caller supplies for a descriptor-backed plan.

    Everything else in the binding (params digest, images, active bindings,
    companion order, legacy part) is DERIVED by Control from the re-verified
    descriptor and its own stored state. The TTL is bounded by Control; the
    loopback port is needed only for a transferred image.
    """

    lease_ttl_seconds: int
    loopback_port: int | None = None


@dataclass(frozen=True, slots=True)
class PlannedImage:
    service: str
    source: str
    release_repository: str
    release_digest: str
    planned_repository: str
    planned_digest: str

    def payload(self) -> dict[str, str]:
        return {
            "service": self.service,
            "source": self.source,
            "release_repository": self.release_repository,
            "release_digest": self.release_digest,
            "planned_repository": self.planned_repository,
            "planned_digest": self.planned_digest,
        }


@dataclass(frozen=True, slots=True)
class PlanRole:
    """One role of an active binding and whether its secret_id is single-use."""

    role: str
    single_use: bool

    def payload(self) -> dict[str, object]:
        return {"role": self.role, "single_use": self.single_use}


@dataclass(frozen=True, slots=True)
class PlanJob:
    """One dispatchable job, as the plan binds it.

    `role` (if any) is the OpenBao role whose secret_id is minted ONLY when this
    job is dispatched; `single_use` is that role's mode (provisional, from the
    descriptor's bindings). `params` are the param names scoped to this job and
    `params_env_digest` the digest of their canonical render: they reach this
    job's env and never the serving app's params.env.
    """

    name: str
    role: str | None
    single_use: bool | None
    materials: tuple[str, ...]
    params: tuple[str, ...]
    params_env_digest: str

    def payload(self) -> dict[str, object]:
        return {
            "name": self.name,
            "role": self.role,
            "single_use": self.single_use,
            "materials": list(self.materials),
            "params": list(self.params),
            "params_env_digest": self.params_env_digest,
        }


@dataclass(frozen=True, slots=True)
class DeployPlanBinding:
    #: Computed by Control over the descriptor bytes (`DeployUnit.digest`).
    deploy_unit_digest: str
    #: sha256 of the released product.toml the descriptor's spec names.
    product_toml_sha256: str
    params_env_digest: str
    images: tuple[PlannedImage, ...]
    lease_ttl_seconds: int
    #: Names of the descriptor's ACTIVE bindings (pre-staged ones deliver nothing).
    active_binding_names: tuple[str, ...] = ()
    #: Roles derived from the verified descriptor, sorted. The agent mints
    #: secret_ids from THIS, so the list is covered by the plan digest.
    roles: tuple[PlanRole, ...] = ()
    #: The service the primary image belongs to. The agent reads the primary
    #: image through it; there is no "the only image" fallback.
    primary_service: str = ""
    #: OpenBao naming inputs the agent reads from the SIGNED plan (never from
    #: CP): `secrets_namespace` is the descriptor's `<product>` segment and
    #: `secrets_environment` the target's namespace-env (`deployment_targets.
    #: bao_environment`, fixed at registration). Required once there are roles.
    secrets_namespace: str = ""
    secrets_environment: str | None = None
    #: Every job of the descriptor with its role, materials and scoped params.
    jobs: tuple[PlanJob, ...] = ()
    legacy: LegacyPlanBinding | None = None
    companion_order: str | None = None

    def payload(self) -> dict[str, Any]:
        """The canonical, JSON-safe document that enters the plan snapshot."""
        return {
            "deploy_unit_digest": self.deploy_unit_digest,
            "product_toml_sha256": self.product_toml_sha256,
            "params_env_digest": self.params_env_digest,
            "images": [i.payload() for i in self.images],
            "lease_ttl_seconds": self.lease_ttl_seconds,
            "active_binding_names": list(self.active_binding_names),
            "roles": [role.payload() for role in self.roles],
            "primary_service": self.primary_service,
            "secrets_namespace": self.secrets_namespace,
            "secrets_environment": self.secrets_environment,
            "jobs": [job.payload() for job in self.jobs],
            "legacy": None if self.legacy is None else self.legacy.payload(),
            "companion_order": self.companion_order,
        }


def build_deploy_binding(
    *,
    deploy_unit_digest: str,
    product_toml_sha256: str,
    params_env_digest: str,
    images: Sequence[PlannedImage],
    lease_ttl_seconds: int,
    allowlist: PullAllowlist,
    legacy: LegacyPlanBinding | None = None,
    companion_order: str | None = None,
    active_binding_names: Sequence[str] = (),
    roles: Sequence[PlanRole] = (),
    primary_service: str = "",
    secrets_namespace: str = "",
    secrets_environment: str | None = None,
    jobs: Sequence[PlanJob] = (),
) -> DeployPlanBinding:
    """Validate and freeze a binding. Every refusal is a typed error."""
    if not is_canonical_digest(deploy_unit_digest):
        raise DeployBindingRefusedError("deploy_unit_digest must be sha256:<64 hex>")
    if not is_canonical_digest(product_toml_sha256):
        raise DeployBindingRefusedError("product_toml_sha256 must be sha256:<64 hex>")
    if not is_canonical_digest(params_env_digest):
        raise DeployBindingRefusedError("params_env_digest must be sha256:<64 hex>")
    if (
        isinstance(lease_ttl_seconds, bool)
        or not isinstance(lease_ttl_seconds, int)
        or not 1 <= lease_ttl_seconds <= MAX_LEASE_TTL_SECONDS
    ):
        raise DeployBindingRefusedError(
            f"the lease TTL must be 1..{MAX_LEASE_TTL_SECONDS} seconds"
        )
    if (
        any(job.role for job in jobs)
        and lease_ttl_seconds > MAX_JOB_ROLE_LEASE_TTL_SECONDS
    ):
        raise DeployBindingRefusedError(
            f"a plan with a role job bounds the lease at {MAX_JOB_ROLE_LEASE_TTL_SECONDS} seconds"
        )
    if not images:
        raise DeployBindingRefusedError("a deploy plan binds at least one image")
    services = [i.service for i in images]
    if len(set(services)) != len(services) or not all(
        _SERVICE.fullmatch(s) for s in services
    ):
        raise DeployBindingRefusedError("image services must be unique and well formed")
    for image in images:
        check_planned_image(
            source=image.source,
            release_repository=image.release_repository,
            release_digest=image.release_digest,
            planned_repository=image.planned_repository,
            planned_digest=image.planned_digest,
            allowlist=allowlist,
        )
    if primary_service not in services:
        raise DeployBindingRefusedError("the primary service is one of the images")
    for job in jobs:
        if not is_canonical_digest(job.params_env_digest):
            raise DeployBindingRefusedError("a job params digest is sha256:<64 hex>")
    if len({job.name for job in jobs}) != len(jobs):
        raise DeployBindingRefusedError("a job appears once")
    needs_naming = bool(roles) or any(job.role for job in jobs)
    if needs_naming:
        if not secrets_namespace or not secrets_environment:
            raise DeployBindingRefusedError(
                "a plan with roles carries the OpenBao naming: secrets_namespace "
                "and secrets_environment"
            )
    for label, value in (
        ("secrets_namespace", secrets_namespace or None),
        ("secrets_environment", secrets_environment),
    ):
        if value is not None and not _SEGMENT_NAME.fullmatch(value):
            raise DeployBindingRefusedError(f"{label} is a lowercase segment")
    if len({r.role for r in roles}) != len(roles):
        raise DeployBindingRefusedError("a role appears once")
    if companion_order not in (None, COMPANION_ORDER):
        raise DeployBindingRefusedError(f"companion order must be {COMPANION_ORDER}")
    return DeployPlanBinding(
        deploy_unit_digest=deploy_unit_digest,
        product_toml_sha256=product_toml_sha256,
        params_env_digest=params_env_digest,
        images=tuple(sorted(images, key=lambda i: i.service)),
        lease_ttl_seconds=lease_ttl_seconds,
        active_binding_names=tuple(sorted(set(active_binding_names))),
        roles=tuple(sorted(roles, key=lambda r: r.role)),
        primary_service=primary_service,
        secrets_namespace=secrets_namespace,
        secrets_environment=secrets_environment,
        jobs=tuple(sorted(jobs, key=lambda job: job.name)),
        legacy=legacy,
        companion_order=companion_order,
    )


# ── Deployment set ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeploymentSet:
    """A primary plan and its companion, approved once over `set_digest`."""

    primary_plan_digest: str
    companion_plan_digest: str | None = None
    order: str = COMPANION_ORDER
    required_at_switch: bool = False

    def __post_init__(self) -> None:
        for digest in (self.primary_plan_digest, self.companion_plan_digest):
            if digest is not None and not is_canonical_digest(digest):
                raise DeployBindingRefusedError("set members are plan digests")
        if self.primary_plan_digest == self.companion_plan_digest:
            raise DeployBindingRefusedError("a set cannot name one plan twice")
        if self.order != COMPANION_ORDER:
            raise DeployBindingRefusedError(f"set order must be {COMPANION_ORDER}")
        if self.companion_plan_digest is None and self.required_at_switch:
            raise DeployBindingRefusedError("a set with no companion cannot require it")

    def payload(self) -> dict[str, Any]:
        return {
            "primary_plan_digest": self.primary_plan_digest,
            "companion_plan_digest": self.companion_plan_digest,
            "order": self.order,
            "required_at_switch": self.required_at_switch,
        }

    def set_digest(self) -> str:
        return DeploymentSetDigestV1.over_json(self.payload()).canonical

    def may_release_companion(self, primary_observation_state: str) -> bool:
        """The companion is released only after the primary is `healthy`."""
        return (
            self.companion_plan_digest is not None
            and primary_observation_state == "healthy"
        )
