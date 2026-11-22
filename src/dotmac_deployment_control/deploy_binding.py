"""What a deploy plan binds, and the deployment set above it.

Everything here goes INSIDE the plan snapshot and therefore inside the plan
digest, so an approval over the digest covers all of it:

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
COMPANION_ORDER: Final = "after_primary_ready"
_SERVICE = re.compile(r"[a-z][a-z0-9_-]{0,63}")


class DeployBindingRefusedError(DeployUnitError):
    """A plan binding was refused."""


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
class DeployPlanBinding:
    params_env_digest: str
    images: tuple[PlannedImage, ...]
    lease_ttl_seconds: int
    legacy: LegacyPlanBinding | None = None
    companion_order: str | None = None

    def payload(self) -> dict[str, Any]:
        """The canonical, JSON-safe document that enters the plan snapshot."""
        return {
            "params_env_digest": self.params_env_digest,
            "images": [i.payload() for i in self.images],
            "lease_ttl_seconds": self.lease_ttl_seconds,
            "legacy": None if self.legacy is None else self.legacy.payload(),
            "companion_order": self.companion_order,
        }


def build_deploy_binding(
    *,
    params_env_digest: str,
    images: Sequence[PlannedImage],
    lease_ttl_seconds: int,
    allowlist: PullAllowlist,
    legacy: LegacyPlanBinding | None = None,
    companion_order: str | None = None,
) -> DeployPlanBinding:
    """Validate and freeze a binding. Every refusal is a typed error."""
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
    if companion_order not in (None, COMPANION_ORDER):
        raise DeployBindingRefusedError(f"companion order must be {COMPANION_ORDER}")
    return DeployPlanBinding(
        params_env_digest=params_env_digest,
        images=tuple(sorted(images, key=lambda i: i.service)),
        lease_ttl_seconds=lease_ttl_seconds,
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
