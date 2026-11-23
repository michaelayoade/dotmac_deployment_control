"""The Control settings of the deploy-unit contract, as values.

Three named settings, each a visible and ATTENDED change (an approval that says
it was attended and names a register line):

* `public_pull_repositories`: repositories whose images may be pulled instead of
  transferred. EMPTY by default.
* `legacy_env_file_allowed_targets`: the TARGETS that may use
  `[legacy_env_file]`. DEFAULT-DENY (empty); a companion descriptor is refused
  whatever this says.
* `legacy_env_file_ceiling`: the enabled-target ratchet. Starts at 0.

A setting with no stored row has its default; there is no way to store a
default, so "never set" and "set to the default" cannot be told apart by
accident. Pure: no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from dotmac_deployment_control.deploy_unit import DeployUnitError
from dotmac_deployment_control.image_policy import PullAllowlist

SETTING_PULL_REPOSITORIES: Final = "public_pull_repositories"
SETTING_LEGACY_TARGETS: Final = "legacy_env_file_allowed_targets"
SETTING_LEGACY_CEILING: Final = "legacy_env_file_ceiling"
#: Per-target ceiling on a `run_job` plan's lease: {target_ref: seconds}. Default
#: 900 (also for an absent target), hard maximum 3600. Attended like the rest.
SETTING_ROLE_JOB_LEASE_CEILING: Final = "role_job_lease_ceiling_seconds"
DEFAULT_ROLE_JOB_LEASE_CEILING: Final = 900
MIN_ROLE_JOB_LEASE_CEILING: Final = 240
MAX_ROLE_JOB_LEASE_CEILING: Final = 3600
SETTING_NAMES: Final = frozenset(
    {
        SETTING_PULL_REPOSITORIES,
        SETTING_LEGACY_TARGETS,
        SETTING_LEGACY_CEILING,
        SETTING_ROLE_JOB_LEASE_CEILING,
    }
)

_TARGET_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")


class DeploySettingRefusedError(DeployUnitError):
    """A setting name or value was refused."""


@dataclass(frozen=True, slots=True)
class DeploySettings:
    pull_allowlist: PullAllowlist = field(default_factory=PullAllowlist)
    legacy_allowed_targets: frozenset[str] = frozenset()
    legacy_ceiling: int = 0
    role_job_lease_ceilings: Mapping[str, int] = field(default_factory=dict)

    def role_job_lease_ceiling(self, target_ref: str) -> int:
        return self.role_job_lease_ceilings.get(
            target_ref, DEFAULT_ROLE_JOB_LEASE_CEILING
        )


def normalise_setting_value(name: str, value: object) -> Any:
    """Validate a new value and return its canonical, JSON-safe form."""
    if name not in SETTING_NAMES:
        raise DeploySettingRefusedError(f"{name!r} is not a deploy setting")
    if name == SETTING_LEGACY_CEILING:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DeploySettingRefusedError("the ceiling is a non-negative integer")
        return value
    if name == SETTING_ROLE_JOB_LEASE_CEILING:
        if not isinstance(value, Mapping):
            raise DeploySettingRefusedError(f"{name} maps target references to seconds")
        out: dict[str, int] = {}
        for ref, seconds in value.items():
            if not isinstance(ref, str) or not _TARGET_REF.fullmatch(ref):
                raise DeploySettingRefusedError("a target reference is not well formed")
            if (
                isinstance(seconds, bool)
                or not isinstance(seconds, int)
                or not MIN_ROLE_JOB_LEASE_CEILING
                <= seconds
                <= MAX_ROLE_JOB_LEASE_CEILING
            ):
                raise DeploySettingRefusedError(
                    f"the role-job lease ceiling is {MIN_ROLE_JOB_LEASE_CEILING}.."
                    f"{MAX_ROLE_JOB_LEASE_CEILING} seconds"
                )
            out[ref] = seconds
        return dict(sorted(out.items()))
    if not isinstance(value, list | tuple | set | frozenset) or not all(
        isinstance(item, str) for item in value
    ):
        raise DeploySettingRefusedError(f"{name} is a list of strings")
    items = sorted(set(value))
    if name == SETTING_PULL_REPOSITORIES:
        PullAllowlist.of(items)  # refuses anything that is not a repository
        return items
    if not all(_TARGET_REF.fullmatch(item) for item in items):
        raise DeploySettingRefusedError("a target reference is not well formed")
    return items


def settings_from_rows(rows: Mapping[str, Any]) -> DeploySettings:
    """Build the effective settings from stored `{name: value}` rows."""
    return DeploySettings(
        pull_allowlist=PullAllowlist.of(rows.get(SETTING_PULL_REPOSITORIES, ())),
        legacy_allowed_targets=frozenset(rows.get(SETTING_LEGACY_TARGETS, ())),
        legacy_ceiling=int(rows.get(SETTING_LEGACY_CEILING, 0)),
        role_job_lease_ceilings=dict(rows.get(SETTING_ROLE_JOB_LEASE_CEILING, {})),
    )
