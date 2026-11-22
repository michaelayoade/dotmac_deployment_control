"""The Control settings of the deploy-unit contract, as values.

Three named settings, each a visible and ATTENDED change (an approval that says
it was attended and names a register line):

* `public_pull_repositories`: repositories whose images may be pulled instead of
  transferred. EMPTY by default.
* `legacy_env_file_allowed_products`: the products that may declare
  `[legacy_env_file]`. DEFAULT-DENY: the default holds ERP v2's product code
  only; a companion descriptor is refused whatever this says.
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

from dotmac_deployment_control.deploy_unit import (
    LEGACY_ENV_FILE_ALLOWED_DEFAULT,
    DeployUnitError,
)
from dotmac_deployment_control.image_policy import PullAllowlist

SETTING_PULL_REPOSITORIES: Final = "public_pull_repositories"
SETTING_LEGACY_PRODUCTS: Final = "legacy_env_file_allowed_products"
SETTING_LEGACY_CEILING: Final = "legacy_env_file_ceiling"
SETTING_NAMES: Final = frozenset(
    {SETTING_PULL_REPOSITORIES, SETTING_LEGACY_PRODUCTS, SETTING_LEGACY_CEILING}
)

_PRODUCT = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")


class DeploySettingRefusedError(DeployUnitError):
    """A setting name or value was refused."""


@dataclass(frozen=True, slots=True)
class DeploySettings:
    pull_allowlist: PullAllowlist = field(default_factory=PullAllowlist)
    legacy_allowed_products: frozenset[str] = LEGACY_ENV_FILE_ALLOWED_DEFAULT
    legacy_ceiling: int = 0


def normalise_setting_value(name: str, value: object) -> Any:
    """Validate a new value and return its canonical, JSON-safe form."""
    if name not in SETTING_NAMES:
        raise DeploySettingRefusedError(f"{name!r} is not a deploy setting")
    if name == SETTING_LEGACY_CEILING:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DeploySettingRefusedError("the ceiling is a non-negative integer")
        return value
    if not isinstance(value, list | tuple | set | frozenset) or not all(
        isinstance(item, str) for item in value
    ):
        raise DeploySettingRefusedError(f"{name} is a list of strings")
    items = sorted(set(value))
    if name == SETTING_PULL_REPOSITORIES:
        PullAllowlist.of(items)  # refuses anything that is not a repository
        return items
    if not all(_PRODUCT.fullmatch(item) for item in items):
        raise DeploySettingRefusedError("a product code is not well formed")
    return items


def settings_from_rows(rows: Mapping[str, Any]) -> DeploySettings:
    """Build the effective settings from stored `{name: value}` rows."""
    return DeploySettings(
        pull_allowlist=PullAllowlist.of(rows.get(SETTING_PULL_REPOSITORIES, ())),
        legacy_allowed_products=(
            frozenset(rows[SETTING_LEGACY_PRODUCTS])
            if SETTING_LEGACY_PRODUCTS in rows
            else LEGACY_ENV_FILE_ALLOWED_DEFAULT
        ),
        legacy_ceiling=int(rows.get(SETTING_LEGACY_CEILING, 0)),
    )
