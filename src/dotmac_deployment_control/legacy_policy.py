"""M11 bridge: the invariants Control enforces on EVERY `[legacy_env_file]` policy.

Scope is fleet-wide and existing apps only (each target enabled as its own act).
New builds never use it: the bridge is DEFAULT-DENY (only targets on
`legacy_env_file_allowed_targets`) and every companion descriptor
are refused. This module implements the Control column of the design's
invariants:

* **L1** the whole-file sha256 is fixed by the operator at enable and bound by
  every plan; any other sha is refused and a sha is never taken from an
  observation. Changing it means a NEW, visible policy version.
* **L2** secret names only: a name must be declared secret-class, and may not
  collide with a param material, a binding name or `APP_IMAGE`.
* **L3** names only shrink across versions.
* **L4** enabled-target ratchet: enabled count <= `ceiling`, starting at 0. A
  raise needs an attended approval plus a register line; each retirement
  decrements the ceiling.
* **L5** one expiry per target (cutover + 30 days), extended only by an attended
  approval plus a register line; an expired policy refuses plans. The exit is
  pre-staged before enable.
* **L8** full retirement: names removed, policy off, file encrypted then
  shredded, drop-in removed, ratchet decremented.

L6/L7 (relocation and read path) are agent and operation concerns, not Control's.

Pure functions over immutable values: no I/O, no database, no clock (callers
pass `now`). Every transition returns a new fleet state or raises
:class:`LegacyPolicyRefusedError`.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Final

from dotmac_deployment_control.deploy_unit import (
    APP_IMAGE_MATERIAL,
    DeployUnitError,
)
from dotmac_deployment_control.digests import is_canonical_digest

EXPIRY_AFTER_CUTOVER: Final = timedelta(days=30)
_MATERIAL = re.compile(r"[A-Z][A-Z0-9_]{0,127}")

ENABLED: Final = "enabled"
RETIRED: Final = "retired"


class LegacyPolicyRefusedError(DeployUnitError):
    """A legacy-policy transition or plan binding was refused."""


@dataclass(frozen=True, slots=True)
class AttendedApproval:
    """The operator's attended approval, with the register line that records it.

    Control does not authenticate the operator here; it refuses a transition
    unless the approval states it was attended and names a register line.
    """

    approver_ref: str
    attended: bool
    register_ref: str

    def require(self, what: str) -> None:
        if not (
            self.attended and self.approver_ref.strip() and self.register_ref.strip()
        ):
            raise LegacyPolicyRefusedError(
                f"{what} needs an attended approval and a register line"
            )


@dataclass(frozen=True, slots=True)
class LegacyRetirementEvidence:
    """L8: what the retirement operation attests it did."""

    names_removed: bool
    file_encrypted_and_shredded: bool
    dropin_removed: bool

    def complete(self) -> bool:
        return (
            self.names_removed
            and self.file_encrypted_and_shredded
            and self.dropin_removed
        )


@dataclass(frozen=True, slots=True)
class LegacyEnvPolicy:
    target_ref: str
    product: str
    version: int
    names: tuple[str, ...]
    sha256: str
    expires_at: datetime
    enabled_by_ref: str
    state: str = ENABLED


@dataclass(frozen=True, slots=True)
class LegacyFleetState:
    """All per-target policies plus the fleet ceiling (starts at 0)."""

    ceiling: int = 0
    policies: Mapping[str, LegacyEnvPolicy] = field(default_factory=dict)

    def enabled_count(self) -> int:
        return sum(1 for p in self.policies.values() if p.state == ENABLED)


@dataclass(frozen=True, slots=True)
class LegacyPlanBinding:
    """What a plan binds. The sha is the policy's, never an observation's."""

    policy_version: int
    sha256: str
    names: tuple[str, ...]

    def payload(self) -> dict[str, object]:
        return {
            "policy_version": self.policy_version,
            "sha256": self.sha256,
            "names": list(self.names),
        }


def _check_names(
    names: Collection[str],
    *,
    secret_names: Collection[str],
    param_materials: Collection[str],
    binding_names: Collection[str],
) -> tuple[str, ...]:
    ordered = tuple(sorted(names))
    if not ordered or len(set(ordered)) != len(ordered):
        raise LegacyPolicyRefusedError("legacy names must be non-empty and unique")
    for name in ordered:
        if not _MATERIAL.fullmatch(name):
            raise LegacyPolicyRefusedError(f"{name!r} is not a material name")
    nonsecret = sorted(set(ordered) - set(secret_names))
    if nonsecret:
        raise LegacyPolicyRefusedError(
            "legacy names must be declared secret-class; non-secret values "
            f"become typed params: {', '.join(nonsecret)}"
        )
    # `binding_names` are the ACTIVE bindings' names; pre-staged ones may reuse
    # a legacy name (see `refuse_activation_of_legacy_names`).
    taken = set(param_materials) | set(binding_names) | {APP_IMAGE_MATERIAL}
    collisions = sorted(set(ordered) & taken)
    if collisions:
        raise LegacyPolicyRefusedError(
            "legacy names collide with a param material, a binding or "
            f"{APP_IMAGE_MATERIAL}: {', '.join(collisions)}"
        )
    return ordered


def refuse_activation_of_legacy_names(
    active_binding_names: Collection[str], legacy_names: Collection[str]
) -> None:
    """L2, activation half: a binding may not go ACTIVE while its name is legacy.

    A pre-staged binding may reuse a legacy name; making it a real delivery
    source while the legacy file still supplies that name would be two sources
    for one name. The name must first be retired from the policy (a revision
    that shrinks the names, or the full retirement).
    """
    clash = sorted(set(active_binding_names) & set(legacy_names))
    if clash:
        raise LegacyPolicyRefusedError(
            "an active binding names a legacy env-file name still in the policy; "
            f"retire the name from the policy first: {', '.join(clash)}"
        )


def check_policy_against_descriptor(
    policy_names: Collection[str],
    *,
    descriptor_legacy_names: Collection[str] | None,
    param_materials: Collection[str],
    active_binding_names: Collection[str],
) -> None:
    """L2 against the VERIFIED descriptor, never against caller-supplied lists.

    The policy's names must be declared by the descriptor's `[legacy_env_file]`
    (a subset: names only shrink) and must not also be supplied by a typed
    param, an active binding or `APP_IMAGE`. Otherwise params.env and the
    legacy file would both supply one name, and env-file order would decide.
    """
    if descriptor_legacy_names is None:
        raise LegacyPolicyRefusedError(
            "the descriptor declares no [legacy_env_file] for this policy"
        )
    stray = sorted(set(policy_names) - set(descriptor_legacy_names))
    if stray:
        raise LegacyPolicyRefusedError(
            f"policy names are not declared by the descriptor: {', '.join(stray)}"
        )
    taken = set(param_materials) | set(active_binding_names) | {APP_IMAGE_MATERIAL}
    clash = sorted(set(policy_names) & taken)
    if clash:
        raise LegacyPolicyRefusedError(
            "policy names collide with a param material, an active binding or "
            f"{APP_IMAGE_MATERIAL}: {', '.join(clash)}"
        )


def _check_sha(sha256: str) -> None:
    if not is_canonical_digest(sha256):
        raise LegacyPolicyRefusedError("the legacy file sha must be sha256:<64 hex>")


def _with(fleet: LegacyFleetState, policy: LegacyEnvPolicy) -> LegacyFleetState:
    return replace(fleet, policies={**fleet.policies, policy.target_ref: policy})


def raise_ceiling(
    fleet: LegacyFleetState, new_ceiling: int, *, approval: AttendedApproval
) -> LegacyFleetState:
    """L4: a raise needs an attended approval plus a register line."""
    if isinstance(new_ceiling, bool) or new_ceiling <= fleet.ceiling:
        raise LegacyPolicyRefusedError("a ceiling raise must increase the ceiling")
    approval.require("raising the legacy_env_file ceiling")
    return replace(fleet, ceiling=new_ceiling)


def enable_policy(
    fleet: LegacyFleetState,
    *,
    target_ref: str,
    product: str,
    names: Collection[str],
    sha256: str,
    secret_names: Collection[str],
    param_materials: Collection[str],
    binding_names: Collection[str],
    cutover_at: datetime,
    now: datetime,
    enabled_by_ref: str,
    exit_prestaged: bool,
    companion: bool = False,
    allowed_targets: frozenset[str] = frozenset(),
) -> LegacyFleetState:
    """Enable the bridge for one existing target (its own policy act)."""
    if companion:
        raise LegacyPolicyRefusedError(
            "a companion descriptor can never use the legacy env-file bridge"
        )
    if target_ref not in allowed_targets:
        raise LegacyPolicyRefusedError(
            f"target {target_ref!r} is not on legacy_env_file_allowed_targets"
        )
    existing = fleet.policies.get(target_ref)
    if existing is not None and existing.state == ENABLED:
        raise LegacyPolicyRefusedError("the target already has an enabled policy")
    if existing is not None:
        # A retired target never regains a legacy file ("no new legacy files").
        raise LegacyPolicyRefusedError("a retired target cannot re-enable the bridge")
    if not enabled_by_ref.strip():
        raise LegacyPolicyRefusedError("the policy must record who enabled it")
    if not exit_prestaged:
        raise LegacyPolicyRefusedError(
            "the exit (bindings, namespace, delivery paths) must be pre-staged "
            "before the bridge is enabled"
        )
    _check_sha(sha256)
    checked = _check_names(
        names,
        secret_names=secret_names,
        param_materials=param_materials,
        binding_names=binding_names,
    )
    expires_at = cutover_at + EXPIRY_AFTER_CUTOVER
    if expires_at <= now:
        raise LegacyPolicyRefusedError("the policy would already be expired")
    if fleet.enabled_count() + 1 > fleet.ceiling:
        raise LegacyPolicyRefusedError(
            f"enabling would exceed the legacy_env_file ceiling ({fleet.ceiling})"
        )
    policy = LegacyEnvPolicy(
        target_ref=target_ref,
        product=product,
        version=1,
        names=checked,
        sha256=sha256,
        expires_at=expires_at,
        enabled_by_ref=enabled_by_ref,
    )
    return _with(fleet, policy)


def _enabled(fleet: LegacyFleetState, target_ref: str) -> LegacyEnvPolicy:
    policy = fleet.policies.get(target_ref)
    if policy is None or policy.state != ENABLED:
        raise LegacyPolicyRefusedError("the target has no enabled legacy policy")
    return policy


def revise_policy(
    fleet: LegacyFleetState,
    *,
    target_ref: str,
    names: Collection[str],
    sha256: str,
    approval: AttendedApproval,
) -> LegacyFleetState:
    """L1 + L3: a new visible version. Names may only shrink.

    A different sha is allowed ONLY here, as a new policy version the operator
    attends; it is never adopted from an observation.
    """
    current = _enabled(fleet, target_ref)
    approval.require("revising a legacy policy")
    _check_sha(sha256)
    ordered = tuple(sorted(set(names)))
    if not ordered:
        raise LegacyPolicyRefusedError(
            "a revision with no names is a retirement; retire the policy instead"
        )
    added = sorted(set(ordered) - set(current.names))
    if added:
        raise LegacyPolicyRefusedError(
            f"legacy names only shrink; revision adds: {', '.join(added)}"
        )
    return _with(
        fleet,
        replace(current, version=current.version + 1, names=ordered, sha256=sha256),
    )


def extend_expiry(
    fleet: LegacyFleetState,
    *,
    target_ref: str,
    new_expires_at: datetime,
    approval: AttendedApproval,
) -> LegacyFleetState:
    """L5: only an attended approval with a register line extends the expiry."""
    current = _enabled(fleet, target_ref)
    approval.require("extending a legacy policy expiry")
    if new_expires_at <= current.expires_at:
        raise LegacyPolicyRefusedError("an extension must move the expiry later")
    return _with(
        fleet,
        replace(current, expires_at=new_expires_at, version=current.version + 1),
    )


def retire_policy(
    fleet: LegacyFleetState,
    *,
    target_ref: str,
    evidence: LegacyRetirementEvidence,
) -> LegacyFleetState:
    """L8: full retirement. Policy off, names removed, ceiling decremented."""
    current = _enabled(fleet, target_ref)
    if not evidence.complete():
        raise LegacyPolicyRefusedError(
            "retirement needs names removed, the file encrypted and shredded "
            "and the drop-in removed"
        )
    retired = replace(current, state=RETIRED, names=(), version=current.version + 1)
    return replace(_with(fleet, retired), ceiling=max(0, fleet.ceiling - 1))


def bind_to_plan(
    fleet: LegacyFleetState,
    *,
    target_ref: str,
    now: datetime,
    observed_sha256: str | None = None,
) -> LegacyPlanBinding:
    """What a plan binds for this target: the policy's own version, sha, names.

    * an expired policy refuses (L5);
    * an observed sha that differs from the policy's refuses (L1); the sha is
      NEVER taken from the observation, so passing none binds the same value;
    * the ratchet is re-checked at plan time (L4).
    """
    policy = _enabled(fleet, target_ref)
    if now >= policy.expires_at:
        raise LegacyPolicyRefusedError("the legacy policy is expired; plans refused")
    if fleet.enabled_count() > fleet.ceiling:
        raise LegacyPolicyRefusedError("the enabled-target count exceeds the ceiling")
    if observed_sha256 is not None and observed_sha256 != policy.sha256:
        raise LegacyPolicyRefusedError(
            "the legacy file sha differs from the sha fixed in the policy"
        )
    return LegacyPlanBinding(
        policy_version=policy.version, sha256=policy.sha256, names=policy.names
    )
