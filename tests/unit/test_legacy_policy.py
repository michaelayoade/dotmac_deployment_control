"""M11 `[legacy_env_file]` invariants L1-L5, L8 and `legacy_never` (design 2.8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dotmac_deployment_control.deploy_unit import DeployUnitError, parse_deploy_unit
from dotmac_deployment_control.legacy_policy import (
    AttendedApproval,
    LegacyFleetState,
    LegacyPolicyRefusedError,
    LegacyRetirementEvidence,
    bind_to_plan,
    enable_policy,
    extend_expiry,
    raise_ceiling,
    retire_policy,
    revise_policy,
)

_NOW = datetime(2026, 12, 1, 9, 0, tzinfo=UTC)
_CUTOVER = datetime(2026, 12, 1, 8, 0, tzinfo=UTC)
_SHA = "sha256:" + "a" * 64
_OTHER_SHA = "sha256:" + "b" * 64
_ATTENDED = AttendedApproval("operator", True, "register-line-1")
_UNATTENDED = AttendedApproval("operator", False, "register-line-1")
_NAMES = ("DB_PASSWORD", "API_SECRET", "SMTP_PASSWORD")


def _fleet(ceiling: int = 1) -> LegacyFleetState:
    fleet = LegacyFleetState()
    return raise_ceiling(fleet, ceiling, approval=_ATTENDED) if ceiling else fleet


def _enable(fleet: LegacyFleetState, **overrides: object) -> LegacyFleetState:
    args: dict[str, object] = {
        "target_ref": "erp/prod/host-a",
        "product": "erp_v2",
        "names": _NAMES,
        "sha256": _SHA,
        "secret_names": set(_NAMES),
        "param_materials": {"PUBLIC_HOST"},
        "binding_names": {"OTHER_BINDING"},
        "cutover_at": _CUTOVER,
        "now": _NOW,
        "enabled_by_ref": "operator",
        "exit_prestaged": True,
    }
    args.update(overrides)
    return enable_policy(fleet, **args)  # type: ignore[arg-type]


def test_legacy_policy_sha_fixed_at_enable() -> None:
    fleet = _enable(_fleet())
    policy = fleet.policies["erp/prod/host-a"]
    assert policy.sha256 == _SHA
    # The plan binds the policy's sha, with or without an observation.
    assert bind_to_plan(fleet, target_ref="erp/prod/host-a", now=_NOW).sha256 == _SHA
    assert (
        bind_to_plan(
            fleet, target_ref="erp/prod/host-a", now=_NOW, observed_sha256=_SHA
        ).sha256
        == _SHA
    )
    # An observed sha that differs is refused, never adopted.
    with pytest.raises(LegacyPolicyRefusedError, match="sha"):
        bind_to_plan(
            fleet, target_ref="erp/prod/host-a", now=_NOW, observed_sha256=_OTHER_SHA
        )
    # Changing the sha is a NEW visible version, attended; v1 is not edited.
    revised = revise_policy(
        fleet,
        target_ref="erp/prod/host-a",
        names=_NAMES,
        sha256=_OTHER_SHA,
        approval=_ATTENDED,
    )
    assert revised.policies["erp/prod/host-a"].version == 2
    assert fleet.policies["erp/prod/host-a"].version == 1
    with pytest.raises(LegacyPolicyRefusedError):
        revise_policy(
            fleet,
            target_ref="erp/prod/host-a",
            names=_NAMES,
            sha256=_OTHER_SHA,
            approval=_UNATTENDED,
        )
    with pytest.raises(LegacyPolicyRefusedError):
        _enable(_fleet(), sha256="not-a-sha")


def test_legacy_refuses_nonsecret_name() -> None:
    with pytest.raises(LegacyPolicyRefusedError, match="secret-class"):
        _enable(_fleet(), names=(*_NAMES, "LOG_LEVEL"))
    with pytest.raises(LegacyPolicyRefusedError):
        _enable(_fleet(), names=("lowercase",), secret_names={"lowercase"})


def test_legacy_refuses_collision() -> None:
    for taken in ("PUBLIC_HOST", "OTHER_BINDING", "APP_IMAGE"):
        names = (*_NAMES, taken)
        with pytest.raises(LegacyPolicyRefusedError, match="collide"):
            _enable(_fleet(), names=names, secret_names=set(names))


def test_legacy_names_only_shrink() -> None:
    fleet = _enable(_fleet())
    shrunk = revise_policy(
        fleet,
        target_ref="erp/prod/host-a",
        names=_NAMES[:2],
        sha256=_SHA,
        approval=_ATTENDED,
    )
    assert shrunk.policies["erp/prod/host-a"].names == tuple(sorted(_NAMES[:2]))
    with pytest.raises(LegacyPolicyRefusedError, match="only shrink"):
        revise_policy(
            shrunk,
            target_ref="erp/prod/host-a",
            names=_NAMES,
            sha256=_SHA,
            approval=_ATTENDED,
        )


def test_legacy_ratchet_ceiling() -> None:
    # Starts at 0: nothing can be enabled.
    with pytest.raises(LegacyPolicyRefusedError, match="ceiling"):
        _enable(LegacyFleetState())
    fleet = _enable(_fleet(1))
    with pytest.raises(LegacyPolicyRefusedError, match="ceiling"):
        _enable(fleet, target_ref="erp/prod/host-b")
    # A raise needs an attended approval with a register line.
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        raise_ceiling(fleet, 2, approval=_UNATTENDED)
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        raise_ceiling(fleet, 2, approval=AttendedApproval("operator", True, " "))
    with pytest.raises(LegacyPolicyRefusedError):
        raise_ceiling(fleet, 1, approval=_ATTENDED)
    raised = raise_ceiling(fleet, 2, approval=_ATTENDED)
    assert _enable(raised, target_ref="erp/prod/host-b").enabled_count() == 2
    # The exit must be pre-staged.
    with pytest.raises(LegacyPolicyRefusedError, match="pre-staged"):
        _enable(_fleet(), exit_prestaged=False)


def test_legacy_retire_decrements() -> None:
    fleet = _enable(_fleet(1))
    done = LegacyRetirementEvidence(True, True, True)
    retired = retire_policy(fleet, target_ref="erp/prod/host-a", evidence=done)
    assert retired.ceiling == 0
    assert retired.enabled_count() == 0
    assert retired.policies["erp/prod/host-a"].state == "retired"
    for partial in (
        LegacyRetirementEvidence(False, True, True),
        LegacyRetirementEvidence(True, False, True),
        LegacyRetirementEvidence(True, True, False),
    ):
        with pytest.raises(LegacyPolicyRefusedError):
            retire_policy(fleet, target_ref="erp/prod/host-a", evidence=partial)
    # A retired target never regains a legacy file, and cannot be retired twice.
    with pytest.raises(LegacyPolicyRefusedError):
        retire_policy(retired, target_ref="erp/prod/host-a", evidence=done)
    with pytest.raises(LegacyPolicyRefusedError):
        _enable(raise_ceiling(retired, 1, approval=_ATTENDED))
    with pytest.raises(LegacyPolicyRefusedError):
        bind_to_plan(retired, target_ref="erp/prod/host-a", now=_NOW)


def test_legacy_expired_refused() -> None:
    fleet = _enable(_fleet())
    expires = fleet.policies["erp/prod/host-a"].expires_at
    assert expires == _CUTOVER + timedelta(days=30)
    bind_to_plan(
        fleet, target_ref="erp/prod/host-a", now=expires - timedelta(seconds=1)
    )
    with pytest.raises(LegacyPolicyRefusedError, match="expired"):
        bind_to_plan(fleet, target_ref="erp/prod/host-a", now=expires)
    # An already-expired policy cannot be enabled at all.
    with pytest.raises(LegacyPolicyRefusedError, match="expired"):
        _enable(_fleet(), cutover_at=_NOW - timedelta(days=31))


def test_legacy_extend_requires_attended() -> None:
    fleet = _enable(_fleet())
    later = fleet.policies["erp/prod/host-a"].expires_at + timedelta(days=7)
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        extend_expiry(
            fleet,
            target_ref="erp/prod/host-a",
            new_expires_at=later,
            approval=_UNATTENDED,
        )
    with pytest.raises(LegacyPolicyRefusedError, match="later"):
        extend_expiry(
            fleet,
            target_ref="erp/prod/host-a",
            new_expires_at=fleet.policies["erp/prod/host-a"].expires_at,
            approval=_ATTENDED,
        )
    extended = extend_expiry(
        fleet, target_ref="erp/prod/host-a", new_expires_at=later, approval=_ATTENDED
    )
    assert extended.policies["erp/prod/host-a"].expires_at == later


_LEGACY_TOML = """
schema = "dotmac.deploy_unit/1"
product = "{product}"
spec = "deploy/product.toml"

[params.legacy_path]
type = "path"

[legacy_env_file]
names = ["DB_PASSWORD"]
path_param = "legacy_path"
"""


def test_legacy_never_products() -> None:
    # An existing app may declare the table.
    unit = parse_deploy_unit(_LEGACY_TOML.format(product="erp_v2"))
    assert unit.legacy_env_file is not None
    assert unit.legacy_env_file.names == ("DB_PASSWORD",)
    # sub_thin (the default legacy_never set) is refused at parse.
    with pytest.raises(DeployUnitError, match="legacy_never"):
        parse_deploy_unit(_LEGACY_TOML.format(product="sub_thin"))
    # Every companion descriptor is refused, whatever its product.
    with pytest.raises(DeployUnitError, match="legacy_never"):
        parse_deploy_unit(_LEGACY_TOML.format(product="integrator"), companion=True)
    # The set is a Control setting: a caller-supplied set is honoured.
    with pytest.raises(DeployUnitError, match="legacy_never"):
        parse_deploy_unit(
            _LEGACY_TOML.format(product="erp_v2"), legacy_never=frozenset({"erp_v2"})
        )
    # And the policy refuses the same products independently of the descriptor.
    with pytest.raises(LegacyPolicyRefusedError, match="legacy_never"):
        _enable(_fleet(), product="sub_thin")
    with pytest.raises(LegacyPolicyRefusedError, match="legacy_never"):
        _enable(_fleet(), companion=True)
    # Names colliding with a param material are refused at parse as well.
    colliding = _LEGACY_TOML.format(product="erp_v2").replace(
        'type = "path"', 'type = "path"\nmaterial = "DB_PASSWORD"', 1
    )
    with pytest.raises(DeployUnitError, match="collide"):
        parse_deploy_unit(colliding)
