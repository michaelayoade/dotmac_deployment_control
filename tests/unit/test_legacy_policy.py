"""M11 `[legacy_env_file]` invariants L1-L5, L8 and default-deny products (2.8)."""

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
    check_policy_against_descriptor,
    enable_policy,
    extend_expiry,
    raise_ceiling,
    refuse_activation_of_legacy_names,
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
        "product": "dotmac-erp-v2",
        "names": _NAMES,
        "sha256": _SHA,
        "secret_names": set(_NAMES),
        "param_materials": {"PUBLIC_HOST"},
        "binding_names": {"OTHER_BINDING"},
        "cutover_at": _CUTOVER,
        "now": _NOW,
        "enabled_by_ref": "operator",
        "exit_prestaged": True,
        "allowed_targets": frozenset({"erp/prod/host-a", "erp/prod/host-b"}),
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


_ERP = "dotmac-erp-v2"
_COMPANION_PATH = "deploy/companion/deploy-unit.toml"


def test_legacy_refused_unless_allowlisted() -> None:
    """DEFAULT-DENY, keyed by TARGET: not on the list means refused."""
    # The descriptor parse refuses the table unless the target is allowed.
    with pytest.raises(DeployUnitError, match="default-deny"):
        parse_deploy_unit(_LEGACY_TOML.format(product=_ERP))
    unit = parse_deploy_unit(_LEGACY_TOML.format(product=_ERP), legacy_allowed=True)
    assert unit.legacy_env_file is not None
    assert unit.legacy_env_file.names == ("DB_PASSWORD",)
    # The policy refuses a target that is not allowed, whatever its product.
    with pytest.raises(LegacyPolicyRefusedError, match="allowed_targets"):
        _enable(_fleet(), allowed_targets=frozenset())
    with pytest.raises(LegacyPolicyRefusedError, match="allowed_targets"):
        _enable(_fleet(), allowed_targets=frozenset({"erp/prod/other-host"}))
    # Allowing ONE target of a product does not admit another target of it.
    allowed = frozenset({"erp/prod/host-a"})
    assert _enable(_fleet(), allowed_targets=allowed)
    with pytest.raises(LegacyPolicyRefusedError, match="allowed_targets"):
        _enable(_fleet(), target_ref="erp/prod/host-b", allowed_targets=allowed)
    # Names colliding with a param material are refused at parse as well.
    colliding = _LEGACY_TOML.format(product=_ERP).replace(
        'type = "path"', 'type = "path"\nmaterial = "DB_PASSWORD"', 1
    )
    with pytest.raises(DeployUnitError, match="collide"):
        parse_deploy_unit(colliding, legacy_allowed=True)


def test_legacy_never_products() -> None:
    """sub_thin (`dotmac-sub`) and companions are refused BY DEFAULT."""
    with pytest.raises(DeployUnitError, match="default-deny"):
        parse_deploy_unit(_LEGACY_TOML.format(product="dotmac-sub"))
    with pytest.raises(LegacyPolicyRefusedError, match="allowed_targets"):
        _enable(
            _fleet(),
            target_ref="sub/prod/host-a",
            product="dotmac-sub",
            allowed_targets=frozenset(),
        )
    # A companion descriptor is ALWAYS refused, even for an allowed target.
    for path in (_COMPANION_PATH, "deploy/companion/sub/deploy-unit.toml"):
        with pytest.raises(DeployUnitError, match="companion"):
            parse_deploy_unit(
                _LEGACY_TOML.format(product=_ERP),
                descriptor_path=path,
                legacy_allowed=True,
            )
    with pytest.raises(LegacyPolicyRefusedError, match="companion"):
        _enable(_fleet(), companion=True)
    # Only the exact prefix counts, and an escaping path is itself refused.
    parse_deploy_unit(
        _LEGACY_TOML.format(product=_ERP),
        descriptor_path="deploy/deploy-unit.toml",
        legacy_allowed=True,
    )
    with pytest.raises(DeployUnitError, match="repository-relative"):
        parse_deploy_unit(
            _LEGACY_TOML.format(product=_ERP),
            descriptor_path="../deploy/x.toml",
            legacy_allowed=True,
        )


def test_policy_is_checked_against_the_descriptor_not_caller_lists() -> None:
    """M1: names must be declared by the descriptor and not collide with it."""
    ok = {"descriptor_legacy_names": ("A", "B"), "param_materials": ["P"]}
    check_policy_against_descriptor(("A",), active_binding_names=["X"], **ok)
    with pytest.raises(LegacyPolicyRefusedError, match="not declared"):
        check_policy_against_descriptor(("C",), active_binding_names=[], **ok)
    with pytest.raises(LegacyPolicyRefusedError, match="collide"):
        check_policy_against_descriptor(
            ("A",),
            descriptor_legacy_names=("A",),
            param_materials=["A"],
            active_binding_names=[],
        )
    with pytest.raises(LegacyPolicyRefusedError, match="collide"):
        check_policy_against_descriptor(("A",), active_binding_names=["A"], **ok)
    with pytest.raises(LegacyPolicyRefusedError, match=r"no \[legacy_env_file\]"):
        check_policy_against_descriptor(
            ("A",),
            descriptor_legacy_names=None,
            param_materials=[],
            active_binding_names=[],
        )


def test_legacy_l2_collision_is_with_active_bindings_only() -> None:
    """A pre-staged binding may reuse a legacy name; an active one may not."""
    # `binding_names` carries the ACTIVE bindings only: a pre-staged name is not
    # passed, so enabling succeeds even though a pre-staged binding shares it.
    assert _enable(_fleet(), binding_names={"MIGRATION_DATABASE_URL"})
    # An ACTIVE binding with a legacy name collides.
    with pytest.raises(LegacyPolicyRefusedError, match="collide"):
        _enable(_fleet(), binding_names={"DB_PASSWORD"})


def test_activating_a_binding_still_in_the_legacy_names_is_refused() -> None:
    fleet = _enable(_fleet())
    policy = fleet.policies["erp/prod/host-a"]
    # Still legacy: activation refused until the name is retired.
    with pytest.raises(LegacyPolicyRefusedError, match="retire the name"):
        refuse_activation_of_legacy_names({"DB_PASSWORD"}, policy.names)
    # An unrelated active binding is fine.
    refuse_activation_of_legacy_names({"OTHER"}, policy.names)
    # Retire the name (a shrinking revision), then activation passes.
    shrunk = revise_policy(
        fleet,
        target_ref="erp/prod/host-a",
        names=("API_SECRET", "SMTP_PASSWORD"),
        sha256=_SHA,
        approval=_ATTENDED,
    ).policies["erp/prod/host-a"]
    refuse_activation_of_legacy_names({"DB_PASSWORD"}, shrunk.names)
    with pytest.raises(LegacyPolicyRefusedError):
        refuse_activation_of_legacy_names({"API_SECRET"}, shrunk.names)
    # Full retirement frees every name and decrements the ceiling (L4).
    retired = retire_policy(
        fleet,
        target_ref="erp/prod/host-a",
        evidence=LegacyRetirementEvidence(True, True, True),
    )
    assert retired.ceiling == fleet.ceiling - 1
    refuse_activation_of_legacy_names(
        set(_NAMES), retired.policies["erp/prod/host-a"].names
    )
