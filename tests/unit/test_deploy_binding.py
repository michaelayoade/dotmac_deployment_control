"""Plan binding, lease TTL, deployment set and the reconcile-marker rule."""

from __future__ import annotations

from uuid import uuid4

import pytest

from dotmac_deployment_control import plan_digest_of, plan_snapshot
from dotmac_deployment_control.deploy_binding import (
    DeployBindingRefusedError,
    DeploymentSet,
    PlannedImage,
    PlanRole,
    build_deploy_binding,
)
from dotmac_deployment_control.image_policy import PullAllowlist
from dotmac_deployment_control.legacy_policy import LegacyPlanBinding
from dotmac_deployment_control.models import DeploymentTarget
from dotmac_deployment_control.reconcile import (
    EXPIRED_UNRELEASED,
    ReconcileObservation,
    ReconcileRefusedError,
    decide_reconcile_marker,
)

_REPO = "registry.example.test/team/app"
_D1 = "sha256:" + "1" * 64
_D2 = "sha256:" + "2" * 64
_P1 = "sha256:" + "3" * 64
_P2 = "sha256:" + "4" * 64
_U1 = "sha256:" + "5" * 64
_U2 = "sha256:" + "6" * 64
_T1 = "sha256:" + "8" * 64
_T2 = "sha256:" + "9" * 64
_EXP = "2027-01-01T00:00:00Z"


def _image(**overrides: str) -> PlannedImage:
    args = {
        "service": "app",
        "source": "transfer",
        "release_repository": _REPO,
        "release_digest": _D1,
        "planned_repository": "127.0.0.1:5000/team/app",
        "planned_digest": _D1,
    }
    args.update(overrides)
    return PlannedImage(**args)


def _binding(**overrides: object):
    args: dict[str, object] = {
        "deploy_unit_digest": _U1,
        "product_toml_sha256": _T1,
        "params_env_digest": _P1,
        "images": [_image()],
        "lease_ttl_seconds": 900,
        "allowlist": PullAllowlist(),
        "primary_service": "app",
        "roles": [PlanRole("migrate", True), PlanRole("app", False)],
        "secrets_namespace": "erp",
        "secrets_environment": "prod",
    }
    args.update(overrides)
    return build_deploy_binding(**args)  # type: ignore[arg-type]


def _target() -> DeploymentTarget:
    return DeploymentTarget(
        id=uuid4(),
        target_ref="erp/staging/host-a",
        subject_ref="subject-1",
        product_code="erp_v2",
        environment="staging",
        desired_revision=1,
        desired_release_ref="erp_v2@1.0.0",
    )


def _digest(binding: object) -> str:
    snap = plan_snapshot(
        _fixed_target(),
        purpose="foundation_execution",
        deploy_binding=binding,  # type: ignore[arg-type]
    )
    return plan_digest_of(snap).canonical


_TARGET = _target()


def _fixed_target() -> DeploymentTarget:
    return _TARGET


def test_plan_without_binding_is_byte_identical_to_before() -> None:
    snap = plan_snapshot(_TARGET, purpose="foundation_execution")
    assert "deploy_binding" not in snap
    assert plan_digest_of(snap) == plan_digest_of(
        plan_snapshot(_TARGET, purpose="foundation_execution", deploy_binding=None)
    )


def test_snapshot_digest_is_sensitive_to_a_binding_params_digest() -> None:
    base = _digest(_binding())
    assert base != _digest(None)
    assert _digest(_binding()) == base
    assert _digest(_binding(params_env_digest=_P2)) != base


def test_every_bound_field_moves_the_plan_digest() -> None:
    base = _digest(_binding())
    variants = [
        _binding(deploy_unit_digest=_U2),
        _binding(product_toml_sha256=_T2),
        _binding(lease_ttl_seconds=600),
        _binding(lease_max_seconds=1800),
        _binding(images=[_image(release_digest=_D2, planned_digest=_D2)]),
        _binding(images=[_image(planned_repository="127.0.0.1:5001/team/app")]),
        _binding(companion_order="after_primary_ready"),
        _binding(legacy=LegacyPlanBinding(1, _P1, ("DB_PASSWORD",), _EXP)),
        _binding(
            allowlist=PullAllowlist.of([_REPO]),
            images=[_image(source="pull", planned_repository=_REPO)],
        ),
    ]
    digests = {_digest(v) for v in variants}
    assert base not in digests
    assert len(digests) == len(variants)
    # Legacy policy version, sha and names each move it.
    legacy = [
        LegacyPlanBinding(1, _P1, ("DB_PASSWORD",), _EXP),
        LegacyPlanBinding(2, _P1, ("DB_PASSWORD",), _EXP),
        LegacyPlanBinding(1, _P2, ("DB_PASSWORD",), _EXP),
        LegacyPlanBinding(1, _P1, ("DB_PASSWORD", "API_SECRET"), _EXP),
        LegacyPlanBinding(1, _P1, ("DB_PASSWORD",), "2028-01-01T00:00:00Z"),
    ]
    assert len({_digest(_binding(legacy=item)) for item in legacy}) == len(legacy)


def test_binding_builder_splits_the_lease_into_ttl_and_maximum() -> None:
    # The TTL is per grant (120..900); the maximum is the total (to 10800).
    assert _binding(lease_ttl_seconds=120).lease_ttl_seconds == 120
    assert _binding(lease_ttl_seconds=900).lease_ttl_seconds == 900
    assert _binding().lease_max_seconds == 900  # default: one grant
    for bad in (0, -1, 119, 901, 3600, True, "900"):
        with pytest.raises(DeployBindingRefusedError, match="TTL"):
            _binding(lease_ttl_seconds=bad)
    assert _binding(lease_max_seconds=10800).lease_max_seconds == 10800
    for bad in (899, 10801, True):
        with pytest.raises(DeployBindingRefusedError, match="maximum|integer"):
            _binding(lease_max_seconds=bad)
    assert _binding(lease_max_seconds=3120).payload()["lease_max_seconds"] == 3120


def test_binding_refuses_bad_images_and_digests() -> None:
    with pytest.raises(DeployBindingRefusedError):
        _binding(params_env_digest="nope")
    with pytest.raises(DeployBindingRefusedError):
        _binding(deploy_unit_digest="nope")
    with pytest.raises(DeployBindingRefusedError):
        _binding(product_toml_sha256="nope")
    with pytest.raises(DeployBindingRefusedError):
        _binding(images=[])
    with pytest.raises(DeployBindingRefusedError):
        _binding(images=[_image(), _image()])
    with pytest.raises(DeployBindingRefusedError):
        _binding(companion_order="before_primary")
    # image policy refusals surface through the binding.
    with pytest.raises(Exception, match="loopback"):
        _binding(images=[_image(planned_repository="198.51.100.7:5000/team/app")])
    with pytest.raises(Exception, match="public_pull_repositories"):
        _binding(images=[_image(source="pull", planned_repository=_REPO)])


def test_deployment_set_digest_and_companion_gate() -> None:
    single = DeploymentSet(_P1)
    paired = DeploymentSet(_P1, _P2)
    assert single.set_digest() != paired.set_digest()
    assert paired.set_digest() == DeploymentSet(_P1, _P2).set_digest()
    assert not paired.may_release_companion("degraded")
    assert not paired.may_release_companion("unknown")
    assert paired.may_release_companion("healthy")
    assert not single.may_release_companion("healthy")
    with pytest.raises(DeployBindingRefusedError):
        DeploymentSet(_P1, None, required_at_switch=True)
    with pytest.raises(DeployBindingRefusedError):
        DeploymentSet("bad")
    with pytest.raises(DeployBindingRefusedError):
        DeploymentSet(_P1, _P2, order="parallel")


def _obs(release: str, *, verified: bool = True, read_only: bool = True):
    return ReconcileObservation(release, verified, read_only)


def test_reconcile_marker_requires_match() -> None:
    kwargs = {
        "standing": EXPIRED_UNRELEASED,
        "last_committed_release_ref": "app@1",
        "planned_release_ref": "app@2",
    }
    # Matches the last committed OR the planned release: marker issued.
    assert decide_reconcile_marker(observation=_obs("app@1"), **kwargs).issue_marker
    assert decide_reconcile_marker(observation=_obs("app@2"), **kwargs).issue_marker
    # Matches neither: restore and fix forward, NO marker.
    other = decide_reconcile_marker(observation=_obs("app@9"), **kwargs)
    assert not other.issue_marker
    assert other.outcome == "restore_and_fix_forward"
    # No last committed release: only the planned one matches.
    first = {**kwargs, "last_committed_release_ref": None}
    assert not decide_reconcile_marker(observation=_obs("app@1"), **first).issue_marker
    assert decide_reconcile_marker(observation=_obs("app@2"), **first).issue_marker
    # Unverified, mutating or empty observations decide nothing.
    for bad in (
        _obs("app@1", verified=False),
        _obs("app@1", read_only=False),
        _obs(" "),
    ):
        with pytest.raises(ReconcileRefusedError):
            decide_reconcile_marker(observation=bad, **kwargs)
    # Only an expired-unreleased lease needs (or can get) a marker.
    with pytest.raises(ReconcileRefusedError):
        decide_reconcile_marker(
            observation=_obs("app@1"), **{**kwargs, "standing": "RELEASED"}
        )


def test_roles_and_the_primary_service_are_bound_sorted_into_the_plan() -> None:
    binding = _binding()
    payload = binding.payload()
    assert payload["roles"] == [
        {"role": "app", "single_use": False},
        {"role": "migrate", "single_use": True},
    ]
    assert payload["primary_service"] == "app"
    base = _digest(binding)
    assert (
        _digest(_binding(roles=[PlanRole("app", True), PlanRole("migrate", True)]))
        != base
    )
    assert _digest(_binding(roles=[PlanRole("app", False)])) != base
    # Order of the input does not matter; the payload is sorted.
    assert (
        _digest(_binding(roles=[PlanRole("app", False), PlanRole("migrate", True)]))
        == base
    )
    with pytest.raises(DeployBindingRefusedError, match="primary service"):
        _binding(primary_service="other")
    with pytest.raises(DeployBindingRefusedError, match="primary service"):
        _binding(primary_service="")
    with pytest.raises(DeployBindingRefusedError, match="role appears once"):
        _binding(roles=[PlanRole("app", False), PlanRole("app", True)])


def test_the_openbao_naming_is_carried_in_the_signed_binding() -> None:
    """The agent reads these two keys from the plan, never from CP."""
    payload = _binding().payload()
    assert payload["secrets_namespace"] == "erp"
    assert payload["secrets_environment"] == "prod"
    base = _digest(_binding())
    assert _digest(_binding(secrets_namespace="sub")) != base
    assert _digest(_binding(secrets_environment="staging")) != base


def test_roles_require_the_openbao_naming() -> None:
    with pytest.raises(DeployBindingRefusedError, match="OpenBao naming"):
        _binding(secrets_environment=None)
    with pytest.raises(DeployBindingRefusedError, match="OpenBao naming"):
        _binding(secrets_namespace="")
    # With no roles there is nothing to mint: the keys may be absent (null).
    bare = _binding(roles=[], secrets_namespace="erp", secrets_environment=None)
    assert bare.payload()["secrets_environment"] is None
    for label, bad in (("secrets_namespace", "Erp"), ("secrets_environment", "Prod")):
        with pytest.raises(DeployBindingRefusedError, match="lowercase segment"):
            _binding(**{label: bad})
