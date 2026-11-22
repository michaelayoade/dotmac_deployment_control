"""Plan binding, lease TTL, deployment set and the reconcile-marker rule."""

from __future__ import annotations

from uuid import uuid4

import pytest

from dotmac_deployment_control import plan_digest_of, plan_snapshot
from dotmac_deployment_control.deploy_binding import (
    DeployBindingRefusedError,
    DeploymentSet,
    PlannedImage,
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
        _binding(lease_ttl_seconds=901),
        _binding(images=[_image(release_digest=_D2, planned_digest=_D2)]),
        _binding(images=[_image(planned_repository="127.0.0.1:5001/team/app")]),
        _binding(companion_order="after_primary_ready"),
        _binding(legacy=LegacyPlanBinding(1, _P1, ("DB_PASSWORD",))),
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
        LegacyPlanBinding(1, _P1, ("DB_PASSWORD",)),
        LegacyPlanBinding(2, _P1, ("DB_PASSWORD",)),
        LegacyPlanBinding(1, _P2, ("DB_PASSWORD",)),
        LegacyPlanBinding(1, _P1, ("DB_PASSWORD", "API_SECRET")),
    ]
    assert len({_digest(_binding(legacy=item)) for item in legacy}) == len(legacy)


def test_binding_builder_caps_the_lease_ttl() -> None:
    assert _binding(lease_ttl_seconds=3600).lease_ttl_seconds == 3600
    for bad in (0, -1, 3601, True, "900"):
        with pytest.raises(DeployBindingRefusedError, match="TTL"):
            _binding(lease_ttl_seconds=bad)


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
