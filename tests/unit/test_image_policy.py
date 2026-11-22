"""Image delivery rules (design 2.7, 2.9 Control column)."""

from __future__ import annotations

import pytest

from dotmac_deployment_control.deploy_unit import (
    DEFAULT_IMAGE_SOURCE,
    parse_deploy_unit,
)
from dotmac_deployment_control.image_policy import (
    ImagePolicyRefusedError,
    PullAllowlist,
    check_image_source,
    check_planned_image,
    effective_image_source,
    loopback_repository,
)

_REPO = "registry.example.test/team/app"
_D1 = "sha256:" + "1" * 64
_D2 = "sha256:" + "2" * 64
_MIN = (
    'schema = "dotmac.deploy_unit/1"\nproduct = "erp_v2"\n'
    'spec = "deploy/product.toml"\n'
)


def test_image_source_default_transfer() -> None:
    assert DEFAULT_IMAGE_SOURCE == "transfer"
    assert effective_image_source(None) == "transfer"
    assert parse_deploy_unit(_MIN).image_source == "transfer"
    assert parse_deploy_unit(_MIN + "[image]\n").image_source == "transfer"
    # The allowlist is empty by default.
    assert PullAllowlist().repositories == frozenset()


def test_pull_requires_public_allowlist() -> None:
    with pytest.raises(ImagePolicyRefusedError, match="public_pull_repositories"):
        check_image_source("pull", _REPO, PullAllowlist())
    allowed = PullAllowlist.of([_REPO])
    assert check_image_source("pull", _REPO, allowed) == "pull"
    # Another repository is still refused, and transfer never needs the list.
    with pytest.raises(ImagePolicyRefusedError):
        check_image_source("pull", _REPO + "-other", allowed)
    assert check_image_source("transfer", _REPO, PullAllowlist()) == "transfer"
    with pytest.raises(ImagePolicyRefusedError):
        check_image_source("copy", _REPO, allowed)
    # A loopback repository can never be allowlisted as a public pull source.
    with pytest.raises(ImagePolicyRefusedError):
        PullAllowlist.of(["127.0.0.1:5000/team/app"])


def _check(**overrides: str | None) -> None:
    args: dict[str, object] = {
        "source": "transfer",
        "release_repository": _REPO,
        "release_digest": _D1,
        "planned_repository": loopback_repository(_REPO, 5000),
        "planned_digest": _D1,
        "allowlist": PullAllowlist(),
    }
    args.update(overrides)
    check_planned_image(**args)  # type: ignore[arg-type]


def test_image_repository_same_digest() -> None:
    assert loopback_repository(_REPO, 5000) == "127.0.0.1:5000/team/app"
    _check()  # the one accepted shape
    # Different digest, different path, off-loopback host, bad port, no port.
    for bad in (
        {"planned_digest": _D2},
        {"planned_repository": "127.0.0.1:5000/team/other"},
        {"planned_repository": "198.51.100.7:5000/team/app"},
        {"planned_repository": "localhost:5000/team/app"},
        {"planned_repository": "127.0.0.1:0/team/app"},
        {"planned_repository": "127.0.0.1/team/app"},
        {"planned_repository": _REPO},
        {"planned_digest": "sha256:" + "G" * 64},
    ):
        with pytest.raises(ImagePolicyRefusedError):
            _check(**bad)  # type: ignore[arg-type]
    # A pulled (allowlisted) image keeps the release repository and digest.
    allowed = PullAllowlist.of([_REPO])
    _check(source="pull", planned_repository=_REPO, allowlist=allowed)
    with pytest.raises(ImagePolicyRefusedError):
        _check(
            source="pull",
            planned_repository=loopback_repository(_REPO, 5000),
            allowlist=allowed,
        )
    with pytest.raises(ImagePolicyRefusedError):
        loopback_repository(_REPO, 70000)


def test_a_non_numeric_registry_port_is_a_typed_refusal() -> None:
    """Not a ValueError leaking out as a 500: a typed, closed refusal."""
    for bad in ("registry.example.test:abc/team/app", "127.0.0.1:x/team/app"):
        with pytest.raises(ImagePolicyRefusedError):
            PullAllowlist.of([bad])
        with pytest.raises(ImagePolicyRefusedError):
            _check(planned_repository=bad)
