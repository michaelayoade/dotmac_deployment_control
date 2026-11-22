"""Image delivery rules: transfer by default, pull only for allowlisted repositories.

Fleet-wide ruling D-1: every private image reaches a host by a governed digest
transfer, and Control pins the manifest digest. A descriptor cannot widen this
by itself. `source = "pull"` is accepted only when the release's repository is
on `public_pull_repositories`, a visible Control setting that is EMPTY by
default. An absent `[image]` table means `transfer`.

## The loopback rule

A transferred image is delivered through a short-lived registry bound to the
host's loopback address. The plan's `image_repository` is therefore
`127.0.0.1:<port>/<the release repository's own path>` carrying the SAME digest.
Control refuses any other repository or digest, so a plan can never name an
image the release record does not.

Pure value rules: no I/O, no database, no clock.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from dotmac_deployment_control.deploy_unit import (
    DEFAULT_IMAGE_SOURCE,
    IMAGE_SOURCES,
    DeployUnitError,
    valid_repository,
)
from dotmac_deployment_control.digests import is_canonical_digest

LOOPBACK_HOST: Final = "127.0.0.1"


class ImagePolicyRefusedError(DeployUnitError):
    """An image source, repository or digest was refused."""


def effective_image_source(declared: str | None) -> str:
    """An absent `[image]` table (None) is `transfer`."""
    source = DEFAULT_IMAGE_SOURCE if declared is None else declared
    if source not in IMAGE_SOURCES:
        raise ImagePolicyRefusedError("image source must be transfer or pull")
    return source


@dataclass(frozen=True, slots=True)
class PullAllowlist:
    """The Control setting `public_pull_repositories`. Empty by default."""

    repositories: frozenset[str] = frozenset()

    @classmethod
    def of(cls, repositories: Iterable[str] = ()) -> PullAllowlist:
        entries = frozenset(repositories)
        for entry in entries:
            if not valid_repository(entry) or _split_port(entry)[1] == LOOPBACK_HOST:
                raise ImagePolicyRefusedError(
                    "an allowlist entry must be a non-loopback repository"
                )
        return cls(entries)


def _split_port(repository: str) -> tuple[int | None, str]:
    host = repository.split("/", 1)[0]
    name, _, port = host.partition(":")
    if port and not (port.isascii() and port.isdigit()):
        raise ImagePolicyRefusedError("a registry port must be a number")
    return (int(port) if port else None), name


def check_image_source(
    source: str | None, release_repository: str, allowlist: PullAllowlist
) -> str:
    """Return the effective source, refusing `pull` off the allowlist."""
    effective = effective_image_source(source)
    if not valid_repository(release_repository):
        raise ImagePolicyRefusedError("the release repository is not well formed")
    if effective == "pull" and release_repository not in allowlist.repositories:
        raise ImagePolicyRefusedError(
            f"source=pull is refused: {release_repository!r} is not on "
            "public_pull_repositories (empty by default)"
        )
    return effective


def loopback_repository(release_repository: str, port: int) -> str:
    """The planned repository for a transferred image: same path, loopback host."""
    if not valid_repository(release_repository):
        raise ImagePolicyRefusedError("the release repository is not well formed")
    if isinstance(port, bool) or not 1 <= port <= 65535:
        raise ImagePolicyRefusedError("the loopback port is out of range")
    path = release_repository.split("/", 1)[1]
    return f"{LOOPBACK_HOST}:{port}/{path}"


def check_planned_image(
    *,
    source: str | None,
    release_repository: str,
    release_digest: str,
    planned_repository: str,
    planned_digest: str,
    allowlist: PullAllowlist,
) -> None:
    """Refuse a planned image that is not exactly what the release names.

    * the digest must be canonical and EQUAL to the release's, always;
    * `transfer`: the planned repository must be the loopback form of the
      release repository's path (host exactly 127.0.0.1, a valid port);
    * `pull`: the planned repository must equal the release repository, which
      must itself be on the allowlist.
    """
    effective = check_image_source(source, release_repository, allowlist)
    for label, digest in (("release", release_digest), ("planned", planned_digest)):
        if not is_canonical_digest(digest):
            raise ImagePolicyRefusedError(f"the {label} digest is not canonical")
    if planned_digest != release_digest:
        raise ImagePolicyRefusedError("the planned digest differs from the release")
    if effective == "pull":
        if planned_repository != release_repository:
            raise ImagePolicyRefusedError("a pulled image keeps the release repository")
        return
    port, host = _split_port(planned_repository)
    if host != LOOPBACK_HOST or port is None or not 1 <= port <= 65535:
        raise ImagePolicyRefusedError(
            "a transferred image is planned on the 127.0.0.1 loopback registry only"
        )
    if not valid_repository(planned_repository):
        raise ImagePolicyRefusedError("the planned repository is not well formed")
    expected_path = release_repository.split("/", 1)[1]
    if planned_repository.split("/", 1)[1] != expected_path:
        raise ImagePolicyRefusedError(
            "the planned repository path differs from the release's"
        )
