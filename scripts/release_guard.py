"""Refuse to publish a version this repository is not entitled to publish.

STEP 8 of the extraction. The floor exists because `0.1.0a1` and `0.1.0a2` were
published from `dotmac_starter_mt` and their artifacts are immutable: Vendor
Control Plane pins a2 by version AND by wheel/sdist hash, so re-uploading those
bytes is not merely disallowed, it would break a live consumer's lock.

Three refusals, and they are independent:

* the DISTRIBUTION must be this one — the credential that will publish it is
  owner-scoped on Forgejo and can write any package under `dotmac`, so the
  narrowing has to happen here;
* the VERSION must be strictly greater than the inherited floor;
* the SHAPE must be one this module can actually order.

The last is not padding. A hand-rolled comparator that guesses at an unfamiliar
version string is worse than no comparator, because it answers confidently. This
one accepts exactly `<major>.<minor>.<patch>a<n>` — the only shape this
distribution has ever used — and REFUSES anything else rather than reasoning
about it. If this package ever moves to beta or a release candidate, the guard
fails closed and someone extends it deliberately.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = REPO_ROOT / "docs" / "published-versions.json"

DISTRIBUTION = "dotmac-deployment-control"

#: `0.1.0a2`, and nothing else. Deliberately narrow — see the module docstring.
_ALPHA = re.compile(r"^(\d+)\.(\d+)\.(\d+)a(\d+)$")


def parse(version: str) -> tuple[int, int, int, int] | None:
    """An orderable key, or None when the shape is not one we can order."""
    match = _ALPHA.fullmatch(version.strip())
    if match is None:
        return None
    major, minor, patch, alpha = match.groups()
    return (int(major), int(minor), int(patch), int(alpha))


def published_versions(path: Path = PUBLISHED) -> list[dict]:
    return list(json.loads(path.read_text(encoding="utf-8"))["releases"])


def published_floor(path: Path = PUBLISHED) -> str:
    """The highest version that EXISTS on the index, from any source.

    Read from the recorded coordinates rather than hard-coded, so the floor and
    the provenance move together. A literal here could drift from the file that
    says which versions actually exist.

    "Exists" is the criterion, not "was released successfully". `0.1.0a3` was
    published by a run cancelled during its own verification and is recorded
    UNPROVABLE and unpinnable — but an index cannot un-publish, so it bounds the
    floor exactly as a good release does. A floor that skipped it would let the
    next release collide with bytes that are permanently there.
    """
    versions = [r["version"] for r in published_versions(path)]
    keys = {v: parse(v) for v in versions}
    unorderable = sorted(v for v, k in keys.items() if k is None)
    if unorderable:
        raise ValueError(f"published versions are unorderable: {unorderable}")
    return max(versions, key=lambda v: keys[v])  # type: ignore[index]


def unpinnable(path: Path = PUBLISHED) -> dict[str, str]:
    """version -> why it may never be depended on."""
    return {
        r["version"]: str(r.get("release_run_note", "recorded as not pinnable"))
        for r in published_versions(path)
        if r.get("pinnable") is False
    }


def refusals(distribution: str, version: str, *, floor: str | None = None) -> list[str]:
    """Every reason this publication must not happen. Empty means proceed."""
    problems: list[str] = []
    ceiling = floor if floor is not None else published_floor()

    # A distinct refusal, before the generic floor message. `0.1.0a3` is
    # refused for a reason the floor cannot express: it EXISTS and is
    # permanently unverifiable, so "publish something higher" is the remedy and
    # "this is below the floor" would understate why.
    reason = unpinnable().get(version.strip())
    if reason is not None:
        problems.append(
            f"version {version} exists on the index and is recorded UNPINNABLE. "
            f"{reason}"
        )

    if distribution != DISTRIBUTION:
        problems.append(
            f"this repository publishes {DISTRIBUTION!r} and nothing else; "
            f"refusing {distribution!r}. The publishing credential is "
            "owner-scoped on Forgejo and can write any package under `dotmac`, "
            "so this check is the only thing that narrows it to one name."
        )

    key = parse(version)
    if key is None:
        problems.append(
            f"version {version!r} is not a shape this guard can order. It "
            f"accepts `<major>.<minor>.<patch>a<n>` only. Refusing rather than "
            "guessing: a comparator that reasons about an unfamiliar version "
            "answers confidently and wrongly. Extend it deliberately."
        )
        return problems

    ceiling_key = parse(ceiling)
    if ceiling_key is None:
        problems.append(f"inherited floor {ceiling!r} is unorderable")
        return problems

    if key <= ceiling_key:
        problems.append(
            f"version {version} is not greater than {ceiling}, which already "
            "exists on the index. Published artifacts are immutable and a "
            "consumer pins one by wheel and sdist hash; re-uploading a name "
            "would either be refused by the index or break that lock. Publish a "
            "version strictly greater than the published floor."
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)

    problems = refusals(args.distribution, args.version)
    for problem in problems:
        print(f"error {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"{args.distribution} {args.version} is above the published floor")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
