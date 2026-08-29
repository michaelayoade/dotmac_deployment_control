"""STEPS 7 AND 8 — inherited coordinates, and the floor derived from them.

Two things that only make sense together. The coordinates record what was
published from `dotmac_starter_mt`; the floor refuses to publish at or below
them. Writing the floor as a literal would let it drift from the file that says
which versions actually exist, so `release_guard` reads it.

## Why the tags are recorded and not recreated

`git filter-repo` rewrote every commit on the way here. A tag named
`dotmac-deployment-control-v0.1.0a2` created in THIS repository would point at a
tree that is not the one published under that name — one version naming two
commits, and every pin against the original coordinate unidentifiable.

Not hypothetical: the extraction's first filter-repo pass carried 110 tags
through the rewrite, both of these among them, pointing at rewritten SHAs. They
were purged before the first push. `test_ported_gate_declared_publication.py`
holds that purge in place; this file holds the coordinates it replaced them with.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INHERITED = REPO_ROOT / "docs" / "inherited-releases.json"

_spec = importlib.util.spec_from_file_location(
    "release_guard", REPO_ROOT / "scripts" / "release_guard.py"
)
assert _spec is not None and _spec.loader is not None
release_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_guard)

COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _inherited() -> dict[str, Any]:
    return json.loads(INHERITED.read_text(encoding="utf-8"))


# ── Step 7: the coordinates ─────────────────────────────────────────────────


def test_both_inherited_releases_are_recorded() -> None:
    versions = [r["version"] for r in _inherited()["releases"]]
    assert versions == ["0.1.0a1", "0.1.0a2"], versions


@pytest.mark.parametrize("field", ["tag_object", "peeled_commit"])
def test_every_coordinate_is_an_immutable_commit(field: str) -> None:
    """A branch or an abbreviation here would not be a coordinate at all."""
    for release in _inherited()["releases"]:
        value = release[field]
        assert COMMIT.fullmatch(value), f"{release['version']}.{field} = {value!r}"


def test_the_peeled_commit_is_distinct_from_the_tag_object() -> None:
    """These are annotated tags, so the two ids differ — and recording only one
    would leave a reader unable to tell which they had. Conflating them is an
    easy mistake because `git rev-parse <tag>` returns the tag object while
    `git rev-list -n1 <tag>` returns the commit."""
    for release in _inherited()["releases"]:
        assert release["tag_object"] != release["peeled_commit"], release["version"]


def test_an_absent_release_run_is_null_and_explained() -> None:
    """a1's run id was not recorded at extraction time. Absent rather than
    invented: a coordinate that resolves to nothing is worse than a gap that
    says so."""
    by_version = {r["version"]: r for r in _inherited()["releases"]}
    assert by_version["0.1.0a1"]["release_run"] is None
    assert by_version["0.1.0a1"]["release_run_note"].strip()
    assert by_version["0.1.0a2"]["release_run"] == "32471956734"


def test_the_record_says_the_tags_stay_in_the_source_repository() -> None:
    assert _inherited()["tags_remain_in_source"] is True
    assert _inherited()["source_repository"] == "dotmac_starter_mt"


# ── Step 8: the floor ───────────────────────────────────────────────────────


def test_the_floor_is_derived_from_the_recorded_coordinates() -> None:
    assert release_guard.inherited_floor() == "0.1.0a2"


def test_the_declared_version_would_be_admitted() -> None:
    """POSITIVE CONTROL. Without it every refusal below is equally consistent
    with a guard that refuses everything."""
    assert release_guard.refusals("dotmac-deployment-control", "0.1.0a3") == []


def test_attempting_the_inherited_version_is_refused() -> None:
    """THE SENSITIVITY PROOF this step exists for: attempt a2.

    a2's artifact is immutable and dotmac_vendor_control_plane pins it by wheel
    AND sdist hash. Re-uploading the name would either be refused by the index
    or break that lock, and this guard is what makes the attempt impossible to
    make by accident.
    """
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a2")
    assert problems and "not greater than 0.1.0a2" in problems[0], problems


@pytest.mark.parametrize("version", ["0.1.0a1", "0.1.0a2", "0.0.9a99", "0.1.0a0"])
def test_nothing_at_or_below_the_floor_is_admitted(version: str) -> None:
    assert release_guard.refusals("dotmac-deployment-control", version)


@pytest.mark.parametrize("version", ["0.1.0a3", "0.1.0a10", "0.2.0a1", "1.0.0a1"])
def test_anything_above_the_floor_is_admitted(version: str) -> None:
    """`0.1.0a10` is the one that matters: lexicographically it sorts BELOW
    `0.1.0a2`, so a string comparison here would refuse the tenth alpha
    forever."""
    assert release_guard.refusals("dotmac-deployment-control", version) == []


@pytest.mark.parametrize(
    "distribution", ["dotmac-kernel", "dotmac-deployment-foundation", ""]
)
def test_another_distribution_is_refused(distribution: str) -> None:
    """The credential will be owner-scoped on Forgejo and able to write any
    package under `dotmac`. This check is the only thing narrowing it to one
    name, so it is tested as a first-class refusal rather than a formality."""
    problems = release_guard.refusals(distribution, "0.1.0a3")
    assert problems and "and nothing else" in problems[0], problems


@pytest.mark.parametrize(
    "version", ["0.1.0", "0.1.0b1", "0.1.0rc1", "1.0.0", "0.1.0a2+local", "", "latest"]
)
def test_a_shape_the_guard_cannot_order_is_refused_not_guessed(version: str) -> None:
    """Fail closed on the unfamiliar. A comparator that reasons about a version
    shape it was not written for answers confidently and wrongly; refusing sends
    someone to extend it deliberately."""
    problems = release_guard.refusals("dotmac-deployment-control", version)
    assert problems and "not a shape this guard can order" in problems[0], problems
