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
PUBLISHED = REPO_ROOT / "docs" / "published-versions.json"

_spec = importlib.util.spec_from_file_location(
    "release_guard", REPO_ROOT / "scripts" / "release_guard.py"
)
assert _spec is not None and _spec.loader is not None
release_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_guard)

COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _published() -> dict[str, Any]:
    return json.loads(PUBLISHED.read_text(encoding="utf-8"))


# ── Step 7: the coordinates ─────────────────────────────────────────────────


def test_every_published_version_is_recorded() -> None:
    versions = [r["version"] for r in _published()["releases"]]
    assert versions == ["0.1.0a1", "0.1.0a2", "0.1.0a3", "0.1.0a4"], versions


@pytest.mark.parametrize("field", ["tag_object", "peeled_commit"])
def test_every_coordinate_is_an_immutable_commit_or_absent(field: str) -> None:
    """A branch or an abbreviation would not be a coordinate at all. `None` is
    permitted only where the thing genuinely does not exist — a3 has no tag
    object because it was never tagged, and inventing one would be worse than
    the gap."""
    for release in _published()["releases"]:
        value = release[field]
        if value is None:
            assert release["version"] == "0.1.0a3", release["version"]
            continue
        assert COMMIT.fullmatch(value), f"{release['version']}.{field} = {value!r}"


def test_the_peeled_commit_is_distinct_from_the_tag_object() -> None:
    """These are annotated tags, so the two ids differ — and recording only one
    would leave a reader unable to tell which they had. Conflating them is an
    easy mistake because `git rev-parse <tag>` returns the tag object while
    `git rev-list -n1 <tag>` returns the commit."""
    for release in _published()["releases"]:
        if release["tag_object"] is None:
            continue
        assert release["tag_object"] != release["peeled_commit"], release["version"]


def test_an_absent_release_run_is_null_and_explained() -> None:
    """a1's run id was not recorded at extraction time. Absent rather than
    invented: a coordinate that resolves to nothing is worse than a gap that
    says so."""
    by_version = {r["version"]: r for r in _published()["releases"]}
    assert by_version["0.1.0a1"]["release_run"] is None
    assert by_version["0.1.0a1"]["release_run_note"].strip()
    assert by_version["0.1.0a2"]["release_run"] == "32471956734"


def test_the_record_says_which_tags_stay_in_the_source_repository() -> None:
    assert _published()["tags_remain_in_source_for"] == ["0.1.0a1", "0.1.0a2"]
    sources = {r["version"]: r["source_repository"] for r in _published()["releases"]}
    assert sources["0.1.0a1"] == "dotmac_starter_mt"
    assert sources["0.1.0a3"] == "dotmac_deployment_control"


def test_a3_is_recorded_as_published_and_never_pinnable() -> None:
    """An index cannot un-publish. The only place "this exists and must never be
    depended on" can live is this record and the guard that reads it."""
    a3 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a3")
    assert a3["pinnable"] is False
    assert a3["status"] == "UNPROVABLE"
    assert a3["tag"] is None and a3["tag_object"] is None
    assert a3["verify_run"] == "33296262948"
    assert "UNPROVABLE" in a3["release_run_note"]


# ── Step 8: the floor ───────────────────────────────────────────────────────


def test_the_floor_is_derived_from_the_recorded_coordinates() -> None:
    """a3 bounds the floor even though it may never be pinned: it EXISTS, and a
    floor that skipped it would let the next release collide with bytes that are
    permanently on the index."""
    assert release_guard.published_floor() == "0.1.0a4"


def test_the_unpinnable_version_is_refused_by_name_not_only_by_the_floor() -> None:
    """A distinct refusal. "Below the floor" would understate why a3 is refused:
    it is not merely superseded, it is permanently unverifiable."""
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a3")
    assert problems and "UNPINNABLE" in problems[0], problems


def test_the_next_version_would_be_admitted() -> None:
    """POSITIVE CONTROL. Without it every refusal below is equally consistent
    with a guard that refuses everything.

    a5 rather than a4: the declared version is now PUBLISHED, so the guard is
    required to refuse it. Leaving the old positive control pointed at a4 would
    have asserted that this repository may re-upload a name that already exists
    — the exact hazard the floor is for."""
    assert release_guard.refusals("dotmac-deployment-control", "0.1.0a5") == []


def test_the_declared_version_is_now_refused_because_it_is_published() -> None:
    """0.1.0a4 is on the index. The floor must close behind it the moment it is
    recorded, or a re-dispatch of the release workflow reaches twine and is
    stopped only by the registry — a transport error standing in for a
    decision."""
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a4")
    assert problems and "not greater than 0.1.0a4" in problems[0], problems


def test_attempting_the_inherited_version_is_refused() -> None:
    """THE SENSITIVITY PROOF this step exists for: attempt a2.

    a2's artifact is immutable and dotmac_vendor_control_plane pins it by wheel
    AND sdist hash. Re-uploading the name would either be refused by the index
    or break that lock, and this guard is what makes the attempt impossible to
    make by accident.
    """
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a2")
    assert problems and "not greater than 0.1.0a4" in problems[0], problems


@pytest.mark.parametrize(
    "version", ["0.1.0a1", "0.1.0a2", "0.1.0a3", "0.1.0a4", "0.0.9a99", "0.1.0a0"]
)
def test_nothing_at_or_below_the_floor_is_admitted(version: str) -> None:
    assert release_guard.refusals("dotmac-deployment-control", version)


@pytest.mark.parametrize("version", ["0.1.0a5", "0.1.0a10", "0.2.0a1", "1.0.0a1"])
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
    problems = release_guard.refusals(distribution, "0.1.0a5")
    assert problems and "and nothing else" in problems[0], problems


@pytest.mark.parametrize(
    "version", ["0.1.0", "0.1.0b1", "0.1.0rc1", "1.0.0", "0.1.0a5+local", "", "latest"]
)
def test_a_shape_the_guard_cannot_order_is_refused_not_guessed(version: str) -> None:
    """Fail closed on the unfamiliar. A comparator that reasons about a version
    shape it was not written for answers confidently and wrongly; refusing sends
    someone to extend it deliberately."""
    problems = release_guard.refusals("dotmac-deployment-control", version)
    assert problems and "not a shape this guard can order" in problems[0], problems


# ── a4: published, independently verified, and now part of the floor ────────


def test_a4_is_recorded_as_published_and_verified_by_an_independent_run() -> None:
    """The tag alone does not carry this. a4's tag was written by a job inside
    its own release run that called itself a verification and compared the
    wheel only — the same gap that made a3 unprovable. What makes a4 sound is
    the SEPARATE verify run recorded here, so the run id is a required
    coordinate rather than a note."""
    a4 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a4")
    assert a4["pinnable"] is True
    assert a4["status"] == "released"
    assert a4["release_run"] == "33297423568"
    assert a4["verify_run"] == "33310594187"
    assert a4["verify_run"] != a4["release_run"], (
        "the verification must not be the publishing run; a publisher "
        "witnessing its own upload is how a4 was tagged in the first place"
    )
    assert a4["source_repository"] == "dotmac_deployment_control"


def test_a4_records_the_exact_bytes_it_names() -> None:
    """A version coordinate without hashes is a name, not an identity. These are
    the digests verify run 33310594187 fetched from registry.dotmac.io by name
    and found equal to release run 33297423568's build."""
    a4 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a4")
    digests = a4["sha256"]
    assert set(digests) == {
        "dotmac_deployment_control-0.1.0a4-py3-none-any.whl",
        "dotmac_deployment_control-0.1.0a4.tar.gz",
    }, sorted(digests)
    for name, digest in digests.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{name} = {digest!r}"


def test_the_recorded_tag_coordinates_match_the_tag_that_exists() -> None:
    """SENSITIVITY on the coordinates themselves. A recorded tag object and
    peeled commit that no tag actually resolves to would be two more strings
    nobody had checked — and this repository's whole argument is that a
    coordinate is only worth what an oracle says about it."""
    import subprocess

    for release in _published()["releases"]:
        if release.get("source_repository") != "dotmac_deployment_control":
            continue
        if not release.get("tag"):
            continue
        tag = release["tag"]
        object_id = subprocess.run(  # noqa: S603
            ["git", "rev-parse", tag],  # noqa: S607
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        peeled = subprocess.run(  # noqa: S603
            ["git", "rev-list", "-n", "1", tag],  # noqa: S607
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        assert object_id == release["tag_object"], (
            f"{tag} resolves to {object_id or 'nothing'}, but the record says "
            f"{release['tag_object']}. Either the checkout has no tags "
            "(`fetch-tags: true`) or a coordinate is wrong."
        )
        assert (
            peeled == release["peeled_commit"]
        ), f"{tag} peels to {peeled or 'nothing'}, not {release['peeled_commit']}"
