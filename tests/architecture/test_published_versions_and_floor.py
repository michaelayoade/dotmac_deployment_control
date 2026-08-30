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
import tomllib
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
    assert versions == [
        "0.1.0a1",
        "0.1.0a2",
        "0.1.0a3",
        "0.1.0a4",
        "0.1.0a5",
    ], versions


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
    assert release_guard.published_floor() == "0.1.0a5"


def test_the_unpinnable_version_is_refused_by_name_not_only_by_the_floor() -> None:
    """A distinct refusal. "Below the floor" would understate why a3 is refused:
    it is not merely superseded, it is permanently unverifiable."""
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a3")
    assert problems and "UNPINNABLE" in problems[0], problems


def test_the_next_version_would_be_admitted() -> None:
    """POSITIVE CONTROL. Without it every refusal below is equally consistent
    with a guard that refuses everything.

    a6 rather than a5, as of the change that recorded a5's coordinates. a5 is
    now PUBLISHED, so the guard is required to refuse it; leaving the control on
    a5 would assert that this repository may re-upload a name that already
    exists — the exact hazard the floor is for.

    The two moves are one change because the floor is DERIVED from
    `docs/published-versions.json`: recording a5 there raises the floor, and a
    control left behind the floor is a control asserting the opposite of what
    the floor says.
    """
    assert release_guard.refusals("dotmac-deployment-control", "0.1.0a6") == []


def test_the_positive_control_tracks_the_floor_rather_than_a_literal() -> None:
    """The rule behind the comment above, checked rather than remembered.

    The admitted control must be exactly one alpha above the derived floor. A
    control that drifted below the floor would be asserting the repository may
    re-upload; one that drifted far above would stop proving the boundary is at
    the floor at all.
    """
    floor = release_guard.published_floor()
    major, minor, patch, alpha = release_guard.parse(floor)
    assert (
        release_guard.refusals(
            "dotmac-deployment-control", f"{major}.{minor}.{patch}a{alpha + 1}"
        )
        == []
    )
    assert release_guard.refusals("dotmac-deployment-control", floor)


def test_a4_carries_the_superseding_disposition_in_four_named_terms() -> None:
    """MICHAEL'S RULING, 2026-08-30, recorded in the exact terms he gave.

    a4 is the version that separates two questions this repository used to ask
    as one. Its five identity proofs stand — the tag peels to
    `2c61540f7`, the wheel and sdist hash as recorded, a clean dependency
    install succeeded, and it imported. It is still unadoptable, because an
    artifact whose identity is beyond doubt can still refuse a correct approval
    and report the wrong version of itself.
    """
    a4 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a4")
    disposition = a4["disposition"]
    assert disposition["artifact_identity"] == "passed"
    assert disposition["functional_authorization"] == "failed"
    assert disposition["version_self_reporting"] == "failed"
    assert disposition["adoption_eligibility"] == "refused"
    # A release-level fact, beside `pinnable`, not inside the disposition blob:
    # a reader scanning the rows must be able to see what to pin instead without
    # opening one. `or` was wrong here and could not short-circuit — the first
    # operand raised `KeyError` before the second was reached, which is a test
    # asserting two places and reaching neither.
    assert a4["superseded_by"] == "0.1.0a5"
    for term in (
        "artifact_identity",
        "functional_authorization",
        "version_self_reporting",
        "adoption_eligibility",
    ):
        assert str(disposition[f"{term}_evidence"]).strip(), (
            f"{term} is a verdict with no evidence behind it, which is the "
            "shape this repository refuses everywhere else"
        )


def test_the_disposition_is_APPENDED_and_never_overwrites_the_pass_record() -> None:
    """THE PROPERTY THAT MATTERS MOST ABOUT a4's ROW.

    Both facts are true at once and the PAIR is the useful evidence: identity
    verification and functional authorization are different questions, and a4
    answers the first completely while failing the second. Rewriting the
    original record to say "failed" would destroy the only worked example the
    fleet has of that distinction — and would also be false.
    """
    a4 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a4")
    note = a4["release_run_note"]
    for original in (
        "Published by run 33297423568 from the exact tip of protected main",
        "INDEPENDENT verify run 33310594187 later returned VERIFIED",
        "2c61540f74018b7e19d7c5add893e0653cfcdb17",
        "publisher read-back, read-only consumer install",
        "The tag is left exactly where that run wrote it and is never moved",
    ):
        assert original in note, (
            f"the original PASS record has lost {original!r}. The superseding "
            "disposition is APPENDED; it never rewrites what was proven."
        )
    assert a4["tag"] == "dotmac-deployment-control-v0.1.0a4"
    assert a4["tag_object"] == "3bc4ab0000c3a3dc8a4cf495d9cfec56ded6ed6a"
    assert a4["peeled_commit"] == "2c61540f74018b7e19d7c5add893e0653cfcdb17"
    assert set(a4["sha256"]) == {
        "dotmac_deployment_control-0.1.0a4-py3-none-any.whl",
        "dotmac_deployment_control-0.1.0a4.tar.gz",
    }


def test_a4_is_recorded_unadoptable_for_functional_reasons_not_identity_ones() -> None:
    """The refusal must say WHICH question failed. "a4 is bad" would send the
    next reader hunting a byte problem that does not exist."""
    a4 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a4")
    assert a4["pinnable"] is False
    reason = a4["unpinnable_reason"]
    assert "identity" in reason.lower()
    assert "0.1.0a5" in reason, "the record must name what to pin instead"
    for evidence in ("approve_plan", "__version__", "the plan changed after approval"):
        assert evidence in reason, evidence


def test_a4_is_refused_by_name_as_well_as_by_the_floor() -> None:
    """TWO independent refusals, and the order matters.

    The floor alone would say "publish something higher", which understates
    why. a4 is not merely superseded: Michael ruled it UNADOPTABLE on
    2026-08-30, so it is recorded `pinnable: false` and refused by name — the
    same distinct refusal a3 gets, for a different reason. The floor refusal
    stays behind it, because a4 is also on the index and re-uploading a name is
    its own hazard.
    """
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a4")
    assert len(problems) >= 2, problems
    assert "UNPINNABLE" in problems[0], problems
    assert "UNADOPTABLE" in problems[0], problems
    assert any("not greater than 0.1.0a5" in p for p in problems), problems


def test_attempting_the_inherited_version_is_refused() -> None:
    """THE SENSITIVITY PROOF this step exists for: attempt a2.

    a2's artifact is immutable and dotmac_vendor_control_plane pins it by wheel
    AND sdist hash. Re-uploading the name would either be refused by the index
    or break that lock, and this guard is what makes the attempt impossible to
    make by accident.
    """
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a2")
    assert problems and "not greater than 0.1.0a5" in problems[0], problems
    assert not any("UNPINNABLE" in p for p in problems), (
        "a2 is pinnable and Vendor Control Plane depends on it; refusing it as "
        "unpinnable would be a different and wrong statement"
    )


@pytest.mark.parametrize(
    "version",
    ["0.1.0a1", "0.1.0a2", "0.1.0a3", "0.1.0a4", "0.1.0a5", "0.0.9a99", "0.1.0a0"],
)
def test_nothing_at_or_below_the_floor_is_admitted(version: str) -> None:
    assert release_guard.refusals("dotmac-deployment-control", version)


@pytest.mark.parametrize("version", ["0.1.0a6", "0.1.0a10", "0.2.0a1", "1.0.0a1"])
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
    problems = release_guard.refusals(distribution, "0.1.0a6")
    assert problems and "and nothing else" in problems[0], problems


@pytest.mark.parametrize(
    "version", ["0.1.0", "0.1.0b1", "0.1.0rc1", "1.0.0", "0.1.0a6+local", "", "latest"]
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
    # `pinnable` is deliberately NOT asserted here. This test is about a4's
    # IDENTITY, which is settled and unchanged; whether it may be adopted is a
    # separate question with its own test below, and conflating them is exactly
    # what would let a superseding disposition quietly erase a proof.
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


# ── a5: published, and the first verified on SEVEN properties ───────────────


def test_a5_is_recorded_as_published_and_independently_verified() -> None:
    """The first release cut through the corrected two-workflow path: the
    publishing run neither verified itself nor tagged, and a separate run
    gathered the evidence afresh and wrote the tag on a VERIFIED verdict."""
    a5 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a5")
    # `pinnable` is deliberately NOT asserted here, for the same reason it is
    # absent from a4's identity test: whether a5's bytes are what they say they
    # are and whether a5 may be adopted are different questions, and conflating
    # them is what lets a superseding disposition quietly erase a proof. a5's
    # adoption standing has its own tests below.
    assert a5["status"] == "released"
    assert a5["release_run"] == "33318227812"
    assert a5["verify_run"] == "33318433336"
    assert a5["verify_run"] != a5["release_run"]
    assert a5["supersedes"] == "0.1.0a4"
    assert a5["peeled_commit"] == "b182a99892067f26c0c1d03d958c5fcdc97c5869"


def test_a5_records_the_exact_bytes_it_names() -> None:
    a5 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a5")
    digests = a5["sha256"]
    assert set(digests) == {
        "dotmac_deployment_control-0.1.0a5-py3-none-any.whl",
        "dotmac_deployment_control-0.1.0a5.tar.gz",
    }, sorted(digests)
    for name, digest in digests.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{name} = {digest!r}"


def test_a5_is_the_version_a4_points_at() -> None:
    """The two rows must agree about the supersession, in both directions. A
    record that says a4 is unadoptable without naming its replacement sends a
    consumer to work out for itself what to pin, and a5 claiming to supersede
    something a4 does not acknowledge is the same gap from the other side."""
    releases = {r["version"]: r for r in _published()["releases"]}
    assert releases["0.1.0a4"]["superseded_by"] == "0.1.0a5"
    assert releases["0.1.0a5"]["supersedes"] == "0.1.0a4"
    assert releases["0.1.0a4"]["pinnable"] is False


def test_the_supersession_chain_ends_at_a_version_that_may_be_pinned() -> None:
    """THE QUESTION A CONSUMER ACTUALLY ASKS, and the one a per-row `pinnable`
    flag cannot answer on its own.

    a3 is unprovable, a4 is unadoptable, a5 is under-constrained. Three rows
    each saying "not this one" leave a reader to reconstruct the chain by hand,
    and the reconstruction is exactly where somebody pins the wrong thing. So
    every refused row must name its replacement, and following the chain from
    the oldest refusal must terminate — either at a pinnable published row, or
    at a version that is declared and not yet published, which is the honest
    answer while a repair is in flight.
    """
    releases = {r["version"]: r for r in _published()["releases"]}
    ledger = json.loads(
        (REPO_ROOT / "docs" / "publication-ledger.json").read_text(encoding="utf-8")
    )["unpublished"]

    seen: list[str] = []
    version = "0.1.0a4"
    while version in releases and releases[version].get("pinnable") is False:
        assert version not in seen, f"the supersession chain loops at {version}"
        seen.append(version)
        nxt = releases[version].get("superseded_by")
        assert nxt, (
            f"{version} is refused and names no replacement. A consumer reading "
            "this file has to guess, and guessing is how 0.1.0a4 nearly got "
            "pinned."
        )
        version = nxt

    assert version not in seen
    if version in releases:
        assert releases[version].get("pinnable") is True, version
    else:
        assert version in ledger, (
            f"the chain ends at {version}, which is neither a published row nor "
            "a declared-and-unpublished one. It ends nowhere."
        )
    assert seen == ["0.1.0a4", "0.1.0a5"], seen


# ── a5: verified, and still not adoptable ───────────────────────────────────


def test_a5_carries_the_superseding_disposition_in_four_named_terms() -> None:
    """MICHAEL'S RULING, 2026-08-30, and it is NEW EVIDENCE rather than a record
    adjusted after the fact.

    a5 is the version that separates a third question from the two a4 already
    separated. a4 showed that artifact identity and functional behaviour are
    different findings. a5 shows that BOTH of those can pass while the DECLARED
    DEPENDENCY FLOOR is wrong: its bytes are the published bytes, the encoding
    defect it was cut for is genuinely fixed, and it still cannot be composed,
    because it imports a kernel module 21 alphas above the floor it declares.
    """
    a5 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a5")
    disposition = a5["disposition"]
    assert disposition["artifact_identity"] == "passed"
    assert disposition["functional_authorization"] == "passed"
    assert disposition["declared_dependency_floor"] == "failed"
    assert disposition["adoption_eligibility"] == "refused"
    assert a5["superseded_by"] == "0.1.0a6"
    for term in (
        "artifact_identity",
        "functional_authorization",
        "declared_dependency_floor",
        "adoption_eligibility",
    ):
        assert str(disposition[f"{term}_evidence"]).strip(), (
            f"{term} is a verdict with no evidence behind it, which is the "
            "shape this repository refuses everywhere else"
        )


def test_a5s_disposition_is_APPENDED_and_never_overwrites_the_pass_record() -> None:
    """THE SAME TREATMENT a4 RECEIVED, and for the same reason.

    a5's seven-property verification really happened and is not withdrawn.
    Rewriting the record to say "failed" would destroy the evidence that a
    complete identity verification and a working artifact are still not enough
    to make a distribution composable — which is the only lesson a6 has to
    teach.
    """
    a5 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a5")
    note = a5["release_run_note"]
    for original in (
        "THE FIRST RELEASE CUT THROUGH THE CORRECTED TWO-WORKFLOW PATH",
        "INDEPENDENT verify run 33318433336 returned VERIFIED",
        "b182a99892067f26c0c1d03d958c5fcdc97c5869",
        "all seven behavioural canaries passing against the wheel the REGISTRY served",
        "Only that run wrote the tag, on a VERIFIED verdict, through tag_once.py",
    ):
        assert original in note, (
            f"the original PASS record has lost {original!r}. The superseding "
            "disposition is APPENDED; it never rewrites what was proven."
        )
    assert a5["tag"] == "dotmac-deployment-control-v0.1.0a5"
    assert a5["tag_object"] == "ed5f62fc68cb068a829d3c28b83f2c65dee2860c"
    assert a5["peeled_commit"] == "b182a99892067f26c0c1d03d958c5fcdc97c5869"
    assert set(a5["sha256"]) == {
        "dotmac_deployment_control-0.1.0a5-py3-none-any.whl",
        "dotmac_deployment_control-0.1.0a5.tar.gz",
    }


def test_a5_is_refused_for_its_declaration_not_for_its_bytes() -> None:
    """The refusal must say WHICH question failed. "a5 is bad" would send the
    next reader hunting a byte problem that does not exist, and would erase the
    distinction that makes this repository's release record worth keeping."""
    a5 = next(r for r in _published()["releases"] if r["version"] == "0.1.0a5")
    assert a5["pinnable"] is False
    reason = a5["unpinnable_reason"]
    assert "0.1.0a6" in reason, "the record must name what to pin instead"
    for evidence in (
        "dotmac_kernel.transactions",
        "0.1.0a98",
        ">=0.1.0a77",
        "21 alphas",
    ):
        assert evidence in reason, evidence
    assert "IDENTITY" in reason.upper()


def test_a5_is_refused_by_name_as_well_as_by_the_floor() -> None:
    """TWO independent refusals, exactly as a4 gets. The floor alone would say
    "publish something higher", which is true and says nothing about why a5
    must not be adopted by a consumer that is not publishing at all."""
    problems = release_guard.refusals("dotmac-deployment-control", "0.1.0a5")
    assert len(problems) >= 2, problems
    assert "UNPINNABLE" in problems[0], problems
    assert "UNSUITABLE FOR NEW ADOPTION" in problems[0], problems
    assert any("not greater than 0.1.0a5" in p for p in problems), problems


def test_the_ledger_holds_the_declared_version_and_nothing_else() -> None:
    """THE DISCIPLINE THE a4 ROW FAILED, stated as a rule rather than as a
    snapshot.

    a4's `never-published` entry outlived its own publication by six hours, and
    the earlier form of this test — `unpublished == {}` — could only be true
    between releases. Held literally it would have forced a6's declaration into
    `docs/published-versions.json` BEFORE the upload, which raises the derived
    floor above the version being published and makes the release guard refuse
    the very release it exists to admit.

    So the rule is the one the two files actually owe each other: the ledger
    holds exactly the versions this tree declares and has not yet published,
    and every row is deleted in the change that records its coordinates.
    """
    ledger = json.loads(
        (REPO_ROOT / "docs" / "publication-ledger.json").read_text(encoding="utf-8")
    )["unpublished"]
    declared = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["tool"]["poetry"]["version"]
    published = {r["version"] for r in _published()["releases"]}

    stale = sorted(set(ledger) - {declared})
    assert not stale, (
        f"{stale} sit in the ledger and are not the version this tree declares. "
        "A row outliving its own release is the stale absolution the "
        "two-directional ratchet exists to catch."
    )
    if declared not in published:
        assert declared in ledger, (
            f"{declared} is declared, unpublished, and unrecorded. A consumer "
            "pinning it gets a resolver error."
        )
        assert str(ledger[declared].get("reason", "")).strip()
    else:
        assert declared not in ledger, (
            f"{declared} is published AND recorded unpublished. Remove the "
            "ledger row in the change that records the coordinates."
        )
