"""PORTED GATE 3 — a declared version nobody can install is detected here.

Source: `dotmac_starter_mt` `tests/architecture/test_declared_publication.py`
and `scripts/declared_publication_sweep.py`, ported as an equivalent property.

Three surfaces agreeing on `0.1.0a3` says nothing about whether `0.1.0a3` was
ever built, uploaded and verified. Internal consistency and publication are
different questions and only the first one is otherwise checked.

**This is a detector, not a fixer.** The repair for an unpublished declaration is
a release run, or a recorded decision to leave it unreleased — never a quiet edit
of the declared number, which makes the repository agree with the index by
discarding the work the number describes.

The ledger is a TWO-DIRECTIONAL ratchet: a version that enters the unpublished
state without an entry fails, and an entry that survives its own publication
fails too. A one-way check lets a stale absolution sit forever.
"""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER = REPO_ROOT / "docs" / "publication-ledger.json"
PUBLISHED = REPO_ROOT / "docs" / "published-versions.json"
TAG_PREFIX = "dotmac-deployment-control-v"

#: Published from `dotmac_starter_mt`; their tags stay there permanently.
INHERITED = frozenset({"0.1.0a1", "0.1.0a2"})


def _declared_version() -> str:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["tool"]["poetry"]["version"])


def _local_tags() -> set[str]:
    result = subprocess.run(  # noqa: S603
        ["git", "tag", "--list", f"{TAG_PREFIX}*"],  # noqa: S607
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        line.removeprefix(TAG_PREFIX)
        for line in result.stdout.split()
        if line.startswith(TAG_PREFIX)
    }


def _ledger() -> dict[str, dict]:
    return json.loads(LEDGER.read_text(encoding="utf-8"))["unpublished"]


def publication_problems(
    version: str, tags: set[str], ledger: dict[str, dict]
) -> list[str]:
    """The whole decision, as a pure function.

    Pure so the live check and its planted violations exercise the SAME code.
    A sensitivity proof that asserts on hand-written literals proves the
    literals, not the gate — which is the vacuity this repository has spent the
    day removing from other people's guards.
    """
    problems: list[str] = []

    if version not in tags:
        entry = ledger.get(version)
        if entry is None:
            problems.append(
                f"{version} is declared, has no {TAG_PREFIX}{version} tag here, "
                "and no ledger entry. A consumer pinning it gets a resolver "
                "error. Release it, or record why it is unreleased — do not "
                "lower the declared number."
            )
        elif not str(entry.get("reason", "")).strip():
            problems.append(f"{version}: the ledger entry is a bare label")

    for stale in sorted(set(ledger) & tags):
        problems.append(
            f"{stale} is recorded as unpublished but a tag for it exists here. "
            "Delete the entry in the same change that publishes."
        )

    for recreated in sorted(INHERITED & tags):
        problems.append(
            f"{recreated} was published from dotmac_starter_mt and its tag "
            "belongs there. filter-repo rewrote the SHAs, so a tag here names a "
            "tree that is not the published one — one version, two contents."
        )
    return problems


def test_the_declared_version_is_accounted_for() -> None:
    assert publication_problems(_declared_version(), _local_tags(), _ledger()) == []


def test_the_gate_refuses_an_unrecorded_unpublished_declaration() -> None:
    """PLANTED VIOLATION — through the same function the live check uses."""
    problems = publication_problems("0.1.0a7", set(), {})
    assert problems and "no ledger entry" in problems[0], problems


def test_the_gate_refuses_a_bare_label() -> None:
    problems = publication_problems("0.1.0a7", set(), {"0.1.0a7": {"state": "x"}})
    assert problems and "bare label" in problems[0], problems


def test_the_gate_refuses_a_stale_absolution() -> None:
    """The other direction: an entry that outlived its own publication."""
    problems = publication_problems(
        "0.1.0a7", {"0.1.0a7"}, {"0.1.0a7": {"reason": "planted"}}
    )
    assert problems and "recorded as unpublished but a tag" in problems[0], problems


def test_the_gate_refuses_a_recreated_inherited_tag() -> None:
    problems = publication_problems(
        "0.1.0a3", {"0.1.0a2"}, {"0.1.0a3": {"reason": "x"}}
    )
    assert problems and "belongs there" in problems[0], problems


def test_the_gate_passes_a_published_version() -> None:
    """POSITIVE CONTROL. Without it the four refusals are equally consistent
    with a function that refuses everything."""
    assert publication_problems("0.1.0a7", {"0.1.0a7"}, {}) == []


# ── the gate must be able to SEE the tags it rules on ───────────────────────


def _published_here_with_a_tag() -> dict[str, str]:
    """version -> tag, for versions this repository published and tagged.

    a1 and a2 are excluded by construction: they were published from
    `dotmac_starter_mt` and their tags live there, so their absence here is
    correct rather than a gap.
    """
    data = json.loads(PUBLISHED.read_text(encoding="utf-8"))
    return {
        r["version"]: r["tag"]
        for r in data["releases"]
        if r.get("tag") and r.get("source_repository") == "dotmac_deployment_control"
    }


def test_a_tag_this_repository_published_is_visible_to_the_gate() -> None:
    """THE VACUITY PROOF, and it is not hypothetical.

    `publication_problems` decides publication from `git tag --list`. A checkout
    that fetches no tags gives it exactly one possible answer — none — and the
    half of the ratchet that catches a stale absolution can then never fire. It
    never fired: `0.1.0a4` was tagged at 06:41 and the ledger went on calling it
    `never-published`, through green CI, because CI could not see the tag.

    So the recorded coordinates are the oracle. Every version this repository
    published and tagged must be visible as a local tag; if one is not, the
    checkout is tagless and every assertion in this file is passing for the
    wrong reason. The repair is `fetch-tags: true` on the CI checkout, or
    `git fetch --tags` locally — never deleting this test.
    """
    expected = _published_here_with_a_tag()
    assert expected, (
        "no version is recorded as published AND tagged from this repository, "
        "so this check proves nothing. Record the coordinates in "
        "docs/published-versions.json."
    )
    visible = _local_tags()
    missing = sorted(v for v in expected if v not in visible)
    assert not missing, (
        f"tags for {missing} are recorded in docs/published-versions.json but "
        f"are not visible locally (visible: {sorted(visible) or 'none'}). The "
        "publication gate reads `git tag --list`, so a tagless checkout makes "
        "it answer 'unpublished' for everything. Add `fetch-tags: true` to the "
        "checkout."
    )


def test_the_ledger_and_the_published_record_never_claim_the_same_version() -> None:
    """A version cannot be both published and awaiting publication.

    The ratchet already catches a ledger row that outlived its tag, but only
    when the tag is visible. This is the same contradiction stated over two
    FILES rather than over git state, so it holds even in a tagless checkout —
    the belt to the previous test's braces.
    """
    record = json.loads(PUBLISHED.read_text(encoding="utf-8"))
    published = {r["version"] for r in record["releases"]}
    both = sorted(published & set(_ledger()))
    assert not both, (
        f"{both} appear in docs/published-versions.json AND in "
        "docs/publication-ledger.json's `unpublished`. An index cannot "
        "un-publish; remove the ledger row in the change that publishes."
    )
