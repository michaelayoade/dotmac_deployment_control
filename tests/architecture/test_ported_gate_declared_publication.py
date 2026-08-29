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
