"""A run that writes a TAG must open the RECORD, and may write nothing else.

Ported from `dotmac_starter_mt`'s `tests/architecture/test_every_release_tags_a
_record.py`, trimmed to this repository's single tagging workflow.

## What it is for

The tag makes `docs/publication-ledger.json`'s row false the INSTANT it lands,
and `test_the_ledger_and_the_published_record_never_claim_the_same_version`
states that contradiction over the two FILES — so it fires on main state even in
a tagless checkout. From the tag until the record, main is red and every open
pull request inherits it while looking like its own branch is broken.

That has happened twice here. `0.1.0a4`'s ledger row outlived its own
publication by six hours and nothing noticed, because CI could not see tags at
all. `0.1.0a7`'s absence turned main red for every pull request, including an
empty one.

Everything the record needed was already computed. The verify run ended by
printing `::notice::OWED…` — a notice nothing reads. This file is what keeps the
replacement from being quietly removed.

## The three properties, and why each is separate

1. **Every tag writer opens a record**, positioned AFTER the tag, with
   `if: always()`. The tag is pushed before this step, so a later failure must
   never leave a tag with no record.
2. **The recorder's authority is exactly branch and pull request.** The App
   token action declares `permission-contents: write` and
   `permission-pull-requests: write` and nothing else; an extra `permission-*`
   key is a widened blast radius wearing a one-line diff.
3. **The record is coordinates only.** The writer opens two paths and the
   opener re-checks the actual diff against the same two. A recorder that
   wrote a disposition, a release note or a floor literal would be a bot
   editing the constraints that bind it.

Discovery is by SEARCH rather than by a filename list, so a second tagging
workflow cannot be added without also being covered.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
ACTION = REPO_ROOT / ".github" / "actions" / "release-recorder-token" / "action.yml"
OPENER = REPO_ROOT / "scripts" / "open_release_record_pr.sh"
WRITER = REPO_ROOT / "scripts" / "write_release_record.py"

#: This repository's tag writer. `tag_once.py` rather than `git tag`, because
#: `test_the_verify_workflow_never_writes_a_raw_git_tag` already forbids the
#: raw command — so the thing to search for is the one form a tag can take.
TAG_WRITER = "tag_once.py"

RECORD_SCRIPT = "scripts/open_release_record_pr.sh"
RECORDER_TOKEN_ACTION = "./.github/actions/release-recorder-token"
PINNED_TOKEN_ACTION = (
    "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
)
PINNED_CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"

#: The only paths a release record may touch. Held here as well as in the two
#: scripts, because a guard that reads its expectation out of the thing it is
#: guarding is not a guard.
ALLOWED_PATHS = (
    "docs/publication-ledger.json",
    "docs/published-versions.json",
)


def _workflows() -> list[Path]:
    return sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")))


def _tagging_workflows() -> list[Path]:
    return [p for p in _workflows() if TAG_WRITER in p.read_text(encoding="utf-8")]


# ── the search itself, before anything relies on it ─────────────────────────


def test_the_search_finds_the_tag_writer_that_exists() -> None:
    """SENSITIVITY. A discovery that found nothing would make every assertion
    below pass over an empty set — the exact vacuity this repository keeps
    finding in other people's guards."""
    found = [p.name for p in _tagging_workflows()]
    assert found == ["verify-release.yml"], found


# ── 1: a tag writer opens a record, after the tag, even on failure ──────────


@pytest.mark.parametrize("workflow", _tagging_workflows(), ids=lambda p: p.name)
def test_a_tag_writer_opens_the_record_after_tagging(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    assert RECORD_SCRIPT in text, (
        f"{workflow.name} writes a tag and never opens the record. The tag "
        "falsifies the publication ledger the instant it lands; a notice "
        "saying so is what failed twice."
    )
    assert text.index(TAG_WRITER) < text.index(RECORD_SCRIPT), (
        "the record is opened before the tag is written, so a version could "
        "be recorded that was never tagged"
    )
    assert RECORDER_TOKEN_ACTION in text
    assert text.index(RECORDER_TOKEN_ACTION) < text.index(
        RECORD_SCRIPT
    ), "the recorder token is minted after the record step that needs it"


@pytest.mark.parametrize("workflow", _tagging_workflows(), ids=lambda p: p.name)
def test_the_record_steps_run_even_when_something_later_fails(
    workflow: Path,
) -> None:
    """`if: always()` on BOTH. The tag is already pushed by the time these run,
    so a failure between them and the end of the job must not be able to leave
    a tag with no record — which is the precise state this exists to prevent."""
    text = workflow.read_text(encoding="utf-8")
    for anchor in (RECORDER_TOKEN_ACTION, RECORD_SCRIPT):
        head = text.rindex("- name:", 0, text.index(anchor))
        step = text[head : text.index(anchor)]
        assert "if: always()" in step, (
            f"the step reaching {anchor} in {workflow.name} is not "
            "`if: always()`; a later failure would leave a tag with no record"
        )


@pytest.mark.parametrize("workflow", _tagging_workflows(), ids=lambda p: p.name)
def test_the_record_prefers_the_app_and_falls_back_loudly(
    workflow: Path,
) -> None:
    """Both halves in `GH_TOKEN`. The App is the intended identity; the
    fallback exists so a missing App produces a pushed branch and a RED run at
    `gh pr create`, never a green run with no record."""
    text = workflow.read_text(encoding="utf-8")
    head = text.rindex("- name:", 0, text.index(RECORD_SCRIPT))
    step = text[head : text.index(RECORD_SCRIPT)]
    assert "steps.recorder-token.outputs.token" in step
    assert "secrets.GITHUB_TOKEN" in step


# ── 2: the recorder's authority is exactly branch and pull request ──────────


def test_the_recorder_app_token_has_only_branch_and_pull_request_authority() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert PINNED_TOKEN_ACTION in text, "the token action is unpinned or moved"
    assert PINNED_CHECKOUT_ACTION in text, "the rebinding checkout is unpinned"

    declared = sorted(re.findall(r"^\s*(permission-[a-z-]+):", text, re.M))
    assert declared == ["permission-contents", "permission-pull-requests"], (
        f"the recorder App token declares {declared}. Anything beyond contents "
        "and pull requests widens a credential that exists to write two JSON "
        "files."
    )
    assert "permission-contents: write" in text
    assert "permission-pull-requests: write" in text


def test_the_recorder_rebinds_git_to_its_own_identity() -> None:
    """`actions/checkout` leaves the ORIGINAL token in the local repository, so
    exporting the App token for `gh` alone would still push the record branch as
    the publisher. The second checkout is what makes one identity own both."""
    text = ACTION.read_text(encoding="utf-8")
    assert "token: ${{ steps.token.outputs.token || github.token }}" in text
    assert "persist-credentials: true" in text


def test_the_tagging_workflow_is_not_granted_pull_request_authority() -> None:
    """The separation the App exists to hold. If the workflow's own token could
    open pull requests, the tag writer and the record author would be one
    identity and the App would be decoration."""
    text = (WORKFLOWS / "verify-release.yml").read_text(encoding="utf-8")
    granted = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("pull-requests:")
    ]
    assert not granted, granted


# ── 3: the record is coordinates only ──────────────────────────────────────


def test_the_writer_can_open_only_the_two_record_files() -> None:
    """Stated over the writer's declared surface AND its actual constants, so a
    new path cannot be added to one without the other."""
    text = WRITER.read_text(encoding="utf-8")
    declared = re.search(r"WRITABLE = \(([^)]*)\)", text)
    assert declared is not None
    assert sorted(re.findall(r'"([^"]+)"', declared.group(1))) == sorted(ALLOWED_PATHS)
    written = set(re.findall(r'REPO_ROOT / "docs" / "([a-z-]+\.json)"', text))
    assert written == {p.split("/")[-1] for p in ALLOWED_PATHS}, written


def test_the_opener_refuses_a_diff_outside_those_two_files() -> None:
    """The check that matters, because the writer's own list is a property of
    code somebody may edit and this one is a property of the run."""
    text = OPENER.read_text(encoding="utf-8")
    allowed = re.search(r'^ALLOWED="([^"]*)"', text, re.M)
    assert allowed is not None, "the opener declares no allowlist"
    assert sorted(allowed.group(1).split()) == sorted(ALLOWED_PATHS)
    assert "git diff --name-only" in text
    assert text.index("git diff --name-only") < text.index("git add -A"), (
        "the coordinates-only check runs after staging, so a stray path would "
        "already be in the commit"
    )


def test_the_recorder_writes_nothing_but_the_two_record_files() -> None:
    """WRITES, not mentions, and the distinction is deliberate.

    The writer READS `pyproject.toml` at the tag to derive the declared kernel
    floor — a coordinate, taken from the published tree rather than from the
    working one. Forbidding the mere substring would forbid that read and would
    push a real machine-owned field out of the record for no gain.

    What must never happen is a WRITE outside the two record files, so that is
    what is asserted: every `write_text` in the writer targets `LEDGER` or
    `PUBLISHED`, and neither script writes a test, a floor literal or the
    project file.
    """
    writer = WRITER.read_text(encoding="utf-8")
    targets = re.findall(r"^\s*([A-Z_]+)\.write_text\(", writer, re.M)
    assert targets, "the writer writes nothing at all"
    assert set(targets) == {"LEDGER", "PUBLISHED"}, targets

    for path in (WRITER, OPENER):
        code = "\n".join(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        for forbidden in ("tests/architecture", "test_published_versions"):
            assert forbidden not in code, (
                f"{path.name} reaches {forbidden!r} outside a comment. The "
                "release floor's guard holds its own positive control, refusal "
                "strings and parametrize lists as literals; a bot writing "
                "those is a bot editing the constraint that binds it."
            )


# ── the failure discipline the mechanism was rebuilt around ────────────────


def test_an_unopened_record_fails_the_run_rather_than_warning() -> None:
    """The Starter's earlier version exited 0 with a `::warning::`, which put
    correctness back on somebody READING a warning in a green run. A green run
    with no record is indistinguishable, at a glance, from a green run with
    one."""
    text = OPENER.read_text(encoding="utf-8")
    give_up = text[
        text.index("give_up() {") : text.index("\n}", text.index("give_up() {"))
    ]
    assert "exit 1" in give_up
    assert "exit 0" not in give_up
    assert "DO NOT RE-RUN THE PUBLISH" in give_up
    assert "${MANUAL}" in give_up and "${COMPARE_URL}" in give_up

    # COMMENT-BLIND, like every other check of its kind in this repository.
    # The script EXPLAINS why a `::warning::` was the wrong answer, in prose,
    # directly above the code that refuses to emit one — and a probe that
    # cannot tell prose from a command reports on itself. This guard tripped on
    # exactly that on its first run.
    code = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "::warning::" not in code, (
        "the record opener emits a ::warning::. A green run with no record is "
        "indistinguishable, at a glance, from a green run with one."
    )


def test_the_only_successful_exit_is_a_record_opened_or_already_complete() -> None:
    exits = set(re.findall(r"^\s*exit (\d+)", OPENER.read_text(encoding="utf-8"), re.M))
    assert exits <= {"0", "1", "2"}, exits
    assert OPENER.read_text(encoding="utf-8").count("exit 0") == 1


def test_the_record_auto_merges_only_after_protected_ci_is_green() -> None:
    """`--auto` waits for branch protection. The App can enable auto-merge and
    cannot waive a check, which is what keeps required CI the merge authority."""
    text = OPENER.read_text(encoding="utf-8")
    assert 'gh pr merge "${BRANCH}" --auto --squash' in text
    assert text.index("gh pr create") < text.index("gh pr merge")
