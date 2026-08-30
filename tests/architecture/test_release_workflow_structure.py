"""The release workflow's restrictions cannot be undone by an edit that passes.

Five restrictions live inside `.github/workflows/release.yml`: identity
preflight, distribution and floor, exact protected-main SHA, immutable conflict
refusal, and a publisher-authenticated read-back before tagging. Every one of
them is removable by a single line, and every removal leaves a workflow that
still runs and still goes green.

So this is the sixth layer, and it is the only one that watches the other five.

## Why an indentation parse and not a YAML parse

There is no YAML parser in this repository's dependency set, and adding one to
inspect a single file would be a lockfile change for very little. The parser
below splits on job keys at two-space indentation, which is reliable for a
GitHub workflow and — more to the point — is exercised by the planted mutations
rather than trusted. A parser nobody has seen reject anything is not a parser.
Its limitation is stated rather than hidden: it reasons about text within a
block, so a restriction expressed through an anchor, a reusable workflow or a
composite action would be invisible to it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

PUBLISH_TOKEN = "FORGEJO_PUBLISH_TOKEN"
READ_TOKEN = "FORGEJO_READ_TOKEN"
PROTECTED_ENVIRONMENT = "registry-release"
PREFLIGHT = "preflight"

_JOB = re.compile(r"^  ([a-z][a-z0-9-]*):\s*$")


def split_jobs(text: str) -> dict[str, str]:
    """Job name -> its block, by two-space indentation."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.rstrip() == "jobs:")
    except StopIteration:  # pragma: no cover - a workflow with no jobs
        return {}
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[start + 1 :]:
        match = _JOB.match(line)
        if match:
            current = match.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return {name: "\n".join(body) for name, body in jobs.items()}


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _jobs() -> dict[str, str]:
    return split_jobs(_text())


# ── the parser itself, before anything relies on it ─────────────────────────


def test_the_parser_finds_the_jobs_that_exist() -> None:
    names = set(_jobs())
    assert {PREFLIGHT, "guard", "build", "publish", "verify"} <= names, names


def test_the_parser_separates_blocks_rather_than_returning_the_file() -> None:
    """SENSITIVITY on the parser. If every job's 'block' were the whole file,
    every containment assertion below would pass for the wrong reason — the most
    dangerous way this file could be wrong."""
    jobs = _jobs()
    assert "publisher identity" in jobs[PREFLIGHT]
    assert "publisher identity" not in jobs["build"]
    assert "twine upload" in jobs["publish"]
    assert "twine upload" not in jobs[PREFLIGHT]


# ── restriction 6: the preflight cannot be skipped ──────────────────────────


def job_keys(block: str) -> list[str]:
    """Keys declared directly on a job, at four-space indentation.

    Line-based rather than a substring search for "\\n    if:". `split_jobs`
    strips the job's own key line, so a condition placed as the block's FIRST
    line has no preceding newline and a substring check misses it — which is
    exactly where someone disabling a job would put it. The planted mutation
    below found this; the first version of this guard had the hole.
    """
    return [
        line.strip().split(":", 1)[0]
        for line in block.splitlines()
        if line.startswith("    ") and not line.startswith("     ") and ":" in line
    ]


def test_the_preflight_carries_no_condition() -> None:
    keys = job_keys(_jobs()[PREFLIGHT])
    for forbidden in ("if", "continue-on-error"):
        assert forbidden not in keys, (
            f"the preflight declares `{forbidden}:` — a skipped job is not a "
            "failed job, and this one exists to be unskippable"
        )


@pytest.mark.parametrize("job", ["guard", "build", "publish", "verify"])
def test_every_other_job_needs_the_preflight(job: str) -> None:
    assert PREFLIGHT in _jobs()[job], (
        f"{job} does not need the preflight, so it can run without the "
        "publisher's identity ever being established"
    )


def test_no_job_is_conditioned_on_a_secret_expression() -> None:
    """`if: secrets.X != ''` turns an absent credential into a green skip."""
    for name, block in _jobs().items():
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith("if:") and "secrets." in stripped:
                pytest.fail(f"{name} is conditioned on a secret: {stripped}")


# ── restrictions 1-5 ────────────────────────────────────────────────────────


def test_the_guard_runs_before_any_build() -> None:
    jobs = _jobs()
    assert "release_guard.py" in jobs["guard"]
    assert "poetry build" not in jobs["guard"]
    assert "guard" in jobs["build"], "build must not run before the guard"


def test_the_floor_and_distribution_are_re_checked_on_the_publish_side() -> None:
    """Defence in depth: a tampered guard output must not smuggle a target past."""
    assert "release_guard.py" in _jobs()["publish"]


@pytest.mark.parametrize("job", ["guard", "publish"])
def test_the_current_main_assertion_runs_in_both_places(job: str) -> None:
    """Once at dispatch, once at the irreversible boundary — a publish job can
    start after main moves."""
    assert "assert_current_main.sh" in _jobs()[job]


def test_the_index_is_checked_for_an_existing_version_before_building() -> None:
    assert "already on the index" in _jobs()["guard"]


def executable_lines(text: str) -> list[str]:
    """Lines that are not YAML comments.

    The predicate is "the upload COMMAND uses this flag", not "the file mentions
    it" — and the file mentions it deliberately, in the comment explaining why
    it is absent. A probe that cannot tell prose from a command is a probe that
    reports on itself: this guard failed on its own rationale the first time it
    ran, which is the same wrong-shaped-predicate mistake as grepping for
    "mentions packages" when the claim was "enumerates packages".
    """
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def test_the_upload_never_skips_an_existing_version() -> None:
    """`--skip-existing` converts a conflicting upload into a silent success."""
    assert not [
        line for line in executable_lines(_text()) if "--skip-existing" in line
    ], (
        "twine --skip-existing makes a re-upload succeed without publishing, "
        "which is the absent-reads-as-success shape this repository refuses"
    )


def test_the_read_back_happens_before_the_tag() -> None:
    block = _jobs()["verify"]
    read_back = block.index("publisher read-back")
    tag = block.index("git tag -a")
    assert read_back < tag, "the tag must not be written before the read-back"


# ── credential handling ─────────────────────────────────────────────────────


def test_the_publish_credential_never_appears_in_a_url() -> None:
    """A URL carrying `user:token@host` leaks the moment anything echoes the
    command — `set -x`, a curl error, a pip resolver diagnostic. Passing it
    through `.netrc` makes acceptance 7 a property of the mechanism rather than
    of remembering not to print it."""
    for line in _text().splitlines():
        if PUBLISH_TOKEN in line and "://" in line:
            pytest.fail(f"the publish token is interpolated into a URL: {line.strip()}")
    assert ".netrc" in _text()


def test_the_protected_environment_gates_every_credential_use() -> None:
    jobs = _jobs()
    for name, block in jobs.items():
        if PUBLISH_TOKEN in block:
            assert f"environment: {PROTECTED_ENVIRONMENT}" in block, (
                f"{name} uses the publish credential without declaring the "
                f"{PROTECTED_ENVIRONMENT} environment, which is what restricts it "
                "to a protected branch"
            )


def test_the_consumer_proof_does_not_use_the_publisher() -> None:
    """A clean install performed with the PUBLISHING credential proves the
    publisher can read its own upload — not that an ordinary consumer can
    retrieve it, which is the claim acceptance 6 makes."""
    block = _jobs()["verify"]
    consumer = block[block.index("An ordinary consumer can install it") :]
    assert READ_TOKEN in consumer
    assert PUBLISH_TOKEN not in consumer, (
        "the consumer proof reaches for the publishing credential; it must use "
        "ci-reader, or it is not a consumer proof"
    )


# ── the mutations: each removal must be caught ──────────────────────────────


def _mutate(text: str, old: str, new: str) -> str:
    assert text.count(old) >= 1, f"planted mutation did not apply: {old!r}"
    return text.replace(old, new, 1)


def test_a_conditioned_preflight_is_caught() -> None:
    mutated = _mutate(
        _text(),
        "  preflight:\n    name: publisher identity\n",
        "  preflight:\n    if: ${{ secrets.TOKEN != '' }}\n"
        "    name: publisher identity\n",
    )
    block = split_jobs(mutated)[PREFLIGHT]
    assert "if" in job_keys(block), "an `if:` as the block's first line was missed"
    conditioned = [
        line.strip()
        for line in block.splitlines()
        if line.strip().startswith("if:") and "secrets." in line
    ]
    assert conditioned, "a secret-conditioned preflight was not detected"


def test_a_job_that_drops_the_preflight_dependency_is_caught() -> None:
    mutated = _mutate(
        _text(), "    needs: [preflight, guard, build]\n", "    needs: [guard, build]\n"
    )
    assert PREFLIGHT not in split_jobs(mutated)["publish"]


def test_skip_existing_is_caught() -> None:
    """Planted into the COMMAND, so it exercises the comment-stripping too."""
    # Anchored on the COMMAND, not on the flag name — the workflow's comment
    # mentions `--non-interactive` too, and planting there would only prove that
    # comment-stripping works. It does; this must prove the command check does.
    mutated = _mutate(
        _text(),
        "python -m twine upload --non-interactive",
        "python -m twine upload --non-interactive --skip-existing",
    )
    offenders = [
        line for line in executable_lines(mutated) if "--skip-existing" in line
    ]
    assert offenders, "a --skip-existing on the upload command was not detected"


def test_a_credential_in_a_url_is_caught() -> None:
    mutated = _mutate(
        _text(),
        "python -m twine upload --non-interactive \\",
        'curl "https://x:${FORGEJO_PUBLISH_TOKEN}@registry.dotmac.io/" \\',
    )
    offenders = [
        line.strip()
        for line in mutated.splitlines()
        if PUBLISH_TOKEN in line and "://" in line
    ]
    assert offenders, "a credential interpolated into a URL was not detected"


def test_a_consumer_proof_using_the_publisher_is_caught() -> None:
    """Swap the reader for the publisher inside the consumer step only."""
    text = _text()
    marker = "An ordinary consumer can install it"
    head, tail = text[: text.index(marker)], text[text.index(marker) :]
    mutated = head + tail.replace(READ_TOKEN, PUBLISH_TOKEN, 1)
    block = split_jobs(mutated)["verify"]
    consumer = block[block.index(marker) :]
    assert PUBLISH_TOKEN in consumer, "the swapped credential was not detected"


# ── the publish path may not rely on a credential file, and uploads nowhere else
#
# Michael's two additions after the a3 incident. Scoped deliberately: the
# CONSUMER download's `.netrc` is legitimate — pip still reads one and the only
# alternative there is credentials in a URL — so the refusal is per-STEP, not
# per-file.

VERIFY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "verify-release.yml"

_STEP = re.compile(r"^      - (?:name|uses):")


def split_steps(block: str) -> list[str]:
    """A job block -> its steps, by six-space `- name:`/`- uses:`."""
    steps: list[str] = []
    current: list[str] = []
    for line in block.splitlines():
        if _STEP.match(line):
            if current:
                steps.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        steps.append("\n".join(current))
    return steps


def test_no_step_uses_the_publish_credential_with_a_credential_file() -> None:
    """The interface moved once under a `.netrc`. A step that both holds the
    publish credential and writes a credential file is relying on a mechanism
    that has already been removed from one of these tools."""
    for name, block in _jobs().items():
        for step in split_steps(block):
            # Comment-blind, like every other check here. This file has now
            # tripped its own guards FOUR times by explaining a forbidden thing
            # in prose beside the code that forbids it. The prose is worth
            # keeping — an unexplained guard is worse — so the checks read
            # executable lines and the rule is uniform rather than per-case.
            code = "\n".join(executable_lines(step))
            if PUBLISH_TOKEN in code and ".netrc" in code:
                pytest.fail(
                    f"{name}: a step uses the publish credential through a "
                    f".netrc:\n{code[:300]}"
                )


def step_named(block: str, fragment: str) -> str | None:
    """The step whose NAME contains `fragment`.

    Matching the whole step's text was wrong and picked the wrong step: the
    phrase "ordinary consumer" appears three times in this workflow — in the
    step name, in the comment ABOVE the preceding step, and inside the tag
    message. The comment attaches to the previous step, so a text match selected
    the read-back step and then asserted things about it that happened to be
    false in a confusing way. The predicate is the step's identity, not a phrase
    occurring anywhere inside it.
    """
    for step in split_steps(block):
        first = step.splitlines()[0]
        if fragment in first:
            return step
    return None


def test_the_consumer_download_may_still_use_one() -> None:
    """POSITIVE CONTROL for the scoping. If the check above were per-file rather
    than per-step it would forbid the consumer's legitimate use, and someone
    would 'fix' it by putting credentials in a URL."""
    consumer = step_named(_jobs()["verify"], "An ordinary consumer can install")
    assert consumer is not None
    assert ".netrc" in consumer
    assert READ_TOKEN in consumer
    assert PUBLISH_TOKEN not in consumer


def test_a_netrc_added_to_the_publish_step_is_caught() -> None:
    """PLANTED VIOLATION."""
    mutated = _mutate(
        _text(),
        "          python -m pip install --quiet 'twine==6.1.0'",
        "          printf 'machine x' > \"${HOME}/.netrc\"\n"
        "          python -m pip install --quiet 'twine==6.1.0'",
    )
    offending = [
        step
        for block in split_jobs(mutated).values()
        for step in split_steps(block)
        if PUBLISH_TOKEN in step and ".netrc" in step
    ]
    assert offending, "a .netrc in the publish step was not detected"


def test_twine_is_pinned() -> None:
    """An unpinned install is how the credential interface moved under this
    workflow between two runs on the same day."""
    installs = [
        line.strip()
        for line in executable_lines(_text())
        if "pip install" in line and "twine" in line
    ]
    assert installs, "no twine install found"
    for line in installs:
        assert re.search(r"twine==\d+\.\d+", line), f"twine is not pinned: {line}"


def test_an_unpinned_twine_is_caught() -> None:
    mutated = _mutate(_text(), "'twine==6.1.0'", "twine")
    installs = [
        line
        for line in executable_lines(mutated)
        if "pip install" in line and "twine" in line
    ]
    assert installs and not re.search(r"twine==", installs[0])


# ── the verify path publishes nothing, structurally ─────────────────────────


def test_the_verify_workflow_uploads_nothing() -> None:
    """Property 5 held by construction rather than promised. The verify path
    exists because a publish already happened; it must not be able to cause a
    second one."""
    code = "\n".join(
        executable_lines(VERIFY_WORKFLOW.read_text(encoding="utf-8"))
    ).lower()
    for forbidden in ("twine", "poetry build", "upload"):
        assert forbidden not in code, (
            f"the verify workflow mentions {forbidden!r}; it must be incapable "
            "of publishing"
        )


def test_the_verify_workflow_tags_only_after_the_decision() -> None:
    text = VERIFY_WORKFLOW.read_text(encoding="utf-8")
    assert text.index("verify_release.py") < text.index("git tag -a"), (
        "the tag must not be written before the verdict; an UNPROVABLE outcome "
        "exits non-zero and must take the tag step with it"
    )
