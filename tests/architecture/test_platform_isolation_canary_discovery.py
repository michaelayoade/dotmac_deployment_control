"""The PostgreSQL canary runner discovers files; it does not remember them.

The defect this guards against: `ci.yml`'s PostgreSQL job named exactly one
`tests/test_*_platform_isolation.py` file for months, so
`tests/test_attestation_trust_registry_platform_isolation.py` was never
executed by CI from the day it was written -- a whole suite of required
PostgreSQL proofs was dead code, and nothing went red, because nothing looked.

`scripts/run_platform_isolation_canaries.py` replaces the maintained filename
with a glob. A glob-based mechanism is only as good as the proof that it
actually discovers what it claims to: this file plants a synthetic file
matching the pattern and shows it is found (the positive control), a
near-miss file that does NOT match and shows it is correctly excluded (so
the glob is not accidentally wide), and the two-directional guard against
`ci.yml` itself drifting back toward a hardcoded filename.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RUNNER_PATH = REPO_ROOT / "scripts" / "run_platform_isolation_canaries.py"

_spec = importlib.util.spec_from_file_location(
    "run_platform_isolation_canaries", RUNNER_PATH
)
assert _spec is not None and _spec.loader is not None
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)


# ── the mechanism itself, proven with a plant and a near-miss ──────────────


def test_the_real_tests_directory_is_never_discovered_as_empty() -> None:
    """NON-VACUITY. If this ever returns nothing, every test below -- and the
    real CI job -- would be proving something about a set with nothing in it."""
    discovered = runner.discover_platform_isolation_tests(REPO_ROOT / "tests")
    assert discovered, "discovery must never find zero real canary files"


def test_the_real_tests_directory_contains_both_known_canaries() -> None:
    names = {path.name for path in runner.discover_platform_isolation_tests()}
    assert "test_deployment_control_platform_isolation.py" in names
    assert "test_attestation_trust_registry_platform_isolation.py" in names


def test_a_planted_file_is_discovered(tmp_path: Path) -> None:
    """THE sensitivity proof: a brand-new file matching the pattern, planted
    after the runner was written, must still be found. Without this plant,
    the discovery mechanism is itself unverified -- which is exactly how the
    single-filename job passed for months while orphaning a whole suite."""
    planted = tmp_path / "test_brand_new_thing_platform_isolation.py"
    planted.write_text("# planted by the sensitivity test\n")

    discovered = runner.discover_platform_isolation_tests(tmp_path)

    assert planted in discovered


def test_a_file_that_does_not_match_the_pattern_is_not_discovered(
    tmp_path: Path,
) -> None:
    """THE near-miss: a file that looks related but does not match the exact
    glob must be excluded, or the glob is wider than it claims to be."""
    near_miss = tmp_path / "test_platform_isolation_helpers.py"
    near_miss.write_text("# not a canary file itself\n")
    unrelated = tmp_path / "test_something_else.py"
    unrelated.write_text("# unrelated entirely\n")

    discovered = runner.discover_platform_isolation_tests(tmp_path)

    assert near_miss not in discovered
    assert unrelated not in discovered


def test_an_empty_directory_is_refused_by_main_not_passed_quietly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A discovery step that finds nothing must fail, not pass quietly."""
    monkeypatch.setattr(runner, "TESTS_DIR", tmp_path)
    with pytest.raises(runner.NoPlatformIsolationCanariesDiscoveredError):
        runner.main([])


def test_the_database_coordinate_is_required_not_skipped() -> None:
    """A missing database coordinate must be a hard failure from this runner,
    independent of whatever the discovered pytest files themselves do."""
    with pytest.raises(runner.DatabaseCoordinateMissingError):
        runner.require_database_url(env={})


def test_either_database_env_var_satisfies_the_requirement() -> None:
    for name in runner.DATABASE_URL_ENV_VARS:
        runner.require_database_url(env={name: "postgresql://x"})


# ── the two-directional guard against `ci.yml` drifting back ───────────────


def test_the_workflow_invokes_the_discovering_runner() -> None:
    """`ci.yml` must call the runner, not reimplement discovery inline."""
    text = CI_WORKFLOW.read_text()
    assert "run_platform_isolation_canaries.py" in text


def test_the_workflow_does_not_hardcode_a_canary_filename_as_a_pytest_argument() -> (
    None
):
    """The exact regression this file exists to prevent: naming one canary
    file as a `pytest` argument silently re-arms the single-filename trap for
    the NEXT canary, even if today's two files are both listed."""
    text = CI_WORKFLOW.read_text()
    assert not re.search(r"pytest\s+tests/test_\S*platform_isolation\.py", text)


def test_every_discovered_file_would_be_reached_by_the_workflows_runner_call() -> None:
    """The first half of the two-directional guard: nothing discovered on disk
    is left unreached by what `ci.yml` actually runs. Since the workflow
    invokes the discovering runner (proven above) rather than a fixed list,
    this holds by construction as long as the invocation itself is real --
    checked here by confirming the runner file it names actually exists and
    is the same one this test loaded its discovery function from."""
    text = CI_WORKFLOW.read_text()
    assert "scripts/run_platform_isolation_canaries.py" in text
    assert RUNNER_PATH.is_file()


def test_the_workflow_names_no_platform_isolation_file_that_does_not_exist() -> None:
    """The second half of the two-directional guard: any
    `test_*_platform_isolation.py` filename mentioned literally in the
    workflow (e.g. in a comment) must correspond to a real file, so a stale
    reference cannot silently drift from what is actually on disk."""
    text = CI_WORKFLOW.read_text()
    referenced = set(re.findall(r"tests/(test_\S*platform_isolation\.py)", text))
    on_disk = {path.name for path in runner.discover_platform_isolation_tests()}
    missing = referenced - on_disk
    assert not missing, f"ci.yml references nonexistent canary files: {missing}"
