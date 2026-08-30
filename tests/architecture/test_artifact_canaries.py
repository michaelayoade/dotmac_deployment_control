"""The canaries run against an INSTALLED WHEEL, and this file is why that holds.

`scripts/artifact_canaries.py` makes a claim no test in `tests/` can make: that
the BUILT ARTIFACT behaves. Its whole value rests on one thing — being executed
by an interpreter that has the wheel installed and does not have this repository
importable. Run from a source checkout it is a slower copy of `tests/unit`
wearing a stronger claim, which is precisely how `0.1.0a4` published a wheel
whose `__version__` said `0.1.0a2`.

Nothing here executes the canaries. This repository's test suite runs from
source, so a canary run from here would be the defect. What is checked instead:

* the script exists and is a standalone script rather than a pytest module;
* its first canary is the one that establishes the environment, and that canary
  actually REFUSES a source import — proven by driving the real function against
  a planted source layout;
* both workflows invoke it with a virtualenv's interpreter and never with the
  runner's;
* a failure blocks the tag, because the verdict consumes it as property 7.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CANARIES = REPO_ROOT / "scripts" / "artifact_canaries.py"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
VERIFY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "verify-release.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

_spec = importlib.util.spec_from_file_location("artifact_canaries", CANARIES)
assert _spec is not None and _spec.loader is not None
canaries = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = canaries
_spec.loader.exec_module(canaries)

_spec_v = importlib.util.spec_from_file_location(
    "verify_release_for_canaries", REPO_ROOT / "scripts" / "verify_release.py"
)
assert _spec_v is not None and _spec_v.loader is not None
verify = importlib.util.module_from_spec(_spec_v)
sys.modules[_spec_v.name] = verify
_spec_v.loader.exec_module(verify)

#: Every canary the runner must offer. A name removed from the list without
#: being removed here is a proof that quietly stopped being made.
EXPECTED_CANARIES = (
    "installed_not_source",
    "version_agreement",
    "propose_emits_canonical",
    "exact_digest_approves",
    "a4_bare_hex_still_binds",
    "encoding_fault_is_not_a_mutation",
    "mutation_after_authorization_is_refused",
)


def _source() -> str:
    return CANARIES.read_text(encoding="utf-8")


# ── the script's own shape ──────────────────────────────────────────────────


def test_it_is_a_standalone_script_and_not_a_pytest_module() -> None:
    """The environment under test contains the distribution's real dependency
    graph and nothing else. Importing pytest there would change the thing being
    proven — and would make the canaries unrunnable in exactly the environment
    a consumer has."""
    tree = ast.parse(_source())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0
    }
    assert "pytest" not in imported, sorted(imported)
    assert not any(
        node.name.startswith("test_")
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    ), "pytest would collect these from `tests/` and run them against src/"


def test_every_expected_canary_is_registered_in_the_runner() -> None:
    """A defined-but-unregistered canary is a proof nobody makes."""
    source = _source()
    for name in EXPECTED_CANARIES:
        assert f"def canary_{name}(" in source, f"canary_{name} is not defined"
        assert f'"{name}"' in source, f"canary_{name} is defined but not registered"


def test_the_runner_reports_a_failure_as_a_non_zero_exit() -> None:
    """A canary suite that always exits 0 is a step name.

    Checked structurally rather than by running it: the environment here is a
    source checkout, and the first canary is required to refuse that.
    """
    tree = ast.parse(_source())
    main = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    returns = {
        node.value.value
        for node in ast.walk(main)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, int)
    }
    assert returns == {0, 1}, returns


def test_no_canary_swallows_its_own_failure() -> None:
    """`|| true` in Python. a4's consumer proof was defeated by exactly this
    shape in shell; the same mistake in the canary runner would be invisible."""
    offenders = [
        line.strip()
        for line in _source().splitlines()
        if re.search(r"except[^:]*:\s*(pass|return\b)", line.strip())
    ]
    assert not offenders, offenders


# ── the environment canary actually refuses a source import ─────────────────


def test_the_environment_canary_refuses_a_module_outside_site_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE SENSITIVITY PROOF, and the only one that matters in this file.

    Everything else the canary script asserts is worthless if this check can be
    satisfied by a checkout. So a fake package is planted in a directory that is
    NOT an install directory, `sys.path` is pointed at it, and the REAL
    `canary_installed_not_source` is driven against it. It must refuse.
    """
    planted = tmp_path / "planted"
    (planted / canaries.IMPORT_NAME).mkdir(parents=True)
    (planted / canaries.IMPORT_NAME / "__init__.py").write_text(
        "__version__ = '0.1.0a5'\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(planted))
    monkeypatch.delitem(sys.modules, canaries.IMPORT_NAME, raising=False)

    with pytest.raises(canaries.CanaryFailure) as raised:
        canaries.canary_installed_not_source()
    # Named, not merely refused. This suite runs from an editable install, so a
    # bare "it refused" assertion would pass whether the plant was imported or
    # not — the refusal must quote the PLANTED path, which is the only evidence
    # that the detector saw the thing it was given.
    assert str(planted) in str(raised.value), raised.value
    assert "install director" in str(raised.value), raised.value


def test_the_environment_canary_names_a_real_install_directory() -> None:
    """POSITIVE CONTROL for the check above. If `_site_directories()` returned
    nothing, the refusal would fire for every input and prove nothing about
    source-versus-installed."""
    sites = canaries._site_directories()
    assert sites, "this interpreter reports no install directory"
    assert all(site.is_absolute() for site in sites), sites


# ── the workflows run it against a venv, never against the runner ───────────


def _canary_invocations(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if "artifact_canaries.py" in line and not line.lstrip().startswith("#")
    ]


@pytest.mark.parametrize(
    ("workflow", "interpreter"),
    [
        (CI_WORKFLOW, "/tmp/canary/bin/python"),
        (VERIFY_WORKFLOW, "/tmp/consumer/bin/python"),
    ],
    ids=["ci", "verify"],
)
def test_the_workflow_runs_the_canaries_with_a_virtualenv_interpreter(
    workflow: Path, interpreter: str
) -> None:
    """THE CLAUSE THE WHOLE THING TURNS ON. `python scripts/artifact_canaries.py`
    would run against the runner's interpreter, where the package is not
    installed at all — and the first canary would fail, loudly, which is the
    correct outcome but not the one anybody wants to discover during a
    release."""
    invocations = _canary_invocations(workflow.read_text(encoding="utf-8"))
    assert invocations, f"{workflow.name} does not run the canaries"
    for line in invocations:
        assert interpreter in line, (
            f"{workflow.name} runs the canaries as {line!r}, not with "
            f"{interpreter}. A canary run from a source checkout proves nothing "
            "about an artifact."
        )


def test_the_release_workflow_does_not_run_them() -> None:
    """A publishing run holding the credential, with the bytes already on disk,
    is the one party that cannot be an independent witness. The canaries run
    pre-merge in CI and post-publication in the verify run; putting them in the
    release run would be the publisher grading its own output again."""
    assert not _canary_invocations(RELEASE_WORKFLOW.read_text(encoding="utf-8"))


def test_the_ci_lane_builds_the_wheel_it_installs() -> None:
    """Installing the distribution by NAME from the index would prove something
    about the last release, not about this pull request."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    block = text[text.index("artifact-canaries:") :]
    assert "poetry build" in block
    assert "dist/*.whl" in block, (
        "the canary lane does not install the wheel it just built, so it is "
        "proving something about a previously published artifact"
    )


def test_the_expected_version_comes_from_outside_the_artifact() -> None:
    """The artifact must be compared against an EXTERNAL statement of what was
    built. Letting it report its own version and checking it against itself is
    the tautology `0.1.0a4` shipped inside."""
    assert "--expect-version" in _source()
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "tool']['poetry']['version']" in ci or 'tool"]["poetry"]["version"]' in ci
    verify_text = VERIFY_WORKFLOW.read_text(encoding="utf-8")
    assert "--expect-version" in verify_text
    assert "inputs.version" in verify_text


# ── a failing canary blocks the tag ─────────────────────────────────────────


def _observations(**overrides: object) -> dict[str, object]:
    wheel = "dotmac_deployment_control-0.1.0a5-py3-none-any.whl"
    sdist = "dotmac_deployment_control-0.1.0a5.tar.gz"
    base: dict[str, object] = {
        "version": "0.1.0a5",
        "run": {
            "id": 1,
            "path": ".github/workflows/release.yml",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": "0" * 40,
        },
        "publish_job_conclusion": "success",
        "head_sha_on_main": True,
        "pyproject_at_head": (
            '[tool.poetry]\nname = "dotmac-deployment-control"\n'
            'version = "0.1.0a5"\n'
        ),
        "built_hashes": {wheel: "a" * 64, sdist: "b" * 64},
        "fetched": {wheel: "a" * 64, sdist: "b" * 64},
        "consumer_installed": True,
        "consumer_imported": True,
        "canaries_passed": True,
        "canary_detail": "all 7 canaries passed against the installed artifact",
        "read_back_ok": True,
        "index_filenames": [wheel, sdist],
    }
    base.update(overrides)
    return base


def test_passing_canaries_are_property_seven_of_a_verified_release() -> None:
    outcome = verify.evaluate(**_observations())
    assert outcome.verdict == verify.VERIFIED, outcome.render()
    seventh = next(f for f in outcome.findings if f.prop == 7)
    assert seventh.proven
    assert len(outcome.findings) == 7


def test_a_failing_canary_makes_the_release_unprovable_and_therefore_untagged() -> None:
    """THE POINT OF WIRING IT INTO THE VERDICT. `0.1.0a4` passed all six
    identity properties and was unadoptable; the seventh is what stops that
    combination reaching a tag."""
    outcome = verify.evaluate(
        **_observations(
            canaries_passed=False,
            canary_detail="1 canary/canaries failed: a4_bare_hex_still_binds",
        )
    )
    assert outcome.verdict == verify.UNPROVABLE
    seventh = next(f for f in outcome.findings if f.prop == 7)
    assert not seventh.proven
    assert "a4_bare_hex_still_binds" in seventh.detail, (
        "the record must say WHICH property of the artifact was wrong; "
        "'the canaries failed' sends the reader back to the logs"
    )


def test_an_observation_file_that_omits_the_canaries_fails_loudly() -> None:
    """FAIL-CLOSED. A missing observation must not default to "passed" — that
    is the absent-reads-as-success shape this repository refuses everywhere
    else."""
    incomplete = _observations()
    del incomplete["canaries_passed"]
    with pytest.raises(TypeError):
        verify.evaluate(**incomplete)
