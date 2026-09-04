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
import json
import re
import sys
from pathlib import Path
from typing import Any

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
    # 0.1.0a6's surviving floor proof answers a defect the seven above cannot
    # see: an
    # artifact whose bytes are perfect and whose DECLARED DEPENDENCY FLOOR is
    # 21 alphas too low.
    "declared_kernel_floor",
    # The two that close a7's gap: its headline was a database catalogue and
    # its canary set was a6's exact nine, so no canary drove the thing the
    # release existed to ship.
    "database_catalogue_as_published",
    "catalogue_digest_binds",
    # a9's portable authorization must be driven from the installed wheel,
    # including its canonical image-set and descriptor signature binding.
    "portable_authorization_binds",
    # a10: the target result is a signed document with a distinct key purpose,
    # verified against the standing authorization before state can change.
    # a11: the outbound concrete attempt is likewise signed under its own
    # purpose; attempt_no is no longer an unsigned sibling of authorization,
    # and a renamed adapter around the authorization key is refused too.
    "signed_dispatch_binds_attempt",
    "signed_execution_observation_binds",
    # The browser surface ships templates as package data, and the kernel
    # validates that directory when it builds the surface graph — at the
    # CONSUMER's startup. A wheel missing it imports perfectly and composes
    # nowhere, which no source-tree check can observe. Labelled by what it
    # proves and NOT by a version: this was written as "0.1.0a7" while a7 was
    # pending, and a7 shipped without it.
    "web_surface_ships_its_templates",
    # Shipping the FILES is not shipping the CONTRACT. Package data is the only
    # part of this distribution with no `__version__` of its own, so a wheel
    # carrying an older `_macros.html` composes, imports, passes every canary
    # above, and renders one answer where the module computed three. This one
    # executes the shipped macros from a working directory that is not a
    # checkout -- the production case -- and requires each state to render
    # distinctly.
    "web_surface_templates_render_their_states",
)

#: Every virtualenv `ci.yml` may run the canaries with, and what each proves.
#: The point of the list is that it is a list: through `0.1.0a5` there was one
#: environment, it resolved `dotmac-kernel` freely, and "whatever the index
#: happens to offer" was the only kernel any canary ever met.
CI_CANARY_INTERPRETERS = {
    "/tmp/canary/bin/python": "the resolver's choice, which is what a consumer gets",
    "/tmp/floor/bin/python": "EXACTLY the declared minimum kernel",
    "/tmp/below-floor/bin/python": "the newest kernel the floor excludes — must FAIL",
    "/tmp/mutated-table/bin/python": "a catalogue publishing a table nobody "
    "declared — must FAIL",
    "/tmp/mutated-column/bin/python": "a catalogue whose plan_digest is the "
    "dc_0001 width — must FAIL",
}


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
    ("workflow", "interpreters"),
    [
        (CI_WORKFLOW, frozenset(CI_CANARY_INTERPRETERS)),
        (VERIFY_WORKFLOW, frozenset({"/tmp/consumer/bin/python"})),
    ],
    ids=["ci", "verify"],
)
def test_the_workflow_runs_the_canaries_with_a_virtualenv_interpreter(
    workflow: Path, interpreters: frozenset[str]
) -> None:
    """THE CLAUSE THE WHOLE THING TURNS ON. `python scripts/artifact_canaries.py`
    would run against the runner's interpreter, where the package is not
    installed at all — and the first canary would fail, loudly, which is the
    correct outcome but not the one anybody wants to discover during a
    release.

    An ALLOWED SET rather than one name, as of `0.1.0a6`: CI now runs the same
    script in three environments that differ only in which kernel is installed.
    The set is closed, so a fourth environment is a deliberate edit here rather
    than a lane nobody declared.
    """
    invocations = _canary_invocations(workflow.read_text(encoding="utf-8"))
    assert invocations, f"{workflow.name} does not run the canaries"
    for line in invocations:
        assert any(interpreter in line for interpreter in interpreters), (
            f"{workflow.name} runs the canaries as {line!r}, with none of "
            f"{sorted(interpreters)}. A canary run from a source checkout "
            "proves nothing about an artifact."
        )


def test_every_declared_ci_interpreter_is_actually_used() -> None:
    """The other direction. A declared lane that no step runs is a claim about
    coverage with nothing behind it, which is the shape this repository refuses
    everywhere else."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    invocations = "\n".join(_canary_invocations(text))
    unused = sorted(i for i in CI_CANARY_INTERPRETERS if i not in invocations)
    assert not unused, f"declared but never run: {unused}"


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


# ── the declared kernel floor is falsifiable, in both directions ────────────


def _canary_job() -> str:
    """The `artifact-canaries` job block, which is the required merge context."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    start = text.index("  artifact-canaries:")
    end = text.index("\n  postgres:", start)
    return text[start:end]


def test_the_floor_lane_installs_the_declared_minimum_and_pins_it() -> None:
    """THE PROOF `0.1.0a5` DID NOT HAVE.

    a5's artifact was byte-perfect, independently verified on seven properties,
    and unusable: it imports `dotmac_kernel.transactions`, first shipped in
    kernel `a98`, while declaring `>=0.1.0a77`. Every check the repository owned
    was satisfied, because every one of them ran in an environment where a
    compatible kernel happened to be present.

    The repair is not another hash. It is a lane that installs the DECLARED
    MINIMUM literally — `dotmac-kernel==${FLOOR}` beside the wheel — and hands
    the canaries `--expect-kernel`, so an environment holding anything else is
    refused rather than accepted as close enough.
    """
    job = _canary_job()
    assert "dotmac-kernel==${FLOOR}" in job, (
        "the floor lane does not pin the kernel to the declared floor, so it "
        "runs against whatever the resolver chose — which is the environment "
        "0.1.0a5's 21-alpha under-constraint was invisible in"
    )
    assert "kernel_floor.py declared" in job, (
        "the floor must be read from the declaration rather than written as a "
        "literal in the workflow; a second literal is a second authority"
    )
    assert "--expect-kernel" in job, (
        "the canaries are not told which kernel the lane pinned, so they cannot "
        "refuse an environment that quietly resolved a newer one"
    )


def test_the_mutation_proves_the_excluded_kernel_cannot_satisfy_the_canaries() -> None:
    """WITHOUT THIS THE FLOOR LANE PASSES FOR THE WRONG REASON.

    A canary nobody has seen refuse is not a canary (ADR-0018). The mutation
    installs the newest kernel the declared floor EXCLUDES and requires the same
    script to fail — which also catches a floor set too HIGH, because a version
    below a needlessly-high floor would run everything perfectly well.

    Both halves are required and they fail independently: the resolver refusing
    the pairing says the declared number is enforced, and the forced downgrade
    says the number is the RIGHT one. Half one alone is close to circular.
    """
    job = _canary_job()
    assert "kernel_floor.py excluded" in job, (
        "the mutation target is not derived from the index, so it is a literal "
        "that can name a version nobody ever published"
    )
    assert "--force-reinstall" in job and "--no-deps" in job, (
        "the mutation never defeats the constraint, so it can only observe pip "
        "obeying the metadata — never whether the metadata is correct"
    )
    assert "the canaries PASSED with dotmac-kernel" in job, (
        "the mutation does not fail when the excluded kernel WORKS, so an "
        "over-constrained floor would go unnoticed"
    )
    assert "ResolutionImpossible" in job, (
        "the resolver half accepts ANY non-zero pip, so a network error or a "
        "typo'd index would report the floor proven on a run that resolved "
        "nothing"
    )
    assert "kernel_floor.py symbol" in job, (
        "the mutation accepts any failure. The floor exists for one module and "
        "the forced failure must name it; a failure that never does is some "
        "other breakage standing in for the proof. Derived, not written here: "
        "the name was `dotmac_kernel.transactions` and is now "
        "`dotmac_kernel.product_database_catalog`, and a literal would have "
        "gone stale at exactly the moment the boundary moved."
    )


def test_the_floor_canary_reads_the_floor_from_the_artifact_not_the_tree() -> None:
    """A canary that PARSED `pyproject.toml` would be reading the source tree
    from an environment built to exclude it — the a4 mistake, committed inside
    the file written to prevent it. The declaration under test is the wheel's
    own `Requires-Dist`, which is the same statement a consumer's resolver
    reads.

    Checked over the script's imports and path literals rather than over the
    word: the docstrings discuss `pyproject.toml` at length, and they should.
    """
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
    assert "tomllib" not in imported, (
        "the canary script imports a TOML parser, so it can read the source "
        "tree's declaration instead of the artifact's"
    )
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "pyproject.toml" not in literals, (
        "the canary script holds `pyproject.toml` as a path; the artifact's "
        "metadata is the only declaration it may read"
    )
    assert (
        "Requires-Dist" in _source()
    ), "nothing in the script reads the artifact's own dependency declaration"


def test_the_installed_observation_canary_drives_both_replay_directions() -> None:
    """The a10 repair turns the formerly excluded path into artifact evidence.

    Acceptance alone cannot distinguish a verifier that forgets the canonical
    receipt. The installed-wheel canary must observe exact bytes replaying the
    first verdict and changed bytes under the same report id conflicting.
    """
    tree = ast.parse(_source())
    canary = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "canary_signed_execution_observation_binds"
    )
    dispositions = {
        node.attr for node in ast.walk(canary) if isinstance(node, ast.Attribute)
    }
    assert {"IDEMPOTENT_REPLAY", "CONFLICT"} <= dispositions
    calls = [
        node
        for node in ast.walk(canary)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "record_observation"
    ]
    assert len(calls) >= 5, "the canary no longer drives the two replay paths"


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
            '[tool.poetry]\nname = "dotmac-deployment-control"\nversion = "0.1.0a5"\n'
        ),
        "built_hashes": {wheel: "a" * 64, sdist: "b" * 64},
        "fetched": {wheel: "a" * 64, sdist: "b" * 64},
        "consumer_installed": True,
        "consumer_imported": True,
        "canaries_passed": True,
        "canary_detail": "all 9 canaries passed against the installed artifact",
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


# ── the catalogue canary's literal, and whether it can see a lie ────────────
#
# `scripts/artifact_canaries.py` writes `mod_deploy`'s whole published
# structure out as literals, because it runs where this repository is not
# importable and cannot ask `src/` what the answer should be. That is the right
# design and it creates exactly one new failure mode: the literal and the
# declaration drifting apart, in either direction. This section is the ratchet
# that holds them together, and the sensitivity proof for the comparison that
# reads them.

_spec_plant = importlib.util.spec_from_file_location(
    "plant_catalogue_mutation", REPO_ROOT / "scripts" / "plant_catalogue_mutation.py"
)
assert _spec_plant is not None and _spec_plant.loader is not None
plant = importlib.util.module_from_spec(_spec_plant)
sys.modules[_spec_plant.name] = plant
_spec_plant.loader.exec_module(plant)

REFUSAL_ASSERTION = REPO_ROOT / "scripts" / "assert_catalogue_refusal.sh"


def _published_catalogue_document() -> dict:
    """The catalogue document the SOURCE declaration produces.

    Built through the same public entry point the canary calls, so the two are
    reading one declaration rather than two descriptions of it.
    """
    from dotmac_kernel import (
        ComposedDatabaseLineageHeadV1,
        DatabaseCatalogOwnerKind,
        DatabaseCatalogOwnerV1,
    )

    from dotmac_deployment_control import build_database_catalog_snapshot, module

    snapshot = build_database_catalog_snapshot(
        distribution_version=module.version,
        composed_lineage_head=ComposedDatabaseLineageHeadV1(
            owner=DatabaseCatalogOwnerV1(
                kind=DatabaseCatalogOwnerKind.MODULE,
                code=canaries.CATALOGUE_MODULE_CODE,
            ),
            revision=canaries.CATALOGUE_LINEAGE_HEAD,
        ),
    )
    return json.loads(snapshot.to_json_bytes())


def test_the_canary_literal_and_the_declaration_do_not_drift() -> None:
    """THE RATCHET. A canary comparing an artifact against a stale expectation
    is worse than no canary: it goes red on a correct release and is then
    "fixed" by copying whatever the artifact said, which is how a proof becomes
    a tautology. Run here, against the declaration itself, a drift fails the
    pull request that caused it rather than the release that meets it."""
    from dotmac_deployment_control import module

    differences = canaries.catalogue_differences(
        _published_catalogue_document(), module.version
    )
    assert differences == [], differences


def test_the_canary_literal_carries_the_whole_extent_and_not_a_summary() -> None:
    """Seven tables and 115 columns, held as the LITERAL's own shape. A future
    edit that trimmed the table to its table names — the `len() == 7` check
    this canary exists to replace — would fail here rather than in a release."""
    assert canaries.CATALOGUE_TABLE_COUNT == 8
    assert canaries.CATALOGUE_COLUMN_COUNT == 134
    for name, columns in canaries.CATALOGUE_TABLES:
        assert columns, name
        for column, ordinal in zip(columns, range(1, len(columns) + 1), strict=True):
            assert column[1] == ordinal, (name, column)
            assert column[2][0] and column[2][1], (name, column)


#: `(mutation, how one catalogue document tells that lie)`. Keyed by the plant
#: script's own mutation names, and every one of them must appear: a plant CI
#: performs and nothing here reasons about would leave the grep in
#: `assert_catalogue_refusal.sh` demanding a string the comparator may not even
#: be able to produce.
def _rename_a_table(document: dict) -> dict:
    for table in document["tables"]:
        if table["name"] == "rollout_attempts":
            table["name"] = "rollout_events"
    return document


def _narrow_the_plan_digest(document: dict) -> dict:
    for table in document["tables"]:
        if table["name"] != "deployment_plans":
            continue
        for column in table["columns"]:
            if column["name"] == "plan_digest":
                column["postgres_type"]["formatted"] = "character varying(64)"
    return document


DOCUMENT_MUTATIONS = {
    "table": _rename_a_table,
    "column": _narrow_the_plan_digest,
}


def test_every_planted_mutation_is_one_the_comparator_can_see() -> None:
    """THE LOOP CLOSED WITHOUT A WHEEL.

    CI plants each mutation into an installed copy and requires the canaries to
    refuse it, naming what moved. Both halves of that — the plant and the grep —
    are strings, and strings agree with each other far more easily than they
    agree with a comparison. So the same lie is told to the comparator here, and
    every string the lane will demand must actually be in the refusal.
    """
    assert set(DOCUMENT_MUTATIONS) == set(plant.MUTATIONS) == set(plant.EVIDENCE)
    from dotmac_deployment_control import module

    for mutation, tell_the_lie in DOCUMENT_MUTATIONS.items():
        document = tell_the_lie(_published_catalogue_document())
        differences = canaries.catalogue_differences(document, module.version)
        assert differences, (
            f"the `{mutation}` mutation produced NO difference. The comparator "
            "cannot see it, so the CI lane that plants it would fail for some "
            "other reason or not at all."
        )
        report = "\n".join(differences)
        for evidence in plant.EVIDENCE[mutation]:
            assert evidence in report, (
                f"`assert_catalogue_refusal.sh` will demand {evidence!r} in the "
                f"refusal for `{mutation}`, and the comparator's own output is:"
                f"\n{report}"
            )


@pytest.mark.parametrize(
    ("field", "value"),
    [("plane", "tenant"), ("schema", "public"), ("relation_kind", "partitioned_table")],
)
def test_the_comparator_sees_moved_plane_schema_and_relation_kind(
    field: str, value: str
) -> None:
    """PLANE AND OWNERSHIP ARE NOT DECORATION. ADR-0023: a plane is DECLARED,
    never inferred — so a catalogue that quietly moved a table to the tenant
    plane, into another schema, or turned it into a partitioned parent, is
    describing a different database while every name still matches."""
    from dotmac_deployment_control import module

    document = _published_catalogue_document()
    document["tables"][0][field] = value
    differences = canaries.catalogue_differences(document, module.version)
    assert any(field in difference for difference in differences), differences


def test_the_comparator_sees_a_stolen_table() -> None:
    """The owner is what says this module's lineage created the table. A
    fragment claiming another owner is another module's contract."""
    from dotmac_deployment_control import module

    document = _published_catalogue_document()
    document["tables"][0]["owner"] = {"kind": "assembly", "code": "somebody_else"}
    differences = canaries.catalogue_differences(document, module.version)
    assert any("owner" in difference for difference in differences), differences


def test_the_comparator_sees_an_identity_that_belongs_to_another_release() -> None:
    """The version in the document is compared against `--expect-version`, which
    is the external statement of what was built. a4 shipped a wheel whose
    `__version__` was two releases stale; a catalogue can do the same."""
    document = _published_catalogue_document()
    differences = canaries.catalogue_differences(document, "0.1.0a999")
    assert any("distribution_version" in d for d in differences), differences
    assert any("module_release_version" in d for d in differences), differences


def test_the_comparator_does_not_pin_the_kernels_manifest_generation() -> None:
    """A DELIBERATE LIMIT, held so it cannot be tightened by accident.

    `manifest_contract_version` is inferred by the KERNEL from
    `KERNEL_MODULE_CONTRACT_VERSION`; this module declares none. It is therefore
    a property of the kernel resolved into the environment, and pinning it would
    turn a kernel bump into a red canary against an artifact that did not
    change. What must still fail is a value that is not a generation at all.
    """
    from dotmac_deployment_control import module

    document = _published_catalogue_document()
    document["manifest_contract_version"] += 1
    assert canaries.catalogue_differences(document, module.version) == []

    document["manifest_contract_version"] = "2"
    differences = canaries.catalogue_differences(document, module.version)
    assert any("manifest_contract_version" in d for d in differences), differences


# ── the mutation the canary has actually been seen to refuse ────────────────


@pytest.mark.parametrize("mutation", sorted(plant.MUTATIONS))
def test_the_plant_finds_its_target_exactly_once_in_the_source(mutation: str) -> None:
    """A PLANT THAT SILENTLY DOES NOTHING IS THE WORST OUTCOME AVAILABLE: the
    canaries pass, and the lane reads that as "the mutation was not refused" —
    a red run chasing a defect that does not exist. The script refuses a pattern
    it cannot place exactly once, and this is what stops a refactor discovering
    that during a release."""
    for filename, before, _ in plant.MUTATIONS[mutation]:
        source = (REPO_ROOT / "src" / "dotmac_deployment_control" / filename).read_text(
            encoding="utf-8"
        )
        assert source.count(before) == 1, (
            f"{filename} contains {before!r} {source.count(before)} times, so "
            f"the `{mutation}` plant cannot place it"
        )


def test_the_plant_refuses_to_edit_anything_outside_the_target_environment() -> None:
    """It rewrites `.py` files in place. Pointed at a checkout it would corrupt
    the working tree, and would prove nothing about a wheel either way."""
    source = (REPO_ROOT / "scripts" / "plant_catalogue_mutation.py").read_text(
        encoding="utf-8"
    )
    assert "is_relative_to" in source and "refusing to mutate" in source


def test_both_catalogue_mutations_are_planted_and_their_refusal_asserted() -> None:
    """Two plants, two lanes, and each has to be its own step: a loop would make
    one failure hide the other, and this repository's whole argument is that two
    facts which can only fail together are one fact wearing two names."""
    job = _canary_job()
    for mutation in sorted(plant.MUTATIONS):
        assert f"--mutation {mutation}" in job, mutation
        assert f"scripts/assert_catalogue_refusal.sh {mutation}" in job, mutation
    assert "the canaries PASSED against an artifact publishing a" in job, (
        "the table lane does not fail when the mutated artifact SATISFIES the "
        "canaries, so a comparison that ignores table identity would pass"
    )
    assert "the canaries PASSED against an artifact declaring" in job, (
        "the column lane does not fail when the mutated artifact satisfies the "
        "canaries, so a names-and-counts comparison would pass"
    )


def test_the_refusal_assertion_is_not_satisfied_by_any_red_run() -> None:
    """`grep -q` on a non-zero exit is the same substitution a `--fail`-less
    curl made: a mutated package that no longer IMPORTS also exits non-zero, and
    it says nothing about whether the comparison can see a renamed table. So the
    assertion requires the catalogue canary BY NAME and requires the artifact to
    still be healthy around it."""
    text = REFUSAL_ASSERTION.read_text(encoding="utf-8")
    assert "FAIL  database_catalogue_as_published" in text
    for healthy in ("installed_not_source", "signed_execution_observation_binds"):
        assert healthy in text, healthy
    assert "--print-evidence" in text, (
        "the strings the refusal must name are repeated in the shell instead of "
        "coming from the plant, so the two can describe different mutations"
    )


def test_the_environment_proof_reaches_the_catalogue_modules_themselves() -> None:
    """`installed_not_source` proves the top-level package came from an install.
    It says nothing about `database_catalog`, which is a separate module and the
    one under test here — and matching the EXISTING mechanism rather than
    inventing a second is the point: two ways of asking "is this the artifact?"
    are two answers waiting to disagree."""
    source = _source()
    assert "_installed_origin" in source
    for dotted in ("database_catalog", "database_catalog_snapshot", "manifest"):
        assert f'f"{{IMPORT_NAME}}.{dotted}"' in source, dotted
    assert "_site_directories()" in source


def test_the_runner_prints_the_environment_it_proved() -> None:
    """The absence of a checkout import is EVIDENCE, so it belongs in the run's
    own output where a reader of the verify log can check it — not only inside a
    refusal that fires when it is already too late."""
    tree = ast.parse(_source())
    main = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    printed = ast.dump(main)
    assert "sys.path" in _source()
    assert "'sys.path:'" in printed or '"sys.path:"' in printed


# ── the rendering canary actually refuses a flattened macro ─────────────────

#: A `_macros.html` whose branches are collapsed exactly the way a real one
#: would be: `{% if value %}` for a tri-state and one wording for two members of
#: the four. It is otherwise a valid template — the rule under test is about the
#: OUTPUT, not about the file being broken.
_FLATTENED_MACROS = """
{% macro image_set(images) %}
<td>{% for image in images or () %}{{ image.service }}{% endfor %}</td>
{% endmacro %}

{% macro executable(value) %}
<td>{% if value %}yes{% else %}no{% endif %}</td>
{% endmacro %}

{% macro binding(standing) %}
<td>{% if standing == "matches" %}matches{% else %}not matching{% endif %}</td>
{% endmacro %}

{% macro approval_standing(value) %}
<td>{{ value }}</td>
{% endmacro %}
"""


def _macros_from(source: str, tmp_path: Path) -> Any:
    from jinja2 import Environment, FileSystemLoader

    (tmp_path / "_macros.html").write_text(source, encoding="utf-8")
    env = Environment(loader=FileSystemLoader(str(tmp_path)), autoescape=True)
    return env.get_template("_macros.html").module


def test_the_rendering_canary_refuses_a_flattened_macro(tmp_path: Path) -> None:
    """THE SENSITIVITY PROOF for the package-data canary.

    Pointed at the real package it passes, which is what a check that has never
    refused looks like from the outside. So a `_macros.html` with the exact
    collapses this rule exists to catch is planted and the REAL rule is driven
    against it.
    """
    import dotmac_deployment_control as module

    macros = _macros_from(_FLATTENED_MACROS, tmp_path)
    with pytest.raises(canaries.CanaryFailure) as raised:
        canaries.prove_states_render_distinctly(macros, module)
    # NAMED. "it refused" would pass on a rule that refuses everything; the
    # message must identify a macro that actually lost a state.
    assert "image_set" in str(raised.value) or "executable" in str(
        raised.value
    ), raised.value


def test_the_rendering_canary_admits_the_shipped_macros(tmp_path: Path) -> None:
    """THE POSITIVE CONTROL. A rule seen only refusing may refuse everything.

    The repository's own `_macros.html` is loaded from a copy, so this asserts
    the rule's verdict on real content rather than re-running the canary's
    path-resolution.
    """
    import shutil

    import dotmac_deployment_control as module

    source = Path(module.__file__ or "").resolve().parent / "templates"
    shutil.copy(source / "_macros.html", tmp_path / "_macros.html")
    macros = _macros_from(
        (tmp_path / "_macros.html").read_text(encoding="utf-8"), tmp_path
    )
    assert canaries.prove_states_render_distinctly(macros, module) == {
        "image_set": 3,
        "executable": 3,
        "binding": 4,
        "approval_standing": 4,
    }


def test_the_rendering_canary_refuses_macros_that_are_simply_absent(
    tmp_path: Path,
) -> None:
    """A wheel carrying package data older than the code that renders through it
    has no such macro at all. That is a different failure from a flattened one
    and gets its own words."""
    import dotmac_deployment_control as module

    macros = _macros_from("{% macro unrelated() %}x{% endmacro %}", tmp_path)
    with pytest.raises(canaries.CanaryFailure) as raised:
        canaries.prove_states_render_distinctly(macros, module)
    assert "package data older" in str(raised.value), raised.value
