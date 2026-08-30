"""The declared kernel floor tracks the symbol it exists for, and can fail.

`0.1.0a5` is the reason this file exists, and its shape is worth stating once
more because every check in here is aimed at it: the artifact's bytes were
beyond doubt — peeled commit, wheel and sdist sha256, publisher read-back, an
independent read-only consumer install, seven behavioural canaries against the
wheel the registry served — and it could not run in its consuming assembly. It
imports `dotmac_kernel.transactions` (`service.py:73`), first shipped in kernel
`0.1.0a98`, while declaring `dotmac-kernel >=0.1.0a77`. **Under-constrained by
21 alphas.** Resolution succeeded, the lock wrote cleanly, the artifacts matched
their published hashes byte-for-byte, and the failure appeared at container
boot.

**A hash comparison proves you got the published bytes; it cannot prove they
import.** And an import performed where a compatible kernel happens to be
present proves the wheel imports — never that its declared FLOOR is honest.

So there are three layers, and only the first two are in this file:

1. **Static** (here): the floor is the highest kernel symbol the package
   actually imports, derived from the source rather than remembered, so raising
   or lowering the literal without moving the import fails the build.
2. **The helper's own behaviour** (here): `scripts/kernel_floor.py` is what
   `ci.yml` asks for the floor and for the mutation target, and a helper that
   answered wrongly would make both lanes confident and useless. Every refusal
   is paired with the shape it refuses (ADR-0018).
3. **Executed, against an installed artifact** (`ci.yml`, not here): the floor
   lane installs the declared minimum literally, and the mutation lane installs
   the newest kernel that floor excludes and requires the canaries to FAIL.
   This repository's test suite runs from source, so a lane that proved
   anything about an artifact could not live in it.
"""

from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "src" / "dotmac_deployment_control"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

_spec = importlib.util.spec_from_file_location(
    "kernel_floor", REPO_ROOT / "scripts" / "kernel_floor.py"
)
assert _spec is not None and _spec.loader is not None
kernel_floor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kernel_floor)

#: The kernel submodule each alpha FIRST shipped, for the ones this package
#: imports. Not a guess: `dotmac_kernel/transactions.py` is absent from the
#: published `0.1.0a97` wheel and present in `0.1.0a98`, and the floor is
#: derived from that fact rather than from a changelog entry about it.
FIRST_SHIPPED_IN = {
    "dotmac_kernel.transactions": "0.1.0a98",
}


def _kernel_imports() -> set[str]:
    """Every `dotmac_kernel.*` module the package imports, at any depth."""
    found: set[str] = set()
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                module = node.module or ""
                if module.startswith("dotmac_kernel"):
                    found.add(module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("dotmac_kernel"):
                        found.add(alias.name)
    return found


# ── the floor is the highest symbol the package actually imports ────────────


def test_the_declared_floor_is_the_version_that_first_shipped_what_we_import() -> None:
    """THE a5 DEFECT, as a static gate.

    a5's floor was the ALLOCATION — a76 carries this module's `mod_deploy`
    ledger row — plus a margin. That is a real lower bound and it is not THE
    lower bound, and nothing compared it with the imports. Here the two are
    compared: for every kernel module this package imports whose introducing
    alpha is recorded above, the declared floor must be at least that alpha.
    """
    floor = kernel_floor.declared_floor()
    imported = _kernel_imports()
    for module, introduced in sorted(FIRST_SHIPPED_IN.items()):
        if module not in imported:
            continue
        assert kernel_floor.parse(floor) >= kernel_floor.parse(introduced), (
            f"the package imports {module}, first shipped in dotmac-kernel "
            f"{introduced}, and declares >={floor}. That is exactly the shape "
            "0.1.0a5 published: a floor that every resolver honours and no "
            "consumer can run."
        )


def test_the_symbol_the_floor_is_set_by_is_still_imported() -> None:
    """THE SENSITIVITY HALF, and without it the test above is vacuous.

    A check written as "for every recorded module the package still imports"
    passes trivially once the package stops importing any of them — including
    the case where somebody deletes the import, leaves the floor at a98, and
    the mutation lane then correctly reports the floor is too high. This states
    the premise instead of assuming it.
    """
    imported = _kernel_imports()
    missing = sorted(m for m in FIRST_SHIPPED_IN if m not in imported)
    assert not missing, (
        f"{missing} no longer imported. The recorded floor is set by that "
        "import; if it is genuinely gone, lower the floor and remove the row "
        "here in the same change — do not leave a floor nothing justifies."
    )


def test_the_floor_is_not_higher_than_anything_the_package_needs() -> None:
    """The other direction, stated here and PROVEN in CI's mutation lane.

    An over-constrained floor is a smaller harm than a5's and it is still a
    harm: it forces a consumer into an upgrade nothing requires, which is
    precisely the 21-alpha jump this change hands Platform CP. So the declared
    floor must equal the highest recorded introduction rather than merely
    exceed it, and the executed proof is `ci.yml`'s mutation lane, which
    installs the newest kernel the floor excludes and fails if it works.
    """
    floor = kernel_floor.declared_floor()
    highest = max(FIRST_SHIPPED_IN.values(), key=kernel_floor.parse)
    assert floor == highest, (
        f"the declared floor is {floor} and the highest symbol this package "
        f"imports first shipped in {highest}. A floor above what the code needs "
        "makes a consumer's upgrade obligation larger than the evidence for it."
    )


# ── the helper answers correctly, and refuses rather than guessing ──────────


def test_it_reads_the_floor_out_of_the_real_declaration() -> None:
    floor = kernel_floor.declared_floor()
    assert re.fullmatch(r"\d+\.\d+\.\d+a\d+", floor), floor
    assert kernel_floor.declared_constraint().strip() == f">={floor}"


@pytest.mark.parametrize(
    "constraint",
    ["^0.1.0a98", ">=0.1.0a98,<0.2", "<=0.1.0a98", "0.1.0a98", "*", ">= 0.1.0b1"],
)
def test_a_constraint_shape_it_cannot_read_is_refused(
    constraint: str, tmp_path: Path
) -> None:
    """PLANTED VIOLATIONS. Each of these changes what "the declared minimum"
    means, and the floor lane installs that minimum literally — so a helper
    that guessed would send the lane at the wrong version while reporting the
    floor proven. A caret is the one worth naming: it carries an implicit
    ceiling, so "the minimum" and "what a resolver may choose" stop being the
    same question."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool.poetry]\nname = 'x'\nversion = '0.1.0a6'\n\n"
        "[tool.poetry.dependencies]\n"
        f'dotmac-kernel = {{ version = "{constraint}" }}\n',
        encoding="utf-8",
    )
    with pytest.raises(kernel_floor.FloorError):
        kernel_floor.declared_floor(pyproject)


def test_a_missing_dependency_is_refused_rather_than_defaulted(
    tmp_path: Path,
) -> None:
    """ABSENT MUST NOT READ AS SATISFIED. A helper that returned some fallback
    floor for a package declaring no kernel at all would let the floor lane
    install a kernel nobody asked for and call it the minimum."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool.poetry]\nname = 'x'\nversion = '0.1.0a6'\n\n"
        "[tool.poetry.dependencies]\npython = '>=3.11'\n",
        encoding="utf-8",
    )
    with pytest.raises(kernel_floor.FloorError, match="declares no"):
        kernel_floor.declared_floor(pyproject)


def _listing(*versions: str) -> str:
    """A simple-index page for `dotmac-kernel`, in the shape Forgejo serves.

    Built rather than pasted so the fixture stays readable at this line length
    and so a test can name the exact set of versions it is reasoning about.
    """
    rows = []
    for version in versions:
        for name in (
            f"dotmac_kernel-{version}-py3-none-any.whl",
            f"dotmac_kernel-{version}.tar.gz",
        ):
            rows.append(
                f'<a href="../../files/dotmac-kernel/{version}/{name}">{name}</a>'
            )
    return "\n".join(rows)


def test_it_names_the_closest_near_miss_as_the_mutation_target() -> None:
    """`a97`, not `a73`. The mutation is worth what its target is worth: the
    version immediately below the floor is the one that would still be chosen
    if the floor were one alpha too high, and something far below would fail
    for a dozen reasons while proving only that ancient kernels are ancient."""
    versions = kernel_floor.index_versions(_listing("0.1.0a73", "0.1.0a97", "0.1.0a98"))
    assert versions == ["0.1.0a73", "0.1.0a97", "0.1.0a98"]
    assert kernel_floor.newest_excluded("0.1.0a98", versions) == "0.1.0a97"


def test_the_ordering_is_numeric_and_not_textual() -> None:
    """`0.1.0a97` sorts ABOVE `0.1.0a100` as a string, so a text comparison
    would name the wrong mutation target the moment the kernel reaches its
    hundredth alpha — and would do it silently, with a lane still reporting
    green."""
    versions = ["0.1.0a9", "0.1.0a97", "0.1.0a100", "0.1.0a101"]
    assert kernel_floor.newest_excluded("0.1.0a101", versions) == "0.1.0a100"
    assert sorted(versions) != kernel_floor.index_versions(_listing(*versions)), (
        "a textual sort and the numeric one must differ on this input, or this "
        "test is not distinguishing the two at all"
    )


def test_an_index_with_nothing_below_the_floor_fails_loudly() -> None:
    """FAIL-CLOSED. If the floor excludes nothing there is no mutation to run,
    and the honest outcome is a red lane — not a lane that quietly proves
    nothing. A canary nobody has seen refuse is not a canary."""
    with pytest.raises(kernel_floor.FloorError, match="no dotmac-kernel version below"):
        kernel_floor.newest_excluded("0.1.0a1", ["0.1.0a97", "0.1.0a98"])


def test_an_empty_listing_is_an_error_and_not_an_empty_answer(tmp_path: Path) -> None:
    """A listing that names no kernel at all must not read as "the floor
    excludes nothing". Absent-as-success is the shape that let a `pytest.skip`
    stand in for this repository's strongest proof, and it is the shape a
    mutation lane is most exposed to: it EXPECTS a failure, so a lane that
    never ran looks exactly like a lane that passed."""
    listing = tmp_path / "index.html"
    listing.write_text("<html>nothing here</html>", encoding="utf-8")
    assert kernel_floor.index_versions(listing.read_text()) == []
    assert kernel_floor.main(["excluded", "--index-html", str(listing)]) == 1


def test_the_cli_prints_the_declared_floor(capsys: pytest.CaptureFixture[str]) -> None:
    """POSITIVE CONTROL over the interface `ci.yml` actually calls. The refusals
    above are equally consistent with a helper that refuses everything."""
    assert kernel_floor.main(["declared"]) == 0
    assert capsys.readouterr().out.strip() == kernel_floor.declared_floor()


def test_the_cli_prints_the_mutation_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listing = tmp_path / "index.html"
    listing.write_text(_listing("0.1.0a73", "0.1.0a97", "0.1.0a98"), encoding="utf-8")
    assert kernel_floor.main(["excluded", "--index-html", str(listing)]) == 0
    assert capsys.readouterr().out.strip() == "0.1.0a97"


def test_the_helper_performs_no_network_io() -> None:
    """The credential stays in the workflow step that owns it. A helper that
    fetched the index itself would need one, and the repository's whole
    credential discipline is that a secret reaches exactly the step that
    declares it."""
    tree = ast.parse((REPO_ROOT / "scripts" / "kernel_floor.py").read_text())
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
    assert not (imported & {"urllib", "http", "socket", "requests", "httpx"}), imported


# ── the workflow asks the helper rather than carrying a literal ─────────────


def test_the_workflow_derives_both_versions_rather_than_hard_coding_them() -> None:
    """A literal in the workflow would be a second authority for the floor, and
    two literals for one fact drift the moment somebody bumps the one they are
    looking at — which is `0.1.0a4`'s `__version__` defect, in a different
    file."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    executable = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "kernel_floor.py declared" in executable
    assert "kernel_floor.py excluded" in executable
    hard_coded = re.findall(r"dotmac-kernel==0\.1\.0a\d+", executable)
    assert not hard_coded, (
        f"the workflow pins {hard_coded} literally. Both versions must be "
        "derived — the floor from the declaration, the mutation target from "
        "the index — or the lanes stop tracking what they claim to test."
    )
