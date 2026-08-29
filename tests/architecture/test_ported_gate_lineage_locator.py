"""PORTED GATE 2 — a module shipping a lineage says where the lineage IS.

Source: `dotmac_starter_mt` `tests/architecture/test_module_lineage_locator.py`,
ported as an equivalent property for the single distribution here.

Shipping revisions as package data is half a contract. A consuming assembly must
name the directory in Alembic's `version_locations`, and that path differs
between a source checkout, a virtualenv, a wheel and a container layer. Without a
public locator the consumer either hard-codes a site-packages path or reaches
into the package's internals; both break on the next install.

This repository is the first consumer to prove it the hard way: the platform
canary composes `versions_dir()` at runtime precisely BECAUSE the monorepo paths
it used to hard-code do not exist here.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from dotmac_deployment_control import versions_dir
from dotmac_deployment_control.migrations import versions_dir as submodule_locator

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "src" / "dotmac_deployment_control"
REVISION_PREFIX = "dc_"

#: Alembic's own `alembic_version.version_num` is `String(32)`. A module must
#: install into ANYONE's assembly, including one using that default table, so a
#: revision id longer than this is uninstallable rather than merely untidy.
MAX_REVISION_ID = 32


def _exports(module_file: Path, name: str) -> bool:
    tree = ast.parse(module_file.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, ast.List | ast.Tuple):
                        for element in node.value.elts:
                            if (
                                isinstance(element, ast.Constant)
                                and element.value == name
                            ):
                                return True
    return False


def test_both_the_package_and_its_migrations_export_the_locator() -> None:
    assert _exports(PACKAGE / "migrations" / "__init__.py", "versions_dir")
    assert _exports(PACKAGE / "__init__.py", "versions_dir"), (
        "the top-level re-export is what a consuming assembly imports; without "
        "it the consumer reaches into a submodule, which is an internal"
    )


def test_the_locator_takes_no_arguments_and_returns_a_path() -> None:
    """A locator with parameters is a function the consumer must be taught to
    call. It answers one question and takes nothing."""
    for locator in (versions_dir, submodule_locator):
        assert locator() == submodule_locator()
    assert isinstance(versions_dir(), Path)


def test_the_locator_points_at_a_directory_that_holds_revisions() -> None:
    directory = versions_dir()
    assert directory.is_dir(), directory
    revisions = sorted(p for p in directory.glob("*.py") if p.name != "__init__.py")
    assert revisions, f"{directory} holds no revisions"
    for revision in revisions:
        assert revision.stem.startswith(REVISION_PREFIX), revision.name
        assert len(revision.stem) <= MAX_REVISION_ID, (
            f"{revision.stem} is {len(revision.stem)} characters; Alembic's "
            f"default version table caps at {MAX_REVISION_ID}, so a longer id "
            "makes this module uninstallable in an assembly using that default"
        )


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ("empty", "holds no revisions"),
        ("missing", "is not a directory"),
    ],
)
def test_the_gate_catches_a_locator_that_points_somewhere_useless(
    tmp_path: Path, planted: str, expected: str
) -> None:
    """PLANTED VIOLATION — the acceptance test for this port.

    The two ways a locator lies: it resolves to a directory holding nothing, or
    it resolves to nothing at all. Both are what a wheel that forgot to ship its
    `migrations/versions` as package data actually looks like — the failure this
    gate exists for, and one that would otherwise surface as an empty Alembic
    history on a consumer's database.
    """
    target = tmp_path / "versions"
    if planted == "empty":
        target.mkdir()

    problems: list[str] = []
    if not target.is_dir():
        problems.append(f"{target} is not a directory")
    elif not sorted(p for p in target.glob("*.py") if p.name != "__init__.py"):
        problems.append(f"{target} holds no revisions")

    assert problems and expected in problems[0], problems
