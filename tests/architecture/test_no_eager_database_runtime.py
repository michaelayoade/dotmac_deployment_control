"""This module never imports the module that makes a database connection.

Every operation in `dotmac_deployment_control` takes a **caller-owned**
`Session`. It opens nothing, closes nothing and configures nothing. So importing
`dotmac_kernel.db` — the reference assembly's CONFIGURED instance, which builds
a `DatabaseRuntime` at module import time — is a boundary violation whether or
not the runtime is ever used. The engine-free `dotmac_kernel.transactions`
re-exports the same `conflict_savepoint` and constructs nothing.

## How the violation hid, and why one test is not enough

`record_observation` imported `dotmac_kernel.db` **lazily, inside a handler**.
Three consequences, each defeating a different kind of check:

* A grep over imports at the top of the file finds nothing.
* Importing the package finds nothing — the import only happens when an
  observation is actually admitted.
* The failure, when it came, was `ArgumentError: Could not parse SQLAlchemy URL`
  raised inside SQLAlchemy's `make_url`, twelve tests deep and nowhere near the
  cause. It was first "fixed" by giving the process a parseable placeholder URL,
  which made the tests pass and left the violation in place. That is the failure
  mode this file exists to prevent recurring: a workaround that restores green.

So three properties, and the third is the one that bites.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "src" / "dotmac_deployment_control"

#: The module that must never be reached. `db` is the assembly's configured
#: instance; `session_runtime` is the class it instantiates — a module that
#: imported the factory directly would be building its own runtime, which is the
#: same violation wearing a different name (`AGENTS.md` rule 8: one transaction
#: authority, and a product supplies its own by constructing one — this package
#: is not a product).
FORBIDDEN = ("dotmac_kernel.db", "dotmac_kernel.session_runtime")


def _forbidden_imports(source: str, where: str) -> list[str]:
    """Every import of a forbidden module, in any of the three spellings.

    A grep for `dotmac_kernel.db` misses `from dotmac_kernel import db`, and a
    grep for either misses one written inside a function — which is exactly how
    this one survived. `ast.walk` descends into function bodies.
    """
    found: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in FORBIDDEN:
                    found.append(f"{where}:{node.lineno} import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in FORBIDDEN:
                found.append(f"{where}:{node.lineno} from {module} import …")
            elif module == "dotmac_kernel":
                for alias in node.names:
                    if f"dotmac_kernel.{alias.name}" in FORBIDDEN:
                        found.append(
                            f"{where}:{node.lineno} from dotmac_kernel "
                            f"import {alias.name}"
                        )
    return found


# ── Property 1: no source in this package imports it, anywhere ──────────────


def test_no_source_file_imports_the_configured_database_module() -> None:
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        offenders += _forbidden_imports(
            path.read_text(encoding="utf-8"), str(path.relative_to(REPO_ROOT))
        )
    assert not offenders, (
        "these import the assembly's configured database module:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse `dotmac_kernel.transactions`, which re-exports the same "
        "`conflict_savepoint` and constructs no engine. This package takes a "
        "caller-owned Session and must never cause a runtime to be built."
    )


@pytest.mark.parametrize(
    "spelling",
    [
        "import dotmac_kernel.db",
        "from dotmac_kernel.db import conflict_savepoint",
        "from dotmac_kernel import db",
        "import dotmac_kernel.session_runtime",
        "def f():\n    from dotmac_kernel.db import conflict_savepoint",
    ],
)
def test_the_detector_catches_every_spelling(spelling: str) -> None:
    """SENSITIVITY, over the vocabulary rather than one member of it.

    The last case is the one that actually happened: an import nested inside a
    function body. A detector that only inspected module-level statements would
    pass this file today and would have passed it before the fix.
    """
    assert _forbidden_imports(spelling, "planted")


def test_the_detector_does_not_fire_on_the_correct_import() -> None:
    """POSITIVE CONTROL. Without it the five refusals above are equally
    consistent with a detector that flags every import."""
    assert not _forbidden_imports(
        "from dotmac_kernel.transactions import conflict_savepoint", "planted"
    )


# ── Properties 2 and 3: proven in a subprocess, on the real code path ───────

_PROBE = """
import os, sys

# Unparseable on purpose. If anything on this path constructs a DatabaseRuntime,
# SQLAlchemy raises rather than quietly accepting a placeholder — which is what
# the first, wrong fix supplied.
os.environ["DATABASE_URL"] = "not a database url at all"
os.environ.pop("PLATFORM_DATABASE_URL", None)

import pytest

code = pytest.main(
    [
        "tests/unit/test_deployment_control_observations.py",
        "-q",
        "-p",
        "no:cacheprovider",
    ]
)

forbidden = ("dotmac_kernel.db", "dotmac_kernel.session_runtime")
leaked = sorted(m for m in forbidden if m in sys.modules)
print("LEAKED:" + ",".join(leaked))
sys.exit(int(code) or (2 if leaked else 0))
"""


@pytest.mark.slow
def test_the_real_path_runs_with_an_invalid_url_and_never_imports_the_runtime() -> None:
    """The half that static analysis cannot do.

    A lazy import inside a handler is invisible to property 1 if someone
    reintroduces it through an indirection — a helper, a re-export, a
    conditional. So this exercises the REAL observation path in a subprocess
    with a deliberately unparseable `DATABASE_URL`, and then asks `sys.modules`
    what was actually loaded.

    Two assertions from one run, because they fail differently and a reader
    needs to know which happened:

    * the suite passes — operations work with a caller-owned session and no
      usable database configuration at all;
    * neither forbidden module is in `sys.modules` afterwards — nothing
      constructed a runtime, as opposed to constructing one that happened not to
      be dialled.
    """
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _PROBE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    leaked_line = next(
        (line for line in result.stdout.splitlines() if line.startswith("LEAKED:")),
        "LEAKED:?",
    )
    leaked = leaked_line.removeprefix("LEAKED:")

    assert leaked == "", (
        f"{leaked} was imported while exercising the real observation path.\n"
        "Something on that path reaches the assembly's configured database "
        "module. Property 1 did not catch it, which means it arrived through an "
        "indirection — a helper, a re-export, or a conditional import.\n"
        f"stdout tail:\n{result.stdout[-1500:]}"
    )
    assert result.returncode == 0, (
        "the observation suite failed with an unparseable DATABASE_URL. "
        "Operations take a caller-owned Session and must not depend on the "
        "process having a usable database configuration.\n"
        f"stdout tail:\n{result.stdout[-2500:]}\nstderr tail:\n{result.stderr[-800:]}"
    )
