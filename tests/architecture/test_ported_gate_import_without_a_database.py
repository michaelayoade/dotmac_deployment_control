"""PORTED GATE 1 — this distribution imports without a database URL.

Source: `dotmac_starter_mt`
`tests/architecture/test_packages_import_without_a_database.py`.

Ported as an EQUIVALENT PROPERTY rather than copied. The original enumerates a
workspace of ninety packages; there is one here. Copying it would create another
unpinned fork of Starter code alongside `adoption_evidence.py`, and that copy has
a blob-id pin precisely because a second copy with no control is how two files
silently disagree.

The property is distinct from `test_no_eager_database_runtime.py` and both are
needed. That file forbids the IMPORT of `dotmac_kernel.db` anywhere in the
package. This one proves the OUTCOME a consumer actually experiences: `import
dotmac_deployment_control` succeeds on a machine with no database configured at
all. A future indirection could satisfy one and break the other.

`DATABASE_URL` is REMOVED from the environment, never blanked. A
parseable-but-empty DSN could let a lazy engine succeed and hide the defect.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_IMPORT_NAMES = tuple(
    entry["include"]
    for entry in tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["tool"]["poetry"]["packages"]
)


def _run_without_database_url(source: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    env.pop("PLATFORM_DATABASE_URL", None)
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
        check=False,
    )


def test_there_is_a_distribution_to_check() -> None:
    """Non-vacuity: a sweep that found nothing would pass silently forever."""
    assert _IMPORT_NAMES == ("dotmac_deployment_control",), _IMPORT_NAMES


def test_the_distribution_imports_without_a_database_url() -> None:
    result = _run_without_database_url("import dotmac_deployment_control\n")
    assert result.returncode == 0, (
        "`import dotmac_deployment_control` fails with no DATABASE_URL in the "
        "environment. Something in the package reaches a module that builds an "
        f"engine at import time.\n{result.stderr[-2000:]}"
    )


def test_the_gate_catches_a_package_that_would_need_one() -> None:
    """PLANTED VIOLATION — the acceptance test for this port.

    Moving a file proves nothing; catching a violation this repository could
    actually commit does. The plant is the exact regression the gate exists for:
    a module-level import of the configured database module. It must fail in the
    same environment where the real import succeeds, or the gate is measuring
    something other than what it claims.
    """
    result = _run_without_database_url(
        "from dotmac_kernel.db import conflict_savepoint\n"
    )
    assert result.returncode != 0, (
        "importing `dotmac_kernel.db` with no DATABASE_URL SUCCEEDED, so this "
        "gate cannot distinguish a package that needs a database from one that "
        "does not. Either the kernel stopped building its runtime at import "
        "time — in which case this gate is now vacuous and must be rewritten — "
        "or the environment is supplying a URL the removal above missed."
    )
