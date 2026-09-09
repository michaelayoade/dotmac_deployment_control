"""Discover and run EVERY root-level PostgreSQL platform-isolation canary.

## The defect this closes

`.github/workflows/ci.yml`'s PostgreSQL job ran exactly one hardcoded file:
`pytest tests/test_deployment_control_platform_isolation.py`. When dc_0011
added a second one, `tests/test_attestation_trust_registry_platform_isolation
.py`, it was never named there -- so all four PostgreSQL proofs that file
contains were dead code from the day they were written. Nothing failed; the
job simply never looked at the new file. The single-filename job was healthy
in exactly the way an unmonitored region is healthy: not exercised, not
refusing anything, not observed at all (ADR-0018's "a guard exemption states
an ENFORCEABLE premise, or the region is unmonitored rather than exempt").

Fixing this by adding the new filename to the pytest invocation would repeat
the exact defect one file later -- the NEXT canary would be orphaned the same
way, because a maintained filename list is a thing someone has to remember to
update. This script exists so nobody has to remember.

## Three refusals, not one

1. **Discovery is glob-based**, not a maintained list
   (`tests/test_*_platform_isolation.py`), so a new canary file is picked up
   the moment it exists.
2. **An empty discovery result is a failure**, not a quiet no-op. If these
   files are ever renamed, moved under `tests/unit`, or deleted without a
   replacement, this script says so instead of reporting success having run
   nothing -- the same "absent reads as success" defect `tests/conftest.py`
   already names for a skipped test, one layer earlier.
3. **The database coordinate must be PRESENT**, or this script refuses
   outright, rather than letting the individual canary files' own
   `pytest.skip(...)` absorb the absence silently. `REQUIRE_NO_SKIPS=1`
   (`tests/conftest.py`) is set below as a second, independent layer: even if
   a future canary file skips for some OTHER reason, that skip still becomes
   a failure in this run.

## What proves this, and where

`tests/architecture/test_platform_isolation_canary_discovery.py` is the
sensitivity proof: it plants a synthetic file matching the glob in a
temporary directory and shows `discover_platform_isolation_tests` finds it
(the positive control this whole mechanism would be unverified without), a
near-miss file that does NOT match the pattern and shows it is correctly
excluded, and the two-directional guard against `ci.yml` itself -- the
workflow must invoke this script rather than naming any
`test_*_platform_isolation.py` file directly, on EITHER side: a file this
script would discover that the workflow step does not reach, or a filename
the workflow step names that no longer exists on disk.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
PATTERN = "test_*_platform_isolation.py"

#: Either satisfies the canary files' own `os.getenv(...) or os.getenv(...)`
#: read. Checked here, ahead of pytest, so the failure is one clear line
#: instead of N per-file pytest.skip calls that REQUIRE_NO_SKIPS then has to
#: convert into N separate failures.
DATABASE_URL_ENV_VARS: tuple[str, ...] = (
    "TEST_MIGRATION_DATABASE_URL",
    "TEST_DATABASE_URL",
)


def discover_platform_isolation_tests(tests_dir: Path = TESTS_DIR) -> list[Path]:
    """Every root-level `tests/test_*_platform_isolation.py` file, sorted.

    Root-level ONLY (`glob`, not `rglob`): every sibling canary lives directly
    under `tests/`, deliberately outside `tests/unit` and `tests/architecture`,
    because those two run against SQLite with no RLS and must never sweep a
    PostgreSQL-only proof in as if it had been exercised there.
    """
    return sorted(tests_dir.glob(PATTERN))


class NoPlatformIsolationCanariesDiscoveredError(RuntimeError):
    """Discovery found zero files. A guard that finds nothing is not a pass."""


class DatabaseCoordinateMissingError(RuntimeError):
    """Required evidence, requested without the database to produce it."""


def require_database_url(env: dict[str, str] | None = None) -> None:
    source = env if env is not None else os.environ
    if any(source.get(name) for name in DATABASE_URL_ENV_VARS):
        return
    raise DatabaseCoordinateMissingError(
        "run_platform_isolation_canaries: none of "
        f"{DATABASE_URL_ENV_VARS} is set. This runner exists to RUN the "
        "PostgreSQL platform-isolation proofs, not to report success having "
        "skipped them -- provide the database coordinate before invoking it"
    )


def main(argv: list[str] | None = None) -> int:
    # `TESTS_DIR`, not the function's own bound default -- looked up fresh at
    # call time, so a test can monkeypatch the module global and observe it.
    discovered = discover_platform_isolation_tests(TESTS_DIR)
    if not discovered:
        raise NoPlatformIsolationCanariesDiscoveredError(
            "run_platform_isolation_canaries: discovered ZERO files matching "
            f"tests/{PATTERN}. A discovery step that finds nothing is a "
            "failure, not a quiet pass -- the platform-isolation canaries "
            "have been renamed, moved, or deleted without this runner "
            "noticing"
        )

    require_database_url()

    env = dict(os.environ)
    # Belt and suspenders with `require_database_url` above: this also turns
    # any OTHER skip a discovered file might raise (not only the missing
    # database coordinate) into a failure for this run.
    env["REQUIRE_NO_SKIPS"] = "1"

    relative = [str(path.relative_to(REPO_ROOT)) for path in discovered]
    print(f"run_platform_isolation_canaries: running {relative}")
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
        [sys.executable, "-m", "pytest", *relative, "-rs"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
