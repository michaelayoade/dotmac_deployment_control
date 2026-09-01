"""Plant one structural lie in an INSTALLED copy of this distribution.

A canary nobody has seen refuse is a step name (ADR-0018), and
`database_catalogue_as_published` is the most tempting canary in this repository
to write and never falsify: it compares a 95-row table against a 95-row table,
and a comparison with a subtle hole in it passes exactly as loudly as one
without.

So CI plants a mutation into the wheel's own `site-packages` copy and requires
the canaries to refuse it. TWO mutations, run separately, because they fail for
different reasons and each would be invisible behind the other:

* ``table``  — renames `rollout_attempts` to `rollout_events` in BOTH the
  catalogue contribution and the manifest's `platform_tables`. Both, on purpose:
  `ModuleManifest._validate_database_catalog` refuses a contribution that names
  a table the manifest does not own, so a one-sided edit would blow up at import
  and every canary would fail with a registry error — a refusal, but not this
  canary's, and not attributable to the catalogue at all. Edited on both sides
  the artifact is internally coherent and ships a table nobody agreed to, which
  is the failure mode a consumer would actually meet.
* ``column`` — narrows `deployment_plans.plan_digest` from `character
  varying(128)` back to the `dc_0001` width `character varying(64)`. A catalogue
  authored from the ROOT revision rather than from `dc_0002` looks exactly like
  this, every table name and column name is still correct, and only a check that
  compares TYPES can see it. It is the precise reason the canary asserts type
  identity and rendered spelling rather than names and counts.

The script refuses rather than warns whenever it cannot prove it changed what it
meant to change: an edit outside the target environment, a pattern that is not
present, or a pattern present more than once. A plant that silently did nothing
would leave the canaries passing, which the lane reads as "the mutation was not
refused" — a red run for the wrong reason, chasing a defect that is not there.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

#: `(file, before, after)` per mutation. `before` must occur EXACTLY once.
MUTATIONS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "table": (
        ("database_catalog.py", '"rollout_attempts",', '"rollout_events",'),
        ("manifest.py", '"rollout_attempts",', '"rollout_events",'),
    ),
    "column": (
        (
            "database_catalog.py",
            '_column("plan_digest", 7, _VARCHAR_128, nullable=True),',
            '_column(\n                    "plan_digest",\n'
            "                    7,\n"
            '                    _base_type("varchar", "character varying(64)"),\n'
            "                    nullable=True,\n"
            "                ),",
        ),
    ),
}

#: What the canary output must NAME once each mutation is planted. The lane
#: greps for these, so a failure that never mentions the thing that moved is
#: some other breakage standing in for the proof.
EVIDENCE: dict[str, tuple[str, ...]] = {
    "table": ("rollout_events", "rollout_attempts"),
    "column": ("plan_digest", "character varying(64)", "character varying(128)"),
}


def installed_package(venv: Path) -> Path:
    """Where THAT environment's interpreter resolves the distribution.

    Asked of the venv's own python rather than computed from a path guess: the
    question is which files the canaries will import, and only that interpreter
    can answer it.
    """
    result = subprocess.run(  # noqa: S603
        [
            str(venv / "bin" / "python"),
            "-c",
            "import dotmac_deployment_control as m;print(m.__file__)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    package = Path(result.stdout.strip()).resolve().parent
    if not package.is_relative_to(venv.resolve()):
        raise SystemExit(
            f"refusing to mutate {package}: it is not inside {venv}. This script "
            "edits an INSTALLED artifact; editing a checkout would corrupt the "
            "working tree and prove nothing about a wheel."
        )
    return package


def plant(package: Path, mutation: str) -> list[str]:
    changed: list[str] = []
    for filename, before, after in MUTATIONS[mutation]:
        path = package / filename
        text = path.read_text(encoding="utf-8")
        occurrences = text.count(before)
        if occurrences != 1:
            raise SystemExit(
                f"refusing to plant `{mutation}`: {before!r} occurs "
                f"{occurrences} times in {path}, and a mutation that cannot be "
                "placed exactly once has not been placed. A silent no-op would "
                "leave the canaries passing and the lane would report the "
                "mutation unrefused."
            )
        path.write_text(text.replace(before, after, 1), encoding="utf-8")
        changed.append(f"{filename}: {before!r} -> {after.splitlines()[0]!r}")
    # Bytecode is keyed on the source's mtime and size, and both moved here — but
    # the cache is removed anyway rather than reasoned about, because a canary
    # run against a stale `.pyc` would silently observe the UNMUTATED artifact.
    shutil.rmtree(package / "__pycache__", ignore_errors=True)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--venv",
        type=Path,
        help="the environment whose installed copy is mutated. Required unless "
        "--print-evidence, which asks a question about the mutation itself.",
    )
    parser.add_argument("--mutation", required=True, choices=sorted(MUTATIONS))
    parser.add_argument(
        "--print-evidence",
        action="store_true",
        help="print the strings the refusal must name, one per line, and exit",
    )
    args = parser.parse_args(argv)
    if args.print_evidence:
        for evidence in EVIDENCE[args.mutation]:
            print(evidence)
        return 0
    if args.venv is None:
        parser.error("--venv is required when planting a mutation")
    package = installed_package(args.venv)
    print(f"planting `{args.mutation}` into {package}")
    for line in plant(package, args.mutation):
        print(f"  {line}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
