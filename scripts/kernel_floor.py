"""The declared kernel floor, and the newest kernel that floor EXCLUDES.

## Why this file exists

`0.1.0a5` published a wheel whose bytes were beyond doubt — peeled commit,
wheel and sdist sha256, publisher read-back, an independent read-only consumer
install, and seven behavioural canaries, all against the artifact the registry
served. It still could not run in its consuming assembly. `service.py` imports
`dotmac_kernel.transactions`, first shipped in kernel `0.1.0a98`, while
`pyproject.toml` declared `dotmac-kernel >=0.1.0a77`: **under-constrained by 21
alphas**. (The floor has since moved on to
`dotmac_kernel.product_database_catalog`, first shipped in `0.1.0a100`; what is
permanent here is the mechanism, not the particular row.) Resolution succeeded,
the lock wrote cleanly, the artifacts matched their published hashes
byte-for-byte, and the failure surfaced at container boot in the Platform CP
lane.

The lesson is narrow and worth stating exactly: **a hash comparison proves you
got the published bytes; it cannot prove they import.** a5's verification did
exercise importability — in an environment where a compatible kernel happened
to be installed. That proves the wheel imports. It says nothing about whether
the DECLARED FLOOR is honest, because nothing in the run ever installed the
declared floor.

## What this module computes, and why both halves are needed

* `declared_floor()` — the exact version the distribution says it needs. The
  CI floor lane installs **that** and nothing looser, so an under-constrained
  floor fails instead of being masked by whatever else the resolver picked.
* `newest_excluded()` — the highest kernel actually on the index that is
  strictly below the floor. The mutation lane installs **that** and requires
  the same canaries to FAIL.
* `floor_symbol()` — the one kernel submodule whose introduction sets the
  declared floor, derived from the package's own imports. The mutation lane
  requires its failure to NAME that module, so "the canaries failed" cannot
  stand in for "the canaries failed at the boundary the floor describes".

Together they make the floor falsifiable in both directions:

| the floor is… | which lane goes red | because |
| --- | --- | --- |
| too LOW (a5's defect) | floor lane | the declared minimum cannot import |
| too HIGH | mutation lane | the version below it runs everything fine |

A floor that is merely *asserted* satisfies neither. Without the mutation the
floor lane passes for the wrong reason and nobody learns whether it can fail
(ADR-0018).

## Refusing rather than guessing

The declared constraint must be exactly `>=<major>.<minor>.<patch>a<n>`. That
is the only shape this dependency has ever carried, and a parser that reasons
about an unfamiliar one answers confidently and wrongly — the same rule
`scripts/release_guard.py` holds for the distribution's own version. A caret, a
range, an upper bound or an extras table is refused here so somebody extends
this deliberately, in the change that introduces it.

`newest_excluded` refuses loudly when the index lists nothing below the floor.
An empty answer there would silently turn the mutation lane into a lane that
proves nothing, which is the failure mode this whole file was written against.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGE = REPO_ROOT / "src" / "dotmac_deployment_control"

DEPENDENCY = "dotmac-kernel"

#: The kernel SUBMODULE each alpha FIRST shipped, for the ones this package
#: imports. Not a changelog reading and not a guess: each row was established by
#: opening the published wheels on either side of the boundary.
#:
#: * `dotmac_kernel/product_database_catalog.py` is absent from `0.1.0a99` and
#:   present in `0.1.0a100`. It sets the floor now.
#:
#: A SUBMODULE rather than a symbol, and that is load-bearing rather than
#: stylistic. `from dotmac_kernel.product_database_catalog import X` against a
#: kernel that lacks it raises `ModuleNotFoundError: No module named
#: 'dotmac_kernel.product_database_catalog'`, which names the boundary; `from
#: dotmac_kernel import X` raises `ImportError: cannot import name 'X' from
#: 'dotmac_kernel'`, which names no module at all and would leave the mutation
#: lane unable to tell its own proof from unrelated breakage.
FIRST_SHIPPED_IN = {
    "dotmac_kernel.product_database_catalog": "0.1.0a100",
}

#: `0.1.0a100`, and nothing else — deliberately the same narrow shape
#: `release_guard.parse` accepts for this distribution's own version.
_ALPHA = re.compile(r"\A(\d+)\.(\d+)\.(\d+)a(\d+)\Z")

#: `>=0.1.0a100`. A lower bound, alone, no upper bound and no second clause.
_LOWER_BOUND = re.compile(r"\A>=\s*(\d+\.\d+\.\d+a\d+)\Z")

#: How the private index renders a file link for this distribution. Both the
#: normalized and the underscored project names appear in the wild, so the
#: pattern keys on the FILENAME rather than on the href.
_INDEX_FILE = re.compile(
    r"dotmac[-_]kernel-(\d+\.\d+\.\d+a\d+)(?:-py3-none-any\.whl|\.tar\.gz)"
)


class FloorError(ValueError):
    """The declared floor, or the index, is not a thing this module may reason about."""


def parse(version: str) -> tuple[int, int, int, int]:
    """An orderable key. Raises rather than returning a sentinel.

    Ordering matters more than it looks: `0.1.0a97` sorts ABOVE `0.1.0a100` as
    a string, so a text comparison would name the wrong mutation target the
    moment the kernel reaches its hundredth alpha.
    """
    match = _ALPHA.fullmatch(version.strip())
    if match is None:
        raise FloorError(
            f"{version!r} is not a shape this module can order. It accepts "
            "`<major>.<minor>.<patch>a<n>` only, and refuses anything else "
            "rather than guessing at it."
        )
    major, minor, patch, alpha = match.groups()
    return (int(major), int(minor), int(patch), int(alpha))


def declared_constraint(pyproject: Path = PYPROJECT) -> str:
    """The raw version constraint the distribution declares for the kernel."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    dependencies = data["tool"]["poetry"]["dependencies"]
    if DEPENDENCY not in dependencies:
        raise FloorError(
            f"{pyproject} declares no {DEPENDENCY} dependency at all. This "
            "module exists to keep that declaration honest; it cannot report a "
            "floor for a dependency that is not declared."
        )
    declared = dependencies[DEPENDENCY]
    if isinstance(declared, str):
        return declared
    if isinstance(declared, dict) and isinstance(declared.get("version"), str):
        return str(declared["version"])
    raise FloorError(
        f"the {DEPENDENCY} dependency is declared as {declared!r}, which is "
        "neither a version string nor a table carrying one. Refusing rather "
        "than reaching into an unfamiliar shape."
    )


def declared_floor(pyproject: Path = PYPROJECT) -> str:
    """The exact minimum kernel this distribution says it needs.

    A pure lower bound is required. `^0.1.0a100` would carry a caret's implicit
    ceiling, `>=0.1.0a100,<0.2` would carry an explicit one, and either would
    make "install exactly the floor" a different question from "install the
    minimum a consumer's resolver may choose". The floor lane's whole claim is
    that those are the same version.
    """
    constraint = declared_constraint(pyproject)
    match = _LOWER_BOUND.fullmatch(constraint.strip())
    if match is None:
        raise FloorError(
            f"{DEPENDENCY} is declared as {constraint!r}. This module reads a "
            "bare lower bound (`>=<version>`) and nothing else: an upper "
            "bound, a caret or a second clause each change what 'the declared "
            "minimum' means, and the floor lane installs that minimum "
            "literally. Extend this deliberately if the constraint shape "
            "changes."
        )
    floor = match.group(1)
    parse(floor)  # refuse an unorderable floor here rather than downstream
    return floor


def kernel_imports(package: Path = PACKAGE) -> set[str]:
    """Every `dotmac_kernel.*` module the package imports, at any depth.

    Parsed, never grepped: a substring scan over the source would be satisfied
    by the prose in a docstring, and this repository has tripped over exactly
    that four times.
    """
    found: set[str] = set()
    for path in sorted(package.rglob("*.py")):
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


def floor_symbol(pyproject: Path = PYPROJECT, package: Path = PACKAGE) -> str:
    """The one kernel submodule whose introduction SETS the declared floor.

    The mutation lane needs this name, because "the canaries failed" is not the
    proof — "the canaries failed for the reason the floor is declared" is. A
    literal in `ci.yml` would be a second authority for it, drifting the moment
    the floor moves, and the drift would be invisible: the lane would report the
    boundary proven on a run that observed some other breakage.

    So it is DERIVED, and it refuses rather than guessing in all three ways it
    can be wrong:

    * no recorded module introduced this floor — the floor names a version
      nothing in the table justifies;
    * more than one did — "the symbol the floor is set by" is not one name;
    * the package no longer imports it — the row outlived its import, and the
      grep would then require a failure that can never happen.
    """
    floor = declared_floor(pyproject)
    candidates = sorted(m for m, v in FIRST_SHIPPED_IN.items() if v == floor)
    if not candidates:
        raise FloorError(
            f"no recorded kernel submodule first shipped in {floor}, which is "
            "the declared floor. Either the floor was raised without recording "
            "the import that justifies it, or the row that justified it was "
            "deleted. FIRST_SHIPPED_IN records "
            f"{sorted(FIRST_SHIPPED_IN.items())}."
        )
    if len(candidates) > 1:
        raise FloorError(
            f"{candidates} all first shipped in {floor}, so 'the symbol the "
            "floor is set by' is not one name. The mutation lane greps for a "
            "single module; pick the one the floor is declared for and record "
            "the others differently."
        )
    symbol = candidates[0]
    imported = kernel_imports(package)
    if symbol not in imported:
        raise FloorError(
            f"the declared floor {floor} is justified by {symbol}, which the "
            f"package no longer imports (it imports {sorted(imported)}). The "
            "mutation lane would then require a failure that cannot occur. "
            "Lower the floor and remove the row in the same change."
        )
    return symbol


def index_versions(html: str) -> list[str]:
    """Every kernel version the index listing names, deduplicated and ordered.

    Read from the index rather than from a literal, because the question the
    mutation lane asks is about what a resolver could actually be handed. A
    hard-coded "the alpha below" would name a version that may never have been
    published, and the lane would then fail on a resolver error while
    reporting that the floor was proven.
    """
    versions = {match.group(1) for match in _INDEX_FILE.finditer(html)}
    return sorted(versions, key=parse)


def newest_excluded(floor: str, versions: list[str]) -> str:
    """The highest published kernel STRICTLY BELOW the floor.

    This is the mutation target, and the choice of "highest below" rather than
    "any below" is the point: it is the closest possible near-miss, so a floor
    set one alpha too high is caught. Something far below would fail for a
    dozen reasons and prove only that ancient kernels are ancient.
    """
    key = parse(floor)
    below = [v for v in versions if parse(v) < key]
    if not below:
        raise FloorError(
            f"the index lists no {DEPENDENCY} version below the declared floor "
            f"{floor}, so there is nothing the floor can be shown to exclude. "
            "The mutation lane must fail here rather than pass over an empty "
            "set: a canary nobody has seen refuse is not a canary."
        )
    return max(below, key=parse)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "what",
        choices=("declared", "excluded", "symbol"),
        help=(
            "`declared` prints the exact minimum kernel the distribution "
            "declares. `excluded` prints the newest kernel on the index that "
            "the floor refuses, which is the mutation target. `symbol` prints "
            "the kernel submodule whose introduction sets that floor, which is "
            "the name the mutation's failure must carry."
        ),
    )
    parser.add_argument("--pyproject", type=Path, default=PYPROJECT)
    parser.add_argument(
        "--index-html",
        type=Path,
        help=(
            "the simple-index listing for dotmac-kernel, already fetched. "
            "Required for `excluded`; this module performs no network I/O of "
            "its own, so the credential stays in the step that owns it."
        ),
    )
    args = parser.parse_args(argv)

    try:
        floor = declared_floor(args.pyproject)
        if args.what == "declared":
            print(floor)
            return 0
        if args.what == "symbol":
            print(floor_symbol(args.pyproject))
            return 0
        if args.index_html is None:
            raise FloorError("`excluded` requires --index-html")
        versions = index_versions(
            args.index_html.read_text(encoding="utf-8", errors="replace")
        )
        if not versions:
            raise FloorError(
                f"{args.index_html} names no {DEPENDENCY} version at all. An "
                "empty listing reads as 'nothing is excluded', which is the "
                "absent-as-success shape this repository refuses everywhere."
            )
        print(newest_excluded(floor, versions))
        return 0
    except FloorError as exc:
        print(f"error {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
