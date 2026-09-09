"""A caller of `attestation_binding.py` cannot name which root or identity to
resolve against -- extending `test_host_attester_enrolment_is_private.py`'s
sibling guard to this module.

## What "naming which root or identity" means here, concretely

The defect this whole registry closes (`attestation_trust_registry.py`'s own
docstring, and `host_attester_enrolment.py`'s "No table added here" section)
is a caller supplying the MAPPING that decides what is trusted --
`active_by_host`/`known_fingerprints` -- rather than the registry deriving it
from its own durable tables. `subject`/`custody_domain`/`fingerprint` as
plain LOOKUP KEYS are not that defect (the registry's own
`resolve_current_root(db, *, custody_domain, subject)` is the sanctioned
shape -- confirmed by
`test_host_attester_enrolment_is_private.py::test_the_scan_does_not_flag_an_unrelated_function_with_a_similar_signature`,
whose near-miss is exactly that signature). What must be structurally
impossible is:

1. A function parameter through which a caller could supply the two
   caller-side mapping names, or any equivalently-shaped "here is the
   registry" argument.
2. A module-level MUTABLE container (a dict/list/set a caller could import
   and mutate to inject a root or an identity from outside this module's
   control flow) -- the in-memory-authority failure mode restated as data
   rather than a parameter.

Both are proved by AST scans over source text, exercisable with synthetic
strings so the sensitivity plants and near-misses below never touch the real
file.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "src" / "dotmac_deployment_control" / "attestation_binding.py"

_CALLER_SUPPLIED_PARAMS = frozenset({"active_by_host", "known_fingerprints"})


def _functions_accepting_caller_supplied_params(source: str) -> list[str]:
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        arg_names = {arg.arg for arg in node.args.args} | {
            arg.arg for arg in node.args.kwonlyargs
        }
        if arg_names & _CALLER_SUPPLIED_PARAMS:
            offenders.append(node.name)
    return offenders


def _module_level_mutable_assignments(source: str) -> list[str]:
    """Every module-level (top-of-file, not inside a function or class) name
    assigned a mutable literal (dict/list/set) -- a candidate for a
    caller-mutable "registry" a consumer could reach around this module's
    functions to poke directly. A `frozenset(...)`/tuple literal is a
    `Call`/`Tuple` AST node, never `Dict`/`List`/`Set`, so an immutable
    constant like `_EXPECTED_KEYS: Final[frozenset[str]] = frozenset({...})`
    is correctly not flagged -- proven by the near-miss below."""
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        else:
            continue
        if not isinstance(value, ast.Dict | ast.List | ast.Set):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and not (
                target.id.startswith("__") and target.id.endswith("__")
            ):
                # Dunder module attributes (`__all__`) are a Python-level
                # convention, not a caller-reachable trust registry -- a
                # module's export list is a list literal by necessity and is
                # not what this guard is about.
                offenders.append(target.id)
    return offenders


# ── caller-supplied mapping parameters ──────────────────────────────────────


def test_the_real_module_names_no_caller_supplied_registry_parameter() -> None:
    offenders = _functions_accepting_caller_supplied_params(MODULE_PATH.read_text())
    assert offenders == []


def test_the_scan_flags_a_planted_caller_supplied_parameter() -> None:
    """PLANT (ADR-0018): a brand-new function reintroducing the exact
    caller-supplied-mapping surface this whole package closed, under a name
    nobody has used before."""
    planted = (
        "def resolve_attestation_binding_v2(db, *, active_by_host, "
        "known_fingerprints):\n    pass\n"
    )
    assert _functions_accepting_caller_supplied_params(planted) == [
        "resolve_attestation_binding_v2"
    ]


def test_the_scan_does_not_flag_the_sanctioned_lookup_key_signature() -> None:
    """NEAR-MISS: the actual, sanctioned shape -- a plain subject/custody
    lookup key, never a caller-supplied registry mapping -- must not be
    flagged, matching the sibling guard's own near-miss for
    `resolve_current_root`."""
    sanctioned = (
        "def resolve_attestation_binding(db, *, custody_domain, subject):\n"
        "    pass\n"
    )
    assert _functions_accepting_caller_supplied_params(sanctioned) == []


# ── module-level mutable "registry" ─────────────────────────────────────────


def test_the_real_module_declares_no_mutable_module_level_registry() -> None:
    offenders = _module_level_mutable_assignments(MODULE_PATH.read_text())
    assert offenders == []


def test_the_scan_flags_a_planted_module_level_mutable_registry() -> None:
    """PLANT: a module-level dict a caller could import and mutate directly,
    reintroducing an in-memory, caller-reachable authority outside any
    function's control flow -- the shape a plain parameter scan would miss
    entirely."""
    planted = "_TRUSTED_ROOTS = {}\n"
    assert _module_level_mutable_assignments(planted) == ["_TRUSTED_ROOTS"]


def test_the_scan_does_not_flag_dunder_all() -> None:
    """NEAR-MISS: `__all__` is a list literal by Python convention, present
    in the real module, and is not a caller-reachable trust registry."""
    synthetic = "__all__ = ['resolve_attestation_binding']\n"
    assert _module_level_mutable_assignments(synthetic) == []


def test_the_scan_does_not_flag_an_immutable_module_level_constant() -> None:
    """NEAR-MISS: the module's REAL module-level constant
    (`_EXPECTED_KEYS: Final[frozenset[str]] = frozenset({...})`) is a `Call`
    node (a call to `frozenset`), never a `Dict`/`List`/`Set` literal, and
    must not be flagged -- or every real run of this guard fails on the
    module's own legitimate, immutable constant."""
    synthetic = (
        "from typing import Final\n"
        "_EXPECTED_KEYS: Final[frozenset[str]] = frozenset({'a', 'b'})\n"
    )
    assert _module_level_mutable_assignments(synthetic) == []


# ── exact public signatures, restated as a direct, non-scanned assertion ───


def test_resolve_attestation_binding_accepts_only_a_session_and_two_lookup_keys() -> (
    None
):
    from dotmac_deployment_control.attestation_binding import (
        resolve_attestation_binding,
    )

    signature = inspect.signature(resolve_attestation_binding)
    assert set(signature.parameters) == {"db", "custody_domain", "subject"}
    for name in ("custody_domain", "subject"):
        assert signature.parameters[name].kind == inspect.Parameter.KEYWORD_ONLY


def test_resolve_fingerprint_standing_accepts_only_a_session_and_a_fingerprint() -> (
    None
):
    from dotmac_deployment_control.attestation_binding import (
        resolve_fingerprint_standing,
    )

    signature = inspect.signature(resolve_fingerprint_standing)
    assert set(signature.parameters) == {"db", "fingerprint"}
    assert signature.parameters["fingerprint"].kind == inspect.Parameter.KEYWORD_ONLY
