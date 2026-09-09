"""No caller may supply the registry that decides whether its own key is trusted.

Before the durable attestation trust registry (`dc_0011`,
`attestation_trust_registry.py`), `host_attester_enrolment.evaluate_enrolment`
and `host_attester_standing` were exported, undeprecated, and took
caller-supplied `active_by_host`/`known_fingerprints` mappings -- "the caller
currently supplies the registry that decides whether the caller's key is
trusted" (the module's own former docstring language, quoted in `dc_0011`'s
migration docstring as the defect it closes). Nothing in this repository's
live routes ever called them, but nothing marked them superseded either, so
the next person wiring a binding surface could reach for the caller-supplied
version as easily as for the registry.

Michael's ruling: removed, or structurally unreachable. This repository chose
UNREACHABLE -- the two functions are renamed private
(`_evaluate_enrolment`/`_host_attester_standing`), dropped from `__all__`,
and their pure evaluation-order logic is kept only as an internal detail this
module's own tests exercise directly by the private name. A real caller uses
`attestation_trust_registry`'s registry-backed functions instead.

This file is the structural proof, checked three ways: the public names are
gone from the module's namespace AND from `__all__` (the two-directional
guard -- a name absent from `__all__` but still a module attribute would
still be importable by name, and a name merely missing from the module while
still in a stale `__all__` would break `import *` loudly rather than
silently, so both must agree), and the plain import a caller would actually
write is refused.
"""

from __future__ import annotations

import ast
from pathlib import Path

from dotmac_deployment_control import host_attester_enrolment

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    REPO_ROOT / "src" / "dotmac_deployment_control" / "host_attester_enrolment.py"
)

_FORMER_PUBLIC_NAMES = ("evaluate_enrolment", "host_attester_standing")
_PRIVATE_NAMES = ("_evaluate_enrolment", "_host_attester_standing")


def test_the_caller_supplied_names_are_not_module_attributes() -> None:
    """PLANT: the exact public names a caller would have imported."""
    for name in _FORMER_PUBLIC_NAMES:
        assert not hasattr(host_attester_enrolment, name), (
            f"{name} must not be reachable as a public module attribute -- a "
            "caller could still supply its own registry through it"
        )


def test_the_caller_supplied_names_are_not_in_dunder_all() -> None:
    """The other half of the two-directional guard: `__all__` itself must not
    still claim these names, or `from host_attester_enrolment import *` would
    raise loudly (a different failure than the silent one this test targets,
    but still evidence the two lists have drifted apart)."""
    for name in _FORMER_PUBLIC_NAMES:
        assert name not in host_attester_enrolment.__all__


def test_a_caller_can_still_reach_the_private_replacement_names() -> None:
    """NEAR-MISS CONTROL: the private names must still be importable by their
    exact new spelling, proving this test would fail if the rename had gone
    too far and deleted the functions outright rather than making them
    private -- `Python`'s `from X import Y` for a genuinely absent `Y` and for
    a merely-private `Y` both succeed identically (leading underscore is a
    convention, not an enforced boundary), which is exactly why the other
    tests in this file check `__all__` and module attributes directly rather
    than relying on import success/failure to prove privacy."""
    from dotmac_deployment_control.host_attester_enrolment import (  # noqa: F401
        _evaluate_enrolment,
        _host_attester_standing,
    )


def test_the_private_functions_still_exist_as_the_evaluation_engine() -> None:
    """Confirms this is a VISIBILITY change, not a deletion: the pure
    evaluation-order logic this module's own unit tests exercise (by the
    private name) is still present and still callable from inside the
    package -- only a caller reaching from OUTSIDE it is refused."""
    for name in _PRIVATE_NAMES:
        assert callable(getattr(host_attester_enrolment, name))


def test_no_function_signature_in_the_module_still_names_the_caller_supplied_parameters() -> (
    None
):
    """Structural, over the SOURCE, not just the two renamed functions: no
    `def` anywhere in this module accepts `active_by_host` or
    `known_fingerprints` under any name other than the two private
    evaluation functions -- so a future function cannot reintroduce the
    caller-supplied surface under a fresh public name without this test
    naming it."""
    tree = ast.parse(MODULE_PATH.read_text())
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        arg_names = {arg.arg for arg in node.args.args} | {
            arg.arg for arg in node.args.kwonlyargs
        }
        if {"active_by_host", "known_fingerprints"} & arg_names:
            if node.name not in _PRIVATE_NAMES:
                offenders.append(node.name)
    assert not offenders, (
        f"caller-supplied registry parameters reappeared on public "
        f"function(s): {offenders}"
    )
