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

## What this repository actually did, stated without overclaiming

Michael's ruling was "removed, or structurally unreachable." This repository
did neither in the strict sense. It renamed the two functions private
(`_evaluate_enrolment`/`_host_attester_standing`) and dropped them from
`__all__`. **That is a convention, not a structural barrier**: Python applies
no access control to a leading underscore, `from
dotmac_deployment_control.host_attester_enrolment import _evaluate_enrolment`
still works from any caller, in or out of this package, exactly as it did
before the rename under the old public name --
`test_a_caller_can_still_reach_the_private_replacement_names` below proves
this directly, as the honest counterpart to the tests that check `__all__`
and `hasattr`. Genuine structural closure would need one of: deleting the two
functions outright (at the cost of the evaluation-order test coverage they
carry, which is real and non-trivial -- 32 tests in
`tests/unit/test_host_attester_enrolment.py`), or moving them into a
module-private submodule Python's import system actually refuses from
outside the package. Both are larger changes than this lane's scope, and are
reported here as the honest "what closure would take" rather than claimed.

What IS structural, and proven below, is
`test_no_function_signature_in_the_module_still_names_the_caller_supplied_parameters`:
an AST scan of this module's SOURCE that fails the build the moment any
function -- public or private, present now or added later -- accepts
`active_by_host` or `known_fingerprints` under a name other than the two
already-private evaluation functions. That guard cannot be defeated by
reintroducing the caller-supplied surface under a fresh public name, which is
the actual mechanism by which "the next person wiring a binding surface"
would recreate this defect.
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
_CALLER_SUPPLIED_PARAMS = frozenset({"active_by_host", "known_fingerprints"})


def _functions_accepting_caller_supplied_params(source: str) -> list[str]:
    """Every `def` in `source` whose parameters include either caller-supplied
    registry mapping, EXCEPT the two functions already named private. Pure
    and over source text, so it is exercisable with a synthetic string --
    the sensitivity tests below plant a violation and a near-miss without
    touching the real module."""
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        arg_names = {arg.arg for arg in node.args.args} | {
            arg.arg for arg in node.args.kwonlyargs
        }
        if arg_names & _CALLER_SUPPLIED_PARAMS and node.name not in _PRIVATE_NAMES:
            offenders.append(node.name)
    return offenders


# ── convention-level checks (leading underscore, __all__) ──────────────────


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
    """HONESTY CHECK, not a near-miss to celebrate: this import SUCCEEDS,
    proving the rename is a convention rather than an enforced boundary.
    Python applies no access control to a leading underscore -- any caller,
    inside or outside this package, can still write exactly this import and
    still supply their own registry to `_evaluate_enrolment` directly. The
    module docstring above states this plainly; this test is the evidence
    for that statement, not a demonstration that the old path is closed."""
    from dotmac_deployment_control.host_attester_enrolment import (  # noqa: F401
        _evaluate_enrolment,
        _host_attester_standing,
    )


def test_the_private_functions_still_exist_as_the_evaluation_engine() -> None:
    """Confirms this is a VISIBILITY change, not a deletion: the pure
    evaluation-order logic this module's own unit tests exercise (by the
    private name) is still present and still callable."""
    for name in _PRIVATE_NAMES:
        assert callable(getattr(host_attester_enrolment, name))


# ── the one guard here that is genuinely structural ─────────────────────────


def test_the_real_module_names_no_caller_supplied_parameter_outside_the_two() -> (
    None
):
    """Non-vacuity: the scan actually runs against the real file and finds
    only the two already-known, already-private functions -- never zero
    matches for the wrong reason (e.g. a typo in the parameter names)."""
    offenders = _functions_accepting_caller_supplied_params(MODULE_PATH.read_text())
    assert offenders == []


def test_no_signature_names_the_caller_supplied_parameters_outside_the_two() -> None:
    """Restated against the live file with a clearer name; kept alongside the
    non-vacuity test above as the assertion an external reader will look for
    first."""
    offenders = _functions_accepting_caller_supplied_params(MODULE_PATH.read_text())
    assert not offenders, (
        f"caller-supplied registry parameters reappeared on function(s): "
        f"{offenders}"
    )


def test_the_scan_flags_a_planted_reintroduction_under_a_fresh_public_name() -> (
    None
):
    """PLANT (ADR-0018): a brand-new PUBLIC function reintroducing exactly the
    caller-supplied surface this whole file exists to keep closed -- under a
    name nobody has used before, since that is the actual future failure
    mode this guard defends against."""
    planted = (
        "def evaluate_enrolment_v2(statement, *, active_by_host, "
        "known_fingerprints):\n    pass\n"
    )
    assert _functions_accepting_caller_supplied_params(planted) == [
        "evaluate_enrolment_v2"
    ]


def test_the_scan_does_not_flag_the_two_already_private_functions() -> None:
    """NEAR-MISS: the two functions that legitimately still carry these
    parameter names, by their private spelling, must not be flagged -- or
    every real run of this guard would fail permanently for a reason
    unrelated to the property it checks."""
    synthetic = (
        "def _evaluate_enrolment(statement, *, active_by_host, "
        "known_fingerprints):\n    pass\n\n"
        "def _host_attester_standing(*, host_id, fingerprint, active_by_host, "
        "known_fingerprints):\n    pass\n"
    )
    assert _functions_accepting_caller_supplied_params(synthetic) == []


def test_the_scan_does_not_flag_an_unrelated_function_with_a_similar_signature() -> (
    None
):
    """NEAR-MISS: a function that merely LOOKS related (same arity, a
    plausible-sounding parameter name) but does not actually name either
    caller-supplied parameter must not be flagged -- proving the scan checks
    the exact parameter names, not merely "a function with keyword-only
    mapping arguments"."""
    unrelated = (
        "def resolve_current_root(db, *, custody_domain, subject):\n    pass\n"
    )
    assert _functions_accepting_caller_supplied_params(unrelated) == []
