"""`attestation_binding.py` is read-only -- proved, not merely asserted.

## The defect this file closes

An independent security review of PR #51 found the module's own docstring
made its BROADEST security claim -- that no function here writes to the
registry or mutates the session -- and attributed that claim to exactly this
file, which did not exist. The property held by inspection; nothing enforced
it, so a future edit adding a direct `enrol_root`/`rotate_root`/`revoke_root`
call, or a raw `db.add`/`db.flush`/`db.commit`/`db.execute`, would have been
caught by NOTHING -- `test_attestation_binding_never_reconciles.py` scans
only for `reconcile_current_root`/`repair_current_root`, a narrower and
different property (never repairs drift on the read path, not "never writes
at all"). This is the sharpest instance of a class of defect this programme
has spent real time hunting: prose asserting test coverage that does not
exist, on a security-load-bearing property.

## What is scanned, and the acknowledged limitation

Two forbidden call shapes, matched by call-target NAME (not by
receiver-type inference -- the same heuristic
`test_attestation_binding_never_reconciles.py`'s reconciliation scan
already uses, and the same limitation it already accepts: a hypothetical
unrelated function also named `enrol_root` or a method named `.add` on an
unrelated object would also be flagged. That is a FALSE-POSITIVE risk this
module's actual, narrow surface makes acceptable, not a gap in what the
guard is meant to catch):

1. **Writing registry callees** -- `enrol_root`, `rotate_root`,
   `revoke_root`, `repair_current_root` -- whether referenced bare or as
   `attestation_trust_registry.<name>(...)`, the exact two shapes this
   module's own sanctioned calls (`resolve_current_root`,
   `fingerprint_standing`) already use.
2. **Session-mutation methods** -- `.add`, `.flush`, `.commit`, `.execute`
   -- this module never legitimately calls ANY of these directly (it always
   delegates to the registry, which owns the `Session` it is handed), so
   all four are forbidden unconditionally here, not merely the
   INSERT/UPDATE/DELETE-shaped subset of `.execute` the module docstring's
   prose names -- a stricter guard than the claim it backs, deliberately.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "src" / "dotmac_deployment_control" / "attestation_binding.py"

_WRITING_REGISTRY_CALLEES = frozenset(
    {"enrol_root", "rotate_root", "revoke_root", "repair_current_root"}
)
_SESSION_MUTATION_METHODS = frozenset({"add", "flush", "commit", "execute"})
_FORBIDDEN = _WRITING_REGISTRY_CALLEES | _SESSION_MUTATION_METHODS


def _write_shaped_calls(source: str) -> list[str]:
    """Every `Call` node in `source` whose target -- bare name or
    `.attr` -- matches a forbidden writing-registry callee or
    session-mutation method. Pure over source text -- exercisable on a
    synthetic string, never only the real file, by the sensitivity tests
    below."""
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name: str | None = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name in _FORBIDDEN:
            offenders.append(name)
    return offenders


# ── non-vacuity against the real file ───────────────────────────────────────


def test_the_real_module_calls_no_writing_function_or_session_mutation() -> None:
    offenders = _write_shaped_calls(MODULE_PATH.read_text())
    assert offenders == []


# ── plants: every writing-registry callee ───────────────────────────────────


def test_the_scan_flags_a_bare_enrol_root_call() -> None:
    """PLANT (ADR-0018)."""
    planted = "def f(db, *, subject):\n    enrol_root(db, subject=subject)\n"
    assert _write_shaped_calls(planted) == ["enrol_root"]


def test_the_scan_flags_a_qualified_rotate_root_call() -> None:
    """PLANT: the same shape this module's OWN sanctioned calls use
    (`attestation_trust_registry.resolve_current_root(...)`), but naming a
    WRITING function instead."""
    planted = (
        "def f(db, *, subject):\n"
        "    attestation_trust_registry.rotate_root(db, subject=subject)\n"
    )
    assert _write_shaped_calls(planted) == ["rotate_root"]


def test_the_scan_flags_a_revoke_root_call() -> None:
    """PLANT."""
    planted = (
        "def f(db, *, fingerprint):\n    revoke_root(db, fingerprint=fingerprint)\n"
    )
    assert _write_shaped_calls(planted) == ["revoke_root"]


def test_the_scan_flags_a_repair_current_root_call() -> None:
    """PLANT: the drift-REPAIR path specifically -- this module must never
    "helpfully" repair on the read path, the same property
    `test_attestation_binding_never_reconciles.py` already proves for THIS
    exact function, restated here as one instance of the broader
    write-shaped-call family."""
    planted = (
        "def f(db, *, subject):\n"
        "    repair_current_root(db, custody_domain='x', subject=subject)\n"
    )
    assert _write_shaped_calls(planted) == ["repair_current_root"]


# ── plants: every session-mutation method ───────────────────────────────────


def test_the_scan_flags_session_add() -> None:
    """PLANT."""
    planted = "def f(db, row):\n    db.add(row)\n"
    assert _write_shaped_calls(planted) == ["add"]


def test_the_scan_flags_session_flush() -> None:
    """PLANT."""
    planted = "def f(db):\n    db.flush()\n"
    assert _write_shaped_calls(planted) == ["flush"]


def test_the_scan_flags_session_commit() -> None:
    """PLANT."""
    planted = "def f(db):\n    db.commit()\n"
    assert _write_shaped_calls(planted) == ["commit"]


def test_the_scan_flags_session_execute() -> None:
    """PLANT: flagged unconditionally, even though the module docstring's
    prose only names the INSERT/UPDATE/DELETE-shaped subset -- this module
    has no legitimate call to `.execute` at all, so the guard is stricter
    than the claim it backs, deliberately (see module docstring)."""
    planted = 'def f(db):\n    db.execute("select 1")\n'
    assert _write_shaped_calls(planted) == ["execute"]


def test_the_scan_flags_every_forbidden_shape_in_one_pass() -> None:
    """Combined plant: all eight forbidden names in one function, proving
    the scan does not stop after the first match."""
    planted = (
        "def f(db, *, subject, fingerprint):\n"
        "    enrol_root(db, subject=subject)\n"
        "    rotate_root(db, subject=subject)\n"
        "    revoke_root(db, fingerprint=fingerprint)\n"
        "    repair_current_root(db, subject=subject)\n"
        "    db.add(None)\n"
        "    db.flush()\n"
        "    db.commit()\n"
        "    db.execute(None)\n"
    )
    assert sorted(_write_shaped_calls(planted)) == sorted(_FORBIDDEN)


# ── near-misses: the module's own sanctioned, read-only calls ──────────────


def test_the_scan_does_not_flag_resolve_current_root() -> None:
    """NEAR-MISS: this module's actual sanctioned call, qualified exactly as
    the real file writes it -- must not be flagged, or every real run of
    this guard fails on the module's own legitimate read."""
    sanctioned = (
        "def resolve_attestation_binding(db, *, custody_domain, subject):\n"
        "    return attestation_trust_registry.resolve_current_root(\n"
        "        db, custody_domain=custody_domain, subject=subject\n"
        "    )\n"
    )
    assert _write_shaped_calls(sanctioned) == []


def test_the_scan_does_not_flag_fingerprint_standing() -> None:
    """NEAR-MISS: this module's other sanctioned call."""
    sanctioned = (
        "def resolve_fingerprint_standing(db, *, fingerprint):\n"
        "    return attestation_trust_registry.fingerprint_standing(\n"
        "        db, fingerprint=fingerprint\n"
        "    )\n"
    )
    assert _write_shaped_calls(sanctioned) == []


def test_the_scan_does_not_flag_an_ordinary_read_only_session_method() -> None:
    """NEAR-MISS: `Session.get` (an ordinary, non-mutating ORM read, used
    throughout this repository's own test suite) must not be flagged --
    proving the scan targets the specific mutating method NAMES, not every
    method called on something that might be a session."""
    read_only = "def f(db, key):\n    return db.get(SomeModel, key)\n"
    assert _write_shaped_calls(read_only) == []
