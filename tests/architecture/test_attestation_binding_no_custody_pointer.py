"""`key_custody_pointer` is unreachable through `AttestationBindingV1` --
proved by construction, not by convention.

## Why "the field is merely absent today" is not the guarantee wanted

A dataclass that simply happens not to list `key_custody_pointer` today could
grow it tomorrow with a one-line edit and no test would notice, because
nothing here would have changed shape in a way a `hasattr`-style check
catches after the fact. Three independent, STRUCTURAL proofs instead:

1. **Exact field allowlist, not a blocklist.** `dataclasses.fields()` is
   compared against the COMPLETE expected set with `==`, not
   `"key_custody_pointer" not in {...}`. Adding ANY new field --
   `key_custody_pointer` or anything else -- fails this test until the
   allowlist is deliberately updated, which is the two-directional ratchet
   ADR-0018 asks for: the guard also fails if a field silently disappears.
2. **`slots=True` makes the field set the actual, runtime attribute
   namespace.** `AttestationBindingV1` is declared `@dataclass(frozen=True,
   slots=True)`, so Python allocates NO `__dict__` for its instances --
   `setattr(binding, "key_custody_pointer", "bao://...")` does not silently
   succeed and get ignored by `fields()`; it raises `AttributeError` at the
   interpreter level, because there is no slot for that name. This is the
   "prove it by construction" half: it holds even against code that never
   went through this module's own constructor logic at all.
3. **AST scan over executable code** for a CONSUMPTION of the column --
   an attribute access, a `getattr` call, or a string used as a lookup key
   naming `key_custody_pointer` -- as a second, independent signal that
   catches a hypothetical future reference to the column (e.g. reading it
   from the registry's `AttestationEnrolment` row and stashing it under a
   differently-named field) that (1) and (2) alone would not.

## Content versus consumption -- the defect this file's first version had

The first version of this scan matched the LITERAL STRING anywhere in the
module's source text, docstrings included. `attestation_binding.py`'s own
module docstring names `key_custody_pointer` five times, BY DESIGN -- it
tells a reader precisely which column is excluded and why, which is the
documentation working, not a violation. A text scan cannot tell "the module
NAMES this column, in prose" from "the module READS this column, in code",
so it flagged the module's own explanation of its own guarantee as the
guarantee's violation -- a self-refuting assertion (the sentence stating the
literal appears nowhere WAS an occurrence of the literal).

Michael's ruling: "do not obscure the strings" -- rewriting the docstring
to dodge the identifier is the wrong fix. The scan below is AST-based over
EXECUTABLE code only (`ast.Attribute`, `getattr(...)`, and a string
`ast.Constant` used as a value, keyed lookup, or keyword name), with the
module's own docstrings and every function/class docstring explicitly
excluded by AST position -- not by any text heuristic that could mistake a
comment for code or vice versa (comments are never part of the AST at all,
so they are excluded structurally, by construction). The property enforced
is CONSUMPTION: does executable code in this module read
`AttestationEnrolment.key_custody_pointer`. A docstring cannot read a
column.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "src" / "dotmac_deployment_control" / "attestation_binding.py"

_EXPECTED_BINDING_FIELDS = frozenset(
    {
        "custody_domain",
        "subject",
        "public_key_fingerprint",
        "public_key_b64",
        "algorithm",
        "enrolled_at",
        "standing",
    }
)


_TARGET = "key_custody_pointer"


def _docstring_constant_ids(tree: ast.Module) -> set[int]:
    """The `id()` of every AST `Constant` node that IS a docstring -- the
    first statement of a module/class/function body, when that statement is
    a bare string expression. Comments are never part of the AST at all
    (Python's tokenizer discards them before `ast.parse` ever sees the
    source), so they need no exclusion here; only docstrings do, since they
    ARE ordinary `Constant` nodes structurally indistinguishable from any
    other string literal except by their POSITION."""
    docstring_ids: set[int] = set()

    def _mark_if_docstring(body: list[ast.stmt]) -> None:
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            docstring_ids.add(id(body[0].value))

    _mark_if_docstring(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            _mark_if_docstring(node.body)
    return docstring_ids


def _consumes_key_custody_pointer(source: str) -> bool:
    """AST scan over EXECUTABLE code only -- docstrings excluded by AST
    position, comments excluded structurally (never part of the AST).
    Flags a CONSUMPTION of the column: an attribute access
    (`enrolment.key_custody_pointer`), a `getattr(x, "key_custody_pointer")`
    call, a string used as a subscript/dict lookup key
    (`row["key_custody_pointer"]`), or a keyword argument named
    `key_custody_pointer` passed to a call -- never a docstring or comment
    naming the column in prose. Pure over source text -- exercisable on a
    synthetic string, never only the real file, by the sensitivity tests
    below."""
    tree = ast.parse(source)
    docstring_ids = _docstring_constant_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == _TARGET:
            return True
        if isinstance(node, ast.keyword) and node.arg == _TARGET:
            return True
        if (
            isinstance(node, ast.Constant)
            and node.value == _TARGET
            and id(node) not in docstring_ids
        ):
            return True
    return False


# ── field allowlist: exact set, both directions ─────────────────────────────


def test_the_binding_carries_exactly_the_allowed_fields() -> None:
    from dotmac_deployment_control.attestation_binding import AttestationBindingV1

    names = {field.name for field in dataclasses.fields(AttestationBindingV1)}
    assert names == _EXPECTED_BINDING_FIELDS


def test_key_custody_pointer_is_not_among_the_fields() -> None:
    """Restated as the assertion an external reader looks for first."""
    from dotmac_deployment_control.attestation_binding import AttestationBindingV1

    names = {field.name for field in dataclasses.fields(AttestationBindingV1)}
    assert "key_custody_pointer" not in names


# ── slots: attribute-level impossibility, not merely field-list absence ────


def test_the_binding_has_no_instance_dict_at_all() -> None:
    """`slots=True` means an instance has NO `__dict__` -- there is nowhere
    for an arbitrary attribute, including a resurrected
    `key_custody_pointer`, to be silently stored."""
    from datetime import UTC, datetime

    from dotmac_deployment_control.attestation_binding import AttestationBindingV1
    from dotmac_deployment_control.host_attester_enrolment import HostAttesterStanding

    binding = AttestationBindingV1(
        custody_domain="host_attester",
        subject="host-slots-dict-check",
        public_key_fingerprint="sha256:" + "cd" * 32,
        public_key_b64="YmFy",
        algorithm="ed25519",
        enrolled_at=datetime(2026, 9, 9, tzinfo=UTC),
        standing=HostAttesterStanding.VALID,
    )
    assert not hasattr(binding, "__dict__")


def test_a_custody_pointer_attribute_cannot_be_attached_after_construction() -> None:
    """PLANT AND SENSITIVITY CONTROL IN ONE: attempting exactly the attack a
    convention-only guarantee would not catch -- bolting the pointer onto an
    already-constructed instance. `slots=True` makes this an `AttributeError`
    at the interpreter level, never a silent success `fields()` would miss."""
    from datetime import UTC, datetime

    from dotmac_deployment_control.attestation_binding import AttestationBindingV1
    from dotmac_deployment_control.host_attester_enrolment import HostAttesterStanding

    binding = AttestationBindingV1(
        custody_domain="host_attester",
        subject="host-slots-check",
        public_key_fingerprint="sha256:" + "ab" * 32,
        public_key_b64="Zm9v",
        algorithm="ed25519",
        enrolled_at=datetime(2026, 9, 9, tzinfo=UTC),
        standing=HostAttesterStanding.VALID,
    )
    with pytest.raises(AttributeError):
        object.__setattr__(binding, "key_custody_pointer", "bao://secret/x")


# ── AST scan: non-vacuity, three consumption plants, three exemption near-misses ──


def test_the_real_module_never_consumes_key_custody_pointer_in_executable_code() -> (
    None
):
    """Non-vacuity, against the REAL file. The module's own docstrings DO
    name `key_custody_pointer` (five times, by design -- see the module
    docstring's own explanation of why); this assertion is about
    EXECUTABLE CODE only, and passes precisely because the AST-position
    exclusion below correctly treats prose as prose."""
    assert _consumes_key_custody_pointer(MODULE_PATH.read_text()) is False


def test_the_scan_flags_an_attribute_access() -> None:
    """PLANT (ADR-0018), restated over AST: a hypothetical future line
    reading the column via ordinary attribute access, under a different
    local variable name -- the scan must catch the COLUMN NAME itself,
    regardless of what it is assigned to. This is the exact plant the
    original text-based scan used; it must still bite unchanged."""
    planted = "pointer = enrolment.key_custody_pointer  # a future regression\n"
    assert _consumes_key_custody_pointer(planted) is True


def test_the_scan_flags_a_getattr_call() -> None:
    """PLANT: dynamic access via `getattr` must be caught too, not only
    literal dotted-attribute syntax -- both are equally a column read."""
    planted = 'pointer = getattr(enrolment, "key_custody_pointer")\n'
    assert _consumes_key_custody_pointer(planted) is True


def test_the_scan_flags_a_string_used_as_a_query_column_key() -> None:
    """PLANT: the case the move to AST must NOT let slip through. A string
    literal used as a subscript/mapping lookup key -- e.g. reading a raw SQL
    row by column name -- is exactly as much a consumption as attribute
    access, and does not involve `ast.Attribute` at all."""
    planted = 'pointer = row["key_custody_pointer"]\n'
    assert _consumes_key_custody_pointer(planted) is True


def test_the_scan_flags_a_keyword_argument_named_for_the_column() -> None:
    """PLANT: passing the column through as a keyword argument -- e.g.
    forwarding it into another call -- is also a consumption; caught via
    `ast.keyword.arg`, which is not a `Constant` node at all."""
    planted = "enrol_root(db, key_custody_pointer=pointer_value)\n"
    assert _consumes_key_custody_pointer(planted) is True


def test_the_scan_does_not_flag_a_module_docstring_naming_the_column() -> None:
    """NEAR-MISS, THE ONE THIS FILE EXISTS TO ADD: a module docstring that
    names the column in prose -- exactly the shape that made the original
    text-based scan flag `attestation_binding.py`'s own explanation of its
    guarantee as the guarantee's violation. Naming is not reading."""
    planted = (
        '"""This module never reads key_custody_pointer -- see below."""\n'
        "\n"
        "x = 1\n"
    )
    assert _consumes_key_custody_pointer(planted) is False


def test_the_scan_does_not_flag_a_function_docstring_naming_the_column() -> None:
    """NEAR-MISS: the same exemption applies to a function's own docstring,
    not only the module's -- the AST-position rule is general, not a
    special case for line 1 of the file."""
    planted = (
        "def resolve_something():\n"
        '    """Never touches key_custody_pointer."""\n'
        "    return None\n"
    )
    assert _consumes_key_custody_pointer(planted) is False


def test_the_scan_does_not_flag_a_comment_naming_the_column() -> None:
    """NEAR-MISS: a comment naming the column. Comments are stripped before
    `ast.parse` ever sees the source, so this is exempt structurally --
    there is no AST node for a comment to be flagged as, which is a
    stronger guarantee than a text-based exclusion rule could offer."""
    planted = "x = 1  # never reads key_custody_pointer\n"
    assert _consumes_key_custody_pointer(planted) is False


def test_the_scan_does_not_flag_an_unrelated_pointer_field() -> None:
    """NEAR-MISS: a similarly-named but genuinely different field must not be
    flagged, proving the scan checks the exact column name rather than any
    string containing the word "pointer" or "custody"."""
    unrelated = (
        "algorithm_pointer = enrolment.algorithm\n"
        "custody_domain = enrolment.custody_domain\n"
    )
    assert _consumes_key_custody_pointer(unrelated) is False
