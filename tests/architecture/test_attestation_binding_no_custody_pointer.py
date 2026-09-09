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
3. **Source-text scan** for the literal string `key_custody_pointer`
   anywhere in the module, as a second, independent signal -- catches a
   hypothetical future reference to the column (e.g. reading it from the
   registry's `AttestationEnrolment` row and stashing it under a
   differently-named field) that (1) and (2) alone would not.
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


def _contains_literal_key_custody_pointer(source: str) -> bool:
    """Pure text scan -- exercisable on a synthetic string, never only the
    real file, by the sensitivity tests below."""
    ast.parse(source)  # non-vacuity: source must at least be valid Python
    return "key_custody_pointer" in source


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


# ── source-text scan: non-vacuity + sensitivity plant + near-miss ──────────


def test_the_real_module_never_names_key_custody_pointer() -> None:
    assert _contains_literal_key_custody_pointer(MODULE_PATH.read_text()) is False


def test_the_scan_flags_a_planted_reference_to_the_pointer() -> None:
    """PLANT (ADR-0018): a hypothetical future line reading the column under
    a different local variable name -- the scan must catch the COLUMN NAME
    itself, regardless of what it is assigned to."""
    planted = "pointer = enrolment.key_custody_pointer  # a future regression\n"
    assert _contains_literal_key_custody_pointer(planted) is True


def test_the_scan_does_not_flag_an_unrelated_pointer_field() -> None:
    """NEAR-MISS: a similarly-named but genuinely different field must not be
    flagged, proving the scan checks the exact column name rather than any
    string containing the word "pointer" or "custody"."""
    unrelated = (
        "algorithm_pointer = enrolment.algorithm\n"
        "custody_domain = enrolment.custody_domain\n"
    )
    assert _contains_literal_key_custody_pointer(unrelated) is False
