"""No digest is compared as a STRING anywhere on the authorization path.

## The defect, in four lines of `0.1.0a4`

    service.py:305  snapshot_digest(...)  -> bare hex
    service.py:311  spec_digest(...)      -> "sha256:" + hex
    service.py:889  plan_digest=snapshot_digest(snapshot)
    service.py:974  if command.evidence.content_digest != row.plan_digest:

Two encodings of one kind of value, ten lines apart in one file, and a `!=`
between them at the point where an approval is authorized. A caller who supplied
the SAME digest in the OTHER encoding was told *"the plan changed after
approval, so a new approval is required"*.

## Why this is a static gate and not only a behavioural test

`tests/unit/test_plan_digest.py` and the installed-artifact canaries prove the
behaviour is right TODAY. Neither prevents the next `!=` between two digest
strings, and the reason a4 shipped is not that anybody thought string comparison
was correct — it is that nothing was watching the shape. So this file watches
the shape: it parses `service.py` and refuses any comparison whose operands are
digest-valued expressions rather than digest VALUES.

## The sensitivity proof

A structural gate over source is worth exactly what its detector is worth, so
the a4 expression is reconstructed and fed to the same detector at the bottom of
this file (ADR-0018). A check that has never been seen to reject anything is not
a check.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "src" / "dotmac_deployment_control"
SERVICE = PACKAGE / "service.py"
DIGESTS = PACKAGE / "digests.py"

#: Attribute names holding a digest THIS MODULE COMPUTES. A comparison between
#: two of these, or between one and anything else, is a comparison of digest
#: TEXT.
DIGEST_ATTRIBUTES = frozenset(
    {
        "plan_digest",
        "content_digest",
        "observed_spec_digest",
        # The FOUNDATION's execution plan digest, in all three of the places it
        # is held: what was proposed, what was authorized, and what a report
        # claims. This module does not compute it — which makes a string
        # comparison MORE dangerous here, not less. A value Control cannot
        # re-derive is a value it can only ever compare, so the comparison is
        # the entire control, and comparing the text would make one digest's
        # spellings disagree in the one place a disagreement is read as "the
        # executor ran something nobody authorized".
        "execution_plan_digest",
        "authorized_execution_plan_digest",
        # The exact inbound observation bytes and canonical receipt bytes are
        # now Control-computed values. They are no longer opaque caller tokens.
        "raw_body_digest",
        "payload_digest",
    }
)

#: Functions returning the canonical STRING rendering. Their result must not be
#: an operand of a comparison either — `snapshot_digest(x) == y` is the same
#: defect written with a call instead of an attribute.
DIGEST_TEXT_CALLS = frozenset({"snapshot_digest", "spec_digest"})

#: `digests.py` is where a digest legitimately becomes text and back, so its
#: own parsing internals are exempt — the exemption is one FILE with an
#: enforceable premise (it is the only place that may know the encoding), not a
#: blanket one.
EXEMPT = frozenset({DIGESTS.name})


def _is_digest_text(node: ast.expr) -> str | None:
    """The name of the digest-valued expression, or None."""
    if isinstance(node, ast.Attribute) and node.attr in DIGEST_ATTRIBUTES:
        return node.attr
    if isinstance(node, ast.Name) and node.id in DIGEST_ATTRIBUTES:
        return node.id
    if isinstance(node, ast.Call):
        func = node.func
        name = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else None
        )
        if name in DIGEST_TEXT_CALLS:
            return f"{name}()"
    # `row.plan_digest or ""` — the `or` does not launder the operand.
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            found = _is_digest_text(value)
            if found is not None:
                return found
    return None


def string_digest_comparisons(source: str) -> list[str]:
    """Every `==`/`!=` in `source` with a digest-TEXT operand."""
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, ast.Eq | ast.NotEq) for op in node.ops):
            continue
        for operand in [node.left, *node.comparators]:
            found = _is_digest_text(operand)
            if found is not None:
                offenders.append(f"line {node.lineno}: compares {found}")
    return offenders


# ── the live claim ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    sorted(p for p in PACKAGE.rglob("*.py") if p.name not in EXEMPT),
    ids=lambda p: p.name,
)
def test_no_module_compares_digest_text(path: Path) -> None:
    offenders = string_digest_comparisons(path.read_text(encoding="utf-8"))
    assert not offenders, (
        f"{path.name} compares digests as strings:\n  "
        + "\n  ".join(offenders)
        + "\nA digest is a value — `PlanDigestV1`/`SpecDigestV1` — and equality "
        "is over its bytes. Comparing the text makes one digest's two encodings "
        "unequal, and `approve_plan` reports that as a changed plan."
    )


def test_the_authorization_path_compares_two_typed_values() -> None:
    """The positive half. "No string comparison" is also satisfied by a
    function that compares NOTHING, which would authorize every approval — so
    the comparison must still be there, between two `PlanDigestV1` values."""
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    approve = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "approve_plan"
    )
    compares = [
        node
        for node in ast.walk(approve)
        if isinstance(node, ast.Compare)
        and any(isinstance(op, ast.NotEq | ast.Eq) for op in node.ops)
        and isinstance(node.left, ast.Name)
        and node.left.id in {"supplied", "frozen"}
    ]
    assert compares, (
        "approve_plan no longer compares the supplied digest with the frozen "
        "one. The binding is ADR-0026 § 2's, and removing it would authorize "
        "any plan under any approval."
    )
    assigned = {
        target.id
        for node in ast.walk(approve)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    assert {"supplied", "frozen"} <= assigned


def test_both_sides_are_produced_by_the_named_boundary_parsers() -> None:
    """A typed comparison built from `str(...)` on both sides would satisfy the
    gate above and reintroduce the defect. The two operands must come from the
    parsers that own the encoding."""
    source = SERVICE.read_text(encoding="utf-8")
    for helper in ("_frozen_plan_digest", "_supplied_plan_digest"):
        assert f"def {helper}(" in source, f"{helper} is gone"
        assert f"{helper}(" in source.split(f"def {helper}(", 1)[1], (
            f"{helper} is defined but never called, so the comparison is being "
            "built some other way"
        )
    assert "PlanDigestV1.parse_accepting_a4_bare_hex" in source


def test_the_legacy_encoding_is_normalized_only_inside_control() -> None:
    """Michael's constraint: Platform CP and the deployment foundation must not
    normalize a Control digest. If they did, there would be three parsers for
    one format and they would disagree — and the disagreement arrives as a
    false "the plan changed".

    Enforceable here as: the ONLY module that knows what a4's encoding looks
    like is `digests.py`, and the only callers of its legacy route are inside
    this package. A consumer cannot be tested from this repository, so the
    honest scope is stated rather than implied — what is checked is that
    Control offers the route and keeps the knowledge in one file.
    """
    knows_the_legacy_shape = [
        path.name
        for path in PACKAGE.rglob("*.py")
        if "[0-9a-f]{64}" in path.read_text(encoding="utf-8")
    ]
    assert knows_the_legacy_shape == [DIGESTS.name], (
        "more than one module knows how to recognise a bare-hex digest: "
        f"{knows_the_legacy_shape}. The parser is the contract; a second copy "
        "of it is a fork waiting to disagree."
    )


# ── the sensitivity proof (ADR-0018) ────────────────────────────────────────


def test_this_package_computes_digests_in_exactly_one_module() -> None:
    """THE PREMISE behind excluding the caller-supplied tokens above.

    If a second module started computing digests, the exclusion would stop
    being a statement about opaque tokens and become a hole. Checked, not
    asserted: `hashlib` must appear in `digests.py` and nowhere else.
    """
    computing = sorted(
        path.name
        for path in PACKAGE.rglob("*.py")
        if "hashlib" in path.read_text(encoding="utf-8")
    )
    assert computing == [DIGESTS.name], (
        f"{computing} compute digests. A new digest computed outside digests.py "
        "creates a second encoding authority and the gate must refuse it."
    )


def test_observation_body_and_receipt_digests_use_the_typed_boundary() -> None:
    """The a10 admission COMPUTES every observation digest; none is parsed in.

    The earlier form of this test pinned the parse of a caller-supplied
    `raw_body_digest` through the typed boundary — the positive half of the
    comparison between the caller's claim about its bytes and the bytes
    themselves. The single-input repair removed that comparison by removing the
    claim: the command carries the wire bytes and nothing else, so there is no
    supplied digest left to parse and nothing for one to disagree with.

    What the boundary now owes, asserted positively so a deleted derivation
    cannot satisfy the source-wide prohibition: the attempt's body digest and
    the receipt's payload digest are both DERIVED through
    `ObservationEnvelopeDigestV1.over_bytes` — the wire bytes for the attempt,
    the canonical signed bytes for the receipt — and no caller text is ever
    read back as an observation digest.
    """
    source = SERVICE.read_text(encoding="utf-8")
    assert "raw_body_digest = ObservationEnvelopeDigestV1.over_bytes(wire)" in source
    assert source.count("ObservationEnvelopeDigestV1.over_bytes(") >= 2
    assert "payload=canonical_payload" in source
    # The removed shape must STAY removed: parsing a caller's digest claim is
    # the split coming back one field at a time.
    assert "ObservationEnvelopeDigestV1.parse(" not in source


def test_the_detector_is_not_looking_at_nothing() -> None:
    """SCOPE PROOF. Every assertion above is a non-existence claim, so the
    corpus must be non-empty and must actually contain comparisons."""
    scanned = [p for p in PACKAGE.rglob("*.py") if p.name not in EXEMPT]
    assert len(scanned) >= 5, [p.name for p in scanned]
    total_compares = sum(
        1
        for path in scanned
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Compare)
    )
    assert total_compares > 20, (
        f"only {total_compares} comparisons in the whole package; the walker is "
        "probably not reaching function bodies"
    )


A4_DEFECT = """
def approve_plan(command, row):
    if command.evidence.content_digest != row.plan_digest:
        raise ApprovalRefusedError("the plan changed after approval")
"""

A4_OBSERVATION_DEFECT = """
def resolve(plan, observed):
    if spec_digest(plan.snapshot["spec"]) == observed.observed_spec_digest:
        return plan.desired_revision
"""

A4_LAUNDERED = """
def approve_plan(command, row):
    if command.evidence.content_digest != (row.plan_digest or ""):
        raise ApprovalRefusedError("the plan changed after approval")
"""


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        (A4_DEFECT, "content_digest"),
        (A4_OBSERVATION_DEFECT, "spec_digest()"),
        (A4_LAUNDERED, "plan_digest"),
    ],
    ids=["a4-approval", "a4-observation", "or-empty-string"],
)
def test_the_detector_catches_the_exact_a4_expressions(
    planted: str, expected: str
) -> None:
    """PLANTED VIOLATION — the two comparisons `0.1.0a4` actually shipped, plus
    the `or ""` form that is one keystroke away from either of them.

    Reconstructed rather than quoted from history so the test is self-contained,
    and fed to the SAME `string_digest_comparisons` the live claim uses. A
    sensitivity proof that runs a private copy of the detector proves the copy.
    """
    offenders = string_digest_comparisons(planted)
    assert offenders, "the a4 expression was not detected"
    assert any(expected in offender for offender in offenders), offenders


def test_the_detector_catches_a_string_comparison_of_the_new_binding() -> None:
    """SENSITIVITY for the columns `dc_0003` adds.

    Widening `DIGEST_ATTRIBUTES` is a non-existence claim like every other one
    in this file, so the a4 expression is reconstructed with the NEW names and
    fed to the same detector. Both directions: the report against the proposal,
    and the proposal against the authorization.
    """
    reported = string_digest_comparisons(
        "if observed.execution_plan_digest != plan.execution_plan_digest:\n    pass\n"
    )
    assert reported, "a string comparison of the execution plan digest is invisible"

    stored = string_digest_comparisons(
        "if plan.execution_plan_digest != plan.authorized_execution_plan_digest:\n"
        "    pass\n"
    )
    assert stored, (
        "a string comparison between the proposal and authorization terms is "
        "invisible, and those two are exactly what step 8 compares"
    )


def test_a_typed_comparison_is_not_flagged() -> None:
    """THE OTHER HALF of sensitivity: the detector must not simply refuse every
    comparison. The shape the fix uses has to pass, or the gate would force the
    binding out of existence."""
    accepted = """
def approve_plan(command, row):
    frozen = _frozen_plan_digest(row)
    supplied = _supplied_plan_digest(row, command.evidence.content_digest)
    if supplied != frozen:
        raise ApprovalRefusedError("the plan changed after approval")
"""
    assert string_digest_comparisons(accepted) == []
