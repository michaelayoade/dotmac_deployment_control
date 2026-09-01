"""Control is STRUCTURALLY unable to recompute the Foundation's plan digest.

## Why a convention would not have been enough

The defect this repairs is one nobody catches by reading. Control's
`plan_digest` hashes the target's desired state wrapped in six sibling keys; the
Deployment Foundation hashes its rendered execution plan alone. Both use
canonical JSON with sorted keys and sha256, so the two agree completely about
SERIALIZATION and disagree about PAYLOAD — they can never be equal, and every
line of both implementations reads as correct in review.

That is what a second canonicalization always looks like from inside. A comment
saying "do not recompute this" is satisfied by a reviewer noticing; the property
Michael's ruling actually requires is that Control CANNOT recompute it. So the
constructor that turns a payload into a digest lives on a class
`ExecutionPlanDigestV1` does not inherit, and this file holds that as a fact
about the class graph and about the source, in both directions.

## The three claims, and the positive control each one needs

Every assertion here is a non-existence claim, and a non-existence claim over an
empty set passes for the wrong reason (ADR-0018). So each is paired:

1. `ExecutionPlanDigestV1` has no payload constructor — AND `PlanDigestV1`, a
   digest this module legitimately computes, still has one. Without the second
   half, `not hasattr` would pass on a package that computes nothing at all.
2. No module constructs one except through `parse` — AND the detector is shown
   refusing a synthetic direct construction.
3. The read-only base carries no `hashlib` reference — AND the computing
   subclass does, so the split is real rather than a rename.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from dotmac_deployment_control import (
    ExecutionPlanDigestV1,
    PlanDigestV1,
    SpecDigestV1,
)
from dotmac_deployment_control import digests as digest_module

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "src" / "dotmac_deployment_control"
DIGESTS = PACKAGE / "digests.py"

#: The constructors that turn a PAYLOAD into a digest, or a non-canonical
#: encoding into one. Neither may be reachable from the received-only type: the
#: first would be a second canonicalization, the second a normalization of
#: somebody else's value.
COMPUTING_CONSTRUCTORS = ("over_json",)
NORMALIZING_CONSTRUCTORS = (
    "parse_a4_bare_hex",
    "parse_accepting_a4_bare_hex",
    "a4_bare_hex",
)


def _sources() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


def _identifiers(source: str) -> set[str]:
    """Every name a source DEFINES or READS — never string contents.

    The same shape `test_deployment_control_module.py` uses, and for the same
    reason: a docstring explaining that the Deployment Foundation owns
    `FoundationExecutionPlanV1` is the OPPOSITE of a violation, and a detector
    that grepped text would flag the very comments that record the boundary.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name.rsplit(".", 1)[-1])
    return names


# ── 1. The class graph ──────────────────────────────────────────────────────


@pytest.mark.parametrize("name", COMPUTING_CONSTRUCTORS + NORMALIZING_CONSTRUCTORS)
def test_the_received_only_type_has_no_payload_or_legacy_constructor(
    name: str,
) -> None:
    assert not hasattr(ExecutionPlanDigestV1, name), (
        f"ExecutionPlanDigestV1 has grown `{name}`. Either it can now compute "
        "the Foundation's digest — a second canonicalization, which is the "
        "defect this binding was cut for — or it can now rewrite a spelling of "
        "it, which is Control normalizing a value it does not own."
    )


@pytest.mark.parametrize("name", COMPUTING_CONSTRUCTORS + NORMALIZING_CONSTRUCTORS)
@pytest.mark.parametrize("owner", [PlanDigestV1, SpecDigestV1])
def test_the_digests_this_module_does_compute_still_carry_them(
    owner: type, name: str
) -> None:
    """THE POSITIVE CONTROL for the check above.

    `not hasattr` is satisfied by a package that computes nothing, by a typo in
    the attribute name, and by a class that was deleted. This says the absence
    is a SPLIT: the same names are present on the digests whose subject this
    module owns.
    """
    assert hasattr(owner, name), f"{owner.__name__} lost `{name}`"


def test_the_two_kinds_of_digest_do_not_share_a_base_that_can_compute() -> None:
    """The absence above is inherited, not merely undefined here.

    A subclass could re-acquire `over_json` at any time by changing one base, so
    the base itself is asserted: `ExecutionPlanDigestV1` derives from the
    read-only class and NOT from the computing one.
    """
    received_base = digest_module._ReceivedSha256Digest
    computing_base = digest_module._Sha256Digest

    assert issubclass(computing_base, received_base)
    assert issubclass(ExecutionPlanDigestV1, received_base)
    assert not issubclass(ExecutionPlanDigestV1, computing_base)
    assert issubclass(PlanDigestV1, computing_base)
    assert issubclass(SpecDigestV1, computing_base)


def test_the_three_types_never_satisfy_one_anothers_bindings() -> None:
    """Same algorithm, same encoding, three subjects. A dataclass compares
    unequal across types, so an execution plan digest cannot satisfy a plan
    digest binding by arriving in the right shape — which is exactly how
    `plan_digest` and `execution_plan_digest` stay distinct values rather than
    one value used twice."""
    text = "sha256:" + "1a" * 32
    assert PlanDigestV1.parse(text) != SpecDigestV1.parse(text)
    assert PlanDigestV1.parse(text) != ExecutionPlanDigestV1.parse(text)
    assert SpecDigestV1.parse(text) != ExecutionPlanDigestV1.parse(text)
    # And the same type IS equal to itself, or the three lines above would pass
    # against a broken `__eq__`.
    assert ExecutionPlanDigestV1.parse(text) == ExecutionPlanDigestV1.parse(text)


# ── 2. The source: every use goes through the parser ────────────────────────


def direct_constructions(source: str) -> list[str]:
    """Every `ExecutionPlanDigestV1(...)` call that is not `.parse(...)`.

    A direct construction takes raw BYTES, which is the one way to make one of
    these without going through the strict parser — and therefore the one way a
    payload could quietly become one.
    """
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "ExecutionPlanDigestV1":
            offenders.append(f"line {node.lineno}: ExecutionPlanDigestV1(...)")
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "ExecutionPlanDigestV1"
            and func.attr != "parse"
        ):
            offenders.append(
                f"line {node.lineno}: ExecutionPlanDigestV1.{func.attr}(...)"
            )
    return offenders


@pytest.mark.parametrize(
    "path",
    sorted(p for p in PACKAGE.rglob("*.py") if p.name != DIGESTS.name),
    ids=lambda p: p.name,
)
def test_no_module_builds_one_except_through_the_strict_parser(path: Path) -> None:
    offenders = direct_constructions(path.read_text(encoding="utf-8"))
    assert not offenders, (
        f"{path.name} constructs an ExecutionPlanDigestV1 without parsing:\n  "
        + "\n  ".join(offenders)
        + "\nThe raw constructor takes bytes, so it is the one route by which a "
        "payload could become this value. Every use outside digests.py must be "
        "`ExecutionPlanDigestV1.parse(...)`, which refuses anything that is not "
        "already the Foundation's canonical text."
    )


def test_the_detector_refuses_a_synthetic_direct_construction() -> None:
    """SENSITIVITY (ADR-0018). The check above is a non-existence claim over
    every file in the package, so the expression it is looking for is written
    out and fed to the same detector."""
    assert direct_constructions(
        "d = ExecutionPlanDigestV1('sha256', hashlib.sha256(b'').digest())\n"
    )
    assert direct_constructions("d = ExecutionPlanDigestV1.over_json({'a': 1})\n")
    # And it must not flag the legitimate route, or the gate above would be
    # satisfied by a package that had stopped using the value entirely.
    assert not direct_constructions("d = ExecutionPlanDigestV1.parse(value)\n")


def test_the_service_reaches_the_value_only_through_named_boundary_helpers() -> None:
    """The positive half: the parse calls must still BE there.

    "No direct construction" is also satisfied by a service that stopped reading
    the value at all, which would leave every binding check comparing nothing.
    """
    source = (PACKAGE / "service.py").read_text(encoding="utf-8")
    for helper in (
        "_stored_execution_plan_digest",
        "_supplied_execution_plan_digest",
        "_supplied_execution_plan_digest_text",
    ):
        assert f"def {helper}(" in source, f"{helper} is gone"
        assert f"{helper}(" in source.split(f"def {helper}(", 1)[1], (
            f"{helper} is defined but never called, so the binding is being "
            "built some other way"
        )
    assert "ExecutionPlanDigestV1.parse(" in source


# ── 3. The split is real, not a rename ──────────────────────────────────────


def _class_source(name: str) -> str:
    tree = ast.parse(DIGESTS.read_text(encoding="utf-8"))
    node = next(
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.ClassDef) and item.name == name
    )
    return ast.unparse(node)


def test_only_the_computing_base_reaches_hashlib() -> None:
    """`hashlib` is already pinned to this one FILE by
    `test_this_package_computes_digests_in_exactly_one_module`. This narrows it
    to one CLASS inside it, which is what makes the inheritance split above a
    statement about capability rather than about names."""
    assert "hashlib" in _class_source("_Sha256Digest")
    assert "hashlib" not in _class_source("_ReceivedSha256Digest")
    assert "hashlib" not in _class_source("ExecutionPlanDigestV1")


def test_control_holds_no_foundation_execution_plan_to_hash() -> None:
    """The other half of "cannot": there is nothing here to compute it OVER.

    A `FoundationExecutionPlanV1` is rendered by the Deployment Foundation from
    the immutable artifact and the authorized environment inventory. Control has
    no renderer for it and no column holding its bytes — only the digest. If a
    module ever started holding the plan itself, the type-level absence above
    would stop being sufficient, because the payload would be in reach.
    """
    holders = sorted(
        path.name
        for path in _sources()
        if any(
            name.startswith("FoundationExecutionPlan")
            for name in _identifiers(path.read_text(encoding="utf-8"))
        )
    )
    assert holders == [], (
        f"{holders} name a FoundationExecutionPlan. Deployment Control holds "
        "the Foundation's DIGEST and never its plan; holding the plan would put "
        "the payload within reach of a second canonicalization, which is the "
        "thing the type split exists to prevent."
    )


def test_that_detector_reads_code_and_not_prose() -> None:
    """SENSITIVITY, and the false positive it must NOT produce.

    Half the value of the check above is that the docstrings explaining the
    boundary keep saying `FoundationExecutionPlanV1` — so the detector has to
    see a real reference and ignore an explanation of one.
    """
    assert "FoundationExecutionPlanV1" in _identifiers(
        "plan = FoundationExecutionPlanV1.render(spec)\n"
    )
    assert "FoundationExecutionPlanV1" not in _identifiers(
        '"""The Foundation owns FoundationExecutionPlanV1 and its digest."""\n'
    )
