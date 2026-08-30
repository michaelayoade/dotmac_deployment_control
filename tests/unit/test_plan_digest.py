"""`PlanDigestV1` — the value type, its parsers, and every refusal.

The defect these tests exist for is not "a digest was wrong". It is that
`0.1.0a4` reported an ENCODING difference as a PLAN MUTATION:

    approve_plan(evidence=<the plan's own digest, bare hex>)
    -> ApprovalRefusedError("the plan changed after approval")

A security refusal standing in for a formatting bug is the worst failure shape
available, because it looks exactly like the system working. So the file below
spends most of its length on the two things that distinguish the fix from a
looser comparison:

* **equality is over BYTES**, so no encoding can change it, and
* **an unreadable value is a `DigestEncodingError`**, which is not an
  `ApprovalRefusedError` and never claims anything about a plan.

A fix that simply accepted more inputs would pass a suite that only checked the
happy path. Every refusal here is asserted for its own reason and its own
message.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from dotmac_deployment_control import (
    ApprovalRefusedError,
    DeploymentControlError,
    DigestEncodingError,
    PlanDigestV1,
    SpecDigestV1,
)
from dotmac_deployment_control.digests import ALGORITHM, DIGEST_BYTES, canonical_json

_PAYLOAD = {"release_ref": "dotmac_sub@7.187.1", "spec": {"replicas": 2}}


def _hex_of(payload: dict[str, object]) -> str:
    """The digest computed independently of the module under test.

    Recomputing it here rather than asking `PlanDigestV1` twice: a test that
    compares a function to itself proves the function is deterministic and
    nothing else.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── the value ───────────────────────────────────────────────────────────────


def test_it_carries_the_algorithm_and_the_bytes_not_a_string() -> None:
    """THE SHAPE. A digest that is a `str` has no algorithm and no identity
    beyond its spelling, which is how one value acquired two encodings."""
    digest = PlanDigestV1.over_json(_PAYLOAD)
    assert digest.algorithm == ALGORITHM
    assert isinstance(digest.digest, bytes)
    assert len(digest.digest) == DIGEST_BYTES
    assert digest.digest == bytes.fromhex(_hex_of(_PAYLOAD))


def test_the_canonical_serialization_is_self_describing() -> None:
    digest = PlanDigestV1.over_json(_PAYLOAD)
    assert digest.canonical == f"sha256:{_hex_of(_PAYLOAD)}"
    assert len(digest.canonical) == 71
    assert str(digest) == digest.canonical


def test_the_digest_is_taken_over_a_key_ORDER_INDEPENDENT_encoding() -> None:
    """A dict iterates in insertion order. Without `sort_keys` the same content
    rebuilt in a different order would produce a different digest and silently
    invalidate an approval nobody touched."""
    forwards = PlanDigestV1.over_json({"a": 1, "b": 2})
    backwards = PlanDigestV1.over_json({"b": 2, "a": 1})
    assert forwards == backwards
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_equality_is_over_bytes_so_no_encoding_can_change_it() -> None:
    """THE PROPERTY THE WHOLE CHANGE RESTS ON."""
    digest = PlanDigestV1.over_json(_PAYLOAD)
    from_canonical = PlanDigestV1.parse(digest.canonical)
    from_a4 = PlanDigestV1.parse_a4_bare_hex(digest.a4_bare_hex)
    assert digest == from_canonical == from_a4
    assert len({digest, from_canonical, from_a4}) == 1, "they must also hash alike"
    # And the two encodings really are different strings, or the assertion
    # above would hold against a string comparison and prove nothing.
    assert digest.canonical != digest.a4_bare_hex


def test_a_different_payload_is_a_different_digest() -> None:
    """SENSITIVITY. Without it every equality above is consistent with a value
    type that compares equal to everything."""
    assert PlanDigestV1.over_json({"replicas": 2}) != PlanDigestV1.over_json(
        {"replicas": 3}
    )


def test_a_spec_digest_can_never_satisfy_a_plan_digest_binding() -> None:
    """Same algorithm, same bytes, DIFFERENT SUBJECT.

    A plan digest identifies a frozen plan; a spec digest identifies what a
    target reports it is running. Comparing strings, as a4 did, these would be
    interchangeable — a value from the observation path could satisfy an
    approval binding by arriving in the right shape.
    """
    plan = PlanDigestV1.over_json(_PAYLOAD)
    spec = SpecDigestV1.over_json(_PAYLOAD)
    assert plan.digest == spec.digest, "the bytes are deliberately identical here"
    assert plan != spec
    assert spec != plan


def test_the_value_is_frozen() -> None:
    digest = PlanDigestV1.over_json(_PAYLOAD)
    with pytest.raises((AttributeError, TypeError)):
        digest.digest = b"\x00" * DIGEST_BYTES  # type: ignore[misc]


# ── the strict parser ───────────────────────────────────────────────────────


def test_the_strict_parser_accepts_only_the_canonical_form() -> None:
    digest = PlanDigestV1.over_json(_PAYLOAD)
    assert PlanDigestV1.parse(digest.canonical) == digest


def test_the_strict_parser_refuses_bare_hex_and_names_the_legacy_route() -> None:
    """Bare hex is a4's form and is not the contract. Refusing it in `parse`
    keeps the compatibility in ONE named place rather than making it the
    format."""
    digest = PlanDigestV1.over_json(_PAYLOAD)
    with pytest.raises(DigestEncodingError) as raised:
        PlanDigestV1.parse(digest.a4_bare_hex)
    assert "parse_accepting_a4_bare_hex" in str(raised.value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", "empty"),
        ("   ", "whitespace"),
        ("not-a-digest", "neither"),
        ("sha256:" + "a" * 63, "64 lowercase hex"),
        ("sha256:" + "a" * 65, "64 lowercase hex"),
        ("sha256:" + "z" * 64, "64 lowercase hex"),
        ("sha256:" + "A" * 64, "lowercase"),
        ("SHA256:" + "a" * 64, "lowercase"),
        ("Sha256:" + "a" * 64, "lowercase"),
        ("a" * 64 + " ", "whitespace"),
        (" " + "a" * 64, "whitespace"),
        ("A" * 64, "lowercase"),
        ("md5:" + "a" * 32, "algorithm"),
        ("sha512:" + "a" * 128, "algorithm"),
        ("sha1:" + "a" * 40, "algorithm"),
    ],
)
def test_a_malformed_value_is_refused_for_its_own_reason(
    value: str, expected: str
) -> None:
    """Each refusal names WHAT is wrong. A single "invalid digest" for all of
    them would send someone hunting the wrong defect — and uppercase, wrong
    length and unknown algorithm have genuinely different repairs."""
    for parse in (
        PlanDigestV1.parse,
        PlanDigestV1.parse_accepting_a4_bare_hex,
        SpecDigestV1.parse,
    ):
        with pytest.raises(DigestEncodingError) as raised:
            parse(value)
        assert expected in str(raised.value), (parse.__name__, value, raised.value)


@pytest.mark.parametrize("value", [None, 42, b"a" * 64, ["sha256:" + "a" * 64]])
def test_a_value_that_is_not_even_a_string_is_refused(value: object) -> None:
    """`bytes` in particular: `b"..." != "..."` is silently False in Python, so
    a bytes digest reaching a string comparison would read as a changed plan."""
    with pytest.raises(DigestEncodingError):
        PlanDigestV1.parse_accepting_a4_bare_hex(value)


def test_constructing_one_directly_with_the_wrong_shape_is_refused() -> None:
    """The parsers are not the only door. A caller can reach the constructor."""
    with pytest.raises(DigestEncodingError):
        PlanDigestV1("md5", b"\x00" * DIGEST_BYTES)
    with pytest.raises(DigestEncodingError):
        PlanDigestV1(ALGORITHM, b"\x00" * 16)
    with pytest.raises(DigestEncodingError):
        PlanDigestV1(ALGORITHM, "a" * 64)  # type: ignore[arg-type]


# ── the legacy parser, and its boundaries ───────────────────────────────────


def test_the_legacy_parser_is_named_for_the_version_it_exists_for() -> None:
    """Not `parse_lenient`, not `normalize`. The name carries the expiry
    conversation: someone reading `parse_a4_bare_hex` in 2027 knows to ask
    whether a4 is still out there."""
    assert hasattr(PlanDigestV1, "parse_a4_bare_hex")
    assert hasattr(PlanDigestV1, "parse_accepting_a4_bare_hex")
    for name in dir(PlanDigestV1):
        assert "normali" not in name.lower(), (
            f"{name} reads as a general normalizer. The compatibility is for one "
            "named published version, and a general name invites a consumer to "
            "reimplement it."
        )


def test_the_legacy_parser_accepts_a4s_form() -> None:
    digest = PlanDigestV1.over_json(_PAYLOAD)
    assert PlanDigestV1.parse_a4_bare_hex(_hex_of(_PAYLOAD)) == digest


def test_the_legacy_parser_refuses_the_canonical_form() -> None:
    """A caller reaching for the legacy parser with a modern value is confused,
    and answering would hide that."""
    digest = PlanDigestV1.over_json(_PAYLOAD)
    with pytest.raises(DigestEncodingError) as raised:
        PlanDigestV1.parse_a4_bare_hex(digest.canonical)
    assert "CANONICAL" in str(raised.value)


def test_the_tolerant_parser_accepts_both_and_nothing_else() -> None:
    digest = PlanDigestV1.over_json(_PAYLOAD)
    assert PlanDigestV1.parse_accepting_a4_bare_hex(digest.canonical) == digest
    assert PlanDigestV1.parse_accepting_a4_bare_hex(digest.a4_bare_hex) == digest
    with pytest.raises(DigestEncodingError):
        PlanDigestV1.parse_accepting_a4_bare_hex(digest.canonical.upper())


# ── the error taxonomy, which is half the fix ───────────────────────────────


def test_an_encoding_fault_is_not_an_approval_refusal() -> None:
    """THE DISTINCTION. A caller must be able to tell "I cannot read what you
    sent" from "the plan you approved is not the plan you are approving", by
    TYPE and not by reading a message."""
    assert not issubclass(DigestEncodingError, ApprovalRefusedError)
    assert not issubclass(ApprovalRefusedError, DigestEncodingError)
    # Both remain catchable as one thing by a caller that wants to.
    assert issubclass(DigestEncodingError, DeploymentControlError)
    assert issubclass(ApprovalRefusedError, DeploymentControlError)


@pytest.mark.parametrize(
    "value", ["", "not-a-digest", "sha256:" + "A" * 64, "md5:" + "a" * 32]
)
def test_no_encoding_refusal_ever_claims_the_plan_changed(value: str) -> None:
    """The exact sentence a4 produced for a correctly-supplied digest."""
    with pytest.raises(DigestEncodingError) as raised:
        PlanDigestV1.parse_accepting_a4_bare_hex(value)
    message = str(raised.value).lower()
    for forbidden in ("plan changed", "new approval", "changed after approval"):
        assert forbidden not in message, (value, raised.value)
    assert "encoding" in message, "the refusal must say what kind of fault it is"
