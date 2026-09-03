"""Content digests as VALUES — an algorithm and its bytes, never a bare string.

## The defect this module exists to remove

Through `0.1.0a4` this package computed the same kind of thing two different
ways, ten lines apart in one file:

    snapshot_digest(...)  ->  "9f86d081884c7d65..."          # bare hex
    spec_digest(...)      ->  "sha256:9f86d081884c7d65..."   # prefixed

`propose_plan` stored the bare form, and `approve_plan` compared it to the
caller's `evidence.content_digest` with `!=` on two strings. A caller that
supplied the SAME digest in the OTHER encoding was refused with:

    the plan changed after approval, so a new approval is required

That message is the real harm. It is a security refusal — "someone edited the
plan under a live approval" — standing in for a formatting mismatch, and it is
the worst failure shape available because it looks exactly like the system
working. An operator reading it does the diligent thing and re-runs the
approval; nothing was ever wrong with the plan.

Two properties follow, and they are separate:

1. **A digest is a typed value.** `PlanDigestV1` carries the algorithm AND the
   raw digest bytes. Two values are equal when the algorithm and the bytes are
   equal, which no encoding can change. Nothing on the authorization path
   compares digest STRINGS — `tests/architecture/test_digest_comparison_is_typed.py`
   fails the build if that comes back.
2. **An encoding fault is not a mutation.** A value this module cannot read at
   all raises `DigestEncodingError`, which is deliberately NOT an
   `ApprovalRefusedError`. "I cannot read what you sent" and "the plan you
   approved is not the plan you are approving" are different findings for
   different people, and collapsing them is what produced the message above.

## Canonical serialization

`sha256:<64 lowercase hex>` — a self-describing form, so a value that leaves
this module carries its own algorithm and a reader never has to infer one from a
length. That inference is the other half of the a4 defect: 64 hex characters
could be a sha256 digest or the first half of a sha512 one, and nothing in the
string says which.

## Legacy input, in ONE named place

`0.1.0a4` emitted bare hex, and something may hold one. `parse_a4_bare_hex` and
`parse_accepting_a4_bare_hex` accept it — named for the version they exist for,
so the compatibility has an expiry conversation attached rather than becoming
the format. They live HERE, inside Control, because Control owns this contract:
a consumer that normalizes a Control digest is a second implementation of this
parser, it will disagree eventually, and the disagreement surfaces as a false
"the plan changed". Platform CP and the deployment foundation must never
normalize; they hand the value across as received.

## Three types, not one, and the third is the one this module cannot compute

`PlanDigestV1` covers a frozen plan snapshot. `SpecDigestV1` covers a deployment
spec alone — what a TARGET reports about itself, because a target knows what it
is running and cannot know which plan produced it. Same algorithm, same
encoding, different subject, and a dataclass compares unequal across types, so a
spec digest can never satisfy a plan-digest binding by arriving in the right
shape. The a4 code, comparing strings, had no such protection.

`ExecutionPlanDigestV1` is the third, and it is a different KIND of value.
Both of the others are over payloads this module builds; that one is over a
`FoundationExecutionPlanV1` the Deployment Foundation renders, canonicalizes and
hashes. Control receives it, freezes it, signs it, and hands it back — and it is
structurally unable to do anything else, because it does not inherit the
constructor that turns bytes into a digest. See the class for why that absence
is the point.

`ImageDigestV1` is a FOURTH, added deliberately rather than by accident, and it
is not a fourth plan digest. Its subject is an OCI image manifest — a
registry's value, not a plan's — so it takes part in no plan/spec/execution
comparison at all, and being a distinct dataclass is what makes that
structural. It inherits the read-only base for the plainest possible reason:
Control does not build images and holds none of the bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from dotmac_deployment_control.ports import DigestEncodingError

#: The one algorithm this module computes. A parser that accepted others would
#: be claiming a verification capability the module does not have.
ALGORITHM = "sha256"

#: 32 bytes. Named so the length check reads as a fact about sha256 rather than
#: as a magic number.
DIGEST_BYTES = 32

_CANONICAL = re.compile(r"\Asha256:([0-9a-f]{64})\Z")
_BARE_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_ANY_PREFIXED = re.compile(r"\A([A-Za-z0-9_-]+):(.*)\Z", re.DOTALL)

_R = TypeVar("_R", bound="_ReceivedSha256Digest")
_T = TypeVar("_T", bound="_Sha256Digest")


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """The exact bytes every digest in this module is taken over.

    `sort_keys=True` because a dict's iteration order is insertion order: a
    digest over an unsorted encoding changes when the same content is rebuilt in
    a different order, which silently invalidates an approval nobody touched.
    """
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _refuse(subject: str, value: object, reason: str) -> DigestEncodingError:
    return DigestEncodingError(
        f"{value!r} is not a readable {subject}: {reason}. This is an ENCODING "
        f"fault, not a statement about any plan or deployment — nothing has "
        f"been compared, and nothing has been found to have changed."
    )


def _parse_hex(subject: str, value: object, *, allow_bare: bool) -> bytes:
    """The whole parse, as one function, so both types refuse identically."""
    if not isinstance(value, str):
        raise _refuse(subject, value, f"it is a {type(value).__name__}, not a string")
    if not value:
        raise _refuse(subject, value, "it is empty")
    if value != value.strip():
        raise _refuse(
            subject,
            value,
            "it carries leading or trailing whitespace. Stripping it here would "
            "make this parser tolerant of a caller that is corrupting the value "
            "somewhere upstream",
        )

    canonical = _CANONICAL.match(value)
    if canonical is not None:
        return bytes.fromhex(canonical.group(1))

    prefixed = _ANY_PREFIXED.match(value)
    if prefixed is not None:
        algorithm, body = prefixed.group(1), prefixed.group(2)
        if algorithm.lower() != ALGORITHM:
            raise _refuse(
                subject,
                value,
                f"it names algorithm {algorithm!r} and this module computes "
                f"{ALGORITHM!r} only. Refusing rather than guessing: a digest "
                "read under the wrong algorithm compares unequal forever",
            )
        if algorithm != ALGORITHM:
            raise _refuse(
                subject,
                value,
                f"the algorithm must be lowercase {ALGORITHM!r}, not "
                f"{algorithm!r}. One digest with two spellings is one digest "
                "with two identities",
            )
        if body.lower() == body and _BARE_HEX.match(body) is None:
            raise _refuse(
                subject,
                value,
                f"the {ALGORITHM} body must be exactly 64 lowercase hex "
                f"characters; this is {len(body)} character(s) and "
                f"{'not hex' if not _is_hexish(body) else 'the wrong length'}",
            )
        raise _refuse(
            subject,
            value,
            "hexadecimal must be lowercase. Uppercase would give one digest two "
            "encodings, which is the whole defect this type exists to remove",
        )

    if _BARE_HEX.match(value) is not None:
        if allow_bare:
            return bytes.fromhex(value)
        raise _refuse(
            subject,
            value,
            "it is bare hexadecimal with no algorithm. That is the 0.1.0a4 form; "
            "it is accepted only through `parse_accepting_a4_bare_hex`, which is "
            "named for the version it exists for. A bare digest cannot say which "
            "algorithm produced it",
        )

    if _is_hexish(value) and value.lower() != value:
        raise _refuse(
            subject,
            value,
            "hexadecimal must be lowercase. Uppercase would give one digest two "
            "encodings, which is the whole defect this type exists to remove",
        )
    raise _refuse(
        subject,
        value,
        f"it is neither `{ALGORITHM}:<64 lowercase hex>` nor 64 lowercase hex "
        f"characters (it is {len(value)} character(s) long)",
    )


def _is_hexish(value: str) -> bool:
    return bool(value) and all(
        character in "0123456789abcdefABCDEF" for character in value
    )


@dataclass(frozen=True, slots=True)
class _ReceivedSha256Digest:
    """A digest this module can READ and RENDER, and cannot COMPUTE.

    Algorithm plus BYTES. The bytes are the identity; the text is a rendering.
    `algorithm` is carried explicitly rather than implied by the class, because
    a value that travels needs to say what it is. It is validated on
    construction: a value naming an algorithm this module cannot compute is
    refused at the boundary rather than becoming a digest that never matches
    anything.

    ## The absence is the feature

    There is no `over_json` here, and no other constructor that turns a payload
    into a digest. The computing constructors live one level DOWN, on
    `_Sha256Digest`, so a type that must never be recomputed simply does not
    inherit them. That is a property of the class graph rather than a rule
    somebody has to remember at each call site — see `ExecutionPlanDigestV1`.
    """

    algorithm: str
    digest: bytes

    def __post_init__(self) -> None:
        if self.algorithm != ALGORITHM:
            raise _refuse(
                type(self).__name__, self.algorithm, f"only {ALGORITHM!r} is computed"
            )
        if not isinstance(self.digest, bytes) or len(self.digest) != DIGEST_BYTES:
            raise _refuse(
                type(self).__name__,
                self.digest,
                f"a {ALGORITHM} digest is exactly {DIGEST_BYTES} bytes",
            )

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def parse(cls: type[_R], value: object) -> _R:
        """STRICT. Canonical `sha256:<64 lowercase hex>` and nothing else.

        VALIDATION, not normalization, and the difference is load-bearing for
        `ExecutionPlanDigestV1`: a value that is not already canonical is
        REFUSED rather than rewritten, so the text that reaches storage is
        byte-identical to the text the caller sent. A parser that accepted bare
        hex or uppercase and tidied it would be a second canonicalization of
        somebody else's value, which is the whole defect class this repair
        exists to close.
        """
        return cls(ALGORITHM, _parse_hex(cls.__name__, value, allow_bare=False))

    # ── rendering ───────────────────────────────────────────────────────────

    @property
    def canonical(self) -> str:
        """`sha256:<64 lowercase hex>` — the one serialization that leaves here."""
        return f"{self.algorithm}:{self.digest.hex()}"

    def __str__(self) -> str:
        return self.canonical


@dataclass(frozen=True, slots=True)
class _Sha256Digest(_ReceivedSha256Digest):
    """A received digest that this module can ALSO compute for itself.

    Everything above plus `over_json` and the two `0.1.0a4` legacy parsers. A
    digest whose subject this module owns — a plan snapshot, a deployment
    spec — belongs here; one whose subject belongs to another system does not.
    """

    @classmethod
    def over_json(cls: type[_T], payload: Mapping[str, Any]) -> _T:
        """Compute over the canonical JSON encoding of `payload`."""
        return cls(ALGORITHM, hashlib.sha256(canonical_json(payload)).digest())

    @classmethod
    def parse_a4_bare_hex(cls: type[_T], value: object) -> _T:
        """THE LEGACY PARSER, and the only one. Bare hex ONLY.

        Refuses a canonical value deliberately: a caller reaching for the legacy
        parser for a modern value is confused, and answering it would hide that.
        Use `parse_accepting_a4_bare_hex` where either may genuinely arrive.
        """
        if isinstance(value, str) and value.startswith(f"{ALGORITHM}:"):
            raise _refuse(
                cls.__name__,
                value,
                "this is the CANONICAL form and this is the 0.1.0a4 legacy "
                "parser. Use `parse`, or `parse_accepting_a4_bare_hex` if both "
                "forms genuinely arrive here",
            )
        return cls(ALGORITHM, _parse_hex(cls.__name__, value, allow_bare=True))

    @classmethod
    def parse_accepting_a4_bare_hex(cls: type[_T], value: object) -> _T:
        """Canonical, or the `0.1.0a4` bare-hex form.

        The ONLY place in the fleet where a4's encoding is normalized. A
        consumer that does this itself has forked this parser; the two will
        disagree, and the disagreement arrives as a false "the plan changed".
        """
        return cls(ALGORITHM, _parse_hex(cls.__name__, value, allow_bare=True))

    # ── rendering ───────────────────────────────────────────────────────────

    @property
    def a4_bare_hex(self) -> str:
        """The `0.1.0a4` rendering. For fixtures and compatibility proofs only.

        Nothing in this package writes it. It exists so a test can construct the
        exact input a4 produced without hand-rolling the encoding, which would
        make the compatibility proof a proof about the test.
        """
        return self.digest.hex()


@dataclass(frozen=True, slots=True)
class PlanDigestV1(_Sha256Digest):
    """The identity of a FROZEN PLAN SNAPSHOT.

    What an `ApprovalEvidence.content_digest` must equal for an approval to bind
    (ADR-0026 § 2, applied where the blast radius is other people's running
    systems). Change the plan and this changes, which makes a prior approval
    stale rather than transferable.
    """


@dataclass(frozen=True, slots=True)
class ObservationEnvelopeDigestV1(_ReceivedSha256Digest):
    """The identity of the exact signed target-observation envelope bytes.

    Unlike a caller-supplied plan or execution digest, Control owns the
    envelope serialization and therefore owns this computation.  Keeping the
    constructor here preserves one digest authority for the package while the
    distinct type prevents an envelope digest satisfying a plan/spec binding.
    """

    @classmethod
    def over_bytes(cls, payload: bytes) -> ObservationEnvelopeDigestV1:
        if not isinstance(payload, bytes):
            raise _refuse(cls.__name__, payload, "the envelope must be bytes")
        return cls(ALGORITHM, hashlib.sha256(payload).digest())


@dataclass(frozen=True, slots=True)
class SpecDigestV1(_Sha256Digest):
    """The identity of a DEPLOYMENT SPEC alone.

    Separate from `PlanDigestV1` because a target reports what it is RUNNING and
    has no way to know which plan produced it, so the comparable value on both
    sides is the spec's own digest.

    Type-distinct on purpose, and the distinction is load-bearing rather than
    tidy: a dataclass compares unequal across types, so a spec digest can never
    satisfy a plan-digest binding by happening to arrive in the right shape.
    """


@dataclass(frozen=True, slots=True)
class ImageDigestV1(_ReceivedSha256Digest):
    """The identity of ONE CONTAINER IMAGE MANIFEST. A registry's value.

    ## This is a fourth type and it is not a fourth plan digest

    The three above are all about a PLAN: Control's frozen snapshot, a target's
    running spec, and the Foundation's rendered execution. Adding a fourth of
    those by accident is how a binding ends up comparing two values that
    describe different things while reading as correct, and it is exactly what
    `ExecutionPlanDigestV1`'s docstring warns about.

    This one has a different SUBJECT entirely. It is `sha256` over an OCI image
    manifest — the value a registry publishes and a runtime resolves — and it
    never participates in a plan-digest, spec-digest or execution-plan-digest
    comparison. A dataclass compares unequal across types, so it structurally
    cannot: an `ImageDigestV1` can never satisfy any of the three bindings by
    arriving in the right shape, and none of them can satisfy an image
    comparison.

    ## Why it inherits the READ-ONLY base

    Same reason, and it is even more clear-cut here than for the execution
    plan: Control does not build container images, does not talk to a registry,
    and holds none of the bytes an image manifest is hashed over. A value it
    cannot possibly compute must not have a constructor that pretends
    otherwise, so `ImageDigestV1.over_json(...)` is an `AttributeError` rather
    than a plausible-looking number.

    ## Why a digest and never a tag

    A tag is a mutable pointer. An "authorized image set" pinned by tag
    authorizes whatever that tag names at the moment something looks — which is
    a different set tomorrow, under the same approval, with the same plan
    digest. Only the constructor `parse` exists and it accepts only
    `sha256:<64 lowercase hex>`, so a tag cannot become an authorized image by
    any route through this module.
    """


@dataclass(frozen=True, slots=True)
class ExecutionPlanDigestV1(_ReceivedSha256Digest):
    """`sha256(canonical FoundationExecutionPlanV1 bytes)` — the Foundation's.

    The middle term binding an authorization to an execution. It is NOT the
    descriptor digest, NOT the authorization-envelope digest, and NOT
    `PlanDigestV1` — Control's own snapshot digest — which is why it is a third
    type rather than a third use of one of them. A dataclass compares unequal
    across types, so none of the three can satisfy another's binding by arriving
    in the right shape.

    ## Why this class inherits from the READ-ONLY base

    The defect being repaired here is subtle and is worth naming, because it is
    the reason a comment would not have been enough. Control's `plan_digest`
    hashes the target's desired state wrapped in six sibling keys; the
    Foundation hashes its execution plan alone. The two agree completely about
    SERIALIZATION — canonical JSON, sorted keys, sha256 — and disagree about
    PAYLOAD. So they can never be equal, and every line of either implementation
    reads as correct.

    That is what a second canonicalization always looks like from inside. The
    only defence that does not depend on somebody noticing is to make the second
    canonicalization impossible to write here: `ExecutionPlanDigestV1` does not
    inherit `over_json`, and there is no other route from a payload to one of
    these. `ExecutionPlanDigestV1.over_json(...)` is an `AttributeError`, not a
    disagreement discovered in production.

    The only constructor is `parse`, which is STRICT — canonical
    `sha256:<64 lowercase hex>` and nothing else. Deliberately no
    `parse_accepting_a4_bare_hex`: this value never existed in `0.1.0a4`, so
    there is no legacy shape to be tolerant of, and tolerance would mean
    rewriting a value Control does not own. A non-canonical spelling is REFUSED,
    so the text Control stores is byte-identical to the text it was handed.
    Refusing is not normalizing.
    """


@dataclass(frozen=True, slots=True)
class DescriptorDigestV1(_ReceivedSha256Digest):
    """The Foundation's canonical deployment-descriptor digest, received only.

    Control binds this value into its own plan snapshot but never interprets or
    recomputes the descriptor.  Keeping it type-distinct from both
    :class:`PlanDigestV1` and :class:`ExecutionPlanDigestV1` prevents three
    different documents that happen to use sha256 from satisfying one
    another's bindings by spelling alone.
    """


__all__ = [
    "ALGORITHM",
    "DIGEST_BYTES",
    "DescriptorDigestV1",
    "DigestEncodingError",
    "ExecutionPlanDigestV1",
    "ImageDigestV1",
    "ObservationEnvelopeDigestV1",
    "PlanDigestV1",
    "SpecDigestV1",
    "canonical_json",
]
