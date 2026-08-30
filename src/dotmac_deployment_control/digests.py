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

## Two types, not one

`PlanDigestV1` covers a frozen plan snapshot. `SpecDigestV1` covers a deployment
spec alone — what a TARGET reports about itself, because a target knows what it
is running and cannot know which plan produced it. Same algorithm, same
encoding, different subject, and a dataclass compares unequal across types, so a
spec digest can never satisfy a plan-digest binding by arriving in the right
shape. The a4 code, comparing strings, had no such protection.
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
class _Sha256Digest:
    """Algorithm plus BYTES. The bytes are the identity; the text is a rendering.

    `algorithm` is carried explicitly rather than implied by the class, because a
    value that travels needs to say what it is. It is validated on construction:
    a value naming an algorithm this module cannot compute is refused at the
    boundary rather than becoming a digest that never matches anything.
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
    def over_json(cls: type[_T], payload: Mapping[str, Any]) -> _T:
        """Compute over the canonical JSON encoding of `payload`."""
        return cls(ALGORITHM, hashlib.sha256(canonical_json(payload)).digest())

    @classmethod
    def parse(cls: type[_T], value: object) -> _T:
        """STRICT. Canonical `sha256:<64 lowercase hex>` and nothing else."""
        return cls(ALGORITHM, _parse_hex(cls.__name__, value, allow_bare=False))

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
    def canonical(self) -> str:
        """`sha256:<64 lowercase hex>` — the one serialization that leaves here."""
        return f"{self.algorithm}:{self.digest.hex()}"

    @property
    def a4_bare_hex(self) -> str:
        """The `0.1.0a4` rendering. For fixtures and compatibility proofs only.

        Nothing in this package writes it. It exists so a test can construct the
        exact input a4 produced without hand-rolling the encoding, which would
        make the compatibility proof a proof about the test.
        """
        return self.digest.hex()

    def __str__(self) -> str:
        return self.canonical


@dataclass(frozen=True, slots=True)
class PlanDigestV1(_Sha256Digest):
    """The identity of a FROZEN PLAN SNAPSHOT.

    What an `ApprovalEvidence.content_digest` must equal for an approval to bind
    (ADR-0026 § 2, applied where the blast radius is other people's running
    systems). Change the plan and this changes, which makes a prior approval
    stale rather than transferable.
    """


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


__all__ = [
    "ALGORITHM",
    "DIGEST_BYTES",
    "DigestEncodingError",
    "PlanDigestV1",
    "SpecDigestV1",
    "canonical_json",
]
