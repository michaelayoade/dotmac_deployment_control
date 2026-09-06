"""Validated evidence that ONE Foundation wheel is ONE known set of bytes.

## The gap this closes

`CandidateArtifactRef.foundation_artifact_digest` accepted a bare string,
refused only by *shape* (`FoundationArtifactDigestV1.parse` requires
`sha256:<64 lowercase hex>`). Shape is not provenance: any 64 hex characters
satisfy it, including 64 a caller typed by hand. Measured directly —
`CandidateArtifact` appeared in this package's source only inside comments
before this module, and `issue_rehearsal_grant` had no way to refuse a
statement whose digest came from nowhere. That is the incompleteness Michael
found: *"If #45 still accepts a free `foundation_artifact_digest` string, the
digest repair is incomplete."*

A hash cannot cryptographically reveal its preimage — that limitation is
irreducible, and `digests.FoundationArtifactDigestV1`'s docstring is right to
say so plainly. What THIS module closes is narrower and real: **issuance must
not accept an arbitrary hex string**, and the repair is to make the digest
reachable only through a typed accessor on validated evidence, never as a bare
argument.

## What this is evidence OF, named rather than implied

**Subject: the built `dotmac-deployment-foundation` PYTHON WHEEL.
Algorithm: SHA-256.** Not "a digest" — the subject is part of this type's
meaning, on the same principle `FoundationArtifactDigestV1` already states: a
workflow-ZIP digest and a source-tree digest are the WRONG subject even though
they are the identical shape of string.

## The independent comparison this type PERFORMS, not merely carries

Michael's chain: Control-verified CandidateArtifact -> signed grant digest ->
HostSource PEP 610 digest -> candidate receipt digest. `CandidateArtifactV1
.parse` requires TWO INDEPENDENTLY-SOURCED readings of the same wheel's digest
to already AGREE before this type can be constructed at all:

* `foundation_artifact_digest` — the sha256 the BUILD attested: CI's own
  computation over the artifact it produced.
* `host_observed_digest` — the sha256 a HOST independently read back via
  PEP 610's `direct_url.json` -> `archive_info.hashes.sha256`
  (`host_source.read_installed_artifact`, upstream, in the Foundation's own
  repository) after installing that same artifact.

Two different processes computing the SAME wheel's digest and agreeing is what
makes this evidence "Control-VERIFIED" rather than "Control-received".
`parse()` refuses, naming both readings, when they disagree — this is the
independent PEP 610 comparison actually being EXERCISED, not merely available
for a caller to run someday.

## What agreement does, and does not, establish

Two agreeing readings say the build and an installer describe the SAME bytes.
They do not prove those bytes are untampered, and they do not, by themselves,
prove the digest is of a wheel rather than some other sha256-shaped subject
smuggled through both sides identically — `FoundationArtifactDigestV1`'s own
docstring already says a well-formed digest cannot reveal its subject from the
bytes alone, and that limitation stands. What agreement across two
INDEPENDENT readers rules out is the narrower, ordinary failure this module
exists for: one caller typing a plausible-looking hex string by hand and
handing it to issuance. A hand-typed string only ever satisfies one side of
this comparison, never two independently computed ones, so it cannot become
`CandidateArtifactV1` evidence.

## Why this closes the issuance path, structurally

`CandidateArtifactV1.parse` is the ONLY constructor this type has — there is
no other function anywhere that returns one. `rehearsal_grant.
issue_rehearsal_grant` takes a `CandidateArtifactV1` as a required keyword
argument and refuses (`RehearsalGrantRefusalCode.CANDIDATE_MISMATCH`) unless
the statement's own candidate terms match that evidence's typed accessors
EXACTLY. A caller cannot sign a statement carrying a hand-typed digest by also
waving an unrelated, validly-parsed `CandidateArtifactV1` at
`issue_rehearsal_grant` — the two are compared, and disagreement refuses
before a single byte is signed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from dotmac_deployment_control.digests import FoundationArtifactDigestV1
from dotmac_deployment_control.ports import (
    CandidateArtifactRefusedError,
    DigestEncodingError,
)

__all__ = [
    "CANDIDATE_ARTIFACT_ALGORITHM",
    "CANDIDATE_ARTIFACT_SCHEMA",
    "CANDIDATE_ARTIFACT_SUBJECT",
    "CANDIDATE_ARTIFACT_VERSION",
    "CandidateArtifactV1",
]

CANDIDATE_ARTIFACT_SCHEMA: Final = "dotmac.deployment_control.candidate_artifact"
CANDIDATE_ARTIFACT_VERSION: Final = 1
#: Named explicitly per Michael's ruling: the subject is part of the type's
#: meaning, not an implementation detail.
CANDIDATE_ARTIFACT_SUBJECT: Final = (
    "the built dotmac-deployment-foundation Python wheel"
)
CANDIDATE_ARTIFACT_ALGORITHM: Final = "sha256"

_REQUIRED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "version",
        "repository",
        "run_id",
        "artifact_id",
        "foundation_artifact_digest",
        "host_observed_digest",
    }
)


@dataclass(frozen=True, slots=True)
class CandidateArtifactV1:
    """Validated evidence for ONE build's Foundation wheel. `parse`-only.

    Holding one of these is a claim that has already been checked: the
    locating triple is non-empty text and the digest is the result of TWO
    independent readings agreeing, not a value this type merely repeats back.
    """

    repository: str
    run_id: str
    artifact_id: str
    digest: FoundationArtifactDigestV1

    @property
    def foundation_artifact_digest(self) -> FoundationArtifactDigestV1:
        """THE TYPED ACCESSOR Michael's ruling requires.

        Subject: `CANDIDATE_ARTIFACT_SUBJECT`. Algorithm:
        `CANDIDATE_ARTIFACT_ALGORITHM`. Returns the typed digest, never a bare
        string — a caller wanting the wire form calls `.canonical` on the
        result, exactly as every other received digest in `digests.py` is
        rendered.
        """
        return self.digest

    @classmethod
    def parse(
        cls, document: Mapping[str, Any], *, where: str = "candidate artifact"
    ) -> CandidateArtifactV1:
        """The ONE place a mapping becomes this type. Nowhere else does.

        Requires schema, version, a non-empty locating triple, and BOTH digest
        readings to parse AND to agree — see the module docstring for why
        agreement is the load-bearing check, not the parsing.
        """
        if not isinstance(document, Mapping):
            raise CandidateArtifactRefusedError(
                f"{where}: must be a mapping, got {type(document).__name__}"
            )
        if document.get("schema") != CANDIDATE_ARTIFACT_SCHEMA:
            raise CandidateArtifactRefusedError(
                f"{where}: declares schema {document.get('schema')!r}, "
                f"expected {CANDIDATE_ARTIFACT_SCHEMA!r}. A mapping with the "
                "right-shaped keys is not evidence unless it names itself as "
                "this document"
            )
        if document.get("version") != CANDIDATE_ARTIFACT_VERSION:
            raise CandidateArtifactRefusedError(
                f"{where}: unsupported version {document.get('version')!r}"
            )
        missing = sorted(_REQUIRED_KEYS - set(document))
        if missing:
            raise CandidateArtifactRefusedError(f"{where}: missing {missing}")

        repository = str(document["repository"]).strip()
        run_id = str(document["run_id"]).strip()
        artifact_id = str(document["artifact_id"]).strip()
        if not repository or not run_id or not artifact_id:
            raise CandidateArtifactRefusedError(
                f"{where}: repository, run_id and artifact_id must all be "
                "non-empty — an artifact id is unique only within the "
                "repository that produced it, so a blank locating field "
                "names nothing"
            )

        try:
            built = FoundationArtifactDigestV1.parse(
                document["foundation_artifact_digest"]
            )
        except DigestEncodingError as error:
            raise CandidateArtifactRefusedError(
                f"{where}: foundation_artifact_digest is not a readable "
                f"{CANDIDATE_ARTIFACT_ALGORITHM} digest: {error}"
            ) from error
        try:
            observed = FoundationArtifactDigestV1.parse(
                document["host_observed_digest"]
            )
        except DigestEncodingError as error:
            raise CandidateArtifactRefusedError(
                f"{where}: host_observed_digest is not a readable "
                f"{CANDIDATE_ARTIFACT_ALGORITHM} digest: {error}"
            ) from error

        if built != observed:
            raise CandidateArtifactRefusedError(
                f"{where}: the build-attested digest {built} disagrees with "
                f"HostSource's independently observed digest {observed} for "
                f"{CANDIDATE_ARTIFACT_SUBJECT}. These are two different "
                "processes reading the SAME wheel; a hand-typed hex string "
                "only ever satisfies one side of this comparison, so a "
                "disagreement here means this evidence was not independently "
                "verified and this type refuses to be built from it"
            )

        return cls(
            repository=repository,
            run_id=run_id,
            artifact_id=artifact_id,
            digest=built,
        )
