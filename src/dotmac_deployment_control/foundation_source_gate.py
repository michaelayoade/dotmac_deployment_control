"""A required CI gate, not a diagnostic: Foundation's OWN source, read cold.

## Why this module exists

`rehearsal_grant.FOUNDATION_STEP_KINDS` is a mirror — a literal, transcribed by
hand from Foundation's `StepKind`. `test_the_step_vocabulary_matches_the_
installed_executor_when_one_is_present` compared it against the real thing only
when Foundation happened to be importable, which in this repository's own CI is
NEVER: `pytest.importorskip` always skips there, so that comparison was
diagnostic rather than enforced — a check that could not fail because it never
ran.

Michael's ruling closes that gap without making Control the author of
Foundation's vocabulary and without making Control depend on
`dotmac-deployment-foundation` (which is not published past `0.2.0a2` — see
`rehearsal_grant.FOUNDATION_STEP_KIND_SOURCE`'s docstring — so a version-pinned
dependency could not even see the steps this gate exists to check):

    "This is not another mirror: the compared value comes from Foundation-owned
    source."

The mechanism: read the bytes AT THE PINNED IMMUTABLE COMMIT
`FOUNDATION_STEP_KIND_SOURCE` names, parse the `StepKind` class out of them with
`ast` — never `import`, never `pip install` — and compare the result against
the mirror with the SAME complete-set-equality comparator
(`rehearsal_grant.foundation_step_vocabulary_drift`) the synthetic sensitivity
tests already prove is sensitive to an addition, a removal, and a same-count
rename (a rename is simultaneously one addition and one removal, so it cannot
pass a symmetric-difference check no matter how the two sets happen to be
sized).

## Fail-closed, on all five axes

`require_foundation_step_vocabulary_agreement` raises
`FoundationStepVocabularySourceError` when the source cannot be READ at all
(`SourceReader.read` raises) or cannot be PARSED in the narrow shape this
module understands (no `StepKind` class; a member whose value is not a bare
string literal — an expression, a call, an f-string, `auto()`), and raises
`FoundationStepVocabularyDriftError` when the source parses cleanly but
disagrees with the mirror by even one member in either direction. There is no
code path that treats "could not tell" as "must agree".

## Reading, without installing

`SourceReader` is a `Protocol` for the identical reason `host_source
.InstalledMetadata` is one in the Foundation's own repository: the thing being
checked must not also be the thing supplying the answer to a test. The
production reader (`scripts/foundation_step_vocabulary_gate.py`) fetches the
pinned commit's raw file over HTTPS with nothing beyond the standard library —
no git checkout, no package install, no `dotmac-deployment-foundation`
dependency of any kind, dev or runtime. Every function in THIS module is pure
and injected with the reader, so the AST parsing and the comparison — the parts
whose sensitivity must be provable in every CI run — are testable with a
synthetic string and no network access at all.

## Two forward obligations, recorded rather than implemented

1. The pinned coordinate this module reads must be kept pointed at the SAME
   commit `rehearsal_grant.FOUNDATION_STEP_KIND_SOURCE` names — the day that pin
   moves to a successor candidate's source, this gate's coordinate moves with
   it, in the same commit, or the two are checking different Foundations.
2. This gate — reading Foundation's SOURCE at a pinned commit — is itself
   transitional. Once a successor candidate exists, grant issuance should
   derive its step vocabulary directly from the VERIFIED WHEEL that candidate
   names (the same `HostSource`/`CandidateArtifact.v1` chain
   `digests.FoundationArtifactDigestV1` binds), not from a second read of
   Foundation's Python source. A mirror checked against source is better than
   an unchecked mirror; deriving the vocabulary from the verified artifact
   itself needs no mirror and no gate at all.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from dotmac_deployment_control.ports import (
    FoundationStepVocabularyDriftError,
    FoundationStepVocabularySourceError,
)
from dotmac_deployment_control.rehearsal_grant import (
    FOUNDATION_STEP_KIND_SOURCE,
    foundation_step_vocabulary_drift,
)

__all__ = [
    "STEP_KIND_CLASS_NAME",
    "SourceCoordinate",
    "SourceReader",
    "extract_step_kind_members",
    "parse_source_coordinate",
    "require_foundation_step_vocabulary_agreement",
]

#: The class this gate looks for. Foundation names its own; this is not a
#: claim that Control owns the name, only the string this narrow reader
#: searches for in the text it is handed.
STEP_KIND_CLASS_NAME = "StepKind"


@dataclass(frozen=True, slots=True)
class SourceCoordinate:
    """`<repository>@<commit>:<path>`, parsed into its three parts."""

    repository: str
    commit: str
    path: str


def parse_source_coordinate(value: str) -> SourceCoordinate:
    """Parse `FOUNDATION_STEP_KIND_SOURCE`'s own format.

    STRICT: a coordinate naming a branch instead of a commit is exactly the
    moving-ref shape this gate exists to refuse admitting as pinned, so a
    `commit` that is not a full 40-character lowercase-hex SHA is refused
    rather than accepted and silently trusted.
    """
    repository, _, rest = value.partition("@")
    commit, _, path = rest.partition(":")
    if not repository or not commit or not path:
        raise FoundationStepVocabularySourceError(
            f"{value!r} is not `<repository>@<commit>:<path>`. A malformed "
            "coordinate names nothing this gate can read"
        )
    if len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise FoundationStepVocabularySourceError(
            f"{commit!r} is not a full 40-character lowercase-hex commit SHA. "
            "A branch name or a short hash is a MOVING reference, and this "
            "gate exists to check a PINNED one"
        )
    return SourceCoordinate(repository=repository, commit=commit, path=path)


@runtime_checkable
class SourceReader(Protocol):
    """How this gate reads bytes, without ever importing them.

    A fake implementation returning a synthetic literal string is what lets
    every failure mode below be exercised with no network access — the exact
    role `host_source.InstalledMetadata` plays for the Foundation's own
    equivalent gate.
    """

    def read(self, coordinate: SourceCoordinate) -> str:
        """The exact source text at `coordinate`, or raise on any failure.

        Any raised exception is treated as SOURCE UNAVAILABLE — this module
        does not inspect the exception type, because every reason a read can
        fail (network, authentication, a renamed path, a rewritten history)
        leads to the identical repair: the pin cannot be checked right now,
        and pretending otherwise is worse than saying so.
        """


def extract_step_kind_members(source: str) -> frozenset[str]:
    """Pull `StepKind`'s string-literal values out of Python SOURCE TEXT.

    `ast.parse`, never `import` or `exec` — this reads syntax, not code, so a
    file with side effects at import time or a dependency this repository does
    not have cannot affect the result and cannot run.

    NARROW ON PURPOSE. Only `NAME = "literal"` assignments directly inside a
    class named `STEP_KIND_CLASS_NAME` are admitted. Anything else this gate
    is asked to read — no such class, a value that is not a bare string
    constant (a call, an f-string, `auto()`, a reference to another name) — is
    a REFUSAL (`FoundationStepVocabularySourceError`), not a best-effort partial
    read, because a partial read that quietly drops a member it could not
    parse would silently produce exactly the "missing member" false negative
    this whole gate exists to catch.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise FoundationStepVocabularySourceError(
            f"the pinned source is not parsable Python: {error}. Foundation's "
            "own file changed shape in a way this narrow AST reader does not "
            "understand, or the wrong bytes were read"
        ) from error

    step_kind_class: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == STEP_KIND_CLASS_NAME:
            step_kind_class = node
            break
    if step_kind_class is None:
        raise FoundationStepVocabularySourceError(
            f"no `class {STEP_KIND_CLASS_NAME}` was found in the pinned "
            "source. Either the coordinate is wrong or Foundation renamed or "
            "removed the class this gate reads"
        )

    members: set[str] = set()
    for statement in step_kind_class.body:
        if not isinstance(statement, ast.Assign):
            # Docstrings, comments (not nodes), decorators on methods, etc.
            # are ignored; only plain `NAME = value` assignments are read.
            continue
        if not isinstance(statement.value, ast.Constant) or not isinstance(
            statement.value.value, str
        ):
            raise FoundationStepVocabularySourceError(
                "a StepKind member's value is not a bare string literal "
                f"(found {ast.dump(statement.value)!r}). This narrow AST "
                "reader refuses rather than silently skipping a member it "
                "cannot evaluate, because a computed or referenced value "
                "could be anything"
            )
        members.add(statement.value.value)

    if not members:
        raise FoundationStepVocabularySourceError(
            f"`class {STEP_KIND_CLASS_NAME}` was found but no string-literal "
            "member assignments were read out of it. An empty vocabulary is "
            "not a step vocabulary; refusing rather than comparing against "
            "nothing"
        )
    return frozenset(members)


def require_foundation_step_vocabulary_agreement(
    reader: SourceReader,
    *,
    coordinate: str = FOUNDATION_STEP_KIND_SOURCE,
) -> None:
    """THE GATE. Read Foundation's pinned source; refuse any disagreement.

    Fail-closed on every one of the five axes: the coordinate itself being
    malformed, the read failing, the source being unparsable in the narrow
    shape this module understands, an ADDITION, a REMOVAL, and — the case a
    subset or count comparison would miss — a same-count RENAME, which
    registers as one addition and one removal simultaneously and so cannot
    pass `foundation_step_vocabulary_drift`'s complete-set-equality check no
    matter how the two sets happen to be sized.
    """
    parsed = parse_source_coordinate(coordinate)
    try:
        source_text = reader.read(parsed)
    except FoundationStepVocabularySourceError:
        raise
    except Exception as error:  # broad on purpose; see `SourceReader.read`
        raise FoundationStepVocabularySourceError(
            f"could not read {coordinate!r}: {error}. The pin cannot be "
            "checked right now, and this gate refuses rather than treating "
            "an unreadable source as an agreeing one"
        ) from error

    observed = extract_step_kind_members(source_text)
    drift = foundation_step_vocabulary_drift(observed)
    if drift:
        raise FoundationStepVocabularyDriftError(
            f"Foundation's pinned source at {coordinate!r} disagrees with the "
            f"mirrored FOUNDATION_STEP_KINDS by {sorted(drift)!r}. Every "
            "member in that set is in exactly one of the two vocabularies — "
            "new to the source, retired from it, or the two halves of a "
            "same-count rename — and the mirror in rehearsal_grant.py must be "
            "updated to match before this gate can pass again"
        )
