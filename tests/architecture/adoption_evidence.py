"""AdoptionEvidenceV1 — the typed, re-checkable adoption claim.

`packages/*/EXTRACTION.toml` used to carry `adoption_evidence` as a list of
free-text ``<repository>:<identity>`` strings, and the only check was that a
string split on a colon into two non-empty halves.  That is addressability, not
verifiability, and the difference is not academic: three defects landed on one
field of one dossier inside a single day and the gate saw none of them.

1.  ``dotmac_erp:dependency:dotmac-deployment-foundation==0.2.0a1`` — true when
    it was read, false hours later when it merged, because ERP repinned in the
    meantime.  A live value copied into another repository's file, where no
    build fails when it drifts.
2.  ``dotmac_erp:main@e1402902`` — eight hex digits AND a branch name.  `main`
    is whatever that repository merged last.
3.  ``dotmac_erp:workflow-run#33248839031`` — a bare run id carries no commit,
    so nothing about the string changed when the tree it exercised did.  It was
    recorded for the a1-era tree and survived the a1→a2 correction untouched,
    presented as evidence for a pin it never exercised.

The organising idea
-------------------

    **A value is permanent if and only if it is scoped to an immutable
    commit.**

"ERP consumes 0.2.0a1" is a statement about a moving branch, so it rots.  "At
commit ``c0de423c``, ERP's ``pyproject.toml`` set the pin to ``0.2.0a1``" is a
statement about a frozen tree.  It was true when written, it is true today, and
it will be true in five years.  It did not become FALSE when ERP repinned; it
became historically superseded, which needs no edit.

Every rule below exists to force the second sentence and forbid the first.

Two families, and why the split is structural
---------------------------------------------

``ASSERTION_KINDS`` — ``adopted``, ``pinned_at``, ``contract_binding``.  A fact
about one field of one file in one tree at one immutable commit.  Carries
``repository``, ``commit``, ``path``, ``field``, ``expected``.  Re-derivable
forever by fetching that commit and reading that field.

``ATTESTATION_KINDS`` — ``workflow_run``, ``deploy_run``, ``image_digest``,
``live_observation``.  An observation of a system that is not a git tree.  There
is no file, so there is no ``path`` and no ``field``; forcing the assertion
shape onto one produces exactly the ``field = "exists"`` pseudo-claims this
module refuses.  It carries its own identity coordinate plus ``observed``,
``observed_at`` and ``observed_by``, because a CI run's logs expire and the
correct report then is `unresolvable`, not `failed` — retention is not
falsification, and a row that records who saw what and when degrades into a
signed human attestation rather than into a dead link.

Historical evidence versus present-tense consumption
----------------------------------------------------

This is the distinction defect 1 destroyed, and it is made STRUCTURAL here
rather than left to a comment.

Every row in `adoption_evidence` is PAST TENSE.  A merged commit proves that
adoption happened; it can never prove that a consumer is current today.  So no
row may carry a present-tense value, and the dossier holds no copy of the live
pin at all.

Where the live answer lives is recorded by `[[adoption_evidence_pointer]]`: a
repository, the paths, the field — and deliberately **no value**.  A pointer
cannot go stale the way a value can, because its failure mode is loud: if the
consumer renames the file the pointer 404s and a checker says so, whereas a
copied value keeps reading fine long after it stopped being true.

A dossier carrying any `pinned_at` row MUST carry a `current_pin` pointer.  That
requirement is the structural sentence "these rows are history; the present
tense is over there, and nobody here holds a second copy of it."

The unmonitored half — stated, not implied
------------------------------------------

ADR-0018 (`AGENTS.md` rule 23): a region is unmonitored rather than exempt, and
that has to be said out loud.  See `UNMONITORED_BY_THIS_GATE`.

This module is `--mode shape`: pure offline structure, no network, no clones.
It validates the vocabulary, the 40-hex commit, the moving-ref refusal, the
family split, the `field` syntax, the pseudo-field refusal, the cohesion of an
attestation with the tree it is attached to, the claim/reference match, and the
pointer's valuelessness.  It would have caught all three defects above.

It CANNOT establish present-tense consumption status.  Nothing in this
repository can: proving that ERP still pins what a 2026-08-29 commit says it
pinned requires reading ERP's tree today.  That is a scheduled external
re-derivation against the cited repositories, and it is NOT built.  The seam for
it is the schema itself — each assertion row is already a complete fetch
instruction and each pointer is already a complete present-tense query.

No field of AdoptionEvidenceV1 may be an input to a permission
--------------------------------------------------------------

Nothing may be retired, published, deployed, merged or approved BECAUSE a row
exists here.  The contract is descriptive only.  A row records that something
happened; it never authorises the next thing.  This is not theoretical: the
`local_copy_retirement` clause of `dotmac-deployment-foundation` once gated
three products' deploy-engine retirement on a `contract_consumers` count, and
that count had gone wrong.  The coupling was severed; this contract must not
re-create it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

#: The version marker a migrated dossier declares.  A dossier that carries typed
#: rows without it is refused: two evidence shapes reachable under one key with
#: no declared version is how a reader ends up guessing which one they have.
SCHEMA_MARKER: Final = "adoption_evidence_schema"
SCHEMA_VALUE: Final = "v1"

#: A fact about one field of one file in one tree at one immutable commit.
ASSERTION_KINDS: Final = frozenset({"adopted", "pinned_at", "contract_binding"})

#: An observation of something that is not a git tree.
ATTESTATION_KINDS: Final = frozenset(
    {"workflow_run", "deploy_run", "image_digest", "live_observation"}
)

EVIDENCE_KINDS: Final = ASSERTION_KINDS | ATTESTATION_KINDS

#: The identity coordinate each attestation kind carries INSTEAD of path/field.
ATTESTATION_IDENTITY: Final = {
    "workflow_run": "run_id",
    "deploy_run": "run_id",
    "image_digest": "digest",
    "live_observation": "subject",
}

#: Closed, not a declaration registry.  ADR-0008 argues for open vocabularies in
#: PRODUCT domains, where a product must be able to name its own without a
#: kernel change.  This one is read across the repository boundary by Governance
#: and the VERIFICATION PROCEDURE DIFFERS PER KIND, so an unknown kind is a claim
#: no checker knows how to check.  It must fail rather than pass through.  Adding
#: a kind is a schema change with a reviewer, which is correct: each new kind is
#: a new verification procedure somebody has to write.
#:
#: The free-text list had already grown an undesigned vocabulary of thirteen
#: prefixes — `main@`, `merge-commit@`, `pull/`, `dependency:`, `workflow-run#`,
#: `production-deploy#`, `local-copy-retired:`, `test:`, `migration:`,
#: `alembic-head:`, `live-schema:`, `catalog-artifact@`, `production-pilot@`,
#: `default-branch:` — three of which duplicated a typed field six lines away in
#: the same file.

#: A commit is exactly 40 lowercase hex.  Not 8, not 12, not a tag, not a branch.
#: Two independent reasons abbreviations are refused even though git resolves
#: them: an abbreviation is only unique in the repository that holds the objects,
#: and this file is read by people and tools that have not cloned it; and an
#: abbreviation is indistinguishable from a truncation somebody performed to make
#: a line fit, so a reader cannot tell whether precision was lost on purpose.
IMMUTABLE_COMMIT: Final = re.compile(r"^[0-9a-f]{40}$")

#: Hex-shaped but not a commit.  Detected separately so the message can say
#: "this is a short SHA" instead of the generic refusal.
HEXISH: Final = re.compile(r"^[0-9a-fA-F]{6,64}$")

#: Names that mean "whatever that repository merged last".  A ref that means
#: something different tomorrow is not a coordinate — `dotmac_governance`
#: ADR 0013 already lists a branch name, "current main" and "latest" among the
#: things that are NOT coordinates.  This is enforcement of an accepted rule,
#: not a new one.
MOVING_REFS: Final = frozenset(
    {
        "main",
        "master",
        "head",
        "trunk",
        "develop",
        "development",
        "latest",
        "default",
        "default-branch",
        "tip",
        "current",
    }
)

#: `field` must name a real key.  These are the ways an author says "the file is
#: there" while appearing to say "the contract is spoken".  A `deploy/product.toml`
#: holding a v2 schema would satisfy `field = "exists"` and count as adoption of
#: v1.
PSEUDO_FIELDS: Final = frozenset({"", "exists", "present", "*", "any", "n/a", "-"})

#: `path` must be parseable by a checker.  A path with no structured extension is
#: refused rather than string-grepped, because a grep result is not a field.
STRUCTURED_SUFFIXES: Final = (".toml", ".yml", ".yaml", ".json")

#: Keys separated by `.`, list indices as `[n]`.  No wildcards, no filters, no
#: expressions — a JSONPath with predicates would let a claim quietly mean "some
#: element somewhere matches", which is not a fact about a named field and cannot
#: be reported usefully when it fails.
FIELD_SYNTAX: Final = re.compile(
    r"^[A-Za-z0-9_.\-]+(\[[0-9]+\])?" r"(\.[A-Za-z0-9_.\-]+(\[[0-9]+\])?)*$"
)

#: This repository.  Reference proof is not adoption (ADR-0006 § 5), and the
#: evidence list was the hole in that rule: the assembly that owns a package
#: proves the wiring works, not that anyone independent chose it.
SELF_REPOSITORY: Final = "dotmac_starter_mt"

ASSERTION_FIELDS: Final = frozenset(
    {"kind", "repository", "commit", "path", "field", "expected", "locator", "note"}
)
ATTESTATION_FIELDS: Final = frozenset(
    {
        "kind",
        "repository",
        "commit",
        "run_id",
        "digest",
        "subject",
        "observed",
        "observed_at",
        "observed_by",
        "locator",
        "note",
    }
)
POINTER_FIELDS: Final = frozenset({"subject", "repository", "paths", "field", "note"})

#: A pointer says WHERE the live answer is.  Any of these would make it say WHAT
#: the live answer is, which is the copied value that rotted in twenty minutes.
POINTER_VALUE_FIELDS: Final = frozenset(
    {"expected", "value", "version", "current", "commit", "observed", "pinned"}
)

ISO_DAY: Final = re.compile(r"^\d{4}-\d{2}-\d{2}$")

#: An `image_digest` is content-addressed and therefore the strongest
#: attestation: one blob, forever, whoever holds it.
DIGEST_SYNTAX: Final = re.compile(r"^sha256:[0-9a-f]{64}$")

#: The same two coordinates, found EMBEDDED in a longer string. A
#: `contract_binding`'s `expected` is a caller's `uses:` line, and the pinned
#: revision sits at the end of it.
EMBEDDED_COORDINATE: Final = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])|sha256:[0-9a-f]{64}"
)


#: ADR-0018 / `AGENTS.md` rule 23: name the unmonitored region rather than
#: implying the local gate covers it.  Each entry is a property this module
#: deliberately does NOT check, and what would have to exist to check it.
UNMONITORED_BY_THIS_GATE: Final = {
    "present_tense_consumption": (
        "Whether a consumer STILL pins what a cited commit says it pinned. "
        "Every row here is past tense by construction. Proving currency means "
        "reading the consumer's tree today, against the "
        "`[[adoption_evidence_pointer]]` coordinates. That is a scheduled "
        "external re-derivation and it is NOT BUILT. It would fetch each "
        "pointer's `repository`/`paths`/`field` at the consumer's current "
        "default branch, compare it with the newest `pinned_at` row's "
        "`expected`, and report SUPERSEDED — never `failed`, because a "
        "superseded historical fact is still a true one."
    ),
    "assertion_resolution": (
        "Whether an assertion's `expected` is what the cited commit actually "
        "holds. Requires fetching `repository@commit` and reading `path`/"
        "`field`. Every input is immutable, so a result is cacheable forever on "
        "`(repository, commit, path, field)` — but it needs network access to "
        "four other repositories and is NOT BUILT. The coordinates in each row "
        "are already a complete fetch instruction; that is the seam."
    ),
    "oracle_resolution": (
        "Whether an attestation's `run_id`/`digest` still resolves and still "
        "reports `observed`. Three outcomes, not two: confirmed, contradicted, "
        "unresolvable. Retention expiry is unresolvable and must NOT turn CI "
        "red — a gate that cannot run is not a gate. NOT BUILT."
    ),
    "in_place_edit_ratchet": (
        "Whether an existing row's `expected` was edited in place rather than "
        "superseded by a new row at a new commit. That is defect 1's literal "
        "mechanism. Detecting it needs the merge-base copy of the dossier, so "
        "it cannot run on a shallow checkout. NOT BUILT; the append-only "
        "discipline is stated review discipline, not a guard."
    ),
    "composition_claim_semantics": (
        "Whether an `adopted` row's `field`/`expected` really DESCRIBES "
        "composition, and whether a `live_observation`'s `subject` really "
        "names this capability. The kind split ('a pin is installation, not "
        "adoption') is checked; the SEMANTICS of the chosen field are not. "
        '`kind = "adopted"` on a row addressing a second dependency entry '
        "would pass, because deciding that `deploy/product.toml`'s `schema` "
        "means composition while `pyproject.toml`'s version does not needs a "
        "reader, not a matcher. Stated review discipline, NOT enforced — a "
        "regex over field names would be a prose scanner wearing a schema, "
        "and `dotmac_governance` ADR 0013 already rejected that shape."
    ),
    "consumer_cross_check": (
        "Whether `contract_consumers` and the set of `adopted` repositories "
        "agree. Deliberately NOT enforced: `contract_consumers` is already "
        "coupled to `status` by the evidence ratchet, and making evidence a "
        "second input to that coupling would put an AdoptionEvidenceV1 field on "
        "a permission path. Stated review discipline instead."
    ),
}


def _problem(where: str, message: str) -> str:
    return f"{where}: {message}" if where else message


def _revision_problem(label: str, value: object) -> str | None:
    """The refusal that is the whole of defect 2, with a specific message each way."""
    if not isinstance(value, str) or not value.strip():
        return (
            f"{label} must be present — an `expected` with no commit to freeze "
            "it to is a standing claim, not a fact"
        )
    text = value.strip()
    if IMMUTABLE_COMMIT.fullmatch(text):
        return None
    head, _, tail = text.partition("@")
    if tail and head.lower() in MOVING_REFS:
        return (
            f"{label} {value!r} names the moving ref {head!r}; a branch is "
            "whatever that repository merged last, so it is not a coordinate"
        )
    if text.lower() in MOVING_REFS:
        return (
            f"{label} {value!r} is a moving ref; `dotmac_governance` ADR 0013 "
            "already lists a branch name and 'latest' among the things that are "
            "not coordinates"
        )
    if HEXISH.fullmatch(text) and len(text) != 40:
        return (
            f"{label} {value!r} is an abbreviated revision ({len(text)} hex "
            "digits); an abbreviation is only unique in a repository the reader "
            "may not have cloned, and is indistinguishable from a truncation"
        )
    return (
        f"{label} {value!r} must be an immutable 40-character lowercase hex " "commit"
    )


def _locator_problem(where: str, locator: object) -> list[str]:
    """A locator is a human handle and is never load-bearing — but it is held to
    the same moving-ref refusal, because a weaker ROLE for a bad coordinate is
    still a bad coordinate in the file."""
    if locator is None:
        return []
    if not isinstance(locator, str) or not locator.strip():
        return [_problem(where, "locator must be a non-empty string when present")]
    text = locator.strip()
    _, _, identity = text.partition(":")
    candidate = identity or text
    head, at, _tail = candidate.partition("@")
    for token in filter(None, (head if at else candidate,)):
        if token.lower() in MOVING_REFS:
            return [
                _problem(
                    where,
                    f"locator {locator!r} names the moving ref {token!r}; "
                    "demoting a branch reference to 'only a locator' does not "
                    "make it point at the same tree tomorrow",
                )
            ]
    return []


def _assertion_problems(
    where: str, row: Mapping[str, Any], kind: str, distribution: str
) -> list[str]:
    problems: list[str] = []

    for absent in sorted(set(row) & (ATTESTATION_FIELDS - ASSERTION_FIELDS)):
        problems.append(
            _problem(
                where,
                f"{kind} is an assertion and must not carry {absent!r}; a file "
                "claim and an oracle lookup are checked by different procedures "
                "and must not be confusable",
            )
        )

    path = row.get("path")
    if not isinstance(path, str) or not path.strip():
        problems.append(
            _problem(where, f"{kind} must cite the `path` its claim is readable in")
        )
    else:
        if path.startswith("/") or ".." in path.split("/"):
            problems.append(
                _problem(where, f"path {path!r} must be repository-relative")
            )
        if not path.lower().endswith(STRUCTURED_SUFFIXES):
            problems.append(
                _problem(
                    where,
                    f"path {path!r} has no structured extension "
                    f"({', '.join(STRUCTURED_SUFFIXES)}); a checker would have to "
                    "grep it, and a grep result is not a field",
                )
            )

    field = row.get("field")
    if not isinstance(field, str) or field.strip().lower() in PSEUDO_FIELDS:
        problems.append(
            _problem(
                where,
                f"{kind}.field {field!r} is not a real key. 'the file is there' "
                "is not 'the contract is spoken' — a descriptor holding a v2 "
                "schema would satisfy it and count as adoption of v1",
            )
        )
    elif not FIELD_SYNTAX.fullmatch(field.strip()):
        problems.append(
            _problem(
                where,
                f"{kind}.field {field!r} is not addressable: dotted keys and "
                "`[n]` indices only, no wildcards, filters or expressions",
            )
        )

    expected = row.get("expected")
    if not isinstance(expected, str) or not expected.strip():
        problems.append(
            _problem(
                where,
                f"{kind} must record the `expected` value the cited field held "
                "at the cited commit; a coordinate with nothing to look FOR is "
                "addressable but not re-checkable",
            )
        )

    # ── claim ↔ reference match ─────────────────────────────────────────────
    # A reference that does not support the claim it is attached to. A
    # `pinned_at` row in THIS package's dossier is a claim about THIS
    # distribution's pin; a row addressing some other distribution's dependency
    # entry is a true fact cited as evidence for something it says nothing
    # about. Checked on the field, which is where the distribution name appears.
    if kind == "pinned_at" and isinstance(field, str) and distribution:
        aliases = {distribution, distribution.replace("-", "_")}
        if not any(alias in field for alias in aliases):
            problems.append(
                _problem(
                    where,
                    f"pinned_at.field {field!r} does not name {distribution!r}; "
                    "the reference does not support the claim it is attached to "
                    "— a pin of some other distribution is a true fact about a "
                    "different subject",
                )
            )

    if kind == "contract_binding" and isinstance(expected, str):
        if not EMBEDDED_COORDINATE.search(expected):
            problems.append(
                _problem(
                    where,
                    "contract_binding.expected must contain the pinned published "
                    f"revision the caller bound to; {expected!r} names no "
                    "immutable coordinate, so the binding cannot fail (rule 28)",
                )
            )

    return problems


def _attestation_problems(where: str, row: Mapping[str, Any], kind: str) -> list[str]:
    problems: list[str] = []

    for present in sorted(set(row) & (ASSERTION_FIELDS - ATTESTATION_FIELDS)):
        problems.append(
            _problem(
                where,
                f"{kind} is an attestation and must not carry {present!r}; there "
                "is no file to read, and dressing an oracle lookup as a "
                "re-checkable file claim is how a stale run id survives a "
                "correction untouched",
            )
        )

    identity = ATTESTATION_IDENTITY[kind]
    for other_kind, other in sorted(ATTESTATION_IDENTITY.items()):
        if other != identity and other in row:
            problems.append(
                _problem(
                    where,
                    f"{kind} carries {other!r}, which belongs to {other_kind!r}",
                )
            )
    value = row.get(identity)
    if not isinstance(value, str) or not value.strip():
        problems.append(_problem(where, f"{kind} must carry a non-empty {identity!r}"))
    elif kind == "image_digest" and not DIGEST_SYNTAX.fullmatch(value.strip()):
        problems.append(
            _problem(
                where,
                f"image_digest.digest {value!r} must be `sha256:<64 hex>`; an "
                "image by TAG is not a coordinate",
            )
        )

    observed = row.get("observed")
    if not isinstance(observed, str) or not observed.strip():
        problems.append(_problem(where, f"{kind} must record what was `observed`"))

    observed_at = row.get("observed_at")
    if not isinstance(observed_at, str) or not ISO_DAY.fullmatch(observed_at.strip()):
        problems.append(
            _problem(
                where,
                f"{kind}.observed_at must be an ISO `YYYY-MM-DD` day. A run's "
                "logs expire, so this row will one day rest entirely on who saw "
                "it and when; an undated observation degrades into a dead link "
                "instead of a signed human attestation",
            )
        )

    observed_by = row.get("observed_by")
    if not isinstance(observed_by, str) or not observed_by.strip():
        problems.append(
            _problem(where, f"{kind} must record `observed_by` for the same reason")
        )

    return problems


def _pointer_problems(where: str, row: Mapping[str, Any]) -> list[str]:
    problems: list[str] = []
    unknown = sorted(set(row) - POINTER_FIELDS)
    for key in unknown:
        if key in POINTER_VALUE_FIELDS:
            problems.append(
                _problem(
                    where,
                    f"pointer carries {key!r}. A pointer says WHERE the live "
                    "answer is and deliberately holds no copy of it: a value "
                    "here is a second copy in another repository with no build "
                    "that fails when it drifts, which is precisely the shape "
                    "that went stale in twenty minutes",
                )
            )
        else:
            problems.append(_problem(where, f"pointer has unknown field {key!r}"))

    for field in ("subject", "repository", "field"):
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            problems.append(
                _problem(where, f"pointer.{field} must be a non-empty string")
            )

    paths = row.get("paths")
    if (
        not isinstance(paths, list)
        or not paths
        or not all(isinstance(p, str) and p.strip() for p in paths)
    ):
        problems.append(
            _problem(where, "pointer.paths must be a non-empty string list")
        )

    field = row.get("field")
    if (
        isinstance(field, str)
        and field.strip()
        and not FIELD_SYNTAX.fullmatch(field.strip())
    ):
        problems.append(_problem(where, f"pointer.field {field!r} is not addressable"))

    return problems


def evidence_problems(
    *,
    rows: object,
    pointers: object,
    schema_marker: object,
    distribution: str,
    where: str = "",
) -> list[str]:
    """Validate one dossier's (or one slice's) adoption evidence, offline.

    `rows` is what the dossier holds under `adoption_evidence`; `pointers` is
    `adoption_evidence_pointer`; `schema_marker` is `adoption_evidence_schema`.
    An empty `rows` is a caller's business — this module says nothing about
    whether a status is entitled to be empty; that ratchet lives in the dossier
    gate and is deliberately kept separate, because a permission and a shape
    check must not be the same test.
    """
    problems: list[str] = []

    if not isinstance(rows, list):
        return [_problem(where, "adoption_evidence must be an array of tables")]

    if not rows:
        if pointers:
            problems.append(
                _problem(where, "adoption_evidence_pointer with no evidence rows")
            )
        return problems

    if schema_marker != SCHEMA_VALUE:
        problems.append(
            _problem(
                where,
                f"{SCHEMA_MARKER} must be {SCHEMA_VALUE!r} wherever typed rows "
                "are present; an undeclared shape leaves a reader guessing which "
                "of two contracts they are holding",
            )
        )

    assertion_commits: dict[str, set[str]] = {}
    seen: set[tuple[Any, ...]] = set()

    for index, row in enumerate(rows):
        here = _problem(where, f"adoption_evidence[{index}]").rstrip(":")
        if isinstance(row, str):
            problems.append(
                f"{here}: {row!r} is a free-text string. AdoptionEvidenceV1 is "
                "typed; an untyped reference proves only that somebody could "
                "find something, which is addressability, not verifiability"
            )
            continue
        if not isinstance(row, Mapping):
            problems.append(f"{here}: must be a table")
            continue

        kind = row.get("kind")
        if kind not in EVIDENCE_KINDS:
            problems.append(
                f"{here}: unknown kind {kind!r}. The vocabulary is closed "
                "because the verification procedure differs per kind, so a kind "
                f"nobody wrote a procedure for cannot be checked. Known: "
                f"{sorted(EVIDENCE_KINDS)}"
            )
            continue

        allowed = ASSERTION_FIELDS if kind in ASSERTION_KINDS else ATTESTATION_FIELDS
        unknown = sorted(set(row) - allowed)
        # Reported by the family checks below where the field belongs to the
        # other family; anything else is simply not part of the contract.
        cross = (ATTESTATION_FIELDS | ASSERTION_FIELDS) - allowed
        for key in unknown:
            if key not in cross:
                problems.append(f"{here}: unknown field {key!r}")

        repository = row.get("repository")
        if not isinstance(repository, str) or not repository.strip():
            problems.append(f"{here}: repository must be a non-empty string")
            repository = ""
        elif "/" in repository or ":" in repository:
            problems.append(
                f"{here}: repository {repository!r} is a URL or registry path, "
                "not a repository name. A registry coordinate is an "
                "`image_digest` whose `repository` names the PRODUCING product"
            )
        elif kind in ASSERTION_KINDS and repository == SELF_REPOSITORY:
            problems.append(
                f"{here}: {SELF_REPOSITORY!r} cannot assert its own adoption. "
                "Reference proof is not adoption (ADR-0006 § 5), and this list "
                "was the hole that rule left open"
            )

        revision_problem = _revision_problem("commit", row.get("commit"))
        if revision_problem:
            problems.append(f"{here}: {revision_problem}")
        elif kind in ASSERTION_KINDS and isinstance(repository, str) and repository:
            assertion_commits.setdefault(repository, set()).add(str(row["commit"]))

        problems.extend(_locator_problem(here, row.get("locator")))

        if kind in ASSERTION_KINDS:
            problems.extend(_assertion_problems(here, row, kind, distribution))
        else:
            problems.extend(_attestation_problems(here, row, kind))

        signature = (
            kind,
            repository,
            row.get("commit"),
            row.get("path"),
            row.get("field"),
            row.get("run_id"),
            row.get("digest"),
            row.get("subject"),
        )
        if signature in seen:
            problems.append(f"{here}: duplicates an earlier row")
        seen.add(signature)

    # ── cohesion: an attestation belongs to a tree this dossier cites ───────
    # Defect 3. A run id carries no commit of its own, so nothing about the
    # string changes when the tree it exercised does. Requiring the attestation's
    # `commit` to be one an assertion in the same dossier cites for the same
    # repository makes the drift visible the moment the assertions move: the run
    # recorded for the a1-era tree would have failed the instant the pin rows
    # were corrected to a2, instead of sitting beside them for a day looking
    # like evidence for them.
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        kind = row.get("kind")
        if kind not in ATTESTATION_KINDS:
            continue
        repository = row.get("repository")
        commit = row.get("commit")
        if not isinstance(repository, str) or not isinstance(commit, str):
            continue
        if not IMMUTABLE_COMMIT.fullmatch(commit):
            continue
        cited = assertion_commits.get(repository)
        if cited is None:
            problems.append(
                _problem(
                    where,
                    f"adoption_evidence[{index}]: {kind} attests {repository!r} "
                    "but no assertion in this dossier cites that repository — an "
                    "observation with no tree behind it cannot be tied to "
                    "anything",
                )
            )
        elif commit not in cited:
            problems.append(
                _problem(
                    where,
                    f"adoption_evidence[{index}]: {kind} was observed against "
                    f"{repository}@{commit[:12]}…, which no assertion in this "
                    "dossier cites. An unrelated run is not evidence for the "
                    "claims beside it; cited commits are "
                    f"{sorted(c[:12] for c in cited)}",
                )
            )

    # ── the present-tense half is pointed at, never copied ──────────────────
    pointer_rows = pointers if isinstance(pointers, list) else []
    if pointers is not None and not isinstance(pointers, list):
        problems.append(
            _problem(where, "adoption_evidence_pointer must be an array of tables")
        )
    subjects: set[str] = set()
    for index, row in enumerate(pointer_rows):
        here = f"adoption_evidence_pointer[{index}]"
        here = _problem(where, here).rstrip(":")
        if not isinstance(row, Mapping):
            problems.append(f"{here}: must be a table")
            continue
        problems.extend(_pointer_problems(here, row))
        subject = row.get("subject")
        if isinstance(subject, str):
            subjects.add(subject)

    has_pin = any(
        isinstance(row, Mapping) and row.get("kind") == "pinned_at" for row in rows
    )
    if has_pin and "current_pin" not in subjects:
        problems.append(
            _problem(
                where,
                "a dossier carrying `pinned_at` history must carry a "
                "`current_pin` [[adoption_evidence_pointer]]. Every row here is "
                "past tense; without the pointer a reader has no way to tell "
                "the newest historical pin from the live one, which is exactly "
                "the confusion that put a twenty-minute-old value in this file",
            )
        )

    # A pointer and an assertion addressing the same coordinate means the live
    # value HAS been copied after all, just spread over two rows.
    pointed: set[tuple[str, str, str]] = set()
    for row in pointer_rows:
        if not isinstance(row, Mapping):
            continue
        repository = row.get("repository")
        field = row.get("field")
        paths = row.get("paths")
        if not (isinstance(repository, str) and isinstance(field, str)):
            continue
        for path in paths if isinstance(paths, list) else []:
            if isinstance(path, str):
                pointed.add((repository, path, field))

    return problems


# ── A pin is installation, not adoption ─────────────────────────────────────
#
# AdoptionEvidenceV1 typed the COORDINATE and left the CLAIM untyped.  A
# dossier's `status` could say `adopted` while every row beneath it recorded
# only that some consumer's dependency file names the distribution — and nine
# of the ten dossiers migrated in #496 came out exactly that way: `pinned_at`
# and no `adopted` row.  Nothing was red, because the status coupling and the
# row vocabulary were checked by two functions that never compared notes.
#
# The ruling that closes it:
#
#     A pin is installation, not adoption.  An exact pin means INSTALLED.
#     Lineage absent + storage absent + writer unchanged means NOT COMPOSED,
#     and therefore NOT ADOPTED.
#
# `dotmac-tax` is the case it was ruled on: ERP pins `dotmac-tax 0.1.0a3` at an
# exact commit, and ERP's own
# `app/services/finance/tax/adoption/composition.py` declares the module NOT
# COMPOSED — the `tx` lineage is absent from `alembic.ini`, `mod_tax` exists in
# no ERP database, and no writer is repointed.  Every one of those facts is
# true at once; the pin is simply not the fact that was being claimed.
#
# So each kind is classified by what it can prove ON ITS OWN.  The
# classification is TOTAL: a kind added later without being placed on one side
# would count as neither, and the guard would weaken by omission rather than by
# decision.  `test_every_evidence_kind_is_classified_by_the_adoption_split`
# fails in that case.

#: Rows that prove a consumer INSTALLED, SHIPPED or BOUND the distribution.
#: Necessary for adoption and never sufficient for it.
#:
#: `deploy_run` and `image_digest` sit here for a reason visible in this
#: repository's own data rather than by argument: run `32022599873` and digest
#: `sha256:56ec5531…` are each cited by THREE dossiers (`dotmac-approvals`,
#: `dotmac-entitlement-allocation`, `dotmac-release-catalog`), and run
#: `32485479666` with digest `sha256:45715e42…` by two more.  One observation
#: that is equally true of several distributions cannot say which capability
#: was composed; it says an image containing all of them shipped, which is
#: installation at fleet scale.  `workflow_run` is weaker still — CI exercising
#: a tree is not that tree running anything in production.
INSTALLATION_KINDS: Final = frozenset(
    {"pinned_at", "contract_binding", "workflow_run", "deploy_run", "image_digest"}
)

#: Rows that can prove COMPOSITION or CUTOVER, which is what adoption means.
#:
#: `adopted` — an assertion: one structured field of one file in the consumer's
#: tree, at an immutable commit, declaring that the capability is composed or
#: that the local writer moved.  Re-derivable forever.
#:
#: `live_observation` — an attestation, and the weaker of the two, but it is
#: the one that carries a per-capability `subject`: `mod_approvals`,
#: `mod_ealloc`, `mod_relcat`, a launcher exercised in a production pilot.  A
#: subject naming THIS capability inside the consumer's running system is a
#: statement about composition that a shared image digest cannot make.  It
#: decays, which is why it is dated and signed, and why it is never rendered as
#: a statement about today.
ADOPTION_PROVING_KINDS: Final = frozenset({"adopted", "live_observation"})

#: States in which an `adopted` ROW is admissible although the dossier no
#: longer claims a live adoption — a "was adopted, since superseded" state.
#:
#: DELIBERATELY EMPTY, and the emptiness is the claim.  The dossier vocabulary
#: (`audit-complete`, `adopted`, `reuse-proven`) has no such member today, so
#: an `adopted` row under a non-adoption status is unconditionally a
#: contradiction: either the row is wrong or the status is.  `PRE_RULE_DEBT`'s
#: `historical-pre-rule` is NOT such a state — ADR-0018 requires
#: "grandfathered" to stay distinguishable from "reviewed and correct", and
#: reusing a debt marker as a superseded-adoption state would collapse exactly
#: that distinction.  The parameter exists so that adding such a state later is
#: a schema decision with a reviewer, not a quiet loosening of this refusal;
#: `test_a_historical_state_admits_the_row_it_is_defined_for` proves the branch
#: is live rather than dead code.
HISTORICAL_ADOPTION_STATES: Final = frozenset()


def rests_on_installation_alone(
    *, status: object, rows: object, adoption_states: frozenset[str]
) -> bool:
    """True when a status claims composition and no row can prove one.

    Exposed separately from the refusal so a caller can run the ratchet over
    the whole tree (which entries are still in this shape?) without catching a
    refusal it is about to suppress.  One predicate, two readers — a second
    hand-rolled copy of this test is how a backlog and its guard drift apart.
    """
    if not isinstance(status, str) or status not in adoption_states:
        return False
    kinds = {
        row.get("kind")
        for row in (rows if isinstance(rows, list) else [])
        if isinstance(row, Mapping)
    }
    return not (kinds & ADOPTION_PROVING_KINDS)


def adoption_state_problems(
    *,
    status: object,
    rows: object,
    adoption_states: frozenset[str],
    historical_states: frozenset[str] = HISTORICAL_ADOPTION_STATES,
    installation_only_is_declared_debt: bool = False,
    where: str = "",
) -> list[str]:
    """The two-directional coupling between a dossier's `status` and its rows.

    Kept out of `evidence_problems` on purpose.  That function answers "is this
    row well formed"; this one answers "does the claim above match the rows
    below", and the caller supplies its own status vocabulary rather than this
    module importing one.  A shape check and a claim check must stay separable,
    or a dossier can be made green by weakening the wrong half.

    Both directions, because the previous model only ever ran one of them:

    1.  A status that asserts a product RAN the capability, with nothing but
        installation rows beneath it.  This is `dotmac-tax` and it is the whole
        point.
    2.  An `adopted` ROW under a status that does not claim adoption.  A row is
        the stronger statement of the two, so the dossier is contradicting
        itself in the direction that under-reports the fleet — the same failure
        ADR-0006's 2026-08-12 amendment calls "a false statement about the
        fleet rather than a missing one".

    `installation_only_is_declared_debt` suppresses direction 1 ONLY, for a
    scope the caller's exact, two-directional backlog already names.  It never
    suppresses direction 2, and it is not an exemption in ADR-0018's sense:
    the premise ("this scope is in the map") is machine-checked in the same
    change, and the map fails when it grows OR shrinks without being edited.

    Nothing here is an input to a permission.  It refuses a self-contradictory
    file; it authorises nothing.
    """
    problems: list[str] = []
    kinds = {
        row.get("kind")
        for row in (rows if isinstance(rows, list) else [])
        if isinstance(row, Mapping)
    }

    if isinstance(status, str) and status in adoption_states:
        if not (kinds & ADOPTION_PROVING_KINDS) and not (
            installation_only_is_declared_debt
        ):
            present = sorted(k for k in kinds if isinstance(k, str))
            problems.append(
                _problem(
                    where,
                    f"status {status!r} claims a product composed this "
                    f"capability, but the evidence is {present or 'empty'} — "
                    f"only {sorted(INSTALLATION_KINDS)} rows, which record what "
                    "a consumer INSTALLED, SHIPPED or BOUND. A pin is "
                    "installation, not adoption: lineage absent, storage absent "
                    "and writer unchanged are all compatible with an exact pin. "
                    f"Cite an {sorted(ADOPTION_PROVING_KINDS)} row, or claim the "
                    "state the evidence supports",
                )
            )
    elif isinstance(status, str) and status not in historical_states:
        if "adopted" in kinds:
            problems.append(
                _problem(
                    where,
                    f"an `adopted` row sits under status {status!r}, which does "
                    "not claim adoption. The row is the stronger statement, so "
                    "one of the two is wrong; the schema defines no "
                    "historical/superseded state that would admit both "
                    f"(historical states: {sorted(historical_states) or 'none'})",
                )
            )

    return problems


def free_text_problems(where: str, rows: object) -> list[str]:
    """The regression bar: no dossier may reintroduce an untyped reference.

    Kept separate from `evidence_problems` so the refusal has its own name in a
    failure message, and so a caller that only wants the ratchet does not have
    to run the whole shape check.
    """
    if not isinstance(rows, list):
        return []
    return [
        _problem(
            where,
            f"adoption_evidence[{index}] is the free-text string {row!r}; "
            "AdoptionEvidenceV1 replaced that shape and it may not come back",
        )
        for index, row in enumerate(rows)
        if isinstance(row, str)
    ]


def iter_rows(dossier: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    """Every typed row a dossier holds, package level and slices together."""
    found: list[Mapping[str, Any]] = []
    for row in dossier.get("adoption_evidence") or []:
        if isinstance(row, Mapping):
            found.append(row)
    for entry in dossier.get("slices") or []:
        if isinstance(entry, Mapping):
            for row in entry.get("adoption_evidence") or []:
                if isinstance(row, Mapping):
                    found.append(row)
    return tuple(found)


def rows_of_kind(dossier: Mapping[str, Any], kind: str) -> Sequence[Mapping[str, Any]]:
    return tuple(row for row in iter_rows(dossier) if row.get("kind") == kind)
