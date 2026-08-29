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

import ast
import re
import tomllib
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

#: A fact about the SHAPE of one Python file in one tree at one immutable
#: commit, established by parsing it — never by executing or importing it.
#:
#: A third family rather than a member of `ASSERTION_KINDS`, and the split is
#: structural for the same reason the assertion/attestation split is.  A TOML
#: assertion addresses a `field`: a key path a reader resolves to a value.  A
#: Python source file has no such thing.  Composition in a real assembly is a
#: NAME appearing as a member of a registration collection, or a call inside a
#: named function — a position in a syntax tree, not a key.  Forcing that onto
#: `field` would produce either a dotted pseudo-key nobody can resolve or a grep
#: pattern, and `STRUCTURED_SUFFIXES` already refuses `.py` precisely because
#: "a grep result is not a field".
#:
#: The gap this closes is not hypothetical.  Vendor Control Plane composes
#: `dotmac-deployment-control` in `src/vendor_cp/assembly.py` and registers its
#: migration lineage in `src/vendor_cp/migrations.py`.  Neither fact is
#: expressible as a TOML field, so the only row the old vocabulary could carry
#: was `pinned_at` — which is installation, not adoption.  That is how nine of
#: the ten dossiers migrated in #496 came out pin-only, and it has now recurred
#: on `dotmac-auth-oidc`, both `dotmac-ui` slices and this package.
#: SOURCE-LEVEL, ALWAYS. `composed_at` reads a tree; it can never say anything
#: about a running system. "The consumer's assembly names this module at commit
#: X" and "this is running in production" are different claims with different
#: oracles, and only `PRODUCTION_PROVING_KINDS` can make the second. A dossier
#: whose adoption rests entirely on `composed_at` has proven composition on a
#: branch and nothing more.
AST_ASSERTION_KINDS: Final = frozenset({"composed_at"})

EVIDENCE_KINDS: Final = ASSERTION_KINDS | ATTESTATION_KINDS | AST_ASSERTION_KINDS

#: Kinds whose claim is a fact about a FILE IN A TREE, whichever family reads
#: it.  Two rules key off "is there a tree behind this row" rather than off the
#: family: the self-assertion refusal, and the pool of commits an attestation
#: may cohere with.  Spelling those as `ASSERTION_KINDS` was correct while the
#: assertion family was the only tree-reading one; it silently stops being
#: correct the moment a second one exists.
TREE_KINDS: Final = ASSERTION_KINDS | AST_ASSERTION_KINDS

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
AST_ASSERTION_FIELDS: Final = frozenset(
    {
        "kind",
        "repository",
        "commit",
        "path",
        "module",
        "symbol",
        "construct",
        "within",
        "proves",
        "expected",
        "locator",
        "note",
    }
)

#: What a `composed_at` row claims the syntax tree shows.  Closed, and closed
#: for the same reason `EVIDENCE_KINDS` is: each member is a different tree
#: walk, so a construct nobody wrote a walk for cannot be checked.
#:
#: `collection_member` — the imported name is an element of a list/tuple/set
#: literal assigned to `within`.  This is a module roster: `STATEFUL_MODULES`,
#: `COMPOSED_MODULES`, a feature tuple.
#: `call` — the imported name is INVOKED inside the function `within`.  This is
#: how a migration lineage is registered: `composed_version_locations()` calls
#: each module's `versions_dir()`.
COMPOSITION_CONSTRUCTS: Final = frozenset({"collection_member", "call"})

#: The two halves a composition claim must prove SEPARATELY.  A module whose
#: manifest is registered but whose lineage is not composed installs tables
#: nobody migrates; a lineage composed without the manifest migrates tables
#: nothing registers.  Both are real, both look adopted from one row, and the
#: dossier gate below refuses a claim that carries only one.
COMPOSITION_PROOFS: Final = frozenset({"module_registration", "migration_lineage"})

#: A Python module path, and a Python identifier.  Neither is a `field`: they
#: are resolved by the parser, not by walking a mapping.
DOTTED_MODULE: Final = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
)
PY_IDENTIFIER: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

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
        "are already a complete fetch instruction; that is the seam. PARTIAL "
        "as of the `composed_at` kind: the verification PROCEDURE now exists "
        "(`composition_claim_problems`, a pure function of source bytes) and is "
        "exercised against verbatim consumer files captured at the cited "
        "commit, whose git blob ids this repository re-derives offline. What is "
        "still NOT BUILT is the FETCH: nothing here reads the consumer's "
        "repository, so a captured fixture going stale against a NEW commit is "
        "invisible. The fixture is pinned to one immutable commit, so it cannot "
        "become wrong about that commit — only incomplete about later ones."
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
        "and `dotmac_governance` ADR 0013 already rejected that shape. This "
        "remains true of `adopted`. It is NO LONGER true of `composed_at`, "
        "whose semantics are not chosen by the author at all: the row names a "
        "module, a symbol, a construct and an enclosing name, and the walk "
        "either finds that shape in the syntax tree or does not. There is no "
        "field for a reader to agree with."
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


def _ast_assertion_problems(where: str, row: Mapping[str, Any], kind: str) -> list[str]:
    """Shape of a `composed_at` row.  The tree walk itself is
    `python_composition_problems`; this only checks the claim is well formed
    enough to be walked."""
    problems: list[str] = []

    for absent in sorted(
        set(row) & ((ASSERTION_FIELDS | ATTESTATION_FIELDS) - AST_ASSERTION_FIELDS)
    ):
        problems.append(
            _problem(
                where,
                f"{kind} is a source-shape assertion and must not carry "
                f"{absent!r}. A `field` is a key path a reader resolves in a "
                "mapping; a Python file has none, and offering one would invite "
                "exactly the grep-dressed-as-a-field claim `STRUCTURED_SUFFIXES` "
                "exists to refuse",
            )
        )

    path = row.get("path")
    if not isinstance(path, str) or not path.strip():
        problems.append(
            _problem(where, f"{kind} must cite the `path` of the source it claims")
        )
    else:
        if path.startswith("/") or ".." in path.split("/"):
            problems.append(
                _problem(where, f"path {path!r} must be repository-relative")
            )
        if not path.endswith(".py"):
            problems.append(
                _problem(
                    where,
                    f"{kind}.path {path!r} is not a Python source file. This kind "
                    "exists because composition is a position in a syntax tree; "
                    "a structured document carries a `field` and belongs to an "
                    f"{sorted(ASSERTION_KINDS)} kind instead",
                )
            )

    module = row.get("module")
    if not isinstance(module, str) or not DOTTED_MODULE.fullmatch(module.strip()):
        problems.append(
            _problem(
                where,
                f"{kind}.module {module!r} must be the importable module the "
                "consumer imports FROM, as a dotted Python path",
            )
        )

    for key in ("symbol", "within"):
        value = row.get(key)
        if not isinstance(value, str) or not PY_IDENTIFIER.fullmatch(value.strip()):
            problems.append(
                _problem(where, f"{kind}.{key} {value!r} must be a Python identifier")
            )

    construct = row.get("construct")
    if construct not in COMPOSITION_CONSTRUCTS:
        problems.append(
            _problem(
                where,
                f"{kind}.construct {construct!r} is unknown; each construct is a "
                f"different tree walk, so the vocabulary is closed. Known: "
                f"{sorted(COMPOSITION_CONSTRUCTS)}",
            )
        )

    proves = row.get("proves")
    if proves not in COMPOSITION_PROOFS:
        problems.append(
            _problem(
                where,
                f"{kind}.proves {proves!r} is unknown. A composition claim names "
                "WHICH half it establishes, because a registered manifest with no "
                "lineage and a composed lineage with no manifest are both real "
                "and both look adopted from one row. Known: "
                f"{sorted(COMPOSITION_PROOFS)}",
            )
        )

    expected = row.get("expected")
    if not isinstance(expected, str) or not expected.strip():
        problems.append(
            _problem(
                where,
                f"{kind} must record in `expected` what the tree was seen to "
                "hold, in words a reader can compare with the parse result",
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

        if kind in ASSERTION_KINDS:
            allowed = ASSERTION_FIELDS
        elif kind in AST_ASSERTION_KINDS:
            allowed = AST_ASSERTION_FIELDS
        else:
            allowed = ATTESTATION_FIELDS
        unknown = sorted(set(row) - allowed)
        # Reported by the family checks below where the field belongs to the
        # other family; anything else is simply not part of the contract.
        cross = (ATTESTATION_FIELDS | ASSERTION_FIELDS | AST_ASSERTION_FIELDS) - allowed
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
        elif kind in TREE_KINDS and repository == SELF_REPOSITORY:
            problems.append(
                f"{here}: {SELF_REPOSITORY!r} cannot assert its own adoption. "
                "Reference proof is not adoption (ADR-0006 § 5), and this list "
                "was the hole that rule left open"
            )

        revision_problem = _revision_problem("commit", row.get("commit"))
        if revision_problem:
            problems.append(f"{here}: {revision_problem}")
        elif kind in TREE_KINDS and isinstance(repository, str) and repository:
            assertion_commits.setdefault(repository, set()).add(str(row["commit"]))

        problems.extend(_locator_problem(here, row.get("locator")))

        if kind in ASSERTION_KINDS:
            problems.extend(_assertion_problems(here, row, kind, distribution))
        elif kind in AST_ASSERTION_KINDS:
            problems.extend(_ast_assertion_problems(here, row, kind))
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

    # ── composition and installation are read from ONE tree ────────────────
    # A `composed_at` row says the consumer's assembly names this module. A
    # `pinned_at` row says the consumer depends on a version of it. Neither is
    # adoption alone, and they are only adoption TOGETHER when they describe the
    # same tree: a roster entry at one commit beside a pin read at another is two
    # true facts arranged to look like one. Same repository AND same commit.
    pinned_trees: set[tuple[str, str]] = set()
    for row in rows:
        if isinstance(row, Mapping) and row.get("kind") == "pinned_at":
            repo, commit = row.get("repository"), row.get("commit")
            if isinstance(repo, str) and isinstance(commit, str):
                pinned_trees.add((repo, commit))

    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or row.get("kind") != "composed_at":
            continue
        repo, commit = row.get("repository"), row.get("commit")
        if not (isinstance(repo, str) and isinstance(commit, str)):
            continue
        if (repo, commit) in pinned_trees:
            continue
        problems.append(
            _problem(
                where,
                f"adoption_evidence[{index}]: composed_at cites "
                f"{repo}@{commit[:12]}… with no `pinned_at` row for that same "
                "tree. Composition without installation is a roster entry for a "
                "dependency the consumer does not declare; the two halves must "
                "be read from ONE commit or they are two facts wearing one claim",
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
#: `composed_at` — an assertion about a syntax tree.  The STRONGEST kind in
#: this set, and the only one whose claim a machine can re-derive from source
#: bytes with no oracle at all: given the file, the answer is a parse away.
#: `adopted` needs a reader to agree the chosen TOML field means composition;
#: `live_observation` decays.  A `composed_at` row means the consumer's own
#: assembly names this module in its registration roster.
ADOPTION_PROVING_KINDS: Final = frozenset(
    {"adopted", "live_observation", "composed_at"}
)

#: The SECOND axis, and it is orthogonal to the first — which is the defect this
#: constant exists to close rather than describe.
#:
#: `INSTALLATION_KINDS` / `ADOPTION_PROVING_KINDS` answers "was this COMPOSED or
#: merely INSTALLED".  It says nothing about whether anything RAN, and the two
#: questions cut across each other: `adopted` and `composed_at` prove
#: composition by reading a SOURCE TREE, while `live_observation` proves it by
#: watching a RUNNING SYSTEM.  A reader asking "is this in production?" and
#: reaching for `ADOPTION_PROVING_KINDS` gets a confident wrong answer.
#:
#: Only these two can speak about a running production system.  `workflow_run`
#: is CI exercising a tree, which is not that tree running anything for anyone;
#: `image_digest` is an artifact that was BUILT, and a built image is not a
#: deployed one.  Both are excluded deliberately.
#:
#: This is a subset of `ATTESTATION_KINDS` by construction and a test asserts
#: it: a production claim cannot be a fact about a file, because no file in any
#: tree can state that a system is running.
PRODUCTION_PROVING_KINDS: Final = frozenset({"deploy_run", "live_observation"})


def rests_on_source_alone(rows: object) -> bool:
    """True when every row is a fact about a source tree.

    The question `ADOPTION_PROVING_KINDS` cannot answer.  A dossier for which
    this is true may legitimately be `adopted` — composition IS adoption — but
    it has no evidence that anything ran, and must not be read or summarised as
    though it had.
    """
    kinds = {
        row.get("kind")
        for row in (rows if isinstance(rows, list) else [])
        if isinstance(row, Mapping)
    }
    return bool(kinds) and not (kinds & ATTESTATION_KINDS)


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


# ── The verification procedure for `composed_at` ────────────────────────────
#
# Everything above is shape: is the claim well formed.  This is the walk that
# decides whether the claim is TRUE of a given source text.
#
# It is a pure function of bytes.  It does not import the module under
# examination, does not execute it, does not resolve its dependencies and does
# not need them installed — `ast.parse` builds a tree from text and nothing
# else.  That matters for a reason beyond hygiene: the file being examined
# belongs to ANOTHER repository, whose dependencies this repository does not
# have and must not acquire.  An importing checker would be a checker that only
# runs inside the consumer, which is the one place a cross-repository evidence
# claim cannot be checked from.
#
# Why a parse rather than a grep, stated concretely because the difference is
# the whole value:
#
#   * A name inside a comment or a docstring is TEXT to grep and is not a
#     `Name` node.  Vendor's `assembly.py` mentions `deployment_control_module`
#     in a nine-line comment above the tuple; a grep-based checker cannot tell
#     that comment from the registration two lines below it, and would keep
#     passing after the registration was deleted.
#   * An `import` is structurally a different node from a registration.  The
#     import-only mutant — keep the import, delete the roster entry — is the
#     mutation that catches a checker which is really matching a module name.
#   * An alias is followed.  `from dotmac_deployment_control import module as
#     deployment_control_module` binds a local name the roster then uses; the
#     walk resolves that binding instead of hard-coding either spelling.


def _local_binding(tree: ast.Module, module: str, symbol: str) -> str | None:
    """The local name `from <module> import <symbol> [as <alias>]` binds."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            for alias in node.names:
                if alias.name == symbol:
                    return alias.asname or alias.name
    return None


def _collection_members(tree: ast.Module, within: str) -> list[ast.expr] | None:
    """Elements of the list/tuple/set literal assigned to `within`, or None."""
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None:
            continue
        if not any(isinstance(t, ast.Name) and t.id == within for t in targets):
            continue
        if isinstance(value, ast.Tuple | ast.List | ast.Set):
            return list(value.elts)
        return []
    return None


def _function_calls(tree: ast.Module, within: str) -> list[ast.Call] | None:
    """Every call made anywhere inside the function `within`, or None."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name == within
        ):
            return [c for c in ast.walk(node) if isinstance(c, ast.Call)]
    return None


def python_composition_problems(
    source: str,
    *,
    module: str,
    symbol: str,
    construct: str,
    within: str,
    where: str = "",
) -> list[str]:
    """Refusals for a `composed_at` claim against one Python source text.

    An empty list means the tree really does show the composition claimed.  The
    three refusals below are the ones the mutation suite exercises, and each
    reports which stage failed, because "not composed" and "not even imported"
    send a reader to different places.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:  # pragma: no cover - a malformed fixture
        return [_problem(where, f"source does not parse: {exc}")]

    local = _local_binding(tree, module, symbol)
    if local is None:
        return [
            _problem(
                where,
                f"no `from {module} import {symbol}` in this file, so the claim "
                "fails before composition is even reachable",
            )
        ]

    if construct == "collection_member":
        members = _collection_members(tree, within)
        if members is None:
            return [
                _problem(
                    where,
                    f"{local!r} is imported but no collection named {within!r} is "
                    "assigned in this file",
                )
            ]
        if not any(isinstance(e, ast.Name) and e.id == local for e in members):
            return [
                _problem(
                    where,
                    f"{local!r} is imported but is NOT a member of {within!r}. An "
                    "import is installation; a roster entry is composition, and "
                    "a mention in a comment is neither — this walk sees only the "
                    "roster",
                )
            ]
        return []

    if construct == "call":
        calls = _function_calls(tree, within)
        if calls is None:
            return [
                _problem(
                    where,
                    f"{local!r} is imported but no function named {within!r} is "
                    "defined in this file",
                )
            ]
        if not any(isinstance(c.func, ast.Name) and c.func.id == local for c in calls):
            return [
                _problem(
                    where,
                    f"{local!r} is imported but never called inside {within!r}, so "
                    "the lineage it returns is not composed into the target",
                )
            ]
        return []

    return [_problem(where, f"unknown construct {construct!r}")]


def declared_dependency_version(toml_text: str, distribution: str) -> str | None:
    """The version a consumer's `pyproject.toml` pins `distribution` to.

    Handles both spellings Poetry accepts — a bare string and an inline table —
    because a checker that understood only one would silently return None for
    the other and report "not pinned" about a file that pins it.
    """
    document = tomllib.loads(toml_text)
    tool = document.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, Mapping) else None
    groups: list[Any] = []
    if isinstance(poetry, Mapping):
        groups.append(poetry.get("dependencies"))
        for group in (poetry.get("group") or {}).values():
            if isinstance(group, Mapping):
                groups.append(group.get("dependencies"))
    project = document.get("project")
    if isinstance(project, Mapping):
        groups.append(project.get("dependencies"))

    for table in groups:
        if not isinstance(table, Mapping):
            continue
        entry = table.get(distribution)
        if isinstance(entry, str):
            return entry
        if isinstance(entry, Mapping) and isinstance(entry.get("version"), str):
            return str(entry["version"])
    return None


def composition_claim_problems(
    *,
    sources: Mapping[str, str],
    rows: Sequence[Mapping[str, Any]],
    pin_source: str | None = None,
    distribution: str = "",
    expected_pin: str | None = None,
    where: str = "",
) -> list[str]:
    """Resolve every `composed_at` row against real source text, plus the pin.

    `sources` maps each row's `path` to that file's contents at the cited
    commit.  A row whose path is absent is reported rather than skipped: a
    silently unresolved claim is the failure mode this whole module exists to
    remove.

    The pin cross-check is here rather than in `python_composition_problems`
    because it is a fact about a different file in the same tree, and because
    composition without a pin is the mirror of `dotmac-tax`: naming a module in
    a roster while depending on nothing installs nothing.
    """
    problems: list[str] = []
    seen_proofs: set[str] = set()

    for index, row in enumerate(rows):
        here = _problem(where, f"composed_at[{index}]").rstrip(":")
        path = row.get("path")
        if not isinstance(path, str) or path not in sources:
            problems.append(
                f"{here}: no source supplied for {path!r}; the claim is "
                "unresolved, which is not the same as satisfied"
            )
            continue
        proves = row.get("proves")
        if isinstance(proves, str):
            seen_proofs.add(proves)
        problems.extend(
            python_composition_problems(
                sources[path],
                module=str(row.get("module", "")),
                symbol=str(row.get("symbol", "")),
                construct=str(row.get("construct", "")),
                within=str(row.get("within", "")),
                where=f"{here} ({path})",
            )
        )

    if rows:
        missing = sorted(COMPOSITION_PROOFS - seen_proofs)
        if missing:
            problems.append(
                _problem(
                    where,
                    f"composition evidence is missing {missing}. A registered "
                    "manifest whose lineage is not composed installs tables "
                    "nobody migrates; a composed lineage with no registered "
                    "manifest migrates tables nothing registers. Both halves or "
                    "neither",
                )
            )

    if rows and pin_source is not None:
        pinned = declared_dependency_version(pin_source, distribution)
        if pinned is None:
            problems.append(
                _problem(
                    where,
                    f"the consumer's dependency table does not pin {distribution!r} "
                    "at the cited commit, so it composes a module it does not "
                    "depend on",
                )
            )
        elif expected_pin is not None and pinned != expected_pin:
            problems.append(
                _problem(
                    where,
                    f"the consumer pins {distribution} {pinned!r} at the cited "
                    f"commit, but the dossier's `pinned_at` row records "
                    f"{expected_pin!r}. Composition and installation must be read "
                    "from ONE tree; two versions across two rows is the drift "
                    "AdoptionEvidenceV1 exists to make impossible",
                )
            )

    return problems
