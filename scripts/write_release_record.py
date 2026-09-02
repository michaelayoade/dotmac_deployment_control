#!/usr/bin/env python3
"""Write the post-release record this repository's verify run leaves behind.

## Why this exists

`verify-release.yml` already computes every mechanical field a release record
needs, writes the tag on a VERIFIED verdict — and then ends by printing

    ::notice::OWED: remove the 0.1.0aN row from docs/publication-ledger.json.

A notice nothing reads. The record has been missed TWICE here, and both times
the missing row was the whole failure:

* `0.1.0a4`'s ledger row said `never-published` and **outlived its own
  publication by six hours**.
* `0.1.0a7`'s absence turned protected `main` red for every open pull request,
  each presenting as *that branch* being broken rather than as `main` being
  broken. a4 failed silently; a7 failed loudly at innocent people.

The tag makes the ledger row false the INSTANT it lands, and
`test_the_ledger_and_the_published_record_never_claim_the_same_version` states
the contradiction over the two FILES, so it fires even in a tagless checkout.
From that instant until the record is written, main is red.

So the record stops being remembered. This script makes the edits; the
`scripts/open_release_record_pr.sh` around it opens them as a pull request under
the dedicated recorder identity and enables squash auto-merge. Protected main
keeps required CI as the merge authority; only the redundant human bookkeeping
gesture is removed.

Ported from `dotmac_starter_mt`'s `scripts/write_release_record.py` — the
already-approved mechanism, not a redesign. What differs is only the two files
this repository keeps its record in.

## COORDINATES ONLY, and the split is the whole safety argument

This script writes exactly two paths and can write nothing else:

* `docs/publication-ledger.json` — REMOVE the row a tag has already falsified.
* `docs/published-versions.json` — ADD the machine-derivable coordinates.

**Machine-owned, written here.** `version`, `tag`, `tag_object`,
`peeled_commit`, `release_run`, `verify_run`, `source_repository`, `index`,
`status`, `sha256` per filename, `supersedes`, `declared_kernel_floor`. Every
one is derived from the tag, the observations the verifier already gathered, or
the tree at the tag. None of them is a judgement.

**Human-owned, never written here.** `pinnable`, `superseded_by`,
`unpinnable_reason`, `release_run_note`, `adoption_note`, `disposition`,
`tag_note`. These are dispositions — what this release means, whether anyone may
depend on it, what is known to be wrong with it. They are not derivable, and
tests assert on that prose deliberately.

**And the floor literals stay human.** Recording a version raises the derived
floor, and the floor's guard holds its own positive control, its refusal strings
and two parametrize lists as literals in
`tests/architecture/test_published_versions_and_floor.py`. A bot writing those
is a bot editing the constraint that binds it. This script does not open that
file, and `open_release_record_pr.sh` refuses a diff that touches anything
outside the two paths above.

## Round-trip, and why it is safe here rather than assumed

The Starter edits its ledger as TEXT, because a `json.dumps` round-trip there
rewrites non-ASCII prose into `\\uXXXX` escapes and turns a five-line removal
into a fifteen-line diff touching paragraphs the change has no business
touching.

Both files here round-trip byte-identically under
`json.dumps(..., indent=2, ensure_ascii=False) + "\\n"`, so the same property is
available without regex surgery on a nested structure. It is PROVEN rather than
believed: `_reserialise` re-encodes the UNMODIFIED document first and refuses
unless it reproduces the original bytes exactly. If the formatting ever drifts,
this script stops rather than reflowing somebody's prose.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER = REPO_ROOT / "docs" / "publication-ledger.json"
PUBLISHED = REPO_ROOT / "docs" / "published-versions.json"

#: The ONLY paths this script may write. `open_release_record_pr.sh` compares
#: the resulting diff against this same list, so "coordinates only" is checked
#: rather than merely intended.
WRITABLE = ("docs/publication-ledger.json", "docs/published-versions.json")

DISTRIBUTION = "dotmac-deployment-control"
SOURCE_REPOSITORY = "dotmac_deployment_control"
INDEX = "registry.dotmac.io/api/packages/dotmac/pypi"

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALPHA = re.compile(r"^(\d+)\.(\d+)\.(\d+)a(\d+)$")


class ReleaseRecordError(RuntimeError):
    """The record cannot be written, and guessing is not an option."""


def _git(*args: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseRecordError(
            f"git {' '.join(args)} failed: {result.stderr.strip() or 'no stderr'}"
        )
    return result.stdout.strip()


def _order(version: str) -> tuple[int, int, int, int]:
    match = _ALPHA.fullmatch(version.strip())
    if match is None:
        raise ReleaseRecordError(
            f"{version!r} is not a shape this record can order. Refusing rather "
            "than guessing — the same narrowness `release_guard.parse` applies."
        )
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _reserialise(path: Path, mutate: Any) -> str:
    """Load, prove the encoding is lossless, mutate, re-encode.

    The proof is the point. `mutate` is applied only AFTER the untouched
    document has been shown to re-encode to the exact original bytes, so a
    diff produced here cannot contain a reflow, an escape change or a reordered
    key that this change did not intend.
    """
    raw = path.read_bytes()
    data = json.loads(raw)
    if (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8") != raw:
        raise ReleaseRecordError(
            f"{path.relative_to(REPO_ROOT)} does not round-trip byte-identically, "
            "so writing it here would reformat prose this change has no business "
            "touching. Repair the record by hand, or restore the file's "
            "formatting first."
        )
    mutate(data)
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


# ── the two edits ───────────────────────────────────────────────────────────


def remove_ledger_row(version: str) -> str | None:
    """Drop the row the tag has already falsified. Absent is a NO-OP.

    A no-op rather than a refusal so a partial repair converges: re-running
    after a half-finished record must reach the same place, not fail because
    the first half already succeeded.
    """
    data = json.loads(LEDGER.read_bytes())
    if version not in data.get("unpublished", {}):
        return None
    return _reserialise(LEDGER, lambda d: d["unpublished"].pop(version))


def coordinates(
    *,
    version: str,
    tag: str,
    observations: dict[str, Any],
    verify_run: str,
) -> dict[str, Any]:
    """The machine-owned row. Every field derived; none of them a judgement."""
    tag_object = _git("rev-parse", tag)
    peeled = _git("rev-parse", f"{tag}^{{commit}}")
    if _git("cat-file", "-t", tag) != "tag":
        raise ReleaseRecordError(
            f"{tag} is a lightweight tag. This repository's records carry a tag "
            "OBJECT and a peeled commit as separate coordinates, and a "
            "lightweight tag has only one of them."
        )
    for name, value in (("tag_object", tag_object), ("peeled_commit", peeled)):
        if not _COMMIT.fullmatch(value):
            raise ReleaseRecordError(f"{name} is not a full object id: {value!r}")
    if tag_object == peeled:
        raise ReleaseRecordError(
            f"{tag}'s tag object and peeled commit are equal, which means it is "
            "not annotated after all"
        )

    run = observations.get("run") or {}
    head_sha = str(run.get("head_sha") or "")
    if head_sha != peeled:
        raise ReleaseRecordError(
            f"the release run published {head_sha!r} and {tag} peels to "
            f"{peeled!r}. The tag and the run must name one commit, or the "
            "record would tie a version to a source it was not built from."
        )

    # THE REGISTRY'S BYTES, not the build's. The verifier already proved the
    # two are equal for every artifact the run built (property 1, exact hash
    # equality in both directions), so recording what the INDEX served is the
    # stronger of two identical statements — it is what a consumer will fetch.
    built = dict(observations.get("built_hashes") or {})
    fetched = dict(observations.get("fetched") or {})
    if not fetched:
        raise ReleaseRecordError("the observations carry no fetched artifacts")
    if fetched != built:
        raise ReleaseRecordError(
            "the fetched and built hashes disagree, so this version was never "
            f"VERIFIED: built={sorted(built)} fetched={sorted(fetched)}. The "
            "record must not be written."
        )
    for name, digest in fetched.items():
        if not _SHA256.fullmatch(str(digest)):
            raise ReleaseRecordError(f"{name} has a malformed sha256: {digest!r}")

    record = json.loads(PUBLISHED.read_bytes())
    existing = [r["version"] for r in record["releases"]]
    if version in existing:
        raise ReleaseRecordError(
            f"{version} is already recorded in docs/published-versions.json. A "
            "published version is written once; re-writing it would let one "
            "version name two sets of coordinates."
        )
    supersedes = max(existing, key=_order)

    floor = None
    pyproject = _git("show", f"{tag}:pyproject.toml")
    match = re.search(r'dotmac-kernel\s*=\s*\{\s*version\s*=\s*"([^"]+)"', pyproject)
    if match is not None:
        floor = match.group(1)

    return {
        "version": version,
        "tag": tag,
        "tag_object": tag_object,
        "peeled_commit": peeled,
        "release_run": str(run.get("id") or ""),
        "verify_run": str(verify_run),
        "source_repository": SOURCE_REPOSITORY,
        "index": INDEX,
        "status": "released",
        "sha256": dict(sorted(fetched.items())),
        "supersedes": supersedes,
        **({"declared_kernel_floor": floor} if floor else {}),
    }


def add_published_row(row: dict[str, Any]) -> str:
    return _reserialise(PUBLISHED, lambda d: d["releases"].append(row))


# ── the whole record ────────────────────────────────────────────────────────


def write_record(
    *, version: str, tag: str, observations_path: Path, verify_run: str
) -> list[str]:
    """Both halves, or neither. Returns the lines the pull request will quote."""
    if tag != f"{DISTRIBUTION}-v{version}":
        raise ReleaseRecordError(
            f"tag {tag!r} does not name version {version!r}; refusing to record "
            "a coordinate pair that disagrees with itself"
        )
    observations = json.loads(observations_path.read_text(encoding="utf-8"))
    if str(observations.get("version") or "") != version:
        raise ReleaseRecordError(
            f"the observations describe {observations.get('version')!r} and this "
            f"record is for {version!r}"
        )

    row = coordinates(
        version=version, tag=tag, observations=observations, verify_run=verify_run
    )
    ledger_text = remove_ledger_row(version)
    published_text = add_published_row(row)

    changed: list[str] = []
    if ledger_text is not None:
        LEDGER.write_text(ledger_text, encoding="utf-8")
        changed.append(
            f"removed the {version} row from docs/publication-ledger.json — the "
            f"{tag} tag made it false the instant it landed"
        )
    else:
        changed.append(
            f"docs/publication-ledger.json carries no {version} row already "
            "(nothing to remove)"
        )
    PUBLISHED.write_text(published_text, encoding="utf-8")
    changed.append(
        f"recorded {version} in docs/published-versions.json: tag object "
        f"{row['tag_object'][:12]}…, peeled commit {row['peeled_commit'][:12]}…, "
        f"release run {row['release_run']}, verify run {row['verify_run']}, "
        + ", ".join(f"{n} {d[:12]}…" for n, d in sorted(row["sha256"].items()))
    )
    changed.append(
        "COORDINATES ONLY: no disposition, no note, no floor literal and no "
        "test was written. `pinnable`, `superseded_by` and the release notes "
        "are human-owned and are still owed."
    )
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the post-release record")
    parser.add_argument("--distribution", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--verify-run", required=True)
    args = parser.parse_args(argv)

    if args.distribution != DISTRIBUTION:
        print(
            f"this repository records {DISTRIBUTION!r} and nothing else; "
            f"refusing {args.distribution!r}",
            file=sys.stderr,
        )
        return 2
    try:
        for line in write_record(
            version=args.version,
            tag=args.tag,
            observations_path=args.observations,
            verify_run=args.verify_run,
        ):
            print(line)
    except ReleaseRecordError as exc:
        print(f"the record writer refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
