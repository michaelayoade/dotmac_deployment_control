"""Write a release tag exactly once, and never move one that already exists.

A tag in this repository is an ASSERTION that a version was verified. Two
distinct failures follow from treating it as a mutable pointer, and this module
exists because the first one already happened.

**Re-running a verification must not be an error.** `verify-release.yml` is the
only thing that may tag, and it is dispatchable — that is deliberate, because a
verdict should be reproducible on demand. The first version of its tag step ran
a bare `git tag -a`, so the second dispatch for a version died with
`fatal: tag ... already exists` (exit 128) AFTER a clean `VERIFIED` verdict.
A red run whose finding was green is evidence nobody can read.

**Moving a tag must stay impossible.** The obvious repair — `git tag -f` — is
much worse than the bug. One version naming two commits makes every pin against
the earlier coordinate unidentifiable, which is the frozen-published-artifact
rule the fleet already holds elsewhere. So a tag that exists on a DIFFERENT
commit is a refusal, loudly, and never a rewrite.

The decision is a pure function so that both outcomes — and the refusal in
particular — are provable without a git repository, a remote, or a release.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

#: The tag is absent; write it.
CREATE = "CREATE"
#: The tag is already on this exact commit. Idempotent success.
ALREADY = "ALREADY"
#: The tag is on some other commit. Refuse; never move it.
REFUSE = "REFUSE"


def decide(tag: str, existing_commit: str | None, head_commit: str) -> tuple[str, str]:
    """(action, message) for a tag write. Pure; no git, no network.

    `existing_commit` is the commit the tag currently peels to, or None when no
    such tag exists.
    """
    if not head_commit:
        return (
            REFUSE,
            f"refusing to write {tag}: no commit was given to tag. A tag with no "
            "target is not a coordinate.",
        )
    if existing_commit is None:
        return CREATE, f"{tag} does not exist yet; writing it on {head_commit}."
    if existing_commit == head_commit:
        return (
            ALREADY,
            f"{tag} already exists on {head_commit}. A verified release is "
            "tagged once, and re-running the verification is not an error.",
        )
    return (
        REFUSE,
        f"refusing to move {tag}: it exists on {existing_commit} and this "
        f"verification is for {head_commit}. A tag is this repository's "
        "assertion that a version was verified; moving it would make one "
        "version name two commits and every pin against the earlier "
        "coordinate unidentifiable. Investigate which commit is right — do "
        "not retag.",
    )


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )


def existing_commit(tag: str) -> str | None:
    """The commit `tag` peels to, or None. Fetches the ref first, because a
    shallow or tagless checkout would otherwise report every tag as absent —
    the single most dangerous wrong answer this function can give."""
    _git("fetch", "--no-tags", "origin", f"refs/tags/{tag}:refs/tags/{tag}")
    result = _git("rev-list", "-n", "1", tag)
    return result.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--message", required=True)
    args = parser.parse_args(argv)

    action, message = decide(args.tag, existing_commit(args.tag), args.commit)
    if action == REFUSE:
        print(f"::error::{message}", file=sys.stderr)
        return 1
    if action == ALREADY:
        print(f"::notice::{message}")
        return 0

    print(message)
    _git("config", "user.name", "github-actions[bot]")
    _git("config", "user.email", "github-actions[bot]@users.noreply.github.com")
    for step in (
        ("tag", "-a", args.tag, "-m", args.message, args.commit),
        ("push", "origin", args.tag),
    ):
        result = _git(*step)
        if result.returncode != 0:
            print(f"::error::git {step[0]} failed: {result.stderr.strip()}")
            return 1
    print(f"tagged {args.tag} on {args.commit}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
