"""The copied evidence vocabulary has not drifted from the tree it came from.

`adoption_evidence.py` is not this repository's code. It belongs to
`dotmac_starter_mt`, and it is here because the dossier gate cannot run without
it. `AGENTS.md` rule 24 permits that as a **one-time extraction** and forbids
what it turns into if nothing watches: a permanent fork, or a second writer.

Two copies with no control is how they silently disagree, and this particular
pair is the worst case for silence — the file is the vocabulary that decides
whether an adoption claim is TRUE. A local edit that loosened a refusal would
make this repository's dossier gate pass claims the Starter's would reject, and
nothing anywhere would say so. The drift would conceal itself.

The control is the one already proven on the Vendor fixtures: a **git blob id**,
`sha1("blob <len>\\0" + content)`, which is a pure function of the bytes. It needs
no network, no clone and no git binary, yet anyone with the Starter checked out
confirms the same value with `git rev-parse <commit>:<path>`.

The pin names a COMMIT and never a branch — a moving ref would let the Starter
change underneath the check while the check kept passing.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PIN = json.loads((HERE / "vocabulary_pin.json").read_text(encoding="utf-8"))
VOCABULARY = HERE / "adoption_evidence.py"

_COMMIT_LEN = 40


def _blob_id(data: bytes) -> str:
    return hashlib.sha1(
        b"blob %d\0" % len(data) + data, usedforsecurity=False
    ).hexdigest()


def test_the_pin_names_an_immutable_commit() -> None:
    """A branch name here would defeat the whole control."""
    commit = PIN["source_commit"]
    assert len(commit) == _COMMIT_LEN, commit
    assert all(c in "0123456789abcdef" for c in commit), commit
    assert PIN["source_repository"] == "dotmac_starter_mt"
    assert PIN["source_path"] == "tests/architecture/adoption_evidence.py"


def test_the_copied_vocabulary_has_not_drifted() -> None:
    actual = _blob_id(VOCABULARY.read_bytes())
    assert actual == PIN["blob_sha1"], (
        "tests/architecture/adoption_evidence.py no longer matches the copy taken "
        f"from {PIN['source_repository']}@{PIN['source_commit']}.\n"
        f"  pinned: {PIN['blob_sha1']}\n"
        f"  local:  {actual}\n"
        "\n"
        "DO NOT fix this by editing the local copy. Editing it is the fork this "
        "check exists to prevent, and because this file decides whether adoption "
        "claims are true, a local divergence would make this repository's gate "
        "accept claims the Starter's gate rejects, silently.\n"
        "\n"
        "The two legitimate repairs:\n"
        "  1. The Starter changed and this repository should follow: re-extract "
        "     the file from the new Starter commit and update vocabulary_pin.json "
        "     to that commit and blob id, in the same change.\n"
        "  2. This repository needs behaviour the Starter's vocabulary does not "
        "     have: that is a change to the SHARED vocabulary and belongs in the "
        "     Starter first, then comes back here through repair 1."
    )


def test_the_check_would_notice_a_single_byte() -> None:
    """SENSITIVITY. A pin nobody has seen fail is a pin nobody knows works.

    Proves the comparison bites on the smallest possible edit — a trailing
    newline — rather than only on a rewrite.
    """
    original = VOCABULARY.read_bytes()
    assert _blob_id(original + b"\n") != PIN["blob_sha1"]
    assert _blob_id(original.replace(b"return", b"return ", 1)) != PIN["blob_sha1"]
    # ...and the positive control: unmodified bytes still match, so the two
    # assertions above are not passing because everything fails.
    assert _blob_id(original) == PIN["blob_sha1"]
