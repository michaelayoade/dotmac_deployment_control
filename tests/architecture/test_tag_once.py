"""A tag is written once, and never moved.

Both halves have already gone wrong in this repository, in opposite directions,
which is why each is asserted separately here.

* **Not idempotent.** The independent verify run for `0.1.0a4` reached a clean
  `VERIFIED` verdict and then died on `fatal: tag ... already exists`, exit 128.
  The run reads as a failed verification. It was not one.
* **Movable.** The one-character repair for that — `git tag -f` — is much worse
  than the bug. One version naming two commits makes every pin against the
  earlier coordinate unidentifiable.

`decide` is pure, so the refusal is provable without a repository, a remote or a
release. A refusal nobody has watched fire is the shape this whole lane exists
to remove.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "tag_once", REPO_ROOT / "scripts" / "tag_once.py"
)
assert _spec is not None and _spec.loader is not None
tag_once = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tag_once
_spec.loader.exec_module(tag_once)

TAG = "dotmac-deployment-control-v0.1.0a4"
HEAD = "2c61540f74018b7e19d7c5add893e0653cfcdb17"
OTHER = "31b6b82f14fee65d22c6d1d218455d21bb12c0f6"


def test_an_absent_tag_is_created() -> None:
    """POSITIVE CONTROL. Without it every refusal below is equally consistent
    with a function that refuses everything."""
    action, message = tag_once.decide(TAG, None, HEAD)
    assert action == tag_once.CREATE
    assert HEAD in message


def test_the_same_tag_on_the_same_commit_is_idempotent_success() -> None:
    """THE a4 RE-DISPATCH. Verify run 33310594187 proved every property and
    then failed on this, turning a green finding into a red run."""
    action, message = tag_once.decide(TAG, HEAD, HEAD)
    assert action == tag_once.ALREADY
    assert "tagged once" in message


def test_a_tag_on_a_different_commit_is_refused_and_never_moved() -> None:
    """THE REFUSAL THIS MODULE EXISTS FOR."""
    action, message = tag_once.decide(TAG, OTHER, HEAD)
    assert action == tag_once.REFUSE
    assert OTHER in message and HEAD in message
    assert "do not retag" in message


def test_the_refusal_explains_the_consequence_not_just_the_rule() -> None:
    """A refusal that says only "not allowed" gets overridden by the next
    person in a hurry. This one has to say what breaks."""
    _, message = tag_once.decide(TAG, OTHER, HEAD)
    assert "two commits" in message
    assert "pin" in message


def test_an_empty_target_is_refused_rather_than_tagged() -> None:
    """A shell that failed to resolve the head SHA passes an empty string, and
    `git tag -a <tag> ""` would tag HEAD — whatever HEAD happens to be."""
    action, message = tag_once.decide(TAG, None, "")
    assert action == tag_once.REFUSE
    assert "not a coordinate" in message


@pytest.mark.parametrize(
    ("existing", "head", "expected"),
    [
        (None, HEAD, tag_once.CREATE),
        (HEAD, HEAD, tag_once.ALREADY),
        (OTHER, HEAD, tag_once.REFUSE),
        (HEAD, OTHER, tag_once.REFUSE),
    ],
)
def test_every_outcome_is_reachable(
    existing: str | None, head: str, expected: str
) -> None:
    """Three outcomes, each reached by some input. A decision function with an
    unreachable branch is a branch nobody has tested."""
    assert tag_once.decide(TAG, existing, head)[0] == expected


def test_the_module_never_offers_a_force_flag() -> None:
    """SENSITIVITY on the whole design. The refusal above is worth nothing if a
    `--force` sits beside it: the next person hitting the error takes the
    documented escape hatch, and the tag moves."""
    source = (REPO_ROOT / "scripts" / "tag_once.py").read_text(encoding="utf-8")
    for forbidden in ("--force", '-f"', "'-f'", "force=True"):
        assert forbidden not in source, (
            f"tag_once.py offers {forbidden!r}. There is no supported way to "
            "move a release tag; a version that named two commits would be "
            "unrepairable, not inconvenient."
        )
