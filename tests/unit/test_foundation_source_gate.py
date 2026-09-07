"""The required gate over Foundation's pinned SOURCE, exercised with no network.

Every test here injects a synthetic `SourceReader` — a fake returning literal
Python source text — so the comparison's sensitivity is provable without
`dotmac-deployment-foundation` ever being installed or reachable, exactly the
gap `rehearsal_grant.py`'s own docstring names as unmonitored in this
repository's actual CI.

`test_a_grant_agrees_with_the_real_current_vocabulary` is the admit control:
read first, because every refusal test below would pass trivially if nothing
could ever agree.
"""

from __future__ import annotations

import pytest

from dotmac_deployment_control.foundation_source_gate import (
    SourceCoordinate,
    extract_step_kind_members,
    parse_source_coordinate,
    require_foundation_step_vocabulary_agreement,
)
from dotmac_deployment_control.ports import (
    FoundationStepVocabularyDriftError,
    FoundationStepVocabularySourceError,
)
from dotmac_deployment_control.rehearsal_grant import FOUNDATION_STEP_KINDS

_PINNED_COMMIT = "3f666ea10160f1bb806a6a8f5a9de88597e0b137"
_COORDINATE = (
    f"michaelayoade/dotmac_starter_mt@{_PINNED_COMMIT}"
    ":packages/dotmac-deployment-foundation/src/"
    "dotmac_deployment_foundation/engine/plan.py"
)


def _synthetic_source(*members: str) -> str:
    """A minimal, syntactically real `StepKind` — not the real file's text,
    just enough AST shape for `extract_step_kind_members` to read."""
    body = "\n".join(f'    {name.upper()} = "{name}"' for name in members)
    return f"class StepKind(str, Enum):\n{body}\n"


class _FakeReader:
    def __init__(self, text: str | Exception) -> None:
        self._text = text

    def read(self, coordinate: SourceCoordinate) -> str:
        if isinstance(self._text, Exception):
            raise self._text
        return self._text


# ── the admit control, first ────────────────────────────────────────────────


def test_a_grant_agrees_with_the_real_current_vocabulary() -> None:
    """NON-VACUITY. A synthetic reproduction of the mirror's exact 27 members
    must be admitted, or every refusal test below proves nothing."""
    reader = _FakeReader(_synthetic_source(*sorted(FOUNDATION_STEP_KINDS)))
    require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)


def test_extract_step_kind_members_reads_the_synthetic_source_correctly() -> None:
    """NON-VACUITY for the AST reader specifically: prove it actually parses,
    rather than merely not-raising."""
    source = _synthetic_source("acquire_lock", "apply_exposure", "release_lock")
    assert extract_step_kind_members(source) == {
        "acquire_lock",
        "apply_exposure",
        "release_lock",
    }


# ── the coordinate itself must be pinned, not a moving reference ───────────


def test_the_coordinate_parses_into_its_three_parts() -> None:
    coordinate = parse_source_coordinate(_COORDINATE)
    assert coordinate.repository == "michaelayoade/dotmac_starter_mt"
    assert coordinate.commit == _PINNED_COMMIT
    assert coordinate.path.endswith("engine/plan.py")


@pytest.mark.parametrize(
    "bad",
    [
        "michaelayoade/dotmac_starter_mt@main:path/to/file.py",  # a branch
        "michaelayoade/dotmac_starter_mt@abc123:path/to/file.py",  # short hash
        "no-at-sign-here",
        "repo@" + "a" * 40,  # no path
    ],
)
def test_a_non_pinned_or_malformed_coordinate_is_refused(bad: str) -> None:
    """A branch name is a MOVING reference; this gate exists to check a
    PINNED one, so it must refuse to even parse a branch as a commit."""
    with pytest.raises(FoundationStepVocabularySourceError):
        parse_source_coordinate(bad)


# ── the five failure modes, each named ──────────────────────────────────────


def test_source_unavailable_is_refused() -> None:
    """FAILURE MODE 1: the coordinate cannot be read at all."""
    reader = _FakeReader(OSError("connection refused"))
    with pytest.raises(FoundationStepVocabularySourceError) as refused:
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)
    assert "connection refused" in str(refused.value)


def test_unsupported_syntax_is_refused() -> None:
    """FAILURE MODE 2: the source parses as Python but not in the narrow shape
    this reader understands — a member computed rather than a bare literal."""
    reader = _FakeReader(
        'class StepKind(str, Enum):\n    ACQUIRE_LOCK = "acquire_lock"\n'
        "    COMPUTED = some_function()\n"
    )
    with pytest.raises(FoundationStepVocabularySourceError) as refused:
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)
    assert "bare string literal" in str(refused.value)


def test_unparsable_python_is_refused() -> None:
    """FAILURE MODE 2, the other half: not even valid Python."""
    reader = _FakeReader("class StepKind(str, Enum):\n    THIS IS NOT PYTHON ][\n")
    with pytest.raises(FoundationStepVocabularySourceError):
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)


def test_a_missing_step_kind_class_is_refused() -> None:
    reader = _FakeReader('class SomethingElse:\n    X = "x"\n')
    with pytest.raises(FoundationStepVocabularySourceError) as refused:
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)
    assert "StepKind" in str(refused.value)


def test_an_addition_is_refused_and_named() -> None:
    """FAILURE MODE 3: the source has a step the mirror lacks."""
    reader = _FakeReader(
        _synthetic_source(*sorted(FOUNDATION_STEP_KINDS), "brand_new_step")
    )
    with pytest.raises(FoundationStepVocabularyDriftError) as refused:
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)
    assert "brand_new_step" in str(refused.value)


def test_a_removal_is_refused_and_named() -> None:
    """FAILURE MODE 4: the source no longer has a step the mirror carries."""
    remaining = sorted(FOUNDATION_STEP_KINDS - {"apply_exposure"})
    reader = _FakeReader(_synthetic_source(*remaining))
    with pytest.raises(FoundationStepVocabularyDriftError) as refused:
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)
    assert "apply_exposure" in str(refused.value)


def test_a_same_count_rename_is_refused_and_named() -> None:
    """FAILURE MODE 5, THE DISCRIMINATING CASE.

    A rename keeps the total member COUNT identical to the mirror's, so any
    comparator built on `len(observed) == len(mirror)` or "is every mirrored
    member still present, ignoring extras" would pass this silently. Complete
    SET EQUALITY does not: a rename is simultaneously one addition
    (`apply_exposure_renamed`) and one removal (`apply_exposure`), and the
    symmetric difference names both.
    """
    renamed = sorted(
        (FOUNDATION_STEP_KINDS - {"apply_exposure"}) | {"apply_exposure_renamed"}
    )
    assert len(renamed) == len(FOUNDATION_STEP_KINDS), (
        "the rename fixture must be a same-COUNT change, or it does not "
        "exercise the discriminating case at all"
    )
    reader = _FakeReader(_synthetic_source(*renamed))
    with pytest.raises(FoundationStepVocabularyDriftError) as refused:
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)
    message = str(refused.value)
    assert "apply_exposure_renamed" in message
    assert "apply_exposure" in message


def test_an_empty_step_kind_class_is_refused_rather_than_agreeing_with_nothing() -> (
    None
):
    reader = _FakeReader("class StepKind(str, Enum):\n    pass\n")
    with pytest.raises(FoundationStepVocabularySourceError):
        require_foundation_step_vocabulary_agreement(reader, coordinate=_COORDINATE)
