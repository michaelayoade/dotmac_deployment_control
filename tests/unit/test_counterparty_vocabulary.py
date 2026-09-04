"""The fence: Control may not authorize what the executor cannot honour.

`operations.py` has always argued that the vocabulary is closed so Control
cannot *"freeze, sign and dispatch an authorization the executor is structurally
unable to honour."* From `0.1.0a10` until now that argument was unenforced:
`recover` entered on the stated premise that the Deployment Foundation's `a5`
was being built against the same three members, the Foundation withdrew it, and
nothing on this side refused the word afterwards.

These tests are the enforcement. They do not assert the two vocabularies are
EQUAL -- Michael's ruling keeps `recover` a member, so equality would be the
wrong invariant and would fail forever. What they assert is that every member
this control plane can name and the executor cannot honour is refused at each
of the three points the docstring names.
"""

from __future__ import annotations

import pytest

from dotmac_deployment_control.counterparty import (
    EXECUTOR_DISTRIBUTION,
    EXECUTOR_OPERATIONS,
    EXECUTOR_SOURCE_COMMIT,
    EXECUTOR_SOURCE_VERSION,
    require_executable_operation,
    unexecutable_operations,
)
from dotmac_deployment_control.operations import (
    OPERATIONS,
    DeploymentOperation,
    require_operation,
)
from dotmac_deployment_control.ports import (
    OperationNotExecutableError,
    OperationRefusedError,
)


def test_the_executable_operations_are_admitted() -> None:
    """POSITIVE CONTROL. Every other test here is a refusal, and a gate only
    ever observed refusing might refuse everything."""
    for word in sorted(EXECUTOR_OPERATIONS):
        assert require_executable_operation(word, where="test").value == word


def test_the_divergence_is_real_and_this_suite_is_not_vacuous() -> None:
    """If the two vocabularies ever agree, every refusal below is unreachable.

    Stated rather than assumed, so the day the executor gains `recover` this
    says so instead of continuing to pass over an empty set.
    """
    assert unexecutable_operations(), (
        "no member is unexecutable, so the fence refuses nothing and every "
        "test below passes without exercising it"
    )
    assert unexecutable_operations() == {"recover"}
    assert EXECUTOR_OPERATIONS < set(OPERATIONS)


@pytest.mark.parametrize("word", sorted(unexecutable_operations()))
def test_an_operation_the_executor_cannot_honour_is_refused(word: str) -> None:
    """The fence itself, over every unexecutable member rather than one name."""
    with pytest.raises(OperationNotExecutableError) as refused:
        require_executable_operation(word, where="test")
    message = str(refused.value)
    assert word in message
    assert EXECUTOR_DISTRIBUTION in message
    assert EXECUTOR_SOURCE_COMMIT in message


def test_the_fence_is_not_a_vocabulary_refusal_and_must_not_be_caught_as_one() -> None:
    """The two say opposite things about the same word, and the difference
    decides whether a stored row stays readable.

    `except OperationRefusedError` turns an unparsable word into a typed
    disposition on the observation path. If the fence inherited from it, that
    handler would swallow this and a `recover` plan would silently become an
    OPERATION_MISMATCH rather than an explicit refusal to dispatch.
    """
    assert not issubclass(OperationNotExecutableError, OperationRefusedError)
    assert not issubclass(OperationRefusedError, OperationNotExecutableError)


def test_the_read_path_still_parses_what_the_fence_refuses() -> None:
    """A row written by an earlier version must stay readable.

    `require_operation` is the READ gate and keeps every member; the fence is a
    separate gate used only where an authorization is frozen, signed or
    dispatched. An authorization trail that becomes unparsable when a
    counterparty changes is a record that rewrites itself.
    """
    for word in sorted(unexecutable_operations()):
        assert require_operation(word, where="read").value == word


def test_a_word_outside_the_vocabulary_is_still_a_vocabulary_refusal() -> None:
    """SENSITIVITY: the fence must not have replaced the closure it sits behind."""
    with pytest.raises(OperationRefusedError):
        require_executable_operation("restore", where="test")


def test_the_pin_matches_the_installed_executor_when_one_is_present() -> None:
    """The pin is the primary source; this is drift detection over it.

    The refusals above run ALWAYS -- a guard that skips is a guard that is off,
    and this repository's CI does not install the Foundation. Where it IS
    importable, the pin is compared with the real thing, and the skip names the
    version it saw so a silent pass is never mistaken for agreement.
    """
    import importlib.metadata as metadata

    try:
        installed = metadata.version(EXECUTOR_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        installed = "absent"
    authorization = pytest.importorskip(
        "dotmac_deployment_foundation.authorization",
        reason=(
            f"{EXECUTOR_DISTRIBUTION} {installed} is not importable here; the "
            f"pin recorded from {EXECUTOR_SOURCE_VERSION} is compared once it is"
        ),
    )
    assert set(authorization.OPERATIONS) == EXECUTOR_OPERATIONS, (
        "the pinned counterparty vocabulary no longer matches the installed "
        "distribution; the fence is deciding against a stale set"
    )


def test_every_member_is_either_executable_or_fenced() -> None:
    """The closing statement, and the one that catches a FIFTH member.

    Adding a word to this vocabulary without either the executor gaining it or
    the fence refusing it recreates exactly the a10 defect: an approval that
    reads as valid on every screen and can never produce a receipt.
    """
    for member in DeploymentOperation:
        if member.value in EXECUTOR_OPERATIONS:
            assert require_executable_operation(member, where="test") is member
        else:
            with pytest.raises(OperationNotExecutableError):
                require_executable_operation(member, where="test")
