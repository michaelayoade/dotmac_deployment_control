"""The role-job window as values: opened bounded, closed permanently, checked."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dotmac_deployment_control.role_job_window import (
    RoleJobWindowRefusedError,
    close_window,
    open_window,
    parse_stamp,
    require_open,
    stamp,
    windows_of,
)

_NOW = datetime(2026, 11, 23, 12, 0, 0, tzinfo=UTC)
_HARD = _NOW + timedelta(hours=8)


def _open(existing=(), **kw):  # type: ignore[no-untyped-def]
    base = {
        "role": "import",
        "window_id": "w1",
        "now": _NOW,
        "closes_at": _NOW + timedelta(hours=4),
        "hard_stop_at": _HARD,
    }
    base.update(kw)
    return open_window(existing, **base)


def test_a_window_opens_bounded_by_the_hard_stop() -> None:
    (row,) = _open()
    assert (row.role, row.window_id, row.state) == ("import", "w1", "open")
    assert row.closes_at == "2026-11-23T16:00:00Z"
    # closes_at is required to be in the future and no later than the hard stop.
    with pytest.raises(RoleJobWindowRefusedError, match="future"):
        _open(closes_at=_NOW)
    with pytest.raises(RoleJobWindowRefusedError, match="hard stop"):
        _open(closes_at=_HARD + timedelta(seconds=1))
    assert _open(closes_at=_HARD)  # exactly the hard stop is allowed
    with pytest.raises(RoleJobWindowRefusedError, match="timezone"):
        _open(closes_at=datetime(2026, 11, 23, 14))
    for bad in ("", "x y", "-a", "a" * 65):
        with pytest.raises(RoleJobWindowRefusedError, match="id"):
            _open(window_id=bad)
    with pytest.raises(RoleJobWindowRefusedError, match="role"):
        _open(role="Import")


def test_one_open_window_per_role_and_ids_are_never_reused() -> None:
    rows = _open()
    with pytest.raises(RoleJobWindowRefusedError, match="already has an open"):
        _open(rows, window_id="w2")
    with pytest.raises(RoleJobWindowRefusedError, match="already exists"):
        _open(rows)
    other = _open(rows, role="holdings", window_id="w2")
    assert len(other) == 2


def test_closing_is_permanent_and_a_reopen_is_a_new_id() -> None:
    rows = _open()
    closed_rows, closed = close_window(rows, window_id="w1", now=_NOW)
    assert closed.state == "closed"
    assert closed.closed_at == "2026-11-23T12:00:00Z"
    with pytest.raises(RoleJobWindowRefusedError, match="already closed"):
        close_window(closed_rows, window_id="w1", now=_NOW)
    with pytest.raises(RoleJobWindowRefusedError, match="no window"):
        close_window(closed_rows, window_id="nope", now=_NOW)
    with pytest.raises(RoleJobWindowRefusedError, match="already exists"):
        _open(closed_rows)  # the closed id is never reused
    assert _open(closed_rows, window_id="w2")  # a NEW id opens


def test_use_needs_an_open_unexpired_window_of_that_role() -> None:
    rows = _open()
    assert require_open(rows, role="import", now=_NOW).window_id == "w1"
    assert require_open(rows, role="import", now=_NOW, window_id="w1")
    with pytest.raises(RoleJobWindowRefusedError, match="no open window"):
        require_open(rows, role="holdings", now=_NOW)
    with pytest.raises(RoleJobWindowRefusedError, match="no open window"):
        require_open(rows, role="import", now=_NOW, window_id="w2")
    # Expired: at and after closes_at.
    with pytest.raises(RoleJobWindowRefusedError, match="no open window"):
        require_open(rows, role="import", now=parse_stamp(rows[0].closes_at))
    closed_rows, _ = close_window(rows, window_id="w1", now=_NOW)
    with pytest.raises(RoleJobWindowRefusedError, match="no open window"):
        require_open(closed_rows, role="import", now=_NOW)


def test_rows_round_trip_through_their_stored_form() -> None:
    rows = _open()
    again = windows_of([row.payload() for row in rows])
    assert again == rows
    assert windows_of(None) == ()
    with pytest.raises(RoleJobWindowRefusedError):
        windows_of("nope")
    assert parse_stamp(stamp(_NOW)) == _NOW


def test_the_hard_stop_may_not_exceed_the_opening_plus_max_days() -> None:
    far = _NOW + timedelta(days=31)
    with pytest.raises(RoleJobWindowRefusedError, match="30 days"):
        _open(hard_stop_at=far, closes_at=_NOW + timedelta(days=2))
    assert _open(hard_stop_at=_NOW + timedelta(days=30))
    assert _open(hard_stop_at=far, closes_at=_NOW + timedelta(days=2), max_days=45)
