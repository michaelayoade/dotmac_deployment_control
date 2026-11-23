"""The role-job window: when a dispatched job's role may be used, as values.

A role job (import-only OpenBao) may be proposed and dispatched only inside an
OPEN window for its role on its target. A window is opened and closed by two
ATTENDED commands (a register line each) and carries `closes_at`, which may not
be later than the hard stop (C-14) recorded with it. Closing is permanent for
that `window_id`; re-opening is a NEW id. The `window_id` and `closes_at` are
copied into the signed plan, so the agent can refuse on its own clock too.

Pure: no I/O. The service persists the rows in the `role_job_windows` setting.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from dotmac_deployment_control.deploy_unit import DeployUnitError

SETTING_ROLE_JOB_WINDOWS: Final = "role_job_windows"
WINDOW_OPEN: Final = "open"
WINDOW_CLOSED: Final = "closed"
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_ROLE: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_STAMP: Final = "%Y-%m-%dT%H:%M:%SZ"


class RoleJobWindowRefusedError(DeployUnitError):
    """A window was opened, closed or used against the rules."""


def stamp(moment: datetime) -> str:
    """The canonical second-resolution UTC text the plan signs."""
    return moment.astimezone(UTC).strftime(_STAMP)


def parse_stamp(text: str) -> datetime:
    return datetime.strptime(text, _STAMP).replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class RoleJobWindow:
    role: str
    window_id: str
    state: str
    opened_at: str
    closes_at: str
    hard_stop_at: str
    closed_at: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "window_id": self.window_id,
            "state": self.state,
            "opened_at": self.opened_at,
            "closes_at": self.closes_at,
            "hard_stop_at": self.hard_stop_at,
            "closed_at": self.closed_at,
        }

    @staticmethod
    def of(raw: Mapping[str, Any]) -> RoleJobWindow:
        return RoleJobWindow(
            role=str(raw["role"]),
            window_id=str(raw["window_id"]),
            state=str(raw["state"]),
            opened_at=str(raw["opened_at"]),
            closes_at=str(raw["closes_at"]),
            hard_stop_at=str(raw["hard_stop_at"]),
            closed_at=None if raw.get("closed_at") is None else str(raw["closed_at"]),
        )


def windows_of(raw: object) -> tuple[RoleJobWindow, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        raise RoleJobWindowRefusedError("stored windows are a list")
    return tuple(RoleJobWindow.of(item) for item in raw)


def open_window(
    existing: Sequence[RoleJobWindow],
    *,
    role: str,
    window_id: str,
    now: datetime,
    closes_at: datetime,
    hard_stop_at: datetime,
) -> tuple[RoleJobWindow, ...]:
    """Add an OPEN window. `closes_at` is required and bounded by the hard stop."""
    if not _ROLE.fullmatch(role):
        raise RoleJobWindowRefusedError("a window role is a lowercase segment")
    if not _ID.fullmatch(window_id):
        raise RoleJobWindowRefusedError("a window id is 1..64 safe characters")
    if closes_at.tzinfo is None or hard_stop_at.tzinfo is None:
        raise RoleJobWindowRefusedError("window times are timezone-aware")
    if closes_at <= now:
        raise RoleJobWindowRefusedError("closes_at must be in the future")
    if closes_at > hard_stop_at:
        raise RoleJobWindowRefusedError(
            "closes_at may not be later than the hard stop (C-14)"
        )
    if any(w.window_id == window_id for w in existing):
        raise RoleJobWindowRefusedError(
            f"window {window_id!r} already exists; a closed window is permanent "
            "and re-opening is a NEW id"
        )
    if any(w.role == role and w.state == WINDOW_OPEN for w in existing):
        raise RoleJobWindowRefusedError(f"role {role!r} already has an open window")
    row = RoleJobWindow(
        role=role,
        window_id=window_id,
        state=WINDOW_OPEN,
        opened_at=stamp(now),
        closes_at=stamp(closes_at),
        hard_stop_at=stamp(hard_stop_at),
    )
    return (*existing, row)


def close_window(
    existing: Sequence[RoleJobWindow], *, window_id: str, now: datetime
) -> tuple[tuple[RoleJobWindow, ...], RoleJobWindow]:
    """Close a window for good. Returns the new rows and the closed one."""
    target = next((w for w in existing if w.window_id == window_id), None)
    if target is None:
        raise RoleJobWindowRefusedError(f"no window {window_id!r}")
    if target.state != WINDOW_OPEN:
        raise RoleJobWindowRefusedError(f"window {window_id!r} is already closed")
    closed = RoleJobWindow(
        role=target.role,
        window_id=target.window_id,
        state=WINDOW_CLOSED,
        opened_at=target.opened_at,
        closes_at=target.closes_at,
        hard_stop_at=target.hard_stop_at,
        closed_at=stamp(now),
    )
    return tuple(closed if w is target else w for w in existing), closed


def require_open(
    existing: Sequence[RoleJobWindow],
    *,
    role: str,
    now: datetime,
    window_id: str | None = None,
) -> RoleJobWindow:
    """The open, unexpired window of `role` (and `window_id`, when given)."""
    for window in existing:
        if window.role != role or window.state != WINDOW_OPEN:
            continue
        if window_id is not None and window.window_id != window_id:
            continue
        if now >= parse_stamp(window.closes_at):
            continue
        return window
    raise RoleJobWindowRefusedError(
        f"no open window for role {role!r}"
        + (f" with id {window_id!r}" if window_id else "")
        + "; open it first (attended), or it has closed or expired"
    )
