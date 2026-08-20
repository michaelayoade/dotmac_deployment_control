"""Public locator for Deployment Control's installed Alembic lineage.

A consuming assembly composes this directory into Alembic's
``version_locations``. Resolving it from this installed package keeps consumers
independent of source checkouts and of the package's private filesystem layout.
"""

from __future__ import annotations

from pathlib import Path


def versions_dir() -> Path:
    """Return the installed directory containing this module's revisions."""
    return Path(__file__).resolve().parent / "versions"


__all__ = ["versions_dir"]
