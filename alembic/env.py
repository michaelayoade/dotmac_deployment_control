"""Run the composed kernel + `mod_deploy` lineages against a real database.

Deliberately thin. This repository owns no migrations, so there is nothing here
to autogenerate against and no metadata to compare: `target_metadata` stays
None. The only job is to connect as the migration owner and apply the lineages
the caller composed into `version_locations`.

The URL comes from `MIGRATION_DATABASE_URL` and has no default. A default would
be a way to run migrations against something nobody named, which is the shape
`AGENTS.md` rule 13 exists to prevent — migrations run as an explicit admin
against an explicit target, never as a side effect of a process starting.
"""

from __future__ import annotations

import os

from sqlalchemy import engine_from_config, pool

from alembic import context

config = context.config

target_metadata = None


def _url() -> str:
    url = os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not set. Migrations run as an explicit "
            "admin against an explicitly named database; there is no default."
        )
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _url()
    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
