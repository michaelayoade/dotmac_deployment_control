"""Deploy-unit state: settings, legacy env-file policy versions, deployment sets.

Additive and expand-only: three new tables, nothing existing is altered.

* `deploy_settings` is the one deliberately mutable table: a small named
  setting, each change recorded with its attended approver and register line
  (`public_pull_repositories`, `legacy_env_file_allowed_targets`,
  `legacy_env_file_ceiling`). The empty or zero default is the ABSENCE of a row.
* `legacy_env_policy_versions` is append-only evidence: one row per policy
  version of a target, so a changed sha or a retirement is a new visible row and
  never an edit. The current policy is the highest version.
* `deployment_sets` is append-only evidence: a primary plan, an optional
  companion plan and the set digest one approval covers.

Revision ID: dc_0017_deploy_unit_state
Revises: dc_0016_controller_key_nonreuse
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0017_deploy_unit_state"
down_revision = "dc_0016_controller_key_nonreuse"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"


def _grant(privileges: str, table: str, role: str) -> None:
    op.execute(f"GRANT {privileges} ON {_SCHEMA}.{table} TO {role};")


def _revoke(table: str) -> None:
    op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM app_user;")


def _append_only(table: str) -> None:
    op.execute(
        "CREATE TRIGGER refuse_evidence_rewrite BEFORE UPDATE OR DELETE ON "
        f"{_SCHEMA}.{table} FOR EACH ROW EXECUTE FUNCTION "
        f"{_SCHEMA}.refuse_evidence_rewrite();"
    )
    op.execute(
        "CREATE TRIGGER refuse_evidence_truncate BEFORE TRUNCATE ON "
        f"{_SCHEMA}.{table} FOR EACH STATEMENT EXECUTE FUNCTION "
        f"{_SCHEMA}.refuse_evidence_rewrite();"
    )


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def upgrade() -> None:
    op.create_table(
        "deploy_settings",
        sa.Column("setting_name", sa.String(length=200), primary_key=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("setting_version", sa.Integer(), nullable=False),
        sa.Column("approver_ref", sa.String(length=200), nullable=False),
        sa.Column("register_ref", sa.String(length=200), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "setting_version >= 1", name="ck_deploy_settings_version_positive"
        ),
        sa.CheckConstraint(
            "setting_name IN ('public_pull_repositories', "
            "'legacy_env_file_allowed_targets', 'legacy_env_file_ceiling')",
            name="ck_deploy_settings_name",
        ),
        schema=_SCHEMA,
    )
    op.create_table(
        "legacy_env_policy_versions",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.deployment_targets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("product_code", sa.String(length=200), nullable=False),
        sa.Column("names", postgresql.JSONB(), nullable=False),
        sa.Column("file_sha256", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled_by_ref", sa.String(length=200), nullable=False),
        sa.Column("register_ref", sa.String(length=200), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint(
            "target_id",
            "policy_version",
            name="uq_legacy_env_policy_versions_target_version",
        ),
        sa.CheckConstraint(
            "policy_version >= 1",
            name="ck_legacy_env_policy_versions_version_positive",
        ),
        sa.CheckConstraint(
            "state IN ('enabled', 'retired')",
            name="ck_legacy_env_policy_versions_state",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_legacy_env_policy_versions_target_id",
        "legacy_env_policy_versions",
        ["target_id"],
        schema=_SCHEMA,
    )
    op.create_table(
        "deployment_sets",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column(
            "primary_plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.deployment_plans.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "companion_plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.deployment_plans.id", ondelete="RESTRICT"),
        ),
        sa.Column("order_policy", sa.String(length=40), nullable=False),
        sa.Column("required_at_switch", sa.Boolean(), nullable=False),
        sa.Column("set_digest", sa.String(length=128), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("set_digest", name="uq_deployment_sets_set_digest"),
        sa.CheckConstraint(
            "companion_plan_id IS NULL OR companion_plan_id <> primary_plan_id",
            name="ck_deployment_sets_distinct_plans",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_deployment_sets_primary_plan_id",
        "deployment_sets",
        ["primary_plan_id"],
        schema=_SCHEMA,
    )

    # THE ACCESS SURFACE. Literal table names, as the grant sweep reads them.
    _grant("SELECT, INSERT, UPDATE", "deploy_settings", "platform_api")
    _grant("SELECT, INSERT, UPDATE", "deploy_settings", "app_admin")
    _revoke("deploy_settings")
    _append_only("legacy_env_policy_versions")
    _grant("SELECT, INSERT", "legacy_env_policy_versions", "platform_api")
    _grant("SELECT, INSERT", "legacy_env_policy_versions", "app_admin")
    _revoke("legacy_env_policy_versions")
    _append_only("deployment_sets")
    _grant("SELECT, INSERT", "deployment_sets", "platform_api")
    _grant("SELECT, INSERT", "deployment_sets", "app_admin")
    _revoke("deployment_sets")


def downgrade() -> None:
    # Policy versions and sets are evidence; a downgrade must not erase them.
    # Settings are current state and are recorded by audit events, so an empty
    # or populated settings table does not block the downgrade.
    for table in ("legacy_env_policy_versions", "deployment_sets"):
        op.execute(f"LOCK TABLE {_SCHEMA}.{table} IN ACCESS EXCLUSIVE MODE")
    bind = op.get_bind()
    if bind.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM mod_deploy.legacy_env_policy_versions)")
    ).scalar_one():
        raise RuntimeError(
            "dc_0017_deploy_unit_state refuses to discard legacy env-file "
            "policy version evidence"
        )
    if bind.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM mod_deploy.deployment_sets)")
    ).scalar_one():
        raise RuntimeError(
            "dc_0017_deploy_unit_state refuses to discard deployment set evidence"
        )
    op.drop_index(
        "ix_deployment_sets_primary_plan_id", "deployment_sets", schema=_SCHEMA
    )
    op.drop_table("deployment_sets", schema=_SCHEMA)
    op.drop_index(
        "ix_legacy_env_policy_versions_target_id",
        "legacy_env_policy_versions",
        schema=_SCHEMA,
    )
    op.drop_table("legacy_env_policy_versions", schema=_SCHEMA)
    op.drop_table("deploy_settings", schema=_SCHEMA)
