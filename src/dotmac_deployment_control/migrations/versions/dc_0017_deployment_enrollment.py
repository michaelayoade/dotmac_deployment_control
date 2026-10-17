"""Unpublished Control-owned health epoch ledger; no historical backfill.

Immutable parents have narrow UPDATE(id) for PostgreSQL RI row locking. The
unconditional evidence triggers still reject every actual UPDATE, even id=id.
This is source preparation and does not authorize applying this migration.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0017_deployment_enrollment"
down_revision = "dc_0016_controller_key_nonreuse"
branch_labels = None
depends_on = None

_SCHEMA = "mod_deploy"
_LEDGER = (
    "deployment_enrollments",
    "deployment_enrollment_components",
    "deployment_health_assessments",
    "deployment_enrollment_closures",
)
_POINTER = "deployment_current_enrollments"


def _uuid(name: str, *, primary_key: bool = False) -> sa.Column:
    return sa.Column(
        name, postgresql.UUID(as_uuid=True), nullable=False, primary_key=primary_key
    )


def _ref(name: str, length: int = 200) -> sa.Column:
    return sa.Column(name, sa.String(length), nullable=False)


def _time(name: str) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=False)


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def _fk(column: str, parent: str, name: str = "id") -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column], [f"{_SCHEMA}.{parent}.{name}"], ondelete="RESTRICT"
    )


def _grant(privileges: str, table: str, role: str) -> None:
    op.execute(f"GRANT {privileges} ON {_SCHEMA}.{table} TO {role}")


def _revoke(table: str) -> None:
    op.execute(f"REVOKE ALL PRIVILEGES ON {_SCHEMA}.{table} FROM app_user")


def upgrade() -> None:
    op.create_table(
        "deployment_enrollments",
        _uuid("id", primary_key=True),
        _ref("enrollment_ref"),
        _uuid("attempt_id"),
        _uuid("target_id"),
        _ref("installation_ref"),
        _ref("identity_fingerprint", 128),
        sa.Column("projection", postgresql.JSONB(), nullable=False),
        sa.Column("binding", postgresql.JSONB(), nullable=False),
        *_timestamps(),
        _fk("attempt_id", "rollout_attempts"),
        _fk("target_id", "deployment_targets"),
        sa.UniqueConstraint("enrollment_ref", name="uq_health_enrollment_ref"),
        sa.UniqueConstraint("attempt_id", name="uq_health_enrollment_attempt"),
        sa.UniqueConstraint(
            "installation_ref", name="uq_health_enrollment_installation"
        ),
        sa.UniqueConstraint("target_id", "id", name="uq_health_enrollment_target_id"),
        schema=_SCHEMA,
    )
    op.create_table(
        "deployment_enrollment_components",
        sa.Column("component_code", sa.String(120), primary_key=True, nullable=False),
        _uuid("enrollment_id"),
        _ref("role"),
        *_timestamps(),
        _fk("enrollment_id", "deployment_enrollments"),
        sa.UniqueConstraint("enrollment_id", "role", name="uq_health_enrollment_role"),
        schema=_SCHEMA,
    )
    op.create_table(
        "deployment_health_assessments",
        _uuid("id", primary_key=True),
        _ref("assessment_ref"),
        _uuid("enrollment_id"),
        sa.Column("sequence", sa.Integer(), nullable=False),
        _time("assessed_at"),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        *_timestamps(),
        _fk("enrollment_id", "deployment_enrollments"),
        sa.UniqueConstraint("assessment_ref", name="uq_health_assessment_ref"),
        sa.UniqueConstraint(
            "enrollment_id", "sequence", name="uq_health_assessment_sequence"
        ),
        sa.CheckConstraint("sequence >= 1", name="ck_health_assessment_sequence"),
        schema=_SCHEMA,
    )
    op.create_table(
        "deployment_enrollment_closures",
        _uuid("enrollment_id", primary_key=True),
        _uuid("target_id"),
        _time("closed_at"),
        _ref("closure_ref"),
        sa.Column("successor_id", postgresql.UUID(as_uuid=True), nullable=True),
        *_timestamps(),
        _fk("enrollment_id", "deployment_enrollments"),
        _fk("successor_id", "deployment_enrollments"),
        sa.ForeignKeyConstraint(
            ["target_id", "enrollment_id"],
            [
                "mod_deploy.deployment_enrollments.target_id",
                "mod_deploy.deployment_enrollments.id",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_id", "successor_id"],
            [
                "mod_deploy.deployment_enrollments.target_id",
                "mod_deploy.deployment_enrollments.id",
            ],
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )
    op.create_table(
        _POINTER,
        _uuid("target_id", primary_key=True),
        _uuid("enrollment_id"),
        *_timestamps(),
        _fk("target_id", "deployment_targets"),
        sa.ForeignKeyConstraint(
            ["target_id", "enrollment_id"],
            [
                "mod_deploy.deployment_enrollments.target_id",
                "mod_deploy.deployment_enrollments.id",
            ],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("enrollment_id", name="uq_health_current_enrollment"),
        schema=_SCHEMA,
    )
    for table in _LEDGER:
        op.execute(
            f"CREATE TRIGGER refuse_evidence_rewrite BEFORE UPDATE OR DELETE "
            f"ON {_SCHEMA}.{table} FOR EACH ROW EXECUTE FUNCTION "
            "mod_deploy.refuse_evidence_rewrite()"
        )
        op.execute(
            f"CREATE TRIGGER refuse_evidence_truncate BEFORE TRUNCATE "
            f"ON {_SCHEMA}.{table} FOR EACH STATEMENT EXECUTE FUNCTION "
            "mod_deploy.refuse_evidence_rewrite()"
        )
    # Literal access declarations follow the lineage-wide architecture contract.
    _grant("SELECT, INSERT", "deployment_enrollments", "platform_api")
    _grant("SELECT, INSERT", "deployment_enrollments", "app_admin")
    _revoke("deployment_enrollments")
    _grant("SELECT, INSERT", "deployment_enrollment_components", "platform_api")
    _grant("SELECT, INSERT", "deployment_enrollment_components", "app_admin")
    _revoke("deployment_enrollment_components")
    _grant("SELECT, INSERT", "deployment_health_assessments", "platform_api")
    _grant("SELECT, INSERT", "deployment_health_assessments", "app_admin")
    _revoke("deployment_health_assessments")
    _grant("SELECT, INSERT", "deployment_enrollment_closures", "platform_api")
    _grant("SELECT, INSERT", "deployment_enrollment_closures", "app_admin")
    _revoke("deployment_enrollment_closures")
    # A child FK check can issue SELECT FOR KEY SHARE as its table owner.
    # Narrow privilege enables RI while the unconditional trigger forbids edits.
    for role in ("platform_api", "app_admin"):
        op.execute(f"GRANT UPDATE (id) ON mod_deploy.deployment_enrollments TO {role}")
    _grant(
        "SELECT, INSERT, UPDATE, DELETE",
        "deployment_current_enrollments",
        "platform_api",
    )
    _grant(
        "SELECT, INSERT, UPDATE, DELETE", "deployment_current_enrollments", "app_admin"
    )
    _revoke("deployment_current_enrollments")


def downgrade() -> None:
    # Lock the whole graph before checking emptiness so arrivals cannot race.
    for table in (*_LEDGER, _POINTER):
        op.execute(f"LOCK TABLE {_SCHEMA}.{table} IN ACCESS EXCLUSIVE MODE")
    for table in (*_LEDGER, _POINTER):
        if (
            op.get_bind()
            .execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM {_SCHEMA}.{table})"))  # noqa: S608 -- closed table constants
            .scalar_one()
        ):
            raise RuntimeError("dc_0017 refuses to discard health enrollment history")
    for table in (_POINTER, *reversed(_LEDGER)):
        op.drop_table(table, schema=_SCHEMA)
