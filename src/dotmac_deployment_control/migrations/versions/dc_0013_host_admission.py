"""Host-admission Control persistence.

Revision ID: dc_0013_host_admission
Revises: dc_0012_rehearsal_lifecycle
Create Date: 2026-09-21
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "dc_0013_host_admission"
down_revision = "dc_0012_rehearsal_lifecycle"
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


def upgrade() -> None:
    op.create_table(
        "attestation_subject_locks",
        sa.Column("custody_domain", sa.String(40), primary_key=True),
        sa.Column("subject", sa.String(200), primary_key=True),
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
        schema=_SCHEMA,
    )
    op.execute(
        "INSERT INTO mod_deploy.attestation_subject_locks "
        "(custody_domain, subject) SELECT DISTINCT custody_domain, subject "
        "FROM mod_deploy.attestation_enrolments ON CONFLICT DO NOTHING"
    )

    op.create_table(
        "attestation_root_descriptors",
        sa.Column("enrolment_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("issuer", sa.String(200), nullable=False),
        sa.Column("attestation_key_id", sa.String(200), nullable=False),
        sa.Column("evidence_purpose", sa.String(200), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["enrolment_id"],
            ["mod_deploy.attestation_enrolments.id"],
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )

    op.create_table(
        "target_host_associations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", sa.String(200), nullable=False),
        sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authority", sa.String(200), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["target_id"], ["mod_deploy.deployment_targets.id"], ondelete="RESTRICT"
        ),
        schema=_SCHEMA,
    )
    op.create_table(
        "target_host_association_closures",
        sa.Column("association_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authority", sa.String(200), nullable=False),
        sa.Column("successor_id", postgresql.UUID(as_uuid=True)),
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
        sa.ForeignKeyConstraint(
            ["association_id"],
            ["mod_deploy.target_host_associations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["successor_id"],
            ["mod_deploy.target_host_associations.id"],
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )
    op.create_table(
        "target_current_hosts",
        sa.Column("target_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("association_id", postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["target_id"], ["mod_deploy.deployment_targets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["association_id"],
            ["mod_deploy.target_host_associations.id"],
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )

    op.create_table(
        "target_admission_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_association_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_root_subject", sa.String(200), nullable=False),
        sa.Column("candidate_audience", sa.String(200), nullable=False),
        sa.Column("installed_audience", sa.String(200), nullable=False),
        sa.Column("expected_foundation_package", sa.String(200), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authority", sa.String(200), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["target_id"], ["mod_deploy.deployment_targets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["host_association_id"],
            ["mod_deploy.target_host_associations.id"],
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )
    op.create_table(
        "target_admission_policy_closures",
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authority", sa.String(200), nullable=False),
        sa.Column("successor_id", postgresql.UUID(as_uuid=True)),
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
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["mod_deploy.target_admission_policies.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["successor_id"],
            ["mod_deploy.target_admission_policies.id"],
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )
    op.create_table(
        "target_current_admission_policies",
        sa.Column("target_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["target_id"], ["mod_deploy.deployment_targets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["mod_deploy.target_admission_policies.id"],
            ondelete="RESTRICT",
        ),
        schema=_SCHEMA,
    )

    _append_only("attestation_root_descriptors")
    _grant("SELECT, INSERT", "attestation_root_descriptors", "platform_api")
    _grant("SELECT, INSERT", "attestation_root_descriptors", "app_admin")
    _revoke("attestation_root_descriptors")
    _append_only("target_host_associations")
    _grant("SELECT, INSERT", "target_host_associations", "platform_api")
    _grant("SELECT, INSERT", "target_host_associations", "app_admin")
    _revoke("target_host_associations")
    _append_only("target_host_association_closures")
    _grant("SELECT, INSERT", "target_host_association_closures", "platform_api")
    _grant("SELECT, INSERT", "target_host_association_closures", "app_admin")
    _revoke("target_host_association_closures")
    _append_only("target_admission_policies")
    _grant("SELECT, INSERT", "target_admission_policies", "platform_api")
    _grant("SELECT, INSERT", "target_admission_policies", "app_admin")
    _revoke("target_admission_policies")
    _append_only("target_admission_policy_closures")
    _grant("SELECT, INSERT", "target_admission_policy_closures", "platform_api")
    _grant("SELECT, INSERT", "target_admission_policy_closures", "app_admin")
    _revoke("target_admission_policy_closures")
    # `attestation_subject_locks` is a lock TARGET: every admission and every
    # root mutation takes `SELECT ... FOR UPDATE` on it, and PostgreSQL's
    # locking-read clause requires the UPDATE privilege (in addition to
    # SELECT) on at least one column, the same way every other lock-target
    # table here (`deployment_targets`, `target_credentials`, ...) carries an
    # explicit UPDATE grant. `_append_only` still refuses a real UPDATE/DELETE
    # statement -- its trigger does not fire for a locking SELECT -- so the
    # row-locking use is preserved while genuine rewrites remain refused.
    _append_only("attestation_subject_locks")
    _grant("SELECT, INSERT, UPDATE", "attestation_subject_locks", "platform_api")
    _grant("SELECT, INSERT, UPDATE", "attestation_subject_locks", "app_admin")
    _revoke("attestation_subject_locks")
    _grant("SELECT, INSERT, UPDATE, DELETE", "target_current_hosts", "platform_api")
    _grant("SELECT, INSERT, UPDATE, DELETE", "target_current_hosts", "app_admin")
    _revoke("target_current_hosts")
    _grant(
        "SELECT, INSERT, UPDATE, DELETE",
        "target_current_admission_policies",
        "platform_api",
    )
    _grant(
        "SELECT, INSERT, UPDATE, DELETE",
        "target_current_admission_policies",
        "app_admin",
    )
    _revoke("target_current_admission_policies")


def downgrade() -> None:
    evidence_checks = (
        (
            "attestation_root_descriptors",
            "SELECT EXISTS (SELECT 1 FROM mod_deploy.attestation_root_descriptors)",
        ),
        (
            "target_host_associations",
            "SELECT EXISTS (SELECT 1 FROM mod_deploy.target_host_associations)",
        ),
        (
            "target_host_association_closures",
            "SELECT EXISTS (SELECT 1 FROM "
            "mod_deploy.target_host_association_closures)",
        ),
        (
            "target_admission_policies",
            "SELECT EXISTS (SELECT 1 FROM mod_deploy.target_admission_policies)",
        ),
        (
            "target_admission_policy_closures",
            "SELECT EXISTS (SELECT 1 FROM "
            "mod_deploy.target_admission_policy_closures)",
        ),
        (
            "attestation_subject_locks",
            "SELECT EXISTS (SELECT 1 FROM mod_deploy.attestation_subject_locks)",
        ),
    )
    for table, _query in evidence_checks:
        op.execute(f"LOCK TABLE {_SCHEMA}.{table} IN ACCESS EXCLUSIVE MODE;")
    connection = op.get_bind()
    for table, query in evidence_checks:
        if connection.execute(sa.text(query)).scalar_one():
            raise RuntimeError(
                "dc_0013_host_admission refuses to discard append-only "
                f"host-admission evidence in {_SCHEMA}.{table}"
            )
    for table in (
        "target_current_admission_policies",
        "target_admission_policy_closures",
        "target_admission_policies",
        "target_current_hosts",
        "target_host_association_closures",
        "target_host_associations",
        "attestation_root_descriptors",
        "attestation_subject_locks",
    ):
        op.drop_table(table, schema=_SCHEMA)
