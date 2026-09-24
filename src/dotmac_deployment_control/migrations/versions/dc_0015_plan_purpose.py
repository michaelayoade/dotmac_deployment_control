"""Freeze the closed authority class of each deployment plan.

Historical plans are Foundation execution plans. No migration infers issuer
authority from a rehearsal environment, operation, or approval.

Revision ID: dc_0015_plan_purpose
Revises: dc_0014_rehearsal_issuer_ledger
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "dc_0015_plan_purpose"
down_revision = "dc_0014_rehearsal_issuer_ledger"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "deployment_plans",
        sa.Column(
            "purpose",
            sa.String(length=40),
            nullable=True,
        ),
        schema="mod_deploy",
    )
    op.execute(
        "UPDATE mod_deploy.deployment_plans SET purpose = "
        "'foundation_execution' WHERE purpose IS NULL"
    )
    op.alter_column("deployment_plans", "purpose", nullable=False, schema="mod_deploy")
    op.create_check_constraint(
        "ck_deployment_plans_purpose",
        "deployment_plans",
        "purpose IN ('foundation_execution', 'rehearsal_issuer_operation')",
        schema="mod_deploy",
    )
    # a14 issued C1 envelopes without an authority-class discriminator.
    # Preserve the ledger and make every such outstanding grant terminal.
    op.execute(
        "UPDATE mod_deploy.rehearsal_issuer_authorizations "
        "SET state = 'revoked', revoked_at = now(), "
        "revocation_ref = 'migration:dc_0015_plan_purpose:legacy_issuer', "
        "updated_at = now() WHERE state = 'issued'"
    )
    op.execute(
        """
CREATE FUNCTION mod_deploy.prevent_plan_purpose_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.snapshot->>'plan_purpose' IS DISTINCT FROM NEW.purpose THEN
            RAISE EXCEPTION 'new deployment plan requires a frozen purpose marker';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.purpose IS DISTINCT FROM OLD.purpose THEN
        RAISE EXCEPTION 'deployment plan purpose is frozen';
    END IF;
    IF NEW.snapshot->'plan_purpose' IS DISTINCT FROM
       OLD.snapshot->'plan_purpose' THEN
        RAISE EXCEPTION 'deployment plan purpose marker is frozen';
    END IF;
    RETURN NEW;
END;
$$
        """
    )
    op.execute(
        """
CREATE TRIGGER deployment_plans_purpose_guard
BEFORE INSERT OR UPDATE ON mod_deploy.deployment_plans
FOR EACH ROW EXECUTE FUNCTION mod_deploy.prevent_plan_purpose_change()
        """
    )


def downgrade() -> None:
    # a14 cannot distinguish any post-dc0015 plan from its old issuer-eligible
    # rehearsal/deploy plans, even when the new plan was Foundation-only.
    # Historical marker-absent rows may be read by a14 as they were before.
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM mod_deploy.deployment_plans "
                "WHERE snapshot ? 'plan_purpose')"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError("cannot discard purpose-marked deployment plans")
    op.execute(
        "DROP TRIGGER deployment_plans_purpose_guard " "ON mod_deploy.deployment_plans"
    )
    op.execute("DROP FUNCTION mod_deploy.prevent_plan_purpose_change()")
    op.drop_constraint(
        "ck_deployment_plans_purpose",
        "deployment_plans",
        schema="mod_deploy",
        type_="check",
    )
    op.drop_column("deployment_plans", "purpose", schema="mod_deploy")
