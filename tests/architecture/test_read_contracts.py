"""The public read surface, and the digest a client may never supply.

Wave 2 groundwork: a browser surface for this module has to be buildable
without a consumer reaching into its tables, and without a client ever naming a
PlanDigest. Both are structural properties, and this file is where they stop
being intentions.

The census found zero module web/API contribution across six manifests, so
there is no existing pattern to copy — correct or otherwise. What is established
here is the reference.
"""

from __future__ import annotations

import dataclasses
import inspect

import pytest

import dotmac_deployment_control as api
from dotmac_deployment_control import facts, service

#: Every public type a caller can CONSTRUCT and hand inward. A digest appearing
#: on one of these is a digest a client can choose.
INPUT_TYPES = (
    api.ProposePlanCommand,
    api.ApprovePlanCommand,
    api.RequestRolloutCommand,
    api.RegisterTargetCommand,
    api.SetDesiredStateCommand,
    api.TargetFilter,
)


class TestTheClientCanNeverSupplyAPlanDigest:
    """The property, stated over the whole input surface rather than one type.

    `propose_plan` derives the digest from state this module owns. If any input
    type grows a plan-digest field, a caller can name the plan an approval binds
    to — and an approval bound to a client-supplied digest is an approval for
    whatever the client chose to describe.
    """

    def test_no_input_type_carries_a_plan_digest_field(self) -> None:
        offenders = [
            f"{cls.__name__}.{f.name}"
            for cls in INPUT_TYPES
            for f in dataclasses.fields(cls)
            if "plan_digest" in f.name
        ]
        assert not offenders, offenders

    def test_the_propose_command_takes_no_digest_at_all(self) -> None:
        names = {f.name for f in dataclasses.fields(api.ProposePlanCommand)}
        assert not {n for n in names if "digest" in n}

    def test_the_approval_digest_is_the_approvers_not_the_plans(self) -> None:
        """`ApprovalEvidence.content_digest` is NOT an exception to the rule.

        It is the approver stating which content they approved, and
        `approve_plan` refuses it unless it equals the digest this module
        derived. That is a comparison against server-derived truth, which is the
        opposite of accepting a client's plan digest.
        """
        names = {f.name for f in dataclasses.fields(api.ApprovalEvidence)}
        assert "content_digest" in names
        source = inspect.getsource(service.approve_plan)
        assert "PlanDigestV1" in source or "plan_digest" in source

    def test_the_preview_is_a_read_with_no_input_but_a_target(self) -> None:
        """A preview that accepted a plan would be a submission wearing a read's
        name."""
        params = list(inspect.signature(api.preview_plan_proposal).parameters)
        assert params == ["db", "target_id"]


class TestTheReadContractsAreTypedAndClosed:
    def test_the_target_filter_is_a_closed_set_of_fields(self) -> None:
        """No predicate, no sort column, no raw where. A consumer that could
        pass a predicate would own every future query."""
        names = {f.name for f in dataclasses.fields(facts.TargetFilter)}
        assert names == {
            "product_code",
            "environment",
            "status",
            "never_observed",
            "page",
            "page_size",
        }

    @pytest.mark.parametrize(
        ("page", "size"), [(0, 50), (-1, 50), (1, 0), (1, 201), (1, -5)]
    )
    def test_the_filter_refuses_an_unbounded_or_nonsense_page(
        self, page: int, size: int
    ) -> None:
        """An unbounded list is how a fleet screen becomes a full-table scan."""
        with pytest.raises(ValueError):
            facts.TargetFilter(page=page, page_size=size)

    def test_the_filter_admits_the_bounds_it_permits(self) -> None:
        """BOTH HALVES — a validator only seen refusing might refuse
        everything."""
        assert facts.TargetFilter(page=1, page_size=1).page_size == 1
        limit = facts.TargetFilter.MAX_PAGE_SIZE
        assert facts.TargetFilter(page=9, page_size=limit).page_size == limit

    def test_the_page_reports_enough_to_render_a_pager(self) -> None:
        page = facts.TargetPage(targets=(), total=412, page=1, page_size=50)
        assert page.has_more
        assert not facts.TargetPage(
            targets=(), total=50, page=1, page_size=50
        ).has_more


class TestQueryConstructionStaysInThisModule:
    """A consumer must never build a query over these tables.

    Platform CP owns the operator workflow; this module owns its schema. The
    moment a consumer writes its own `select()` it has taken a second read
    authority over tables it does not own, and every column rename becomes a
    cross-repository break.
    """

    def test_the_public_surface_exposes_reads_not_tables(self) -> None:
        for name in ("list_targets", "preview_plan_proposal", "get_target"):
            assert callable(getattr(api, name))

    def test_query_construction_lives_only_in_the_service_layer(self) -> None:
        import pathlib

        root = pathlib.Path(service.__file__).parent
        offenders = [
            path.name
            for path in root.glob("*.py")
            if path.name != "service.py" and "select(" in path.read_text()
        ]
        assert not offenders, (
            f"query construction outside the service layer: {offenders}"
        )
