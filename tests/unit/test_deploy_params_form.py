"""The typed params form is derived from ParamSpec, never from caller text."""

from __future__ import annotations

from dotmac_deployment_control.deploy_unit import ParamSpec
from dotmac_deployment_control.web import _PARAM_PREFIX, _PARAMS_FIELDS, _field_view


def test_each_field_mirrors_its_param_spec() -> None:
    number = _field_view(
        ParamSpec(
            name="workers",
            type="int",
            minimum=1,
            maximum=8,
            default="2",
            required_in=frozenset({"production"}),
        ),
        None,
    )
    assert (number["input"], number["min"], number["max"]) == (
        f"{_PARAM_PREFIX}workers",
        1,
        8,
    )
    assert number["required"] is True
    assert number["value"] == "2"  # the default pre-fills an unset value
    flag = _field_view(ParamSpec(name="seed", type="bool"), "true")
    assert flag["choices"] == ("true", "false")
    assert flag["value"] == "true"  # a stored value wins over the default
    enum = _field_view(
        ParamSpec(name="mode", type="enum", choices=("mirror", "write")), None
    )
    assert enum["choices"] == ("mirror", "write")


def test_the_form_has_no_descriptor_text_or_digest_field() -> None:
    assert _PARAMS_FIELDS == {
        "release_ref",
        "descriptor_path",
        "expected_desired_revision",
    }
