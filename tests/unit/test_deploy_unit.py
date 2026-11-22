"""The deploy-unit descriptor and typed params (design 2.2, 2.5, 2.9 Control column).

Pure value tests: no database. Documentation ranges only (192.0.2.0/24,
198.51.100.0/24); no estate addresses.
"""

from __future__ import annotations

import pytest

from dotmac_deployment_control.deploy_unit import (
    DeployUnitError,
    ParamRefusedError,
    ParamSpec,
    canonical_render,
    params_env_digest,
    parse_deploy_unit,
    parse_secret_ref,
    validate_param_value,
    validate_params,
)

_DESCRIPTOR = """
schema = "dotmac.deploy_unit/1"
product = "erp_v2"
spec = "deploy/product.toml"

[params.public_host]
type = "hostname"
material = "PUBLIC_HOST"
required_in = ["staging", "production"]

[params.workers]
type = "int"
material = "WORKERS"
minimum = 1
maximum = 16

[params.log_level]
type = "enum"
material = "LOG_LEVEL"
choices = ["info", "debug"]

[params.secrets_dir_app]
type = "path"
material = "SECRETS_DIR_APP"

[params.legacy_path]
type = "path"

[[bindings]]
name = "DB_PASSWORD"
kind = "kv"
roles = ["app"]
writer = "agent"
rotation = "manual"
single_use = false
"""


def _unit(extra: str = "", *, product: str = "erp_v2"):
    text = _DESCRIPTOR.replace('product = "erp_v2"', f'product = "{product}"') + extra
    return parse_deploy_unit(text)


def _spec(kind: str, **kw: object) -> ParamSpec:
    return ParamSpec(name="p", type=kind, **kw)  # type: ignore[arg-type]


def test_descriptor_digest_is_computed_by_control_not_declared() -> None:
    unit = _unit()
    assert unit.digest.startswith("sha256:")
    assert unit.digest == _unit().digest
    assert unit.digest != _unit("\n# a comment changes the bytes\n").digest
    with pytest.raises(DeployUnitError):
        parse_deploy_unit(
            _DESCRIPTOR + "spec_digest = " + '"sha256:' + "a" * 64 + '"\n'
        )


def test_descriptor_parses_and_image_defaults_to_transfer() -> None:
    unit = _unit()
    assert unit.product == "erp_v2"
    assert unit.image_source == "transfer"
    assert set(unit.params) == {
        "public_host",
        "workers",
        "log_level",
        "secrets_dir_app",
        "legacy_path",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        ('schema = "dotmac.deploy_unit/1"', 'schema = "dotmac.deploy_unit/2"'),
        ('spec = "deploy/product.toml"', 'spec = "elsewhere.toml"'),
        ('type = "hostname"', 'type = "ipv9"'),
        ('material = "WORKERS"', 'material = "APP_IMAGE"'),
        ('material = "WORKERS"', 'material = "PUBLIC_HOST"'),
    ],
)
def test_descriptor_refusals(mutation: tuple[str, str]) -> None:
    with pytest.raises(DeployUnitError):
        parse_deploy_unit(_DESCRIPTOR.replace(*mutation))


def test_descriptor_refuses_unknown_keys_and_bad_image_source() -> None:
    with pytest.raises(DeployUnitError):
        parse_deploy_unit(_DESCRIPTOR + "\nsurprise = 1\n")
    with pytest.raises(DeployUnitError):
        parse_deploy_unit(_DESCRIPTOR + '\n[image]\nsource = "copy"\n')


def test_params_refused_unknown_and_missing_required() -> None:
    unit = _unit()
    with pytest.raises(ParamRefusedError, match="unknown"):
        validate_params(
            unit,
            {"public_host": "erp.example.test", "nope": "1"},
            environment="staging",
        )
    with pytest.raises(ParamRefusedError, match="required"):
        validate_params(unit, {"workers": 2}, environment="staging")
    # Not required in an environment that does not list it.
    assert validate_params(unit, {"workers": 2}, environment="dev") == {"workers": "2"}


def test_params_refused_out_of_bounds() -> None:
    unit = _unit()
    for bad in (0, 17, True, "x", 2.5):
        with pytest.raises(ParamRefusedError):
            validate_params(
                unit,
                {"public_host": "erp.example.test", "workers": bad},
                environment="staging",
            )
    with pytest.raises(ParamRefusedError):
        validate_param_value(_spec("enum", choices=("a",)), "b")
    with pytest.raises(ParamRefusedError):
        validate_param_value(_spec("duration_seconds"), -1)
    with pytest.raises(ParamRefusedError):
        validate_param_value(_spec("string", max_length=3), "abcd")


@pytest.mark.parametrize(
    "value",
    ["a\nb", "a\rb", "a\x00b", " lead", "trail ", '"quoted"', "'quoted'", ""],
)
def test_params_refused_quote_or_whitespace(value: str) -> None:
    with pytest.raises(ParamRefusedError):
        validate_param_value(_spec("string"), value)


def test_params_refused_secret_shaped() -> None:
    # Built at runtime so no literal credential-shaped string sits in the source.
    shaped = [
        "ghp_" + "Ab1" * 12,
        "-----BEGIN " + "PRIVATE KEY-----",
        "hvs." + "Zz9" * 8,
        "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "postgres://user:hunter2@db.example.test/app",
        "q8Zr7Lk2Vb9Xw3Nc5Mt1Hy6Pd4Sg0Jf8Ae2Ru",
    ]
    for value in shaped:
        with pytest.raises(ParamRefusedError):
            validate_param_value(_spec("string"), value)
    # Ordinary values pass.
    assert validate_param_value(_spec("string"), "release-2026.11") == "release-2026.11"


@pytest.mark.parametrize(
    ("kind", "good", "bad"),
    [
        ("hostname", "erp.example.test", "erp..example"),
        ("hostname", "a-b.example.test", "-bad.example.test"),
        ("cidr", "198.51.100.0/24", "198.51.100.1/24"),
        ("url", "https://erp.example.test:8443/x", "https://u:p@erp.example.test/"),
        ("url", "http://192.0.2.10/health", "ftp://erp.example.test/"),
        ("path", "/run/dotmac/erp/secrets", "relative/path"),
        ("path", "/opt/dotmac/erp", "/opt/../etc"),
        ("image_digest", "sha256:" + "a" * 64, "sha256:" + "A" * 64),
        (
            "image_repository",
            "registry.example.test/team/app",
            "registry.example.test/app:1",
        ),
        ("bool", True, "yes"),
        ("duration_seconds", 30, "soon"),
    ],
)
def test_typed_values(kind: str, good: object, bad: object) -> None:
    assert validate_param_value(_spec(kind), good)
    with pytest.raises(ParamRefusedError):
        validate_param_value(_spec(kind), bad)


def test_secret_ref_grammar() -> None:
    ref = parse_secret_ref("bao://staging/erp_v2/kv/app/DB_PASSWORD".lower())
    assert (ref.environment, ref.product, ref.role) == ("staging", "erp_v2", "app")
    assert ref.render() == "bao://staging/erp_v2/kv/app/db_password"
    for bad in (
        "bao://staging/erp/app/x",
        "https://staging/erp/kv/app/x",
        "bao://staging/erp/kv/app",
        "bao://staging/erp/kv/app/x/extra",
        "bao://staging/erp/kv//x",
        None,
    ):
        with pytest.raises(DeployUnitError):
            parse_secret_ref(bad)


def test_canonical_render_is_sorted_lf_terminated_and_includes_app_image() -> None:
    unit = _unit()
    image = "127.0.0.1:5000/team/app@sha256:" + "b" * 64
    values = {
        "workers": 4,
        "public_host": "erp.example.test",
        "secrets_dir_app": "/run/dotmac/erp_v2/secrets/app",
        "legacy_path": "/etc/dotmac/legacy/erp.env",  # no material: not rendered
    }
    render = canonical_render(unit, values, app_image=image, environment="staging")
    assert (
        render
        == (
            f"APP_IMAGE={image}\n"
            "PUBLIC_HOST=erp.example.test\n"
            "SECRETS_DIR_APP=/run/dotmac/erp_v2/secrets/app\n"
            "WORKERS=4\n"
        ).encode()
    )
    assert params_env_digest(render).startswith("sha256:")
    # Insertion order does not matter.
    again = canonical_render(
        unit,
        dict(reversed(list(values.items()))),
        app_image=image,
        environment="staging",
    )
    assert again == render


def test_plan_binds_params_env_digest() -> None:
    """Any change to a value, or to the planned image, moves the digest."""
    unit = _unit()
    base = {"public_host": "erp.example.test", "workers": 2}
    image = "127.0.0.1:5000/team/app@sha256:" + "c" * 64

    def digest(values: dict[str, object], app_image: str = image) -> str:
        return params_env_digest(
            canonical_render(unit, values, app_image=app_image, environment="dev")
        )

    reference = digest(base)
    assert digest({**base, "workers": 3}) != reference
    assert digest(base, image.replace("c", "d")) != reference
    assert digest(dict(base)) == reference
