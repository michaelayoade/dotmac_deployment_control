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
min = 1
max = 16

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


# ── The a18 descriptor schema (shapes the descriptor lane relies on) ─────────

_ERP_SHAPED = """
schema = "dotmac.deploy_unit/1"
product = "dotmac-erp-v2"
spec = "deploy/product.toml"

[image]
source = "transfer"

[params.trusted_hosts]
type = "string"
required_in = ["production"]
material = "TRUSTED_HOSTS"
pattern = "^[A-Za-z0-9.-]+(,[A-Za-z0-9.-]+)*$"
max_length = 512

[params.seed_on_startup]
type = "bool"
default = false
choices = [false]
required_in = ["production"]
material = "SEED_ON_STARTUP"

[params.port_mode]
type = "enum"
default = "mirror"
choices = ["mirror", "write"]
material = "PORT_MODE"

[params.legacy_env_path]
type = "path"
pattern = "^/etc/dotmac/legacy/[A-Za-z0-9._-]+\\\\.env$"
max_length = 255

[params.hold_timeout_seconds]
type = "duration_seconds"
default = 1800
min = 60
max = 3600
required_in = ["production"]
material = "HOLD_TIMEOUT_SECONDS"

[legacy_env_file]
names = ["DATABASE_URL", "JWT_SECRET"]
path_param = "legacy_env_path"

[[bindings]]
name = "DATABASE_URL"
state = "pre_staged"
kind = "pg_login_dsn"
roles = ["app"]
writer = "ceremony"
rotation = "copy_only"
single_use = false

[[bindings]]
name = "JWT_SECRET"
state = "pre_staged"
kind = "key"
roles = ["app"]
writer = "ceremony"
rotation = "copy_only"
single_use = false

[[bindings]]
name = "MIGRATION_DATABASE_URL"
kind = "pg_login_dsn"
roles = ["migrate"]
writer = "ceremony"
rotation = "copy_only"
single_use = true

[[jobs]]
name = "import"
command = ["python", "-m", "erp_v2.importer", "execute"]
trigger = "operator"
materials = ["MIGRATION_DATABASE_URL"]
runbook = "docs/rehearsal.md"

[[hold_points]]
name = "companion-genesis-window"
member = "companion"
before = "migrate"
timeout_param = "hold_timeout_seconds"
on_timeout = "abandon_member_record_deviation"
released_by = "operator"

[[companions]]
product = "dotmac-integrator-companion"
descriptor = "deploy/companion/deploy-unit.toml"
order = "after_primary_ready"
required_at_switch = false
host = "same"

[health]
gates = ["migrate", "heads", "live", "ready"]
"""


def test_the_full_descriptor_shape_parses() -> None:
    unit = parse_deploy_unit(_ERP_SHAPED)
    assert [b.state for b in unit.bindings] == ["pre_staged", "pre_staged", "active"]
    assert unit.active_binding_names() == ("MIGRATION_DATABASE_URL",)
    assert [j.name for j in unit.jobs] == ["import"]
    assert unit.hold_points[0].timeout_param == "hold_timeout_seconds"
    assert unit.companions[0].host == "same"
    assert unit.health_gates == ("migrate", "heads", "live", "ready")
    assert unit.params["hold_timeout_seconds"].default == "1800"
    assert unit.params["seed_on_startup"].default == "false"
    assert unit.params["seed_on_startup"].choices == ("false",)


def test_defaults_fill_an_absent_value_and_choices_and_patterns_bind() -> None:
    unit = parse_deploy_unit(_ERP_SHAPED)
    rendered = validate_params(
        unit, {"trusted_hosts": "erp.example.test"}, environment="production"
    )
    assert rendered["hold_timeout_seconds"] == "1800"
    assert rendered["seed_on_startup"] == "false"
    assert rendered["port_mode"] == "mirror"
    base = {"trusted_hosts": "ok.example.test"}
    for bad in (
        {"trusted_hosts": "bad host"},
        {**base, "seed_on_startup": True},
        {**base, "port_mode": "other"},
        {**base, "hold_timeout_seconds": 3601},
        {**base, "hold_timeout_seconds": 59},
        {**base, "legacy_env_path": "/opt/x.env"},
    ):
        with pytest.raises(ParamRefusedError):
            validate_params(unit, bad, environment="production")
    ok = {**base, "legacy_env_path": "/etc/dotmac/legacy/e.env"}
    assert validate_params(unit, ok, environment="production")


@pytest.mark.parametrize(
    "mutation",
    [
        (
            'rotation = "copy_only"\nsingle_use = false\n\n[[bindings]]\nname = "JWT',
            'rotation = "weekly"\nsingle_use = false\n\n[[bindings]]\nname = "JWT',
        ),
        ('state = "pre_staged"\nkind = "key"', 'state = "half"\nkind = "key"'),
        ('trigger = "operator"', 'trigger = "cron"'),
        ('materials = ["MIGRATION_DATABASE_URL"]', 'materials = ["NOT_A_MATERIAL"]'),
        ('timeout_param = "hold_timeout_seconds"', 'timeout_param = "trusted_hosts"'),
        ('on_timeout = "abandon_member_record_deviation"', 'on_timeout = "retry"'),
        ('before = "migrate"', 'before = "teatime"'),
        (
            'gates = ["migrate", "heads", "live", "ready"]',
            'gates = ["migrate", "migrate"]',
        ),
        ('gates = ["migrate", "heads", "live", "ready"]', 'gates = ["unheard_of"]'),
        ('host = "same"', 'host = "Bad Host"'),
        ('runbook = "docs/rehearsal.md"', 'runbook = "/etc/passwd"'),
        ("max = 3600\n", ""),
        ('pattern = "^[A-Za-z0-9.-]+(,[A-Za-z0-9.-]+)*$"', 'pattern = "(unclosed"'),
        ('spec = "deploy/product.toml"', 'spec = "deploy/companion/product.toml"'),
    ],
)
def test_descriptor_shape_refusals(mutation: tuple[str, str]) -> None:
    assert mutation[0] in _ERP_SHAPED, mutation[0]
    with pytest.raises(DeployUnitError):
        parse_deploy_unit(_ERP_SHAPED.replace(*mutation))


def test_a_companion_descriptor_names_the_product_toml_beside_it() -> None:
    text = (
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-integrator-companion"\n'
        'spec = "deploy/companion/product.toml"\n'
    )
    assert parse_deploy_unit(text, descriptor_path="deploy/companion/deploy-unit.toml")
    with pytest.raises(DeployUnitError, match="beside"):
        parse_deploy_unit(text)


def test_pre_staged_bindings_may_reuse_legacy_names_but_active_ones_may_not() -> None:
    assert parse_deploy_unit(_ERP_SHAPED).legacy_env_file is not None
    active = _ERP_SHAPED.replace('state = "pre_staged"\nkind = "key"', 'kind = "key"')
    with pytest.raises(DeployUnitError, match="collide"):
        parse_deploy_unit(active)
