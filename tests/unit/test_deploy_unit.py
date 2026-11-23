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
    canonical_job_render,
    canonical_render,
    params_env_digest,
    parse_deploy_unit,
    parse_secret_ref,
    scoped_param_names,
    validate_param_value,
    validate_params,
)

_DESCRIPTOR = """
schema = "dotmac.deploy_unit/1"
product = "erp_v2"
spec = "deploy/product.toml"
secrets_namespace = "erp"

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


def test_params_env_digest_is_sensitive_to_values_and_image() -> None:
    """Any change to a value, or to the planned image, moves the digest.

    That the PLAN binds this digest, and that Control derives it, is proved in
    `test_deploy_unit_state.py::test_plan_binds_params_env_digest`.
    """
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
secrets_namespace = "erp"

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
    unit = parse_deploy_unit(_ERP_SHAPED, legacy_allowed=True)
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
    unit = parse_deploy_unit(_ERP_SHAPED, legacy_allowed=True)
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
        parse_deploy_unit(_ERP_SHAPED.replace(*mutation), legacy_allowed=True)


def test_a_companion_descriptor_names_the_product_toml_beside_it() -> None:
    text = (
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-integrator-companion"\n'
        'spec = "deploy/companion/product.toml"\n'
        'secrets_namespace = "erp-integrator"\n'
    )
    assert parse_deploy_unit(text, descriptor_path="deploy/companion/deploy-unit.toml")
    with pytest.raises(DeployUnitError, match="beside"):
        parse_deploy_unit(text)


def test_pre_staged_bindings_may_reuse_legacy_names_but_active_ones_may_not() -> None:
    assert (
        parse_deploy_unit(_ERP_SHAPED, legacy_allowed=True).legacy_env_file is not None
    )
    active = _ERP_SHAPED.replace('state = "pre_staged"\nkind = "key"', 'kind = "key"')
    with pytest.raises(DeployUnitError, match="collide"):
        parse_deploy_unit(active, legacy_allowed=True)


def test_params_render_golden_bytes() -> None:
    """Fixed bytes and a fixed digest, independent of the production function.

    APP_IMAGE sorts with the other lines (bytewise), the file is LF-terminated
    and has no trailing blank line.
    """
    unit = parse_deploy_unit(_ERP_SHAPED, legacy_allowed=True)
    image = "127.0.0.1:5000/team/app@sha256:" + "b" * 64
    render = canonical_render(
        unit,
        {"trusted_hosts": "erp.example.test"},
        app_image=image,
        environment="production",
    )
    assert render == (
        b"APP_IMAGE=127.0.0.1:5000/team/app@sha256:"
        + b"b" * 64
        + b"\nHOLD_TIMEOUT_SECONDS=1800\nPORT_MODE=mirror\n"
        b"SEED_ON_STARTUP=false\nTRUSTED_HOSTS=erp.example.test\n"
    )
    assert params_env_digest(render) == (
        "sha256:00464f3d19bf85ad61c33e5fd1e0472245273600c22a15b5a86fcb9f02804921"
    )


def test_a_role_has_one_mode_and_roles_are_derived_sorted() -> None:
    """R3: the agent mints one secret_id per role, so a role has one answer."""
    text = (
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-erp-v2"\n'
        'spec = "deploy/product.toml"\n'
        'secrets_namespace = "erp"\n'
        '[[bindings]]\nname = "B_KEY"\nkind = "key"\nroles = ["migrate"]\n'
        'writer = "ceremony"\nrotation = "copy_only"\nsingle_use = true\n'
        '[[bindings]]\nname = "A_KEY"\nkind = "key"\nroles = ["app"]\n'
        'writer = "ceremony"\nrotation = "copy_only"\n'
        '[[bindings]]\nname = "C_KEY"\nstate = "pre_staged"\nkind = "key"\n'
        'roles = ["backup"]\nwriter = "ceremony"\nrotation = "copy_only"\n'
    )
    unit = parse_deploy_unit(text)
    # Only ACTIVE bindings contribute roles; the result is sorted.
    assert unit.role_bindings() == (("app", False), ("migrate", True))
    mixed = text.replace(
        'roles = ["app"]\nwriter = "ceremony"\nrotation = "copy_only"\n',
        'roles = ["migrate"]\nwriter = "ceremony"\nrotation = "copy_only"\n',
        1,
    )
    # A role has ONE secret_id: its mode is the STRICTER of its bindings
    # (single-use if ANY binding in the role is single-use).
    assert parse_deploy_unit(mixed).role_bindings() == (("migrate", True),)
    bad_role = text.replace('roles = ["app"]', 'roles = ["App"]', 1)
    with pytest.raises(DeployUnitError, match="lowercase segment"):
        parse_deploy_unit(bad_role)


def test_secrets_namespace_is_required_and_a_lowercase_segment() -> None:
    """V-1: the `<product>` segment of the OpenBao layout is a descriptor field."""
    text = (
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-erp-v2"\n'
        'spec = "deploy/product.toml"\n'
    )
    with pytest.raises(DeployUnitError, match="secrets_namespace is required"):
        parse_deploy_unit(text)
    for bad in ("Erp", "erp app", "erp/x", ""):
        with pytest.raises(DeployUnitError, match="secrets_namespace"):
            parse_deploy_unit(text + f'secrets_namespace = "{bad}"\n')
    unit = parse_deploy_unit(text + 'secrets_namespace = "erp-integrator"\n')
    assert unit.secrets_namespace == "erp-integrator"
    # It is NOT the product code: the two are independent facts.
    assert unit.product == "dotmac-erp-v2"


# ── Import-only OpenBao: job roles, job-scoped params ───────────────────────

_IMPORT = """
schema = "dotmac.deploy_unit/1"
product = "dotmac-erp-v2"
spec = "deploy/product.toml"
secrets_namespace = "erp"

[params.workers]
type = "int"
material = "WORKERS"
default = 2

[params.import_approved]
type = "bool"
material = "ERP_IMPORT_APPROVED"
default = false
jobs = ["import"]

[params.import_payable]
type = "string"
material = "ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF"
pattern = "^[A-Za-z0-9._:-]+$"
max_length = 64
jobs = ["import"]

[[bindings]]
name = "MIGRATION_DATABASE_URL"
kind = "pg_login_dsn"
roles = ["migrate", "import"]
writer = "ceremony"
rotation = "copy_only"
single_use = true

[[bindings]]
name = "LEGACY_DATABASE_URL"
kind = "pg_login_dsn"
roles = ["import"]
writer = "ceremony"
rotation = "copy_only"
single_use = false

[[jobs]]
name = "import"
role = "import"
command = ["python", "-m", "erp_v2.importer", "execute"]
trigger = "operator"
materials = [
  "MIGRATION_DATABASE_URL",
  "LEGACY_DATABASE_URL",
  "ERP_IMPORT_APPROVED",
  "ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF",
]
runbook = "docs/rehearsal.md"
"""


def test_a_job_declares_its_role_and_params_are_scoped_to_jobs() -> None:
    unit = parse_deploy_unit(_IMPORT)
    job = unit.jobs[0]
    assert (job.name, job.role) == ("import", "import")
    assert unit.params["import_approved"].jobs == ("import",)
    assert unit.params["workers"].jobs == ()
    assert unit.job_roles() == frozenset({"import"})
    # The job role is minted for the job only: the serving deploy has `migrate`.
    assert unit.role_bindings() == (("import", True), ("migrate", True))
    assert unit.deploy_role_bindings() == (("migrate", True),)
    assert unit.job_role_single_use(job) is True


def test_a_binding_with_several_roles_gets_its_own_ref_per_role() -> None:
    unit = parse_deploy_unit(_IMPORT)
    refs = unit.secret_refs("prod")
    assert refs[("migrate", "MIGRATION_DATABASE_URL")] == (
        "bao://prod/erp/kv/migrate/migration_database_url"
    )
    assert refs[("import", "MIGRATION_DATABASE_URL")] == (
        "bao://prod/erp/kv/import/migration_database_url"
    )
    assert refs[("import", "LEGACY_DATABASE_URL")] == (
        "bao://prod/erp/kv/import/legacy_database_url"
    )
    assert len(refs) == 3


def test_scoped_params_reach_only_their_job_never_the_app_render() -> None:
    unit = parse_deploy_unit(_IMPORT)
    values = {"import_approved": "true", "import_payable": "acct.net-payable"}
    image = "127.0.0.1:5000/team/app@sha256:" + "1" * 64
    app = canonical_render(unit, values, app_image=image, environment="production")
    assert app == f"APP_IMAGE={image}\nWORKERS=2\n".encode()
    assert b"ERP_IMPORT" not in app
    assert b"PAYABLE" not in app
    job = canonical_job_render(
        unit, values, job_name="import", environment="production"
    )
    assert job == (
        b"ERP_IMPORT_APPROVED=true\n"
        b"ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF=acct.net-payable\n"
    )
    assert scoped_param_names(unit, "import") == ("import_approved", "import_payable")
    # The scope changes the app digest: unscoped, the same param would be in it.
    unscoped = _IMPORT.replace('jobs = ["import"]\n', "")
    flat = parse_deploy_unit(unscoped)
    assert params_env_digest(
        canonical_render(flat, values, app_image=image, environment="production")
    ) != params_env_digest(app)


def test_job_credentials_are_never_legacy_names_or_app_materials() -> None:
    legacy = _IMPORT + (
        '\n[legacy_env_file]\nnames = ["MIGRATION_DATABASE_URL"]\n'
        'path_param = "legacy_path"\n[params.legacy_path]\ntype = "path"\n'
    )
    # Legacy table must come before tables it does not belong to in TOML order;
    # the refusal is the same whichever name is listed.
    for name in ("MIGRATION_DATABASE_URL", "LEGACY_DATABASE_URL"):
        text = legacy.replace(
            'names = ["MIGRATION_DATABASE_URL"]', f'names = ["{name}"]'
        )
        with pytest.raises(DeployUnitError, match="never include a dispatched job"):
            parse_deploy_unit(text, legacy_allowed=True)
    # An UNSCOPED param may not carry one of them as an app material...
    app_material = _IMPORT.replace(
        '[params.workers]\ntype = "int"\nmaterial = "WORKERS"',
        '[params.workers]\ntype = "string"\nmaterial = "LEGACY_DATABASE_URL"',
    )
    with pytest.raises(DeployUnitError, match="may not be an app material"):
        parse_deploy_unit(app_material)
    # ...but a param scoped to the job may (it is the job's, not the app's).
    scoped = _IMPORT.replace(
        "[params.import_payable]",
        '[params.dsn_path]\ntype = "path"\nmaterial = "MIGRATION_DATABASE_URL"\n'
        'jobs = ["import"]\n\n[params.import_payable]',
    )
    assert parse_deploy_unit(scoped).params["dsn_path"].jobs == ("import",)


def test_job_scope_and_role_references_must_exist() -> None:
    with pytest.raises(DeployUnitError, match="unknown jobs"):
        parse_deploy_unit(_IMPORT.replace('jobs = ["import"]', 'jobs = ["nope"]', 1))
    with pytest.raises(DeployUnitError, match="no binding has"):
        parse_deploy_unit(_IMPORT.replace('role = "import"', 'role = "ghost"', 1))
    with pytest.raises(DeployUnitError, match="lowercase segment"):
        parse_deploy_unit(_IMPORT.replace('role = "import"', 'role = "Import"', 1))
    with pytest.raises(DeployUnitError, match="needs a material"):
        parse_deploy_unit(
            _IMPORT.replace('material = "ERP_IMPORT_APPROVED"\n', "", 1).replace(
                '"ERP_IMPORT_APPROVED",\n', ""
            )
        )
