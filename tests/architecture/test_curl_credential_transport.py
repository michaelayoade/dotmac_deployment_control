"""A credential reaches curl through a 0600 file, never through argv.

`curl -u "ci-reader:${TOKEN}"` and `curl -H "Authorization: token ${TOKEN}"`
both place the credential in the process's ARGUMENT VECTOR, where anything that
can read the process table sees it while the request is in flight and anything
that captures a command line into a log keeps it. `docs/CONTROL_EXCEPTIONS.md`
recorded that as an accepted exception; Michael withdrew the acceptance, and
`scripts/curl_with_credential.sh` is the replacement.

## What each layer here establishes, and what it does NOT

Three layers, deliberately unequal, because it matters which one is load-bearing
for which claim.

1. **Process-table observation** (`/proc`, real curl, real socket). While a real
   request is in flight, every readable `/proc/<pid>/cmdline` on the host is
   scanned for the credential. This is the only layer that measures the actual
   property — the running process's argv — and it also proves the credential
   DID reach the server, so "absent from argv" cannot be satisfied by a request
   that quietly never authenticated. It does not observe the workflows: it
   observes the helper they call.

2. **Wrapper interception** (a `curl` shim on `PATH`). Records curl's argv, the
   config file's path, its mode and its contents at the moment curl was
   invoked. Weaker than (1) — it is a stand-in for curl, not curl — but it can
   assert things (1) cannot: the file's mode as curl saw it, cleanup after a
   FAILING curl, cleanup after a cancellation signal, and behaviour under
   `bash -x`.

3. **Static analysis** of the workflows and `scripts/*.sh`. This proves the
   checked-in SOURCE contains no argv-placing form. It proves NOTHING about any
   running process, and it is here only as a ratchet so the defect cannot come
   back by an edit that passes review. Do not read a green (3) as evidence
   about argv; that is (1)'s job.

## Every detector below has a sensitivity proof

The repository is clean, so a check over the current tree passes for the wrong
reason unless the offending shape is reconstructed and each detector is watched
to fire on it (`AGENTS.md` rule 23 / ADR-0018 failure mode 1: empty scope). So
each assertion here is paired with a planted credential-bearing curl, a planted
trailing `rm`, a planted 0644 config, a planted un-suppressed `set -x`, a
planted workspace-local config, or a planted workflow mutation — and the pair
asserts the detector reports the violation.

## What the sensitivity proofs turned up about `curl -u` itself

The first version of the process-table proof reconstructed `curl -u` and FAILED:
the scan found nothing. curl built with writable argv **blanks its own `-u`
argument in place** after parsing it, so a `ps` during the request shows
`curl -sS -u<spaces> http://...` while `Authorization: Basic ...` still goes on
the wire.

The exception record was therefore wrong about which sites were worse. The two
`-u` sites it named were the LESS exposed pair; the five
`-H "Authorization: token ${TOKEN}"` sites it did not name are visible in the
process table for the entire request, because curl scrubs `--user` and not a
header. `-u` still leaks through `execve` (recorded before curl can scrub, so
auditd and any exec tracer keep it) and through `bash -x`, and
`test_curl_scrubs_its_own_dash_u_value_but_not_the_wire_or_the_trace` holds that
finding as an assertion rather than as prose.

## No real credential is used anywhere

Every secret in this file is a synthetic sentinel generated per test
(`uuid4().hex`). The publish and read credentials live in OpenBao and are never
read, printed, or compared against here — the assertions are non-membership of
a value this file created, which is why nothing has to echo a secret to test
for it.
"""

from __future__ import annotations

import base64
import itertools
import os
import re
import signal
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from types import TracebackType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "scripts" / "curl_with_credential.sh"
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOW_DIR / "ci.yml"
RELEASE_WORKFLOW = WORKFLOW_DIR / "release.yml"
VERIFY_WORKFLOW = WORKFLOW_DIR / "verify-release.yml"
WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml"))
SHELL_SCRIPTS = sorted((REPO_ROOT / "scripts").glob("*.sh"))

# The names a credential travels under in this repository. A curl command line
# mentioning any of them is putting a secret in argv.
CREDENTIAL_REFERENCES = (
    "FORGEJO_PUBLISH_TOKEN",
    "FORGEJO_READ_TOKEN",
    "CURL_CREDENTIAL_SECRET",
    "${TOKEN}",
    "$TOKEN",
    "secrets.",
)

_CURL_INVOCATION = re.compile(r"(?:^|[\s(`;&|=])curl\b")
_USER_FLAG = re.compile(r"(?:^|\s)(?:-u|--user)(?:\s|=)")

PROBE_TIMEOUT = 60.0


def _sentinel() -> str:
    """A synthetic credential. Never a real one, and never printed."""
    return "argvcanary" + uuid.uuid4().hex


# ── layer 1: the process table, with a real curl and a real socket ──────────


def _procfs_or_skip() -> None:
    """`/proc` is Linux-only.

    A plain `skipif` would be the 'absent reads as success' shape this
    repository keeps finding: the STRONGEST test in this file would silently do
    nothing the day the runner image changed. In CI its absence is a failure.
    """
    if Path("/proc").is_dir():
        return
    if os.getenv("CI"):
        pytest.fail(
            "/proc is not readable, so the process-table observation — the only "
            "check here that measures argv on a running process — cannot run. "
            "The CI lane must be Linux."
        )
    pytest.skip("/proc is Linux-only; the argv observation runs in CI")


def process_table_hits(needle: str) -> list[str]:
    """Every readable process command line containing `needle`."""
    hits: list[str] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue  # gone, or not ours to read
        text = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        if needle in text:
            hits.append(f"pid {entry.name}: {text}")
    return hits


def live_curl_config_paths() -> list[str]:
    """The `--config` argument of every live curl process."""
    paths: list[str] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv = [part for part in raw.split(b"\x00") if part]
        if not argv or not argv[0].decode("utf-8", "replace").endswith("curl"):
            continue
        decoded = [part.decode("utf-8", "replace") for part in argv]
        for flag, value in itertools.pairwise(decoded):
            if flag in ("--config", "-K"):
                paths.append(value)
    return paths


class Probe:
    """A localhost endpoint that accepts one request and HOLDS it open.

    Holding it is the point: the credential must be observed in (or absent
    from) the process table WHILE curl is running, and a request that completes
    instantly leaves nothing to observe.
    """

    def __init__(self) -> None:
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port: int = self._sock.getsockname()[1]
        self.request: bytes = b""
        self.in_flight = threading.Event()
        self.release = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/probe"

    def __enter__(self) -> Probe:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release.set()
        self._thread.join(timeout=PROBE_TIMEOUT)
        self._sock.close()

    def _serve(self) -> None:
        self._sock.settimeout(PROBE_TIMEOUT)
        try:
            conn, _ = self._sock.accept()
        except OSError:
            self.in_flight.set()
            return
        with conn:
            conn.settimeout(PROBE_TIMEOUT)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            self.request = data
            self.in_flight.set()
            self.release.wait(timeout=PROBE_TIMEOUT)
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
            except OSError:
                pass


def _helper_env(tmp_path: Path, secret: str, **extra: str) -> dict[str, str]:
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(exist_ok=True)
    env = dict(os.environ)
    env.update(
        {
            "RUNNER_TEMP": str(runner_temp),
            "CURL_CREDENTIAL_SECRET": secret,
            # The probe is a loopback socket in this process. An inherited
            # proxy variable would send curl somewhere else entirely and the
            # request would never arrive, which reads as "the helper is
            # broken" rather than as the environment problem it is.
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
    )
    env.update(extra)
    return env


def runner_temp_of(tmp_path: Path) -> Path:
    return tmp_path / "runner-temp"


def test_the_credential_is_absent_from_the_process_table_in_flight(
    tmp_path: Path,
) -> None:
    """THE MEASUREMENT. Real curl, real request, argv read from `/proc`.

    ESTABLISHES: while the helper's curl is talking to a server, the credential
    appears in no process's command line on this host, and the server
    nonetheless received it — so the absence is not the absence of
    authentication.

    DOES NOT ESTABLISH: anything about the workflows. They are checked
    statically, further down, and that check says nothing about argv.
    """
    _procfs_or_skip()
    secret = _sentinel()
    with Probe() as probe:
        proc = subprocess.Popen(  # noqa: S603
            ["bash", str(HELPER), "token", "-sS", probe.url],  # noqa: S607
            cwd=tmp_path,
            env=_helper_env(tmp_path, secret),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert probe.in_flight.wait(
                timeout=PROBE_TIMEOUT
            ), "curl never reached the probe"

            # THE POSITIVE HALF, asserted before the negative one so a broken
            # request can never be mistaken for a clean argv.
            request = probe.request.decode("utf-8", "replace")
            assert f"Authorization: token {secret}" in request, (
                "the credential did not reach the server, so this test would "
                "prove nothing by finding it absent from argv"
            )
            head = request.splitlines()[0] if request else ""
            assert secret not in head, f"the credential is in the request line: {head}"

            hits = process_table_hits(secret)
            # Scoped to THIS run's RUNNER_TEMP. An unrelated curl elsewhere on
            # the runner is not this test's subject, and letting one in would
            # make the mode assertion below fail for a reason nobody could act
            # on.
            mine = str(runner_temp_of(tmp_path))
            configs = [
                path for path in live_curl_config_paths() if path.startswith(mine)
            ]
            modes = {path: oct(Path(path).stat().st_mode & 0o777) for path in configs}
        finally:
            probe.release.set()
            stdout, stderr = proc.communicate(timeout=PROBE_TIMEOUT)

    assert not hits, "the credential is in a live process's argv:\n" + "\n".join(hits)
    assert configs, "no live curl was pointed at a --config file"
    assert set(modes.values()) == {"0o600"}, modes
    assert proc.returncode == 0, f"helper failed: {stderr}"
    assert secret not in stdout and secret not in stderr
    # Cleanup, on the real path a real curl really read.
    for path in configs:
        assert not Path(path).exists(), f"the config file outlived the request: {path}"


def test_basic_mode_sends_what_dash_u_sent(tmp_path: Path) -> None:
    """AUTHENTICATION SUCCEEDS, and the wire form is unchanged.

    The two replaced sites used `-u "ci-reader:${TOKEN}"`, which is
    `Authorization: Basic base64("ci-reader:<token>")`. This asserts the config
    file produces exactly that, so the change is a transport change and not an
    authentication change.
    """
    _procfs_or_skip()
    secret = _sentinel()
    expected = base64.b64encode(f"ci-reader:{secret}".encode()).decode()
    with Probe() as probe:
        proc = subprocess.Popen(  # noqa: S603
            ["bash", str(HELPER), "basic", "-sS", probe.url],  # noqa: S607
            cwd=tmp_path,
            env=_helper_env(tmp_path, secret, CURL_CREDENTIAL_USER="ci-reader"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert probe.in_flight.wait(timeout=PROBE_TIMEOUT)
            request = probe.request.decode("utf-8", "replace")
            hits = process_table_hits(secret)
        finally:
            probe.release.set()
            proc.communicate(timeout=PROBE_TIMEOUT)

    assert f"Authorization: Basic {expected}" in request, request.splitlines()[:6]
    assert not hits, hits


def live_curl_argvs() -> list[list[str]]:
    """Every live curl process's argument vector."""
    argvs: list[list[str]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv = [part.decode("utf-8", "replace") for part in raw.split(b"\x00") if part]
        if argv and argv[0].endswith("curl"):
            argvs.append(argv)
    return argvs


LEAKY_HEADER = """#!/usr/bin/env bash
# Five of the seven replaced sites had this shape. curl does NOT scrub a header
# argument, so it stays in the process table for the whole request.
set -euo pipefail
curl -sS -H "Authorization: token ${CURL_CREDENTIAL_SECRET}" "$@"
"""

LEAKY_DASH_U = """#!/usr/bin/env bash
# The other two. See the test below for why this one behaves differently.
set -euo pipefail
curl -sS -u "ci-reader:${CURL_CREDENTIAL_SECRET}" "$@"
"""


def _run_leaky(
    tmp_path: Path, body: str, secret: str, *, xtrace: bool = False
) -> tuple[list[str], list[list[str]], str, str]:
    """Run a reconstructed leaky invocation and observe it mid-request."""
    leaky = tmp_path / "leaky.sh"
    leaky.write_text(body, encoding="utf-8")
    with Probe() as probe:
        command = ["bash"] + (["-x"] if xtrace else []) + [str(leaky), probe.url]
        proc = subprocess.Popen(  # noqa: S603
            command,
            cwd=tmp_path,
            env=_helper_env(tmp_path, secret),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert probe.in_flight.wait(timeout=PROBE_TIMEOUT), "curl never arrived"
            hits = process_table_hits(secret)
            argvs = live_curl_argvs()
            request = probe.request.decode("utf-8", "replace")
        finally:
            probe.release.set()
            _, stderr = proc.communicate(timeout=PROBE_TIMEOUT)
    return hits, argvs, request, stderr


def test_the_process_table_scan_catches_a_credential_bearing_curl(
    tmp_path: Path,
) -> None:
    """SENSITIVITY for the measurement above.

    Without this the argv assertion would pass on a repository where curl was
    never called at all. The `-H "Authorization: ..."` form is reconstructed —
    five of the seven sites this change replaced used it — and the same scan
    must report it.
    """
    _procfs_or_skip()
    secret = _sentinel()
    hits, _, request, _ = _run_leaky(tmp_path, LEAKY_HEADER, secret)
    assert f"Authorization: token {secret}" in request
    assert hits, (
        "the process-table scan did not see a credential passed as `curl -H`. "
        "The detector is blind, and every clean result it reports is worthless."
    )


def test_curl_scrubs_its_own_dash_u_value_but_not_the_wire_or_the_trace(
    tmp_path: Path,
) -> None:
    """A CORRECTION TO THE EXCEPTION RECORD, kept as an executable observation.

    The record said `curl -u` "places the credential in the process arguments,
    where a process listing can read it", and named those two sites as the
    defect. That is only half right. curl built with writable argv **blanks its
    own `-u` argument in place** once it has parsed it — a `ps` taken during the
    request shows `curl -sS -u<spaces> http://...` — so the two sites the record
    named were the LESS exposed pair, and the five `-H` sites it did not name
    were the ones visible for the whole request.

    That does not make `-u` safe, and this asserts the two channels that remain:

    - the credential still goes **on the wire**, so the form was authenticating
      and its scrubbing is not a refusal;
    - `bash -x` prints the **expanded** command, and the trace is not scrubbed —
      the leak arrives through the log instead of the process table.

    A third channel is not observable from here and is stated rather than
    asserted: `execve` records argv BEFORE curl can scrub it, so auditd, eBPF
    and any exec-tracing agent capture the credential regardless.

    The `-u` flag itself is asserted present, not its value: whether the value
    survives depends on `HAVE_WRITABLE_ARGV` in the local build, and a test that
    demanded one answer would be asserting a property of the runner image.
    """
    _procfs_or_skip()
    secret = _sentinel()
    expected = base64.b64encode(f"ci-reader:{secret}".encode()).decode()
    _, argvs, request, stderr = _run_leaky(tmp_path, LEAKY_DASH_U, secret, xtrace=True)
    assert f"Authorization: Basic {expected}" in request, (
        "the reconstructed `-u` invocation did not authenticate, so this "
        "observation is about nothing"
    )
    assert any("-u" in argv for argv in argvs), argvs
    assert secret in stderr, (
        "`bash -x` did not print the credential for a `curl -u` command. That "
        "is the channel `-u` leaks through even where curl scrubs its argv, and "
        "it is why the helper suppresses xtrace across its own credential write."
    )


# ── layer 2: a curl shim on PATH ────────────────────────────────────────────

FAKE_CURL = """#!/bin/sh
# Stands in for curl. Records its own argv, and the config file it was pointed
# at — path, mode and contents — at the moment it was invoked, which is the
# only moment that matters: the helper deletes the file immediately afterwards.
: > "$FAKE_CURL_ARGV"
for a in "$@"; do printf '%s\\n' "$a" >> "$FAKE_CURL_ARGV"; done
prev=""
for a in "$@"; do
  case "$prev" in
    --config|-K)
      printf '%s\\n' "$a" > "$FAKE_CURL_CFGPATH"
      cp "$a" "$FAKE_CURL_CFGCOPY"
      stat -c '%a' "$a" > "$FAKE_CURL_CFGMODE" 2>/dev/null \\
        || stat -f '%Lp' "$a" > "$FAKE_CURL_CFGMODE"
      ;;
  esac
  prev="$a"
done
if [ -n "${FAKE_CURL_READY:-}" ]; then : > "$FAKE_CURL_READY"; fi
if [ -n "${FAKE_CURL_SLEEP:-}" ]; then sleep "$FAKE_CURL_SLEEP"; fi
exit "${FAKE_CURL_EXIT:-0}"
"""


class Shim:
    """A recording `curl` earlier on PATH than the real one."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path / "shim"
        (self.root / "bin").mkdir(parents=True, exist_ok=True)
        self.binary = self.root / "bin" / "curl"
        self.binary.write_text(FAKE_CURL, encoding="utf-8")
        self.binary.chmod(0o755)
        self.argv_log = self.root / "argv"
        self.cfg_path = self.root / "cfgpath"
        self.cfg_copy = self.root / "cfgcopy"
        self.cfg_mode = self.root / "cfgmode"
        self.ready = self.root / "ready"

    def env(self, base: dict[str, str], **extra: str) -> dict[str, str]:
        env = dict(base)
        env["PATH"] = f"{self.root / 'bin'}{os.pathsep}{env.get('PATH', '')}"
        env.update(
            {
                "FAKE_CURL_ARGV": str(self.argv_log),
                "FAKE_CURL_CFGPATH": str(self.cfg_path),
                "FAKE_CURL_CFGCOPY": str(self.cfg_copy),
                "FAKE_CURL_CFGMODE": str(self.cfg_mode),
            }
        )
        env.update(extra)
        return env

    @property
    def argv(self) -> list[str]:
        return self.argv_log.read_text(encoding="utf-8").splitlines()

    @property
    def observed_config(self) -> Path:
        return Path(self.cfg_path.read_text(encoding="utf-8").strip())


def _run_with_shim(
    cwd: Path,
    shim: Shim,
    secret: str,
    args: list[str],
    *,
    mode: str = "token",
    bash_flags: tuple[str, ...] = (),
    user: str | None = None,
    script: Path | None = None,
    runner_temp_root: Path | None = None,
    **shim_env: str,
) -> subprocess.CompletedProcess[str]:
    base = _helper_env(runner_temp_root or cwd, secret)
    if user is not None:
        base["CURL_CREDENTIAL_USER"] = user
    return subprocess.run(  # noqa: S603
        ["bash", *bash_flags, str(script or HELPER), mode, *args],  # noqa: S607
        cwd=cwd,
        env=shim.env(base, **shim_env),
        capture_output=True,
        text=True,
        timeout=PROBE_TIMEOUT,
        check=False,
    )


def test_curl_receives_a_path_and_the_path_holds_the_credential(
    tmp_path: Path,
) -> None:
    """ESTABLISHES: `--config <path>` was passed, no argument contains the
    credential, and the file at that path DID contain it when curl ran — the
    positive and negative halves of the same claim.

    DOES NOT ESTABLISH: how the real curl behaves. That is layer 1.
    """
    secret = _sentinel()
    shim = Shim(tmp_path)
    result = _run_with_shim(tmp_path, shim, secret, ["-sS", "https://example.invalid/"])
    assert result.returncode == 0, result.stderr

    argv = shim.argv
    assert "--config" in argv, argv
    assert argv[argv.index("--config") + 1] == str(shim.observed_config)
    offenders = [arg for arg in argv if secret in arg]
    assert not offenders, f"the credential is in curl's argv: {offenders}"
    assert secret in shim.cfg_copy.read_text(encoding="utf-8"), (
        "the config file curl was handed did not contain the credential, so "
        "'absent from argv' here means 'absent everywhere' and proves nothing"
    )


def test_the_config_file_is_0600_when_curl_reads_it(tmp_path: Path) -> None:
    """The mode is observed AT USE, not after the fact. Creating a file
    world-readable and tightening it afterwards leaves a window, and on a shared
    runner that window is the whole vulnerability — so the assertion has to be
    made by the party that opens the file."""
    shim = Shim(tmp_path)
    _run_with_shim(tmp_path, shim, _sentinel(), ["https://example.invalid/"])
    assert shim.cfg_mode.read_text(encoding="utf-8").strip() == "600"


LOOSE_MODE_HELPER = """#!/usr/bin/env bash
# A helper that writes the credential first and tightens the mode afterwards —
# the window this repository must not ship.
set -euo pipefail
shift || true
dir="$(mktemp -d "${RUNNER_TEMP}/loose.XXXXXXXX")"
trap 'rm -rf -- "${dir}"' EXIT HUP INT TERM
cfg="${dir}/curl.conf"
umask 022
printf 'header = "Authorization: token %s"\\n' "${CURL_CREDENTIAL_SECRET}" > "${cfg}"
curl --config "${cfg}" "$@"
"""


def test_the_mode_check_catches_a_world_readable_config(tmp_path: Path) -> None:
    """SENSITIVITY for the mode assertion."""
    shim = Shim(tmp_path)
    loose = tmp_path / "loose.sh"
    loose.write_text(LOOSE_MODE_HELPER, encoding="utf-8")
    _run_with_shim(
        tmp_path,
        shim,
        _sentinel(),
        ["https://example.invalid/"],
        script=loose,
    )
    assert shim.cfg_mode.read_text(encoding="utf-8").strip() != "600", (
        "a config written under umask 022 was reported as 0600; the mode "
        "detector is not reading the mode"
    )


def test_the_argv_recorder_catches_a_credential_when_one_is_passed(
    tmp_path: Path,
) -> None:
    """SENSITIVITY for the shim's argv assertion: pass the sentinel to the shim
    directly and require the recorder to show it."""
    secret = _sentinel()
    shim = Shim(tmp_path)
    subprocess.run(  # noqa: S603
        [str(shim.binary), "-u", f"ci-reader:{secret}", "https://example.invalid/"],
        cwd=tmp_path,
        env=shim.env(_helper_env(tmp_path, secret)),
        capture_output=True,
        text=True,
        timeout=PROBE_TIMEOUT,
        check=False,
    )
    assert [arg for arg in shim.argv if secret in arg], (
        "the argv recorder did not see a credential handed straight to it; "
        "every clean argv it reports is meaningless"
    )


def test_the_config_lives_outside_the_workspace(tmp_path: Path) -> None:
    """ARTIFACTS. `actions/upload-artifact` takes workspace-relative paths, so a
    credential file inside the checkout is a credential file one glob away from
    being uploaded. The helper writes under RUNNER_TEMP instead."""
    shim = Shim(tmp_path)
    _run_with_shim(tmp_path, shim, _sentinel(), ["https://example.invalid/"])
    observed = shim.observed_config.resolve()
    assert runner_temp_of(tmp_path).resolve() in observed.parents, observed


def _workspace_files(workspace: Path) -> list[Path]:
    return [path for path in workspace.rglob("*") if path.is_file()]


def test_the_helper_writes_nothing_into_the_workspace(tmp_path: Path) -> None:
    """ARTIFACTS, the other direction.

    `actions/upload-artifact` globs the workspace, so the strongest statement
    is not "the credential is absent from what we upload" but "the helper
    creates nothing in the workspace at all" — nothing to glob, nothing to
    forget to exclude. Run with the checkout as the working directory, exactly
    as a workflow step runs it.
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shim = Shim(tmp_path)
    _run_with_shim(
        workspace,
        shim,
        _sentinel(),
        ["https://example.invalid/"],
        runner_temp_root=tmp_path,
    )
    assert _workspace_files(workspace) == []


WORKSPACE_CONFIG_HELPER = """#!/usr/bin/env bash
# Writes the config into the working directory — where an artifact upload can
# reach it.
set -euo pipefail
shift || true
umask 077
printf 'header = "Authorization: token %s"\\n' "${CURL_CREDENTIAL_SECRET}" > ./curl.conf
curl --config ./curl.conf "$@"
"""


def test_the_workspace_check_catches_a_config_written_there(tmp_path: Path) -> None:
    """SENSITIVITY for the artifact claim: a helper that writes into the
    workspace must be seen, or "the workspace is clean" is a statement about a
    directory nobody looked in."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    secret = _sentinel()
    shim = Shim(tmp_path)
    inside = workspace / "inside.sh"
    inside.write_text(WORKSPACE_CONFIG_HELPER, encoding="utf-8")
    _run_with_shim(
        workspace,
        shim,
        secret,
        ["https://example.invalid/"],
        script=inside,
        runner_temp_root=tmp_path,
        FAKE_CURL_EXIT="7",
    )
    left = [path for path in _workspace_files(workspace) if path != inside]
    assert left, "a config file written into the workspace was not noticed"
    assert any(
        secret in path.read_text(encoding="utf-8", errors="replace") for path in left
    )


# ── cleanup, and the failing path is the one that matters ───────────────────


def test_cleanup_on_success(tmp_path: Path) -> None:
    shim = Shim(tmp_path)
    result = _run_with_shim(tmp_path, shim, _sentinel(), ["https://example.invalid/"])
    assert result.returncode == 0
    assert not shim.observed_config.exists()
    assert list(runner_temp_of(tmp_path).iterdir()) == []


def test_cleanup_when_curl_fails(tmp_path: Path) -> None:
    """THE FAILING PATH, which is the common one.

    A `rm` on the step's last line runs only when every line before it
    succeeded, and `set -e` makes not-succeeding routine. The exit status must
    also survive: a cleanup that swallowed curl's failure would turn a broken
    release check green.
    """
    shim = Shim(tmp_path)
    result = _run_with_shim(
        tmp_path,
        shim,
        _sentinel(),
        ["https://example.invalid/"],
        FAKE_CURL_EXIT="7",
    )
    assert result.returncode == 7, result
    assert not shim.observed_config.exists()
    assert list(runner_temp_of(tmp_path).iterdir()) == []


def test_cleanup_when_curl_cannot_be_executed(tmp_path: Path) -> None:
    """A failure at the LAST line, with the config already written.

    The credential file exists, curl exists on PATH, and executing it fails —
    so the trap is the only thing standing between the failure and a secret
    left on the runner. A broken interpreter line rather than a missing binary
    on purpose: emptying PATH would break `mktemp` too and the helper would
    fail before it ever wrote anything, which passes for the wrong reason.
    """
    secret = _sentinel()
    shim = Shim(tmp_path)
    shim.binary.write_text("#!/nonexistent/interpreter\n", encoding="utf-8")
    shim.binary.chmod(0o755)
    result = _run_with_shim(tmp_path, shim, secret, ["https://example.invalid/"])
    assert result.returncode != 0, result
    assert (
        list(runner_temp_of(tmp_path).iterdir()) == []
    ), "an unexecutable curl left the config behind"


def test_cleanup_when_the_step_is_cancelled(tmp_path: Path) -> None:
    """CANCELLATION, not merely failure.

    This repository lost `0.1.0a3` to a run cancelled mid-step. Cancellation is
    a signal arriving while a command is in flight, so the trap covers HUP, INT
    and TERM and not only EXIT.
    """
    secret = _sentinel()
    shim = Shim(tmp_path)
    env = shim.env(
        _helper_env(tmp_path, secret),
        FAKE_CURL_SLEEP="30",
        FAKE_CURL_READY=str(shim.ready),
    )
    proc = subprocess.Popen(  # noqa: S603
        ["bash", str(HELPER), "token", "https://example.invalid/"],  # noqa: S607
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + PROBE_TIMEOUT
        while not shim.ready.exists() and time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        assert shim.ready.exists(), "the stand-in curl never started"
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.communicate(timeout=PROBE_TIMEOUT)
    finally:
        if proc.poll() is None:  # pragma: no cover - only on a hung child
            proc.kill()
            proc.communicate()

    assert (
        list(runner_temp_of(tmp_path).iterdir()) == []
    ), "a cancelled step left the credential file on the runner"


TRAILING_RM_HELPER = """#!/usr/bin/env bash
# Cleanup on the last line — the shape the trap replaced.
set -euo pipefail
shift || true
dir="$(mktemp -d "${RUNNER_TEMP}/trailing.XXXXXXXX")"
cfg="${dir}/curl.conf"
umask 077
printf 'header = "Authorization: token %s"\\n' "${CURL_CREDENTIAL_SECRET}" > "${cfg}"
curl --config "${cfg}" "$@"
rm -rf -- "${dir}"
"""


def test_the_cleanup_check_catches_a_trailing_rm(tmp_path: Path) -> None:
    """SENSITIVITY for every cleanup assertion above.

    A trailing `rm` passes the SUCCESS case, which is exactly why proving
    cleanup only on success proves the half that does not matter. Under a
    failing curl it leaks, and the detector must say so.
    """
    shim = Shim(tmp_path)
    trailing = tmp_path / "trailing.sh"
    trailing.write_text(TRAILING_RM_HELPER, encoding="utf-8")
    _run_with_shim(
        tmp_path,
        shim,
        _sentinel(),
        ["https://example.invalid/"],
        script=trailing,
        FAKE_CURL_EXIT="7",
    )
    assert list(runner_temp_of(tmp_path).iterdir()) != [], (
        "a trailing `rm` skipped by a failing curl was reported as clean; the "
        "cleanup detector cannot see a leak"
    )


# ── logs ────────────────────────────────────────────────────────────────────


def test_no_credential_in_the_helper_output(tmp_path: Path) -> None:
    secret = _sentinel()
    shim = Shim(tmp_path)
    result = _run_with_shim(tmp_path, shim, secret, ["https://example.invalid/"])
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_no_credential_in_the_log_under_xtrace(tmp_path: Path) -> None:
    """`set -x` echoes the EXPANDED command, so one traced line touching the
    secret prints it into the step log. The workflow's own comment already
    named `set -x` as a leak vector for URLs; it is one for a config write too.

    The trace must still be USEFUL, or the helper could pass by disabling
    xtrace and never restoring it — so this also requires the curl invocation
    itself to appear in the trace, showing the config file's path.
    """
    secret = _sentinel()
    shim = Shim(tmp_path)
    result = _run_with_shim(
        tmp_path,
        shim,
        secret,
        ["https://example.invalid/"],
        bash_flags=("-x",),
    )
    assert result.returncode == 0, result.stderr
    assert secret not in result.stderr, "the credential was traced into the log"
    assert secret not in result.stdout
    assert "+ curl --config" in result.stderr, (
        "the trace does not show the curl invocation, so the helper may simply "
        "have turned tracing off and left it off"
    )


UNGUARDED_XTRACE_HELPER = """#!/usr/bin/env bash
# No xtrace suppression around the credential write.
set -euo pipefail
shift || true
dir="$(mktemp -d "${RUNNER_TEMP}/unguarded.XXXXXXXX")"
trap 'rm -rf -- "${dir}"' EXIT HUP INT TERM
cfg="${dir}/curl.conf"
umask 077
printf 'header = "Authorization: token %s"\\n' "${CURL_CREDENTIAL_SECRET}" > "${cfg}"
curl --config "${cfg}" "$@"
"""


def test_the_log_check_catches_an_unguarded_xtrace(tmp_path: Path) -> None:
    """SENSITIVITY for the log assertion."""
    secret = _sentinel()
    shim = Shim(tmp_path)
    unguarded = tmp_path / "unguarded.sh"
    unguarded.write_text(UNGUARDED_XTRACE_HELPER, encoding="utf-8")
    result = _run_with_shim(
        tmp_path,
        shim,
        secret,
        ["https://example.invalid/"],
        script=unguarded,
        bash_flags=("-x",),
    )
    assert secret in result.stderr, (
        "an unguarded `printf` of the credential under `bash -x` was not seen "
        "in the captured log; the log detector is blind"
    )


# ── layer 3: the static ratchet, which proves only what the source says ─────


def executable_lines(text: str) -> list[str]:
    """Lines that are not YAML/shell comments.

    The whole file below reasons about COMMANDS, and this repository's guards
    have tripped on their own explanatory prose four times. The prose stays;
    the predicate reads code.
    """
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def logical_commands(text: str) -> list[str]:
    """Backslash-continued shell lines joined into one command each."""
    commands: list[str] = []
    buffer: list[str] = []
    for line in executable_lines(text):
        stripped = line.rstrip()
        buffer.append(stripped.rstrip("\\").strip())
        if not stripped.endswith("\\"):
            commands.append(" ".join(buffer).strip())
            buffer = []
    if buffer:
        commands.append(" ".join(buffer).strip())
    return [command for command in commands if command]


def curl_commands(text: str) -> list[str]:
    """Commands that invoke curl DIRECTLY.

    `\\bcurl\\b` deliberately does not match `curl_with_credential.sh`: the
    underscore is a word character, so the helper's own name is not a curl
    invocation. `test_the_command_scan_is_not_looking_at_nothing` proves the
    matcher still finds the one real invocation that exists.
    """
    return [
        command
        for command in logical_commands(text)
        if _CURL_INVOCATION.search(command)
    ]


SCANNED = [*WORKFLOWS, *SHELL_SCRIPTS]


def test_the_command_scan_is_not_looking_at_nothing() -> None:
    """SCOPE PROOF (ADR-0018 failure mode 1).

    Every static assertion below is a non-existence claim over this scan. If
    the scan found no files, or the matcher found no curl, they would all pass
    over an empty set. So: the corpus is non-empty, and the matcher finds the
    one genuine curl invocation in the repository — the helper's.
    """
    assert len(SCANNED) >= 6, [path.name for path in SCANNED]
    helper_curl = curl_commands(HELPER.read_text(encoding="utf-8"))
    assert len(helper_curl) == 1, helper_curl
    assert "--config" in helper_curl[0], helper_curl
    assert not _USER_FLAG.search(helper_curl[0]), helper_curl


@pytest.mark.parametrize("path", SCANNED, ids=lambda p: p.name)
def test_no_curl_command_carries_a_credential_in_argv(path: Path) -> None:
    """THE RATCHET, and the honest description of it: this proves the SOURCE
    contains no argv-placing form. It proves nothing about a running process —
    the process-table observation at the top of this file is the only check
    that does."""
    offenders = []
    for command in curl_commands(path.read_text(encoding="utf-8")):
        if _USER_FLAG.search(command):
            offenders.append(f"-u/--user: {command}")
        for name in CREDENTIAL_REFERENCES:
            if name in command:
                offenders.append(f"{name}: {command}")
    assert not offenders, (
        f"{path.name} puts a credential in curl's arguments:\n" + "\n".join(offenders)
    )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_invokes_curl_directly(path: Path) -> None:
    """Authenticated HTTP in a workflow goes through the helper.

    Stronger than the rule above and for a different reason: the rule above
    catches the two forms known to leak, while this catches a THIRD form nobody
    has thought of yet by removing the place it would be written. A deliberately
    unauthenticated curl is a reasonable future need; adding it means relaxing
    this test in the same change, which is the review this is for.
    """
    offenders = curl_commands(path.read_text(encoding="utf-8"))
    assert not offenders, (
        f"{path.name} invokes curl directly:\n"
        + "\n".join(offenders)
        + "\nUse scripts/curl_with_credential.sh, which keeps the credential "
        "in a 0600 file and only its path in argv."
    )


def _mutate(text: str, old: str, new: str) -> str:
    assert text.count(old) >= 1, f"planted mutation did not apply: {old!r}"
    return text.replace(old, new, 1)


def test_a_planted_dash_u_is_caught() -> None:
    """SENSITIVITY for the static ratchet: the exact line this PR removed."""
    mutated = _mutate(
        CI_WORKFLOW.read_text(encoding="utf-8"),
        "          code=$(bash scripts/curl_with_credential.sh basic \\",
        '          code=$(curl -sS -u "ci-reader:${TOKEN}" \\',
    )
    commands = curl_commands(mutated)
    assert commands, "the mutated workflow's curl was not even seen"
    assert any(_USER_FLAG.search(command) for command in commands), commands


def test_a_planted_authorization_header_is_caught() -> None:
    """SENSITIVITY for the OTHER argv form.

    `-H "Authorization: token ${TOKEN}"` is not `-u`, and it leaks identically.
    The exception record named only the `-u` sites; five header sites had the
    same defect, and a detector that only knows `-u` would have let every one
    of them back in.
    """
    mutated = _mutate(
        RELEASE_WORKFLOW.read_text(encoding="utf-8"),
        "          login=$(bash scripts/curl_with_credential.sh token -sS \\",
        '          login=$(curl -sS -H "Authorization: token ${TOKEN}" \\',
    )
    offenders = [
        command
        for command in curl_commands(mutated)
        if any(name in command for name in CREDENTIAL_REFERENCES)
    ]
    assert offenders, "a credential in a curl -H argument was not detected"


def test_the_helper_never_puts_the_credential_on_a_command_line() -> None:
    """The credential is read from the environment and written to a file. Any
    line that both names it and invokes something is a line that could place it
    in a child's argv."""
    for command in logical_commands(HELPER.read_text(encoding="utf-8")):
        if "CURL_CREDENTIAL_SECRET" not in command and "_dmc_secret" not in command:
            continue
        assert not _CURL_INVOCATION.search(command), command
        assert "://" not in command, f"the credential is near a URL: {command}"


@pytest.mark.parametrize("path", SCANNED, ids=lambda p: p.name)
def test_no_credential_reaches_a_url(path: Path) -> None:
    """The older `test_no_credential_ever_appears_in_a_url` covers release.yml
    and verify-release.yml. `ci.yml` and the scripts were outside it — an
    unmonitored region, not a covered one — so the same rule is applied to the
    whole corpus here."""
    offenders = [
        line.strip()
        for line in executable_lines(path.read_text(encoding="utf-8"))
        if "://" in line and any(name in line for name in CREDENTIAL_REFERENCES)
    ]
    # The step-level `env:` mapping names the secret and no URL; a URL and a
    # credential on the SAME line is the shape that leaks.
    assert not offenders, f"{path.name}: a credential sits in a URL: {offenders}"


def test_the_planted_credential_url_is_caught() -> None:
    """SENSITIVITY for the URL check across the widened corpus."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    # Anchored on the index URL the probe actually requests, rather than on a
    # copy of that line: a copy drifts, and a mutation that fails to apply
    # would make this sensitivity proof silently vacuous. `_mutate` asserts the
    # anchor exists for the same reason.
    target = next(line for line in text.splitlines() if "simple/dotmac-kernel/" in line)
    mutated = _mutate(
        text, target, '            "https://x:${TOKEN}@registry.dotmac.io/" \\'
    )
    offenders = [
        line
        for line in executable_lines(mutated)
        if "://" in line and any(name in line for name in CREDENTIAL_REFERENCES)
    ]
    assert offenders, "a credential interpolated into a URL was not detected"


# ── the boundary this change must not cross ─────────────────────────────────


def test_the_upload_still_authenticates_only_through_the_environment() -> None:
    """`docs/CONTROL_EXCEPTIONS.md` records an accepted control: the PUBLISH
    path may not depend on a credential file, because twine dropped `.netrc`
    support between two runs on the same day and the workflow failed at the
    upload boundary.

    That control is about twine, and this change does not touch it: the upload
    step still authenticates by `TWINE_USERNAME`/`TWINE_PASSWORD` and reads no
    file. The curl config file introduced here is curl's own interface, used by
    the preflight and read-back steps, and never by the uploader. Asserting it
    here rather than assuming it, because the two now sit in the same workflow.
    """
    jobs = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    upload = jobs[jobs.index("- name: Publish the exact built bytes") :]
    upload = upload[: upload.index("  # ── 5.")]
    code = "\n".join(executable_lines(upload))
    assert "TWINE_PASSWORD" in code
    assert "--config" not in code
    assert ".netrc" not in code
    assert "curl_with_credential.sh" not in code, (
        "the twine upload reaches for the curl credential helper; the upload's "
        "credential interface is the environment, and that is the control"
    )
