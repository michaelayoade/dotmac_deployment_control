#!/usr/bin/env bash
# Authenticate a curl request without putting the credential in argv.
#
# WHAT WAS WRONG
#
# `curl -u "ci-reader:${TOKEN}"` and `curl -H "Authorization: token ${TOKEN}"`
# both place the credential in the process's ARGUMENT VECTOR. Anything that can
# read the process table on that host can read it while the request is in
# flight, and anything that captures a command line into a log or a crash dump
# captures it permanently. `docs/CONTROL_EXCEPTIONS.md` recorded this as an
# accepted exception whose premise was "ephemeral, single-tenant runners".
# Michael withdrew that acceptance; this script is the replacement.
#
# It is a SEPARATE FILE for the same reason `assert_current_main.sh` is: shell
# living inside YAML cannot be executed, and therefore cannot be tested, outside
# a workflow run. `tests/architecture/test_curl_credential_transport.py` drives
# this file directly — with a real curl against a local socket, and with an
# intercepting shim — because a static check over the workflow text proves the
# SOURCE is clean and proves nothing about the running process.
#
# THE MECHANISM
#
# A curl configuration file (`--config`). Only its PATH reaches argv; the
# credential is a line inside a file that
#
#   * is created under `umask 077`, so it is 0600 from the instant it exists.
#     Creating it world-readable and tightening the mode afterwards leaves a
#     window, and on a shared runner that window is the whole vulnerability;
#   * lives under `RUNNER_TEMP` — outside `GITHUB_WORKSPACE`, so no
#     `upload-artifact` path can sweep it up — in a directory the runner
#     destroys regardless;
#   * is removed by a trap on EXIT, HUP, INT and TERM. A `rm` on the last line
#     never runs when the step fails, and `set -e` makes failing the common
#     case rather than the rare one. INT/TERM are not decoration either: this
#     repository lost `0.1.0a3` to a CANCELLED run, and cancellation is exactly
#     a signal arriving mid-step.
#
# Configuration values are QUOTED. curl's config parser terminates an unquoted
# value at the first whitespace, so `header = Authorization: token abc` reaches
# curl as the header `Authorization:` with no value at all — a silently
# unauthenticated request, which is a worse failure than a loud one. Quoted
# values take backslash escapes, so both the user and the secret are escaped
# before interpolation rather than assumed to be hex.
#
# Usage:  curl_with_credential.sh <basic|token> [curl arguments...]
#
#   basic  — sends `Authorization: Basic base64(user:secret)`, the wire form
#            `curl -u user:secret` produced. Requires CURL_CREDENTIAL_USER.
#   token  — sends `Authorization: token <secret>`, the wire form
#            `curl -H "Authorization: token ..."` produced.
#
# Environment:
#   CURL_CREDENTIAL_SECRET  required, the credential. Set through the step's
#                           `env:` mapping, never on a command line.
#   CURL_CREDENTIAL_USER    required for `basic`.
#
# Neither mode changes what goes over the wire. This is a transport change, not
# an authentication change: the same header the workflow sent before is sent
# now, from a file instead of from argv.
set -euo pipefail

# xtrace echoes the EXPANDED command, so ONE traced line touching the secret
# prints it into the step log — the leak this script exists to prevent, arriving
# through the log instead of through the process table. Remember the caller's
# setting, then run every credential-handling line untraced. It is restored
# before curl is invoked, so a debugging `bash -x` still shows the request being
# made; what it shows is the config file's PATH.
_dmc_xtrace=off
case "$-" in
  *x*) _dmc_xtrace=on ;;
esac
set +x

_dmc_mode="${1:?usage: curl_with_credential.sh <basic|token> [curl arguments...]}"
shift

if [ -z "${CURL_CREDENTIAL_SECRET:-}" ]; then
  echo "curl_with_credential.sh: CURL_CREDENTIAL_SECRET is empty or unset." >&2
  echo "The credential is passed by environment, never as an argument." >&2
  exit 2
fi

_dmc_base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
umask 077
_dmc_dir="$(mktemp -d "${_dmc_base%/}/curlcred.XXXXXXXX")"
# Armed BEFORE the secret is written. The window between mktemp and here holds
# an empty directory and nothing else.
trap 'rm -rf -- "${_dmc_dir}"' EXIT HUP INT TERM
chmod 700 -- "${_dmc_dir}"

_dmc_cfg="${_dmc_dir}/curl.conf"
: > "${_dmc_cfg}"          # created 0600 by the umask above, and EMPTY
chmod 600 -- "${_dmc_cfg}" # explicit, and before any secret is in it

_dmc_secret="${CURL_CREDENTIAL_SECRET//\\/\\\\}"
_dmc_secret="${_dmc_secret//\"/\\\"}"

case "${_dmc_mode}" in
  basic)
    if [ -z "${CURL_CREDENTIAL_USER:-}" ]; then
      echo "curl_with_credential.sh: basic mode needs CURL_CREDENTIAL_USER." >&2
      exit 2
    fi
    _dmc_user="${CURL_CREDENTIAL_USER//\\/\\\\}"
    _dmc_user="${_dmc_user//\"/\\\"}"
    printf 'user = "%s:%s"\n' "${_dmc_user}" "${_dmc_secret}" >> "${_dmc_cfg}"
    unset _dmc_user
    ;;
  token)
    printf 'header = "Authorization: token %s"\n' "${_dmc_secret}" >> "${_dmc_cfg}"
    ;;
  *)
    echo "curl_with_credential.sh: unknown mode '${_dmc_mode}'; use basic or token." >&2
    exit 2
    ;;
esac
unset _dmc_secret

if [ "${_dmc_xtrace}" = "on" ]; then
  set -x
fi

curl --config "${_dmc_cfg}" "$@"
