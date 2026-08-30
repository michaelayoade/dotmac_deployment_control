#!/usr/bin/env bash
# Fail unless this run is on the EXACT current tip of protected main — not
# merely an ancestor of it.
#
# Called TWICE by the release workflow: once in `guard`, so a stale or
# side-branch dispatch cannot reach a build, and again in `publish`, AFTER the
# queue boundary and before anything irreversible. The second call is not
# redundant. A publish job can start minutes after the guard passed, and any
# commit landing in that interval would be silently absent from a release that
# claims to be current — with the tag pointing at a SHA that is no longer the
# tip.
#
# Extracted from the YAML so the comparison is executable, and therefore
# testable, outside a workflow run.
#
# Usage: assert_current_main.sh <run_sha> [<main_sha>]
#   main_sha is optional and resolved from origin/main when omitted; passing it
#   is what lets a test simulate a moved ref with no network and no fake remote.
set -euo pipefail

RUN_SHA="${1:?usage: assert_current_main.sh <run_sha> [<main_sha>]}"
MAIN_SHA="${2:-}"

if [ -z "${MAIN_SHA}" ]; then
  git fetch --no-tags origin main
  MAIN_SHA="$(git rev-parse origin/main)"
fi

if [ "${RUN_SHA}" != "${MAIN_SHA}" ]; then
  echo "::error::release run SHA ${RUN_SHA} is not the current protected main ${MAIN_SHA} — main moved after dispatch. Re-dispatch on the current tip."
  exit 1
fi

echo "on current protected main: ${MAIN_SHA}"
