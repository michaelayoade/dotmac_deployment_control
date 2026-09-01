#!/usr/bin/env bash
# The refusal a planted catalogue mutation MUST produce, checked as a property
# rather than as "the canaries went red".
#
# Any non-zero exit satisfies "it failed", and this repository has already been
# bitten twice by that substitution: a `--fail`-less curl and a `|| true`
# reported proofs that never ran. A mutated package that no longer IMPORTS also
# exits non-zero, and it would prove nothing about whether the catalogue
# comparison can see a renamed table or a narrowed column.
#
# So four separate statements, all required:
#   1. the failure NAMES what moved — the strings come from
#      `plant_catalogue_mutation.py --print-evidence`, so the plant and the
#      assertion cannot drift into describing different mutations;
#   2. the canary that failed is `database_catalogue_as_published`;
#   3. `installed_not_source` still PASSED, so the environment is still an
#      installed artifact and not a wreck;
#   4. `conflict_savepoint_executes` still PASSED, so the package still imports
#      and still works — the refusal is the catalogue's alone.
set -euo pipefail

MUTATION="${1:?the mutation name}"
REPORT="${2:?the canary output to inspect}"

fail() {
  echo "::error::${1}"
  exit 1
}

while IFS= read -r evidence; do
  [ -n "${evidence}" ] || continue
  grep -q -F -- "${evidence}" "${REPORT}" || fail \
    "the canaries failed under the \`${MUTATION}\` mutation, but the output never mentions ${evidence}. A failure that does not name what moved is some other breakage standing in for the proof."
done < <(python3 scripts/plant_catalogue_mutation.py --mutation "${MUTATION}" --print-evidence)

grep -q "FAIL  database_catalogue_as_published" "${REPORT}" || fail \
  "the canaries failed under the \`${MUTATION}\` mutation and \`database_catalogue_as_published\` was not one of the failures. Something else refused the artifact first, so the catalogue comparison is still unproven."

for healthy in installed_not_source conflict_savepoint_executes; do
  grep -q "ok    ${healthy}" "${REPORT}" || fail \
    "\`${healthy}\` did not pass under the \`${MUTATION}\` mutation. The plant was supposed to change one structural fact, not break the artifact — a package that no longer imports fails every canary and proves none of them."
done

echo "the \`${MUTATION}\` mutation was refused by database_catalogue_as_published, in an environment where the artifact still installs, imports and works"
