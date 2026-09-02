#!/usr/bin/env bash
# Open the post-release record as a pull request, straight after tagging.
#
# PORTED from `dotmac_starter_mt`'s script of the same name — the already
# approved mechanism, not a redesign. What differs is the writer it calls and
# the coordinates-only diff check below; the failure discipline, the branch
# naming, the identity split and the auto-merge behaviour are as they are there.
#
# `verify-release.yml` writes the TAG. It did not write the RECORD, and the tag
# invalidates the publication ledger the instant it lands. The record has been
# missed twice here: `0.1.0a4`'s row outlived its own publication by six hours,
# and `0.1.0a7`'s absence turned protected main red for every open pull request
# — each presenting as *that branch* being broken rather than as main being
# broken, which is what made it expensive to diagnose rather than expensive to
# fix. a4 failed silently; a7 failed loudly at innocent people.
#
# Everything the verify run needed was already computed. It ended by printing
#
#     ::notice::OWED: remove the 0.1.0aN row from docs/publication-ledger.json
#
# — a notice nothing reads. That is the gap this closes.
#
# FAILS LOUDLY when it cannot open the record. The Starter's earlier version
# exited 0 with a `::warning::`, reasoning that the artifact is already
# published so the run should not report a successful publication as failed.
# That reasoning was wrong and recreated the exact failure class the script
# exists to close: correctness went back to depending on somebody READING a
# warning in a green run, and a green run with no record is indistinguishable,
# at a glance, from a green run with one.
#
# So the run goes RED. The message states plainly that the artifact IS published
# and tagged — nobody should re-run the publish — names the hand-repair command,
# and links the ready-made pull-request page for the branch it has already
# pushed. "Tag exists, record missing" becomes visible where people already look.
#
# COORDINATES ONLY, and it is CHECKED here rather than merely intended. The
# writer can only open two paths, but "the writer is careful" is a property of
# code somebody may edit; the diff check below is a property of this run. A
# record that reached a test, a floor literal or a human note would be a bot
# editing the constraints that bind it, so anything outside the allowlist stops
# the record rather than being pushed.
set -uo pipefail

DISTRIBUTION=""
VERSION=""
TAG=""
OBSERVATIONS=""
VERIFY_RUN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --distribution) DISTRIBUTION="$2"; shift 2 ;;
    --version)      VERSION="$2";      shift 2 ;;
    --tag)          TAG="$2";          shift 2 ;;
    --observations) OBSERVATIONS="$2"; shift 2 ;;
    --verify-run)   VERIFY_RUN="$2";   shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for required in DISTRIBUTION VERSION TAG OBSERVATIONS VERIFY_RUN; do
  if [ -z "${!required}" ]; then
    echo "--${required,,} is required" >&2
    exit 2
  fi
done

# The two paths a release record may touch. Kept here as well as in the writer
# because they are two different claims: the writer's list is what it intends to
# open, and this one is what actually changed.
ALLOWED="docs/publication-ledger.json docs/published-versions.json"

MANUAL="python scripts/write_release_record.py --distribution ${DISTRIBUTION} --version ${VERSION} --tag ${TAG} --observations <observations.json> --verify-run ${VERIFY_RUN}"

BRANCH="chore/record-${DISTRIBUTION}-${VERSION}"
COMPARE_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-michaelayoade/dotmac_deployment_control}/pull/new/${BRANCH}"

give_up() {
  echo "::error::the ${TAG} release record was NOT opened: $1"
  echo "::error::"
  echo "::error::The branch may already carry the correct edits. Check, and if"
  echo "::error::so open it directly:"
  echo "::error::  ${COMPARE_URL}"
  echo "::error::"
  echo "::error::DO NOT RE-RUN THE PUBLISH. ${DISTRIBUTION} ${VERSION} is already"
  echo "::error::published and tagged; the artifact is fine and this failure is"
  echo "::error::bookkeeping only. main is RED until the record lands."
  echo "::error::"
  echo "::error::Close it by hand, on a branch off main:"
  echo "::error::  ${MANUAL}"
  echo "::error::then open a pull request titled:"
  echo "::error::  chore(release): record the ${DISTRIBUTION} ${VERSION} publication"
  exit 1
}

# The identity split, ported as-is. The App token is the PUSH and API
# credential — bound to git by the recorder-token action's second checkout —
# while the commit itself is authored by the actions bot. Changing either half
# diverges from the mechanism the guard pins.
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

git fetch origin main --quiet || give_up "could not fetch main"
git checkout -B "${BRANCH}" origin/main --quiet || give_up "could not branch from main"

if ! OUTPUT="$(python scripts/write_release_record.py \
    --distribution "${DISTRIBUTION}" \
    --version "${VERSION}" \
    --tag "${TAG}" \
    --observations "${OBSERVATIONS}" \
    --verify-run "${VERIFY_RUN}" 2>&1)"; then
  echo "${OUTPUT}"
  give_up "the record writer refused (see above)"
fi
echo "${OUTPUT}"

if git diff --quiet; then
  # A real success, and the ONLY one besides opening the pull request: the
  # writer found the record already complete, so there is nothing to record.
  echo "the ${TAG} record is already complete — no pull request needed"
  exit 0
fi

# COORDINATES ONLY, checked. Before `git add`, so a stray path never reaches a
# commit at all.
TOUCHED="$(git diff --name-only)"
for path in ${TOUCHED}; do
  case " ${ALLOWED} " in
    *" ${path} "*) ;;
    *) give_up "the record touched ${path}, which is not one of: ${ALLOWED}. A
release record is coordinates only: dispositions, release notes and the release
floor's own literals are human-owned, and a recorder that wrote them would be
editing the constraints that bind it." ;;
  esac
done
echo "coordinates only: ${TOUCHED}"

git add -A
git commit --quiet -m "chore(release): record the ${DISTRIBUTION} ${VERSION} publication

Written by scripts/write_release_record.py from the verify workflow, straight
after tagging ${TAG}.

The tag makes this distribution's publication-ledger row false the moment it
lands, and the two files must never both claim one version. Both halves are
recorded here rather than remembered, because remembering has failed twice: a4's
row outlived its own publication by six hours, and a7's absence turned protected
main red for every open pull request.

COORDINATES ONLY. Every field is derived from the tag, from the observations the
verifier gathered, or from the tree at the tag. The disposition — pinnable,
superseded_by, the release notes and the floor's own literals — is human-owned
and is deliberately absent." \
  || give_up "nothing to commit after a non-empty diff (unexpected)"

git push --force-with-lease origin "${BRANCH}" --quiet \
  || give_up "could not push ${BRANCH}"

if ! gh pr view "${BRANCH}" --json number >/dev/null 2>&1; then
  gh pr create \
    --base main \
    --head "${BRANCH}" \
    --title "chore(release): record the ${DISTRIBUTION} ${VERSION} publication" \
    --body "Opened automatically by the verify workflow immediately after tagging \`${TAG}\`.

\`${DISTRIBUTION} ${VERSION}\` **is published, verified and tagged.** Until this merges, \`main\` is red on the gate that holds a publication and its record together, and every open pull request inherits that failure while looking like its own branch is broken.

$(echo "${OUTPUT}" | sed 's/^/- /')

**This pull request is coordinates only.** Every field is derived from the tag, from the verifier's own observations, or from the tree at the tag. The disposition is not: \`pinnable\`, \`superseded_by\`, the release notes and the release floor's own literals in \`tests/architecture/test_published_versions_and_floor.py\` are human-owned, and the recorder is refused any path outside the two record files. **Those edits are still owed and this branch is where they belong.**

Configured to squash-merge automatically as soon as every protected-main check is green." \
    || give_up "could not open the pull request (branch ${BRANCH} is pushed)"
else
  echo "a pull request for ${BRANCH} already exists — updated it"
fi

gh pr merge "${BRANCH}" --auto --squash \
  || give_up "could not enable auto-merge for ${BRANCH}"

echo "post-release record opened with auto-merge enabled for ${TAG}"
