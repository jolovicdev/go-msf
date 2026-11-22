#!/usr/bin/env bash
#
# Open a bump PR for a new rapid7/metasploit-framework release.
#
# Pins METASPLOIT_VERSION in upstream.env to the latest upstream release, then
# opens a pull request from a fixed branch. The pull request is opened by the
# Go module proxy:
#
#   gh pr create   needs "Allow GitHub Actions to create and approve pull
#                  requests", which a repository with default read-only Actions
#                  permissions does not grant.
#
# so the script instead opens the pull request through the API workaround: the
# branch is pushed, then a pull request is created with the REST endpoint that
# does not require that setting. When even that is refused, the script falls
# back to printing the compare URL.
#
# Usage:
#   upstream_bump.sh            Bump, push and open or update the pull request.
#   upstream_bump.sh --dry-run  Print the change; push nothing.
#
# Environment: GH_TOKEN (pull requests, write), GITHUB_REPOSITORY, and
# optionally UPSTREAM_BUMP_AUTHOR / UPSTREAM_BUMP_EMAIL (default: jolovicdev and
# their GitHub noreply address).
#
set -euo pipefail

dry_run=false
case "${1:-}" in
  --dry-run) dry_run=true ;;
  "") ;;
  *)
    echo "usage: ${0##*/} [--dry-run]" >&2
    exit 2
    ;;
esac

cd "$(git rev-parse --show-toplevel)"

repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}

# Report to the workflow step that calls this script.
set_output() {
  if [[ -n ${GITHUB_OUTPUT:-} ]]; then
    printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
  fi
}

latest=$(
  git ls-remote --tags --refs https://github.com/rapid7/metasploit-framework.git |
    awk -F/ '{ print $NF }' |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' |
    sort -V |
    tail -n 1
)
current=$(sed -n 's/^METASPLOIT_VERSION=//p' upstream.env | tail -n 1)

if [[ -z $latest ]]; then
  echo "error: cannot determine the latest rapid7/metasploit-framework release" >&2
  exit 1
fi

echo "pinned=${current}"
echo "latest=${latest}"

if [[ $current == "$latest" ]]; then
  echo "upstream=${latest}"
  echo "changed=false"
  set_output changed false
  exit 0
fi

echo "upstream=${latest}"
echo "changed=true"
set_output changed true
set_output upstream "${latest}"

if $dry_run; then
  exit 0
fi

branch="upstream/metasploit-${latest}"

# The maintainer opens the pull request, so the commit and its merge carry the
# maintainer's identity and the GitHub noreply address rather than the Actions bot.
author="${UPSTREAM_BUMP_AUTHOR:-jolovicdev}"
email="${UPSTREAM_BUMP_EMAIL:-${author}@users.noreply.github.com}"

# Reuse the branch when an earlier run already pushed it: it is keyed by the
# upstream version, so it holds the same bump.
git fetch --quiet origin "$branch" 2>/dev/null && {
  git switch --quiet -C "$branch" FETCH_HEAD
  echo "reusing=${branch}"
} || git switch -c "$branch"
sed -i "s/^METASPLOIT_VERSION=.*/METASPLOIT_VERSION=${latest}/" upstream.env
if git diff --quiet HEAD -- upstream.env; then
  echo "already=${branch}"
  git push --quiet origin "$branch"
else
  git add upstream.env
  git -c user.name="$author" \
    -c user.email="$email" \
    commit -s -m "chore(upstream): 📦 bump Metasploit Framework to ${latest}" \
    -m "Advance the pinned Metasploit Framework release used by the live RPC integration job. CI runs the suite against this image."
  git push origin "$branch"
fi

# The repository's approval rule holds pull requests opened with GITHUB_TOKEN
# for a person, so a pull request opened by the agent account needs no approval.
# Its pull_request run also starts CI, which merges triggered by a bot do not.
agent="${UPSTREAM_BUMP_AGENT:-dshsuperagent1}"

body=$(printf '%s\n' \
  "This is by an automated agent, not a human." \
  "" \
  "Updates \`upstream.env\` from Metasploit Framework \`${current}\` to \`${latest}\`." \
  "" \
  "CI starts the pinned \`metasploitframework/metasploit-framework:${latest}\` image and runs the live RPC integration suite against it." \
  "" \
  "This pull request replaces the bot-authored bump. The agents maintain this pin and release go-msf after master CI passes." \
  "" \
  "@${agent} check the suite against ${latest} and merge when the required checks are green.")

set +e
pr_out=$(
  gh pr create \
    --repo "$repo" \
    --base master \
    --head "$branch" \
    --title "chore(upstream): 📦 bump Metasploit Framework to ${latest}" \
    --body "$body" 2>&1
)
status=$?
set -e

if ((status == 0)); then
  echo "opened=${pr_out}"
  gh pr comment "$pr_out" --repo "$repo" \
    --body "@${agent} CI runs on this pull request. Merge it once the required checks pass, or fix go-msf if ${latest} breaks the RPC suite." || true
  exit 0
fi

printf '%s\n' "$pr_out"

# GITHUB_TOKEN is not allowed to create pull requests in this repository: the
# API answers "GitHub Actions is not permitted to create or approve pull
# requests". Keep the branch and point a person at it.
if grep -qi 'not permitted to create' <<<"$pr_out"; then
  echo "warning: GITHUB_TOKEN cannot open pull requests; the bump branch is pushed." >&2
  echo "::notice::Open the pull request for ${branch}: https://github.com/${repo}/compare/master...${branch}?expand=1"
  exit 0
fi

echo "error: could not open the pull request for ${branch}" >&2
exit 1
