#!/usr/bin/env bash
#
# Publish the next semantic version of go-msf after CI succeeds on master.
#
# The next version is derived from conventional commits since the newest v* tag:
#
#   fix: ...                         -> patch
#   feat: ...                        -> minor
#   type!: ... / BREAKING CHANGE: ... -> major
#
# Commits that are not fix, feat or breaking produce no release. The script
# pushes an annotated v<X.Y.Z> tag and creates a GitHub Release with concise
# generated notes: a summary, notable changes, and the pinned Metasploit
# Framework version when it changed.
#
# Usage:
#   release.sh            Publish the release (needs GH_TOKEN).
#   release.sh --dry-run  Print the computed version and notes; change nothing.
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

latest_tag=$(
  git tag --list 'v[0-9]*' --sort=-version:refname |
    grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' |
    head -n 1 || true
)
if [[ -z $latest_tag ]]; then
  echo "error: no v<major>.<minor>.<patch> tag found; create the initial release tag manually." >&2
  exit 1
fi

IFS=. read -r major minor patch <<<"${latest_tag#v}"

server_url=${GITHUB_SERVER_URL:-https://github.com}
repo_slug=${GITHUB_REPOSITORY:-}
if [[ -z $repo_slug ]]; then
  origin_url=$(git remote get-url origin 2>/dev/null || true)
  origin_url=${origin_url%.git}
  case $origin_url in
    *://*) repo_slug=${origin_url#*://}; repo_slug=${repo_slug#*/} ;;
    *@*:*) repo_slug=${origin_url#*@}; repo_slug=${repo_slug#*:} ;;
  esac
fi

commit_url() {
  local sha=$1
  if [[ -n $repo_slug ]]; then
    printf '%s/%s/commit/%s' "$server_url" "$repo_slug" "$sha"
  else
    printf '%s' "${sha:0:7}"
  fi
}

# Rank: 0 = nothing to release, 1 = patch, 2 = minor, 3 = major.
bump_rank=0
features=()
fixes=()
breaking=()
conventional_subject='^([A-Za-z][A-Za-z0-9_-]*)(\([^)]*\))?(!)?:[[:space:]](.*)$'

while IFS= read -r sha; do
  [[ -z $sha ]] && continue

  subject=$(git log -1 --format=%s "$sha")
  body=$(git log -1 --format=%b "$sha")

  type=""
  description=$subject
  bang=""
  if [[ $subject =~ $conventional_subject ]]; then
    type=${BASH_REMATCH[1],,}
    bang=${BASH_REMATCH[3]}
    description=${BASH_REMATCH[4]}
  fi

  is_breaking=false
  if [[ -n $bang ]] || grep -qE '^BREAKING[ -]CHANGE:' <<<"$body"; then
    is_breaking=true
  fi

  entry="${description} ([${sha:0:7}]($(commit_url "$sha")))"

  if $is_breaking; then
    detail=$(
      grep -m 1 -E '^BREAKING[ -]CHANGE:' <<<"$body" |
        sed -E 's/^BREAKING[ -]CHANGE:[[:space:]]*//' || true
    )
    [[ -n $detail ]] && entry+=$'\n'"  - Breaking: ${detail}"
    breaking+=("$entry")
    bump_rank=3
  elif [[ $type == feat ]]; then
    features+=("$entry")
    if ((bump_rank < 2)); then
      bump_rank=2
    fi
  elif [[ $type == fix ]]; then
    fixes+=("$entry")
    if ((bump_rank < 1)); then
      bump_rank=1
    fi
  fi
done < <(git rev-list --reverse "${latest_tag}..HEAD")

echo "latest=${latest_tag}"

if ((bump_rank == 0)); then
  echo "releasable=false"
  echo "No feat, fix or breaking conventional commits since ${latest_tag}; skipping release."
  exit 0
fi

case $bump_rank in
  1)
    bump="patch"
    patch=$((patch + 1))
    ;;
  2)
    bump="minor"
    minor=$((minor + 1))
    patch=0
    ;;
  3)
    bump="major"
    major=$((major + 1))
    minor=0
    patch=0
    ;;
esac
next="v${major}.${minor}.${patch}"

# A module path major must match the tag major, otherwise the published tag is
# not a valid Go module version. A major bump therefore requires the module
# path migration (for example /v3) in the same change set.
module_path=$(awk '$1 == "module" { print $2; exit }' go.mod 2>/dev/null || true)
if [[ -z $module_path ]]; then
  echo "error: cannot read the module path from go.mod." >&2
  exit 1
fi
expected_suffix=""
if ((major >= 2)); then
  expected_suffix="/v${major}"
fi
if [[ $module_path != *"$expected_suffix" ]]; then
  echo "error: next version ${next} is a v${major} release but go.mod declares module ${module_path}." >&2
  echo "error: update the module path (and imports) before releasing ${next}." >&2
  exit 1
fi

echo "bump=${bump}"
echo "next=${next}"
echo "releasable=true"

count_label() {
  if (( $1 == 1 )); then
    printf '%s %s' "$1" "$2"
  else
    printf '%s %s' "$1" "$3"
  fi
}

join_and() {
  local result="" item
  local last=$#
  local i=0
  for item in "$@"; do
    i=$((i + 1))
    if ((i == 1)); then
      result=$item
    elif ((i == last)); then
      result+=" and ${item}"
    else
      result+=", ${item}"
    fi
  done
  printf '%s' "$result"
}

summary_parts=()
if ((${#features[@]} > 0)); then
  summary_parts+=("$(count_label "${#features[@]}" feature features)")
fi
if ((${#fixes[@]} > 0)); then
  summary_parts+=("$(count_label "${#fixes[@]}" fix fixes)")
fi
if ((${#breaking[@]} > 0)); then
  summary_parts+=("$(count_label "${#breaking[@]}" "breaking change" "breaking changes")")
fi

notes="## Summary"$'\n\n'
notes+="go-msf **${next}** includes $(join_and "${summary_parts[@]}") since **${latest_tag}**."

if ((${#breaking[@]} > 0)); then
  notes+=$'\n\n## 💥 Breaking changes\n\n'
  notes+=$(printf -- '- %s\n' "${breaking[@]}")
fi
if ((${#features[@]} > 0)); then
  notes+=$'\n\n## ✨ Features\n\n'
  notes+=$(printf -- '- %s\n' "${features[@]}")
fi
if ((${#fixes[@]} > 0)); then
  notes+=$'\n\n## 🐛 Fixes\n\n'
  notes+=$(printf -- '- %s\n' "${fixes[@]}")
fi

current_msf=$(sed -n 's/^METASPLOIT_VERSION=//p' upstream.env 2>/dev/null | tail -n 1 || true)
previous_msf=""
if git cat-file -e "${latest_tag}:upstream.env" 2>/dev/null; then
  previous_msf=$(git show "${latest_tag}:upstream.env" | sed -n 's/^METASPLOIT_VERSION=//p' | tail -n 1)
fi
if [[ -n $current_msf && $current_msf != "$previous_msf" ]]; then
  notes+=$'\n\n## 📦 Metasploit Framework\n\n'
  if [[ -n $previous_msf ]]; then
    notes+="Pinned version changed from \`${previous_msf}\` to \`${current_msf}\`."
  else
    notes+="Pinned version: \`${current_msf}\`."
  fi
fi

if [[ -n $repo_slug ]]; then
  notes+=$'\n\n**Full changelog**: '"${server_url}/${repo_slug}/compare/${latest_tag}...${next}"
fi

printf '\n%s\n' "$notes"

if $dry_run; then
  exit 0
fi

if git rev-parse -q --verify "refs/tags/${next}" >/dev/null; then
  echo "Tag ${next} already exists; nothing to publish."
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$next" -m "go-msf ${next}" HEAD
git push origin "refs/tags/${next}"

notes_file=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/go-msf-${next}-notes.XXXXXX")
trap 'rm -f "$notes_file"' EXIT
printf '%s\n' "$notes" >"$notes_file"

gh_args=(release create "$next" --title "$next" --notes-file "$notes_file" --verify-tag)
if [[ -n $repo_slug ]]; then
  gh_args+=(--repo "$repo_slug")
fi
if ! gh "${gh_args[@]}"; then
  echo "error: release creation failed; removing tag ${next} so a re-run can publish it." >&2
  git push origin ":refs/tags/${next}" || true
  exit 1
fi

echo "Published ${next}."

if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  {
    printf '## Published %s\n\n' "$next"
    printf '%s\n' "$notes"
  } >>"$GITHUB_STEP_SUMMARY"
fi
