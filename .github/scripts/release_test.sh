#!/usr/bin/env bash
#
# Regression tests for .github/scripts/release.sh.
#
# The tests build throwaway git repositories with fixed tags and commit
# histories, then check the computed version, generated notes and the published
# tag. No network access is needed: git remotes are local bare repositories and
# gh is replaced by a stub.
#
set -euo pipefail

release_script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/release.sh"
tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

passes=0
failures=0

ok() {
  passes=$((passes + 1))
  printf 'ok - %s\n' "$1"
}

not_ok() {
  failures=$((failures + 1))
  printf 'not ok - %s\n' "$1" >&2
  if [[ -n ${2:-} ]]; then
    printf '  %s\n' "$2" >&2
  fi
  return 0
}

assert_contains() { # label needle output
  if [[ $3 == *"$2"* ]]; then
    ok "$1"
  else
    not_ok "$1" "missing: $2"
  fi
}

assert_not_contains() { # label needle output
  if [[ $3 == *"$2"* ]]; then
    not_ok "$1" "unexpected: $2"
  else
    ok "$1"
  fi
}

assert_equal() { # label actual expected
  if [[ $2 == "$3" ]]; then
    ok "$1"
  else
    not_ok "$1" "expected [$3], got [$2]"
  fi
}

new_repo() { # name [metasploit-version] [tag]
  local name=$1
  local msf=${2:-6.5.9}
  local tag=${3:-v1.2.3}
  local dir="$tmp_root/$name"

  mkdir -p "$dir"
  git -C "$dir" init -q -b master
  git -C "$dir" config user.name "Release Test"
  git -C "$dir" config user.email "release-test@example.com"
  git -C "$dir" config commit.gpgsign false
  git -C "$dir" config tag.gpgsign false

  printf 'module github.com/jolovicdev/go-msf/v2\n\ngo 1.26\n' >"$dir/go.mod"
  printf '# go-msf\n' >"$dir/README.md"
  printf 'METASPLOIT_VERSION=%s\n' "$msf" >"$dir/upstream.env"

  git -C "$dir" add go.mod README.md upstream.env
  git -C "$dir" commit -qm "chore: initial commit"
  git -C "$dir" tag -a "$tag" -m "$tag"
  printf '%s\n' "$dir"
}

commit_msg() { # dir subject [body]
  local dir=$1 subject=$2 body=${3:-}
  if [[ -n $body ]]; then
    git -C "$dir" commit -q --allow-empty -m "$subject" -m "$body"
  else
    git -C "$dir" commit -q --allow-empty -m "$subject"
  fi
}

commit_file() { # dir file content subject
  local dir=$1 file=$2 content=$3 subject=$4
  printf '%s' "$content" >"$dir/$file"
  git -C "$dir" add "$file"
  git -C "$dir" commit -qm "$subject"
}

dry_run() { # dir
  (
    cd "$1"
    GITHUB_REPOSITORY=example/go-msf GITHUB_SERVER_URL=https://github.com \
      bash "$release_script" --dry-run
  )
}

# fix -> patch
repo=$(new_repo fix)
commit_msg "$repo" "fix(modules): 🐛 correct option encoding"
out=$(dry_run "$repo")
assert_contains "fix bumps patch" "next=v1.2.4" "$out"
assert_contains "fix bump type" "bump=patch" "$out"
assert_contains "fix notes entry" "correct option encoding" "$out"
assert_contains "fix summary" "**v1.2.4** includes 1 fix since **v1.2.3**" "$out"
assert_contains "full changelog link" "compare/v1.2.3...v1.2.4" "$out"
assert_contains "fix links commit" "[$(git -C "$repo" rev-parse --short=7 HEAD)]" "$out"
assert_not_contains "no Metasploit section" "## 📦 Metasploit Framework" "$out"

# feat -> minor
repo=$(new_repo feat)
commit_msg "$repo" "feat(events): ✨ add watch filters"
out=$(dry_run "$repo")
assert_contains "feat bumps minor" "next=v1.3.0" "$out"
assert_contains "feat bump type" "bump=minor" "$out"
assert_contains "feat section" "## ✨ Features" "$out"
assert_contains "feat notes entry" "add watch filters" "$out"

# breaking marker -> major
repo=$(new_repo breaking-bang)
commit_msg "$repo" "feat(api)!: 💥 require context on Execute"
out=$(dry_run "$repo")
assert_contains "bang bumps major" "next=v2.0.0" "$out"
assert_contains "bang bump type" "bump=major" "$out"
assert_contains "breaking section" "## 💥 Breaking changes" "$out"
assert_contains "breaking entry" "require context on Execute" "$out"

# BREAKING CHANGE footer -> major, even without fix/feat type
repo=$(new_repo breaking-footer)
commit_msg "$repo" "refactor: reshuffle managers" "BREAKING CHANGE: managers moved under Client"
out=$(dry_run "$repo")
assert_contains "footer bumps major" "next=v2.0.0" "$out"
assert_contains "footer breaking section" "## 💥 Breaking changes" "$out"
assert_contains "footer detail" "managers moved under Client" "$out"

# docs-only history -> no release
repo=$(new_repo docs-only)
commit_msg "$repo" "docs: 📝 clarify install"
out=$(dry_run "$repo")
assert_contains "docs-only skips" "releasable=false" "$out"
assert_not_contains "docs-only has no next version" "next=" "$out"

# mixed history takes the highest bump
repo=$(new_repo precedence)
commit_msg "$repo" "fix: 🐛 repair one"
commit_msg "$repo" "feat: ✨ add two"
out=$(dry_run "$repo")
assert_contains "highest bump wins" "next=v1.3.0" "$out"
assert_contains "highest bump type" "bump=minor" "$out"
assert_contains "mixed summary" "1 feature and 1 fix since" "$out"

# version sort is numeric, not lexical
repo=$(new_repo tag-sort)
git -C "$repo" tag -a v1.10.0 -m v1.10.0
commit_msg "$repo" "fix: 🐛 repair sort"
out=$(dry_run "$repo")
assert_contains "numeric tag order" "next=v1.10.1" "$out"

# pinned Metasploit version is reported when it changes
repo=$(new_repo msf-change 6.5.8)
commit_file "$repo" upstream.env $'METASPLOIT_VERSION=6.5.9\n' \
  "feat(upstream): 📦 bump Metasploit Framework to 6.5.9"
out=$(dry_run "$repo")
assert_contains "Metasploit section" "## 📦 Metasploit Framework" "$out"
assert_contains "Metasploit change" "Pinned version changed from \`6.5.8\` to \`6.5.9\`" "$out"

# a major tag requires a matching module path
repo=$(new_repo module-guard 6.5.9 v2.1.1)
commit_msg "$repo" "feat!: 💥 remove legacy API"
set +e
out=$(dry_run "$repo" 2>&1)
status=$?
set -e
assert_equal "major without /v3 fails" "1" "$status"
assert_contains "major without /v3 explains fix" "update the module path" "$out"

repo=$(new_repo module-major 6.5.9 v2.1.1)
commit_file "$repo" go.mod $'module github.com/jolovicdev/go-msf/v3\n\ngo 1.26\n' \
  "feat!: 💥 move module to /v3"
out=$(dry_run "$repo")
assert_contains "migrated module tags major" "next=v3.0.0" "$out"

# publishing pushes an annotated tag and creates the release
bare="$tmp_root/publish-origin.git"
git init -q --bare "$bare"
repo=$(new_repo publish)
git -C "$repo" remote add origin "$bare"
git -C "$repo" push -q origin master --tags
commit_msg "$repo" "fix: 🐛 repair release publishing"

mkdir -p "$tmp_root/fake-bin"
cat >"$tmp_root/fake-bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GH_LOG:?}"
if [[ ${1:-} == release && ${2:-} == create ]]; then
  previous=""
  for argument in "$@"; do
    if [[ $previous == --notes-file ]]; then
      cp "$argument" "${GH_NOTES:?}"
    fi
    previous=$argument
  done
fi
if [[ ${GH_FAIL:-0} == 1 ]]; then
  exit 1
fi
STUB
chmod +x "$tmp_root/fake-bin/gh"

run_publish() { # dir
  (
    cd "$1"
    PATH="$tmp_root/fake-bin:$PATH" \
      GH_LOG="$tmp_root/gh.log" \
      GH_NOTES="$tmp_root/gh-notes.md" \
      GITHUB_REPOSITORY=example/go-msf \
      GITHUB_SERVER_URL=https://github.com \
      bash "$release_script"
  )
}

publish_out=$(run_publish "$repo")
assert_contains "publish reports version" "Published v1.2.4." "$publish_out"
assert_equal "published tag object is annotated" "tag" "$(git -C "$bare" cat-file -t v1.2.4)"
assert_equal "published tag points at HEAD" \
  "$(git -C "$repo" rev-parse HEAD)" "$(git -C "$bare" rev-parse 'v1.2.4^{}')"
assert_contains "gh release receives tag" "release create v1.2.4" "$(cat "$tmp_root/gh.log")"
assert_contains "gh release verifies tag" "--verify-tag" "$(cat "$tmp_root/gh.log")"
assert_contains "release notes were passed to gh" "repair release publishing" "$(cat "$tmp_root/gh-notes.md")"

# a failed release removes the pushed tag so a re-run can retry
failed_bare="$tmp_root/failed-origin.git"
git init -q --bare "$failed_bare"
failed_repo=$(new_repo retry)
git -C "$failed_repo" remote add origin "$failed_bare"
git -C "$failed_repo" push -q origin master --tags
commit_msg "$failed_repo" "fix: 🐛 repair retry path"
set +e
failed_out=$(
  cd "$failed_repo" &&
    PATH="$tmp_root/fake-bin:$PATH" \
      GH_LOG="$tmp_root/gh-failure.log" \
      GH_NOTES="$tmp_root/gh-failure-notes.md" \
      GH_FAIL=1 \
      GITHUB_REPOSITORY=example/go-msf \
      GITHUB_SERVER_URL=https://github.com \
      bash "$release_script" 2>&1
)
failed_status=$?
set -e
assert_equal "failed release exits nonzero" "1" "$failed_status"
assert_contains "failed release explains retry" "removing tag v1.2.4" "$failed_out"
assert_equal "failed release removes tag" "" "$(git -C "$failed_bare" tag --list 'v1.2.4')"

# a second run on the same commit publishes nothing
second_out=$(run_publish "$repo")
assert_contains "second run skips" "skipping release" "$second_out"
assert_equal "no duplicate release call" "1" "$(wc -l <"$tmp_root/gh.log" | tr -d ' ')"
assert_equal "no duplicate tag" "1" "$(git -C "$bare" tag --list 'v1.2.4' | wc -l | tr -d ' ')"

printf '\n%d passed, %d failed\n' "$passes" "$failures"
if ((failures > 0)); then
  exit 1
fi
