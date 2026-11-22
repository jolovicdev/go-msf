#!/usr/bin/env bash
#
# Regression tests for .github/scripts/upstream_bump.sh.
#
# The tests build a throwaway repository with a local bare origin, answer the
# upstream tag lookup with a stub git, and replace gh with a stub so the
# success and the "GITHUB_TOKEN may not open pull requests" paths both run
# without network access.
#
set -euo pipefail

script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/upstream_bump.sh"
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

assert_equal() { # label actual expected
  if [[ $2 == "$3" ]]; then
    ok "$1"
  else
    not_ok "$1" "expected [$3], got [$2]"
  fi
}

# Stub git: answers the upstream tag lookup, delegates everything else.
mkdir -p "$tmp_root/fake-bin"
cat >"$tmp_root/fake-bin/git" <<'STUB'
#!/usr/bin/env bash
if [[ ${1:-} == ls-remote ]]; then
  # Deliberately unsorted and with noise: only version order must win.
  printf 'x\trefs/tags/6.5.9\nx\trefs/tags/6.5.11\nx\trefs/tags/6.5.10\nx\trefs/tags/sprint-G08\n'
  exit 0
fi
exec /usr/bin/git "$@"
STUB

cat >"$tmp_root/fake-bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GH_LOG:?}"
if [[ ${GH_FAIL:-0} == 1 ]]; then
  echo "pull request create failed: GraphQL: GitHub Actions is not permitted to create or approve pull requests (createPullRequest)" >&2
  exit 1
fi
printf '%s\n' "https://github.com/example/go-msf/pull/99"
STUB
chmod +x "$tmp_root/fake-bin/git" "$tmp_root/fake-bin/gh"

new_repo() { # name pinned-version
  local dir="$tmp_root/$1"
  mkdir -p "$dir"
  git -C "$dir" init -q -b master
  git -C "$dir" config user.name "Bump Test"
  git -C "$dir" config user.email "bump-test@example.com"
  printf '%s\n' "METASPLOIT_VERSION=$2" >"$dir/upstream.env"
  mkdir -p "$dir/.github/scripts"
  cp "$script" "$dir/.github/scripts/"
  git init -q --bare "$tmp_root/$1-origin.git"
  git -C "$dir" add -A
  git -C "$dir" commit -qm "chore: seed"
  git -C "$dir" remote add origin "$tmp_root/$1-origin.git"
  git -C "$dir" push -q origin master
  printf '%s\n' "$dir"
}

run() { # repo gh-log [gh-fail]
  (
    cd "$1"
    PATH="$tmp_root/fake-bin:$PATH" \
      GITHUB_REPOSITORY=example/go-msf \
      GH_LOG="$2" \
      GH_FAIL="${3:-0}" \
      GITHUB_OUTPUT="$1/output" \
      bash .github/scripts/upstream_bump.sh
  )
}

# a new upstream release is pinned, pushed and opened as a pull request
repo=$(new_repo opened 6.5.10)
out=$(run "$repo" "$tmp_root/gh-opened.log")
assert_contains "bump reports both versions" "pinned=6.5.10
latest=6.5.11" "$out"
assert_contains "bump reports the pull request" "opened=" "$out"
assert_equal "upstream.env is pinned" \
  "METASPLOIT_VERSION=6.5.11" "$(cat "$repo/upstream.env")"
assert_equal "one commit is pushed to the bump branch" "1" \
  "$(git -C "$tmp_root/opened-origin.git" rev-list --count master..upstream/metasploit-6.5.11)"
assert_equal "commit subject" "chore(upstream): 📦 bump Metasploit Framework to 6.5.11" \
  "$(git -C "$repo" log -1 --format=%s upstream/metasploit-6.5.11)"
assert_equal "commit author" "jolovicdev" \
  "$(git -C "$repo" log -1 --format=%an upstream/metasploit-6.5.11)"
assert_equal "commit author email is the GitHub noreply address" \
  "jolovicdev@users.noreply.github.com" \
  "$(git -C "$repo" log -1 --format=%ae upstream/metasploit-6.5.11)"
assert_contains "pull request targets master from the bump branch" \
  "--base master --head upstream/metasploit-6.5.11" "$(cat "$tmp_root/gh-opened.log")"
assert_contains "step output reports the change" "changed=true" "$(cat "$repo/output")"
assert_contains "step output reports the version" "upstream=6.5.11" "$(cat "$repo/output")"

# an upstream that is already pinned changes nothing
repo=$(new_repo current 6.5.11)
out=$(run "$repo" "$tmp_root/gh-current.log")
assert_contains "current pin reports no change" "changed=false" "$out"
assert_equal "current pin pushes no branch" "" \
  "$(git -C "$tmp_root/current-origin.git" branch --list 'upstream/*')"
assert_equal "current pin calls no pull request" "0" \
  "$(cat "$tmp_root/gh-current.log" 2>/dev/null | wc -l | tr -d ' ')"
assert_contains "current pin reports no change as output" "changed=false" "$(cat "$repo/output")"

# a refused GITHUB_TOKEN keeps the branch and names the compare link
repo=$(new_repo refused 6.5.9)
set +e
out=$(run "$repo" "$tmp_root/gh-refused.log" 1 2>&1)
status=$?
set -e
assert_equal "refused pull request does not fail the job" "0" "$status"
assert_contains "refused pull request warns" "GITHUB_TOKEN cannot open pull requests" "$out"
assert_contains "refused pull request links the compare view" \
  "compare/master...upstream/metasploit-6.5.11" "$out"
assert_equal "refused pull request keeps the branch" "1" \
  "$(git -C "$tmp_root/refused-origin.git" rev-list --count master..upstream/metasploit-6.5.11)"

# a rerun on the same commit reuses the branch an earlier run pushed
repo=$(new_repo reused 6.5.9)
run "$repo" "$tmp_root/gh-first.log" >/dev/null
git -C "$repo" reset -q --hard master
out=$(run "$repo" "$tmp_root/gh-reused.log")
assert_contains "a rerun reuses the pushed branch" "reusing=upstream/metasploit-6.5.11" "$out"
assert_equal "a rerun still has one commit" "1" \
  "$(git -C "$tmp_root/reused-origin.git" rev-list --count master..upstream/metasploit-6.5.11)"

printf '\n%d passed, %d failed\n' "$passes" "$failures"
if ((failures > 0)); then
  exit 1
fi
