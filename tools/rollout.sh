#!/usr/bin/env bash
#
# rollout.sh -- add (or refresh) the malware-scan caller workflow in every
# repository of a GitHub owner, one pull request per repo, idempotently.
#
# Run it from your Mac, from a checkout of the scanner repo:
#
#   tools/rollout.sh --owner <owner> --all --dry-run   # look first
#   tools/rollout.sh --owner <owner> --all             # open the PRs
#   tools/rollout.sh --owner <owner> --all --merge     # ... and merge them
#
# ---------------------------------------------------------------------------
# WHY THIS SCRIPT IS BUILT THE WAY IT IS
#
# The repos it touches may still contain the 2026-08 EtherHiding / JADESNOW
# implant in their working tree or their history. So it must add a workflow
# file to a repo *without ever putting that repo's project files on disk*.
# Three independent measures, any one of which would do on its own:
#
#   1. `clone --no-checkout --filter=blob:none --depth 1 --single-branch`.
#      The clone writes nothing to the worktree, and project blobs are never
#      even downloaded.
#   2. `sparse-checkout set --no-cone '/.github/workflows/'` before the one
#      checkout. NOTE: --no-cone deliberately, *not* --cone. Cone mode always
#      materialises every file in the repository root, and the repository root
#      is precisely where this implant lives (`vite.config.js`,
#      `postcss.config.mjs`). Measured here on git 2.50.1 against a fixture
#      repo: cone mode produced `.git .github package.json README.md
#      vite.config.js`; --no-cone produced `.git .github`. Cone mode would
#      still not *execute* anything -- but "the payload is never written to
#      this Mac" is a far easier property to audit than "the payload is
#      written but nothing opens it".
#   3. Every git invocation runs with `-c core.hooksPath=/dev/null -c
#      core.fsmonitor=false`, so no repo-local hook or fsmonitor daemon can
#      execute even if a checkout somehow materialised one. (`git clone` does
#      not install hooks from the remote and we never adopt remote config --
#      this is belt and braces.)
#
# After the checkout and before anything is written, the script asserts the
# temp clone holds nothing but `.git` and `.github`, and abandons that repo if
# it does. It then asserts the resulting commit touches exactly one path.
# Nothing here runs npm or node, and nothing executes a file that came out of
# a scanned repo.
#
# WHY SSH RATHER THAN THE CONTENTS API
#
# Writing a file under `.github/workflows/` through the REST Contents API
# requires a token carrying the `workflow` scope; `gh auth login` does not
# grant it by default (this owner's token is `admin:org, gist, repo`), and
# minting a token that may rewrite workflows across 55 repos is a much bigger
# capability than this job needs. Git-over-SSH has no such restriction -- the
# push is an ordinary ref update authenticated by the SSH key. So the file
# goes in over SSH, and only read-only metadata goes over the API.
#
# IDEMPOTENCY
#
# The rendered caller is byte-stable (see tools/render-caller.py). Its git
# blob SHA-1 is compared against the `sha` GitHub reports for the file already
# on the default branch -- the Contents API's `sha` field *is* the blob SHA-1,
# so `git hash-object` of the rendering is directly comparable. Identical =>
# the repo is skipped without being cloned at all. Re-running the whole
# rollout is therefore cheap and safe, which matters because
# .github/workflows/org-coverage.yml exists to tell you to re-run it whenever
# a new repo appears.
# ---------------------------------------------------------------------------

set -euo pipefail

# Never let git stop for a credential prompt in the middle of a 55-repo loop.
export GIT_TERMINAL_PROMPT=0

PROG="$(basename "$0")"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TEMPLATE="$REPO_ROOT/.github/workflows/caller-template.yml"
RENDERER="$HERE/render-caller.py"

TAB=$'\t'
WF_PATH=".github/workflows/malware-scan.yml"
SCANNER_REPO_NAME="security-scan"

DEFAULT_USES="gbsimon/security-scan/.github/workflows/malware-scan.yml@main"
DEFAULT_FAIL_ON="HIGH"

# Trusted authors are NOT baked into this script. They are real people's email
# addresses, and this script lives in a public repository. They are read, in
# order, from:
#   1. --trusted-authors "a@b,c@d"
#   2. --trusted-authors-file <path>
#   3. $TRUSTED_AUTHORS_DIR/<owner>   (see below)
#   4. nothing -- and the run warns loudly, because every author in every repo
#      will then be reported as unknown.
# The per-owner file is one address per line, '#' starts a comment.
TRUSTED_AUTHORS_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/security-scan/trusted-authors.d"
DEFAULT_BRANCH_NAME="chore/malware-scan"

COMMIT_SUBJECT="ci: add malware-scan (EtherHiding/JADESNOW) workflow"
# Squash-merge subject. The [skip ci] tag matters: most of these repos deploy
# on a push to their default branch, and merging ~100 PRs would otherwise
# trigger ~100 production redeploys of unrelated projects in a few minutes --
# for a change that touches nothing but .github/workflows/. GitHub Actions
# honours [skip ci] in the head commit message and skips push-triggered runs;
# the malware-scan schedule and --dispatch still run, so the scan is not
# skipped, only the redeploy storm.
MERGE_SUBJECT="ci: add malware-scan workflow [skip ci]"
WORKFLOW_FILE="malware-scan.yml"
# Seconds between --dispatch retries; a freshly merged workflow takes a few
# seconds to register before `gh workflow run` can find it.
DISPATCH_SLEEP="${ROLLOUT_DISPATCH_SLEEP:-10}"
DISPATCH_TRIES=3
PR_TITLE="ci: add malware-scan (EtherHiding/JADESNOW) workflow"
SESSION_TRAILER="Claude-Session: https://claude.ai/code/session_01WDEJd63rzv5saGia9KjYmP"

OWNER=""
USES="$DEFAULT_USES"
REPOS_CSV=""
ALL=0
INCLUDE_ARCHIVED=0
INCLUDE_FORKS=0
DRY_RUN=0
TRUSTED=""
TRUSTED_SET=0
TRUSTED_FILE=""
TRUSTED_SOURCE=""
FAIL_ON="$DEFAULT_FAIL_ON"
BRANCH="$DEFAULT_BRANCH_NAME"
MERGE=0
DISPATCH=0
NO_SIGN=0
REMOTE_BASE=""   # undocumented test override: URLs become <base>/<repo>.git
USE_GH=1         # undocumented test override: --no-gh skips every gh call

WORKDIR=""

usage() {
  cat <<'USAGE'
rollout.sh -- roll the malware-scan caller workflow out across an owner's repos.

Usage:
  tools/rollout.sh --owner <org-or-user> [--all | --repos a,b,c] [options]

Selecting repositories:
  --owner <name>          GitHub org OR user account. Required. Both work:
                          every API this script uses (repo list, repo view,
                          contents, pr) is owner-kind agnostic.
  --all                   Every repo of that owner (gh repo list, limit 500).
                          Archived repos and forks are skipped by default, and
                          the security-scan repo itself is always skipped.
  --repos a,b,c           Explicit comma-separated repo names instead.
  --include-archived      Do not skip archived repos.
  --include-forks         Do not skip forks.

What gets written:
  --uses <ref>            Reusable-workflow ref the caller points at. Default:
                          gbsimon/security-scan/.github/workflows/malware-scan.yml@main
                          (public -- callers need no token at all)
  --trusted-authors <csv> Author emails expected in these repos. Everyone else
                          is reported at MEDIUM (non-blocking) on purpose.
  --trusted-authors-file <path>
                          Read them from a file instead: one address per line,
                          '#' starts a comment.
                          With neither flag, the list is read from
                          $XDG_CONFIG_HOME/security-scan/trusted-authors.d/<owner>
                          (default ~/.config/...), which is deliberately
                          outside this repository -- these are real people's
                          addresses and this repo is public. With no list at
                          all the rollout still works, but every commit author
                          in every repo is reported as unknown, so it says so
                          loudly.
  --fail-on <severity>    Severity that fails a scan. Default: HIGH.

How it is delivered:
  --branch <name>         Branch to push. Default: chore/malware-scan.
  --merge                 After opening each PR, squash-merge it. Tries
                          --auto first and falls back to an immediate merge,
                          because auto-merge is not available on GitHub Free.
                          The squash commit is titled
                          "ci: add malware-scan workflow [skip ci]" so that
                          merging does not trigger a deploy in every repo that
                          builds on push to its default branch.
  --dispatch              After a repo is merged (or was already current),
                          run the malware-scan workflow once immediately, so
                          the first full-history sweep happens now instead of
                          at the next 06:17 UTC schedule. Retries a few times:
                          a just-merged workflow takes a moment to register.
  --no-sign               Do not sign the commits. Otherwise your global
                          commit.gpgsign applies -- signing 55 commits through
                          1Password means 55 approval prompts.
  --dry-run               Print the plan and the rendered workflow, then stop.
                          Lists repos (read-only) but never clones or pushes.
  -h, --help              This text.

Exit status: 0 if every selected repo succeeded, 1 if any failed. Re-running
is safe: repos that already have the exact file are skipped without cloning.

Coverage over time is reported by .github/workflows/org-coverage.yml in
security-scan, which opens an issue naming the repos still missing the
workflow -- and the exact rollout.sh command to fix them.
USAGE
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 2; }
info() { printf '%s\n' "$*" >&2; }

cleanup() {
  if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then rm -rf "$WORKDIR"; fi
  return 0
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --owner)            [ $# -ge 2 ] || die "--owner needs a value"; OWNER="$2"; shift 2 ;;
    --uses)             [ $# -ge 2 ] || die "--uses needs a value"; USES="$2"; shift 2 ;;
    --repos)            [ $# -ge 2 ] || die "--repos needs a value"; REPOS_CSV="$2"; shift 2 ;;
    --all)              ALL=1; shift ;;
    --include-archived) INCLUDE_ARCHIVED=1; shift ;;
    --include-forks)    INCLUDE_FORKS=1; shift ;;
    --dry-run)          DRY_RUN=1; shift ;;
    --trusted-authors)  [ $# -ge 2 ] || die "--trusted-authors needs a value"; TRUSTED="$2"; TRUSTED_SET=1; shift 2 ;;
    --trusted-authors-file) [ $# -ge 2 ] || die "--trusted-authors-file needs a value"; TRUSTED_FILE="$2"; shift 2 ;;
    --fail-on)          [ $# -ge 2 ] || die "--fail-on needs a value"; FAIL_ON="$2"; shift 2 ;;
    --branch)           [ $# -ge 2 ] || die "--branch needs a value"; BRANCH="$2"; shift 2 ;;
    --merge)            MERGE=1; shift ;;
    --dispatch)         DISPATCH=1; shift ;;
    --no-sign)          NO_SIGN=1; shift ;;
    --remote-base)      [ $# -ge 2 ] || die "--remote-base needs a value"; REMOTE_BASE="$2"; shift 2 ;;
    --no-gh)            USE_GH=0; shift ;;
    -h|--help)          usage; exit 0 ;;
    *)                  die "unknown argument: $1 (try --help)" ;;
  esac
done

[ -n "$OWNER" ] || die "--owner is required (try --help)"
if [ "$ALL" -eq 0 ] && [ -z "$REPOS_CSV" ]; then die "pass --all or --repos a,b,c"; fi
if [ "$ALL" -eq 1 ] && [ -n "$REPOS_CSV" ]; then die "--all and --repos are mutually exclusive"; fi
[ -f "$TEMPLATE" ] || die "template not found: $TEMPLATE"
[ -f "$RENDERER" ] || die "renderer not found: $RENDERER"
command -v git >/dev/null 2>&1 || die "git is not on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 is not on PATH"
if [ "$USE_GH" -eq 1 ]; then
  command -v gh >/dev/null 2>&1 || die "gh is not on PATH (or pass --no-gh)"
fi

case "$FAIL_ON" in
  INFO|LOW|MEDIUM|HIGH|CRITICAL) ;;
  *) die "--fail-on must be one of INFO LOW MEDIUM HIGH CRITICAL" ;;
esac

# --- resolve the trusted-author list ------------------------------------
# One address per line, '#' comments and blanks dropped, joined with commas.
read_trusted_file() {
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$1" \
    | grep -v '^$' \
    | paste -sd, -
}

if [ "$TRUSTED_SET" -eq 1 ]; then
  TRUSTED_SOURCE="--trusted-authors"
elif [ -n "$TRUSTED_FILE" ]; then
  [ -r "$TRUSTED_FILE" ] || die "cannot read --trusted-authors-file: $TRUSTED_FILE"
  TRUSTED="$(read_trusted_file "$TRUSTED_FILE")"
  TRUSTED_SOURCE="$TRUSTED_FILE"
elif [ -r "$TRUSTED_AUTHORS_DIR/$OWNER" ]; then
  TRUSTED="$(read_trusted_file "$TRUSTED_AUTHORS_DIR/$OWNER")"
  TRUSTED_SOURCE="$TRUSTED_AUTHORS_DIR/$OWNER"
else
  TRUSTED=""
  TRUSTED_SOURCE="none"
fi

# Safe git: no repo-local hook, no fsmonitor daemon, no detached-HEAD noise.
GIT_SAFE_OPTS=( -c core.hooksPath=/dev/null
                -c core.fsmonitor=false
                -c advice.detachedHead=false )
if [ "$NO_SIGN" -eq 1 ]; then
  GIT_SAFE_OPTS=( "${GIT_SAFE_OPTS[@]}" -c commit.gpgsign=false )
fi

sgit() { command git "${GIT_SAFE_OPTS[@]}" "$@"; }

# --------------------------------------------------------------------------
# Render the caller once. Every repo gets these exact bytes.
# --------------------------------------------------------------------------

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/malware-scan-rollout.XXXXXXXX")"
RENDER_FILE="$WORKDIR/malware-scan.yml"

python3 "$RENDERER" \
  --template "$TEMPLATE" \
  --uses "$USES" \
  --trusted-authors "$TRUSTED" \
  --fail-on "$FAIL_ON" \
  --out "$RENDER_FILE" \
  || die "could not render the caller workflow"

RENDER_SHA="$(sgit hash-object "$RENDER_FILE")"

# The scanner repo is never a caller of itself.
SCANNER_OWNER_REPO="${USES%%/.github/workflows/*}"

# --------------------------------------------------------------------------
# Repository discovery
# --------------------------------------------------------------------------

git_url() {
  if [ -n "$REMOTE_BASE" ]; then
    # file:// rather than a bare path: git silently ignores partial-clone
    # filters on the local transport, and we want --filter=blob:none honoured.
    printf 'file://%s/%s.git' "$REMOTE_BASE" "$1"
  else
    printf 'git@github.com:%s/%s.git' "$OWNER" "$1"
  fi
}

remote_default_branch() {
  local ref
  ref="$(sgit ls-remote --symref "$(git_url "$1")" HEAD 2>/dev/null \
          | awk '$1 == "ref:" { print $2; exit }')" || true
  # "-" rather than "" -- see the NOTE above list_repos.
  if [ -z "${ref:-}" ]; then
    printf '%s' "-"
  else
    printf '%s' "${ref#refs/heads/}"
  fi
}

# Emits TSV: name, isArchived, isFork, defaultBranch, visibility
#
# NOTE: a missing default branch is emitted as "-", never as an empty field.
# Tab is an IFS *whitespace* character, so `while IFS=$'\t' read -r a b c d e`
# collapses a run of tabs into one delimiter and every later column shifts
# left. An empty repository has `defaultBranchRef.name == ""` and did
# exactly that: it came out with its *visibility* as its default branch.
# Keep every field non-empty.
list_repos() {
  local name d
  if [ "$ALL" -eq 1 ]; then
    if [ "$USE_GH" -eq 1 ]; then
      gh repo list "$OWNER" --limit 500 \
        --json name,isArchived,isFork,defaultBranchRef,visibility \
        --jq '.[] | [.name,
                     (.isArchived|tostring),
                     (.isFork|tostring),
                     (if (.defaultBranchRef.name // "") == "" then "-"
                      else .defaultBranchRef.name end),
                     (.visibility // "UNKNOWN")] | @tsv'
    else
      [ -n "$REMOTE_BASE" ] || die "--all with --no-gh needs --remote-base"
      for d in "$REMOTE_BASE"/*.git; do
        [ -d "$d" ] || continue
        name="$(basename "$d" .git)"
        printf '%s\tfalse\tfalse\t%s\tLOCAL\n' \
               "$name" "$(remote_default_branch "$name")"
      done
    fi
  else
    # printf '%s\n' -- with no trailing newline the last field is an
    # unterminated line and `read` drops it.
    printf '%s\n' "$REPOS_CSV" | tr ',' '\n' | while IFS= read -r name; do
      name="$(printf '%s' "$name" | tr -d '[:space:]')"
      [ -n "$name" ] || continue
      if [ "$USE_GH" -eq 1 ]; then
        gh repo view "$OWNER/$name" \
          --json name,isArchived,isFork,defaultBranchRef,visibility \
          --jq '[.name,
                 (.isArchived|tostring),
                 (.isFork|tostring),
                 (if (.defaultBranchRef.name // "") == "" then "-"
                  else .defaultBranchRef.name end),
                 (.visibility // "UNKNOWN")] | @tsv' \
          2>/dev/null \
          || printf '%s\tfalse\tfalse\t-\tUNREADABLE\n' "$name"
      else
        printf '%s\tfalse\tfalse\t%s\tLOCAL\n' \
               "$name" "$(remote_default_branch "$name")"
      fi
    done
  fi
}

# --------------------------------------------------------------------------
# Per-repo work
# --------------------------------------------------------------------------

# Blob SHA of $WF_PATH on <branch>, or "" if absent / not askable.
remote_blob_sha() {
  if [ "$USE_GH" -eq 0 ]; then printf ''; return 0; fi
  gh api "repos/$OWNER/$1/contents/$WF_PATH?ref=$2" --jq '.sha' 2>/dev/null \
    || printf ''
}

pr_body() {
  cat <<BODY
Adds \`$WF_PATH\`, a thin caller for the reusable workflow
\`$USES\`.

### What it does

| Trigger | Check |
|---|---|
| every push and PR | scans the working tree for the EtherHiding / JADESNOW implant, hostile \`package.json\` lifecycle scripts, \`.npmrc\` tricks and hijacked git hooks -- plus commit forensics on the pushed range: backdating, out-of-order author dates, unexpected authors, force-pushes |
| daily, 06:17 UTC | sweeps **every reachable git object** -- branches, tags, reflog -- so a payload that was committed and later "cleaned" off the tip is still found |

The scanner is Python-3 stdlib and **reads bytes**. It never installs, imports
or executes anything it scans, and it never runs a package manager. There is
no \`npm install\` anywhere in this workflow.

### Expect the first runs to be green

This is a safety net being installed after the incident, not a report of a new
one. The affected repos had their \`main\` history rebuilt on 2026-08-20, so a
clean first scheduled run is the expected result -- not a sign the scan is
misconfigured.

### Trusted-author policy

\`trusted_authors\` is the same list in every repo:

\`\`\`
$TRUSTED
\`\`\`

A commit from anyone else is reported at **MEDIUM**, which is deliberate and
**does not fail the build** (\`fail_on: $FAIL_ON\`). It is a prompt to look, not
an accusation -- the 2026-08 compromise arrived through a contributor account,
so "an author I did not expect touched a build config" is exactly the signal
worth surfacing. When someone legitimate turns up in that list, add them to
the rollout's \`--trusted-authors\` and re-run it, rather than silencing the
rule in one repo.

### Prerequisites (already done at org level)

- \`security-scan\` -> Settings -> Actions -> General -> Access -> *accessible
  from repositories in the organization*, without which callers fail with
  "workflow was not found".
- Org secret \`SCANNER_TOKEN\` (fine-grained PAT, read-only Contents on
  \`security-scan\`), passed through by \`secrets: inherit\`. The built-in
  \`GITHUB_TOKEN\` cannot read a different private repo.

### If it ever fires

**Do not build, do not \`npm install\`, do not open the project in a dev
server** -- the payload runs at build time, so "just having a look" is the
infection. Follow \`docs/RUNBOOK.md\` in \`security-scan\`.

This file is generated by \`tools/rollout.sh\`; re-running the rollout restores
it byte-for-byte if it is edited by hand.
BODY
}

commit_message() {
  cat <<MSG
$COMMIT_SUBJECT

Calls the reusable scanner in $SCANNER_OWNER_REPO on every push and PR, plus a
daily sweep of all reachable git objects. Defensive response to the 2026-08
EtherHiding / JADESNOW supply-chain compromise.

Generated by tools/rollout.sh from .github/workflows/caller-template.yml.

$SESSION_TRAILER
MSG
}

# dispatch_scan <name> <branch> -- kick off the malware-scan workflow now.
# A workflow file that has only just landed on the default branch is not
# immediately dispatchable: GitHub needs a moment to register it, and until it
# does `gh workflow run` fails with "could not find any workflows named ...".
# Retry rather than report a false failure.
dispatch_scan() {
  local name="$1" branch="$2" try=1
  [ "$USE_GH" -eq 1 ] || { printf 'no-gh'; return 0; }
  while [ "$try" -le "$DISPATCH_TRIES" ]; do
    if gh workflow run "$WORKFLOW_FILE" -R "$OWNER/$name" --ref "$branch" \
         >/dev/null 2>&1; then
      printf 'dispatched'
      return 0
    fi
    if [ "$try" -lt "$DISPATCH_TRIES" ] && [ "$DISPATCH_SLEEP" -gt 0 ]; then
      sleep "$DISPATCH_SLEEP"
    fi
    try=$((try + 1))
  done
  printf 'dispatch-failed'
  return 1
}

# process_repo <name> <default-branch>
# Prints one TSV result row on stdout. Fails the repo, never the run.
process_repo() {
  local name="$1" base="$2"
  local url tmp existing_sha action pr_url ls_out changed push_ok
  local branch_sha branch_blob branch_current merged_now

  url="$(git_url "$name")"
  tmp="$WORKDIR/clone"
  rm -rf "$tmp"

  # ---- cheap path: already byte-identical, so never clone at all -------
  existing_sha="$(remote_blob_sha "$name" "$base")"
  if [ -n "$existing_sha" ] && [ "$existing_sha" = "$RENDER_SHA" ]; then
    action="skipped-identical"
    if [ "$DISPATCH" -eq 1 ]; then
      action="$action+$(dispatch_scan "$name" "$base" || true)"
    fi
    printf '%s\t%s\t%s\n' "$name" "$action" "-"
    return 0
  fi

  # ---- safe clone: empty worktree, no project blobs fetched ------------
  if ! {
        sgit clone --quiet --no-checkout --depth 1 --filter=blob:none \
             --single-branch --branch "$base" "$url" "$tmp" &&
        sgit -C "$tmp" sparse-checkout set --no-cone '/.github/workflows/' &&
        sgit -C "$tmp" checkout --quiet "$base"
      } >/dev/null 2>&1; then
    info "    clone/sparse-checkout failed"
    rm -rf "$tmp"
    printf '%s\t%s\t%s\n' "$name" "failed" "-"
    return 1
  fi

  # ---- assert the safety property before writing anything -------------
  # Printed, not merely asserted: this one line is the evidence that no file
  # from the scanned repo was ever written to this machine.
  ls_out="$(ls -A "$tmp" | sort | tr '\n' ' ')"
  info "    worktree materialised: [${ls_out}]"
  case "$ls_out" in
    ".git "|".git .github ") : ;;
    *)
      info "    ABORT: sparse checkout materialised more than .git/.github:"
      info "           [$ls_out]"
      rm -rf "$tmp"
      printf '%s\t%s\t%s\n' "$name" "failed" "-"
      return 1 ;;
  esac

  # ---- second chance at idempotency -----------------------------------
  # --no-gh has no API to ask, and the API answer can be stale behind a
  # just-merged PR.
  if [ -f "$tmp/$WF_PATH" ]; then
    if [ "$(sgit hash-object "$tmp/$WF_PATH")" = "$RENDER_SHA" ]; then
      rm -rf "$tmp"
      action="skipped-identical"
      if [ "$DISPATCH" -eq 1 ]; then
        action="$action+$(dispatch_scan "$name" "$base" || true)"
      fi
      printf '%s\t%s\t%s\n' "$name" "$action" "-"
      return 0
    fi
    action="updated"
  else
    action="created"
  fi

  # ---- has a previous run already prepared the branch? ----------------
  # Without this, re-running the rollout force-pushes an identical tree to
  # every unmerged branch and churns 55 open PRs for nothing.
  branch_current=0
  branch_sha="$(sgit -C "$tmp" ls-remote origin "refs/heads/$BRANCH" 2>/dev/null \
                | awk 'NR == 1 { print $1 }')"
  if [ -n "${branch_sha:-}" ]; then
    if sgit -C "$tmp" fetch --quiet --depth 1 origin \
         "+refs/heads/$BRANCH:refs/remotes/origin/rollout-branch" \
         >/dev/null 2>&1; then
      # blob:none still fetches trees, so this resolves without the content.
      branch_blob="$(sgit -C "$tmp" rev-parse -q --verify \
                       "refs/remotes/origin/rollout-branch:$WF_PATH" \
                       2>/dev/null || printf '')"
      if [ "${branch_blob:-}" = "$RENDER_SHA" ]; then branch_current=1; fi
    fi
  fi

  if [ "$branch_current" -eq 1 ]; then
    info "    $BRANCH already carries these exact bytes; not pushing again"
    action="branch-current"
  else

    mkdir -p "$tmp/.github/workflows"
    cp "$RENDER_FILE" "$tmp/$WF_PATH"

    if ! sgit -C "$tmp" checkout --quiet -b "$BRANCH" >/dev/null 2>&1; then
      info "    could not create branch $BRANCH"
      rm -rf "$tmp"; printf '%s\t%s\t%s\n' "$name" "failed" "-"; return 1
    fi
    if ! sgit -C "$tmp" add -- "$WF_PATH" >/dev/null 2>&1; then
      info "    git add failed"
      rm -rf "$tmp"; printf '%s\t%s\t%s\n' "$name" "failed" "-"; return 1
    fi
    if ! commit_message | sgit -C "$tmp" commit --quiet -F - >/dev/null 2>&1; then
      info "    commit failed (git identity? signing key? try --no-sign)"
      rm -rf "$tmp"; printf '%s\t%s\t%s\n' "$name" "failed" "-"; return 1
    fi

    # ---- assert the commit is a one-file change -------------------------
    changed="$(sgit -C "$tmp" show --pretty=format: --name-status HEAD \
               | sed '/^[[:space:]]*$/d')"
    if [ "$changed" != "A${TAB}${WF_PATH}" ] \
       && [ "$changed" != "M${TAB}${WF_PATH}" ]; then
      info "    ABORT: commit touched more than $WF_PATH: [$changed]"
      rm -rf "$tmp"; printf '%s\t%s\t%s\n' "$name" "failed" "-"; return 1
    fi

    # ---- push --------------------------------------------------------
    # If the branch already exists we overwrite it, but only under an explicit
    # lease naming the SHA we just observed -- so a concurrent push by someone
    # else is rejected rather than clobbered. The bare `--force-with-lease`
    # form cannot be used here: this is a fresh single-branch clone with no
    # remote-tracking ref for $BRANCH, and git refuses the lease without one.
    push_ok=0
    if [ -n "${branch_sha:-}" ]; then
      if sgit -C "$tmp" push --quiet \
           --force-with-lease="$BRANCH:$branch_sha" -u origin "$BRANCH" \
           >/dev/null 2>&1; then push_ok=1; fi
    else
      if sgit -C "$tmp" push --quiet -u origin "$BRANCH" >/dev/null 2>&1; then
        push_ok=1
      fi
    fi
    if [ "$push_ok" -ne 1 ]; then
      info "    push failed (branch moved under us? re-run to retry)"
      rm -rf "$tmp"; printf '%s\t%s\t%s\n' "$name" "failed" "-"; return 1
    fi

  fi

  # ---- pull request ---------------------------------------------------
  if [ "$USE_GH" -eq 1 ]; then
    pr_url="$(gh pr list --repo "$OWNER/$name" --head "$BRANCH" --state open \
                --json url --jq '.[0].url // ""' 2>/dev/null || printf '')"
    if [ -z "$pr_url" ]; then
      pr_url="$(pr_body | gh pr create --repo "$OWNER/$name" \
                  --base "$base" --head "$BRANCH" \
                  --title "$PR_TITLE" --body-file - 2>/dev/null \
                | tail -n 1 || printf '')"
    fi
    if [ -z "$pr_url" ]; then
      info "    branch pushed but PR creation failed -- open it by hand"
      rm -rf "$tmp"
      printf '%s\t%s\t%s\n' "$name" "$action" "PUSHED-NO-PR"
      return 1
    fi
    if [ "$MERGE" -eq 1 ]; then
      # Auto-merge is a paid feature, and an immediate merge is refused while
      # required checks are still running -- so try both, then give up
      # quietly and leave the PR open rather than fail the repo.
      merged_now=0
      if gh pr merge "$pr_url" --squash --delete-branch --auto \
           --subject "$MERGE_SUBJECT" >/dev/null 2>&1; then
        # Queued, not merged: the workflow is not on the default branch yet,
        # so there is nothing to dispatch.
        action="$action+auto-merge"
      elif gh pr merge "$pr_url" --squash --delete-branch \
             --subject "$MERGE_SUBJECT" >/dev/null 2>&1; then
        action="$action+merged"
        merged_now=1
      else
        action="$action+merge-deferred"
      fi
      if [ "$DISPATCH" -eq 1 ]; then
        if [ "$merged_now" -eq 1 ]; then
          action="$action+$(dispatch_scan "$name" "$base" || true)"
        else
          action="$action+dispatch-deferred"
        fi
      fi
    elif [ "$DISPATCH" -eq 1 ]; then
      # Without --merge the workflow is still only on the PR branch.
      action="$action+dispatch-deferred"
    fi
  else
    pr_url="(--no-gh: no PR opened)"
  fi

  rm -rf "$tmp"
  printf '%s\t%s\t%s\n' "$name" "$action" "$pr_url"
  return 0
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

info "$PROG"
info "  owner            : $OWNER"
info "  uses             : $USES"
info "  fail_on          : $FAIL_ON"
info "  branch           : $BRANCH"
info "  workflow path    : $WF_PATH"
info "  rendered blob sha: $RENDER_SHA"
N_TRUSTED="$(printf '%s' "$TRUSTED" | tr ',' '\n' | grep -c . || true)"
info "  trusted authors  : ${N_TRUSTED:-0} addresses (from $TRUSTED_SOURCE)"
if [ "${N_TRUSTED:-0}" -eq 0 ]; then
  info ""
  info "  !! WARNING: no trusted authors."
  info "  !! Every commit author in every scanned repo will be reported as"
  info "  !! COMMIT-AUTHOR-UNKNOWN (MEDIUM, non-blocking) -- which is noise,"
  info "  !! not signal, and it will bury a real unexpected author."
  info "  !! Create $TRUSTED_AUTHORS_DIR/$OWNER"
  info "  !! with one address per line, or pass --trusted-authors."
  info ""
fi
if [ "$MERGE" -eq 1 ];   then info "  merge            : yes (squash: $MERGE_SUBJECT)"; fi
if [ "$DISPATCH" -eq 1 ]; then info "  dispatch         : yes ($WORKFLOW_FILE, after merge)"; fi
if [ "$DRY_RUN" -eq 1 ]; then info "  DRY RUN          : nothing cloned, written or pushed"; fi
info ""

info "Listing repositories for $OWNER..."
REPO_TSV="$WORKDIR/repos.tsv"
SELECTED_TSV="$WORKDIR/selected.tsv"
list_repos > "$REPO_TSV" || die "could not list repositories for $OWNER"
: > "$SELECTED_TSV"

n_selected=0
n_excluded=0
EXCLUDED_TXT="$WORKDIR/excluded.txt"
: > "$EXCLUDED_TXT"

while IFS="$TAB" read -r name archived fork defbranch visibility; do
  [ -n "${name:-}" ] || continue
  reason=""
  if [ "$name" = "$SCANNER_REPO_NAME" ] \
     || [ "$OWNER/$name" = "$SCANNER_OWNER_REPO" ]; then
    reason="the scanner repo itself"
  elif [ "${archived:-false}" = "true" ] && [ "$INCLUDE_ARCHIVED" -eq 0 ]; then
    reason="archived"
  elif [ "${fork:-false}" = "true" ] && [ "$INCLUDE_FORKS" -eq 0 ]; then
    reason="fork"
  elif [ -z "${defbranch:-}" ] || [ "$defbranch" = "-" ]; then
    reason="empty repository"
  fi
  if [ -n "$reason" ]; then
    printf '  - %s (%s)\n' "$name" "$reason" >> "$EXCLUDED_TXT"
    n_excluded=$((n_excluded + 1))
    continue
  fi
  printf '%s\t%s\t%s\n' "$name" "$defbranch" "${visibility:-UNKNOWN}" \
    >> "$SELECTED_TSV"
  n_selected=$((n_selected + 1))
done < "$REPO_TSV"

info "  $n_selected selected, $n_excluded skipped"
if [ "$n_excluded" -gt 0 ]; then
  info ""
  info "Skipped:"
  cat "$EXCLUDED_TXT" >&2
fi

info ""
info "Plan ($n_selected repositories, workflow -> $WF_PATH):"
while IFS="$TAB" read -r name defbranch visibility; do
  [ -n "${name:-}" ] || continue
  info "  $OWNER/$name  (default branch: $defbranch, $visibility)"
done < "$SELECTED_TSV"

if [ "$DRY_RUN" -eq 1 ]; then
  info ""
  info "Rendered $WF_PATH -- identical in every repo, blob $RENDER_SHA:"
  info "--------------------------------------------------------------------"
  cat "$RENDER_FILE"
  info "--------------------------------------------------------------------"
  info ""
  info "Dry run: no clone, no commit, no push, no PR. Drop --dry-run to apply."
  exit 0
fi

if [ "$n_selected" -eq 0 ]; then info "Nothing to do."; exit 0; fi

info ""
info "Applying..."
RESULTS="$WORKDIR/results.tsv"
: > "$RESULTS"
failures=0

# Read from a file, not a pipeline: a `while read` fed by a pipe runs in a
# subshell and would lose the `failures` counter.
while IFS="$TAB" read -r name defbranch visibility; do
  [ -n "${name:-}" ] || continue
  info "  $OWNER/$name ($defbranch)"
  if process_repo "$name" "$defbranch" >> "$RESULTS"; then
    :
  else
    failures=$((failures + 1))
  fi
done < "$SELECTED_TSV"

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

info ""
printf '%-34s  %-26s  %s\n' "REPO" "ACTION" "PR"
printf '%-34s  %-26s  %s\n' \
  "----------------------------------" "--------------------------" "--"
while IFS="$TAB" read -r name action pr; do
  [ -n "${name:-}" ] || continue
  printf '%-34s  %-26s  %s\n' "$name" "$action" "$pr"
done < "$RESULTS"
printf '\n'

count_action() {
  awk -F'\t' -v want="$1" '$2 ~ ("^" want) { n++ } END { print n + 0 }' \
      "$RESULTS"
}
printf 'created: %s   updated: %s   already current: %s   branch already open: %s   failed: %s\n' \
       "$(count_action created)" "$(count_action updated)" \
       "$(count_action skipped-identical)" "$(count_action branch-current)" \
       "$failures"

if [ "$failures" -gt 0 ]; then
  printf '\n%s: %d repositories failed; re-running retries just those.\n' \
         "$PROG" "$failures" >&2
  exit 1
fi
exit 0
