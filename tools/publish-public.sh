#!/usr/bin/env bash
#
# publish-public.sh -- publish the sanitized scanner as a PUBLIC repository.
#
#   tools/publish-public.sh [--repo gbsimon/security-scan] [--dry-run]
#
# WHY AN ORPHAN COMMIT, NOT A PUSH OF THIS HISTORY
#
# This repository's history still contains the two real JADESNOW samples: they
# were fixtures until they were removed, so they live in commit e88eea9 and
# every commit between it and their removal. `git push` publishes objects, not
# just the tip -- pushing this branch would publish the malware. So the public
# repository gets a single ORPHAN commit built from the current, sanitized
# working tree, with no parent and therefore no reachable history.
#
# The private repository stays where it is. It remains the incident record:
# the evidence, the ticket history, and the commits that show what was
# actually done. Only the *tool* becomes public. See docs/MULTI-ORG.md.
#
# WHAT IT REFUSES TO DO
#
#   * publish with a dirty working tree (the orphan commit is built from the
#     tree, so anything uncommitted would be published unreviewed);
#   * publish if tools/verify-no-samples.py finds a byte window of a real
#     sample anywhere in the tree, or in the orphan commit it just built;
#   * publish if that check cannot run at all -- a check that did not run is
#     not a clean result, so a missing evidence volume is a hard stop, not a
#     warning;
#   * push anything to `origin`. It pushes only to the `public` remote, and
#     refuses if that remote resolves to the same URL as origin.
#
# It asks before every step that changes anything, locally or remotely.

set -euo pipefail
export GIT_TERMINAL_PROMPT=0

PROG="$(basename "$0")"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

PUBLIC_REPO="gbsimon/security-scan"
PUBLIC_REMOTE="public"
ORPHAN_BRANCH="public-main"
TARGET_BRANCH="main"
DESCRIPTION="Defensive scanner for the EtherHiding / JADESNOW supply-chain implant (DPRK UNC5342). Python 3 stdlib, reads bytes, executes nothing."
DRY_RUN=0
SAMPLES=""
ALLOW_DISCLOSURES=0

# The list of strings that must not reach a public repository -- client and
# org names, the people involved, the attacker identifiers -- is itself a list
# of those exact strings. Keeping it in this file would publish the very thing
# it guards, and because the gate used to exclude this script from its own
# scan, it did so invisibly. So the patterns live outside the repository:
#
#   ${XDG_CONFIG_HOME:-$HOME/.config}/security-scan/disclosure-patterns
#
# One extended regular expression per line, '#' starts a comment, matched
# case-insensitively. See examples/disclosure-patterns.example for the shape.
# Missing file => refuse to publish: a gate that cannot run is not a pass.
DISCLOSURE_PATTERNS_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/security-scan/disclosure-patterns"


die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 2; }
say() { printf '%s\n' "$*"; }

confirm() {
  local reply
  printf '\n%s [y/N] ' "$1"
  read -r reply || reply=""
  case "$reply" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) say "Aborted."; exit 1 ;;
  esac
}

usage() {
  cat <<'USAGE'
publish-public.sh -- publish the sanitized scanner as a public repository.

  --repo <owner/name>   Public repository to create/push to.
                        Default: gbsimon/security-scan
  --samples <dir>       Evidence directory for the no-samples check.
                        Default: the backup volume path baked into
                        tools/verify-no-samples.py.
  --dry-run             Print the plan and run the safety checks, then stop.
  --allow-disclosures   Publish even though victim-identifying or personal
                        strings were found -- or none could be checked for.
                        Off by default: the check is a HARD GATE, because a
                        name published once is published for good.
  --disclosure-patterns <file>
                        Patterns to refuse to publish, one extended regex per
                        line, '#' for comments. Default:
                        ~/.config/security-scan/disclosure-patterns
                        (kept outside this repo: the list is made of the very
                        strings it exists to keep out). Template:
                        examples/disclosure-patterns.example
  -h, --help            This text.

Publishing is one-way in practice: once these bytes are on github.com they are
cloned, cached and indexed. Read the plan it prints.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)    [ $# -ge 2 ] || die "--repo needs a value"; PUBLIC_REPO="$2"; shift 2 ;;
    --samples) [ $# -ge 2 ] || die "--samples needs a value"; SAMPLES="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --allow-disclosures) ALLOW_DISCLOSURES=1; shift ;;
    --disclosure-patterns) [ $# -ge 2 ] || die "--disclosure-patterns needs a value"; DISCLOSURE_PATTERNS_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

command -v git >/dev/null 2>&1 || die "git is not on PATH"
command -v gh  >/dev/null 2>&1 || die "gh is not on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 is not on PATH"
cd "$REPO_ROOT"

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
PUBLIC_URL="git@github.com:${PUBLIC_REPO}.git"
ORIGIN_URL="$(git remote get-url origin 2>/dev/null || printf '')"

say "$PROG"
say "  source tree      : $REPO_ROOT"
say "  current branch   : $CURRENT_BRANCH"
say "  origin           : ${ORIGIN_URL:-(none)}"
say "  public repo      : $PUBLIC_REPO"
say "  public url       : $PUBLIC_URL"
say "  orphan branch    : $ORPHAN_BRANCH  ->  ${PUBLIC_REMOTE}/${TARGET_BRANCH}"
say ""
say "Plan:"
say "  1. refuse if the working tree is dirty"
say "  2. tools/verify-no-samples.py over the working tree  (hard gate)"
say "  3. scan for victim-identifying / personal strings    (hard gate)"
say "  4. git checkout --orphan $ORPHAN_BRANCH && git add -A && commit"
say "  5. tools/verify-no-samples.py over $ORPHAN_BRANCH's tree (hard gate)"
say "  6. create $PUBLIC_REPO if it does not exist (gh repo create --public)"
say "  7. push $ORPHAN_BRANCH to ${PUBLIC_REMOTE}:${TARGET_BRANCH}"
say "  8. return to $CURRENT_BRANCH"
say ""
say "It never pushes to origin, and never touches the private history."

if [ "$ORIGIN_URL" = "$PUBLIC_URL" ]; then
  die "origin and the public URL are the same repository. Refusing."
fi

# ---- 1. clean tree ------------------------------------------------------
if [ -n "$(git status --porcelain)" ]; then
  say ""
  git status --short
  die "working tree is not clean. Commit or stash first: the orphan commit is
     built from the tree, so anything here would be published unreviewed."
fi
say ""
say "[1/8] working tree is clean."

# ---- 2. hard gate: no real sample bytes --------------------------------
say ""
say "[2/8] checking for real malware bytes in the working tree..."
VERIFY=(python3 "$HERE/verify-no-samples.py" --repo "$REPO_ROOT" --rev "")
[ -n "$SAMPLES" ] && VERIFY=("${VERIFY[@]}" --samples "$SAMPLES")
if ! "${VERIFY[@]}"; then
  die "the no-samples check did not pass. Nothing was changed and nothing was
     published. See tests/fixtures/positive/README.md."
fi

# ---- 3. hard gate: victim-identifying and personal strings -------------
# Not malware, but this is what turns a public security tool into a public
# disclosure about a client and about named individuals. A name published once
# is published for good, so this fails closed.
#
# This script is NOT excluded from its own scan. It used to be -- which is
# precisely how it came to contain the whole pattern list in clear.
#
# The one allowed form is the public repository's own name, which legitimately
# appears in every `uses:` ref. It is whitelisted by *removing that substring*
# from each candidate line and re-testing the remainder, not by dropping the
# whole line: a line that mentions the public repo AND something private must
# still be caught.
say ""
say "[3/8] scanning for victim-identifying / personal strings..."
if [ ! -r "$DISCLOSURE_PATTERNS_FILE" ]; then
  if [ "$ALLOW_DISCLOSURES" -eq 1 ]; then
    say "  no disclosure patterns file at $DISCLOSURE_PATTERNS_FILE"
    say "  --allow-disclosures given: skipping the check entirely."
  else
    die "no disclosure patterns file; refusing to publish without one.
     Expected: $DISCLOSURE_PATTERNS_FILE
     Copy examples/disclosure-patterns.example, fill in the names that must
     never be published, and chmod 600 it. Pass --disclosure-patterns to
     point elsewhere, or --allow-disclosures to publish unchecked."
  fi
else
  DISCLOSURE_RE="$(sed -e 's/#.*//' -e 's/^[[:space:]]*//' \
                       -e 's/[[:space:]]*$//' "$DISCLOSURE_PATTERNS_FILE" \
                   | grep -v '^$' | paste -sd'|' -)"
  [ -n "$DISCLOSURE_RE" ] || die "$DISCLOSURE_PATTERNS_FILE has no patterns."
  N_PAT="$(sed -e 's/#.*//' "$DISCLOSURE_PATTERNS_FILE" | grep -c '[^[:space:]]' || true)"
  say "  ${N_PAT} pattern(s) from $DISCLOSURE_PATTERNS_FILE"
  say "  allowing only the repository's own name: $PUBLIC_REPO"

  HITS="$(git grep -n -I -i -E "$DISCLOSURE_RE" -- . 2>/dev/null \
          | ALLOW="$PUBLIC_REPO" RE="$DISCLOSURE_RE" python3 -c '
import os, re, sys
allow, rx = os.environ["ALLOW"], re.compile(os.environ["RE"], re.I)
for line in sys.stdin:
    if rx.search(line.rstrip("\n").replace(allow, "")):
        sys.stdout.write(line)
' || true)"

  if [ -n "$HITS" ]; then
    N_HITS="$(printf '%s\n' "$HITS" | grep -c . || true)"
    say ""
    printf '%s\n' "$HITS" | sed 's/^/    /'
    say ""
    say "  ${N_HITS} line(s) would disclose who was attacked, which client"
    say "  projects were involved, or who works there."
    if [ "$ALLOW_DISCLOSURES" -eq 1 ]; then
      say ""
      say "  --allow-disclosures given: continuing anyway."
      confirm "Publish these strings publicly, permanently?"
    else
      die "refusing to publish. Edit them out and commit, or pass
     --allow-disclosures if you have decided they are fine. The SHA256s,
     wallets, RPC hosts, XOR keys and marker patterns are technical IOCs,
     not disclosures -- they can and should stay."
    fi
  else
    say "  none found."
  fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
  say ""
  say "Dry run: both gates passed, nothing was created, committed or pushed."
  exit 0
fi

confirm "Build the orphan commit and publish to $PUBLIC_REPO?"

# ---- 4. orphan commit ---------------------------------------------------
cleanup_branch() {
  git checkout --quiet "$CURRENT_BRANCH" 2>/dev/null || true
}
trap cleanup_branch EXIT

if git rev-parse --verify -q "refs/heads/$ORPHAN_BRANCH" >/dev/null; then
  confirm "Local branch $ORPHAN_BRANCH already exists. Delete and rebuild it?"
  git branch -D "$ORPHAN_BRANCH" >/dev/null
fi

say ""
say "[4/8] building the orphan commit..."
git checkout --quiet --orphan "$ORPHAN_BRANCH"
git add -A
git commit --quiet -m "Initial public release

Defensive scanner for the EtherHiding / JADESNOW supply-chain implant
(DPRK UNC5342, \"Contagious Interview\").

Published as a single commit with no history on purpose: the private
repository this was developed in contains the real recovered malware samples
in its history, and pushing that history would publish them. Every fixture
here is synthetic -- see tests/fixtures/positive/README.md."
say "      $(git rev-parse --short HEAD)  $(git rev-list --count HEAD) commit, $(git ls-files | wc -l | tr -d ' ') files"

# ---- 5. hard gate again, this time on what will actually be pushed -----
say ""
say "[5/8] checking the orphan commit's tree..."
VERIFY2=(python3 "$HERE/verify-no-samples.py" --repo "$REPO_ROOT" --rev "$ORPHAN_BRANCH")
[ -n "$SAMPLES" ] && VERIFY2=("${VERIFY2[@]}" --samples "$SAMPLES")
if ! "${VERIFY2[@]}"; then
  say ""
  say "The orphan commit contains real sample bytes. Not pushing."
  say "The branch $ORPHAN_BRANCH is left in place so you can inspect it."
  exit 1
fi

# ---- 6. create the repository if needed ---------------------------------
say ""
if gh repo view "$PUBLIC_REPO" >/dev/null 2>&1; then
  say "[6/8] $PUBLIC_REPO already exists."
else
  confirm "[6/8] $PUBLIC_REPO does not exist. Create it as a PUBLIC repo?"
  gh repo create "$PUBLIC_REPO" --public --description "$DESCRIPTION" \
    --disable-wiki
  say "      created."
fi

# ---- 7. push ------------------------------------------------------------
if git remote get-url "$PUBLIC_REMOTE" >/dev/null 2>&1; then
  git remote set-url "$PUBLIC_REMOTE" "$PUBLIC_URL"
else
  git remote add "$PUBLIC_REMOTE" "$PUBLIC_URL"
fi
say ""
confirm "[7/8] push $ORPHAN_BRANCH to ${PUBLIC_REMOTE} (${PUBLIC_URL}) as ${TARGET_BRANCH}?"
git push "$PUBLIC_REMOTE" "$ORPHAN_BRANCH:refs/heads/$TARGET_BRANCH"
say "      pushed."

# ---- 8. back to where we started ---------------------------------------
say ""
say "[8/8] returning to $CURRENT_BRANCH."
git checkout --quiet "$CURRENT_BRANCH"
trap - EXIT

say ""
say "Done. Next:"
say "  1. tools/protect-public-main.sh   (block force-push and deletion)"
say "  2. re-point the callers:"
say "       tools/rollout.sh --owner <org-or-user> --all --merge --dispatch"
say "     ... once per owner."
say "  3. only once those are merged and green, delete the now-unnecessary"
say "     SCANNER_TOKEN org secret (see tools/sync-secret-visibility.md)."
