#!/usr/bin/env bash
#
# protect-public-main.sh -- lock down `main` on the public scanner repo.
#
#   tools/protect-public-main.sh [--repo gbsimon/security-scan] [--dry-run]
#
# WHY THIS MATTERS MORE THAN USUAL
#
# Once the callers point at
# `gbsimon/security-scan/.github/workflows/malware-scan.yml@main`, that branch
# is executed by CI in every repo of three owners, on every push. Whoever can
# move that ref can run code in all of them. The whole point of publishing was
# to remove tokens from the callers; that trade is only sound if the published
# branch cannot be quietly rewritten.
#
# So: no force-push, no deletion, linear history, changes go through a PR --
# and **bypass_actors is empty**, which means the rule binds the repository
# owner too. That is deliberate. A ruleset an admin can step around protects
# against accidents, not against a stolen admin session, and a stolen session
# is exactly how the incident that started all this began. Landing a change
# means opening a PR to your own repo; that is the cost, and it is small.
#
# Required approvals is 0: he is the only author, and requiring an approval he
# cannot give would mean either never merging or adding a bypass. 0 approvals
# still forces the PR, the diff view, and the status checks.
#
# NOT APPLICABLE, deliberately: "Settings -> Actions -> General -> Access".
# That setting controls who may call a reusable workflow in a *private* repo.
# A public repository's workflows are callable by anyone with no setting at
# all -- which is precisely why publishing removed the need for SCANNER_TOKEN.
# There is nothing to configure there, and nothing to loosen.
#
# Rulesets are available on public repositories on the Free plan. This is the
# one piece of the "when you upgrade to Team" list in docs/RUNBOOK.md that can
# be had today, because the repo is public.

set -euo pipefail

PROG="$(basename "$0")"
PUBLIC_REPO="gbsimon/security-scan"
RULESET_NAME="protect-main"
DRY_RUN=0

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
protect-public-main.sh -- apply a branch ruleset to the public scanner repo.

  --repo <owner/name>   Default: gbsimon/security-scan
  --dry-run             Print the ruleset that would be applied, then stop.
  -h, --help            This text.

Applies to the default branch: block deletion, block force-push, require
linear history, require a pull request (0 approvals). No bypass actors --
the rule binds the owner too.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)    [ $# -ge 2 ] || die "--repo needs a value"; PUBLIC_REPO="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

command -v gh >/dev/null 2>&1 || die "gh is not on PATH"

# ~DEFAULT_BRANCH follows the repo's default branch rather than hard-coding
# "main", so renaming the branch cannot silently unprotect it.
read -r -d '' RULESET <<'JSON' || true
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash", "merge", "rebase"]
      }
    }
  ]
}
JSON

say "$PROG"
say "  repo    : $PUBLIC_REPO"
say "  ruleset : $RULESET_NAME  (target: the default branch)"
say ""
say "Rules to apply:"
say "  - deletion                blocked"
say "  - non_fast_forward        blocked  (no force-push)"
say "  - required_linear_history on       (no merge commits)"
say "  - pull_request            required, 0 approvals"
say "  - bypass_actors           NONE -- this binds you as well"
say ""
say "Not applicable: Settings -> Actions -> Access. A public repository's"
say "reusable workflows are callable by anyone with no setting at all; that"
say "is why the callers no longer need SCANNER_TOKEN."

if [ "$DRY_RUN" -eq 1 ]; then
  say ""
  say "Ruleset payload:"
  printf '%s\n' "$RULESET"
  say ""
  say "Dry run: nothing was applied."
  exit 0
fi

gh repo view "$PUBLIC_REPO" >/dev/null 2>&1 \
  || die "$PUBLIC_REPO not found (or not visible to your token). Run
     tools/publish-public.sh first."

VISIBILITY="$(gh repo view "$PUBLIC_REPO" --json visibility \
              --jq '.visibility' 2>/dev/null || printf '?')"
say ""
say "  visibility: $VISIBILITY"
if [ "$VISIBILITY" != "PUBLIC" ]; then
  say ""
  say "  NOTE: rulesets on PRIVATE repositories need a paid plan. On Free"
  say "  this call will fail with 'Upgrade to GitHub Team'. That is a plan"
  say "  limit, not a mistake in this script."
fi

# Idempotent: update the ruleset if one with this name is already there.
EXISTING_ID="$(gh api "repos/$PUBLIC_REPO/rulesets" \
                 --jq ".[] | select(.name == \"$RULESET_NAME\") | .id" \
                 2>/dev/null | head -n 1 || printf '')"

if [ -n "$EXISTING_ID" ]; then
  confirm "Ruleset '$RULESET_NAME' already exists (id $EXISTING_ID). Update it?"
  printf '%s' "$RULESET" \
    | gh api -X PUT "repos/$PUBLIC_REPO/rulesets/$EXISTING_ID" --input - \
        --jq '"updated ruleset \(.id): \(.name) [\(.enforcement)]"'
else
  confirm "Create ruleset '$RULESET_NAME' on $PUBLIC_REPO?"
  printf '%s' "$RULESET" \
    | gh api -X POST "repos/$PUBLIC_REPO/rulesets" --input - \
        --jq '"created ruleset \(.id): \(.name) [\(.enforcement)]"'
fi

say ""
say "Verify:"
say "  gh api repos/$PUBLIC_REPO/rules/branches/main --jq '.[].type'"
say ""
say "From now on a change to the scanner lands through a PR on the public"
say "repo. Every caller in every owner you roll this out to runs whatever"
say "is on that branch, so that is the correct amount of friction."
