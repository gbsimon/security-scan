# Runbook

## What each layer catches

| Layer | Where | Catches | Misses |
|---|---|---|---|
| `scan.py tree` | CI on every push/PR; daily launchd sweep | the implant sitting in a working tree, hostile lifecycle scripts, `.npmrc` tricks, hijacked git hooks | anything only in history; anything already built |
| `scan.py history` | CI daily (`schedule`); `safe-clone`; on demand | the payload in **any** reachable commit, branch, tag or reflog entry — including commits later "cleaned" from the tip | commits garbage-collected or never fetched |
| `scan.py commits` | CI on push/PR | backdated commits, out-of-order author dates, unknown or known-bad authors, unsigned commits claiming a trusted author, force-pushes, IOCs on added lines | a forged commit that is signed with a stolen key |
| `safe-clone` | your Mac | a hostile repo **before** a working tree exists on disk | repos you clone with plain `git clone` |
| `org-coverage.yml` | CI daily, in this repo | repos that have **no** `malware-scan.yml` at all — including repos created after the rollout — and callers pointing at the wrong `uses:` | anything inside a repo that *does* have the workflow |
| launchd daily sweep | your Mac, 12:30 | re-infection of `~/LocalSites` / `~/LocalApps` between CI runs | history (deliberately — too slow, and would fire daily until the remotes are rewritten) |

The scanner reads bytes. It never installs, imports, or executes anything it
scans, and it only uses read-only git plumbing (`rev-list`, `grep`, `log`,
`show`, `diff`) — never `status`, `checkout`, `stash` or `fetch`, so a
repo-local `core.fsmonitor` cannot be triggered by it.

## Rolling it out across the whole org

The first wave covered 7 repos by hand. At org scale that is dozens — too many
to copy a file into by hand — so `tools/rollout.sh` does it, and
`org-coverage.yml` keeps doing it for repos that do not exist yet.

1. **Nothing to set up per caller.** The scanner is the *public* repo
   `gbsimon/security-scan`, so every caller checks it out with the built-in
   `GITHUB_TOKEN`. No org secret, no PAT, no "Settings → Actions → Access".
   That is why it was published: personal repos cannot read an org secret at
   all. See `docs/MULTI-ORG.md`.
   *(Alternative, still supported: vendor `scanner/scan.py` into a repo and
   the cross-repo checkout is skipped automatically. Pointing `scanner_repo`
   at a private fork is the one case that still needs `scanner_token`.)*
2. **Trusted authors, once per owner.** The list of commit authors you expect
   is real people's email addresses, so it lives outside this repository, in
   `~/.config/security-scan/trusted-authors.d/<owner>` — one address per line,
   `#` for comments, `chmod 600`. `tools/rollout.sh` reads it automatically;
   `--trusted-authors "a@b,c@d"` and `--trusted-authors-file <path>` override
   it in that order. With no list at all the rollout still runs but warns,
   because every author in every repo then reports as
   `COMMIT-AUTHOR-UNKNOWN`, which buries the one that matters.
3. **Coverage config, once:** set the repository variable `COVERAGE_OWNERS`
   (comma-separated orgs and/or user accounts) and one fine-grained PAT per
   owner named `COVERAGE_TOKEN_<OWNER>` — upper-cased, non-alphanumerics
   replaced by `_`. Metadata + Contents, read-only, all repositories. Exact
   steps in `tools/sync-secret-visibility.md`, which also covers retiring the
   now-unnecessary `SCANNER_TOKEN` **after** every caller is green.
4. **All repos at once, per owner:**

       tools/rollout.sh --owner <owner> --all --dry-run   # read-only
       tools/rollout.sh --owner <owner> --all --merge --dispatch

   `--merge` squash-merges each PR with the subject
   `ci: add malware-scan workflow [skip ci]`. The tag is load-bearing: most of
   these repos deploy on a push to their default branch, so without it merging
   dozens of PRs would fire dozens of unrelated production deploys in a few
   minutes. `--dispatch` then runs each repo's malware-scan once immediately,
   so the first full-history sweep happens now rather than at 06:17 UTC.
   Repeat per owner; a user account works exactly the same way.

   Every repo of an owner gets that owner's `trusted_authors` list. Anyone
   else is reported at MEDIUM, which does not fail a build; that is the point,
   since the 2026-08 compromise arrived through a contributor account. Add
   `--merge` to
   squash-merge as it goes, `--repos a,b,c` to do a subset, `--branch` to
   change the branch name. Re-running is safe and cheap: a repo that already
   has the exact file is skipped without even being cloned.

   The script never checks out project code. It clones with
   `--no-checkout --filter=blob:none --depth 1` and a **`--no-cone`** sparse
   pattern (`/.github/workflows/`), then asserts the temp clone holds nothing
   but `.git` and `.github` before writing. Cone mode would not do: it always
   materialises the repository root, which is exactly where the implant lives.
5. **Then check it stayed done.** `org-coverage.yml` runs daily as a matrix
   over every owner in `COVERAGE_OWNERS`, lists every non-archived
   non-fork repo of each, and keeps one issue per owner — *[org-coverage]
   repos without malware-scan (owner)* — naming the uncovered repos and the
   `tools/rollout.sh --repos …` command that fixes them. Each closes itself at
   100% and reopens when a new repo shows up uncovered. It also flags callers
   pointing at an unexpected `uses:` ref, and an owner whose token is missing
   is skipped with a notice rather than failing the run. It is read-only
   across every owner by design: opening PRs in every repo from CI would need
   org-wide *write* tokens, and these orgs were compromised three weeks ago.
6. Run the workflow once manually in a repo (**Actions → malware-scan → Run
   workflow**) so the `schedule`/`workflow_dispatch` history sweep runs
   against the full object graph. The six affected repos had their `main`
   history rebuilt on 2026-08-20 and the malicious commits are dangling
   (unreachable), so a clean first run is the expected result. `rev-list
   --all` cannot see dangling objects — only GitHub Support can purge those
   (ticket open).
7. On your Mac: `./local/install.sh` (idempotent, asks before doing anything).

Other orgs and personal repos work the same way, because the scanner is public
and none of them needs a secret. `docs/MULTI-ORG.md` records why that route was
chosen; `tools/publish-public.sh` and `tools/protect-public-main.sh` are how
the public copy is created and locked down.

## When the scanner fires

**Do not build. Do not `npm install`. Do not open the project in a dev server.**
The payload runs at *build* time, so "just having a look" is the infection.

1. **Stop.** Do not "fix" it in place: deleting the appended line from the
   working tree leaves it in history and tells the attacker you noticed.
2. **Preserve.** Copy the flagged files somewhere isolated, renaming them to
   `<name>.SAMPLE.txt` so no build tool can load them. Keep the JSON report
   (CI uploads it as an artifact; the daily sweep writes it to
   `~/Library/Logs/malware-scan/`).
3. **Assume credential theft** if the file was ever present during a build on
   that machine. Rotate, in this order: GitHub tokens and SSH keys, `.env` and
   deploy secrets, cloud keys, then anything in the password manager that a
   browser or 1Password session could have exposed.
4. **Check the blast radius.** `scan.py tree ~/LocalSites ~/LocalApps` — this
   family self-propagates into sibling repos' build configs. Then
   `scan.py history` each affected repo.
5. **Re-clone rather than repair.** Rewrite the remote history from a known-good
   commit (or start a fresh repo), then `safe-clone` it and cherry-pick your
   unpushed work across. Do not push from the machine that was infected.
6. **Check for backdated commits** on every branch, not just `main`:
   `scan.py commits <repo> --head <branch> --trusted-authors "you@example.com"`.
   The 2026-08 wave force-pushed to feature branches too.

## The public scanner repo already has rulesets

Rulesets are free on *public* repositories, so `gbsimon/security-scan` gets
the protection the private repos cannot have yet: no force-push, no deletion,
linear history, PR required, and **no bypass actors** — the rule binds the
owner too. `tools/protect-public-main.sh` applies it. This matters more than
usual: every caller in three owners executes whatever is on that branch, so
whoever can move the ref can run code everywhere.

## When you upgrade to Team

Nothing below is available on Free with private repos. Do all of it on day one
of the upgrade — the whole reason this tooling has to shout is that none of it
can currently block.

**Branch ruleset on `main` (and any deploy branch), for every repo:**
- Block force-pushes. Block deletions. **No bypass list — including admins.**
- Require a pull request, 1 approval, dismiss stale approvals on new commits.
- Require the status check **`malware-scan`** to pass, and require branches to
  be up to date before merging.
- Require signed commits. *(Then set `--signature-severity HIGH` in the caller
  workflow so `COMMIT-TRUSTED-AUTHOR-UNSIGNED` becomes blocking — until commits
  are actually signed, an author line is just a string an attacker can type.)*
- Require linear history; block merge commits from the API.

**CODEOWNERS** (`.github/CODEOWNERS`), so these need a second pair of eyes:

    /package.json          @your-handle
    /package-lock.json     @your-handle
    /yarn.lock             @your-handle
    /*.config.*            @your-handle
    /.npmrc                @your-handle
    /.husky/               @your-handle
    /scripts/              @your-handle
    /.storybook/           @your-handle
    /.github/workflows/    @your-handle

**Org settings:**
- Require 2FA for all members.
- Fine-grained PATs only, with an expiry; ban classic PATs; require approval
  for PATs that can act on org repos.
- No outside collaborators with write access. Review every existing one — the
  vector here was a contributor account, not a stolen laptop.
- Actions: allow only actions from this org plus explicitly listed verified
  creators; require approval for first-time contributors' workflow runs.
- Turn on secret scanning + push protection.

## When a HIGH is honest but expected

CRITICAL findings are exact indicator matches -- a known hash, a wallet, a
JADESNOW marker. There is nothing to weigh up; work the incident.

MEDIUM and HIGH are heuristics, and heuristics meet real code. The three
shapes that turned up across the org, and what to do with each:

| What you see | What it usually is | What to do |
|---|---|---|
| `OBF-DANGEROUS-API` **MEDIUM** on a script | a genuine `eval`/`atob` with nothing else suspicious in the file | read it once. MEDIUM does not fail the build; it is a note, not an alarm |
| `OBF-DANGEROUS-API` **HIGH** on a bundle | a vendored minified SDK that evals its own packed source | confirm the vendor and the version, then suppress it *by path*, below |
| `COMMIT-BACKDATED` **LOW** | a rebase: author date left behind, no build-time file touched | ignore. It is LOW precisely so it does not need triage |

To suppress a reviewed path, add it to `.malwarescanignore` in that repo
**with the reasoning**, so the next person reads a decision rather than a
mystery:

    # reviewed 2026-08-21 simon: vendored blaze SDK v3.2, evals its own
    # packed source, no network calls, pinned by integrity hash
    scripts/api.js

The scanner then emits a MEDIUM `SCAN-IGNORE-ACTIVE` listing every active
pattern, so a suppression can never be silent, and `--no-ignore-file` shows
everything again. Prefer a path over a rule: muting `OBF-DANGEROUS-API`
everywhere would have hidden the real implant, which used `eval` too.

**Never** suppress by disabling the workflow or widening `fail_on`.

## What the heuristics deliberately skip

Documentation and prose -- `.md`, `.mdx`, `.txt`, `.rst`, `.adoc`, `.html`,
`README*`, `LICENSE*`, `CHANGELOG*`, `NOTICE*`, and anything under `docs/` --
are exempt from the `OBF-*` and `EXEC-*` heuristics. A 200-space run in a
Markdown table is column alignment, not a payload pushed off-screen, and a
`curl … | sh` line in a README is an instruction to read, not a build step.
Both cost real failures on the first org-wide sweep: a `README.md` under
`scripts/` was being treated as a build script purely because of its parent
directory.

The exact-match IOC rules still apply to prose, so a wallet address or a
JADESNOW marker in a `.md` is still CRITICAL. Only the guessing stops.

The same applies to **vendored upstream trees** — `wp-content/plugins/`,
`wp-content/mu-plugins/`, `wp-content/upgrade/`, `wp-content/uploads/`,
`wp-includes/`, `wp-admin/`, `storage/framework/`. That is code someone else
released and this repo merely stores; a minified plugin bundle or a
column-aligned PHP array looks exactly like a hidden append, and nobody is
going to review upstream's formatting. Exact IOC matching still runs there,
and it is worth more than the heuristics were: a known hash or a wallet in a
plugin file means that plugin is backdoored. `--heuristics-in-vendor` opts
back in. (`node_modules`, `vendor`, `bower_components` and `.yarn` are not
read at all — a stronger, long-standing exclusion.)

`OBF-WHITESPACE-PAD` is HIGH only in a build config, script directory or hook
— files that run at build time, where the pad-then-code shape is the actual
attack. In ordinary source it is LOW: reported, not blocking.

## A failed run is not a clean run

If the workflow cannot check the repository out, no scan happens. That used to
surface as *"clean at or above HIGH"* with the tracking issue auto-closed,
because nothing was found — by a scan that never ran. The job now fails with
*"malware-scan did not run"* and refuses to close anything.

### The dangling-gitlink case

The cause seen in the wild was a **stale gitlink**: a `160000` entry in the
tree with no matching `url` in `.gitmodules`. `actions/checkout` runs
`git submodule foreach --recursive` during its credential setup and teardown
**whether or not `submodules` is enabled** — measured, the log prints
`submodules: false` and runs it anyway — and that command exits 128 on such a
tree.

The important detail: it fails *after* the worktree is fully populated. So the
workflow no longer treats a failed checkout as fatal. It checks whether HEAD
resolves and the tree is non-empty; if so it scans it and says why, and only
falls back to a manual clone (which runs no submodule command at all) when
there is genuinely nothing there. If even that fails, the run fails — it never
proceeds to report clean.

It also scrubs any credential the interrupted teardown left behind:
`persist-credentials: false` promises no usable token in `.git/config`, and a
checkout that dies mid-teardown can break that promise inside a tree we are
about to scan for malware.

The scan reports the underlying problem as `GIT-DANGLING-GITLINK` (LOW). Fix
the repository properly with `git rm --cached <path>` for the stale gitlink,
or add the missing `[submodule]` block with its `url`.

## Tuning and suppression

`--fail-on` (default `HIGH`) sets what fails the run. MEDIUM findings are
hygiene: they are reported, they do not block.

A `.malwarescanignore` file (gitignore-style globs) suppresses findings, but
the scanner then emits a MEDIUM `SCAN-IGNORE-ACTIVE` listing every pattern, so
suppression is never silent — and `--no-ignore-file` disables it entirely.
`malware-scan: allow` in a line's own text suppresses that line. Only this
repo ships an ignore file, because a malware scanner necessarily contains the
indicators it hunts for.

If a rule misfires on real code, prefer narrowing the rule in `scan.py` and
adding the code as a negative fixture in `tests/fixtures/negative/` over
ignoring a path. `python3 scanner/scan.py selftest` must stay green.
