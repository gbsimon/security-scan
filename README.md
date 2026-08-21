# security-scan

Defensive scanner for the **EtherHiding / JADESNOW** supply-chain implant that
hit a small agency's private GitHub org in August 2026 (DPRK UNC5342,
"Contagious Interview"). Malware
was appended to build-config files (`vite.config.js`, `postcss.config.mjs`),
ran at build time, stole credentials, self-propagated into sibling repos on the
same Mac, and was then hidden behind backdated force-pushes with a forged
author.

> **This repository contains no malware.** Every fixture under `tests/` is
> synthetic — built to trip the scanner's rules without carrying any bytes of
> the real implant. The two recovered samples were removed before publication
> and stay on the incident evidence volume; their SHA256s remain as IOCs. See
> `tests/fixtures/positive/README.md`, and `tools/verify-no-samples.py`, which
> is the check that proves it. This repo has no dependencies and no
> `package.json` by design; nothing here ever runs `npm install`.

```
scanner/scan.py                  Python 3 stdlib only, reads bytes, runs nothing
  tree <path>...                 walk a working tree
  history <repo>                 read-only sweep of every reachable git object
  commits --base A --head B      commit-metadata forensics (backdating, authors)
  selftest                       fixtures in tests/ -- must stay green

.github/workflows/
  malware-scan.yml               reusable workflow (on: workflow_call)
  caller-template.yml            the ~20 lines each repo adds
  org-coverage.yml               daily: which org repos still lack the caller
  selftest.yml                   CI for this repo

tools/
  rollout.sh                     bulk-install the caller across an owner's
                                 repos, one PR each, idempotent, never checks
                                 out project code
  render-caller.py               caller-template.yml -> the per-repo caller
  verify-no-samples.py           proves no real malware bytes are in this tree
  publish-public.sh              publish as a single orphan commit
  protect-public-main.sh         ruleset on the public main, no bypass actors
  sync-secret-visibility.md      the coverage tokens, and retiring SCANNER_TOKEN

local/
  install.sh                     idempotent, confirms first, installs the below
  scan-repo                      tree + history on the repo you are in
  safe-clone                     clone --no-checkout -> scan -> then checkout
  com.malware-scan.daily.plist   daily 12:30 sweep + notification

docs/RUNBOOK.md                  what each layer catches, rollout, incident steps
docs/IOC.md                      every indicator encoded, with its source
docs/MULTI-ORG.md                covering several orgs and personal repos
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `HIGH`),
`2` error.

The scanner lives in the **public** repo `gbsimon/security-scan`, so a caller
needs **no token**: any repo, in any org or none, can check it out with the
built-in `GITHUB_TOKEN`. That is the whole reason it is public — personal
repos cannot read an org secret. See `docs/MULTI-ORG.md`.

```yaml
jobs:
  scan:
    uses: gbsimon/security-scan/.github/workflows/malware-scan.yml@main
```

Rolling that out across an owner — one PR per repo:

```sh
tools/rollout.sh --owner <org-or-user> --all --dry-run   # plan + rendered file
tools/rollout.sh --owner <org-or-user> --all --merge --dispatch
```

The list of commit authors you expect is **not** in this repository — those
are real people's addresses. Put one address per line in
`~/.config/security-scan/trusted-authors.d/<owner>` (or pass
`--trusted-authors "you@example.com"` / `--trusted-authors-file`). Without a
list the rollout still works, but every author is reported as unknown and it
warns you.

One PR per repo. Safe to re-run, handles default branches that are not `main`,
squash-merges with `[skip ci]` so 51 merges do not trigger 51 deploys, and
only ever materialises `.github/workflows/` from the repos it touches — see
the header of `tools/rollout.sh`. `--dispatch` runs the first full-history
sweep straight away instead of waiting for the 06:17 UTC schedule.

`org-coverage.yml` then runs daily over every owner named in the repository
variable `COVERAGE_OWNERS`, and keeps one issue per owner listing any repo
still uncovered — including repos created after the rollout — with the exact
command to fix them.

```sh
python3 scanner/scan.py selftest
python3 scanner/scan.py tree ~/Local\ Sites --fail-on HIGH
python3 scanner/scan.py history /path/to/repo
python3 scanner/scan.py commits /path/to/repo --range main@{1}..main \
    --trusted-authors "you@example.com"
```

Start with `docs/RUNBOOK.md`.
