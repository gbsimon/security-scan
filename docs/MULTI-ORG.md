# One public scanner, several owners — decided

**Decision: option B.** The scanner is published as a PUBLIC repository, and
every caller — two organisations and ~40 personal repos — points at it. A
separate private repository stays as the incident record: the real samples in
its history, the evidence, the tickets.

The forcing constraint was that **a personal repo cannot read an org secret,
and there is no user-level secret.** Covering ~40 personal repos with a
private scanner meant a PAT in ~40 repo secrets, each expiring. A scanner that
fails closed on an expired token stops running without telling anyone, so the
option that has nothing to expire won.

## What the two options cost

| | A — private copy per owner | B — one public copy *(chosen)* |
|---|---|---|
| Token per caller | an org secret per org, **~40 repo secrets** for the personal account | **none** — a public repo is checked out by the built-in `GITHUB_TOKEN` |
| Copies of `scan.py` | three, drifting | one |
| Setup per new repo | inherit an org secret, or add one by hand | nothing |
| Real samples | stay in the fixtures | removed; synthetic fixtures replace them |
| Rules | private | readable by anyone |

The two costs of B, honestly:

- `tests/fixtures/positive/*.SAMPLE.txt` were real JADESNOW samples and could
  not be published. Synthetic fixtures replaced them, tripping the same rule
  IDs, and the SHA256s stay in `KNOWN_BAD_SHA256` so `IOC-KNOWN-SHA256` keeps
  its teeth — exercised by `tests/fixtures/test-hashes.txt` via
  `--extra-hashes`. Rule coverage is unchanged; the loss is proof the suite
  still fires on the exact bytes that hit us. `tools/verify-no-samples.py`
  scans the real samples on the evidence volume against this tree so that loss
  stays deliberate rather than accidental.
- The rules are now readable by the people they detect. Smaller than it
  sounds: the indicators derive from public GTIG/Mandiant reporting on
  UNC5342, so `scan.py` gives away nothing the write-ups do not. It is a
  safety net, not an access control.

## What publishing changed

- `uses:` points at the public scanner everywhere — the default in
  `caller-template.yml`, `tools/rollout.sh` and `org-coverage.yml`.
- The old scanner PAT is **no longer needed** and should be deleted once every
  caller is merged and green (`tools/sync-secret-visibility.md`). The
  `scanner_token` input survives for one case only: pointing `scanner_repo` at
  a private fork.
- "Settings → Actions → General → Access" is no longer needed either. A public
  repo's reusable workflows are callable by anyone, with no setting.
- Coverage is a matrix over the owners named in the repository variable
  `COVERAGE_OWNERS`, one issue per owner, one fine-grained PAT per owner (a
  PAT can only be scoped to one resource owner), named
  `COVERAGE_TOKEN_<OWNER>`. An owner whose secret is missing is skipped with a
  notice, not a failure.
- Nothing that identifies the victim, the client projects or the people
  involved is in the public tree: the trusted-author lists live in
  `~/.config/security-scan/trusted-authors.d/<owner>`, the attacker
  identifiers behind `scan.py --actors`, and `docs/IOC.md` describes the
  intrusion generically. `tools/publish-public.sh` fails closed if any of it
  creeps back in.

## Publishing it

`tools/publish-public.sh` — refuses on a dirty tree, refuses unless
`verify-no-samples.py` passes over both the working tree and the orphan commit
it builds, refuses if any victim-identifying or personal string is found
(`--allow-disclosures` overrides, deliberately awkward), then pushes **a
single orphan commit** to the public repo. Orphan because the private
repository's history still contains the real samples, and `git push` publishes
objects, not just the tip.

Then `tools/protect-public-main.sh`: no force-push, no deletion, linear
history, PR required, **no bypass actors**. Every caller in every owner runs
whatever is on that branch, so nobody — including the owner — gets to move it
by hand.
