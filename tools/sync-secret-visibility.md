# Secrets and configuration

The scanner is a public repository, so **callers need no secret at all**. What
is left is the coverage tooling, which needs one read-only token per owner,
and the trusted-author lists, which are not secrets but must not live in a
public repo either.

Run these where `gh auth status` shows you as an owner of the org in question.

## 1. Callers need nothing — and the old scanner token should go

Before publication the reusable workflow lived in a private repo, so every
caller needed a PAT to check it out: the built-in `GITHUB_TOKEN` cannot read a
*different private* repo. That token (`SCANNER_TOKEN`, or whatever you called
it) is now dead weight, and dead credentials are worth removing — it is a live
PAT in an org secret, readable by any workflow it is visible to.

**Order matters.** Delete it only once every caller has been re-pointed at the
public scanner *and* run green at least once. Delete it first and every caller
still on the old `uses:` fails at the checkout step.

```sh
# 1. re-point everything (one PR per repo; --dispatch runs the first
#    full-history sweep immediately after each merge)
tools/rollout.sh --owner <owner> --all --merge --dispatch

# 2. confirm coverage is 100% for every owner
gh workflow run org-coverage.yml --repo <owner>/security-scan
#    ... then check that the [org-coverage] issues have closed

# 3. only then
gh secret delete SCANNER_TOKEN --org <org>
```

Also revoke the PAT itself at **Settings → Developer settings → Fine-grained
tokens**; deleting the secret does not revoke the credential.

"Settings → Actions → General → Access" on the old private repo no longer
matters either — it only governs reusable workflows in *private* repos.

## 2. `COVERAGE_OWNERS` — which owners to survey

`.github/workflows/org-coverage.yml` names no organisations. It reads the
owner list from a repository variable, so the public tree stays generic:

```sh
gh variable set COVERAGE_OWNERS --repo <owner>/security-scan \
  --body "acme-org,another-org,someuser"
```

Orgs and user accounts can be mixed; which is which is detected at run time.
A manual run can override it with the `owners` input. With neither set the
workflow does nothing and says so.

## 3. `COVERAGE_TOKEN_<OWNER>` — one per owner

A fine-grained PAT can only be scoped to **one** resource owner, so each owner
needs its own secret, stored on the scanner repo. The name is the owner
upper-cased with every non-alphanumeric character replaced by an underscore:

| Owner | Secret |
|---|---|
| `acme-org` | `COVERAGE_TOKEN_ACME_ORG` |
| `someuser` | `COVERAGE_TOKEN_SOMEUSER` |

Create each at **Settings → Developer settings → Personal access tokens →
Fine-grained tokens → Generate new token**:

| Field | Value |
|---|---|
| Resource owner | the owner |
| Repository access | **All repositories** — the point is to see repos that do not exist yet |
| Repository permissions → Metadata | **Read-only** |
| Repository permissions → Contents | **Read-only** |
| Everything else | *No access* |
| Expiration | set one, and put the renewal in the calendar |

Org-owned tokens may need an org owner to approve them (**Settings → Personal
access tokens → Pending requests**). Then:

```sh
gh secret set COVERAGE_TOKEN_ACME_ORG --repo <owner>/security-scan
```

Any secret may be missing: that owner is skipped with a notice rather than
failing the run, so you can set them up one at a time.

Check it works — **Actions → org-coverage → Run workflow**, or:

```sh
gh workflow run org-coverage.yml --repo <owner>/security-scan
gh workflow run org-coverage.yml --repo <owner>/security-scan -f owners=acme-org
```

A repo listed under *Could not be read* in the resulting issue means that
owner's PAT does not cover it — re-check **All repositories**.

These tokens are never used to write. The workflow puts each one in a
different step from the step that writes the issue, so the writing step is
never handed one.

## 4. Trusted authors — not a secret, but not public either

The list of commit authors you expect per owner is real people's email
addresses. It is not in this repository. `tools/rollout.sh` reads it from:

```
~/.config/security-scan/trusted-authors.d/<owner>
```

(or `$XDG_CONFIG_HOME/security-scan/...`), one address per line, `#` for
comments. `chmod 600`. Override with `--trusted-authors "a@b,c@d"` or
`--trusted-authors-file <path>`, in that order of precedence. With no list the
rollout still runs but warns loudly, because every author then reports as
`COMMIT-AUTHOR-UNKNOWN` and the one that matters is buried.

The same applies to known-malicious identities: `scan.py --actors FILE` takes
a local list of account names and email addresses. None ship with the scanner
— see *Why the actor identifiers are not in this repository* in `docs/IOC.md`.

## Why personal repos need a token but not a secret

A user account is not an org, so there is nowhere to put a shared secret its
repos could inherit — which is exactly why the scanner was published instead.
Personal repos now need **no secret at all**; the only user-scoped token is
the coverage one above, and it lives in a single repo.
