# Indicators of compromise — EtherHiding / JADESNOW

Everything below is encoded in `scanner/scan.py`. Rule ids are the strings the
scanner emits, so a finding maps straight back to a row here.

**Source:** two samples recovered from a real intrusion in August 2026, plus a
static decompilation of the payload (the malware was never executed). Campaign:
DPRK **UNC5342 / "Contagious Interview"**, loader **JADESNOW**, reported by the
Canadian Centre for Cyber Security and by Google Threat Intelligence Group /
Mandiant. Later stages in this family are BEAVERTAIL (infostealer) and
INVISIBLEFERRET (backdoor).

The victim is not named here, and neither is the compromised contributor
account. Everything below is technical: it is what the scanner matches on, and
it works the same whoever was hit.

## How the implant is shaped

A build-config file (`vite.config.js`, `postcss.config.mjs`) keeps its normal,
readable contents. On the **last line**, after the module terminator
(`export default config;` or `});`), come **709 spaces** — enough to push the
payload off the right edge of any editor — and then ~5 KB of obfuscated
JavaScript on that same line. An `import { createRequire } from 'module'` shim
is inserted at the top so the ESM config can reach `require`.

At build time the payload asks a TRON wallet's last transaction for a pointer,
pulls an encrypted blob out of a BSC transaction's `input` field (Aptos as
fallback), XOR-decrypts it, `eval`s it, and re-launches itself via a detached
`node -e` child process. Nothing malicious is ever hosted on a server the
defender can take down — the C2 is public blockchain data. That is
"EtherHiding".

## CRITICAL — exact matches (any text file)

| Rule id | Indicator |
|---|---|
| `IOC-KNOWN-SHA256` | `390eee2966268432eb47695e9b5b077ad438f4171160964239a1e0e197b4b286` (sample A, `vite.config.js`, patient zero)<br>`98502bf024152db68ba993d29e3f2412ed6169b32ec1503613e0cfcdb90b057f` (sample B, `postcss.config.mjs`, propagated) |
| `IOC-JADESNOW-CHARCODE127` | `String.fromCharCode(127)` — the DEL character used as the string-table delimiter by all three descrambler stages |
| `IOC-JADESNOW-GLOBAL-SEED` | `global.<id>='7-…'` — stage-0 seed (`global.i='7-mlc12041'`, `global.o='7-c1251'`) |
| `IOC-JADESNOW-STRINGTABLE` | `var _$_<hex>=` — the scrambled string table (`_$_b229`, `_$_3035`, `_$_e981`) |
| `IOC-JADESNOW-DESCRAMBLER-FN` | `_$xxNNNNNN(` — the descrambler function (`_$af912794`) |
| `IOC-JADESNOW-RUNTIME-GLOBAL` | runtime globals `_V` (re-entry marker) and `_p_t` (30 s throttle) |
| `IOC-C2-RPC-HOST` | `api.trongrid.io`, `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com`, `fullnode.mainnet.aptoslabs.com` |
| `IOC-C2-WALLET` | `TCqf6ZkaQD84vYsC2cuu1jRwB6JveTaRrF`, `TFMryB9m6d4kBMRjEVyFRbqKSV1cV2NcpH` |
| `IOC-C2-TXHASH` | `0x9d202c824402ca89e9aaccd2390b6f8b332ae743caa1469c695feb2781d56519`, `0x3d2075f97b7b1e3234bd653779d21c605d7d8c6ec9c98d983880be5c7f4f9471` |
| `IOC-XOR-KEY` | `2[gWfGj;<:-93Z^C`, `m6:tTh^D)cBz?NM]` |
| `IOC-SPAWN-DETACHED-NODE` | `spawn('node', ['-e', …])` |
| `IOC-SPAWN-DETACHED-TRIPLE` | `child_process` + `detached:true` + `windowsHide:true` in one file |
| `IOC-ACTOR-EMAIL` | *not shipped* — supply your own with `--actors FILE` |
| `IOC-ACTOR-HANDLE` (HIGH) | *not shipped* — same file |
| `COMMIT-KNOWN-BAD-AUTHOR` | commits authored **or committed** by an identity in your `--actors` file |
| `COMMIT-KNOWN-BAD-SHA` | `de959c6`, `a69498d`, `ea93a52` — backdated or evil-merge commits carrying the loader |

Only four of these actually appear as literal bytes in the samples we hold
(`IOC-KNOWN-SHA256`, `CHARCODE127`, `GLOBAL-SEED`, `STRINGTABLE`) — the wallets,
hosts and XOR keys live inside the scrambled string table and only surface
after deobfuscation. They are encoded anyway: they will match a decompiled
copy, an analyst's notes, or a variant that skips a scrambling layer.

### Why the actor identifiers are not in this repository

They name a real person. In this campaign the account used was a **hijacked
contributor**, not the operator — so shipping the identifiers publicly accuses
whoever owns that account of an intrusion they were the first victim of, and
buys nothing: the operator changes accounts freely, while the wallets, keys and
marker patterns above are what actually persist across victims.

The detection is not lost, only unbundled. Put the identifiers in a local file
and pass `--actors`:

```sh
printf '%s\n' someone@example.com theirhandle > ~/.config/security-scan/actors
python3 scanner/scan.py history /path/to/repo --actors ~/.config/security-scan/actors
```

One entry per line, `#` starts a comment, an entry containing `@` is an email
and anything else is an account name. It feeds `IOC-ACTOR-EMAIL`,
`IOC-ACTOR-HANDLE`, `COMMIT-KNOWN-BAD-AUTHOR` and the history sweep alike.

## HIGH — obfuscation heuristics (build-config and lifecycle files)

| Rule id | Trigger |
|---|---|
| `OBF-WHITESPACE-PAD` | ≥ 100 consecutive spaces/tabs followed by code (the samples use 709). **HIGH** in a build config, script directory or hook — where the shape is the attack; **LOW** in ordinary source, where it is usually column alignment |
| `OBF-APPENDED-PAYLOAD` | module terminator, then a pad, then > 100 chars of code on the same line |
| `OBF-LONG-LINE` | any line > 300 chars in a build config |
| `OBF-HIGH-ENTROPY-STRING` | string literal ≥ 200 chars with Shannon entropy ≥ 4.5 bits/char (samples: 5.03–5.66) |
| `OBF-ESCAPE-DENSITY` | ≥ 6 `\xNN` (or ≥ 12 `\uNNNN`) escapes on one line of a build config (samples: 7) |
| `OBF-DANGEROUS-API` | `eval(`, `new Function(`, `atob(`, `child_process`, `String.fromCharCode(`, `Buffer.from(…,'base64')`, `process.binding`, `vm.runIn*Context`, `require('http(s)')` in a build config; the first three also in `scripts/` and `.husky/`. **HIGH** in a build config or a hook, or when the file carries another obfuscation signal (long line, high-entropy string, escape density, whitespace pad); **MEDIUM** otherwise. `eval` preceded by `.` (`model.eval()`) and matches inside an f-string are not counted |
| `EXEC-REMOTE-PIPE-SHELL` | `curl`/`wget` or `base64 -d` piped into a shell from a build/lifecycle script (MEDIUM inside a `Dockerfile`, which builds in a container rather than your shell) |
| `PUSH-FORCED` | `github.event.forced == true` on a push |
| `COMMIT-BACKDATED` | author date > 7 days older than committer date — the tell of the 2026-08 force-push wave. **HIGH** only when the commit touches a watched path (build config, lockfile, `package.json`, workflow, `.npmrc`, hook); **LOW** otherwise, because that is also what an ordinary rebase looks like |
| `DIFF-*` | any CRITICAL pattern, or a whitespace pad, on a line **added** by the pushed range |

None of the `OBF-*` or `EXEC-*` heuristics apply to vendored upstream trees
(`wp-content/plugins/`, `wp-content/mu-plugins/`, `wp-content/upgrade/`,
`wp-content/uploads/`, `wp-includes/`, `wp-admin/`, `storage/framework/`;
`--heuristics-in-vendor` opts back in), nor to documentation and prose
(`.md`, `.mdx`, `.txt`, `.rst`, `.adoc`, `.html`, `README*`, `LICENSE*`,
`CHANGELOG*`, `NOTICE*`, anything under `docs/`). The CRITICAL rules above
still do. See *What the heuristics deliberately skip* in `docs/RUNBOOK.md`.

## MEDIUM — supply-chain hygiene

`PKG-LIFECYCLE-DANGEROUS`, `PKG-LIFECYCLE-UNRECOGNISED` (preinstall/install/
postinstall/prepare running a downloader or interpreter), `PKG-NONREGISTRY-DEP`
(`https://`, `git+`, `github:`; local `file:`/`link:` are not flagged),
`NPMRC-UNSAFE` (`ignore-scripts=false`, `unsafe-perm=true`, embedded tokens),
`NPMRC-FOREIGN-REGISTRY`, `GITHOOK-PRESENT`, `GITHOOK-DANGEROUS`,
`GITCFG-HOOKSPATH`, `GITCFG-FSMONITOR`, `GITCFG-SSHCOMMAND`,
`GHA-UNPINNED-ACTION`, `GHA-PULL-REQUEST-TARGET`, `COMMIT-AUTHOR-UNKNOWN`,
`COMMIT-OUT-OF-ORDER`, `COMMIT-FUTURE-DATED`, `COMMIT-TRUSTED-AUTHOR-UNSIGNED`,
`SCAN-IGNORE-ACTIVE`, `SCAN-COMMITS-TRUNCATED`, `SCAN-TIME-BUDGET`.

## How it played out

Generic on purpose — the victim is not named, and the shape is what is useful
to anyone reading this.

| Stage | What happened |
|---|---|
| Initial access | A contributor account with write access to a small agency's private GitHub org was compromised. It committed the loader into a private React/Vite repository, in a commit whose message and diff looked like ordinary feature work. |
| Execution | Months later, a build of that repository on a developer's Mac ran the payload at build time — the implant lives in a build config, so `npm run build` is the trigger. No one has to open anything. |
| Propagation | Subsequent builds appended the loader to the build configs of *sibling checkouts on the same machine*, so repositories that were never cloned from an infected remote became infected locally. |
| Credential theft | Tokens and keys reachable from that machine were exfiltrated over the blockchain C2. |
| Cover-up | The stolen GitHub token force-pushed backdated commits and an evil merge across roughly six repositories, with a forged author line copying a legitimate maintainer, so the malicious commits appeared old and trusted. |
| Detection | Roughly nine months after initial access. The tell was the backdated-commit wave, not the payload. |

Three things generalise from that:

- **The payload was in history long before it ran.** A working-tree scan alone
  would have missed it; `scan.py history` sweeps every reachable object.
- **The propagation vector was a shared filesystem, not a shared remote.**
  Scan every checkout on the machine, not just the repository you suspect.
- **An author line is a string the attacker can type.** It is only evidence if
  commits are signed, which is why `COMMIT-TRUSTED-AUTHOR-UNSIGNED` exists.
