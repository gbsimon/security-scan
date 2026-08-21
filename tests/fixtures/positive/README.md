# Positive fixtures — all synthetic

Everything in this directory is invented. **This repository ships no malware.**

It used to. Two fixtures were byte-exact copies of the JADESNOW loader
recovered from a real intrusion. They were removed when the scanner was
published, and replaced by fixtures that imitate the *shape* of the implant
without carrying any of its bytes. The originals stay on the incident evidence
volume, which is where they belong.

    390eee2966268432eb47695e9b5b077ad438f4171160964239a1e0e197b4b286  sample A: vite.config.js (patient zero)
    98502bf024152db68ba993d29e3f2412ed6169b32ec1503613e0cfcdb90b057f  sample B: postcss.config.mjs (propagated)

Those two digests are still real IOCs and are still detected — they live in
`KNOWN_BAD_SHA256` in `scanner/scan.py` and in `docs/IOC.md`. What changed is
that no file here hashes to them any more.

| Fixture | Imitates | Fires |
|---|---|---|
| `jadesnow-shape/vite.config.js` | patient zero: a payload appended to the last line of a Vite config behind 709 spaces | `IOC-JADESNOW-CHARCODE127`, `-GLOBAL-SEED`, `-STRINGTABLE`, `OBF-WHITESPACE-PAD`, `-APPENDED-PAYLOAD`, `-LONG-LINE`, `-HIGH-ENTROPY-STRING`, `-ESCAPE-DENSITY`, `-DANGEROUS-API` |
| `jadesnow-shape-propagated/postcss.config.mjs` | the same implant after copying itself into a sibling project | the same, minus nothing |
| `knownhash/vite.config.js` | nothing — its **digest** is the thing under test | `IOC-KNOWN-SHA256`, via `--extra-hashes tests/fixtures/test-hashes.txt` |
| *(the temp git repo `scan.py` builds)* | a backdated, forged-author commit and one from a "known-bad" identity | the `COMMIT-*` rules, with invented identities from `tests/fixtures/test-actors.txt` via `--actors` |
| `synthetic/vite.config.js` | a hidden append with no IOC tokens at all | the `OBF-*` heuristics only |
| `lifecycle/package.json` | a hostile `postinstall` | `PKG-LIFECYCLE-DANGEROUS`, `PKG-NONREGISTRY-DEP`, `IOC-SPAWN-DETACHED-NODE` |
| `npmrc/.npmrc` | re-enabling install scripts, foreign registry | `NPMRC-UNSAFE`, `NPMRC-FOREIGN-REGISTRY` |
| `hook/.husky/pre-commit` | a git hook piping a download into a shell | `EXEC-REMOTE-PIPE-SHELL` |

## What "synthetic" means here, precisely

The two `jadesnow-shape*` fixtures reproduce the *structure* an analyst would
recognise — module terminator, 709-space pad, then one long line holding a
`_$_`-prefixed string table, a `global.X='7-…'` seed and
`String.fromCharCode(127)`. They do **not** contain a descrambler, an XOR key,
a wallet address, an RPC host, a network call, or an `eval`. The "string
table" is random base64 noise from a seeded PRNG, and the only executable
statement sits behind `if (false)`. Running one does nothing.

That is a deliberate trade. The rules stay covered; what is no longer proven
is that the suite fires on the exact bytes that hit us. If you have the
evidence volume and want that proof back, scan it directly:

```sh
python3 scanner/scan.py tree "/Volumes/…/MALWARE-EVIDENCE-…/samples" --no-ignore-file
```

`tools/verify-no-samples.py` is the check that keeps this honest: it takes
byte windows from the real samples on the evidence volume and fails if any of
them appears anywhere in this repository or in a given commit's tree.
`tools/publish-public.sh` refuses to publish unless it passes.
