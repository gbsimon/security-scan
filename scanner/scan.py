#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan.py -- EtherHiding / JADESNOW supply-chain malware scanner.

Built after the 2026-08 EtherHiding
(DPRK UNC5342 "Contagious Interview", JADESNOW loader) compromise.

Design rules (non-negotiable):
  * READS BYTES ONLY. It never imports, evaluates, installs or executes any
    scanned content, and never runs a package manager.
  * git access is read-only plumbing (rev-list / grep / log / show / diff).
    It never runs status/checkout/stash/fetch, so no hook or fsmonitor can
    be triggered by this tool.
  * stdlib only. Runs on macOS system python3 (3.9) and ubuntu-latest (3.12).

Modes:
  scan.py tree <path>...            walk working tree(s)
  scan.py history <repo>            read-only sweep of all reachable objects
  scan.py commits --range a..b      commit-metadata forensics
  scan.py selftest                  run bundled fixtures

Exit codes: 0 = clean, 1 = findings at or above --fail-on, 2 = error.
"""

from __future__ import annotations

import argparse
import collections
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

EXCERPT_MAX = 160  # never print more than this many chars of a suspicious blob

# --------------------------------------------------------------------------
# Path classification
# --------------------------------------------------------------------------

# The scanner's own installation directory.
#
# The reusable workflow checks this repository out INTO the repository under
# test (as `.malware-scan-tool/`) and then runs `tree .` from the caller's
# root, so without this the scanner reads its own docs/IOC.md, its own rule
# source and its whole positive-fixture corpus, and reports the tool as
# malware. That is exactly what happened on the first real caller run: 45
# CRITICAL findings, every one of them this file's own reference material.
#
# The tool's own .malwarescanignore cannot help, because an ignore file is
# only read at the *scan root* -- which is the caller's root, not the tool's.
# So the exclusion has to live here, and it has to be unconditional: a scanner
# that can be made to cry wolf about itself is a scanner people learn to
# ignore.
TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(
    os.path.realpath(__file__))))


def excludes_tool_root(root):
    """True if TOOL_ROOT lies strictly below `root`, so scanning `root` would
    otherwise walk into the scanner's own files."""
    root = os.path.realpath(os.path.abspath(root))
    tool = os.path.realpath(TOOL_ROOT)
    return tool != root and is_inside(tool, root)


def is_inside(path, parent):
    """True if `path` is `parent` or lives under it. Symlink-safe."""
    try:
        path = os.path.realpath(path)
        parent = os.path.realpath(parent)
    except OSError:
        return False
    if path == parent:
        return True
    return path.startswith(parent.rstrip(os.sep) + os.sep)


SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "dist", "build", "out", ".next", ".nuxt", ".svelte-kit", ".astro",
    ".output", "coverage", ".nyc_output", "storybook-static", ".turbo",
    ".cache", ".parcel-cache", ".yarn", ".pnpm-store", "__pycache__",
    ".venv", "venv", ".terraform", ".gradle", ".mvn", "target", "Pods",
    "test-results", "playwright-report", ".playwright-mcp", ".DS_Store",
    ".idea", ".vscode-test", "site", "_site", ".docusaurus", ".serverless",
}

# Extensions we never scan (binary/media). Binary sniffing catches the rest.
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".tiff",
    ".ico", ".icns", ".svgz", ".psd", ".ai", ".sketch", ".fig",
    ".mp4", ".webm", ".mov", ".avi", ".mkv", ".m4v", ".mp3", ".wav",
    ".ogg", ".flac", ".aac", ".m4a",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    ".dmg", ".pkg", ".exe", ".dll", ".so", ".dylib", ".a", ".o", ".wasm",
    ".class", ".jar", ".pyc", ".pyo", ".db", ".sqlite", ".sqlite3",
    ".mind", ".glb", ".gltf", ".fbx", ".obj", ".bin", ".dat", ".pack",
}

MINIFIED_GLOBS = ("*.min.js", "*.min.mjs", "*.min.cjs", "*.min.css",
                  "*-min.js", "*.bundle.js", "*.chunk.js")

# Build-config files: hand-written, small, and the exact vector used in the
# incident. Obfuscation heuristics are strict here.
BUILD_CONFIG_GLOBS = (
    "vite.config.*", "vitest.config.*", "rollup.config.*", "webpack.config.*",
    "webpack.*.js", "postcss.config.*", "tailwind.config.*", "next.config.*",
    "nuxt.config.*", "svelte.config.*", "astro.config.*", "remix.config.*",
    "babel.config.*", ".babelrc", ".babelrc.*", "esbuild.config.*",
    "tsup.config.*", "rspack.config.*", "farm.config.*", "parcel.config.*",
    "eslint.config.*", ".eslintrc", ".eslintrc.*",
    "prettier.config.*", ".prettierrc", ".prettierrc.*", ".prettier.*",
    "stylelint.config.*", ".stylelintrc", ".stylelintrc.*",
    "jest.config.*", "playwright.config.*", "cypress.config.*",
    "metro.config.*", "gatsby-config.*", "gatsby-node.*", "craco.config.*",
    "commitlint.config.*", "lint-staged.config.*", ".lintstagedrc*",
    "i18n.config.*", "nx.json", "svgo.config.*", "uno.config.*",
    "capacitor.config.*", "quasar.config.*", "angular.json",
    "*.config.js", "*.config.mjs", "*.config.cjs",
    "*.config.ts", "*.config.mts", "*.config.cts",
)

# Directories whose contents run at build/dev/commit time.
SCRIPT_DIR_PARTS = (".storybook", "scripts", "tools", "bin", ".husky",
                    ".config")

LIFECYCLE_KEYS = (
    "preinstall", "install", "postinstall", "prepare", "prepublish",
    "prepublishOnly", "prepack", "postpack", "publish", "postpublish",
    "preuninstall", "uninstall", "postuninstall", "dependencies",
)

# Paths whose modification in a commit is worth a second look.
DEFAULT_WATCH_PATHS = [
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs",
    "vite.config.*", "vitest.config.*", "postcss.config.*",
    "tailwind.config.*", "next.config.*", "nuxt.config.*", "svelte.config.*",
    "astro.config.*", "rollup.config.*", "webpack.config.*",
    "eslint.config.*", ".eslintrc*", "prettier.config.*", ".prettierrc*",
    "babel.config.*", ".babelrc*", "*.config.js", "*.config.mjs",
    "*.config.cjs", "*.config.ts", "*.config.mts",
    ".github/workflows/*", ".husky/*", ".storybook/*", "scripts/*",
    "Dockerfile", "Makefile",
]

# git pathspecs used for the fast first pass of `history`.
HISTORY_FAST_PATHSPECS = [
    "*.config.js", "*.config.mjs", "*.config.cjs", "*.config.ts",
    "*.config.mts", "*.config.cts", "*.config.json",
    ".babelrc", ".babelrc.*", ".eslintrc*", ".prettierrc*", ".prettier.*",
    "package.json", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs",
    ".storybook/*", "scripts/*", "tools/*", "bin/*", ".husky/*",
    ".github/workflows/*", "gatsby-node.js", "gatsby-config.js",
]

SOURCE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
              ".vue", ".svelte", ".astro", ".json", ".sh", ".bash", ".zsh",
              ".yml", ".yaml", ".py", ".rb", ".php"}


# Evidence samples are defanged by appending ".SAMPLE.txt" so no build tool can
# load them. Classify them by the filename they *were*, so the same rules apply.
RE_DEFANGED = re.compile(r"\.SAMPLE\.txt$", re.I)


def logical_name(relpath):
    return RE_DEFANGED.sub("", relpath)


def _basename_matches(name, globs):
    for g in globs:
        if fnmatch.fnmatch(name, g):
            return True
    return False


def is_minified(relpath):
    return _basename_matches(os.path.basename(logical_name(relpath)),
                             MINIFIED_GLOBS)


def is_build_config(relpath):
    """True for hand-written build-config files (strict heuristics apply)."""
    relpath = logical_name(relpath)
    name = os.path.basename(relpath)
    if _basename_matches(name, BUILD_CONFIG_GLOBS):
        return True
    parts = relpath.replace("\\", "/").split("/")
    if ".storybook" in parts:
        return True
    return False


def is_script_like(relpath):
    """True for files that execute at build/dev/commit time (looser rules)."""
    relpath = logical_name(relpath)
    parts = relpath.replace("\\", "/").split("/")
    if any(p in SCRIPT_DIR_PARTS for p in parts[:-1]):
        return True
    return os.path.basename(relpath) in (
        "Makefile", "Dockerfile", "gulpfile.js", "Gruntfile.js")


# Documentation and prose. The obfuscation and remote-pipe heuristics do NOT
# apply here, because their premises do not hold:
#   * a 200-space run in a Markdown table is column padding, not a payload
#     hidden off the right edge of an editor;
#   * `curl … | sh` in a README is an install instruction someone is meant to
#     read, not a build step that runs on `npm run build`.
# Both cost us real failures on the first org-wide sweep, and both came from
# is_script_like(): a README under `scripts/` or `tools/` was treated as a
# build script purely because of its parent directory.
#
# The exact-match IOC rules (CRITICAL) still apply to every file, prose
# included -- a wallet address or a JADESNOW marker in a .md is still worth
# knowing about, and those rules do not guess.
PROSE_EXT = {".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc", ".asciidoc",
             ".html", ".htm"}
PROSE_BASENAME_PREFIXES = ("readme", "license", "licence", "changelog",
                           "notice", "contributing", "authors", "copying")


def is_prose(relpath):
    relpath = logical_name(relpath).replace("\\", "/")
    parts = relpath.split("/")
    if "docs" in parts[:-1]:
        return True
    name = os.path.basename(relpath)
    if os.path.splitext(name)[1].lower() in PROSE_EXT:
        return True
    stem = os.path.splitext(name)[0].lower()
    return stem.startswith(PROSE_BASENAME_PREFIXES)


# Vendored / upstream trees. The HEURISTICS are off here; the exact-match IOC
# rules are not.
#
# These directories hold code someone else released and this repository merely
# stores: WordPress core and plugin trees, Composer/Bower/Yarn caches, Laravel
# framework storage. The obfuscation heuristics have no precision there --
# minified plugin bundles and column-aligned PHP look exactly like a hidden
# append, and nobody is going to review upstream's formatting. Six of the
# round-two failures were exactly that, all of them third-party WordPress
# plugin code.
#
# What does still work there is exact matching: a known-bad hash, a wallet, a
# JADESNOW marker in a plugin file means that plugin is backdoored, and that
# is worth every bit as much as finding it in authored code. So the CRITICAL
# rules run everywhere, always.
#
# `vendor`, `bower_components`, `.yarn`, `node_modules` are in SKIP_DIRS and
# are not read at all -- a stronger exclusion than this one, and long-standing.
VENDOR_PATH_SEQUENCES = (
    ("wp-content", "plugins"),
    ("wp-content", "mu-plugins"),
    ("wp-content", "upgrade"),
    ("wp-content", "uploads"),
    ("wp-includes",),
    ("wp-admin",),
    ("storage", "framework"),
)


def is_vendored(relpath):
    parts = logical_name(relpath).replace("\\", "/").split("/")[:-1]
    for seq in VENDOR_PATH_SEQUENCES:
        w = len(seq)
        for i in range(len(parts) - w + 1):
            if tuple(parts[i:i + w]) == seq:
                return True
    return False


def is_hook_like(relpath):
    """Git/husky hooks: they run on commit, so `eval` there is not decoration."""
    relpath = logical_name(relpath).replace("\\", "/")
    parts = relpath.split("/")
    return ".husky" in parts or "hooks" in parts[:-1]


def is_config_like(relpath):
    return is_build_config(relpath) or is_script_like(relpath)


# --------------------------------------------------------------------------
# Indicators of compromise
#
# Source: two samples recovered from a real intrusion, plus a static
#         decompilation of the payload  (see docs/IOC.md)
# --------------------------------------------------------------------------

_XOR_KEYS = [b"2[gWfGj;<:-93Z^C", b"m6:tTh^D)cBz?NM]"]
_WALLETS = [b"TCqf6ZkaQD84vYsC2cuu1jRwB6JveTaRrF",
            b"TFMryB9m6d4kBMRjEVyFRbqKSV1cV2NcpH"]
_TXHASHES = [
    b"0x9d202c824402ca89e9aaccd2390b6f8b332ae743caa1469c695feb2781d56519",
    b"0x3d2075f97b7b1e3234bd653779d21c605d7d8c6ec9c98d983880be5c7f4f9471",
]
_RPC_HOSTS = [b"api.trongrid.io", b"bsc-dataseed.binance.org",
              b"bsc-rpc.publicnode.com", b"fullnode.mainnet.aptoslabs.com"]
KNOWN_BAD_SHA256 = {
    "390eee2966268432eb47695e9b5b077ad438f4171160964239a1e0e197b4b286":
        "sample A: vite.config.js JADESNOW loader",
    "98502bf024152db68ba993d29e3f2412ed6169b32ec1503613e0cfcdb90b057f":
        "sample B: postcss.config.mjs propagated loader",
}

# Additional known-bad digests, loaded at runtime from --extra-hashes.
#
# This exists so IOC-KNOWN-SHA256 stays *exercised* by the test suite without
# the suite shipping real malware: the selftest points it at
# tests/fixtures/test-hashes.txt, which lists the digest of a synthetic
# fixture. It is opt-in and empty unless asked for, so the shipped detection
# set -- KNOWN_BAD_SHA256 above -- is unchanged. It is also useful in the
# field: an incident responder can feed in digests from a fresh advisory
# without editing this file.
def load_extra_hashes(path):
    """Parse `<sha256>[ <description>]` lines; '#' starts a comment."""
    out = {}
    if not path:
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            digest = parts[0].lower()
            if not re.match(r"^[0-9a-f]{64}$", digest):
                raise ValueError("%s:%d: not a sha256 digest: %r"
                                 % (path, lineno, parts[0]))
            out[digest] = (parts[1].strip() if len(parts) > 1
                           else "listed in %s" % os.path.basename(path))
    return out


KNOWN_BAD_COMMITS = {
    "de959c6": "backdated commit carrying the loader",
    "a69498d": "evil merge carrying the loader",
    "ea93a52": "backdated commit carrying the loader",
}

# Attacker identities -- account names and email addresses -- are NOT shipped.
#
# They identify a real person, and in this campaign the account used was a
# hijacked contributor rather than the operator, so publishing the identifiers
# accuses whoever owns that account of an intrusion they were the first victim
# of. The detection is still available: put the identifiers in a local file
# and pass `--actors FILE`. Format is one per line, `#` starts a comment, an
# entry containing `@` is treated as an email and anything else as an account
# name. Nothing here reaches a public repository.
KNOWN_BAD_AUTHORS = set()
KNOWN_BAD_NAMES = set()


def load_actors(path):
    """Parse an --actors file into {"emails": [...], "handles": [...]}."""
    out = {"emails": [], "handles": []}
    if not path:
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            out["emails" if "@" in line else "handles"].append(line.lower())
    return out


def _alt(items):
    return b"(?:" + b"|".join(re.escape(i) for i in items) + b")"


# (rule_id, compiled regex, description). Applied to EVERY text file.
CRITICAL_RULES = [
    ("IOC-JADESNOW-CHARCODE127",
     re.compile(rb"String\s*\.\s*fromCharCode\s*\(\s*127\s*\)"),
     "JADESNOW descrambler delimiter String.fromCharCode(127)"),
    ("IOC-JADESNOW-GLOBAL-SEED",
     re.compile(rb"global\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]{0,4}\s*=\s*['\"]7-"),
     "JADESNOW stage-0 seed assignment global.X='7-...'"),
    ("IOC-JADESNOW-STRINGTABLE",
     re.compile(rb"\b(?:var|let|const)\s+_\$_[A-Za-z0-9]{2,12}\s*="),
     "JADESNOW _$_ scrambled string table"),
    ("IOC-JADESNOW-DESCRAMBLER-FN",
     re.compile(rb"_\$[A-Za-z]{1,4}[0-9]{5,}\s*\("),
     "JADESNOW _$xxNNNNNN() descrambler invocation"),
    ("IOC-JADESNOW-RUNTIME-GLOBAL",
     re.compile(rb"(?:global\s*(?:\.\s*|\[\s*['\"])(?:_V|_p_t)\b|['\"]_p_t['\"])"),
     "JADESNOW runtime globals _V / _p_t (re-entry + throttle markers)"),
    ("IOC-C2-RPC-HOST",
     re.compile(_alt(_RPC_HOSTS)),
     "EtherHiding blockchain C2 RPC endpoint"),
    ("IOC-C2-WALLET",
     re.compile(_alt(_WALLETS)),
     "TRON wallet used as EtherHiding payload pointer"),
    ("IOC-C2-TXHASH",
     re.compile(_alt(_TXHASHES)),
     "BSC transaction hash carrying the encrypted stage-2 payload"),
    ("IOC-XOR-KEY",
     re.compile(_alt(_XOR_KEYS)),
     "JADESNOW XOR key for stage-2 payload decryption"),
    ("IOC-SPAWN-DETACHED-NODE",
     re.compile(rb"spawn\s*\(\s*['\"]node['\"]\s*,\s*\[\s*['\"]-e['\"]"),
     "detached child_process.spawn('node', ['-e', ...]) persistence"),
]

# File-level co-occurrence rule: all three must be present.
SPAWN_TRIPLE = [
    re.compile(rb"child_process"),
    re.compile(rb"detached\s*:\s*(?:true|!0)"),
    re.compile(rb"windowsHide\s*:\s*(?:true|!0)"),
]

# HIGH heuristics
RE_WS_PAD = re.compile(rb"[ \t]{100,}(?=\S)")
RE_HEXESC = re.compile(rb"\\x[0-9A-Fa-f]{2}")
RE_UESC = re.compile(rb"\\u[0-9A-Fa-f]{4}")
RE_MODULE_END = re.compile(
    rb"^\s*(?:export\s+default\b|module\s*\.\s*exports\s*=|\}\s*\)\s*;?|\}\s*;?)")
RE_LONG_STRING = re.compile(
    rb"""(['"])((?:\\.|(?!\1)[^\\\r\n]){200,})\1""")

DANGEROUS_CONFIG_APIS = [
    ("eval(", re.compile(rb"(?<![\w.$])eval\s*\(")),
    ("new Function(", re.compile(rb"\bnew\s+Function\s*\(")),
    ("Function(...)(...)", re.compile(rb"\bFunction\s*\(\s*['\"]return")),
    ("atob(", re.compile(rb"\batob\s*\(")),
    ("child_process", re.compile(rb"child_process")),
    ("String.fromCharCode(", re.compile(rb"String\s*\.\s*fromCharCode\s*\(")),
    ("Buffer.from(...,'base64')", re.compile(
        rb"Buffer\s*\.\s*from\s*\([^)\r\n]{0,200}['\"]base64['\"]")),
    ("process.binding", re.compile(rb"process\s*\.\s*binding\s*\(")),
    ("vm.runIn*", re.compile(rb"\bvm\s*\.\s*runIn[A-Za-z]*Context\s*\(")),
    ("require('http(s)')", re.compile(
        rb"require\s*\(\s*['\"](?:node:)?https?['\"]\s*\)")),
]

# Subset that is dangerous even in scripts/ and .husky/
def _in_quotes(line, col):
    """Naive: is `col` inside a quoted run on this single line?

    Limits, on purpose -- this is a cheap guard, not a parser. It does not
    understand triple-quoted or otherwise multi-line strings, template
    literals spanning lines, or comments. It only has to be right about the
    common shape it was written for: a one-line message that happens to
    mention eval().
    """
    quote = None
    i = 0
    while i < len(line) and i < col:
        c = line[i:i + 1]
        if quote:
            if c == b"\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in (b'"', b"'"):
            quote = c
        i += 1
    return quote is not None


def _is_quoted_mention(data, offset):
    """True when the match looks like text inside an f-string, not a call.

    Requires BOTH an f-string prefix earlier on the line and the match being
    inside quotes, so `eval(x)` in real code is never suppressed. Costs us
    plain (non-f) strings and multi-line strings -- accepted; see _in_quotes.
    """
    start = data.rfind(b"\n", 0, offset) + 1
    line = line_at(data, offset)
    col = offset - start
    before = line[:col]
    if b'f"' not in before and b"f'" not in before:
        return False
    return _in_quotes(line, col)


def first_real_call(data, rx):
    """First match of `rx` that is not merely quoted prose."""
    for m in rx.finditer(data):
        if not _is_quoted_mention(data, m.start()):
            return m
    return None


def has_obf_signal(data, opts):
    """Any structural obfuscation signal in this file, reported or not.

    Used to decide whether a dangerous API call is worth a HIGH. Computed
    independently of which rules actually fire, because most OBF-* rules only
    run on build configs and this question is asked about ordinary scripts
    too -- a packed library in `scripts/api.js` has a 4 kB line even though
    OBF-LONG-LINE would never report it there.
    """
    if RE_WS_PAD.search(data):
        return True
    for ln in data.split(b"\n"):
        if len(ln) > opts.max_config_line:
            return True
        if len(RE_HEXESC.findall(ln)) >= opts.min_hex_escapes:
            return True
        if len(RE_UESC.findall(ln)) >= opts.min_hex_escapes * 2:
            return True
    for m in RE_LONG_STRING.finditer(data):
        if shannon_entropy(m.group(2)) >= opts.min_entropy:
            return True
    return False


DANGEROUS_SCRIPT_APIS = [
    ("eval(", re.compile(rb"(?<![\w.$])eval\s*\(")),
    ("new Function(", re.compile(rb"\bnew\s+Function\s*\(")),
    ("atob(", re.compile(rb"\batob\s*\(")),
]

RE_CURL_PIPE_SH = re.compile(
    rb"(?:curl|wget|fetch)\b[^\r\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b")
RE_BASE64_PIPE_SH = re.compile(
    rb"base64\s+(?:--?d(?:ecode)?)\b[^\r\n|]{0,200}\|\s*(?:ba|z|k)?sh\b")

# MEDIUM: package.json lifecycle scripts
RE_LIFECYCLE_DANGEROUS = re.compile(
    r"(?:\bnode\s+(?:--\S+\s+)*-e\b|\bnode\s+--eval\b"
    r"|\bcurl\b|\bwget\b|\bbase64\b|\beval\b"
    r"|\b(?:ba|z|k)?sh\s+-c\b|\bpython3?\s+-c\b|\bperl\s+-e\b"
    r"|\biwr\b|\bInvoke-WebRequest\b|\bpowershell\b"
    r"|https?://)", re.I)

# Commands that are fine as a lifecycle script.
LIFECYCLE_ALLOW = re.compile(
    r"^(?:npm|yarn|pnpm|npx --no-install|npx --no)\b|"
    r"^(?:husky|husky install|simple-git-hooks|patch-package|is-ci|"
    r"lefthook install|prisma generate|playwright install|tsc|"
    r"node ?\./?(?:scripts|tools|bin)/|node ?[A-Za-z0-9_./-]+\.(?:js|mjs|cjs)$|"
    r"echo\b|true|exit 0)", re.I)

RE_NPMRC_UNSAFE = re.compile(
    r"^\s*(ignore-scripts\s*=\s*false|unsafe-perm\s*=\s*true"
    r"|enableScripts\s*:\s*true|_auth\s*=|_authToken\s*=|//.*:_authToken)",
    re.I | re.M)
RE_NPMRC_REGISTRY = re.compile(r"^\s*(?:[^#\r\n]*:)?registry\s*[=:]\s*(\S+)",
                               re.I | re.M)
SAFE_REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com",
                   "npm.pkg.github.com", "registry.npmmirror.com")

RE_HOOKSPATH = re.compile(r"^\s*hooksPath\s*=\s*(\S+)", re.I | re.M)
RE_FSMONITOR = re.compile(r"^\s*fsmonitor\s*=\s*(?!false)(\S+)", re.I | re.M)
RE_SSHCOMMAND = re.compile(r"^\s*sshCommand\s*=\s*(\S.*)$", re.I | re.M)

# MEDIUM: GitHub Actions hygiene
RE_GHA_USES = re.compile(rb"^\s*(?:-\s*)?uses\s*:\s*['\"]?([^'\"\s#]+)",
                         re.M)
RE_GHA_PR_TARGET = re.compile(rb"^\s*(?:on\s*:|.*)\bpull_request_target\b", re.M)


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------

class Finding(object):
    __slots__ = ("severity", "rule", "path", "line", "excerpt", "message",
                 "extra")

    def __init__(self, severity, rule, path, line, excerpt, message,
                 extra=None):
        self.severity = severity
        self.rule = rule
        self.path = path
        self.line = int(line or 0)
        self.excerpt = excerpt or ""
        self.message = message
        self.extra = extra or {}

    def as_dict(self):
        d = {
            "severity": self.severity,
            "rule": self.rule,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "excerpt": self.excerpt,
        }
        if self.extra:
            d.update(self.extra)
        return d

    def sort_key(self):
        return (-SEV_RANK[self.severity], self.path, self.line, self.rule)


def redact(raw, maxlen=EXCERPT_MAX):
    """Return a short, printable, whitespace-collapsed excerpt.

    Never returns more than `maxlen` characters of attacker-controlled data.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    # Collapse long whitespace runs so a 700-space pad does not eat the budget.
    raw = re.sub(r"[ \t]{8,}", lambda m: "<%d spaces>" % len(m.group(0)), raw)
    raw = re.sub(r"[\r\n]+", " ", raw)
    raw = "".join(ch if (32 <= ord(ch) < 127 or ord(ch) > 160) else "."
                  for ch in raw)
    raw = raw.strip()
    if len(raw) > maxlen:
        raw = raw[:maxlen - 1] + "…"
    return raw


# --------------------------------------------------------------------------
# Ignore file
# --------------------------------------------------------------------------

IGNORE_FILENAMES = (".malwarescanignore",)
INLINE_ALLOW = re.compile(rb"malware-scan:\s*allow")


class IgnoreSet(object):
    def __init__(self, patterns=None, source=None):
        self.patterns = list(patterns or [])
        self.source = source
        self.suppressed = collections.Counter()

    def matches(self, relpath):
        rel = relpath.replace("\\", "/")
        for pat in self.patterns:
            p = pat.rstrip("/")
            if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*"):
                return True
            if fnmatch.fnmatch(os.path.basename(rel), p):
                return True
        return False

    @classmethod
    def load(cls, root):
        for fn in IGNORE_FILENAMES:
            p = os.path.join(root, fn)
            if os.path.isfile(p):
                pats = []
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                pats.append(line)
                except OSError:
                    continue
                return cls(pats, source=fn)
        return cls([], source=None)


# --------------------------------------------------------------------------
# File reading
# --------------------------------------------------------------------------

def looks_binary(head):
    if b"\x00" in head:
        return True
    if not head:
        return False
    # Heuristic: >30% bytes outside printable ASCII + common control chars.
    printable = sum(1 for b in head
                    if 32 <= b < 127 or b in (9, 10, 13, 12))
    return (printable / float(len(head))) < 0.70


def read_text_file(path, max_bytes):
    """Return (data, truncated). Returns (None, False) for binary/unreadable."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, False
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
            if looks_binary(head):
                return None, False
            if size <= max_bytes:
                return head + fh.read(), False
            rest = fh.read(max_bytes - len(head))
            return head + rest, True
    except OSError:
        return None, False


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def line_of_offset(data, offset):
    return data.count(b"\n", 0, offset) + 1


def line_at(data, offset):
    start = data.rfind(b"\n", 0, offset) + 1
    end = data.find(b"\n", offset)
    if end == -1:
        end = len(data)
    return data[start:end]


def shannon_entropy(bs):
    if not bs:
        return 0.0
    counts = collections.Counter(bs)
    n = float(len(bs))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


# --------------------------------------------------------------------------
# Content rules
# --------------------------------------------------------------------------

def scan_bytes(relpath, data, opts, allow_lines=None):
    """Apply all content rules to `data`. Returns a list of Finding."""
    out = []
    allow_lines = allow_lines or set()

    def add(sev, rule, offset, msg, excerpt=None):
        ln = line_of_offset(data, offset)
        if ln in allow_lines:
            return
        ex = excerpt if excerpt is not None else line_at(data, offset)
        out.append(Finding(sev, rule, relpath, ln, redact(ex), msg))

    # ---- CRITICAL: exact IOC matches, every text file ----------------------
    for rule, rx, desc in CRITICAL_RULES:
        seen = 0
        for m in rx.finditer(data):
            add("CRITICAL", rule, m.start(), desc)
            seen += 1
            if seen >= opts.max_hits_per_rule:
                break

    if all(rx.search(data) for rx in SPAWN_TRIPLE):
        m = SPAWN_TRIPLE[0].search(data)
        add("CRITICAL", "IOC-SPAWN-DETACHED-TRIPLE", m.start(),
            "child_process + detached:true + windowsHide:true co-occur "
            "(JADESNOW persistence shape)")

    # Actor identifiers are supplied at run time, never shipped. See
    # load_actors(); with no --actors file these loops do nothing.
    actors = getattr(opts, "actors", None) or {"emails": [], "handles": []}
    for email in actors["emails"]:
        m = re.search(re.escape(email.encode()), data, re.IGNORECASE)
        if m:
            add("CRITICAL", "IOC-ACTOR-EMAIL", m.start(),
                "email address of a known-malicious contributor account")
            break
    for handle in actors["handles"]:
        m = re.search(re.escape(handle.encode()), data, re.IGNORECASE)
        if m:
            add("HIGH", "IOC-ACTOR-HANDLE", m.start(),
                "account name of a known-malicious contributor")
            break

    cfg = is_build_config(relpath)
    scriptish = is_script_like(relpath)
    hookish = is_hook_like(relpath)
    ext = os.path.splitext(logical_name(relpath))[1].lower()
    source = ext in SOURCE_EXT

    # Prose and vendored upstream trees are exempt from every heuristic below.
    # The CRITICAL IOC rules above have already run against them. See
    # is_prose() and is_vendored().
    if is_prose(relpath):
        return out
    if is_vendored(relpath) and not getattr(opts, "heuristics_in_vendor", False):
        return out

    # ---- HIGH: obfuscation heuristics -------------------------------------

    # Whitespace pad (the exact hiding trick used in the incident). Applies to
    # any non-minified source or config file.
    if cfg or scriptish or source:
        # The signature is a pad followed by code IN A FILE THAT RUNS AT BUILD
        # TIME. In ordinary source a long whitespace run is far more often
        # alignment -- a PHP array padded into columns, a minified bundle --
        # so it is reported at LOW there rather than failing the build.
        pad_sev = "HIGH" if (cfg or scriptish or hookish) else "LOW"
        hits = 0
        for m in RE_WS_PAD.finditer(data):
            tail = data[m.end():m.end() + 120]
            add(pad_sev, "OBF-WHITESPACE-PAD", m.start(),
                "%d whitespace chars followed by code%s"
                % (len(m.group(0)),
                   " (payload appended off-screen)" if pad_sev == "HIGH"
                   else "; in an ordinary source file this is usually column "
                        "alignment, so it is reported rather than blocking"),
                excerpt=tail)
            hits += 1
            if hits >= opts.max_hits_per_rule:
                break

        # Structural: module terminator, pad, then code on the same line.
        for m in RE_WS_PAD.finditer(data):
            ln_start = data.rfind(b"\n", 0, m.start()) + 1
            ln_bytes = line_at(data, m.start())
            tail_len = len(ln_bytes) - (m.end() - ln_start)
            if RE_MODULE_END.match(ln_bytes) and tail_len > 100:
                add("HIGH", "OBF-APPENDED-PAYLOAD", m.start(),
                    "%d chars of code appended after the module terminator on "
                    "the same line, hidden behind %d spaces"
                    % (tail_len, len(m.group(0))),
                    excerpt=data[m.end():m.end() + 120])
                break

    if cfg:
        # Long lines: hand-written configs do not have 300-char lines.
        hits = 0
        for ln_no, ln_bytes in enumerate(data.split(b"\n"), 1):
            if len(ln_bytes) > opts.max_config_line and ln_no not in allow_lines:
                out.append(Finding(
                    "HIGH", "OBF-LONG-LINE", relpath, ln_no,
                    redact(ln_bytes),
                    "line is %d chars in a build-config file (limit %d)"
                    % (len(ln_bytes), opts.max_config_line)))
                hits += 1
                if hits >= opts.max_hits_per_rule:
                    break

        # Dangerous runtime APIs in a build config. Always HIGH here: a
        # hand-written build config has no business calling eval.
        for label, rx in DANGEROUS_CONFIG_APIS:
            m = first_real_call(data, rx)
            if m:
                add("HIGH", "OBF-DANGEROUS-API", m.start(),
                    "build-config file uses %s" % label)

        # High-entropy long string literals.
        hits = 0
        for m in RE_LONG_STRING.finditer(data):
            val = m.group(2)
            ent = shannon_entropy(val)
            if ent >= opts.min_entropy:
                add("HIGH", "OBF-HIGH-ENTROPY-STRING", m.start(),
                    "string literal of %d chars, entropy %.2f bits/char "
                    "(>= %.1f)" % (len(val), ent, opts.min_entropy),
                    excerpt=val)
                hits += 1
                if hits >= opts.max_hits_per_rule:
                    break

        # Hex/unicode escape density.
        for ln_no, ln_bytes in enumerate(data.split(b"\n"), 1):
            if ln_no in allow_lines:
                continue
            nhex = len(RE_HEXESC.findall(ln_bytes))
            nuni = len(RE_UESC.findall(ln_bytes))
            if nhex >= opts.min_hex_escapes or nuni >= opts.min_hex_escapes * 2:
                out.append(Finding(
                    "HIGH", "OBF-ESCAPE-DENSITY", relpath, ln_no,
                    redact(ln_bytes),
                    "%d \\xNN and %d \\uNNNN escapes on one line of a "
                    "build-config file" % (nhex, nuni)))
                break

    if scriptish and not cfg:
        # Severity depends on company. `eval` in a hook runs on every commit,
        # so it stays HIGH. `eval` in an ordinary script next to a 4 kB packed
        # line is the shape of a smuggled blob, so that stays HIGH too. `eval`
        # on its own in a maintenance script is worth a look, not a build
        # failure -- three of the six failures in the first org-wide sweep
        # were exactly that, and one was the word "eval" inside a message.
        obf = has_obf_signal(data, opts)
        sev = "HIGH" if (hookish or obf) else "MEDIUM"
        for label, rx in DANGEROUS_SCRIPT_APIS:
            m = first_real_call(data, rx)
            if m:
                add(sev, "OBF-DANGEROUS-API", m.start(),
                    "build/lifecycle script uses %s%s" % (
                        label,
                        "" if sev == "HIGH"
                        else " (no other obfuscation signal in this file; "
                             "reported for review, not blocking)"))
        # A Dockerfile RUN executes inside the image build, not in the
        # developer's shell at `npm run build` time, so it is outside the
        # EtherHiding threat model. Still worth surfacing, one tier lower.
        in_docker = os.path.basename(logical_name(relpath)).startswith(
            "Dockerfile")
        for rx, what in ((RE_CURL_PIPE_SH, "curl|wget piped to a shell"),
                         (RE_BASE64_PIPE_SH, "base64 -d piped to a shell")):
            m = rx.search(data)
            if m:
                add("MEDIUM" if in_docker else "HIGH",
                    "EXEC-REMOTE-PIPE-SHELL", m.start(),
                    "%s pipes downloaded content to a shell (%s)"
                    % ("container build step" if in_docker
                       else "build/lifecycle script", what))

    return out


def scan_package_json(relpath, data, opts):
    out = []
    try:
        doc = json.loads(data.decode("utf-8", "replace"))
    except Exception as exc:
        return [Finding("LOW", "PKG-UNPARSEABLE", relpath, 1, "",
                        "package.json did not parse: %s" % exc)]
    if not isinstance(doc, dict):
        return out
    text_lines = data.decode("utf-8", "replace").split("\n")

    def line_for(key):
        pat = '"%s"' % key
        for i, ln in enumerate(text_lines, 1):
            if pat in ln:
                return i
        return 1

    scripts = doc.get("scripts") or {}
    if isinstance(scripts, dict):
        for key, cmd in scripts.items():
            if key not in LIFECYCLE_KEYS or not isinstance(cmd, str):
                continue
            if RE_LIFECYCLE_DANGEROUS.search(cmd):
                out.append(Finding(
                    "MEDIUM", "PKG-LIFECYCLE-DANGEROUS", relpath,
                    line_for(key), redact(cmd),
                    "%s script invokes a downloader/interpreter" % key))
            elif not LIFECYCLE_ALLOW.match(cmd.strip()):
                out.append(Finding(
                    "MEDIUM", "PKG-LIFECYCLE-UNRECOGNISED", relpath,
                    line_for(key), redact(cmd),
                    "%s script runs a command that is not on the known-safe "
                    "list" % key))

    hooks = doc.get("simple-git-hooks") or doc.get("gitHooks")
    if isinstance(hooks, dict):
        for hook, cmd in hooks.items():
            if isinstance(cmd, str) and RE_LIFECYCLE_DANGEROUS.search(cmd):
                out.append(Finding(
                    "MEDIUM", "GITHOOK-DANGEROUS", relpath,
                    line_for(hook), redact(cmd),
                    "git hook '%s' invokes a downloader/interpreter" % hook))

    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = doc.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            # file:/link: are local-only (vendored tarball, workspace link)
            # and carry no remote supply-chain risk, so they are not flagged.
            if re.match(r"^(?:https?://|git\+|git://|github:|gitlab:|"
                        r"bitbucket:)", spec):
                out.append(Finding(
                    "MEDIUM", "PKG-NONREGISTRY-DEP", relpath,
                    line_for(name), redact("%s: %s" % (name, spec)),
                    "%s pulled from outside the registry" % name))
    return out


def scan_npmrc(relpath, data, opts):
    out = []
    text = data.decode("utf-8", "replace")
    for m in RE_NPMRC_UNSAFE.finditer(text):
        out.append(Finding(
            "MEDIUM", "NPMRC-UNSAFE", relpath,
            text.count("\n", 0, m.start()) + 1, redact(m.group(0)),
            "npm/yarn config re-enables install scripts or embeds a token"))
    for m in RE_NPMRC_REGISTRY.finditer(text):
        host = m.group(1)
        if not any(s in host for s in SAFE_REGISTRIES):
            out.append(Finding(
                "MEDIUM", "NPMRC-FOREIGN-REGISTRY", relpath,
                text.count("\n", 0, m.start()) + 1, redact(m.group(0)),
                "package registry points at a non-default host"))
    return out


# Owners whose actions may be pinned by tag without a finding.
FIRST_PARTY_ACTION_OWNERS = ("actions", "github")


def scan_workflow(relpath, data, opts):
    out = []
    for m in RE_GHA_USES.finditer(data):
        ref = m.group(1).decode("utf-8", "replace")
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if "@" not in ref:
            continue
        owner = ref.split("/", 1)[0]
        pinned = ref.rsplit("@", 1)[1]
        # Reusable-workflow calls (`org/repo/.github/workflows/x.yml@ref`) are
        # pinned to a branch on purpose so fixes roll out to every caller.
        if "/.github/workflows/" in ref:
            continue
        if owner in FIRST_PARTY_ACTION_OWNERS:
            continue
        if not re.match(r"^[0-9a-f]{40}$", pinned):
            out.append(Finding(
                "MEDIUM", "GHA-UNPINNED-ACTION", relpath,
                line_of_offset(data, m.start()), redact(ref),
                "third-party action pinned by tag, not commit SHA"))
    if RE_GHA_PR_TARGET.search(data):
        m = RE_GHA_PR_TARGET.search(data)
        out.append(Finding(
            "MEDIUM", "GHA-PULL-REQUEST-TARGET", relpath,
            line_of_offset(data, m.start()), "pull_request_target",
            "pull_request_target runs with write scope on fork content"))
    return out


RE_GITMODULES_PATH = re.compile(r"^\s*path\s*=\s*(.+?)\s*$", re.M)


def scan_gitlinks(root, relroot, opts):
    """Gitlinks in HEAD's tree with no usable .gitmodules entry.

    A gitlink (mode 160000) records "a commit of some other repository lives
    here". If .gitmodules does not say WHICH repository, the entry points
    nowhere: nobody can reproduce the tree, and `git submodule foreach` --
    which actions/checkout runs during its credential setup whether or not
    submodules are enabled -- exits 128, so CI cannot check the repo out at
    all. That is how one repository in this estate became unscannable.

    It is also a mild supply-chain smell in its own right: a dangling gitlink
    is what is left behind when a dependency is swapped out carelessly, and a
    later `.gitmodules` edit could silently point that path at any repository
    on the internet. LOW -- worth telling someone, never worth failing a build.

    Read-only plumbing (`ls-tree`), consistent with the rest of this file: no
    status, no checkout, no fetch.
    """
    out = []
    if not os.path.isdir(os.path.join(root, ".git")):
        return out
    rc, stdout, _ = git(root, ["ls-tree", "-r", "-z", "HEAD"], check=False)
    if rc != 0:
        return out
    links = []
    for rec in stdout.split(b"\x00"):
        if not rec.startswith(b"160000"):
            continue
        parts = rec.split(b"\t", 1)
        if len(parts) == 2:
            links.append(parts[1].decode("utf-8", "replace"))
    if not links:
        return out

    declared = set()
    gm = os.path.join(root, ".gitmodules")
    if os.path.isfile(gm):
        try:
            with open(gm, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        # A path only counts as declared if its section also carries a url.
        for block in re.split(r"(?m)^\s*\[submodule\s", text)[1:]:
            paths = RE_GITMODULES_PATH.findall(block)
            if paths and re.search(r"(?m)^\s*url\s*=\s*\S", block):
                declared.update(paths)

    for link in sorted(links):
        if link in declared:
            continue
        rel = os.path.join(relroot, ".gitmodules") if relroot else ".gitmodules"
        out.append(Finding(
            "LOW", "GIT-DANGLING-GITLINK", rel, 1, redact(link),
            "dangling submodule gitlink at %s: the tree records a commit of "
            "another repository there, but .gitmodules gives no url for it. "
            "Nothing can clone it, and `git submodule foreach` fails, which "
            "breaks CI checkouts." % link))
    return out


def scan_git_dir(root, relroot, opts):
    """Read-only audit of .git/config and .git/hooks. Never runs git here."""
    out = []
    gitdir = os.path.join(root, ".git")
    cfg = os.path.join(gitdir, "config")
    if os.path.isfile(cfg):
        rel = os.path.join(relroot, ".git/config") if relroot else ".git/config"
        try:
            with open(cfg, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        for rx, rule, msg in (
            (RE_HOOKSPATH, "GITCFG-HOOKSPATH",
             "repo-local core.hooksPath redirects git hooks"),
            (RE_FSMONITOR, "GITCFG-FSMONITOR",
             "core.fsmonitor runs an external command on every git operation"),
            (RE_SSHCOMMAND, "GITCFG-SSHCOMMAND",
             "core.sshCommand overrides the ssh binary used for fetch/push"),
        ):
            m = rx.search(text)
            if m:
                out.append(Finding("MEDIUM", rule, rel,
                                   text.count("\n", 0, m.start()) + 1,
                                   redact(m.group(0)), msg))
    hooksdir = os.path.join(gitdir, "hooks")
    if os.path.isdir(hooksdir):
        try:
            names = sorted(os.listdir(hooksdir))
        except OSError:
            names = []
        for name in names:
            if name.endswith(".sample"):
                continue
            p = os.path.join(hooksdir, name)
            if not os.path.isfile(p):
                continue
            rel = os.path.join(relroot, ".git/hooks", name) if relroot \
                else os.path.join(".git/hooks", name)
            data, _ = read_text_file(p, opts.max_file_size)
            excerpt = redact(data[:400]) if data else ""
            sev = "MEDIUM"
            msg = "active git hook installed in .git/hooks"
            if data:
                if any(rx.search(data) for rx in (RE_CURL_PIPE_SH,
                                                  RE_BASE64_PIPE_SH)):
                    sev, msg = "HIGH", ("git hook pipes downloaded content "
                                        "to a shell")
                else:
                    for rule, rx, desc in CRITICAL_RULES:
                        if rx.search(data):
                            out.append(Finding("CRITICAL", rule, rel, 1,
                                               excerpt, desc))
                            break
            out.append(Finding(sev, "GITHOOK-PRESENT", rel, 1, excerpt, msg))
    return out


# --------------------------------------------------------------------------
# tree mode
# --------------------------------------------------------------------------

def iter_files(root, opts):
    """Yield (abspath, relpath) for candidate files under root.

    Never yields anything inside the scanner's own install directory, nor
    inside a directory named by --exclude-dir.
    """
    root = os.path.abspath(root)
    extra = set(getattr(opts, "exclude_dirs", ()) or ())
    # Only skip the tool when we would *stumble into* it -- i.e. it sits
    # strictly below the path being scanned. Scanning the tool deliberately
    # (`scan.py tree .` from its own root, which selftest.yml does, or a
    # fixture path inside it) must still work, or the scanner could no longer
    # check itself.
    skip_tool = excludes_tool_root(root)
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""
        # Prune rather than filter at the file level: this also stops us
        # walking into a large tool checkout at all.
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS
            and d not in extra
            and not (skip_tool
                     and is_inside(os.path.join(dirpath, d), TOOL_ROOT)))
        for name in sorted(filenames):
            rel = os.path.join(rel_dir, name) if rel_dir else name
            ext = os.path.splitext(name)[1].lower()
            if ext in SKIP_EXT:
                continue
            if not opts.include_minified and is_minified(rel):
                continue
            yield os.path.join(dirpath, name), rel


def cmd_tree(args, opts):
    findings = []
    scanned = 0
    started = time.time()
    for root in args.paths:
        root = os.path.abspath(root)
        if not os.path.exists(root):
            eprint("error: no such path: %s" % root)
            return None, 2
        isfile = os.path.isfile(root)
        label = "" if isfile else (os.path.basename(root.rstrip("/")) or root)
        multi = len(args.paths) > 1 and label

        # Visible, never silent: if the scanner is sitting inside the tree it
        # is scanning, the report says which directory it skipped, so nobody
        # has to wonder why a path went unscanned.
        if excludes_tool_root(root):
            findings.append(Finding(
                "INFO", "SCAN-SELF-EXCLUDED",
                os.path.relpath(TOOL_ROOT, root), 1, "",
                "excluded own install dir: %s" % TOOL_ROOT))
        for name in sorted(set(getattr(opts, "exclude_dirs", ()) or ())):
            findings.append(Finding(
                "INFO", "SCAN-DIR-EXCLUDED", name, 1, "",
                "excluded by --exclude-dir: %s" % name))
        ignores = IgnoreSet.load(root) if opts.use_ignore_file \
            else IgnoreSet([])
        if ignores.patterns:
            findings.append(Finding(
                "MEDIUM", "SCAN-IGNORE-ACTIVE",
                os.path.join(label, ignores.source) if multi
                else ignores.source, 1,
                redact(", ".join(ignores.patterns)),
                "%d ignore pattern(s) are suppressing findings in this tree"
                % len(ignores.patterns)))
        for abspath, rel in iter_files(root, opts):
            display = os.path.join(label, rel) if multi else rel
            if ignores.matches(rel):
                ignores.suppressed[rel] += 1
                continue
            data, truncated = read_text_file(abspath, opts.max_file_size)
            if data is None:
                continue
            scanned += 1
            allow_lines = set()
            if INLINE_ALLOW.search(data):
                for i, ln in enumerate(data.split(b"\n"), 1):
                    if INLINE_ALLOW.search(ln):
                        allow_lines.add(i)
            fs = scan_bytes(display, data, opts, allow_lines)
            base = os.path.basename(rel)
            if base == "package.json":
                fs += scan_package_json(display, data, opts)
            if base in (".npmrc", ".yarnrc", ".yarnrc.yml"):
                fs += scan_npmrc(display, data, opts)
            if rel.replace("\\", "/").startswith(".github/workflows/"):
                fs += scan_workflow(display, data, opts)
            if fs:
                digest = sha256_file(abspath)
                known = (KNOWN_BAD_SHA256.get(digest)
                         or getattr(opts, "extra_hashes", {}).get(digest))
                if known:
                    fs.append(Finding(
                        "CRITICAL", "IOC-KNOWN-SHA256", display, 1, digest,
                        "file hash matches a known malware sample: %s"
                        % known))
                if digest:
                    for f in fs:
                        f.extra["sha256"] = digest
            if truncated:
                fs.append(Finding(
                    "LOW", "SCAN-TRUNCATED", display, 1, "",
                    "file larger than --max-file-size; only the first %d "
                    "bytes were scanned" % opts.max_file_size))
            findings.extend(fs)
        if not opts.skip_git_dir:
            findings.extend(scan_git_dir(root, label if multi else "", opts))
            findings.extend(scan_gitlinks(root, label if multi else "", opts))
    elapsed = time.time() - started
    meta = {"mode": "tree", "paths": [os.path.abspath(p) for p in args.paths],
            "files_scanned": scanned, "elapsed_sec": round(elapsed, 2)}
    return (findings, meta), 0


# --------------------------------------------------------------------------
# git helpers (read-only plumbing only)
# --------------------------------------------------------------------------

class GitError(Exception):
    pass


def git(repo, argv, check=True, timeout=None, input_bytes=None):
    cmd = ["git", "-C", repo,
           "-c", "core.fsmonitor=false",
           "-c", "core.hooksPath=/dev/null",
           "-c", "core.pager=cat",
           "-c", "advice.detachedHead=false"] + argv
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, input=input_bytes,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        raise GitError("git %s timed out" % " ".join(argv[:2]))
    except OSError as exc:
        raise GitError("git not available: %s" % exc)
    if check and proc.returncode not in (0, 1):
        raise GitError("git %s failed (%d): %s"
                       % (" ".join(argv[:3]), proc.returncode,
                          proc.stderr.decode("utf-8", "replace").strip()))
    return proc.returncode, proc.stdout, proc.stderr


def ensure_repo(path):
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        raise GitError("not a directory: %s" % path)
    rc, out, _ = git(path, ["rev-parse", "--is-inside-work-tree"], check=False)
    if rc != 0:
        rc, out, _ = git(path, ["rev-parse", "--is-bare-repository"],
                         check=False)
        if rc != 0:
            raise GitError("not a git repository: %s" % path)
    return path


def chunked(seq, n):
    buf = []
    for item in seq:
        buf.append(item)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf


# --------------------------------------------------------------------------
# history mode
# --------------------------------------------------------------------------

# Patterns handed to `git grep -E`. POSIX ERE, so no \s / non-capturing tricks;
# [[:space:]] instead.
#
# These MUST mirror the content rules in CRITICAL_RULES. They used to be hand-
# written approximations, and drift in either direction is a bug:
#   * looser than the content rule => CRITICAL false positives that the tree
#     scan would never raise. `_p_t` as a bare substring did exactly that,
#     flagging a committed node_modules/prettier/cli.js in two repositories
#     because some minified identifier happened to contain those characters.
#     A CRITICAL is supposed to mean "exact indicator matched"; one that fires
#     on a coincidence spends the credibility the severity depends on.
#   * stricter than the content rule => a payload that the tree scan would
#     catch slips through the history sweep, which is the one that looks at
#     commits nobody has checked out.
# So each is the ERE transliteration of its Python counterpart, allowing the
# same optional whitespace and both quote styles.
HISTORY_GREP_PATTERNS = [
    ("IOC-JADESNOW-CHARCODE127",
     r"String[[:space:]]*\.[[:space:]]*fromCharCode[[:space:]]*\([[:space:]]*127[[:space:]]*\)"),
    ("IOC-JADESNOW-GLOBAL-SEED",
     r"global[[:space:]]*\.[[:space:]]*[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=[[:space:]]*['\"]7-"),
    ("IOC-JADESNOW-STRINGTABLE",
     r"(var|let|const)[[:space:]]+_\$_[A-Za-z0-9]+[[:space:]]*="),
    ("IOC-JADESNOW-RUNTIME-GLOBAL",
     r"(global[[:space:]]*(\.[[:space:]]*|\[[[:space:]]*['\"])(_V|_p_t)([^A-Za-z0-9_$]|$)"
     r"|['\"]_p_t['\"])"),
    ("IOC-C2-RPC-HOST",
     r"(api\.trongrid\.io|bsc-dataseed\.binance\.org|bsc-rpc\.publicnode\.com|fullnode\.mainnet\.aptoslabs\.com)"),
    ("IOC-C2-WALLET",
     r"(TCqf6ZkaQD84vYsC2cuu1jRwB6JveTaRrF|TFMryB9m6d4kBMRjEVyFRbqKSV1cV2NcpH)"),
    ("IOC-SPAWN-DETACHED-NODE",
     r"spawn[[:space:]]*\([[:space:]]*['\"]node['\"][[:space:]]*,[[:space:]]*\[[[:space:]]*['\"]-e['\"]"),
]


def history_patterns(opts):
    """Shipped patterns plus any --actors identifiers, for this run only."""
    pats = list(HISTORY_GREP_PATTERNS)
    actors = getattr(opts, "actors", None) or {"emails": [], "handles": []}
    known = actors["emails"] + actors["handles"]
    if known:
        pats.append(("IOC-ACTOR-EMAIL",
                     "(%s)" % "|".join(re.escape(k) for k in known)))
    return pats


def commit_meta(repo, sha, cache):
    if sha in cache:
        return cache[sha]
    rc, out, _ = git(repo, ["show", "-s", "--no-show-signature",
                            "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%cI%x1f%s",
                            sha], check=False)
    if rc != 0 or not out.strip():
        meta = {"sha": sha}
    else:
        parts = out.decode("utf-8", "replace").strip("\n").split("\x1f")
        keys = ["sha", "author_name", "author_email", "author_date",
                "commit_date", "subject"]
        meta = dict(zip(keys, parts))
    cache[sha] = meta
    return meta


def cmd_history(args, opts):
    started = time.time()
    try:
        repo = ensure_repo(args.repo)
    except GitError as exc:
        eprint("error: %s" % exc)
        return None, 2

    findings = []
    # Reachable objects from every ref, plus the reflog when one exists.
    rc, out, _ = git(repo, ["rev-list", "--all", "--reflog"], check=False)
    if rc != 0:
        rc, out, _ = git(repo, ["rev-list", "--all"], check=False)
        if rc != 0:
            eprint("error: rev-list failed in %s" % repo)
            return None, 2
    shas = out.decode("ascii", "replace").split()
    # rev-list --reflog can repeat commits; keep first-seen order.
    seen = set()
    ordered = []
    for s in shas:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    total = len(ordered)
    truncated = False
    if total > opts.max_commits:
        ordered = ordered[:opts.max_commits]
        truncated = True

    hits = {}  # (sha, path) -> set(rule)
    budget_hit = False
    patterns = history_patterns(opts)
    combined = "|".join("(%s)" % p for _, p in patterns)

    def run_pass(pathspecs, label):
        nonlocal budget_hit
        for batch in chunked(ordered, opts.grep_batch):
            if time.time() - started > opts.time_budget:
                budget_hit = True
                return
            argv = ["grep", "-I", "-l", "-E", "-e", combined]
            argv += batch
            if pathspecs:
                argv += ["--"] + list(pathspecs)
            rc, out, err = git(repo, argv, check=False,
                               timeout=opts.grep_timeout)
            if rc not in (0, 1):
                eprint("warn: git grep (%s pass) returned %d: %s"
                       % (label, rc, err.decode("utf-8", "replace")[:200]))
                continue
            for line in out.decode("utf-8", "replace").splitlines():
                if ":" not in line:
                    continue
                sha, path = line.split(":", 1)
                hits.setdefault((sha, path), set())

    # A tool checkout is untracked, so it cannot appear in history -- unless
    # someone vendored it. Exclude it there too rather than rely on that.
    excl = [":(exclude)%s/**" % d
            for d in sorted(set(getattr(opts, "exclude_dirs", ()) or ()))]
    run_pass(list(HISTORY_FAST_PATHSPECS) + excl, "fast")
    if not args.fast_only:
        run_pass(excl or None, "full")

    # Attribute rules per hit with one targeted grep per distinct path.
    cache = {}
    by_path = collections.defaultdict(list)
    for (sha, path) in hits:
        by_path[path].append(sha)

    for path, shalist in sorted(by_path.items()):
        shalist.sort(key=lambda s: ordered.index(s) if s in seen else 0)
        rules = set()
        probe = shalist[0]
        for rule, pat in patterns:
            rc, out, _ = git(repo, ["grep", "-I", "-l", "-E", "-e", pat,
                                    probe, "--", path], check=False,
                             timeout=opts.grep_timeout)
            if rc == 0 and out.strip():
                rules.add(rule)
        # Report oldest and newest carriers so the operator sees the span.
        metas = [commit_meta(repo, s, cache) for s in shalist]
        metas.sort(key=lambda m: m.get("commit_date", ""))
        oldest, newest = metas[0], metas[-1]
        for m in metas[:opts.max_report_commits]:
            findings.append(Finding(
                "CRITICAL", "HIST-" + (sorted(rules)[0] if rules
                                       else "IOC-UNATTRIBUTED"),
                path, 0,
                redact("%s %s <%s> %s" % (m.get("sha", "")[:12],
                                          m.get("author_name", "?"),
                                          m.get("author_email", "?"),
                                          m.get("subject", ""))),
                "malware signature present in git history (%s)"
                % (", ".join(sorted(rules)) or "combined pattern"),
                extra={
                    "commit": m.get("sha"),
                    "author_name": m.get("author_name"),
                    "author_email": m.get("author_email"),
                    "author_date": m.get("author_date"),
                    "commit_date": m.get("commit_date"),
                    "subject": m.get("subject"),
                    "carrier_commits": len(shalist),
                    "oldest_commit": oldest.get("sha"),
                    "newest_commit": newest.get("sha"),
                    "rules": sorted(rules),
                }))
        if len(shalist) > opts.max_report_commits:
            findings.append(Finding(
                "INFO", "HIST-TRUNCATED-CARRIERS", path, 0, "",
                "%d further commits carry this file; showing %d"
                % (len(shalist) - opts.max_report_commits,
                   opts.max_report_commits)))

    if truncated:
        findings.append(Finding(
            "MEDIUM", "SCAN-COMMITS-TRUNCATED", repo, 0, "",
            "repository has %d reachable commits; only the newest %d were "
            "swept (raise --max-commits for a full sweep)"
            % (total, opts.max_commits)))
    if budget_hit:
        findings.append(Finding(
            "MEDIUM", "SCAN-TIME-BUDGET", repo, 0, "",
            "history sweep stopped after --time-budget %ds; coverage is "
            "incomplete" % opts.time_budget))

    meta = {"mode": "history", "repo": repo, "commits_total": total,
            "commits_swept": len(ordered),
            "elapsed_sec": round(time.time() - started, 2)}
    return (findings, meta), 0


# --------------------------------------------------------------------------
# commits mode
# --------------------------------------------------------------------------

ISO = "%Y-%m-%dT%H:%M:%S"

# git's well-known empty-tree object, used as a base when a range starts at
# a root commit (there is no "before" state to diff against).
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def parse_iso(s):
    """Parse git's %aI / %cI (strict ISO-8601 with numeric offset)."""
    if not s:
        return None
    s = s.strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})"
                 r"(?:\.\d+)?(?:([+-]\d{2}):?(\d{2})|Z)$", s)
    if not m:
        return None
    import datetime as _dt
    base = _dt.datetime.strptime(m.group(1) + "T" + m.group(2), ISO)
    if m.group(3) is None:
        return base
    off = int(m.group(3)) * 60 + (int(m.group(4)) *
                                  (1 if m.group(3).startswith("+") else -1))
    return base - _dt.timedelta(minutes=off)


def path_matches_watch(path, patterns):
    p = path.replace("\\", "/")
    base = os.path.basename(p)
    for pat in patterns:
        if fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(base, pat):
            return True
        if pat.endswith("/*") and p.startswith(pat[:-1]):
            return True
    return False


def cmd_commits(args, opts):
    started = time.time()
    try:
        repo = ensure_repo(args.repo)
    except GitError as exc:
        eprint("error: %s" % exc)
        return None, 2

    if args.range:
        rev = args.range
    elif args.base and args.head:
        base = args.base
        # A force-push or a first push gives an all-zero "before" sha.
        if re.match(r"^0{7,40}$", base):
            rev = args.head
        else:
            rc, _, _ = git(repo, ["cat-file", "-e", base + "^{commit}"],
                           check=False)
            rev = args.head if rc != 0 else "%s..%s" % (base, args.head)
    elif args.head:
        rev = args.head
    else:
        rev = "HEAD"

    findings = []
    if args.forced:
        findings.append(Finding(
            "HIGH", "PUSH-FORCED", repo, 0, redact(rev),
            "this push was a FORCE-PUSH; on a repo without branch protection "
            "that can silently rewrite or hide history"))

    fmt = "%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%G?%x1f%s%x1e"
    argv = ["log", "--no-show-signature", "--format=" + fmt,
            "-n", str(opts.max_commits)]
    if args.first_parent:
        argv.append("--first-parent")
    argv += rev.split()
    rc, out, err = git(repo, argv, check=False, timeout=opts.grep_timeout)
    if rc != 0:
        eprint("error: git log %s failed: %s"
               % (rev, err.decode("utf-8", "replace").strip()[:300]))
        return None, 2

    commits = []
    for rec in out.decode("utf-8", "replace").split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        f = rec.split("\x1f")
        if len(f) < 10:
            continue
        commits.append({
            "sha": f[0], "parents": f[1].split(), "author_name": f[2],
            "author_email": f[3], "author_date": f[4], "committer_name": f[5],
            "committer_email": f[6], "commit_date": f[7], "sig": f[8],
            "subject": f[9],
        })

    trusted = set(e.strip().lower() for e in
                  (args.trusted_authors or "").split(",") if e.strip())
    watch = args.watch_paths.split(",") if args.watch_paths \
        else DEFAULT_WATCH_PATHS
    skew = float(args.max_date_skew_days)
    unsigned_trusted = []

    for c in commits:
        ad = parse_iso(c["author_date"])
        cd = parse_iso(c["commit_date"])
        short = c["sha"][:12]
        who = "%s <%s>" % (c["author_name"], c["author_email"])
        base_extra = {
            "commit": c["sha"], "author_name": c["author_name"],
            "author_email": c["author_email"], "author_date": c["author_date"],
            "commit_date": c["commit_date"], "signature": c["sig"],
            "subject": c["subject"],
        }

        # Which watched paths does it touch?
        rc, out2, _ = git(repo, ["show", "--no-show-signature",
                                 "--name-only", "--format=", c["sha"]],
                          check=False, timeout=opts.grep_timeout)
        touched = [p for p in out2.decode("utf-8", "replace").splitlines()
                   if p.strip()]
        watched = [p for p in touched if path_matches_watch(p, watch)]
        esc = "HIGH" if watched else "MEDIUM"

        bad_emails = KNOWN_BAD_AUTHORS | set(
            (getattr(opts, "actors", None) or {}).get("emails", []))
        bad_names = KNOWN_BAD_NAMES | set(
            (getattr(opts, "actors", None) or {}).get("handles", []))
        if c["author_email"].lower() in bad_emails or \
                c["committer_email"].lower() in bad_emails or \
                c["author_name"].lower() in bad_names:
            findings.append(Finding(
                "CRITICAL", "COMMIT-KNOWN-BAD-AUTHOR", c["sha"], 0,
                redact("%s %s %s" % (short, who, c["subject"])),
                "commit authored/committed by a known malicious identity",
                extra=base_extra))

        if c["sha"][:7] in KNOWN_BAD_COMMITS:
            findings.append(Finding(
                "CRITICAL", "COMMIT-KNOWN-BAD-SHA", c["sha"], 0,
                redact("%s %s" % (short, c["subject"])),
                "commit matches a known malicious commit from the incident "
                "(%s)" % KNOWN_BAD_COMMITS[c["sha"][:7]], extra=base_extra))

        if ad and cd:
            delta_days = (cd - ad).total_seconds() / 86400.0
            if delta_days > skew:
                findings.append(Finding(
                    # A rebase moves the committer date and leaves the
                    # author date behind, which looks exactly like backdating.
                    # What separated the real attack from a rebase was WHAT it
                    # touched: the 2026-08 wave backdated commits carrying
                    # build-config changes. No watched path, no HIGH.
                    "HIGH" if watched else "LOW",
                    "COMMIT-BACKDATED", c["sha"], 0,
                    redact("%s %s | author %s | committed %s | %s"
                           % (short, who, c["author_date"], c["commit_date"],
                              c["subject"])),
                    ("author date is %.1f days older than the committer date "
                     "(> %.0f); classic backdating to hide a force-push"
                     % (delta_days, skew)) if watched else
                    ("author date is %.1f days older than the committer date "
                     "(> %.0f), but the commit touches no build config, "
                     "lockfile, workflow or hook -- the ordinary shape of a "
                     "rebase" % (delta_days, skew)),
                    extra=dict(base_extra, skew_days=round(delta_days, 2),
                               watched_paths=watched[:20])))
            elif delta_days < -1.0:
                findings.append(Finding(
                    "MEDIUM", "COMMIT-FUTURE-DATED", c["sha"], 0,
                    redact("%s %s | author %s | committed %s"
                           % (short, who, c["author_date"],
                              c["commit_date"])),
                    "author date is %.1f days AFTER the committer date"
                    % (-delta_days), extra=base_extra))

        if trusted:
            if c["author_email"].lower() in trusted:
                if c["sig"] in ("N", "B", "E", "R", "Y"):
                    unsigned_trusted.append((c, esc, watched))
            else:
                findings.append(Finding(
                    "MEDIUM", "COMMIT-AUTHOR-UNKNOWN", c["sha"], 0,
                    redact("%s %s | %s" % (short, who, c["subject"])),
                    "author email is not in --trusted-authors",
                    extra=dict(base_extra, watched_paths=watched[:20])))

        if watched:
            findings.append(Finding(
                "LOW", "COMMIT-TOUCHES-BUILD-CONFIG", c["sha"], 0,
                redact("%s %s | %s" % (short, who, ", ".join(watched[:6]))),
                "commit modifies build-config / lifecycle / workflow files",
                extra=dict(base_extra, watched_paths=watched[:20])))

    # Out-of-order author dates along first-parent order.
    fp = [c for c in commits]
    for i in range(len(fp) - 1):
        newer, older = fp[i], fp[i + 1]
        if older["sha"] not in newer["parents"]:
            continue  # not a first-parent step in this listing
        a_new, a_old = parse_iso(newer["author_date"]), \
            parse_iso(older["author_date"])
        if not (a_new and a_old):
            continue
        gap = (a_old - a_new).total_seconds() / 86400.0
        if gap > skew:
            findings.append(Finding(
                "MEDIUM", "COMMIT-OUT-OF-ORDER", newer["sha"], 0,
                redact("%s author %s precedes parent %s author %s"
                       % (newer["sha"][:12], newer["author_date"],
                          older["sha"][:12], older["author_date"])),
                "commit's author date is %.1f days older than its parent's; "
                "history was rewritten or dates were forged" % gap,
                extra={"commit": newer["sha"], "parent": older["sha"],
                       "author_date": newer["author_date"],
                       "parent_author_date": older["author_date"]}))

    if unsigned_trusted:
        if len(unsigned_trusted) > opts.max_report_commits:
            worst = max(e[1] for e in unsigned_trusted)
            findings.append(Finding(
                "MEDIUM", "COMMIT-TRUSTED-AUTHOR-UNSIGNED", repo, 0,
                redact("%d commits" % len(unsigned_trusted)),
                "%d commits claim a trusted author but carry no valid "
                "signature; an attacker with a token can forge any author "
                "line (see docs/RUNBOOK.md 'commit signing')"
                % len(unsigned_trusted),
                extra={"count": len(unsigned_trusted),
                       "worst_severity_if_signed": worst,
                       "commits": [c["sha"] for c, _, _ in
                                   unsigned_trusted[:50]]}))
        else:
            for c, esc, watched in unsigned_trusted:
                findings.append(Finding(
                    args.signature_severity, "COMMIT-TRUSTED-AUTHOR-UNSIGNED",
                    c["sha"], 0,
                    redact("%s %s <%s> sig=%s | %s"
                           % (c["sha"][:12], c["author_name"],
                              c["author_email"], c["sig"], c["subject"])),
                    "commit claims trusted author %s but signature status is "
                    "'%s'" % (c["author_email"], c["sig"]),
                    extra={"commit": c["sha"],
                           "author_email": c["author_email"],
                           "signature": c["sig"],
                           "watched_paths": watched[:20]}))

    # Content scan of what the range ADDED (catches payloads later removed).
    if commits and not args.no_diff_scan:
        if ".." in rev:
            diff_rev = rev
        elif commits[-1]["parents"]:
            diff_rev = "%s^..%s" % (commits[-1]["sha"], commits[0]["sha"])
        else:
            # Oldest commit in the listing is a root commit: diff against the
            # empty tree so the whole reachable content is content-scanned.
            diff_rev = "%s..%s" % (EMPTY_TREE, commits[0]["sha"])
        if diff_rev:
            rc, dout, _ = git(repo, ["diff", "--no-color", "--unified=0",
                                     "--diff-filter=AM", diff_rev],
                              check=False, timeout=opts.grep_timeout)
            if rc == 0 and dout:
                if len(dout) > opts.max_diff_bytes:
                    dout = dout[:opts.max_diff_bytes]
                    findings.append(Finding(
                        "LOW", "SCAN-TRUNCATED", repo, 0, "",
                        "diff larger than --max-diff-bytes; content scan of "
                        "the range is partial"))
                cur_path = "?"
                for raw in dout.split(b"\n"):
                    if raw.startswith(b"+++ b/"):
                        cur_path = raw[6:].decode("utf-8", "replace")
                        continue
                    if not raw.startswith(b"+") or raw.startswith(b"+++"):
                        continue
                    body = raw[1:]
                    for rule, rx, desc in CRITICAL_RULES:
                        if rx.search(body):
                            findings.append(Finding(
                                "CRITICAL", "DIFF-" + rule, cur_path, 0,
                                redact(body),
                                "%s introduced by this range" % desc,
                                extra={"range": diff_rev}))
                            break
                    else:
                        if RE_WS_PAD.search(body) and is_config_like(cur_path):
                            m = RE_WS_PAD.search(body)
                            findings.append(Finding(
                                "HIGH", "DIFF-OBF-WHITESPACE-PAD", cur_path, 0,
                                redact(body[m.end():m.end() + 120]),
                                "added line hides code behind %d spaces"
                                % len(m.group(0)),
                                extra={"range": diff_rev}))

    meta = {"mode": "commits", "repo": repo, "range": rev,
            "commits_examined": len(commits),
            "elapsed_sec": round(time.time() - started, 2)}
    return (findings, meta), 0


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def eprint(msg):
    sys.stderr.write(str(msg) + "\n")


SEV_ICON = {"CRITICAL": "●", "HIGH": "◆", "MEDIUM": "▲",
            "LOW": "○", "INFO": "·"}


def report_text(findings, meta, opts):
    lines = []
    counts = collections.Counter(f.severity for f in findings)
    lines.append("malware-scan %s — mode=%s" % (__version__,
                                                     meta.get("mode")))
    for k in ("paths", "repo", "range"):
        if meta.get(k):
            lines.append("  %-16s %s" % (k + ":", meta[k]))
    for k in ("files_scanned", "commits_total", "commits_swept",
              "commits_examined", "elapsed_sec"):
        if meta.get(k) is not None:
            lines.append("  %-16s %s" % (k + ":", meta[k]))
    lines.append("")
    if not findings:
        lines.append("  no findings")
    for f in sorted(findings, key=lambda x: x.sort_key()):
        if SEV_RANK[f.severity] < SEV_RANK[opts.min_severity]:
            continue
        loc = f.path if not f.line else "%s:%d" % (f.path, f.line)
        lines.append("%s %-8s %-32s %s" % (SEV_ICON.get(f.severity, " "),
                                           f.severity, f.rule, loc))
        lines.append("           %s" % f.message)
        if f.excerpt:
            lines.append("           | %s" % f.excerpt)
        lines.append("")
    summary = "  ".join("%s=%d" % (s, counts.get(s, 0))
                        for s in reversed(SEVERITIES) if counts.get(s))
    lines.append("summary: %s" % (summary or "clean"))
    return "\n".join(lines)


def report_github(findings, meta, opts):
    out = []
    for f in sorted(findings, key=lambda x: x.sort_key()):
        if SEV_RANK[f.severity] < SEV_RANK["MEDIUM"]:
            continue
        level = "error" if SEV_RANK[f.severity] >= SEV_RANK["HIGH"] \
            else "warning"
        title = "%s %s" % (f.severity, f.rule)
        msg = f.message
        if f.excerpt:
            msg += " || " + f.excerpt
        msg = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        title = title.replace("%", "%25")
        path = f.path or "."
        if f.line:
            out.append("::%s file=%s,line=%d,title=%s::%s"
                       % (level, path, f.line, title, msg))
        else:
            out.append("::%s title=%s::%s [%s]" % (level, title, msg, path))
    return "\n".join(out)


def emit(result, opts, args):
    findings, meta = result
    counts = collections.Counter(f.severity for f in findings)
    meta = dict(meta, counts=dict(counts), version=__version__,
                fail_on=opts.fail_on)
    payload = {"meta": meta, "findings": [f.as_dict() for f in
                                          sorted(findings,
                                                 key=lambda x: x.sort_key())]}
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=False)
                fh.write("\n")
        except OSError as exc:
            eprint("warn: could not write --report %s: %s"
                   % (args.report, exc))
    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    elif args.github:
        gh = report_github(findings, meta, opts)
        if gh:
            sys.stdout.write(gh + "\n")
        sys.stdout.write(report_text(findings, meta, opts) + "\n")
    else:
        sys.stdout.write(report_text(findings, meta, opts) + "\n")

    threshold = SEV_RANK[opts.fail_on]
    worst = max([SEV_RANK[f.severity] for f in findings] or [-1])
    return 1 if worst >= threshold else 0


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

def _build_commit_fixture(tmp):
    """Create a throwaway git repo with forged/backdated commits.

    Nothing here executes project code: the repo is empty apart from small
    text files this function writes, git runs with hooks disabled, and the
    directory is removed afterwards.
    """
    subprocess.run(["git", "-c", "init.defaultBranch=main",
                    "-c", "commit.gpgsign=false", "init", "-q", tmp],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True)

    def commit(msg, name, email, adate, cdate, files):
        for rel, body in files.items():
            fp = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(fp), exist_ok=True) \
                if os.path.dirname(rel) else None
            with open(fp, "w", encoding="utf-8") as fh:
                fh.write(body)
        subprocess.run(["git", "-C", tmp, "add", "-A"],
                       stdout=subprocess.DEVNULL, check=True)
        env = dict(os.environ)
        env["GIT_AUTHOR_DATE"] = adate
        env["GIT_COMMITTER_DATE"] = cdate
        env["GIT_AUTHOR_NAME"] = name
        env["GIT_AUTHOR_EMAIL"] = email
        env["GIT_COMMITTER_NAME"] = name
        env["GIT_COMMITTER_EMAIL"] = email
        subprocess.run(["git", "-C", tmp,
                        "-c", "core.hooksPath=/dev/null",
                        "-c", "commit.gpgsign=false",
                        "commit", "-q", "--no-verify", "-m", msg],
                       env=env, stdout=subprocess.DEVNULL, check=True)

    commit("chore: init", "Jane Doe", "jane@example.com",
           "2026-01-05T10:00:00-05:00", "2026-01-05T10:00:00-05:00",
           {"README.md": "# fixture\n",
            "vite.config.js": "export default { base: './' }\n"})
    commit("feat: add a page", "Jane Doe", "jane@example.com",
           "2026-02-10T09:30:00-05:00", "2026-02-10T09:30:00-05:00",
           {"src/page.js": "export const page = 1\n"})
    # Backdated + forged author, touching a build config: the incident shape.
    payload = ("export default { base: './' }" + " " * 300 +
               "global.z='7-x1';var _$_dead=(function(a,b){return a})" +
               "(String.fromCharCode(127));\n")
    def tag(name):
        subprocess.run(["git", "-C", tmp, "-c", "core.hooksPath=/dev/null",
                        "tag", "-f", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True)

    commit("chore: tidy build config", "Jane Doe",
           "jane@example.com",
           "2025-11-27T12:00:00-05:00", "2026-08-18T22:14:00+00:00",
           {"vite.config.js": payload})
    # Tagged, not indexed. Expectations used to address these commits as
    # HEAD~N, which silently broke every time a commit was appended to this
    # fixture -- twice already. Tags survive that; `<tag>^` gives the base.
    tag("fx/backdated-config")
    # A commit from a "known-malicious" identity. Both identifiers are
    # invented and live in tests/fixtures/test-actors.txt, which the selftest
    # feeds in via --actors.
    commit("updated images", "evilcontributor", "mallory@example.invalid",
           "2026-08-18T23:00:00+00:00", "2026-08-18T23:00:00+00:00",
           {"src/img.js": "export const img = 2\n"})
    # The ordinary shape of a rebase: author date left far behind the
    # committer date, but touching nothing that runs at build time. Must be
    # LOW -- nine of these on one repo failed the first org-wide sweep.
    commit("refactor: extract helper", "Jane Doe", "jane@example.com",
           "2026-03-02T11:00:00-05:00", "2026-08-19T09:00:00+00:00",
           {"src/helper.js": "export const help = () => 3\n"})
    tag("fx/backdated-src-only")
    # A committed dependency whose minified identifiers merely CONTAIN the
    # runtime-global marker as a substring. The history sweep greps every
    # reachable object, so its patterns must be as strict as the content
    # rules; a bare `_p_t` here used to raise a CRITICAL.
    commit("chore: vendor a dependency", "Jane Doe", "jane@example.com",
           "2026-04-01T10:00:00-05:00", "2026-04-01T10:00:00-05:00",
           {"node_modules/pretty/cli.js":
            "var chunk_p_type=1,a_p_t2=2;module.exports={chunk_p_type,a_p_t2};\n"})
    tag("fx/vendored-substring")
    return tmp


def cmd_selftest(args, opts):
    root = args.fixtures or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tests")
    root = os.path.abspath(root)
    expect_path = os.path.join(root, "expectations.json")
    if not os.path.isfile(expect_path):
        eprint("error: no expectations.json under %s" % root)
        return None, 2
    with open(expect_path, "r", encoding="utf-8") as fh:
        spec = json.load(fh)

    passed = failed = 0
    failures = []

    class _A(object):
        pass

    for case in spec["cases"]:
        rel = case["path"]
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            failed += 1
            failures.append("%s: fixture missing (%s)" % (case["name"], path))
            continue
        a = _A()
        a.paths = [path]
        a.report = None
        a.json = False
        a.github = False
        o = make_opts(argparse.Namespace(
            fail_on=case.get("fail_on", "HIGH"),
            min_severity="INFO",
            include_minified=case.get("include_minified", False),
            heuristics_in_vendor=case.get("heuristics_in_vendor", False),
            max_file_size=opts.max_file_size,
            max_config_line=opts.max_config_line,
            min_entropy=opts.min_entropy,
            min_hex_escapes=opts.min_hex_escapes,
            max_hits_per_rule=opts.max_hits_per_rule,
            max_commits=opts.max_commits, max_report_commits=20,
            time_budget=opts.time_budget, grep_batch=opts.grep_batch,
            grep_timeout=opts.grep_timeout,
            max_diff_bytes=opts.max_diff_bytes,
            no_ignore_file=True, skip_git_dir=True,
            extra_hashes=(os.path.join(root, case["extra_hashes"])
                          if case.get("extra_hashes") else None),
            actors=(os.path.join(root, case["actors"])
                    if case.get("actors") else None)))
        res, rc = cmd_tree(a, o)
        if rc == 2:
            failed += 1
            failures.append("%s: scanner error" % case["name"])
            continue
        findings, _meta = res
        got_rules = collections.Counter(f.rule for f in findings)
        got_sev = collections.Counter(f.severity for f in findings)

        ok = True
        detail = []
        for rule in case.get("expect_rules", []):
            if not got_rules.get(rule):
                ok = False
                detail.append("missing rule %s" % rule)
        for rule in case.get("forbid_rules", []):
            if got_rules.get(rule):
                ok = False
                detail.append("unexpected rule %s" % rule)
        if "expect_max_severity" in case:
            want = SEV_RANK[case["expect_max_severity"]]
            worst = max([SEV_RANK[f.severity] for f in findings] or [-1])
            if worst != want:
                ok = False
                detail.append("max severity %s, want %s"
                              % (SEVERITIES[worst] if worst >= 0 else "NONE",
                                 case["expect_max_severity"]))
        if case.get("expect_clean"):
            bad = [f for f in findings
                   if SEV_RANK[f.severity] >= SEV_RANK[
                       case.get("clean_below", "MEDIUM")]]
            if bad:
                ok = False
                detail.append("expected clean, got: " +
                              "; ".join("%s %s @%s:%d" % (f.severity, f.rule,
                                                          f.path, f.line)
                                        for f in bad[:8]))
        if ok:
            passed += 1
            print("  PASS  %-46s (%s)" % (
                case["name"],
                " ".join("%s=%d" % (s, got_sev[s])
                         for s in reversed(SEVERITIES) if got_sev[s])
                or "clean"))
        else:
            failed += 1
            print("  FAIL  %-46s %s" % (case["name"], "; ".join(detail)))
            failures.append("%s: %s" % (case["name"], "; ".join(detail)))

    # ---- dangling-gitlink case -------------------------------------------
    gl = spec.get("gitlink_case")
    if gl:
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="malware-scan-selftest-gitlink-")
        try:
            def g(*argv):
                subprocess.run(["git", "-C", tmp,
                                "-c", "core.hooksPath=/dev/null",
                                "-c", "user.name=Jane Doe",
                                "-c", "user.email=jane@example.com",
                                "-c", "commit.gpgsign=false"] + list(argv),
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=True)
            g("init", "-q", "-b", "main", ".")
            with open(os.path.join(tmp, "README.md"), "w") as fh:
                fh.write("# fixture\n")
            g("add", "-A")
            g("commit", "-qm", "init")
            head = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                                  stdout=subprocess.PIPE,
                                  check=True).stdout.decode().strip()
            # A gitlink with no .gitmodules entry: the shape that makes
            # `git submodule foreach` exit 128 and breaks CI checkouts.
            g("update-index", "--add", "--cacheinfo",
              "160000,%s,%s" % (head, gl["path"]))
            g("commit", "-qm", "add a stale gitlink")
            a = _A()
            a.paths = [tmp]
            a.report = None
            a.json = False
            a.github = False
            a.include_minified = False
            a.skip_git_dir = False
            o = make_opts(argparse.Namespace(
                fail_on="HIGH", min_severity="INFO",
                no_ignore_file=True, skip_git_dir=False))
            res, rc = cmd_tree(a, o)
            detail = []
            if rc == 2:
                detail.append("scanner error")
            else:
                got = [f for f in res[0] if f.rule == "GIT-DANGLING-GITLINK"]
                if not got:
                    detail.append("no GIT-DANGLING-GITLINK finding")
                elif got[0].severity != "LOW":
                    detail.append("severity %s, want LOW" % got[0].severity)
                elif gl["path"] not in got[0].excerpt:
                    detail.append("finding does not name the path")
                worst = max([SEV_RANK[f.severity] for f in res[0]] or [-1])
                if worst > SEV_RANK["LOW"]:
                    detail.append("a stale gitlink must not exceed LOW")
            if detail:
                failed += 1
                print("  FAIL  %-46s %s" % (gl["name"], "; ".join(detail)))
                failures.append("%s: %s" % (gl["name"], "; ".join(detail)))
            else:
                passed += 1
                print("  PASS  %-46s (%s)" % (gl["name"], "LOW, names the path"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ---- the tool-checkout case ------------------------------------------
    # The reusable workflow checks the scanner out INSIDE the repository under
    # test and runs it from there, which once made it report itself as
    # malware. Reproducing that needs the COPY to be the running scanner --
    # the self-exclusion is derived from the running file's own location, so
    # exercising it with the in-repo scan.py would prove nothing. Hence a
    # subprocess. It runs this project's own code, never scanned content.
    tc = spec.get("tool_checkout_case")
    if tc:
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="malware-scan-selftest-tool-")
        try:
            proj = os.path.join(tmp, "proj")
            shutil.copytree(os.path.join(root, tc["app"]), proj)
            tool = os.path.join(proj, tc.get("tool_dir", ".malware-scan-tool"))
            shutil.copytree(TOOL_ROOT, tool, symlinks=False,
                            ignore=shutil.ignore_patterns(
                                ".git", "__pycache__", "*.pyc"))
            proc = subprocess.run(
                [sys.executable, os.path.join(tool, "scanner", "scan.py"),
                 "tree", proj, "--fail-on", "HIGH", "--min-severity", "INFO",
                 "--json"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            detail = []
            try:
                doc = json.loads(proc.stdout.decode("utf-8", "replace"))
            except ValueError:
                doc = None
                detail.append("scanner produced no JSON (rc=%d)"
                              % proc.returncode)
            if doc is not None:
                got = doc.get("findings", [])
                worst = max([SEV_RANK[f["severity"]] for f in got] or [-1])
                ceiling = SEV_RANK[tc.get("max_severity_allowed", "INFO")]
                if worst > ceiling:
                    detail.append(
                        "a tool checkout inside the scanned tree produced %s: %s"
                        % (SEVERITIES[worst],
                           ", ".join(sorted({f["rule"] for f in got
                                             if SEV_RANK[f["severity"]]
                                             > ceiling}))[:200]))
                if not any(f["rule"] == "SCAN-SELF-EXCLUDED" for f in got):
                    detail.append("no SCAN-SELF-EXCLUDED notice: the skip "
                                  "must be visible, not silent")
                if proc.returncode != 0:
                    detail.append("exit %d, want 0" % proc.returncode)
            if detail:
                failed += 1
                print("  FAIL  %-46s %s" % (tc["name"], "; ".join(detail)))
                failures.append("%s: %s" % (tc["name"], "; ".join(detail)))
            else:
                passed += 1
                print("  PASS  %-46s (%s)"
                      % (tc["name"], "tool checkout not scanned"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ---- git-backed cases (tmp repo, removed afterwards) ------------------
    git_cases = spec.get("git_cases", [])
    if git_cases:
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="malware-scan-selftest-")
        try:
            _build_commit_fixture(tmp)
            for case in git_cases:
                a = _A()
                a.repo = tmp
                a.report = None
                a.json = False
                a.github = False
                a.fast_only = case.get("fast_only", False)
                a.range = case.get("range")
                a.base = case.get("base")
                a.head = case.get("head")
                a.forced = case.get("forced", False)
                a.first_parent = False
                a.trusted_authors = case.get("trusted_authors", "")
                a.watch_paths = case.get("watch_paths", "")
                a.max_date_skew_days = case.get("max_date_skew_days", 7.0)
                a.signature_severity = case.get("signature_severity", "MEDIUM")
                a.no_diff_scan = case.get("no_diff_scan", False)
                o = make_opts(argparse.Namespace(
                    fail_on="HIGH", min_severity="INFO",
                    max_commits=opts.max_commits, max_report_commits=20,
                    time_budget=opts.time_budget,
                    grep_batch=opts.grep_batch,
                    grep_timeout=opts.grep_timeout,
                    max_diff_bytes=opts.max_diff_bytes,
                    no_ignore_file=True, skip_git_dir=True,
                    actors=(os.path.join(root, case["actors"])
                            if case.get("actors") else None)))
                fn = cmd_history if case["mode"] == "history" else cmd_commits
                try:
                    res, rc = fn(a, o)
                except GitError as exc:
                    failed += 1
                    print("  FAIL  %-46s git error: %s" % (case["name"], exc))
                    failures.append(case["name"])
                    continue
                if rc == 2 or res is None:
                    failed += 1
                    print("  FAIL  %-46s scanner error" % case["name"])
                    failures.append(case["name"])
                    continue
                fnd, _m = res
                got = collections.Counter(f.rule for f in fnd)
                got_sev = collections.Counter(f.severity for f in fnd)
                ok, detail = True, []
                for rule in case.get("expect_rules", []):
                    if not got.get(rule):
                        ok = False
                        detail.append("missing rule %s" % rule)
                for rule in case.get("forbid_rules", []):
                    if got.get(rule):
                        ok = False
                        detail.append("unexpected rule %s" % rule)
                if "expect_max_severity" in case:
                    want = SEV_RANK[case["expect_max_severity"]]
                    worst = max([SEV_RANK[f.severity] for f in fnd] or [-1])
                    if worst != want:
                        ok = False
                        detail.append("max severity %s, want %s" % (
                            SEVERITIES[worst] if worst >= 0 else "NONE",
                            case["expect_max_severity"]))
                if ok:
                    passed += 1
                    print("  PASS  %-46s (%s)" % (
                        case["name"],
                        " ".join("%s=%d" % (sv, got_sev[sv])
                                 for sv in reversed(SEVERITIES)
                                 if got_sev[sv]) or "clean"))
                else:
                    failed += 1
                    print("  FAIL  %-46s %s" % (case["name"],
                                                "; ".join(detail)))
                    failures.append(case["name"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("")
    print("selftest: %d passed, %d failed" % (passed, failed))
    if failures:
        return None, 1
    return None, 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class Opts(object):
    pass


def make_opts(ns):
    o = Opts()
    o.fail_on = getattr(ns, "fail_on", "HIGH")
    o.min_severity = getattr(ns, "min_severity", "LOW")
    o.include_minified = getattr(ns, "include_minified", False)
    o.max_file_size = getattr(ns, "max_file_size", 8 * 1024 * 1024)
    o.max_config_line = getattr(ns, "max_config_line", 300)
    o.min_entropy = getattr(ns, "min_entropy", 4.5)
    o.min_hex_escapes = getattr(ns, "min_hex_escapes", 6)
    o.max_hits_per_rule = getattr(ns, "max_hits_per_rule", 5)
    o.max_commits = getattr(ns, "max_commits", 5000)
    o.max_report_commits = getattr(ns, "max_report_commits", 20)
    o.time_budget = getattr(ns, "time_budget", 900)
    o.grep_batch = getattr(ns, "grep_batch", 150)
    o.grep_timeout = getattr(ns, "grep_timeout", 300)
    o.max_diff_bytes = getattr(ns, "max_diff_bytes", 20 * 1024 * 1024)
    o.use_ignore_file = not getattr(ns, "no_ignore_file", False)
    o.skip_git_dir = getattr(ns, "skip_git_dir", False)
    o.extra_hashes = load_extra_hashes(getattr(ns, "extra_hashes", None))
    o.actors = load_actors(getattr(ns, "actors", None))
    o.exclude_dirs = list(getattr(ns, "exclude_dirs", None) or [])
    o.heuristics_in_vendor = bool(getattr(ns, "heuristics_in_vendor", False))
    return o


def add_common(p):
    p.add_argument("--fail-on", default="HIGH", choices=SEVERITIES,
                   help="minimum severity that makes the run exit 1")
    p.add_argument("--min-severity", default="LOW", choices=SEVERITIES,
                   help="minimum severity to print in text output")
    p.add_argument("--json", action="store_true", help="emit JSON on stdout")
    p.add_argument("--github", action="store_true",
                   help="emit GitHub Actions annotations")
    p.add_argument("--report", metavar="FILE",
                   help="also write the JSON report to FILE")
    p.add_argument("--max-commits", type=int, default=5000)
    p.add_argument("--max-report-commits", type=int, default=20)
    p.add_argument("--time-budget", type=int, default=900)
    p.add_argument("--grep-batch", type=int, default=150)
    p.add_argument("--grep-timeout", type=int, default=300)
    p.add_argument("--max-diff-bytes", type=int, default=20 * 1024 * 1024)
    p.add_argument("--max-file-size", type=int, default=8 * 1024 * 1024)
    p.add_argument("--max-config-line", type=int, default=300)
    p.add_argument("--min-entropy", type=float, default=4.5)
    p.add_argument("--min-hex-escapes", type=int, default=6)
    p.add_argument("--max-hits-per-rule", type=int, default=5)
    p.add_argument("--no-ignore-file", action="store_true",
                   help="ignore .malwarescanignore entirely")
    p.add_argument("--extra-hashes", metavar="FILE",
                   help="file of additional known-bad sha256 digests, one "
                        "per line, optionally followed by a description")
    p.add_argument("--exclude-dir", metavar="NAME", action="append",
                   default=[], dest="exclude_dirs",
                   help="never scan a directory with this basename; repeat "
                        "for more. The scanner's own install directory is "
                        "always excluded regardless.")
    p.add_argument("--heuristics-in-vendor", action="store_true",
                   help="also apply the OBF-*/EXEC-* heuristics inside "
                        "vendored upstream trees (%s). Exact-match IOC rules "
                        "always run there regardless."
                        % ", ".join("/".join(x) + "/**"
                                    for x in VENDOR_PATH_SEQUENCES))
    p.add_argument("--actors", metavar="FILE",
                   help="file of known-malicious account names and email "
                        "addresses, one per line; not shipped with the "
                        "scanner (see load_actors)")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="scan.py",
        description="EtherHiding / JADESNOW supply-chain malware scanner "
                    "(reads bytes only, never executes scanned code)")
    ap.add_argument("--version", action="version",
                    version="malware-scan " + __version__)
    sub = ap.add_subparsers(dest="mode")

    t = sub.add_parser("tree", help="scan a working tree")
    t.add_argument("paths", nargs="+")
    t.add_argument("--include-minified", action="store_true")
    t.add_argument("--skip-git-dir", action="store_true",
                   help="do not audit .git/config and .git/hooks")
    add_common(t)

    h = sub.add_parser("history", help="sweep all reachable git objects")
    h.add_argument("repo")
    h.add_argument("--fast-only", action="store_true",
                   help="only grep build-config/script pathspecs")
    add_common(h)

    c = sub.add_parser("commits", help="commit-metadata forensics")
    c.add_argument("repo", nargs="?", default=".")
    c.add_argument("--range", help="a..b revision range")
    c.add_argument("--base")
    c.add_argument("--head")
    c.add_argument("--forced", action="store_true",
                   help="this push was a force-push (github.event.forced)")
    c.add_argument("--first-parent", action="store_true")
    c.add_argument("--trusted-authors", default="")
    c.add_argument("--watch-paths", default="")
    c.add_argument("--max-date-skew-days", type=float, default=7.0)
    c.add_argument("--signature-severity", default="MEDIUM",
                   choices=SEVERITIES)
    c.add_argument("--no-diff-scan", action="store_true")
    add_common(c)

    s = sub.add_parser("selftest", help="run bundled fixtures")
    s.add_argument("--fixtures", help="path to tests/ directory")
    add_common(s)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.mode:
        ap.print_help()
        return 2
    try:
        opts = make_opts(args)
    except (OSError, ValueError) as exc:
        eprint("error: --extra-hashes/--actors: %s" % exc)
        return 2
    try:
        if args.mode == "tree":
            result, rc = cmd_tree(args, opts)
        elif args.mode == "history":
            result, rc = cmd_history(args, opts)
        elif args.mode == "commits":
            result, rc = cmd_commits(args, opts)
        elif args.mode == "selftest":
            result, rc = cmd_selftest(args, opts)
        else:
            ap.print_help()
            return 2
    except GitError as exc:
        eprint("error: %s" % exc)
        return 2
    except KeyboardInterrupt:
        eprint("interrupted")
        return 2
    if rc == 2:
        return 2
    if result is None:
        return rc
    return emit(result, opts, args)


if __name__ == "__main__":
    sys.exit(main())
