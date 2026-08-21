#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
render-caller.py -- turn .github/workflows/caller-template.yml into the
per-repo caller that tools/rollout.sh commits as
.github/workflows/malware-scan.yml.

Why a renderer at all: `trusted_authors`, `fail_on` and the `uses:` ref are
the only things that vary, and the rendered bytes must be *stable* -- the
rollout compares `git hash-object` of the rendering against the blob SHA
GitHub reports for the file already in the repo, and skips the repo when they
match. A byte-unstable renderer would open a pointless PR every single run.

Stability rules, therefore:
  * no timestamps, no hostnames, no run ids, no dict ordering in the output;
  * pure function of (template bytes, --uses, --trusted-authors, --fail-on);
  * LF line endings, UTF-8, exactly one trailing newline.

What it changes, and nothing else:
  1. the "COPY THIS FILE ..." header paragraph, which is an instruction to a
     human reading the template and is false once rendered, becomes a
     "generated, do not hand-edit" banner. Every other comment in the
     template -- notably the PREREQUISITE block -- is copied through
     verbatim, because a caller sitting alone in some repo is exactly where
     that explanation is needed;
  2. the `if: github.repository != '<scanner repo>'` guard and the comment
     lines that document it are dropped: the guard only exists to keep the
     template inert inside the scanner repository itself;
  3. `uses:`, `trusted_authors:` and `fail_on:` take the requested values.

Every one of those is asserted afterwards, so a future edit to the template
that breaks an assumption fails the rollout loudly instead of silently
shipping a caller with, say, the default single-author list.

stdlib only, python3.9+ (macOS system python and ubuntu-latest both work).
Reads and writes text; runs nothing.
"""

from __future__ import annotations

import argparse
import re
import sys

BANNER = """\
# .github/workflows/malware-scan.yml -- supply-chain malware scan.
#
# GENERATED FILE. Rendered by `tools/rollout.sh` from
# `.github/workflows/caller-template.yml` in %s.
# Do not hand-edit: the rollout compares this file byte-for-byte and will
# open a PR to put it back. Change the template, or the rollout flags.
#
"""

RE_PREREQ = re.compile(r"^#\s*PREREQUISITES?\b")
RE_USES = re.compile(
    r"^(\s*)uses:\s*\S+/\.github/workflows/malware-scan\.yml@\S+\s*$")
RE_TRUSTED = re.compile(r"^(\s*)trusted_authors:\s*.*$")
RE_FAIL_ON = re.compile(r"^(\s*)fail_on:\s*.*$")
RE_GUARD = re.compile(r"^\s*if:\s*github\.repository\s*!=")
RE_COMMENT = re.compile(r"^\s*#")

# owner/repo/.github/workflows/<file>.yml@<ref>
RE_USES_VALUE = re.compile(
    r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/\.github/workflows/[A-Za-z0-9._-]+"
    r"\.ya?ml@[^\s'\"]+$")


class RenderError(RuntimeError):
    pass


def yaml_dq(value):
    """Double-quoted YAML scalar. The three values we substitute are emails,
    a ref and a severity word, so only \\ and " can ever need escaping."""
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def render(template_text, uses, trusted_authors, fail_on):
    if not RE_USES_VALUE.match(uses):
        raise RenderError(
            "--uses must look like owner/repo/.github/workflows/file.yml@ref, "
            "got %r" % uses)
    if "\n" in trusted_authors or "\n" in fail_on:
        raise RenderError("newline in --trusted-authors/--fail-on")

    lines = template_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # trailing newline; re-added on join

    # 1. header -------------------------------------------------------------
    start = None
    for i, ln in enumerate(lines):
        if RE_PREREQ.match(ln):
            start = i
            break
        if not RE_COMMENT.match(ln) and ln.strip():
            break  # real YAML began before any PREREQUISITE block
    if start is None:
        raise RenderError(
            "no '# PREREQUISITE' comment found in the template; refusing to "
            "guess where the header ends")
    body = lines[start:]

    out = []
    n_uses = n_trusted = n_fail = n_guard = 0
    for ln in body:
        # 2. guard (plus the comment block that documents it) ---------------
        if RE_GUARD.match(ln):
            n_guard += 1
            while out and RE_COMMENT.match(out[-1]):
                out.pop()
            continue
        # 3. substitutions --------------------------------------------------
        m = RE_USES.match(ln)
        if m:
            n_uses += 1
            out.append("%suses: %s" % (m.group(1), uses))
            continue
        m = RE_TRUSTED.match(ln)
        if m:
            n_trusted += 1
            out.append("%strusted_authors: %s"
                       % (m.group(1), yaml_dq(trusted_authors)))
            continue
        m = RE_FAIL_ON.match(ln)
        if m:
            n_fail += 1
            out.append("%sfail_on: %s" % (m.group(1), yaml_dq(fail_on)))
            continue
        out.append(ln)

    for what, n in (("uses:", n_uses), ("trusted_authors:", n_trusted),
                    ("fail_on:", n_fail), ("the security-scan guard", n_guard)):
        if n != 1:
            raise RenderError(
                "expected exactly one %s line in the template, found %d "
                "-- the template changed shape; fix render-caller.py"
                % (what, n))

    # Name the repo the caller actually points at, so the banner stays true
    # if the scanner is ever moved or forked.
    scanner_repo = uses.split("/.github/workflows/", 1)[0]
    text = (BANNER % scanner_repo) + "\n".join(out).rstrip("\n") + "\n"

    # post-conditions, checked on the bytes we are about to ship ------------
    if "github.repository !=" in text:
        raise RenderError("guard survived rendering")
    if ("uses: " + uses) not in text:
        raise RenderError("uses: did not take")
    if ("trusted_authors: " + yaml_dq(trusted_authors)) not in text:
        raise RenderError("trusted_authors did not take")
    if ("fail_on: " + yaml_dq(fail_on)) not in text:
        raise RenderError("fail_on did not take")
    for needed in ("name: malware-scan", "jobs:", "secrets: inherit"):
        if needed not in text:
            raise RenderError("rendered caller lost %r" % needed)
    if "\r" in text:
        raise RenderError("CR in rendered output; endings must be LF")
    return text


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="render-caller.py",
        description="Render the per-repo malware-scan caller workflow.")
    ap.add_argument("--template", required=True,
                    help="path to .github/workflows/caller-template.yml")
    ap.add_argument("--uses", required=True,
                    help="owner/repo/.github/workflows/malware-scan.yml@ref")
    ap.add_argument("--trusted-authors", required=True,
                    help="comma-separated author emails")
    ap.add_argument("--fail-on", required=True,
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    ap.add_argument("--out", help="write here instead of stdout")
    args = ap.parse_args(argv)

    try:
        with open(args.template, "r", encoding="utf-8") as fh:
            template_text = fh.read()
    except OSError as exc:
        sys.stderr.write("render-caller: cannot read template: %s\n" % exc)
        return 2

    try:
        text = render(template_text, args.uses, args.trusted_authors,
                      args.fail_on)
    except RenderError as exc:
        sys.stderr.write("render-caller: %s\n" % exc)
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
