#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify-no-samples.py -- prove this repository contains none of the real
malware bytes, before it is published.

The two JADESNOW samples recovered in August 2026 used to live in
tests/fixtures/positive/ as *.SAMPLE.txt. They were replaced by synthetic
fixtures when the repo was prepared for publication. This script is the
evidence that the replacement was complete.

How it works: it takes several byte windows from the *payload region* of each
real sample (the long appended last line, not the innocuous config above it)
and searches for each window in

  * every file in the working tree, excluding .git, and
  * every blob reachable from a given commit-ish (default HEAD), read through
    `git cat-file`, so a file deleted from the tree but still in the commit is
    caught.

Any hit fails. `tools/publish-public.sh` refuses to publish unless this exits
0.

IMPORTANT: the windows are read from the evidence volume at run time and are
held only in this process's memory. They are never written to disk, never
printed, and never passed as command-line arguments (which would put them in
the process table). On a hit the script reports the *offset* of the window and
the file it was found in -- never the bytes.

This scans; it does not execute anything. Read-only. stdlib only.

Usage:
  MALWARE_EVIDENCE_DIR=/path/to/samples tools/verify-no-samples.py
  tools/verify-no-samples.py [--samples DIR] [--windows N] [--size N]
                             [--rev HEAD] [--repo .] [-v]

Exit: 0 clean, 1 a sample byte window was found, 2 could not run the check
(missing evidence volume, not a git repo). 2 is not "clean" -- publishing
must treat it as a failure.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

# No default path: it would name the incident, and this file is public. Set
# MALWARE_EVIDENCE_DIR in your shell, or pass --samples.
DEFAULT_SAMPLES = os.environ.get("MALWARE_EVIDENCE_DIR", "")

# Directories never worth reading, and never a place a sample could hide in a
# way that would ship. .git is handled separately, through the object store.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".DS_Store"}


def eprint(*a):
    print(*a, file=sys.stderr)


def payload_windows(path, count, size):
    """`count` byte windows of `size` bytes from the payload region.

    The payload is the appended tail of the longest line; taking windows from
    the readable config above it would produce false positives against any
    ordinary vite config. Windows are spaced evenly across the tail.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    lines = data.split(b"\n")
    longest = max(lines, key=len)
    # Skip the legitimate-looking head of the line and the whitespace pad.
    tail = longest.lstrip()
    pad = tail.find(b"     ")
    if pad != -1:
        tail = tail[pad:].lstrip()
    if len(tail) < size * 2:
        raise ValueError("%s: no payload region long enough to sample" % path)
    span = len(tail) - size
    step = max(1, span // max(1, count - 1)) if count > 1 else 1
    out, seen = [], set()
    for i in range(count):
        off = min(span, i * step)
        w = tail[off:off + size]
        if w not in seen and b"\x00" not in w:
            seen.add(w)
            out.append((off, w))
    return out


def iter_worktree(repo):
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = os.path.join(root, name)
            if os.path.islink(full):
                continue
            yield full, os.path.relpath(full, repo)


def git(repo, *args):
    return subprocess.run(("git", "-C", repo) + args, capture_output=True)


def iter_rev_blobs(repo, rev):
    """(path, bytes) for every blob in `rev`'s tree, via git cat-file."""
    p = git(repo, "ls-tree", "-r", "-z", "--format=%(objectname) %(path)", rev)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode("utf-8", "replace").strip())
    entries = []
    for rec in p.stdout.split(b"\x00"):
        if not rec.strip():
            continue
        sha, _, path = rec.partition(b" ")
        entries.append((sha.decode(), path.decode("utf-8", "replace")))
    for sha, path in entries:
        blob = git(repo, "cat-file", "blob", sha)
        if blob.returncode == 0:
            yield path, blob.stdout


def main():
    ap = argparse.ArgumentParser(prog="verify-no-samples.py")
    ap.add_argument("--samples", default=DEFAULT_SAMPLES,
                    help="directory holding the real *.SAMPLE.txt evidence "
                         "(default: $MALWARE_EVIDENCE_DIR)")
    ap.add_argument("--repo", default=".", help="repository to check")
    ap.add_argument("--rev", default="HEAD",
                    help="commit-ish whose tree is also checked ('' to skip)")
    ap.add_argument("--windows", type=int, default=10,
                    help="byte windows per sample (default 10)")
    ap.add_argument("--size", type=int, default=48,
                    help="window length in bytes (default 48)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    if not args.samples:
        eprint("error: no evidence directory. Pass --samples DIR or set "
               "MALWARE_EVIDENCE_DIR.")
        eprint("       Refusing to report a clean result from a check that "
               "did not run.")
        return 2
    if not os.path.isdir(args.samples):
        eprint("error: evidence directory not found: %s" % args.samples)
        eprint("       mount the backup volume, or pass --samples. Refusing "
               "to report a clean result from a check that did not run.")
        return 2

    samples = sorted(n for n in os.listdir(args.samples)
                     if n.endswith(".SAMPLE.txt"))
    if not samples:
        eprint("error: no *.SAMPLE.txt files in %s" % args.samples)
        return 2

    windows = []          # (sample_name, offset, bytes)
    for name in samples:
        try:
            for off, w in payload_windows(os.path.join(args.samples, name),
                                          args.windows, args.size):
                windows.append((name, off, w))
        except (OSError, ValueError) as exc:
            eprint("error: %s" % exc)
            return 2

    print("verify-no-samples: %d windows of %d bytes from %d sample(s)"
          % (len(windows), args.size, len(samples)))
    for name in samples:
        print("  source: %s" % name)

    hits = []

    n_files = 0
    for full, rel in iter_worktree(repo):
        try:
            with open(full, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        n_files += 1
        for name, off, w in windows:
            if w in data:
                hits.append(("worktree", rel, name, off))
    print("  scanned %d files in the working tree" % n_files)

    if args.rev:
        try:
            n_blobs = 0
            for path, data in iter_rev_blobs(repo, args.rev):
                n_blobs += 1
                for name, off, w in windows:
                    if w in data:
                        hits.append(("%s tree" % args.rev, path, name, off))
            print("  scanned %d blobs in %s" % (n_blobs, args.rev))
        except RuntimeError as exc:
            eprint("error: could not read %s: %s" % (args.rev, exc))
            return 2

    if hits:
        print()
        print("FAIL: real sample bytes are still present.")
        for where, path, name, off in hits:
            print("  %-12s %s  <- %s @+%d" % (where, path, name, off))
        print()
        print("Nothing may be published until every hit is gone. Note that a")
        print("hit in a *tree* but not the worktree means the file is only in")
        print("history -- publishing must use an orphan commit, which is what")
        print("tools/publish-public.sh does.")
        return 1

    print()
    print("PASS: no window of any real sample appears in the working tree"
          + ((" or in %s." % args.rev) if args.rev else "."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
