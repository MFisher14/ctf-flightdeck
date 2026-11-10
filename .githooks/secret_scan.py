#!/usr/bin/env python3
"""Commit guard for ctf-flightdeck: secrets, private material, oversized files.

Runs as the pre-commit hook (--staged) or across the whole index (--all). It never
prints a matched value: each finding names the file, the rule and, for denylist hits,
an 8-character sha256 prefix.

Optional denylist: sha256 hex digests, one per line, of exact sensitive strings (your
platform tokens, IPs, team names). Location: $FLIGHTDECK_DENYLIST, else
~/.config/ctf-flightdeck/denylist.sha256. If none is found the scan still runs the
pattern rules and prints a warning saying the hash checks were skipped.

A line containing the pragma "secret-scan: allow" may carry a known-fake value that
matches a token shape (test fixtures). The pragma never overrides a denylist hit.
"""
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

BLOCK_BYTES = 10 * 1024 * 1024
WARN_BYTES = 2 * 1024 * 1024
PRAGMA = b"secret-scan: allow"

PATH_RULES = [
    (re.compile(r"(^|/)\.ctf/"), "per-event credential directory (.ctf/)"),
    (re.compile(r"(^|/)private-notes/"), "local-only private notes"),
    (re.compile(r"(^|/)(token|\.env|\.env\..+|auth\.json|cookies?\.txt)$"), "credential file name"),
]

# (pattern, rule, pragma may allow it)
CONTENT_RULES = [
    (re.compile(rb"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}"), "GitHub token", True),
    (re.compile(rb"\bsk-(?:ant-|or-)?[A-Za-z0-9_-]{24,}"), "API key (OpenAI/Anthropic/OpenRouter shape)", True),
    (re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key", True),
    (re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), "AWS access key", True),
    (re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token", True),
    (re.compile(rb"\bctfd_[a-f0-9]{64}\b"), "CTFd API token shape", True),
]

WARN_RULES = [
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "PEM private key (fine if synthetic)"),
    (re.compile(rb"(?i)\bauthorization:\s*(?:bearer|token|basic)\s+[A-Za-z0-9._~+/=-]{16,}"), "Authorization header value"),
]

# Candidate substrings hashed against the denylist (exact-string match).
CANDIDATE_PATTERNS = [
    re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(rb"ctfd_[a-f0-9]{16,}"),
    re.compile(rb"[A-Za-z0-9_.\-]{20,}"),
    re.compile(rb"[A-Za-z0-9_\-]{16,}"),
]


def load_denylist():
    env = os.environ.get("FLIGHTDECK_DENYLIST")
    path = Path(env).expanduser() if env else Path.home() / ".config/ctf-flightdeck/denylist.sha256"
    if not path.is_file():
        print(f"secret-scan: WARNING: no denylist at {path}; token/IP hash checks skipped "
              f"(pattern rules still ran)", file=sys.stderr)
        return set()
    lines = path.read_text().splitlines()
    return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def split_z(raw):
    return [p.decode("utf-8", "surrogateescape") for p in raw.split(b"\0") if p]


def iter_blobs(paths):
    """Yield (path, bytes|None) for each path from the index, via one cat-file process."""
    proc = subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    try:
        for p in paths:
            proc.stdin.write(b":" + p.encode("utf-8", "surrogateescape") + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline()
            if header.rstrip().endswith(b"missing"):
                yield p, None
                continue
            size = int(header.split()[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)
            yield p, data
    finally:
        proc.stdin.close()
        proc.wait()


def scan(path, data, deny):
    blocks, warns = [], []
    for rx, rule in PATH_RULES:
        if rx.search(path):
            blocks.append(rule)
    if data is None:
        return blocks, warns
    if len(data) > BLOCK_BYTES:
        blocks.append(f"file over {BLOCK_BYTES // (1024 * 1024)} MB ({len(data) // (1024 * 1024)} MB)")
    elif len(data) > WARN_BYTES:
        warns.append(f"large file ({len(data) // 1024} KB)")
    lines = None
    for rx, rule, pragma_ok in CONTENT_RULES:
        for m in rx.finditer(data):
            if pragma_ok:
                if lines is None:
                    lines = data.split(b"\n")
                line_no = data.count(b"\n", 0, m.start())
                if PRAGMA in lines[line_no]:
                    continue
            blocks.append(rule)
            break
    for rx, rule in WARN_RULES:
        if rx.search(data):
            warns.append(rule)
    if deny:
        seen = set()
        for rx in CANDIDATE_PATTERNS:
            for m in rx.finditer(data):
                s = m.group(0)
                if s in seen:
                    continue
                seen.add(s)
                h = hashlib.sha256(s).hexdigest()
                if h in deny:
                    blocks.append(f"denylisted value [sha256:{h[:8]}]")
    return blocks, warns


def main(argv):
    mode = argv[1] if len(argv) > 1 else "--staged"
    if mode not in ("--staged", "--all"):
        sys.exit("usage: secret_scan.py --staged | --all")
    deny = load_denylist()
    if mode == "--staged":
        paths = split_z(git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))
    else:
        paths = split_z(git("ls-files", "-z"))
    n_block = 0
    for path, data in iter_blobs(paths):
        blocks, warns = scan(path, data, deny)
        for rule in dict.fromkeys(blocks):
            print(f"BLOCKED {path}: {rule}", file=sys.stderr)
            n_block += 1
        for rule in dict.fromkeys(warns):
            print(f"warn    {path}: {rule}", file=sys.stderr)
    if n_block:
        print(f"secret-scan: {n_block} blocking finding(s) in {len(paths)} file(s). "
              f"Remove the value (do not bypass with --no-verify).", file=sys.stderr)
        return 1
    print(f"secret-scan: ok ({len(paths)} file(s), {mode})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
