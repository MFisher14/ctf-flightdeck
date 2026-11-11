#!/usr/bin/env python3
"""Commit guard for ctf-flightdeck: secrets, private material, oversized files.

Runs as the pre-commit hook (--staged), across the whole index (--all), or across every
file version in the history (--history, before a repository goes public). --add asks for
strings to deny (without showing them) and appends their digests to the denylist; --remove
asks for strings that may appear after all (a name made public on purpose) and takes their
digests out. It never
prints a matched value: each finding names the file, the rule and, for denylist hits,
an 8-character sha256 prefix.

Optional denylist: sha256 hex digests, one per line, of exact sensitive strings (your
platform tokens, IPs, team names, handles). Location: $FLIGHTDECK_DENYLIST, else
~/.config/ctf-flightdeck/denylist.sha256. If none is found the scan still runs the
pattern rules and prints a warning saying the hash checks were skipped.

What gets hashed and compared: token-shaped runs (IPs, ctfd_ tokens, 16+ characters)
exactly as written; every word of 3+ characters (also joined ones like quokka-crew or
quokka_crew); and every run of 2 to 4 words joined by one space. Words are taken as
written and in lower case. So a name matches when its digest is of the name in lower
case, words separated by single spaces, e.g.
    printf '%s' 'quokka crew' | shasum -a 256

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

# Candidate substrings hashed against the denylist (exact-string match), plus the names
# from name_candidates().
CANDIDATE_PATTERNS = [
    re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(rb"ctfd_[a-f0-9]{16,}"),
    re.compile(rb"[A-Za-z0-9_.\-]{20,}"),
    re.compile(rb"[A-Za-z0-9_\-]{16,}"),
]


JOINED = re.compile(r"\w+(?:[.'-]\w+)*")  # quokka-crew, quokka_crew, q.crew
WORD = re.compile(r"[^\W_]+")  # letters and digits only: quokka_crew is two words
MIN_WORD = 3
MAX_WINDOW = 4


def name_candidates(data):
    """Words (3+ characters) and runs of 2-4 words, as written and lower-cased, as bytes."""
    text = data.decode("utf-8", "ignore")
    words = WORD.findall(text)
    out = {w for w in JOINED.findall(text) + words if len(w) >= MIN_WORD}
    for n in range(2, MAX_WINDOW + 1):
        out.update(" ".join(words[i : i + n]) for i in range(len(words) - n + 1))
    out |= {s.lower() for s in out}
    return {s.encode("utf-8") for s in out}


def denylist_path():
    env = os.environ.get("FLIGHTDECK_DENYLIST")
    return Path(env).expanduser() if env else Path.home() / ".config/ctf-flightdeck/denylist.sha256"


def add_to_denylist():
    """Ask for strings to keep out of the repository, without echoing them, and append their
    digests: as typed, and in the form names are compared in (lower case, single spaces)."""
    import getpass

    path = denylist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Adding to {path}.")
    print("Type each team name, handle, real name, IP or token to keep out of the repository.")
    print("Nothing you type is shown or stored; only its sha256 digest is. Press Enter on an empty line to finish.")
    added = 0
    while True:
        value = getpass.getpass("string: ").strip()
        if not value:
            break
        forms = {value, " ".join(value.lower().split())}
        with open(path, "a", encoding="utf-8") as out:
            for form in sorted(forms):
                out.write(hashlib.sha256(form.encode("utf-8")).hexdigest() + "\n")
        added += 1
    if path.exists():
        os.chmod(path, 0o600)
    print(f"added {added} string(s); now run: python3 .githooks/secret_scan.py --history")
    return 0


def _forms(value):
    """The digests --add stores for one string: as typed, and as names are compared."""
    return {hashlib.sha256(form.encode("utf-8")).hexdigest() for form in {value, " ".join(value.lower().split())}}


def _asked(prompt_intro):
    """Strings typed without echo (at a terminal), else one per line on stdin."""
    import getpass

    if not sys.stdin.isatty():
        return [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
    print(prompt_intro)
    values = []
    while True:
        value = getpass.getpass("string: ").strip()
        if not value:
            return values
        values.append(value)


def remove_from_denylist():
    """Take strings off the denylist (a name or handle made public on purpose): every digest
    --add would have stored for each is removed. Prints how many went, never a value."""
    path = denylist_path()
    if not path.is_file():
        print(f"secret-scan: no denylist at {path}; nothing to remove", file=sys.stderr)
        return 1
    values = _asked("Type each string that may now appear in the repository. Nothing you type is shown. "
                    "Press Enter on an empty line to finish.")
    gone = set().union(*(_forms(value) for value in values)) if values else set()
    lines = path.read_text().splitlines()
    kept = [line for line in lines if line.strip() not in gone]
    removed = len(lines) - len(kept)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text("".join(line + "\n" for line in kept))
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    print(f"removed {removed} digest(s) for {len(values)} string(s)"
          + ("" if removed else ": none of them was on the denylist"))
    return 0


def history_blobs():
    """(path, data) for every blob in every commit's tree, each blob once."""
    listing = subprocess.run(["git", "rev-list", "--all", "--objects"], capture_output=True, check=True).stdout
    seen = set()
    for line in listing.decode("utf-8", "replace").splitlines():
        sha, _, path = line.partition(" ")
        if not path or sha in seen:
            continue
        kind = subprocess.run(["git", "cat-file", "-t", sha], capture_output=True, text=True).stdout.strip()
        if kind != "blob":
            continue
        seen.add(sha)
        data = subprocess.run(["git", "cat-file", "blob", sha], capture_output=True, check=True).stdout
        yield path, data


def load_denylist():
    path = denylist_path()
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
        candidates = {m.group(0) for rx in CANDIDATE_PATTERNS for m in rx.finditer(data)}
        for s in sorted(candidates | name_candidates(data)):
            h = hashlib.sha256(s).hexdigest()
            if h in deny:
                blocks.append(f"denylisted value [sha256:{h[:8]}]")
    return blocks, warns


def main(argv):
    mode = argv[1] if len(argv) > 1 else "--staged"
    if mode not in ("--staged", "--all", "--history", "--add", "--remove"):
        sys.exit("usage: secret_scan.py --staged | --all | --history | --add | --remove")
    if mode == "--add":
        return add_to_denylist()
    if mode == "--remove":
        return remove_from_denylist()
    deny = load_denylist()
    if mode == "--history":
        blobs = list(history_blobs())
        paths = [path for path, _ in blobs]
    elif mode == "--staged":
        paths = split_z(git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))
        blobs = iter_blobs(paths)
    else:
        paths = split_z(git("ls-files", "-z"))
        blobs = iter_blobs(paths)
    n_block = 0
    for path, data in blobs:
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
