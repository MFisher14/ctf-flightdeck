#!/usr/bin/env python3
"""Toolkit `hashcrack`: a john-the-ripper pipeline wrapper for the LOCAL hash-cracking archetypes
(CSCTF 2024 Linux/John, My secure password, Hashes; Crypto/Signed Flask is a flask-unsign job, see
docs/playbooks/linux.md). Offline, standard library only.

  .venv/bin/python solvers/toolkits/hashcrack.py <protected.zip | shadow [passwd] | hashes.txt>...

What it does, and firmly does NOT do:
  * It recognises a password-protected archive (zip/rar/7z), an /etc shadow(+passwd) pair, or a file
    of raw hashes, and emits the EXACT john invocation for it: the right `*2john` extractor
    (zip2john / rar2john / 7z2john.pl), `unshadow` for a shadow+passwd pair, then
    `john --wordlist=<rockyou> <hashfile>` and `john --show`.
  * If john + the extractor + a rockyou wordlist are all installed it will RUN that dictionary attack
    locally and report the recovered password(s) (the cracked plaintext is often itself the flag, or
    you take the longest one -- the My-secure-password trick). Otherwise it prints the exact commands
    for the player to run.
  * This is LOCAL dictionary cracking of a hash we already hold -- it is NOT a flag brute-force and
    never touches the CTFd judge. It only ever runs the trusted cracking tools (john, zip2john, ...)
    against a wordlist; it never executes the challenge artifact as code. Per AGENTS.md the ban is on
    sweeping candidate FLAGS at the scoreboard, not on offline password recovery, which every top team
    does with exactly this toolchain.

Import use:
    sys.path.insert(0, "solvers/toolkits"); import hashcrack
    plan = hashcrack.plan(["secret.zip"])          # a Plan: kind, commands, tool availability
    print(plan.render())                            # the copy-paste command block
    res = hashcrack.crack(["secret.zip"], run=True) # runs locally iff tools+rockyou present
    hashcrack.longest(res.cracked)                  # the longest password (My-secure-password)
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# ctf package (env for the configured wordlist, paths for the repo root) -- script runs need the
# checkout root on sys.path; the import must never silently vanish (rule 6: a missing config fails loud).
try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:  # pragma: no cover - exercised only outside the checkout
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths

# john-jumbo keeps its *2john extractors and unshadow in a share dir that is usually NOT on PATH
# (Homebrew: /opt/homebrew/share/john; Debian/Kali: /usr/share/john, /usr/sbin). We look there too.
JOHN_SHARE_DIRS = [
    "/opt/homebrew/share/john",
    "/usr/local/share/john",
    "/usr/share/john",
    "/usr/sbin",
    "/usr/local/sbin",
    "/opt/john/run",
]

ROCKYOU_CANDIDATES = [
    "/usr/share/wordlists/rockyou.txt",
    "/opt/homebrew/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    str(Path.home() / "tools" / "wordlists" / "rockyou.txt"),
    str(Path.home() / "wordlists" / "rockyou.txt"),
    str(Path.home() / "rockyou.txt"),
]

RUN_TIMEOUT_S = 180         # cap on the john dictionary run; a miss is a miss, not a hang
EXTRACT_TIMEOUT_S = 30


def find_tool(name: str) -> str | None:
    """Absolute path of a john tool (`john`, `zip2john`, `unshadow`, `rar2john`, `7z2john.pl`, ...),
    PATH first then the john share dirs; None when it is not installed."""
    if not isinstance(name, str):
        return None
    hit = shutil.which(name)
    if hit:
        return hit
    for d in JOHN_SHARE_DIRS:
        p = Path(d) / name
        if p.exists() and (os.access(p, os.X_OK) or p.suffix in (".pl", ".py")):
            return str(p)
    return None


class WordlistMissing(RuntimeError):
    """No cracking wordlist is configured, or the configured path is not a readable file, or it lies
    inside the repo. A loud, named failure (rule 6/10): never a silent fall back to no wordlist."""


def _inside_repo(path) -> bool:
    """True when `path` resolves to somewhere inside this checkout. A wordlist there would mean a
    committed corpus, which the outside-repo rule forbids (rule 10); both wordlist() and find_rockyou()
    use this so the run path and the loud path agree."""
    try:
        Path(path).expanduser().resolve().relative_to(ctf_paths.repo_root().resolve())
        return True
    except (ValueError, OSError):
        return False


def find_rockyou() -> str | None:
    """Path of an installed rockyou.txt, or None. The configured CTF_WORDLIST wins (read through
    ctf.env so legacy spellings resolve), then $ROCKYOU / $WORDLIST, then the usual install paths. A
    configured path inside the repo is refused here too (as wordlist() refuses it), so the run path
    plan()/crack() take never picks an in-repo corpus."""
    configured = ctf_env.get("CTF_WORDLIST")
    if configured and Path(configured).expanduser().is_file() and not _inside_repo(configured):
        return str(Path(configured).expanduser())
    for env in ("ROCKYOU", "WORDLIST"):
        v = os.environ.get(env)
        if v and Path(v).is_file():
            return v
    for c in ROCKYOU_CANDIDATES:
        if Path(c).is_file():
            return c
    return None


def wordlist() -> str:
    """The configured cracking wordlist, as an absolute path, or WordlistMissing with a named reason.

    The source is CTF_WORDLIST (a path to rockyou or any list), kept OUTSIDE the repo so no corpus is
    committed; $ROCKYOU/$WORDLIST and the common install paths are accepted as a fallback for an
    interactive run. It fails loudly (rule 6) when nothing is configured, when the path is not a
    readable file, or when it points inside this checkout."""
    configured = ctf_env.get("CTF_WORDLIST")
    if configured:
        p = Path(configured).expanduser()
        if not p.is_file():
            raise WordlistMissing(f"CTF_WORDLIST is set to {configured!r}, which is not a readable file")
        if _inside_repo(configured):
            raise WordlistMissing(f"CTF_WORDLIST {configured!r} is inside the repo; keep the wordlist "
                                  f"outside the checkout (no corpus is committed)")
        return str(p.resolve())
    found = find_rockyou()
    if found:
        return str(Path(found).resolve())
    raise WordlistMissing("no cracking wordlist: set CTF_WORDLIST to a wordlist path outside the repo "
                          "(rockyou.txt or similar), or install one on the usual path")


# ---- input classification (by magic / content, never by file name) --------------------------------

_SHADOW_HASH_RE = re.compile(r"^[^:\s]+:(\$[\w./-]+\$|\*|!|)[^:]*:")   # user:hash:lastchg:...
_PASSWD_RE = re.compile(r"^[^:\s]+:[^:]*:\d+:\d+:[^:]*:[^:]*:[^:]*\s*$")
_RAWHASH_RE = re.compile(r"^[\$\w./+=:*-]{8,}$")


def _magic(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(8)
    except (OSError, TypeError, ValueError):
        return b""


def classify(path: str) -> str:
    """One of: 'zip', 'rar', '7z', 'shadow', 'passwd', 'hashes', 'unknown'. Shadow vs passwd is read
    from the line shape; archives from the magic bytes."""
    m = _magic(path)
    if m[:2] == b"PK" and m[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08"):
        return "zip"
    if m[:4] == b"Rar!":
        return "rar"
    if m[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, TypeError, ValueError):
        return "unknown"
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return "unknown"
    if sum(1 for ln in lines if ln.count(":") >= 6 and _SHADOW_HASH_RE.match(ln)) >= max(1, len(lines) // 2):
        # distinguish a shadow (hash in field 2) from a passwd (x/*, numeric uid in field 3)
        if any(ln.split(":")[1].startswith("$") for ln in lines if ln.count(":") >= 6):
            return "shadow"
    if sum(1 for ln in lines if _PASSWD_RE.match(ln)) >= max(1, len(lines) // 2):
        return "passwd"
    if sum(1 for ln in lines if ln.count(":") >= 6 and _SHADOW_HASH_RE.match(ln)) >= max(1, len(lines) // 2):
        return "shadow"
    if sum(1 for ln in lines if _RAWHASH_RE.match(ln)) >= max(1, len(lines) // 2):
        return "hashes"
    return "unknown"


ARCHIVE_TOOL = {"zip": "zip2john", "rar": "rar2john", "7z": "7z2john.pl"}


@dataclass
class Plan:
    kind: str                       # 'archive' | 'shadow' | 'hashes' | 'unknown'
    inputs: list                    # the paths, classified
    extractor: str | None           # the *2john tool name, or None
    unshadow: bool = False
    commands: list = field(default_factory=list)   # the exact shell commands, in order
    notes: list = field(default_factory=list)
    hashfile: str = "hashes.john"

    def render(self) -> str:
        head = [f"hashcrack plan: {self.kind}"]
        for n in self.notes:
            head.append(f"  note: {n}")
        head.append("  commands:")
        head += [f"    {c}" for c in self.commands]
        return "\n".join(head)


def plan(paths: list, rockyou: str | None = None, hashfile: str = "hashes.john") -> Plan:
    """Build the john command plan for a set of input paths. Does not run anything."""
    if paths is None:
        paths = []
    rock = rockyou or find_rockyou() or "/usr/share/wordlists/rockyou.txt"
    kinds = {p: classify(p) for p in paths}
    archives = [p for p, k in kinds.items() if k in ARCHIVE_TOOL]
    shadows = [p for p, k in kinds.items() if k == "shadow"]
    passwds = [p for p, k in kinds.items() if k == "passwd"]
    rawhashes = [p for p, k in kinds.items() if k == "hashes"]
    notes = []

    if archives:
        a = archives[0]
        tool = ARCHIVE_TOOL[kinds[a]]
        runner = "perl " if tool.endswith(".pl") else ""
        cmds = [
            f"{runner}{tool} {_q(a)} > {_q(hashfile)}",
            f"john --wordlist={_q(rock)} {_q(hashfile)}",
            f"john --show {_q(hashfile)}",
        ]
        if kinds[a] == "zip":
            notes.append("zip2john prints the archive password hash; the cracked plaintext is the zip "
                         "password (mind leading/trailing spaces -- CSCTF 2024 John used \" school13\").")
        return Plan("archive", list(kinds.items()), tool, False, cmds, notes, hashfile)

    if shadows:
        s = shadows[0]
        if passwds:
            cmds = [
                f"unshadow {_q(passwds[0])} {_q(s)} > {hashfile}",
                f"john --wordlist={_q(rock)} {hashfile}",
                f"john --show {hashfile}",
            ]
            notes.append("unshadow merges passwd (usernames/uid) with shadow (hashes). For "
                         "My-secure-password take the LONGEST cracked password as the flag.")
            return Plan("shadow", list(kinds.items()), "unshadow", True, cmds, notes, hashfile)
        cmds = [
            f"cp {_q(s)} {hashfile}",
            f"john --wordlist={_q(rock)} {hashfile}",
            f"john --show {hashfile}",
        ]
        notes.append("No passwd given; john cracks the shadow file directly (usernames are in it).")
        return Plan("shadow", list(kinds.items()), None, False, cmds, notes, hashfile)

    if rawhashes:
        h = rawhashes[0]
        cmds = [
            f"john --wordlist={_q(rock)} {_q(h)}",
            f"john --show {_q(h)}",
        ]
        notes.append("Raw hash list: if john cannot guess the format add --format=<raw-md5|raw-sha1|"
                     "sha512crypt|...>.")
        return Plan("hashes", list(kinds.items()), None, False, cmds, notes, h)

    return Plan("unknown", list(kinds.items()), None, False,
                ["# unrecognised input: not an archive, shadow/passwd pair, or hash list"],
                ["Could not classify the input. Inspect it by hand."], hashfile)


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'" if re.search(r"[\s'\"$&|;<>()]", s) else s


# ---- running the plan locally (best effort) --------------------------------------------------------

@dataclass
class Result:
    plan: Plan
    ran: bool
    cracked: list = field(default_factory=list)   # [(id, password)] -- id is the user or archive name
    pot: str = ""
    log: list = field(default_factory=list)
    missing: list = field(default_factory=list)   # tools/wordlist that stopped a run


def parse_show(output: str) -> list:
    """Cracked (id, password) pairs from `john --show`. Handles the archive form (name:password) and
    the unshadowed form (user:password:uid:...). Ignores the summary line."""
    if output is None:
        return []
    out = []
    for ln in output.splitlines():
        ln = ln.rstrip("\n")
        if not ln or re.match(r"^\d+ password hashes? cracked", ln):
            continue
        parts = ln.split(":")
        if len(parts) >= 2:
            out.append((parts[0], parts[1]))
    return out


def parse_pot(pot_text: str) -> list:
    """(hash, password) pairs from a john .pot file (`$hash:password`)."""
    if pot_text is None:
        return []
    out = []
    for ln in pot_text.splitlines():
        if ":" in ln:
            h, _, pw = ln.partition(":")
            out.append((h, pw))
    return out


def longest(cracked: list) -> str | None:
    """The longest cracked password (My-secure-password: the answer is the longest of the five)."""
    pws = []
    for row in cracked or []:
        try:
            _, pw = row
        except (TypeError, ValueError):
            continue
        if pw:
            pws.append(pw)
    return max(pws, key=len) if pws else None


# ---- hash-type disambiguation (B-074): a 32-hex digest is raw-MD5 OR NTLM -----------------------
# A bare 32-hex hash drops out of memory, a database, or an /etc shadow with no `$1$`/`$6$` tag, and
# john cannot tell raw-MD5 from NT (NTLM) by its shape alone -- both are 128-bit. When a candidate
# plaintext is in hand (harvested, or a cracked value from another hash), we verify it under BOTH and
# report which one it is, so the right `--format=` goes to john and the recovered value is trusted.


def _left_rotate(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data: bytes) -> bytes:
    """MD4 digest (pure Python). hashlib dropped MD4 on OpenSSL 3, so NTLM needs its own; this gives
    the same 16 bytes deterministically, with no external dependency and no silent fallback."""
    msg = bytearray(data)
    orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += orig_len_bits.to_bytes(8, "little")
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little") for i in range(16)]
        aa, bb, cc, dd = a, b, c, d

        def f(x, y, z): return (x & y) | (~x & z)
        def g(x, y, z): return (x & y) | (x & z) | (y & z)
        def h(x, y, z): return x ^ y ^ z
        for i in (0, 4, 8, 12):
            a = _left_rotate(a + f(b, c, d) + x[i], 3)
            d = _left_rotate(d + f(a, b, c) + x[i + 1], 7)
            c = _left_rotate(c + f(d, a, b) + x[i + 2], 11)
            b = _left_rotate(b + f(c, d, a) + x[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = _left_rotate(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = _left_rotate(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = _left_rotate(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = _left_rotate(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = _left_rotate(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3)
            d = _left_rotate(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = _left_rotate(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = _left_rotate(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


def raw_md5(plaintext: str) -> str:
    return hashlib.md5(plaintext.encode("utf-8")).hexdigest()


def ntlm(plaintext: str) -> str:
    """The NT hash (NTLM) of a password: MD4 of the UTF-16LE plaintext, lower-case hex."""
    return md4(plaintext.encode("utf-16-le")).hex()


def disambiguate(target_hash: str, plaintext: str) -> list:
    """Which 32-hex format(s) the plaintext produces for this target: ['raw-md5'], ['ntlm'], both, or
    []. Verifying both is the point -- the shape alone cannot say which (B-074)."""
    if not isinstance(target_hash, str):
        return []
    want = target_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", want):
        return []
    out = []
    if raw_md5(plaintext) == want:
        out.append("raw-md5")
    if ntlm(plaintext) == want:
        out.append("ntlm")
    return out


def verify(target_hash: str, candidates) -> list:
    """[(plaintext, format)] for every candidate that matches the 32-hex target under raw-MD5 or NTLM.
    Used to turn a harvested or cross-cracked plaintext into a trusted, format-tagged hit."""
    out = []
    for pw in candidates or []:
        if not isinstance(pw, str):
            continue
        for fmt in disambiguate(target_hash, pw):
            out.append((pw, fmt))
    return out


# ---- 7z/rar retry through archive_expand (B-074) ------------------------------------------------
# When john's extractor for a 7z/rar is not installed (7z2john.pl / rar2john), or john itself is
# absent, a mechanical recovery is still possible: try the known passwords (the harvested candidate
# store) against the archive through tools/archive_expand -- a zip in process, a 7z/rar with 7-Zip.
# This reuses the trusted openers only; it never executes the archive's contents.


def _load_archive_passwords():
    common = Path(__file__).resolve().parents[1] / "common"
    if str(common) not in sys.path:
        sys.path.insert(0, str(common))
    import archive_passwords
    return archive_passwords


def _load_harvest():
    common = Path(__file__).resolve().parents[1] / "common"
    if str(common) not in sys.path:
        sys.path.insert(0, str(common))
    import harvest
    return harvest


def _harvest_candidates(path: str) -> list:
    """The candidate passwords to try against an archive: those harvested from the file's own bytes and
    its sibling notes (B-074), then the stored candidate list, de-duplicated with the harvest first."""
    out, seen = [], set()
    try:
        harvested = _load_harvest().harvest(path)
    except (ImportError, OSError, ValueError) as e:
        # Best-effort gather: a missing harvest module or an unreadable file leaves [] here, but say so
        # by name (rule 6) rather than swallow it silently -- the retry still runs on the stored list.
        print(f"hashcrack: harvest candidate gather skipped ({type(e).__name__}: {e})", file=sys.stderr)
        harvested = []
    for c in harvested:
        if c not in seen:
            seen.add(c)
            out.append(c)
    try:
        for c in _load_archive_passwords().candidates():
            s = c.decode("utf-8", "replace") if isinstance(c, bytes) else c
            if s not in seen:
                seen.add(s)
                out.append(s)
    except (ImportError, OSError, ValueError) as e:
        print(f"hashcrack: stored candidate gather skipped ({type(e).__name__}: {e})", file=sys.stderr)
    return out


def retry_archive(path: str, candidates=None) -> str | None:
    """Recover a zip/7z/rar password by trying the candidate passwords against it with the trusted
    openers (zipfile for a zip, 7-Zip for a 7z/rar). Returns the recovered password, or None. With no
    `candidates` it uses the harvested/stored candidate list. Needs 7-Zip only for 7z/rar."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    kind = classify(path)
    if kind not in ("zip", "7z", "rar"):
        return None
    pw = _load_archive_passwords()
    cands = [c.encode("utf-8") if isinstance(c, str) else c
             for c in (candidates if candidates is not None else pw.candidates())]
    if kind == "zip":
        try:
            op = pw.Opener(data, cands=cands)
        except Exception:
            return None
        for info in op.zf.infolist():
            if not info.is_dir() and pw.encrypted(info):
                op.read(info)
        got = op.password_for()
        return got.decode("utf-8", "replace") if isinstance(got, bytes) else got
    exe = shutil.which("7zz") or shutil.which("7z")
    if not exe:
        return None
    with tempfile.TemporaryDirectory(prefix="hashcrack_arc_") as td:
        src = Path(td) / ("archive.7z" if kind == "7z" else "archive.rar")
        src.write_bytes(data)
        for pwd in cands:
            try:
                done = subprocess.run([exe, "t", "-y", "-p" + pwd.decode("utf-8", "replace"), str(src)],
                                      capture_output=True, timeout=EXTRACT_TIMEOUT_S)
            except (subprocess.SubprocessError, OSError):
                continue
            if done.returncode == 0:
                return pwd.decode("utf-8", "replace")
    return None


def crack(paths: list, run: bool = False, rockyou: str | None = None, timeout: int = RUN_TIMEOUT_S) -> Result:
    """Plan the attack and, when run=True and john+extractor+rockyou are all present, run the local
    dictionary attack and parse the recovered passwords. Never runs the challenge artifact; only the
    trusted cracking tools against the wordlist."""
    rock = rockyou or find_rockyou()
    p = plan(paths, rockyou=rock)
    if not run:
        return Result(p, False, missing=["(run=False: plan only)"])

    john = find_tool("john")
    missing = []
    if john is None:
        missing.append("john")
    if rock is None:
        missing.append("rockyou.txt")
    if p.extractor and find_tool(p.extractor) is None:
        missing.append(p.extractor)
    if p.kind == "unknown":
        missing.append("classified input")
    if missing:
        # B-074: for a 7z/rar/zip, retry through archive_expand with the harvested/stored candidates
        # before giving up -- the password john would have found may already be in the candidate store.
        if p.kind == "archive":
            arc = paths_of(p, ARCHIVE_TOOL)
            got = retry_archive(arc, candidates=_harvest_candidates(arc)) if arc else None
            if got is not None:
                return Result(p, True, cracked=[(Path(arc).name, got)],
                              log=[f"recovered via archive_expand retry (john path unavailable: "
                                   f"{', '.join(missing)})"])
        return Result(p, False, missing=missing)

    log = []
    with tempfile.TemporaryDirectory(prefix="hashcrack_") as td:
        hashfile = str(Path(td) / "hashes.john")
        potfile = str(Path(td) / "run.pot")
        # 1) produce the hash file
        if p.kind == "archive":
            tool = find_tool(p.extractor)
            argv = (["perl", tool] if tool.endswith(".pl") else [tool]) + [paths_of(p, ARCHIVE_TOOL)]
            try:
                r = subprocess.run(argv, capture_output=True, timeout=EXTRACT_TIMEOUT_S)
            except (subprocess.SubprocessError, OSError) as e:
                return Result(p, False, log=[f"extractor failed: {e}"], missing=[p.extractor])
            Path(hashfile).write_bytes(r.stdout)
            log.append(f"{p.extractor}: {len(r.stdout)} bytes of hash")
        elif p.kind == "shadow" and p.unshadow:
            un = find_tool("unshadow")
            passwd = [pp for pp, k in p.inputs if k == "passwd"][0]
            shadow = [pp for pp, k in p.inputs if k == "shadow"][0]
            try:
                r = subprocess.run([un, passwd, shadow], capture_output=True, timeout=EXTRACT_TIMEOUT_S)
            except (subprocess.SubprocessError, OSError) as e:
                return Result(p, False, log=[f"unshadow failed: {e}"], missing=["unshadow"])
            Path(hashfile).write_bytes(r.stdout)
        else:
            src = [pp for pp, k in p.inputs if k in ("shadow", "hashes")][0]
            shutil.copyfile(src, hashfile)

        # 2) the dictionary attack (wordlist mode only -- bounded, no incremental sweep)
        base = ["--pot=" + potfile]
        try:
            subprocess.run([john, f"--wordlist={rock}", hashfile] + base,
                           capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            log.append(f"john timed out after {timeout}s (partial results below)")
        except (subprocess.SubprocessError, OSError) as e:
            return Result(p, False, log=[f"john failed: {e}"], missing=["john"])
        # 3) read results
        try:
            show = subprocess.run([john, "--show", hashfile] + base, capture_output=True, text=True)
        except (subprocess.SubprocessError, OSError) as e:
            return Result(p, False, log=log + [f"john --show failed: {e}"], missing=["john"])
        cracked = parse_show(show.stdout)
        pot = Path(potfile).read_text(encoding="utf-8", errors="replace") if Path(potfile).exists() else ""
        if not cracked and pot:
            cracked = [(h, pw) for h, pw in parse_pot(pot)]
    return Result(p, True, cracked=cracked, pot=pot, log=log)


def paths_of(p: Plan, kinds: dict) -> str:
    inputs = getattr(p, "inputs", None)
    if not inputs:
        return ""
    for pp, k in inputs:
        if k in kinds:
            return pp
    return ""


def report(paths: list, run: bool = False) -> str:
    res = crack(paths, run=run)
    L = [res.plan.render(), ""]
    L.append(f"rockyou: {find_rockyou() or '(not found -- install it or set $ROCKYOU)'}")
    L.append(f"john: {find_tool('john') or '(not installed)'}")
    if res.plan.extractor:
        L.append(f"{res.plan.extractor}: {find_tool(res.plan.extractor) or '(not installed)'}")
    if res.ran:
        if res.cracked:
            L.append("")
            L.append("CRACKED:")
            for who, pw in res.cracked:
                L.append(f"  {who} -> {pw!r}")
            lg = longest(res.cracked)
            L.append(f"  longest password (My-secure-password answer): {lg!r}")
        else:
            L.append("\njohn ran but cracked nothing with this wordlist.")
        for ln in res.log:
            L.append(f"  [log] {ln}")
    else:
        if res.missing and res.missing != ["(run=False: plan only)"]:
            L.append(f"\nnot run locally; missing: {', '.join(res.missing)} -- run the commands above by hand.")
        else:
            L.append("\n(plan only; pass run=True / --run to attempt the local crack)")
    return "\n".join(L)


def main(argv) -> int:
    if argv is None:
        argv = []
    run = False
    args = []
    for a in argv:
        if a in ("-h", "--help"):
            print(__doc__.split("\n\n")[0], file=sys.stderr)
            return 2
        if a == "--run":
            run = True
        else:
            args.append(a)
    if not args:
        print("usage: hashcrack.py [--run] <zip | shadow [passwd] | hashes.txt>...", file=sys.stderr)
        return 2
    missing = [p for p in args if not os.path.exists(p)]
    if missing:
        print(f"hashcrack.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(report(args, run=run))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
