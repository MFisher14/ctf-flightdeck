#!/usr/bin/env python3
"""B-068 -- Evidence ledger: cross-file key / GUID / password join.

A delivery often hides an archive password in a *different* file from the archive: a GUID in a
registry hive or a .lnk, a password in a shell-history line or a cleartext pcap login, an xattr in a
pax tar, a Base64 or HMAC recipe in a PowerShell script. Correlating those by hand is what this
module does for the operator.

It extends solvers/common/evidence_core.py's indicator Index with three kinds the raw-byte scan does
not produce on its own -- `guid` (also scanned from raw now), `key` and `password` -- by running the
carried readers over each member and adding what they surface:

  * windows.lnk()            -- a shell link's machine id (a GUID) and any password on its arguments
  * windows Hive values      -- MachineGuid, DefaultPassword and other password-named values
  * nix_host.parse_history() -- a password passed to 7z/unzip/openssl/curl/gpg/mysql on a shell line
  * network.credentials()    -- a cleartext ftp/pop3/imap/telnet/http login in a capture
  * archive_expand.pax_records() -- a pax extended-header / SCHILY.xattr record of a tar
  * powershell (static only) -- a Base64 literal, and HMAC-over-a-MachineGuid key derivation

Then it joins values seen across two or more members (the pivots) and offers every surfaced password /
key / derived value as a candidate password, which it feeds to B-074's harvest path
(solvers/common/archive_passwords.add_many) so the B-013 sweep's encrypted members are retried with
them. No challenge artifact is ever executed: PowerShell is read statically, never run (`never run
pwsh`), and only the two recipe forms the B-068 spec allows (Base64 literal, HMAC over MachineGuid)
are derived. Passwords are shown only through archive_passwords.mask(); a value is never printed.
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import importlib.util
import re
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

MAX_CANDIDATES = 4000           # a join never floods the password store
MAX_PW_LEN = 128                # archive_passwords' own limit; a longer run is not a password
_DERIVE_CAP = 2000              # bounded HMAC derivation: guids x literals x orders x renderings


# -- lazy module loading ----------------------------------------------------------------------------
#
# The readers live in several lane folders; load each by its path under a unique name so this module
# imports the same engines whether it runs from the suite (conftest puts the lanes on sys.path) or
# from a tool (no lane on sys.path). Loaded once and cached.

_MODS = {}
_READER_PATHS = {
    "evidence_core": "solvers/common/evidence_core.py",
    "archive_passwords": "solvers/common/archive_passwords.py",
    "nix_host": "solvers/common/nix_host.py",
    "windows": "solvers/toolkits/windows.py",
    "network": "solvers/toolkits/network.py",
    "powershell": "solvers/script-analysis/powershell.py",
    "archive_expand": "tools/archive_expand.py",
}


def _mod(name):
    if name not in _MODS:
        rel = _READER_PATHS[name]
        spec = importlib.util.spec_from_file_location("evledger_" + name, ROOT / rel)
        m = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = m
        spec.loader.exec_module(m)
        _MODS[name] = m
    return _MODS[name]


# -- password-bearing command lines -----------------------------------------------------------------
#
# A password passed to a common archive / crypto / login tool on a shell line or a .lnk argument
# string. Each alternative captures the value in exactly one group; the whole set is read once.
_PW_FLAG = re.compile(
    r"""(?x)
    -p(?P<attached>[^\s'"]{1,128})                 # 7z/zip: -pSECRET (attached, no space)
    | -P\s+(?P<unzip>[^\s'"]{1,128})               # unzip -P SECRET
    | --pass(?:word|phrase)?[=\s]+(?P<long>[^\s'"]{1,128})
    | -pass\s+pass:(?P<openssl>[^\s'"]{1,128})     # openssl -pass pass:SECRET
    | (?:openssl\b[^\n]*?)\s-k\s+(?P<ossl_k>[^\s'"]{1,128})
    | --passphrase[=\s]+(?P<gpg>[^\s'"]{1,128})
    | -u\s+[^\s:'"]{1,64}:(?P<curl>[^\s'"]{1,128})  # curl -u user:pass
    | \b(?:PASS(?:WORD)?|PASSPHRASE|ZIP_PASSWORD)=(?P<env>[^\s'"]{1,128})
    """,
    re.I,
)


def _passwords_in_command(text):
    """Every password literal a command line hands to an archive / crypto / login tool. Deduplicated,
    source order."""
    out, seen = [], set()
    for m in _PW_FLAG.finditer(text or ""):
        value = next((g for g in m.groups() if g), None)
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


_GUID_RE = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?")
_PW_NAME = re.compile(r"pass(?:word|phrase)?|pwd|secret|credential", re.I)


# -- the readers: each yields (kind, value, via) ----------------------------------------------------

def lnk_indicators(data):
    """GUID and password indicators of one shell link. [] when the bytes are not a .lnk."""
    win = _mod("windows")
    try:
        link = win.lnk(data)
    except Exception:                   # noqa: BLE001 -- a non-lnk or a damaged one surfaces nothing
        return []
    out = []
    mid = link.get("machine_id")
    if mid and _GUID_RE.fullmatch(mid.strip()):
        out.append(("guid", mid.strip(), "lnk"))
    for field in ("arguments", "command_line"):
        val = link.get(field)
        if isinstance(val, str) and val:
            for g in _GUID_RE.findall(val):
                out.append(("guid", g, "lnk"))
            for pw in _passwords_in_command(val):
                out.append(("password", pw, "lnk"))
    return out


def hive_indicators(data):
    """MachineGuid, password-named values and GUID-shaped values of one registry hive. [] when the
    bytes are not a regf hive."""
    win = _mod("windows")
    try:
        hive = win.Hive(data)
    except Exception:                   # noqa: BLE001
        return []
    out = []
    # walk() yields the root's subkeys and below but not the root key itself; include it so a value
    # stored directly on the root (and the common deep MachineGuid path) are both read.
    keys = [getattr(hive, "root", None)] + list(hive.walk())
    for key in keys:
        if key is None:
            continue
        try:
            vals = key.values()
        except Exception:               # noqa: BLE001 -- a damaged key never stops the walk
            continue
        for name, val in vals.items():
            data_str = val.data if isinstance(val.data, str) else None
            if name.lower() == "machineguid" and data_str and _GUID_RE.fullmatch(data_str.strip()):
                out.append(("guid", data_str.strip(), "hive"))
            elif _PW_NAME.search(name or "") and data_str and data_str.strip():
                out.append(("password", data_str.strip(), "hive"))
            elif data_str and _GUID_RE.fullmatch(data_str.strip()):
                out.append(("guid", data_str.strip(), "hive"))
    return out


def history_indicators(data):
    """Password literals handed to archive/crypto/login tools on shell-history command lines."""
    nix = _mod("nix_host")
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    out = []
    try:
        entries = nix.parse_history(text)
    except Exception:                   # noqa: BLE001
        return []
    for entry in entries:
        for pw in _passwords_in_command(entry.get("command") or ""):
            out.append(("password", pw, "history"))
    return out


def pcap_indicators(data):
    """Cleartext login passwords (and usernames as keys) of one capture. [] when not a capture."""
    net = _mod("network")
    try:
        if not net.is_capture(data):
            return []
        cap = net.Capture(data)
        creds = cap.credentials()
    except Exception:                   # noqa: BLE001
        return []
    out = []
    for c in creds:
        pw = c.get("password")
        if isinstance(pw, (bytes, bytearray)):
            pw = pw.decode("utf-8", "replace")
        if isinstance(pw, str) and pw:
            out.append(("password", pw, "pcap"))
    return out


def pax_indicators(data):
    """Values of a tar's non-standard pax / xattr records. A GUID-shaped one is a guid; the rest are
    offered as passwords (an author parks a secret in an xattr)."""
    ax = _mod("archive_expand")
    out = []
    try:
        records = ax.pax_records(data)
    except Exception:                   # noqa: BLE001
        return []
    for _member, keyword, value in records:
        value = value.strip()
        if not value:
            continue
        if _GUID_RE.fullmatch(value):
            out.append(("guid", value, "pax"))
        else:
            kind = "password" if _PW_NAME.search(keyword or "") else "key"
            out.append((kind, value, "pax"))
    return out


# -- PowerShell: the two static recipe forms the spec allows ---------------------------------------

_HMAC_ALGO = re.compile(r"HMAC(?:SHA(?P<bits>256|384|512|1)|(?P<md5>MD5))", re.I)
_HASH_FOR = {"1": hashlib.sha1, "256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}


def _printable(raw):
    try:
        text = raw.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None
    text = text.strip()
    if text and all(32 <= ord(c) < 127 for c in text) and len(text) <= MAX_PW_LEN:
        return text
    return None


def _render(digest):
    """The hex (lower and upper) and Base64 renderings of a derived digest, usable as a password."""
    out = [digest.hex()]
    up = digest.hex().upper()
    if up != out[0]:
        out.append(up)
    out.append(base64.b64encode(digest).decode("ascii"))
    return [v for v in out if 0 < len(v) <= MAX_PW_LEN]


def powershell_indicators(data, machine_guids=()):
    """Static-only recipe candidates from one PowerShell script: Base64 string literals decoded to a
    printable value, and HMAC(key, message) over a MachineGuid for every GUID (joined-in or literal in
    the script) and every string literal, rendered hex/Base64. Never runs pwsh; both orders of
    key/message are tried because the spec names neither."""
    ps = _mod("powershell")
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    out = []

    # (1) Base64 literals -> a printable value is a password candidate.
    for raw in ps.encoded_candidates(text):
        value = _printable(raw)
        if value:
            out.append(("password", value, "powershell>base64"))

    algo = _HMAC_ALGO.search(text)
    if not algo:
        return out

    hfn = hashlib.md5 if algo.group("md5") else _HASH_FOR[algo.group("bits")]
    literals = [s for s in ps.ps_strings(text) if 0 < len(s) <= MAX_PW_LEN]
    guids = list(OrderedDict.fromkeys(
        [g.strip("{}") for g in machine_guids] + [g.strip("{}") for g in _GUID_RE.findall(text)]
    ))
    if not guids:
        return out

    # (2) HMAC over a MachineGuid. The key is the GUID (as the spec says), the message a literal; the
    # reverse order is tried too. Bounded by _DERIVE_CAP so a long script cannot explode the store.
    seen, derived = set(), 0
    for guid in guids:
        guid_bytes = guid.encode("utf-8")
        for lit in literals or [guid]:
            if derived >= _DERIVE_CAP:
                break
            for key, msg in ((guid_bytes, lit.encode("utf-8")), (lit.encode("utf-8"), guid_bytes)):
                digest = hmac.new(key, msg, hfn).digest()
                for value in _render(digest):
                    if value not in seen:
                        seen.add(value)
                        out.append(("key", value, "powershell>hmac"))
                        derived += 1
    return out


# -- which reader a member goes to ------------------------------------------------------------------

def _reader_for(name, data):
    """The readers that apply to one member, by magic and name. A member may hit more than one (a tar
    of a hive): each reader is defensive, so a miss costs only its own guard."""
    readers, short = [], name.split("->")[-1].strip().lower()
    head = bytes(data[:8])
    if head[:4] == b"regf":
        readers.append(hive_indicators)
    if head == b"L\x00\x00\x00\x01\x14\x02\x00" or short.endswith(".lnk"):
        readers.append(lnk_indicators)
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a") or short.endswith((".pcap", ".pcapng", ".cap")):
        readers.append(pcap_indicators)
    if head[:2] == b"\x1f\x8b" or short.endswith((".tar", ".pax")) or _looks_tar(data):
        readers.append(pax_indicators)
    if re.search(r"(^|[._])(bash_|zsh_|sh_)?history$", short) or (b"\n#1" in data[:4096] and data[:1] != b"\x7f"):
        readers.append(history_indicators)
    if short.endswith((".ps1", ".psm1")) or re.search(rb"(?i)frombase64string|hmacsha|convert\]::|new-object", data[:65536]):
        readers.append(powershell_indicators)
    return readers


def _looks_tar(data):
    return len(data) >= 265 and data[257:262] == b"ustar"


# -- building the ledger ----------------------------------------------------------------------------

def collect(files, deadline=None):
    """The indicator Index of a delivery, enriched with the B-068 reader kinds (guid/key/password).

    `files` is {name: bytes} (as a solver is handed them), a list of paths, or one path -- the same
    shapes evidence_core.ioc() takes. The base index is built first (so every raw-byte guid and the
    existing kinds are there), then each member is passed to the readers that apply."""
    ec = _mod("evidence_core")
    if isinstance(files, (str, Path)):
        files = [files]
    if not isinstance(files, dict):
        files = {str(p): Path(p).read_bytes() for p in files}
    index = ec.ioc(files, deadline=deadline)

    # The joined machine GUIDs feed the PowerShell HMAC recipe: a GUID in a hive/lnk can be the key a
    # script derives the password from, so it is read before the PowerShell members.
    guids = list(OrderedDict.fromkeys(h.value for h in index.hits if h.kind == "guid"))

    # Readers run over the unpacked leaves AND the raw inputs: member_files drops an archive whose
    # members it extracted, but a tar's pax extended headers live only in the raw tar, not in any
    # extracted member, so a pax secret would be lost if the readers saw leaves alone.
    members, seen_data = [], set()
    for name, data in list(ec.member_files(files)) + list(files.items()):
        token = (name, len(data), hash(bytes(data[:4096])))
        if token not in seen_data:
            seen_data.add(token)
            members.append((name, data))

    for name, data in members:
        for reader in _reader_for(name, data):
            try:
                if reader is powershell_indicators:
                    found = powershell_indicators(data, machine_guids=guids)
                else:
                    found = reader(data)
            except Exception:           # noqa: BLE001 -- a reader never breaks the ledger
                index.notes.append(f"{name}: {reader.__name__} raised; skipped")
                continue
            for kind, value, via in found:
                index.add(kind, value, name, -1, via)
                if kind == "guid" and value not in guids:
                    guids.append(value)
    return index


def joins(index, kinds=("guid", "key", "password")):
    """The cross-file pivots: [(kind, value, [members])] for a value of one of `kinds` seen in two or
    more members. These are the joins an operator acts on."""
    return index.cross(kinds=kinds)


def candidates(index):
    """Every candidate password the ledger offers, most-specific first: a surfaced password, then a
    derived or surfaced key, then a GUID (bare and brace-wrapped), then any value that joined across
    files. De-duplicated, each a usable store value (1..128 chars, no newline/NUL), capped."""
    out, seen = [], set()

    def put(value):
        if not isinstance(value, str):
            return
        if value and "\n" not in value and "\x00" not in value and len(value) <= MAX_PW_LEN and value not in seen:
            seen.add(value)
            out.append(value)

    for kind in ("password", "key"):
        for value in index.values(kind):
            put(value)
    for value in index.values("guid"):
        put(value)
        put("{" + value.upper() + "}")      # a GUID is often the password in its registry brace form
    for _kind, value, _members in joins(index):
        put(value)
    return out[:MAX_CANDIDATES]


def feed_store(files, source="ledger-join"):
    """Build the ledger and feed its candidate passwords to B-074's archive-open store
    (archive_passwords.add_many) so the B-013 sweep's encrypted members are retried with them. Returns
    {candidates, new, joins, notes}: `new` and the join values are MASKED (archive_passwords.mask),
    never the plaintext."""
    ap = _mod("archive_passwords")
    index = collect(files)
    cands = candidates(index)
    new = ap.add_many(cands, source=source)
    js = joins(index)
    return {
        "candidates": len(cands),
        "new": [ap.mask(v) for v in new],
        "joins": [{"kind": k, "value": ap.mask(v), "members": ms} for k, v, ms in js],
        "notes": list(index.notes),
    }


def harvest_candidates(files):
    """The ledger's candidate passwords for a caller that stores them itself (ctf/sweep.py's harvest
    step). Plaintext, for the store only -- the caller must not print them."""
    return candidates(collect(files))


# -- CLI --------------------------------------------------------------------------------------------

def main(argv=None):
    ap = _mod("archive_passwords")
    p = argparse.ArgumentParser(
        description="Evidence ledger: join keys/GUIDs/passwords across LNK/registry/pcap/PAX/history/"
                    "PowerShell and offer them as archive-password candidates (B-068). Passwords are "
                    "shown masked; a value is never printed.")
    p.add_argument("paths", nargs="+", help="files or a delivery folder's members")
    p.add_argument("--feed", action="store_true", help="store the candidates in the archive-open password store")
    args = p.parse_args(argv)

    files = {}
    for path in args.paths:
        pp = Path(path)
        if pp.is_dir():
            for f in sorted(pp.rglob("*")):
                if f.is_file():
                    files[str(f.relative_to(pp))] = f.read_bytes()
        elif pp.is_file():
            files[pp.name] = pp.read_bytes()
    if not files:
        print("no readable files")
        return 2

    index = collect(files)
    js = joins(index)
    print(f"members read: {len(index.members)}")
    print(f"joins (value in >=2 files): {len(js)}")
    for kind, value, members in js:
        print(f"  {kind:8} {ap.mask(value):24} <- {', '.join(members)}")
    cands = candidates(index)
    print(f"candidate passwords: {len(cands)}")
    for value in cands[:50]:
        print(f"  {ap.mask(value)}")
    if args.feed:
        new = ap.add_many(cands, source="ledger-cli")
        print(f"stored {len(new)} new candidate(s): {', '.join(ap.mask(v) for v in new)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
