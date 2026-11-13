#!/usr/bin/env python3
"""Windows Installer (.msi) and MSIX/AppX package identity of a handout, read with no model (B-220).

Huntress Day 13 asked an MSI's ProductCode and the lane had no reader of MSI tables: Layer 1 stopped on
UNKNOWN PROPERTY and an agent wrote a live patch that decoded the string pool and the Property table.
That reader now ships as the Metadata lane's pack (readers_msi.py, loaded by properties_strict.py).
This engine puts its identity facts in front of every challenge whose files hold an installer or a
package, at intake and through `python -m ctf run`:

  msi    msi.product_code_guid, msi.upgrade_code_guid, msi.package_code (the summary's Revision
         Number), msi.product_name, msi.product_version, msi.manufacturer, msi.product_language
  msix   msix.identity_name, .identity_publisher, .identity_version, .processor_architecture,
         .package_full_name, .package_family_name, .publisher_id (a bundle: its own Identity)

Each fact is given with its answer forms in the lane's order. A GUID read as text (a Property row, the
Revision Number) comes first in its STORED form, exactly as the file holds it, then the other
spellings (row 284: Day 13's installers stored `{DD1A80D5-...}` uppercase in braces, the judge took
exactly that, and the binary order had offered it fifth). Every Property row's value, and every identity
text, is also searched for the event's flag format.

Inputs: every file under the challenge folder (not its own `recon/`; no symlink is followed), and the
.msi/.msix/.appx/bundle members of a zip there, one level down. Only the tables and the package
manifest are read: no embedded cabinet is unpacked, so no other program is started. A file or member
named as an installer or package that is not read (over MAX_BYTES, encrypted, in a zip that cannot be
opened) is an `unreadable` evidence line with the reason; any other file not read is named in the notes.

Result: `candidate` when a Property value or identity text holds a string in the event flag format;
`unsure` with one evidence line per file when identity facts were read (which fact a question wants is
the question's to say); `unsure` too, with the reason by file, when nothing was read but a file that
looks like an installer or a package (the compound-file magic, an .msi/.msix/.appx/bundle name) could
not be read as one (a cut or damaged installer); `none` when no file is an installer or a package;
`blocked` when an installer is there and olefile, which reads its compound file, is not installed. A
fact the bytes do not settle (a pool that does not sum, two ProductCode rows) is named in the notes,
never guessed.

    python -m ctf run metadata_forensics.msi_identity <challenge_dir>
    python solvers/metadata-forensics/msi_identity.py <file> [<file> ...]     # the facts, by hand
"""
from __future__ import annotations

import importlib.util
import io
import os
import sys
import zipfile
from pathlib import Path

ENGINE = "metadata_forensics.msi_identity"
MSI_NAMES = ("msi.product_code_guid", "msi.upgrade_code_guid", "msi.package_code", "msi.product_name",
             "msi.product_version", "msi.manufacturer", "msi.product_language")
MSIX_NAMES = ("msix.identity_name", "msix.identity_publisher", "msix.identity_version",
              "msix.processor_architecture", "msix.package_full_name", "msix.package_family_name",
              "msix.publisher_id")
PACKAGE_EXTS = (".msi", ".msix", ".appx", ".msixbundle", ".appxbundle")
MAX_FILES = 64              # files of a handout that are looked at
MAX_BYTES = 256 << 20       # bytes of one file (or zip member) that are read
MAX_MEMBERS = 16            # installer/package members of one zip
SKIP_DIRS = {"recon", ".git", "__pycache__"}
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")


class Blocked(RuntimeError):
    """The engine cannot read what is there (a named missing library)."""


def _lane():
    """properties_strict with every reader pack loaded (a missing pack raises PackMissing, by name)."""
    import properties_strict as M
    msi = M.MORE_MODULES.get("readers_msi.py")
    if msi is None:
        raise Blocked("the Metadata lane did not load its MSI reader pack readers_msi.py")
    return M, msi


def kind_of(data: bytes) -> str | None:
    """'msi' for an installer database, 'msix' for a package or bundle, None for anything else."""
    return probe("", data)[0]


def probe(name: str, data: bytes) -> tuple[str | None, str | None]:
    """(kind, why it was not read). kind is as kind_of gives it; `why` names the reason when the file
    looks like an installer or a package (the compound-file magic, a zip or a package name, an .msi
    name) and still could not be read as one: a cut or damaged installer is said, never dropped."""
    M, msi = _lane()
    named = name.lower().endswith(PACKAGE_EXTS)
    if data[:8] == CFB_MAGIC:
        try:
            if msi.RF._msi(data) is not None:
                return "msi", None
        except Exception as e:  # noqa: BLE001 - any parse failure of untrusted bytes is reported, by name
            return None, f"compound file not readable ({type(e).__name__}: {e})"
        if named:
            return None, "a compound file, but no Windows Installer tables in it"
        return None, None
    if data[:4] == b"PK\x03\x04":
        if msi._msix_quiet(data):
            return "msix", None
        if named:
            return None, "a zip, but no readable AppxManifest.xml or bundle manifest in it"
        return None, None
    if named:
        return None, "named as an installer or package, but neither a compound file nor a zip"
    return None, None


def identity(name: str, data: bytes) -> dict:
    """{"kind", "facts": [(property, [(form, text)], best first)], "unsettled": [(property, why)],
    "texts": [every Property value and identity text, for the flag search], "unreadable": why or None}
    of one file; kind None (and nothing but "unreadable") when the file is neither an installer nor a
    package; "unreadable" names why a file that looks like one could not be read."""
    M, msi = _lane()
    kind, why = probe(name, data)
    out = {"kind": kind, "facts": [], "unsettled": [], "texts": [], "unreadable": why}
    if kind is None:
        return out
    if kind == "msi" and importlib.util.find_spec("olefile") is None:
        raise Blocked("olefile is not installed: it reads the installer's compound file "
                      "(uv pip install --python .venv/bin/python olefile)")
    for prop in (MSI_NAMES if kind == "msi" else MSIX_NAMES):
        p = M.lookup(prop)
        if p is None:
            raise Blocked(f"the lane registers no reader for {prop}: readers_msi.py is not the pack this engine knows")
        try:
            options, absent = M.options_for(p, name, data)
        except (M.Unknown, TypeError) as e:
            out["unsettled"].append((prop, str(e) or type(e).__name__))
            continue
        if absent or not options:
            continue
        out["facts"].append((prop, [(str(f), str(v)) for f, v in options]))
        out["texts"].append(str(options[0][1]))
    if kind == "msi":
        try:
            table = msi._table(data, "Property")
        except M.Unknown as e:
            out["unsettled"].append(("msi.property_table", str(e)))
            table = None
        if table:
            out["texts"].extend(str(v) for _, v in table[1] if v is not None)
    return out


def _local_names(data: bytes) -> list[str]:
    """The member names in the local file headers of a zip that zipfile could not open (a cut or broken
    zip): read from the raw bytes, so an installer inside it can still be named. Names only, no data."""
    names, at = [], data.find(b"PK\x03\x04")
    while at != -1 and len(names) < 4 * MAX_MEMBERS:
        head = data[at + 26:at + 30]
        if len(head) < 4:
            break
        n_len = int.from_bytes(head[:2], "little")
        raw = data[at + 30:at + 30 + n_len]
        if len(raw) == n_len and n_len:
            names.append(raw.decode("utf-8", "replace"))
        at = data.find(b"PK\x03\x04", at + 4)
    return names


def _zip_members(rel: str, data: bytes, out: list, notes: list) -> None:
    """Append the installer and package members of the zip `data` to `out` as (rel, label, name, bytes,
    None), or (rel, label, name, None, why) for one that is there but cannot be read (encrypted, over
    MAX_BYTES, cut). A zip that cannot be opened at all is named in `notes`, and every member its raw
    headers name as an installer or package is given as unreadable."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = [i for i in z.infolist() if not i.is_dir() and i.filename.lower().endswith(PACKAGE_EXTS)]
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, ValueError) as e:
        why = f"the zip could not be opened ({type(e).__name__}: {e})"
        named = [n for n in dict.fromkeys(_local_names(data)) if n.lower().endswith(PACKAGE_EXTS)]
        for n in named[:MAX_MEMBERS]:
            out.append((rel, f"{rel} -> {n}", Path(n).name, None, why))
        if not named:
            notes.append(f"{rel}: {why}; no installer or package name in its headers")
        return
    for i in infos[:MAX_MEMBERS]:
        label, name = f"{rel} -> {i.filename}", Path(i.filename).name
        if i.file_size > MAX_BYTES:
            out.append((rel, label, name, None, f"{i.file_size} bytes, over MAX_BYTES={MAX_BYTES}, not read"))
            continue
        try:
            out.append((rel, label, name, z.read(i), None))
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, ValueError) as e:
            out.append((rel, label, name, None, f"zip member not read ({type(e).__name__}: {e})"))
    if len(infos) > MAX_MEMBERS:
        notes.append(f"{rel}: {len(infos) - MAX_MEMBERS} more installer/package member(s) not read "
                     f"(over MAX_MEMBERS={MAX_MEMBERS})")


def _handout(challenge_dir: Path):
    """([(path relative to the challenge, label, file name, bytes or None, why not read or None)],
    files over MAX_FILES, notes) of the files to read: every file outside recon/, and the installer and
    package members of a zip, one level down. A file or member named as an installer or package that is
    not read (over MAX_BYTES, encrypted, in a broken zip) comes with bytes None and the reason; any other
    file that is not read is named in the notes. Nothing is dropped silently."""
    found = []
    for dirpath, dirnames, filenames in os.walk(challenge_dir):
        here = Path(dirpath)
        # os.walk does not follow a symlinked folder (followlinks=False); a symlinked file is refused below
        dirnames[:] = sorted(d for d in dirnames if not (here == challenge_dir and d in SKIP_DIRS))
        for n in sorted(filenames):
            f = here / n
            if f.is_symlink() or not f.is_file():
                continue
            found.append(f)
    out, notes = [], []
    for f in found[:MAX_FILES]:
        rel = str(f.relative_to(challenge_dir))
        size = f.stat().st_size
        if size > MAX_BYTES:
            why = f"{size} bytes, over MAX_BYTES={MAX_BYTES}, not read"
            if f.name.lower().endswith(PACKAGE_EXTS):
                out.append((rel, rel, f.name, None, why))
            else:
                notes.append(f"{rel}: {why}")
            continue
        data = f.read_bytes()
        out.append((rel, rel, f.name, data, None))
        if data[:4] == b"PK\x03\x04" and kind_of(data) is None:
            _zip_members(rel, data, out, notes)
    return out, max(0, len(found) - MAX_FILES), notes


def _line(prop: str, options) -> str:
    best = options[0]
    more = ", ".join(v for _, v in options[1:])
    return f"{prop} = {best[1]}  [{best[0]}" + (f"; also {more}]" if more else "]")


def solve(challenge_dir, profile, **_opts):
    """Identity facts (stored GUID form first) of every installer and package in the handout."""
    from ctf import flagfmt
    from ctf.result import Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    files, over, notes = _handout(challenge_dir)
    evidence, flags, read, unreadable = [], [], 0, 0
    for rel, label, name, data, why in files:
        try:
            got = identity(name, data) if data is not None else {"kind": None, "unreadable": why}
        except Blocked as e:
            return SolverResult(status="blocked", engine=ENGINE, notes=f"{label}: {e}")
        if got["unreadable"]:
            unreadable += 1
            evidence.append(Evidence(kind="unreadable", detail=f"{label}: {got['unreadable']}", path=rel))
            notes.append(f"{label}: not read as an installer or package ({got['unreadable']})")
        if got["kind"] is None:
            continue
        read += 1
        for prop, options in got["facts"]:
            evidence.append(Evidence(kind=f"{got['kind']}-identity", detail=f"{label}: {_line(prop, options)}", path=rel))
        for prop, why in got["unsettled"]:
            notes.append(f"{label}: {prop} not established ({why})")
        for text in got["texts"]:
            for fl in ff.find_flags(text):
                if fl not in flags:
                    flags.append(fl)
                    evidence.append(Evidence(kind="match", detail=f"{label}: flag-format text in an identity "
                                                                  f"field or Property value", path=rel))
    if over:
        notes.append(f"{over} more file(s) not read (over MAX_FILES={MAX_FILES})")
    note = "; ".join(notes)
    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE,
                            notes=("flag-format text in an installer or package (static, unverified). " + note).strip())
    if not read and unreadable:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=ENGINE,
                            notes=f"{unreadable} file(s) look like an installer or package and could not be read: "
                                  + note)
    if not read:
        return SolverResult(status="none", engine=ENGINE,
                            notes="no Windows Installer database or MSIX/AppX package in the handout" + ("; " + note if note else ""))
    return SolverResult(status="unsure", evidence=tuple(evidence), engine=ENGINE,
                        notes=(f"identity of {read} installer/package file(s); the GUIDs read as text are "
                               "given in their stored form first" + ("; " + note if note else "")))


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: msi_identity.py <file> [<file> ...]", file=sys.stderr)
        return 2
    status = 0
    for a in argv:
        try:
            data = Path(a).read_bytes()
            got = identity(Path(a).name, data)
        except (OSError, Blocked) as e:
            print(f"msi_identity.py: {a}: {e}", file=sys.stderr)
            status = 1
            continue
        if got["kind"] is None:
            print(f"{a}: neither a Windows Installer database nor an MSIX/AppX package"
                  + (f" that could be read ({got['unreadable']})" if got["unreadable"] else ""))
            continue
        print(f"{a}: {got['kind']}")
        for prop, options in got["facts"]:
            print("  " + _line(prop, options))
        for prop, why in got["unsettled"]:
            print(f"  {prop}: not established ({why})")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
