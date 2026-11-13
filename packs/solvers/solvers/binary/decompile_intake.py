#!/usr/bin/env python3
"""Decompile-on-intake for every ELF / PE / Mach-O / .NET binary (B-011).

At intake this engine finds every native executable (and .NET assembly) in the challenge handout,
runs a *static* decompiler over it, and saves the pseudocode of ``main``, the entry point and every
constructor (ELF ``.init_array`` / ``.ctors``) into ``recon/decompile/<file>/`` in the workspace, so
the reverse and pwn engines (B-024, B-025, B-026) and the agent read one decompile instead of each
re-running Ghidra.  The decompiled text is scanned for the event flag format: a hardcoded flag in a
check function surfaces as a ``candidate``.

Backends, in order of preference, auto-detected and reported by name:
  * r2ghidra   -- radare2 with the ``pdg`` (Ghidra) decompiler plugin (the Huntress/csctf sandbox tool)
  * ghidra     -- Ghidra headless ``analyzeHeadless`` with a DecompileScript (heavy)
  * ilspycmd   -- ILSpy command line, for .NET assemblies

No decompiler is ever *guessed*: when none that fits a file's format is installed the engine fails
loudly with a named reason (``blocked`` / a per-file note), never a silent empty result.  The
decompiler only reads the binary statically; this engine never executes a challenge binary.

Entry: ``solve(challenge_dir, profile) -> SolverResult`` (an intake ``run = "challenge"`` adapter).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ----------------------------------------------------------------------------- limits
MAX_FILE_BYTES = 256 * 1024 * 1024    # a handout "binary" larger than this is not decompiled at intake
HEAD_BYTES = 64 * 1024                # bytes read to classify and to parse the ELF section table
MAX_BINARIES = 16                     # binaries decompiled in one challenge (the rest are listed)
MAX_CONSTRUCTORS = 32                 # init_array / .ctors entries decompiled per binary
MAX_PDG_BYTES = 1 << 20              # pseudocode kept per function
DEFAULT_TIMEOUT = 300                 # seconds for one binary's whole decompile

# ----------------------------------------------------------------------------- magic / formats
_ELF = b"\x7fELF"
_PE = b"MZ"
_MACHO = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
          b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
_DOTNET_META = b"BSJB"                 # CLI metadata root signature (ECMA-335)


def classify(head: bytes) -> str | None:
    """The executable format of a file from its first bytes, or None when it is not one we decompile.

    Returns one of ``"elf"``, ``"pe"``, ``"macho"``.  ``.NET`` assemblies are PE files; :func:`is_dotnet`
    tells them apart.
    """
    if head[:4] == _ELF:
        return "elf"
    if head[:4] in _MACHO:
        return "macho"
    if head[:2] == _PE:
        return "pe"
    return None


def is_dotnet(data: bytes) -> bool:
    """True when a PE file carries a .NET/CLI metadata root (the ``BSJB`` signature).

    A heuristic that does not require a full PE parse: a managed assembly always contains the metadata
    root header, which native PEs do not.  Checked only after :func:`classify` says ``"pe"``.
    """
    return data[:2] == _PE and _DOTNET_META in data


# ----------------------------------------------------------------------------- ELF constructors
_SHT_INIT_ARRAY = 14
_SHT_PREINIT_ARRAY = 16


def init_array_targets(data: bytes) -> list[int]:
    """The virtual addresses in an ELF's ``.init_array`` / ``.preinit_array`` (its constructors).

    Parses the ELF section table directly (32/64-bit, little/big endian) and reads the pointer array,
    dropping null / ``~0`` sentinels.  Returns ``[]`` for a non-ELF, a truncated header, or no section.
    This never executes the binary; it only reads its bytes.
    """
    if data[:4] != _ELF or len(data) < 64:
        return []
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return []
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"
    try:
        if is64:
            e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 0x3A)
            ptr_sz, ptr_code = 8, "Q"
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 0x2E)
            ptr_sz, ptr_code = 4, "I"
    except struct.error:
        return []
    if not e_shoff or not e_shnum or e_shoff + e_shnum * e_shentsize > len(data):
        return []
    out: list[int] = []
    for i in range(min(e_shnum, 4096)):
        base = e_shoff + i * e_shentsize
        try:
            sh_type = struct.unpack_from(endian + "I", data, base + 4)[0]
            if is64:
                sh_addr, sh_offset, sh_size = struct.unpack_from(endian + "QQQ", data, base + 0x10)
            else:
                sh_addr, sh_offset, sh_size = struct.unpack_from(endian + "III", data, base + 0x0C)
        except struct.error:
            continue
        if sh_type not in (_SHT_INIT_ARRAY, _SHT_PREINIT_ARRAY):
            continue
        if sh_offset + sh_size > len(data) or sh_size % ptr_sz:
            continue
        for off in range(sh_offset, sh_offset + sh_size, ptr_sz):
            (val,) = struct.unpack_from(endian + ptr_code, data, off)
            mask = (1 << (ptr_sz * 8)) - 1
            if val and val != mask:
                out.append(val)
            if len(out) >= MAX_CONSTRUCTORS:
                return out
    return out


# ----------------------------------------------------------------------------- backends
class NoDecompiler(RuntimeError):
    """No installed decompiler fits a format.  Carries the named reason (the tools looked for)."""


@dataclass
class DecompileOutput:
    binary: str                        # path relative to the challenge folder
    fmt: str | None
    backend: str | None                # the decompiler used, or None when none ran
    functions: dict[str, str] = field(default_factory=dict)   # name -> file written (rel to challenge)
    note: str = ""
    pseudocode: str = ""               # all decompiled text joined, for the flag scan

    @property
    def ok(self) -> bool:
        return bool(self.functions)


def _resolve(*names: str) -> str | None:
    """The first of ``names`` on PATH or in the interpreter's bin folder, else None."""
    for n in names:
        if hit := shutil.which(n):
            return hit
        cand = Path(sys.executable).parent / n
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


# The sentinel must avoid r2's shell-like metacharacters (< > | ~ @ ; # &): `>` would redirect `?e`
# output to a file. `===...===` is echoed verbatim.
_SENTINEL = "===CTF-DECOMP-FN:%s==="
_SENTINEL_RE = re.compile(r"===CTF-DECOMP-FN:([^=]*)===")
_r2_pdg_cache: dict[str, bool] = {}


class R2GhidraBackend:
    """radare2 + r2ghidra (the ``pdg`` command).  Two static passes: ``aaa``+``aflj`` to discover
    functions, then ``aaa``+``pdg`` per target.  Never runs the binary (no ``-d``)."""

    name = "r2ghidra"
    formats = ("elf", "pe", "macho")

    def __init__(self, r2_bin: str | None = None):
        self.r2_bin = r2_bin or _resolve("radare2", "r2")

    def available(self) -> bool:
        if not self.r2_bin:
            return False
        if self.r2_bin not in _r2_pdg_cache:
            _r2_pdg_cache[self.r2_bin] = self._probe_pdg()
        return _r2_pdg_cache[self.r2_bin]

    def _probe_pdg(self) -> bool:
        try:
            p = subprocess.run([self.r2_bin, "-N", "-q", "-c", "pdg?", "--", os.devnull],
                               capture_output=True, timeout=30, text=True, errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return False
        return "pdg" in (p.stdout + p.stderr).lower() and "ghidra" in (p.stdout + p.stderr).lower()

    def _r2(self, binary: Path, commands: list[str], timeout: float) -> str:
        # Open the file for static analysis (no `-d`, so it is never executed). The path is made
        # absolute so it always starts with "/" and is never read as an r2 option.
        argv = [self.r2_bin, "-N", "-q", "-e", "scr.color=0"]
        for c in commands:
            argv += ["-c", c]
        argv.append(str(Path(binary).resolve()))
        p = subprocess.run(argv, capture_output=True, timeout=timeout, text=True, errors="replace",
                           stdin=subprocess.DEVNULL)
        return p.stdout

    def _functions(self, binary: Path, timeout: float) -> dict[str, int]:
        out = self._r2(binary, ["aaa", "aflj"], timeout)
        try:
            table = json.loads(out.strip().splitlines()[-1]) if out.strip() else []
        except (ValueError, IndexError):
            return {}
        names: dict[str, int] = {}
        for fn in table if isinstance(table, list) else []:
            if not isinstance(fn, dict) or not isinstance(fn.get("name"), str):
                continue
            addr = fn.get("offset", fn.get("addr"))   # r2 builds vary: "offset" (older) / "addr" (6.2+)
            if isinstance(addr, int):
                names[fn["name"]] = addr
        return names

    def decompile(self, binary: Path, fmt: str, data: bytes, timeout: float) -> list[tuple[str, str]]:
        """[(label, pseudocode)] for main, entry0 and each constructor that decompiled non-empty."""
        funcs = self._functions(binary, timeout)
        targets: list[tuple[str, int]] = []
        for label in ("main", "sym.main", "entry0", "entry.init0"):
            if label in funcs:
                targets.append((label.split(".")[-1] if label.startswith("sym.") else label, funcs[label]))
        chosen = {name for name, _ in targets}
        for va in init_array_targets(data):
            # map a constructor VA to the nearest function r2 found at that address
            name = next((n for n, off in funcs.items() if off == va), None)
            label = (name or f"ctor_{va:#x}")
            if label not in chosen:
                targets.append((label, va))
                chosen.add(label)
        if not targets:                 # nothing resolved: at least try the entry point by seek
            targets = [("entry0", 0)]
        cmds = ["aaa"]
        for label, off in targets:
            cmds.append(f"?e {_SENTINEL % label}")
            cmds.append(f"s {off:#x}" if off else "s entry0")
            cmds.append("pdg")
        blob = self._r2(binary, cmds, timeout)
        return _split_sentinels(blob)


class GhidraHeadlessBackend:
    """Ghidra ``analyzeHeadless`` with a one-shot DecompileScript.  Heavy; detected only."""

    name = "ghidra"
    formats = ("elf", "pe", "macho")

    def __init__(self, headless: str | None = None):
        self.headless = headless or _resolve("analyzeHeadless")

    def available(self) -> bool:
        return bool(self.headless)

    def decompile(self, binary: Path, fmt: str, data: bytes, timeout: float) -> list[tuple[str, str]]:
        # The headless path is detected and wired, but running a full Ghidra project at intake is not
        # exercised in the suite (no Ghidra on the build host). It is a documented human step.
        raise NoDecompiler("ghidra analyzeHeadless path is detect-only on this host (see build log)")


class IlspyBackend:
    """ILSpy command line for .NET assemblies."""

    name = "ilspycmd"
    formats = ("dotnet",)

    def __init__(self, ilspy: str | None = None):
        self.ilspy = ilspy or _resolve("ilspycmd")

    def available(self) -> bool:
        return bool(self.ilspy)

    def decompile(self, binary: Path, fmt: str, data: bytes, timeout: float) -> list[tuple[str, str]]:
        p = subprocess.run([self.ilspy, str(binary)], capture_output=True, timeout=timeout,
                           text=True, errors="replace", stdin=subprocess.DEVNULL)
        text = p.stdout
        if not text.strip():
            return []
        return [("assembly", text[:MAX_PDG_BYTES])]


def _split_sentinels(blob: str) -> list[tuple[str, str]]:
    """Split r2 stdout on the per-function sentinels into [(label, pseudocode)], dropping empties."""
    parts = _SENTINEL_RE.split(blob)
    out: list[tuple[str, str]] = []
    # parts = [pre, label1, body1, label2, body2, ...]
    for i in range(1, len(parts) - 1, 2):
        label, body = parts[i], parts[i + 1]
        code = body.strip()
        if code and "pdg" not in code.split("\n", 1)[0].lower():   # drop "command not found" noise
            out.append((label, code[:MAX_PDG_BYTES]))
    return out


def native_backends() -> list:
    return [R2GhidraBackend(), GhidraHeadlessBackend()]


def select_backend(fmt: str):
    """The first available backend for a format (``"elf"``/``"pe"``/``"macho"``/``"dotnet"``).

    Raises :class:`NoDecompiler` with the named tools when none is installed (no silent fallback).
    """
    if fmt == "dotnet":
        b = IlspyBackend()
        if b.available():
            return b
        raise NoDecompiler("no .NET decompiler: install ilspycmd (dotnet tool install -g ilspycmd)")
    backends = [b for b in native_backends() if fmt in b.formats]
    for b in backends:
        if b.available():
            return b
    raise NoDecompiler(
        f"no decompiler for {fmt}: install radare2 with the r2ghidra pdg plugin, or Ghidra "
        f"(analyzeHeadless on PATH)")


_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _safe(name: str) -> str:
    return _SAFE.sub("_", name)[:80] or "fn"


def decompile_file(path: Path, outdir: Path, *, timeout: float = DEFAULT_TIMEOUT,
                   challenge_dir: Path | None = None) -> DecompileOutput:
    """Classify, pick a backend and decompile one file into ``outdir``.

    Returns a :class:`DecompileOutput`: on success ``functions`` maps each decompiled label to the file
    written; on a missing backend ``note`` names what to install.  Reads at most :data:`MAX_FILE_BYTES`.
    """
    rel = str(path.relative_to(challenge_dir)) if challenge_dir else path.name
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        return DecompileOutput(rel, None, None, note=f"skipped: {size} bytes over the {MAX_FILE_BYTES} cap")
    data = path.read_bytes()
    fmt = classify(data[:HEAD_BYTES])
    if fmt is None:
        return DecompileOutput(rel, None, None, note="not a recognized executable")
    kind = "dotnet" if fmt == "pe" and is_dotnet(data) else fmt
    try:
        backend = select_backend(kind)
    except NoDecompiler as e:
        return DecompileOutput(rel, kind, None, note=str(e))
    try:
        blocks = backend.decompile(path, kind, data, timeout)
    except NoDecompiler as e:
        return DecompileOutput(rel, kind, backend.name, note=str(e))
    except subprocess.TimeoutExpired:
        return DecompileOutput(rel, kind, backend.name, note=f"{backend.name} timed out after {timeout:g}s")
    except OSError as e:
        return DecompileOutput(rel, kind, backend.name, note=f"{backend.name} failed to start: {e}")
    out = DecompileOutput(rel, kind, backend.name)
    if not blocks:
        out.note = f"{backend.name} produced no pseudocode (decompiler plugin missing or empty analysis)"
        return out
    outdir.mkdir(parents=True, exist_ok=True)
    texts = []
    for label, code in blocks:
        fname = f"{_safe(label)}.c"
        (outdir / fname).write_text(code, encoding="utf-8")
        wrote = str((outdir / fname).relative_to(challenge_dir)) if challenge_dir else fname
        out.functions[label] = wrote
        texts.append(code)
    out.pseudocode = "\n".join(texts)
    return out


# ----------------------------------------------------------------------------- B-054: bundle / NODE_SEA unpack
# A .NET single-file bundle (an apphost with its assemblies appended) and a Node single-executable
# (NODE_SEA) blob were unpacked by hand before. This step reuses the readers that already inflate a
# bundle's members in memory (binary/generic._bundle_children, via facts.dotnet_bundle) and read a
# SEA blob's main script (script-analysis/nodepkg.read_sea), writes those members under
# recon/unpack/<file>/, and queues every extracted *.NET assembly* for decompile_file (bounded depth:
# an extracted assembly is decompiled but never itself re-unpacked). ilspycmd is detected by
# IlspyBackend; when it is missing the extracted assembly's decompile is a loud `blocked` naming
# `dotnet tool install -g ilspycmd`, never a silent empty result.

SEA_MAGIC = bytes.fromhex("20da4301")     # NODE_SEA_BLOB marker (nodepkg.SEA_MAGIC; LE 0x0143da20)
MAX_UNPACK_MEMBERS = 256                  # members written out of one container
MAX_UNPACK_BYTES = 128 * 1024 * 1024      # total bytes written for one container
SEA_BUDGET = 8.0                          # seconds nodepkg may spend reading one SEA blob


def _sibling(rel_path: str, alias: str):
    """Load an engine-lane module by its exact file, never a flat ``import`` (``generic`` and others
    exist in more than one lane; the engine sys.path's first folder would win)."""
    from _shadowed import module_at
    return module_at(Path(__file__).resolve().parent.parent / rel_path, alias)


def _runtime_facts():
    return _sibling("binary/facts.py", "binary_facts")


def _binary_generic():
    return _sibling("binary/generic.py", "binary_generic")


def _nodepkg():
    return _sibling("script-analysis/nodepkg.py", "script_nodepkg")


def bundle_members(data: bytes) -> list[tuple[str, bytes]]:
    """``[(member_path, bytes)]`` of a .NET single-file bundle, the app's own assemblies (and any
    compressed member) inflated in memory, or ``[]`` when the file carries no bundle manifest.

    Delegates to :func:`facts.dotnet_bundle` (the manifest parse) and
    :func:`generic._bundle_children` (which inflates deflated members); this never executes anything.
    """
    facts = _runtime_facts()
    if facts.BUNDLE_SIG not in data or facts.dotnet_bundle(data) is None:
        return []
    gen = _binary_generic()
    out: list[tuple[str, bytes]] = []
    for how, body in gen._bundle_children(data):
        name = how.split("bundle:", 1)[1] if how.startswith("bundle:") else how
        out.append((name, body))
        if len(out) >= MAX_UNPACK_MEMBERS:
            break
    return out


def sea_members(data: bytes) -> list[tuple[str, bytes]]:
    """``[(name, bytes)]`` of a NODE_SEA blob's main script (and its embedded assets), or ``[]``.

    Delegates to :func:`nodepkg.read_sea`, which locates the blob (standalone or injected into a
    native host by postject) and returns its scripts as text.
    """
    if SEA_MAGIC not in data:
        return []
    np = _nodepkg()
    try:
        got = np.read_sea(bytes(data), np.Budget(SEA_BUDGET))
    except TimeoutError:
        return []
    if not got:
        return []
    mods, _notes = got
    out: list[tuple[str, bytes]] = []
    for path, text in mods:
        body = text.encode("utf-8", "replace") if isinstance(text, str) else bytes(text)
        out.append((path or "main", body))
        if len(out) >= MAX_UNPACK_MEMBERS:
            break
    return out


@dataclass
class UnpackOutput:
    container: str                      # path relative to the challenge folder
    kind: str | None                    # "dotnet_bundle" | "node_sea" | None
    members: dict[str, str] = field(default_factory=dict)   # member name -> file written (rel)
    assemblies: list[Path] = field(default_factory=list)    # extracted .NET assemblies, absolute
    text: str = ""                      # extracted member text joined, for the flag scan
    note: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.members)


def _safe_member(name: str) -> str:
    """A member's path made safe to write under ``outdir``: traversal (``..``), absolute and drive
    components are dropped, each remaining component sanitised. Never escapes the output folder."""
    parts: list[str] = []
    for comp in re.split(r"[\\/]+", name):
        comp = comp.strip()
        if comp in ("", ".", ".."):
            continue
        parts.append(_SAFE.sub("_", comp)[:120] or "_")
    return "/".join(parts[:16]) or "member"


def unpack_file(path: Path, out_root: Path, *, challenge_dir: Path | None = None) -> UnpackOutput:
    """Detect a .NET bundle / NODE_SEA container and write its members under ``out_root``.

    ``assemblies`` lists the extracted .NET assemblies (``.dll`` carrying a CLI metadata root) for the
    caller to decompile; ``members`` maps each member to the file written. A non-container file, or one
    over :data:`MAX_FILE_BYTES`, yields an empty :class:`UnpackOutput` (no ``kind``).
    """
    rel = str(path.relative_to(challenge_dir)) if challenge_dir else path.name
    if path.stat().st_size > MAX_FILE_BYTES:
        return UnpackOutput(rel, None, note=f"skipped: over the {MAX_FILE_BYTES} byte cap")
    data = path.read_bytes()
    members = bundle_members(data)
    kind = "dotnet_bundle" if members else None
    if not members:
        members = sea_members(data)
        kind = "node_sea" if members else None
    if not members:
        return UnpackOutput(rel, None)
    out = UnpackOutput(rel, kind)
    dest = out_root / _safe(rel.replace("/", "__"))
    total = 0
    texts: list[str] = []
    for name, body in members:
        total += len(body)
        if total > MAX_UNPACK_BYTES:
            out.note = f"unpack truncated at the {MAX_UNPACK_BYTES} byte cap"
            break
        target = dest / _safe_member(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        out.members[name] = str(target.relative_to(challenge_dir)) if challenge_dir else str(target)
        texts.append(body.decode("utf-8", "replace"))
        if kind == "dotnet_bundle" and name.lower().endswith(".dll") and is_dotnet(body):
            out.assemblies.append(target)
    out.text = "\n".join(texts)
    return out


# ----------------------------------------------------------------------------- intake entry
_SKIP_DIRS = {"recon", "unpacked"}     # intake's own output under the challenge folder


def _candidate_files(challenge_dir: Path) -> list[Path]:
    """Handout files that look like executables, under ``files/`` (and the folder root), newest-irrelevant
    deterministic order; intake's own ``recon/`` output is left out."""
    roots = [challenge_dir / "files", challenge_dir]
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not (here == challenge_dir and d in _SKIP_DIRS)
                                 and not (here / d).is_symlink())
            for n in sorted(filenames):
                f = here / n
                if f.is_symlink() or not f.is_file() or f.resolve() in seen:
                    continue
                try:
                    with open(f, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    continue
                if classify(head) is not None:
                    seen.add(f.resolve())
                    out.append(f)
    for f in _carved_files(challenge_dir):
        if f.resolve() not in seen:
            seen.add(f.resolve())
            out.append(f)
    return out


# B-135: programs the pull sweep carved from a disk image's free blocks (ctf/recover/extfs.CARVE_DIR) sit
# in the sweep's scratch copy, which is otherwise skipped (it repeats the handout). Only those folders.
_CARVE_DIRS = ("ext-unallocated",)


def _carved_files(challenge_dir: Path) -> list[Path]:
    root = challenge_dir / "unpacked"
    out: list[Path] = []
    if not root.is_dir() or root.is_symlink():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if not (here / d).is_symlink())
        if here.name not in _CARVE_DIRS:
            continue
        for n in sorted(filenames):
            f = here / n
            if f.is_symlink() or not f.is_file():
                continue
            try:
                with open(f, "rb") as fh:
                    head = fh.read(4)
            except OSError:
                continue
            if classify(head) is not None:
                out.append(f)
    return out


def _unpack_candidate_files(challenge_dir: Path) -> list[Path]:
    """Handout files that may be an unpack container: every native executable (a .NET bundle apphost
    or a postject-injected NODE_SEA host is one) plus any file whose first bytes are the standalone
    NODE_SEA magic. intake's own ``recon/`` output is left out."""
    roots = [challenge_dir / "files", challenge_dir]
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not (here == challenge_dir and d in _SKIP_DIRS)
                                 and not (here / d).is_symlink())
            for n in sorted(filenames):
                f = here / n
                if f.is_symlink() or not f.is_file() or f.resolve() in seen:
                    continue
                try:
                    with open(f, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    continue
                if classify(head) is not None or head == SEA_MAGIC:
                    seen.add(f.resolve())
                    out.append(f)
    return out


def solve(challenge_dir, profile, *, timeout: float = DEFAULT_TIMEOUT, **_opts):
    """Decompile every ELF/PE/Mach-O/.NET in the handout, unpack .NET bundles and NODE_SEA blobs, and
    decompile the extracted assemblies, into ``recon/`` — then report.

    First every native/.NET binary is decompiled to ``recon/decompile/`` (B-011). Then every .NET
    single-file bundle and NODE_SEA container is unpacked to ``recon/unpack/`` (B-054) and each
    extracted .NET assembly is decompiled too (bounded depth: an extracted assembly is not re-unpacked).

    ``candidate`` when a decompiled function or an unpacked script holds a string in the event flag
    format; ``blocked`` when there is work but no decompiler ran for any of it (notes name what to
    install, e.g. ``dotnet tool install -g ilspycmd``); ``none`` when nothing needed decompiling or it
    decompiled with no flag; ``unsure`` when some decompiled/unpacked and some could not.
    """
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    files = _candidate_files(challenge_dir)
    base = challenge_dir / "recon" / "decompile"
    outputs: list[DecompileOutput] = []
    listed = files[:MAX_BINARIES]
    for f in listed:
        outdir = base / _safe(str(f.relative_to(challenge_dir)).replace("/", "__"))
        outputs.append(decompile_file(f, outdir, timeout=timeout, challenge_dir=challenge_dir))
    overflow = len(files) - len(listed)

    # B-054: unpack .NET bundles and NODE_SEA blobs, then decompile each extracted .NET assembly.
    unpack_root = challenge_dir / "recon" / "unpack"
    unpacks: list[UnpackOutput] = []
    for f in _unpack_candidate_files(challenge_dir)[:MAX_BINARIES]:
        u = unpack_file(f, unpack_root, challenge_dir=challenge_dir)
        if u.kind:
            unpacks.append(u)
    for u in unpacks:
        for asm in u.assemblies[:MAX_BINARIES]:
            outdir = base / _safe(str(asm.relative_to(challenge_dir)).replace("/", "__"))
            outputs.append(decompile_file(asm, outdir, timeout=timeout, challenge_dir=challenge_dir))

    if not files and not unpacks:
        return SolverResult(status="none", engine="binary.decompile_intake",
                            notes="no ELF/PE/Mach-O/.NET binary or .NET-bundle/NODE_SEA container in the handout")

    evidence: list[Evidence] = []
    flags: list[str] = []
    for o in outputs:
        for label, wrote in o.functions.items():
            evidence.append(Evidence(kind="decompile",
                                     detail=f"{o.backend} decompiled {label} of {o.binary}", path=wrote))
        if o.pseudocode:
            for fl in ff.find_flags(o.pseudocode):
                if fl not in flags:
                    flags.append(fl)
    for u in unpacks:
        for name, wrote in u.members.items():
            evidence.append(Evidence(kind="unpack",
                                     detail=f"{u.kind} member {name} of {u.container}", path=wrote))
        if u.text:
            for fl in ff.find_flags(u.text):
                if fl not in flags:
                    flags.append(fl)

    decompiled = [o for o in outputs if o.ok]
    failed = [o for o in outputs if not o.ok]
    notes = []
    for o in failed:
        notes.append(f"{o.binary}: {o.note}")
    for u in unpacks:
        if u.note:
            notes.append(f"{u.container}: {u.note}")
    if overflow:
        notes.append(f"{overflow} more binary(ies) not decompiled (over MAX_BINARIES={MAX_BINARIES})")
    note = "; ".join(notes)
    unpacked_desc = [f"{u.container} ({u.kind}, {len(u.members)} member(s))" for u in unpacks]
    did = [o.binary for o in decompiled] + unpacked_desc

    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(evidence),
                            engine="binary.decompile_intake",
                            notes=("flag-format string(s) in decompiled pseudocode / unpacked scripts "
                                   "(static, unverified). " + note).strip())
    if decompiled and not failed:
        return SolverResult(status="none", evidence=tuple(evidence), engine="binary.decompile_intake",
                            notes=("decompiled/unpacked " + ", ".join(did)
                                   + " to recon/" + ("; " + note if note else "")))
    if decompiled and failed:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine="binary.decompile_intake",
                            notes=("decompiled/unpacked " + ", ".join(did)
                                   + "; could not decompile: " + note))
    if failed:
        # decompiling was needed but nothing decompiled: a loud blocked naming what to install
        # (e.g. `dotnet tool install -g ilspycmd`). Any members already unpacked are still on disk.
        unp = ("; unpacked " + ", ".join(unpacked_desc)) if unpacked_desc else ""
        return SolverResult(status="blocked", evidence=tuple(evidence), engine="binary.decompile_intake",
                            notes="no decompiler ran. " + note + unp)
    # nothing needed decompiling: only unpack ran (e.g. a NODE_SEA script), or there was nothing to do.
    return SolverResult(status="none", evidence=tuple(evidence), engine="binary.decompile_intake",
                        notes=(("unpacked " + ", ".join(unpacked_desc) + " to recon/unpack/"
                                + ("; " + note if note else "")) if unpacked_desc
                               else "nothing to decompile or unpack"))


if __name__ == "__main__":        # manual: python solvers/binary/decompile_intake.py <file> [<outdir>]
    f = Path(sys.argv[1])
    d = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd() / "decompile-out"
    r = decompile_file(f, d)
    print(json.dumps({"binary": r.binary, "format": r.fmt, "backend": r.backend,
                      "functions": r.functions, "note": r.note}, indent=2))
