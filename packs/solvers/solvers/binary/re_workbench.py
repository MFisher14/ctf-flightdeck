"""Static-RE workbench toolkit (B-165): the setup work every static-RE racer rebuilt.

Inert helpers an agent imports. Nothing here executes, emulates, or decompiles a challenge
binary, and nothing touches the network: the capstone / lief wrappers only *read* bytes the
caller already extracted. Those wrappers import their library lazily and raise ``ToolUnavailable``
naming the missing package -- a missing tool fails loudly, never silently (repo rule 6).

Pieces (each is independently useful; an agent imports the one it needs):

  ApiHashNamer         resolve API-hash constants (ror13, djb2, djb2a, sdbm, fnv1a32, crc32) to
                       the symbol names a binary hid behind them. The generalised form (any width,
                       seed, trailing NUL) of toolkits/pe_emu.py's 32-bit catalog: its default word
                       list starts from pe_emu.COMMON_WINDOWS_APIS, and the suite cross-checks every
                       shared scheme against pe_emu.HASHERS so the two cannot drift.
  timelock_fastforward Rivest-Shamir-Wagner time lock ``x^(2^t) mod n``: t sequential squarings,
                       or an instant answer when the modulus factorisation (phi) is known
  force_environment    turn a binary's anti-analysis identity checks into the concrete environment
                       that satisfies them (environment-fingerprint forcing)
  AcceptedInputSearch  the standard find-the-accepted-input flow: decompose a validator into
                       per-position predicates, solve each, byte-prove the whole against the
                       caller's reimplementation
  disasm               thin capstone wrapper (bytes in, instructions out; never runs them)
  pe_export_names /     thin lief wrappers over a PE's export / import tables, to feed a specific
  pe_import_names       DLL's symbols into ApiHashNamer (input capped at MAX_PE_BYTES)

Bounded emulation is not here: toolkits/pe_emu.py (map_pe, find_compare_sites, SafeUnicorn with
denying API stubs and instruction/wall budgets) is the repo's fail-closed harness. Full Windows
process emulation is B-148.

This module is import-only (manifest class ``library``); ``ctf run`` refuses it on purpose.
"""
from __future__ import annotations

import math
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

try:  # flat import: the engine boot, tools/ctfpy and the test suite put solvers/toolkits on sys.path
    import pe_emu as _pe_emu
except ModuleNotFoundError:  # a bare run with only solvers/binary on sys.path: add the sibling lane
    sys.path.append(str(Path(__file__).resolve().parents[1] / "toolkits"))
    import pe_emu as _pe_emu

__all__ = [
    "ToolUnavailable",
    "WorkbenchError",
    "ApiHashNamer",
    "HASH_SCHEMES",
    "COMMON_WIN32_APIS",
    "TimeLockResult",
    "timelock_fastforward",
    "EnvConstraint",
    "ForcedEnvironment",
    "force_environment",
    "AcceptedInputSearch",
    "require_capstone",
    "require_lief",
    "disasm",
    "pe_export_names",
    "pe_import_names",
    "MAX_PE_BYTES",
]


class WorkbenchError(RuntimeError):
    """A workbench helper was called with input it cannot honour."""


class ToolUnavailable(WorkbenchError):
    """An optional analysis library (capstone / lief) is not importable.

    ``tool`` names the pip package the caller must install; the message says so. The wrappers
    never degrade to a weaker reader -- a missing tool is reported, not worked around.
    """

    def __init__(self, tool: str, reason: str = "not importable"):
        self.tool = tool
        super().__init__(f"{tool}: {reason}; install it into the venv to use this helper")


# =========================================================================== API-hash naming

def _mask(width: int) -> int:
    if width <= 0 or width % 8:
        raise WorkbenchError(f"hash width must be a positive multiple of 8, got {width}")
    return (1 << width) - 1


def _ror(value: int, bits: int, width: int) -> int:
    m = _mask(width)
    value &= m
    bits %= width
    return ((value >> bits) | (value << (width - bits))) & m


def _h_ror13(data: bytes, width: int, seed: int) -> int:
    m = _mask(width)
    h = seed & m
    for byte in data:
        h = _ror(h, 13, width)
        h = (h + byte) & m
    return h


def _h_djb2(data: bytes, width: int, seed: int) -> int:
    m = _mask(width)
    h = (seed or 5381) & m
    for byte in data:
        h = ((h * 33) + byte) & m
    return h


def _h_djb2a(data: bytes, width: int, seed: int) -> int:
    m = _mask(width)
    h = (seed or 5381) & m
    for byte in data:
        h = ((h * 33) ^ byte) & m
    return h


def _h_sdbm(data: bytes, width: int, seed: int) -> int:
    m = _mask(width)
    h = seed & m
    for byte in data:
        h = (byte + (h << 6) + (h << 16) - h) & m
    return h


def _h_fnv1a32(data: bytes, width: int, seed: int) -> int:
    if width != 32:
        raise WorkbenchError("fnv1a32 is defined for width 32 only")
    h = seed if seed else 2166136261
    for byte in data:
        h = ((h ^ byte) * 16777619) & _MASK32
    return h


def _h_crc32(data: bytes, width: int, seed: int) -> int:
    if width != 32:
        raise WorkbenchError("crc32 is defined for width 32 only")
    return zlib.crc32(data, seed) & _MASK32


_MASK32 = _mask(32)

# name -> (function, default width). Add more by handing ApiHashNamer a scheme callable.
HASH_SCHEMES: dict[str, tuple[Callable[[bytes, int, int], int], int]] = {
    "ror13": (_h_ror13, 32),
    "djb2": (_h_djb2, 32),
    "djb2a": (_h_djb2a, 32),
    "sdbm": (_h_sdbm, 32),
    "fnv1a32": (_h_fnv1a32, 32),
    "crc32": (_h_crc32, 32),
}

# The default word list: pe_emu's catalog (one source for the shared names), then the loader /
# injection / network APIs CTF loaders also hash that pe_emu's anti-debug-oriented list lacks. The
# caller extends it (or feeds pe_export_names of a specific DLL) via ApiHashNamer(names=...).
_EXTRA_WIN32_APIS: tuple[str, ...] = (
    "LoadLibraryExA", "GetModuleHandleA", "VirtualAlloc", "CreateThread",
    "CreateProcessA", "CreateProcessW", "WinExec", "ExitProcess", "ExitThread",
    "WriteProcessMemory", "ReadProcessMemory", "OpenProcess", "RegSetValueExA",
    "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "HttpSendRequestA", "URLDownloadToFileA",
    "WSAStartup", "socket", "connect", "send", "recv", "GetComputerNameA", "GetUserNameA",
    "GetTickCount",
)
COMMON_WIN32_APIS: tuple[str, ...] = tuple(dict.fromkeys(
    [name for _dll, name in _pe_emu.COMMON_WINDOWS_APIS] + list(_EXTRA_WIN32_APIS)
))


@dataclass
class ApiHashNamer:
    """Build a hash->name table for one hashing scheme and resolve constants a binary used.

    ``scheme`` is a key of HASH_SCHEMES or a callable ``fn(name_bytes, width, seed) -> int``.
    ``encoding``/``uppercase``/``include_terminator`` preprocess the symbol before hashing: many
    loaders uppercase the name and hash the trailing NUL, so those are tunable. ``build`` indexes a
    wordlist; ``resolve`` maps one constant back to the name (or None); ``resolve_all`` does a batch.
    A hash that two names collide on is reported, never silently dropped.
    """

    scheme: str | Callable[[bytes, int, int], int] = "ror13"
    width: int = 32
    seed: int = 0
    encoding: str = "ascii"
    uppercase: bool = False
    include_terminator: bool = False
    names: Iterable[str] = field(default_factory=tuple)
    _fn: Callable[[bytes, int, int], int] = field(init=False, repr=False)
    _table: dict[int, list[str]] = field(init=False, default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if callable(self.scheme):
            self._fn = self.scheme
        else:
            try:
                fn, default_width = HASH_SCHEMES[self.scheme]
            except KeyError:
                raise WorkbenchError(
                    f"unknown hash scheme {self.scheme!r}; known: {', '.join(sorted(HASH_SCHEMES))}"
                ) from None
            self._fn = fn
            if self.width is None:  # pragma: no cover - defensive
                self.width = default_width
        _mask(self.width)  # validate width early
        if self.names:
            self.build(self.names)

    def _encode(self, name: str) -> bytes:
        text = name.upper() if self.uppercase else name
        raw = text.encode(self.encoding)
        if self.include_terminator:
            raw += b"\x00"
        return raw

    def hash(self, name: str) -> int:
        """The constant this scheme produces for ``name`` (bytes-exact, deterministic)."""
        return self._fn(self._encode(name), self.width, self.seed) & _mask(self.width)

    def build(self, names: Iterable[str]) -> "ApiHashNamer":
        for name in names:
            self._table.setdefault(self.hash(name), [])
            bucket = self._table[self.hash(name)]
            if name not in bucket:
                bucket.append(name)
        return self

    def resolve(self, value: int) -> str | None:
        """The single name for ``value``; None if unknown; raises on a collision (ambiguous)."""
        bucket = self._table.get(value & _mask(self.width))
        if not bucket:
            return None
        if len(bucket) > 1:
            raise WorkbenchError(
                f"hash 0x{value:x} is ambiguous under {self._scheme_name()}: {', '.join(bucket)}"
            )
        return bucket[0]

    def candidates(self, value: int) -> list[str]:
        """Every name that hashes to ``value`` (empty if none); the collision-tolerant resolve."""
        return list(self._table.get(value & _mask(self.width), ()))

    def resolve_all(self, values: Iterable[int]) -> dict[int, list[str]]:
        return {v: self.candidates(v) for v in values}

    def _scheme_name(self) -> str:
        return self.scheme if isinstance(self.scheme, str) else getattr(self.scheme, "__name__", "custom")


# =========================================================================== time-lock puzzle

@dataclass(frozen=True)
class TimeLockResult:
    value: int
    method: str          # "fast-forward" (phi known) | "sequential"
    squarings: int       # how many modular squarings were actually performed


def timelock_fastforward(
    base: int,
    t: int,
    modulus: int,
    phi: int | None = None,
    *,
    max_sequential: int = 5_000_000,
) -> TimeLockResult:
    """Evaluate the RSW time-lock value ``base^(2^t) mod modulus``.

    With ``phi`` (Euler totient of ``modulus``) and ``gcd(base, modulus) == 1``, reduce the huge
    exponent ``2^t`` modulo ``phi`` and finish in one modpow -- the "fast-forward" that turns a
    minutes-long squaring chain into an instant answer. Without ``phi`` it does the honest ``t``
    sequential squarings, refusing past ``max_sequential`` so a hostile ``t`` cannot wedge the host
    (raise, naming the limit -- the caller supplies ``phi`` or raises the cap deliberately).
    """
    if modulus <= 1:
        raise WorkbenchError("modulus must be > 1")
    if t < 0:
        raise WorkbenchError("t must be >= 0")
    base %= modulus
    if phi is not None:
        if phi <= 0:
            raise WorkbenchError("phi must be positive")
        if math.gcd(base, modulus) != 1:
            raise WorkbenchError(
                "fast-forward needs gcd(base, modulus) == 1; base shares a factor with the modulus"
            )
        exponent = pow(2, t, phi)
        return TimeLockResult(pow(base, exponent, modulus), "fast-forward", 0)
    if t > max_sequential:
        raise WorkbenchError(
            f"t={t} exceeds max_sequential={max_sequential} and no phi was given; "
            "supply phi (the modulus factorisation) or raise max_sequential"
        )
    value = base
    for _ in range(t):
        value = (value * value) % modulus
    return TimeLockResult(value, "sequential", t)


# =========================================================================== env-fingerprint

_OPS = ("eq", "oneof", "ne", "prefix", "suffix", "contains")


@dataclass(frozen=True)
class EnvConstraint:
    """One identity check a binary makes on a named environment key.

    key: "username", "hostname", "domain", a registry path, a filename, "cpuid_vendor", ...
    op in eq | oneof | ne | prefix | suffix | contains; ``value`` is the operand (a tuple for oneof).
    """

    key: str
    op: str
    value: object

    def __post_init__(self) -> None:
        if self.op not in _OPS:
            raise WorkbenchError(f"unknown constraint op {self.op!r}; known: {', '.join(_OPS)}")
        if self.op == "oneof" and (not isinstance(self.value, (list, tuple)) or not self.value):
            raise WorkbenchError("oneof needs a non-empty list/tuple of allowed values")

    def satisfied_by(self, actual: str) -> bool:
        if self.op == "eq":
            return actual == self.value
        if self.op == "oneof":
            return actual in self.value
        if self.op == "ne":
            return actual != self.value
        if self.op == "prefix":
            return actual.startswith(self.value)  # type: ignore[arg-type]
        if self.op == "suffix":
            return actual.endswith(self.value)  # type: ignore[arg-type]
        return self.value in actual  # contains


@dataclass(frozen=True)
class ForcedEnvironment:
    environment: Mapping[str, str]
    satisfied: bool
    conflicts: tuple[str, ...]        # human-readable conflict descriptions, empty when satisfied


def force_environment(constraints: Sequence[EnvConstraint]) -> ForcedEnvironment:
    """Synthesize the environment that passes a binary's anti-analysis identity checks.

    Each key's constraints are combined into one concrete value: a positive ``eq``/``oneof`` pins
    it, affixes build it up, and ``ne`` steers away. Contradictory positives on one key (two
    different ``eq`` values) are reported as conflicts with ``satisfied=False`` -- the caller sees
    exactly which check it cannot satisfy rather than a plausible-looking wrong environment.
    """
    by_key: dict[str, list[EnvConstraint]] = {}
    for c in constraints:
        by_key.setdefault(c.key, []).append(c)

    env: dict[str, str] = {}
    conflicts: list[str] = []
    for key, items in by_key.items():
        value, problem = _solve_key(items)
        env[key] = value
        if problem:
            conflicts.append(f"{key}: {problem}")
    # Final check: every constraint must actually hold against the chosen value.
    unmet = [
        f"{c.key} {c.op} {c.value!r}"
        for c in constraints
        if not c.satisfied_by(env.get(c.key, ""))
    ]
    for u in unmet:
        if u not in conflicts:
            conflicts.append(u)
    return ForcedEnvironment(env, not conflicts, tuple(conflicts))


def _solve_key(items: Sequence[EnvConstraint]) -> tuple[str, str]:
    bans = {c.value for c in items if c.op == "ne"}
    pinned = {c.value for c in items if c.op == "eq"}
    if len(pinned) > 1:
        return str(next(iter(pinned))), f"contradictory eq values {sorted(map(str, pinned))}"
    if pinned:
        # an exact pin is the value; an ne / affix that disagrees is caught by the final check
        return str(next(iter(pinned))), ""
    oneof = [c for c in items if c.op == "oneof"]
    if oneof:
        allowed = set(oneof[0].value)  # type: ignore[arg-type]
        for c in oneof[1:]:
            allowed &= set(c.value)  # type: ignore[arg-type]
        if not allowed:
            return "", "oneof sets do not intersect"
        open_values = sorted(map(str, allowed - bans))
        if not open_values:
            every = sorted(map(str, allowed))
            return every[0], f"every allowed value {every} is excluded by ne"
        # prefer a value that also meets the key's affix checks; else the final check names the gap
        fits = [v for v in open_values if all(c.satisfied_by(v) for c in items)]
        return (fits or open_values)[0], ""
    problems: list[str] = []
    prefix, bad = _merge_affixes([str(c.value) for c in items if c.op == "prefix"], str.startswith)
    if bad:
        problems.append(f"prefixes {bad} disagree (no value starts with all of them)")
    suffix, bad = _merge_affixes([str(c.value) for c in items if c.op == "suffix"], str.endswith)
    if bad:
        problems.append(f"suffixes {bad} disagree (no value ends with all of them)")
    # every contains part goes in the middle; one already inside another part (or an affix) adds nothing
    parts = list(dict.fromkeys(str(c.value) for c in items if c.op == "contains"))
    kept = [p for p in parts
            if not any(p != q and p in q for q in parts) and p not in prefix and p not in suffix]
    contains = "".join(kept)
    base = f"{prefix}{contains}{suffix}" or "FORCED"
    # nothing pins the value exactly, so steer away from a banned value by growing it in the middle
    # (after the contains parts, before the suffix, so every affix still holds)
    guard = 0
    while base in bans and guard < 64:
        contains = f"{contains}_"
        base = f"{prefix}{contains}{suffix}"
        guard += 1
    return str(base), "; ".join(problems)


def _merge_affixes(values: list[str], extends: Callable[[str, str], bool]) -> tuple[str, list[str]]:
    """The one affix that satisfies every prefix (or suffix) check on a key: the longest, when each
    shorter one is a prefix (suffix) of it. Two that disagree ('ab' / 'ac') are a true conflict: the
    longest is returned with the sorted disagreeing values."""
    if not values:
        return "", []
    longest = max(values, key=len)
    clash = sorted({v for v in values if not extends(longest, v)})
    return longest, ([longest, *clash] if clash else [])


# =========================================================================== accepted input

@dataclass(frozen=True)
class AcceptedInput:
    data: bytes
    verified: bool               # the caller's full checker accepts ``data``
    underdetermined: tuple[int, ...] = ()   # positions with more than one solution (ambiguous)


class AcceptedInputSearch:
    """The standard find-the-accepted-input flow for static crackmes.

    ``AcceptedInputSearch(length, alphabet)`` fixes the input length and the byte alphabet. An agent
    reverses a validator, then uses one of two decompositions:

      solve_per_position(predicates, check=None): the validator splits into independent
        per-position predicates ``predicates[i](byte) -> bool`` (the common per-char / byte-compare
        shape). Each position is solved on its own; a position with no solution raises
        WorkbenchError, a position with several is reported in ``underdetermined``.

      hillclimb(score, check=None, filler=None): the validator exposes a separable integer score
        (more correct bytes -> higher). Greedy per-position maximisation recovers the input.

    Both return AcceptedInput; ``verified`` is True only when a ``check`` (the caller's full
    validator reimplementation) was given and accepts the data -- never on the search alone.
    ``verify(data, check)`` byte-proves any candidate the same way.
    """

    def __init__(self, length: int, alphabet: bytes | Sequence[int] = range(256)):
        if length <= 0:
            raise WorkbenchError("length must be > 0")
        self.length = length
        self.alphabet = bytes(alphabet)
        if not self.alphabet:
            raise WorkbenchError("alphabet must be non-empty")

    def solve_per_position(
        self,
        predicates: Sequence[Callable[[int], bool]],
        check: Callable[[bytes], bool] | None = None,
    ) -> AcceptedInput:
        if len(predicates) != self.length:
            raise WorkbenchError(f"need {self.length} predicates, got {len(predicates)}")
        chosen = bytearray(self.length)
        underdetermined: list[int] = []
        for i, pred in enumerate(predicates):
            sols = [b for b in self.alphabet if pred(b)]
            if not sols:
                raise WorkbenchError(f"position {i} has no byte in the alphabet that passes its check")
            chosen[i] = sols[0]
            if len(sols) > 1:
                underdetermined.append(i)
        data = bytes(chosen)
        verified = bool(check(data)) if check else False
        return AcceptedInput(data, verified, tuple(underdetermined))

    def hillclimb(
        self,
        score: Callable[[bytes], int],
        check: Callable[[bytes], bool] | None = None,
        filler: int | None = None,
    ) -> AcceptedInput:
        fill = self.alphabet[0] if filler is None else filler
        current = bytearray([fill]) * self.length
        for i in range(self.length):
            best_byte, best_score = current[i], score(bytes(current))
            for b in self.alphabet:
                current[i] = b
                s = score(bytes(current))
                if s > best_score:
                    best_byte, best_score = b, s
            current[i] = best_byte
        data = bytes(current)
        verified = bool(check(data)) if check else False
        return AcceptedInput(data, verified, ())

    @staticmethod
    def verify(data: bytes, check: Callable[[bytes], bool]) -> bool:
        """Byte-prove ``data`` against the caller's full validator reimplementation."""
        return bool(check(data))


# =========================================================================== capstone / lief

def require_capstone():
    try:
        import capstone  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001 - any import failure means the tool is unavailable
        raise ToolUnavailable("capstone", f"import {type(exc).__name__}: {exc}") from exc
    return capstone


def require_lief():
    try:
        import lief  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001 - any import failure means the tool is unavailable
        raise ToolUnavailable("lief", f"import {type(exc).__name__}: {exc}") from exc
    return lief


_ARCHES = {
    "x86": ("CS_ARCH_X86", "CS_MODE_32"),
    "x86_32": ("CS_ARCH_X86", "CS_MODE_32"),
    "x86_64": ("CS_ARCH_X86", "CS_MODE_64"),
    "amd64": ("CS_ARCH_X86", "CS_MODE_64"),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
    "thumb": ("CS_ARCH_ARM", "CS_MODE_THUMB"),
    "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "aarch64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "mips32": ("CS_ARCH_MIPS", "CS_MODE_MIPS32"),
    "mips64": ("CS_ARCH_MIPS", "CS_MODE_MIPS64"),
}


@dataclass(frozen=True)
class Insn:
    address: int
    mnemonic: str
    op_str: str
    size: int
    bytes: bytes


def disasm(code: bytes, arch: str = "x86_64", base: int = 0, count: int = 0) -> list[Insn]:
    """Disassemble ``code`` with capstone and return a list of Insn. Reads bytes; never runs them.

    ``arch`` is a key of the supported set (x86/x86_64/arm/thumb/arm64/mips...). ``base`` is the
    address of the first byte; ``count`` caps the number of instructions (0 = all).
    """
    capstone = require_capstone()
    try:
        arch_const, mode_const = _ARCHES[arch]
    except KeyError:
        raise WorkbenchError(
            f"unsupported arch {arch!r}; known: {', '.join(sorted(_ARCHES))}"
        ) from None
    md = capstone.Cs(getattr(capstone, arch_const), getattr(capstone, mode_const))
    out: list[Insn] = []
    for insn in md.disasm(bytes(code), base, count):
        out.append(Insn(insn.address, insn.mnemonic, insn.op_str, insn.size, bytes(insn.bytes)))
    return out


# lief parses untrusted bytes: cap the input like pe_emu does (one limit for both readers).
MAX_PE_BYTES = _pe_emu.MAX_FILE


def _parse_pe(data: bytes):
    if len(data) > MAX_PE_BYTES:
        raise WorkbenchError(
            f"PE input is {len(data)} bytes, over the {MAX_PE_BYTES}-byte cap (MAX_PE_BYTES)"
        )
    lief = require_lief()
    return lief.PE.parse(list(data))


def pe_export_names(data: bytes) -> list[str]:
    """Export-table symbol names of a PE given its raw bytes (lief). For feeding ApiHashNamer.

    Reads the container only; never maps or runs it. Raises WorkbenchError if ``data`` is not a PE
    or is over MAX_PE_BYTES.
    """
    binary = _parse_pe(data)
    if binary is None:
        raise WorkbenchError("not a PE image (lief could not parse it)")
    names: list[str] = []
    exp = getattr(binary, "get_export", None)
    export = exp() if callable(exp) else getattr(binary, "export", None)
    entries = getattr(export, "entries", ()) if export is not None else ()
    for entry in entries:
        name = getattr(entry, "name", "")
        if name:
            names.append(name)
    return names


def pe_import_names(data: bytes) -> list[str]:
    """Imported symbol names of a PE given its raw bytes (lief), ``library!symbol`` per entry."""
    binary = _parse_pe(data)
    if binary is None:
        raise WorkbenchError("not a PE image (lief could not parse it)")
    names: list[str] = []
    for lib in getattr(binary, "imports", ()):
        libname = getattr(lib, "name", "") or ""
        for entry in getattr(lib, "entries", ()):
            sym = getattr(entry, "name", "")
            if sym:
                names.append(f"{libname}!{sym}")
    return names
