#!/usr/bin/env python3
"""Mixer-inversion at intake (B-024).

Keygen / check binaries built on an integer *mixer* -- a bijective sequence of xor-shift, odd
multiply, add/xor and rotate steps (MurmurHash3's ``fmix64`` / ``fmix32``, SplitMix64's finalizer,
or a custom multiplier chain) -- hide a secret code by comparing ``mix(input)`` to a hard-coded
target.  Recovering the code by hand (invert the mixer, decode the pre-image bytes) was the whole
solve of csctf 9084-ground-lock.  This engine does it automatically:

  * **signature-match** the mixer by the multiplier constants that appear in the binary (as little
    endian immediates) or in the B-011 decompiled pseudocode;
  * **invert** each candidate target with z3 (a general bit-vector solver over the op chain), so a
    custom chain inverts without bespoke algebra;
  * **verify** every recovered pre-image by running the mixer *forward* in pure Python -- only a
    pre-image that reproduces the target is ever reported (no z3-translation can slip through);
  * **decode** consecutive pre-images whose bytes are all printable into the recovered code, and,
    when wrapping it in the event flag format yields a valid flag, report it as a ``candidate``.

z3 is required; it fails loudly (``blocked``) when z3 is absent.  The binary is only ever read as
bytes -- this engine never executes it.

Entry: ``solve(challenge_dir, profile) -> SolverResult`` (an intake ``run = "challenge"`` adapter).
Public helpers are importable for reuse: :func:`forward`, :func:`invert`, :func:`invert_analytic`,
:func:`identify`, :data:`KNOWN`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------- op model
# A mixer is an ordered list of reversible ops; each op is (kind, arg).  width is the bit width.
#   xorshr s : x ^= x >> s            xorshl s : x ^= x << s   (masked)
#   mul c    : x  = x * c   (c odd)   add c    : x  = x + c     sub c : x = x - c
#   xor c    : x ^= c                 rotl r / rotr r : rotate by r
OP_KINDS = ("xorshr", "xorshl", "mul", "add", "sub", "xor", "rotl", "rotr")


class MixerError(ValueError):
    pass


class Z3Unavailable(RuntimeError):
    """z3 is not installed; the inversion cannot run (no silent fallback)."""


def _mask(width: int) -> int:
    if width <= 0 or width % 8:
        raise MixerError(f"width must be a positive multiple of 8, got {width}")
    return (1 << width) - 1


def forward(ops, x: int, width: int = 64) -> int:
    """Run the mixer forward in pure Python (the independent verifier for every inversion)."""
    m = _mask(width)
    x &= m
    for kind, arg in ops:
        if kind == "xorshr":
            x ^= x >> arg
        elif kind == "xorshl":
            x ^= (x << arg) & m
        elif kind == "mul":
            x = (x * arg) & m
        elif kind == "add":
            x = (x + arg) & m
        elif kind == "sub":
            x = (x - arg) & m
        elif kind == "xor":
            x ^= arg
        elif kind == "rotl":
            r = arg % width
            x = ((x << r) | (x >> (width - r))) & m if r else x
        elif kind == "rotr":
            r = arg % width
            x = ((x >> r) | (x << (width - r))) & m if r else x
        else:
            raise MixerError(f"unknown op {kind!r}")
        x &= m
    return x


# --------------------------------------------------------------------------- analytic inverse (fast path)
def _unxorshr(y: int, s: int, width: int) -> int:
    """Invert ``y = x ^ (x >> s)`` (s > 0).

    Over GF(2) the step is ``(I + R_s)`` with ``R_s`` the right shift by s (nilpotent), so the inverse
    is the Neumann series ``I + R_s + R_s^2 + ...`` i.e. ``y ^ (y>>s) ^ (y>>2s) ^ ...``.
    """
    if s <= 0:
        raise MixerError("xorshr shift must be positive")
    x = y & _mask(width)
    sh = s
    while sh < width:
        x ^= y >> sh
        sh += s
    return x & _mask(width)


def _unxorshl(y: int, s: int, width: int) -> int:
    """Invert ``y = x ^ (x << s)`` (s > 0): the left-shift Neumann series ``y ^ (y<<s) ^ (y<<2s) ...``."""
    if s <= 0:
        raise MixerError("xorshl shift must be positive")
    m = _mask(width)
    x = y & m
    sh = s
    while sh < width:
        x ^= (y << sh) & m
        sh += s
    return x & m


def invert_analytic(ops, target: int, width: int = 64) -> int | None:
    """Invert a mixer with closed-form step inverses, or ``None`` when a step is not invertible.

    Fast enough to sweep a whole binary; every result it returns is still checked against
    :func:`forward` by the caller, so a wrong inverse is never reported.
    """
    m = _mask(width)
    x = target & m
    for kind, arg in reversed(list(ops)):
        if kind == "xorshr":
            x = _unxorshr(x, arg, width)
        elif kind == "xorshl":
            x = _unxorshl(x, arg, width)
        elif kind == "mul":
            if arg % 2 == 0:
                return None                      # even multiplier: not a bijection mod 2^width
            x = (x * pow(arg, -1, 1 << width)) & m
        elif kind == "add":
            x = (x - arg) & m
        elif kind == "sub":
            x = (x + arg) & m
        elif kind == "xor":
            x ^= arg
        elif kind == "rotl":
            r = arg % width
            x = ((x >> r) | (x << (width - r))) & m if r else x
        elif kind == "rotr":
            r = arg % width
            x = ((x << r) | (x >> (width - r))) & m if r else x
        else:
            raise MixerError(f"unknown op {kind!r}")
    return x if forward(ops, x, width) == (target & m) else None


# --------------------------------------------------------------------------- z3 inverse (general)
def _forward_z3(ops, bv, width: int):
    import z3
    x = bv
    for kind, arg in ops:
        if kind == "xorshr":
            x = x ^ z3.LShR(x, arg)
        elif kind == "xorshl":
            x = x ^ (x << arg)
        elif kind == "mul":
            x = x * arg
        elif kind == "add":
            x = x + arg
        elif kind == "sub":
            x = x - arg
        elif kind == "xor":
            x = x ^ arg
        elif kind == "rotl":
            x = z3.RotateLeft(x, arg % width)
        elif kind == "rotr":
            x = z3.RotateRight(x, arg % width)
        else:
            raise MixerError(f"unknown op {kind!r}")
    return x


def invert(ops, target: int, width: int = 64, *, limit: int = 4) -> list[int]:
    """All pre-images ``x`` with ``forward(ops, x, width) == target``, up to ``limit`` (z3).

    Raises :class:`Z3Unavailable` when z3 is not installed.  Each returned value is verified against
    :func:`forward`, so only genuine pre-images come back.
    """
    try:
        import z3
    except ImportError as e:                                   # no silent fallback
        raise Z3Unavailable("z3-solver is not installed (pip install z3-solver==5.1.0.0)") from e
    m = _mask(width)
    target &= m
    x = z3.BitVec("mixer_in", width)
    s = z3.Solver()
    s.add(_forward_z3(ops, x, width) == target)
    out: list[int] = []
    while len(out) < limit and s.check() == z3.sat:
        v = s.model()[x].as_long()
        if forward(ops, v, width) == target and v not in out:
            out.append(v)
        s.add(x != v)
    return out


# --------------------------------------------------------------------------- known mixers
@dataclass(frozen=True)
class Mixer:
    name: str
    width: int
    ops: tuple
    muls: tuple                                  # the identifying (odd) multiplier constants


KNOWN: tuple[Mixer, ...] = (
    Mixer("fmix64", 64,
          (("xorshr", 33), ("mul", 0xff51afd7ed558ccd), ("xorshr", 33),
           ("mul", 0xc4ceb9fe1a85ec53), ("xorshr", 33)),
          (0xff51afd7ed558ccd, 0xc4ceb9fe1a85ec53)),
    Mixer("fmix32", 32,
          (("xorshr", 16), ("mul", 0x85ebca6b), ("xorshr", 13),
           ("mul", 0xc2b2ae35), ("xorshr", 16)),
          (0x85ebca6b, 0xc2b2ae35)),
    Mixer("splitmix64", 64,
          (("xorshr", 30), ("mul", 0xbf58476d1ce4e5b9), ("xorshr", 27),
           ("mul", 0x94d049bb133111eb), ("xorshr", 31)),
          (0xbf58476d1ce4e5b9, 0x94d049bb133111eb)),
)


def identify(constants) -> list[Mixer]:
    """Known mixers all of whose multiplier constants appear in ``constants``."""
    cs = set(constants)
    return [mx for mx in KNOWN if all(c in cs for c in mx.muls)]


_HEX = re.compile(r"0x[0-9a-fA-F]+")
_DEC = re.compile(r"(?<![\w.])\d{10,}(?![\w.])")


def constants_in_text(text: str) -> set[int]:
    """Every integer literal (hex or long decimal) in decompiled pseudocode."""
    out: set[int] = set()
    for m in _HEX.finditer(text):
        out.add(int(m.group(0), 16))
    for m in _DEC.finditer(text):
        try:
            out.add(int(m.group(0)))
        except ValueError:
            pass
    return out


def mixers_in_bytes(data: bytes) -> list[Mixer]:
    """Known mixers whose multiplier constants appear as little-endian immediates in ``data``."""
    found = []
    for mx in KNOWN:
        wb = mx.width // 8
        if all(c.to_bytes(wb, "little") in data for c in mx.muls):
            found.append(mx)
    return found


# --------------------------------------------------------------------------- recovery
_PRINTABLE = frozenset(range(0x20, 0x7f))


def _printable(b: bytes) -> bool:
    return bool(b) and all(c in _PRINTABLE for c in b)


@dataclass(frozen=True)
class Recovery:
    mixer: str
    code: bytes                                  # concatenated printable pre-image bytes
    targets: tuple[int, ...]                      # the mixer outputs that were inverted, in order
    source: str                                  # "pseudocode" | "immediates"


def _ordered_values_in_text(text: str, width: int, exclude: set[int]) -> list[int]:
    """width-bit hex literals in appearance order, dropping the mixer's own constants and dups."""
    wb_max = (1 << width) - 1
    seen: set[int] = set()
    vals: list[int] = []
    for m in _HEX.finditer(text):
        v = int(m.group(0), 16)
        if v <= wb_max and v > 0xffff and v not in exclude and v not in seen:
            seen.add(v)
            vals.append(v)
    return vals


def recover_from_targets(targets, mixer: Mixer, source: str) -> list[Recovery]:
    """Invert an ordered list of targets; group maximal runs whose pre-images are all printable."""
    pre: list[tuple[int, bytes] | None] = []
    for t in targets:
        sols = invert(mixer.ops, t, mixer.width)
        chosen = None
        for v in sols:
            b = v.to_bytes(mixer.width // 8, "little")
            if _printable(b):
                chosen = (t, b)
                break
        pre.append(chosen)
    out: list[Recovery] = []
    run_bytes: list[bytes] = []
    run_targets: list[int] = []
    for item in pre + [None]:                     # trailing None flushes the last run
        if item is None:
            if run_bytes:
                out.append(Recovery(mixer.name, b"".join(run_bytes), tuple(run_targets), source))
                run_bytes, run_targets = [], []
        else:
            run_targets.append(item[0])
            run_bytes.append(item[1])
    return out


def recover_keytable(data: bytes, mixer: Mixer, *, max_scan: int = 8 << 20,
                     min_run: int = 2, max_code: int = 256) -> list[Recovery]:
    """Sweep ``data`` for consecutive qwords whose mixer pre-images are all printable (a keygen's
    target table).  Uses the fast analytic inverse; every recovered code is still forward-verified.
    """
    wb = mixer.width // 8
    data = data[:max_scan]
    n = len(data)
    # pre[i] = printable pre-image bytes of the qword at byte offset i, or None
    pre: dict[int, bytes] = {}

    def at(off: int):
        if off in pre:
            return pre[off]
        if off < 0 or off + wb > n:
            pre[off] = None
            return None
        t = int.from_bytes(data[off:off + wb], "little")
        x = invert_analytic(mixer.ops, t, mixer.width)
        b = x.to_bytes(wb, "little") if x is not None else b""
        pre[off] = b if _printable(b) else None
        return pre[off]

    out: list[Recovery] = []
    off = 0
    while off + wb <= n:
        if at(off) is None or at(off - wb) is not None:
            off += 1                              # not the start of a maximal printable run
            continue
        run_bytes: list[bytes] = []
        run_targets: list[int] = []
        cur = off
        while at(cur) is not None and len(run_bytes) * wb < max_code:
            run_bytes.append(at(cur))
            run_targets.append(int.from_bytes(data[cur:cur + wb], "little"))
            cur += wb
        if len(run_bytes) >= min_run:
            code = b"".join(run_bytes)
            if forward_run_ok(mixer, code, run_targets):
                out.append(Recovery(mixer.name, code, tuple(run_targets), "immediates"))
        off += 1
    return out


def forward_run_ok(mixer: Mixer, code: bytes, targets) -> bool:
    """Every ``width/8`` chunk of ``code`` mixes forward to the matching target."""
    wb = mixer.width // 8
    if len(code) != wb * len(targets):
        return False
    for i, t in enumerate(targets):
        q = int.from_bytes(code[i * wb:(i + 1) * wb], "little")
        if forward(mixer.ops, q, mixer.width) != t:
            return False
    return True


# --------------------------------------------------------------------------- intake engine
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_BINARIES = 8
_ELF = b"\x7fELF"


def _elf_files(challenge_dir: Path) -> list[Path]:
    out = []
    for p in sorted(challenge_dir.rglob("*")):
        if "recon" in p.parts:
            continue
        if not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            with p.open("rb") as fh:
                if fh.read(4) != _ELF:
                    continue
        except OSError:
            continue
        out.append(p)
        if len(out) >= MAX_BINARIES:
            break
    return out


def _pseudocode(challenge_dir: Path) -> str:
    base = challenge_dir / "recon" / "decompile"
    if not base.is_dir():
        return ""
    chunks = []
    for c in sorted(base.rglob("*.c")):
        try:
            chunks.append(c.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(chunks)


def solve(challenge_dir, profile, **_opts):
    """Signature-match a known mixer in the handout and invert its target(s) to recover the code.

    ``candidate`` when a recovered code wraps into a valid event flag or a flag-format string decodes;
    ``unsure`` when a printable code is recovered but is not in flag format; ``none`` when no mixer or
    no printable pre-image is found; ``blocked`` only when z3 is not installed.
    """
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    files = _elf_files(challenge_dir)
    text = _pseudocode(challenge_dir)

    # Which mixers are present, from decompiled constants and from raw immediates.
    text_consts = constants_in_text(text) if text else set()
    present: dict[str, Mixer] = {mx.name: mx for mx in identify(text_consts)}
    blobs: list[tuple[Path, bytes]] = []
    for f in files:
        try:
            data = f.read_bytes()
        except OSError:
            continue
        blobs.append((f, data))
        for mx in mixers_in_bytes(data):
            present.setdefault(mx.name, mx)

    if not present:
        return SolverResult(status="none", engine="binary.mixer_invert",
                            notes="no known integer mixer (fmix64/fmix32/splitmix64) signature found")

    recoveries: list[tuple[Recovery, Path | None]] = []
    z3_missing = ""
    for mx in present.values():
        # pseudocode targets (ordered, z3) -- the ground-lock path
        if text:
            vals = _ordered_values_in_text(text, mx.width, set(mx.muls))
            try:
                for r in recover_from_targets(vals, mx, "pseudocode"):
                    recoveries.append((r, None))
            except Z3Unavailable as e:
                z3_missing = str(e)
        # raw-immediate target table (analytic + forward-verify; needs no z3)
        for f, data in blobs:
            if mx in mixers_in_bytes(data):
                for r in recover_keytable(data, mx):
                    recoveries.append((r, f))

    # Dedupe by (mixer, code); prefer the longest codes first.
    seen: set[tuple[str, bytes]] = set()
    uniq: list[tuple[Recovery, Path | None]] = []
    for r, f in sorted(recoveries, key=lambda rp: -len(rp[0].code)):
        key = (r.mixer, r.code)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((r, f))

    if not uniq:
        names = ", ".join(sorted(present))
        if z3_missing:                            # a signature and pseudocode targets, but no z3
            return SolverResult(status="blocked", engine="binary.mixer_invert",
                                notes=f"{names} signature present but inversion is blocked: {z3_missing}")
        return SolverResult(status="none", engine="binary.mixer_invert",
                            notes=f"{names} signature(s) present but no target inverted to a printable code")

    flags: list[str] = []
    evidence: list[Evidence] = []
    notes: list[str] = []
    codes: list[str] = []
    for r, f in uniq:
        try:
            code_s = r.code.decode("ascii")
        except UnicodeDecodeError:
            continue
        codes.append(code_s)
        path = str(f.relative_to(challenge_dir)) if f is not None else None
        detail = (f"{r.mixer} inverted {len(r.targets)} target(s) -> {code_s!r} "
                  f"(verified forward == target)")
        evidence.append(Evidence(kind="match", detail=detail, path=path))
        # direct flag-format hit, then wrap in the event format.
        for fl in ff.find_flags(code_s):
            if fl not in flags:
                flags.append(fl)
        for pre in profile.flag.prefixes if getattr(profile, "flag", None) else ():
            wrapped = f"{pre}{{{code_s}}}"
            if ff.is_flag(wrapped) and wrapped not in flags:
                flags.append(wrapped)
                break
        notes.append(f"{r.mixer}: {code_s!r} from {r.source}")

    # Hand the recovered codes to binary.exec_grep: it runs the binary with each as argv and greps.
    if codes:
        try:
            out = challenge_dir / "recon" / "mixer"
            out.mkdir(parents=True, exist_ok=True)
            (out / "recovered.txt").write_text("\n".join(codes) + "\n", encoding="utf-8")
        except OSError:
            pass

    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(evidence),
                            engine="binary.mixer_invert",
                            notes="recovered code(s) inverted from mixer target(s): " + "; ".join(notes))
    return SolverResult(status="unsure", evidence=tuple(evidence), engine="binary.mixer_invert",
                        notes=("recovered printable pre-image(s), not in flag format "
                               "(try as the program's input / wrap by hand): " + "; ".join(notes)))


if __name__ == "__main__":            # manual: python mixer_invert.py <binary>
    import json
    import sys
    d = Path(sys.argv[1]).read_bytes()
    for mx in mixers_in_bytes(d):
        recs = recover_keytable(d, mx)
        print(json.dumps({"mixer": mx.name,
                          "codes": [r.code.decode("latin-1") for r in recs]}, indent=2))
