#!/usr/bin/env python3
"""Logic-schematic netlist extractor and simulator for circuit-editor image exports (B-134).

It reads a circuit drawn as boxes and wires in a PNG, rebuilds the netlist, and sweeps gate kinds and
event-name inputs for a printable readout.

Some "stego" handouts are not pixel stego: the image is a logic circuit exported from an editor, and
the flag is what the circuit computes. PINK 27 was a Logigator export of 126 identical `?` boxes; the
solve was: rebuild the netlist, decide the unknown box is a NOR gate, feed the event name (with its
`+`) through the data lines one character at a time and read the output lamps at each selector state.
This module does the mechanical part and turns the two reasoning steps into a bounded sweep.

    extract(image)             image -> Extraction (netlist + geometry + issues). NotSchematic when the
                               image is not a circuit export, SchematicError when it is one this
                               vectorizer cannot read (the message names why).
    detect(image)              the same decision as a Detection record; never raises.
    Netlist, Gate              n-input gates, input devices in physical order (tied devices share a
                               net), the node each output device reads, in physical order.
    simulate(netlist, ...)     bit-parallel evaluation under a gate-kind assignment.
    transduce(netlist, ...)    feed a text through the data lines, one byte out per selector state.
    event_texts(profile)       the inputs to sweep: the event's brand as written in its profile name
                               (punctuation kept), its flag prefixes, case variants, the slug.
    sweep(netlist, texts, ...) every (gate kinds, selector/data split, selector schedule, bit order,
                               text) hypothesis; keeps the readings that are wholly printable ASCII.
    solve(challenge_dir, profile, **opts)   the engine contract.

Geometry read (measured on a Logigator export; nothing is assumed about colours or scale):
  * one dominant background colour, one ink colour (wires, outlines, junction squares, lamps), and
    optionally a third colour for the symbols inside boxes;
  * wires are axis-aligned ink lines on a square lattice; component outlines sit half a cell off it;
  * a component is a closed, rectangular outline with a symbol inside; a wire stub ending on its
    outline is a pin; the side with one pin is the output, the opposite side holds the inputs (for a
    one-input box the output side is the one with clipped corners);
  * three wire ends meeting join; four join only under a junction square (a plain crossing passes
    through); a lamp is a filled disc on a lattice point;
  * a net no component drives is an input, and whatever its wire ends on is its input device; a
    driven net's wire end is an output device. Devices are ordered left to right or top to bottom.

Status rules (docs/CONTRACTS.md section 7). The gate kind and the readout schedule are inferred, so
nothing here is ever `solved`:
  none       every image was looked at and none is a circuit export.
  unsure     a circuit export that could not be vectorized (the note names why); or an image that was
             not looked at (over a pixel cap, over the cap of MAX_IMAGES per challenge, not reached
             within the `seconds` CPU budget, unreadable, truncated or damaged, or in a folder that
             could not be listed: each is named); or a netlist with no printable reading;
             or printable readings that are not in the event flag format. Such a reading is a flag
             BODY: it is reported as text, never wrapped into the flag format, so intake never
             mistakes an inferred value for a found flag. `wrap=true` (an operator option, for a
             brief that says "wrap it yourself") returns the wrapped readings as `candidate`, best
             first.
  candidate  a reading that itself contains a flag in the event format.
  blocked    Pillow or numpy is missing.

A result that names no flag never prints text in the event flag format: intake scans an engine's
output for flags when its result has none, and a reading that holds `PREFIX{` could be closed into a
match by a later brace (the result JSON's own). When that would happen, every brace in the printed
result is spelled \\x7b / \\x7d; readings.json keeps the streams as read.

readings.json holds every printable reading of a circuit, best first (the result shows the first
MAX_READINGS). A file that could not be written is named, and the result then says the rest are not
on disk instead of pointing at it.

Not built (docs/build-log/B-134.md): distinctive-shape gate symbols (the curved AND/OR shapes of
Logisim's default style) are detected as a circuit canvas but not vectorized; pass a netlist you
extracted yourself with `netlist=<file.json>` (the to_dict() form) to use the simulator and sweep.
A canvas is told from other line art by its dot grid: dots at least DOT_MIN_PITCH wire widths apart,
on a quarter or more of the image's lattice points, across at least half of each side.

Nothing in an image is executed, nothing is uploaded, no editor is run and no program is started:
Pillow is told to open PNG, GIF, BMP and WebP only, so no file is handed to an external decoder. Only
regular files are opened: a named pipe, a socket or a device in the folder is named and passed over.
Only Pillow and numpy are imported, so the engine also runs under intake's Python-level hook guard.

    python -m ctf run toolkits.logic_schematic <challenge_dir> [--opt wrap=true] [--opt texts='["x"]']
    python solvers/toolkits/logic_schematic.py <image-or-netlist.json> [--event SLUG] [--wrap]
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import stat
import sys
import time
from dataclasses import dataclass, field, replace
from functools import cached_property
from pathlib import Path
from typing import Iterable, Mapping, Sequence

ENGINE = "toolkits.logic_schematic"

MAX_PIXELS = 64_000_000          # an image over this is refused by name, never decoded
MIN_SIDE = 48
MAX_RUNS = 8_000_000             # ink runs along the rows or the columns of one image; more is not line art
MAX_GATES = 5000
MAX_IMAGES = 8                   # images examined per challenge; the rest are named in the notes
MAX_TEXT = 64                    # characters of one input text
MAX_HYPOTHESES = 60_000          # transductions per sweep
MAX_READINGS = 12                # readings reported
DEFAULT_SECONDS = 40.0           # CPU seconds for one solve(): under intake's per-challenge engine budget
IMAGE_EXTS = (".png", ".gif", ".bmp", ".webp")
IMAGE_FORMATS = ("PNG", "GIF", "BMP", "WEBP")   # the decoders Pillow may use; none of them starts a program
KINDS = ("nor", "nand", "and", "or", "xor", "xnor")   # NOR/NAND first: one unknown box is a universal gate
SKIP_DIRS = {"recon", ".git"}


class SchematicError(ValueError):
    """A circuit export (or a netlist) that cannot be used; the message names the reason."""
    editor = "box-and-wire"      # what detect() calls a drawing that fails with this error


class NotSchematic(SchematicError):
    """The image is not a circuit-editor export."""


class Unexamined(SchematicError):
    """The image was not looked at (over a pixel cap, unreadable, truncated or damaged), so nothing is
    known about what it shows."""


class NoBoxes(SchematicError):
    """An editor canvas (a dot grid under line art) with no rectangular component box on it."""
    editor = "grid-canvas"


class ToolMissing(RuntimeError):
    """An imaging package this engine needs is not installed."""


def _imaging():
    try:
        import numpy as np
        from PIL import Image
    except ImportError as e:
        raise ToolMissing(f"cannot import {e.name or 'an imaging package'} ({e}): logic_schematic needs Pillow "
                          "and numpy") from e
    return np, Image


_cpu = time.process_time         # the budget clock: CPU time (wall-clock time says little on a loaded machine)


# ================================================================================== netlist model

@dataclass(frozen=True)
class Gate:
    """One component. `ins` name its input nodes (a gate id or an input device). `kind` is its Boolean
    operation when it is known; None means "unknown": gates that share a `symbol` (the glyph drawn in
    the box) share one kind in a sweep."""
    id: str
    ins: tuple[str, ...]
    kind: str | None = None
    symbol: int = 0

    def __post_init__(self):
        object.__setattr__(self, "ins", tuple(self.ins))


@dataclass(frozen=True)
class Netlist:
    """A combinational netlist.

    inputs    input devices in physical order.
    outputs   the node each output device reads, in physical order.
    ties      (device, earlier device) pairs: two input devices wired to one net. The net is named
              after the earlier device and carries the OR of its devices.
    floating  nets no gate and no device drives; they are held at 0 and reported.
    """
    gates: tuple[Gate, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    ties: tuple[tuple[str, str], ...] = ()
    floating: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "gates", tuple(self.gates))
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "outputs", tuple(self.outputs))
        object.__setattr__(self, "ties", tuple((str(a), str(b)) for a, b in self.ties))
        object.__setattr__(self, "floating", tuple(self.floating))
        self._validate()

    def _validate(self) -> None:
        if len(self.gates) > MAX_GATES:
            raise SchematicError(f"netlist has {len(self.gates)} gates (cap {MAX_GATES})")
        sources = list(self.inputs) + list(self.floating)
        names = [g.id for g in self.gates] + sources
        dup = sorted({n for n in names if names.count(n) > 1}) if len(set(names)) != len(names) else []
        if dup:
            raise SchematicError(f"node name used twice: {', '.join(dup[:5])}")
        known = set(names)
        order = {n: i for i, n in enumerate(self.inputs)}
        for dev, to in self.ties:
            if dev not in order or to not in order or order[to] >= order[dev]:
                raise SchematicError(f"tie {dev!r} -> {to!r} must join an input device to an earlier one")
        tied = {dev for dev, _ in self.ties}
        if len(tied) != len(self.ties):
            raise SchematicError("an input device is tied twice")
        for g in self.gates:
            if not g.ins:
                raise SchematicError(f"gate {g.id} has no input")
            if g.kind is not None and g.kind not in KINDS:
                raise SchematicError(f"gate {g.id} has unknown kind {g.kind!r} (known: {', '.join(KINDS)})")
            for ref in g.ins:
                if ref not in known:
                    raise SchematicError(f"gate {g.id} reads undefined node {ref!r}")
                if ref in tied:
                    raise SchematicError(f"gate {g.id} reads the tied device {ref!r}; name its net {self.root(ref)!r}")
        for o in self.outputs:
            if o not in known:
                raise SchematicError(f"output reads undefined node {o!r}")
        self.order  # raises on a combinational loop

    def root(self, device: str) -> str:
        """The net an input device drives: itself, or the earlier device it is tied to."""
        to = dict(self.ties)
        while device in to:
            device = to[device]
        return device

    @cached_property
    def independent(self) -> tuple[str, ...]:
        """Input devices that drive their own net (tied followers left out), in physical order."""
        tied = {dev for dev, _ in self.ties}
        return tuple(n for n in self.inputs if n not in tied)

    @cached_property
    def order(self) -> tuple[Gate, ...]:
        """Gates in evaluation order. SchematicError on a combinational loop."""
        gmap = {g.id: g for g in self.gates}
        done: dict[str, bool] = {}
        out: list[Gate] = []
        for start in self.gates:
            stack = [(start.id, iter(start.ins))]
            if start.id in done:
                continue
            done[start.id] = False
            while stack:
                node, it = stack[-1]
                for ref in it:
                    if ref not in gmap:
                        continue
                    if ref not in done:
                        done[ref] = False
                        stack.append((ref, iter(gmap[ref].ins)))
                        break
                    if done[ref] is False:
                        raise SchematicError(f"combinational loop through gate {ref}")
                else:
                    done[node] = True
                    out.append(gmap[node])
                    stack.pop()
        return tuple(out)

    @cached_property
    def symbols(self) -> tuple[int, ...]:
        """The symbol classes of the gates whose kind is unknown, ascending."""
        return tuple(sorted({g.symbol for g in self.gates if g.kind is None}))

    def to_dict(self) -> dict:
        d: dict = {
            "gates": [{"id": g.id, "ins": list(g.ins), **({"kind": g.kind} if g.kind else {}),
                       **({"symbol": g.symbol} if g.symbol else {})} for g in self.gates],
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
        }
        if self.ties:
            d["ties"] = [list(t) for t in self.ties]
        if self.floating:
            d["floating"] = list(self.floating)
        return d

    @classmethod
    def from_dict(cls, obj) -> "Netlist":
        """The to_dict() form. Anything else is a SchematicError naming the field."""
        if not isinstance(obj, Mapping):
            raise SchematicError("a netlist is a JSON object")
        extra = sorted(set(obj) - {"gates", "inputs", "outputs", "ties", "floating"})
        if extra:
            raise SchematicError(f"unknown netlist field: {', '.join(extra)}")
        for key in ("gates", "inputs", "outputs"):
            if not isinstance(obj.get(key), list):
                raise SchematicError(f"netlist field {key!r} must be a list")
        gates = []
        for raw in obj["gates"]:
            if not isinstance(raw, Mapping) or not isinstance(raw.get("id"), str) or not isinstance(raw.get("ins"), list):
                raise SchematicError("each gate is {\"id\": str, \"ins\": [str, ...], \"kind\"?: str, \"symbol\"?: int}")
            sym = raw.get("symbol", 0)
            if not isinstance(sym, int) or isinstance(sym, bool) or not all(isinstance(i, str) for i in raw["ins"]):
                raise SchematicError(f"gate {raw['id']}: ins are node names and symbol is an integer")
            gates.append(Gate(raw["id"], tuple(raw["ins"]), raw.get("kind"), sym))
        try:
            ties = [(a, b) for a, b in obj.get("ties", [])]
        except (TypeError, ValueError):
            raise SchematicError("netlist field 'ties' is a list of [device, earlier device] pairs") from None
        strs = [obj["inputs"], obj["outputs"], obj.get("floating", [])]
        if not all(isinstance(x, list) and all(isinstance(s, str) for s in x) for x in strs):
            raise SchematicError("inputs, outputs and floating are lists of node names")
        return cls(tuple(gates), tuple(obj["inputs"]), tuple(obj["outputs"]), tuple(ties), tuple(obj.get("floating", [])))


# ====================================================================================== simulator

def _apply(kind: str, vals: Sequence[int], mask: int) -> int:
    if kind in ("nor", "or"):
        acc = 0
        for v in vals:
            acc |= v
    elif kind in ("nand", "and"):
        acc = mask
        for v in vals:
            acc &= v
    elif kind in ("xor", "xnor"):
        acc = 0
        for v in vals:
            acc ^= v
    else:
        raise SchematicError(f"unknown gate kind {kind!r} (known: {', '.join(KINDS)})")
    return acc ^ mask if kind in ("nor", "nand", "xnor") else acc


def simulate(netlist: Netlist, assignment: Mapping[str, int], kinds, *, width: int = 1) -> dict[str, int]:
    """Every node's value for an input assignment.

    Bit-parallel: each value is an integer of `width` bits, bit t being the value under test vector t,
    so `width=1` is the plain single-vector case. `assignment` maps input devices to values (a missing
    device is 0; an unknown name is an error); tied devices are ORed onto their net. `kinds` is one
    kind for every gate, or {symbol: kind}; a gate's own `kind` wins. A gate left without a kind is a
    SchematicError.
    """
    mask = (1 << width) - 1
    unknown = sorted(set(assignment) - set(netlist.inputs))
    if unknown:
        raise SchematicError(f"not an input device: {', '.join(unknown[:5])}")
    values: dict[str, int] = {n: 0 for n in netlist.independent}
    values.update({n: 0 for n in netlist.floating})
    for dev, val in assignment.items():
        values[netlist.root(dev)] |= int(val) & mask
    uniform = kinds if isinstance(kinds, str) else None
    for g in netlist.order:
        kind = g.kind or uniform or (None if uniform is not None else kinds.get(g.symbol))
        if kind is None:
            raise SchematicError(f"gate {g.id} (symbol {g.symbol}) has no kind")
        values[g.id] = _apply(kind, [values[r] for r in g.ins], mask)
    return values


@dataclass(frozen=True)
class Readout:
    """How a transducer circuit is driven and read.

    selectors   input devices that pick which branch the outputs show.
    data        input devices that carry one character, data[0] first.
    states      the selector states read for each character, in order; a state gives selectors[k] its
                k-th bit.
    msb_first   data[0] takes the character's top bit (else its bottom bit).
    out_msb_first   outputs[0] is the top bit of the byte read (else the bottom bit).
    """
    selectors: tuple[str, ...]
    data: tuple[str, ...]
    states: tuple[tuple[int, ...], ...]
    msb_first: bool = True
    out_msb_first: bool = True

    def describe(self) -> str:
        sel = (f"selectors {','.join(self.selectors)} at {' '.join(''.join(map(str, s)) for s in self.states)}"
               if self.selectors else "no selector")
        return (f"{sel}; data {self.data[0]}..{self.data[-1]} {'MSB' if self.msb_first else 'LSB'} first; "
                f"outputs {'MSB' if self.out_msb_first else 'LSB'} first")


def transduce(netlist: Netlist, text: str, readout: Readout, kinds) -> list[int]:
    """Feed each character of `text` through the data lines at every selector state; one output value
    per (character, state), characters outermost. A character too wide for the data lines is a
    SchematicError."""
    if not readout.data or not readout.states:
        raise SchematicError("a readout needs data lines and at least one selector state")
    nbits, nstates = len(readout.data), len(readout.states)
    text = text[:MAX_TEXT]
    width = len(text) * nstates
    if not width:
        return []
    assign = {name: 0 for name in readout.data + readout.selectors}
    for ci, ch in enumerate(text):
        cp = ord(ch)
        if cp >> nbits:
            raise SchematicError(f"character {ch!r} does not fit {nbits} data lines")
        for si, state in enumerate(readout.states):
            t = ci * nstates + si
            for k, name in enumerate(readout.data):
                bit = (cp >> (nbits - 1 - k)) if readout.msb_first else (cp >> k)
                if bit & 1:
                    assign[name] |= 1 << t
            for name, bit in zip(readout.selectors, state):
                if bit:
                    assign[name] |= 1 << t
    values = simulate(netlist, assign, kinds, width=width)
    outs = [values[o] for o in netlist.outputs]
    if not readout.out_msb_first:
        outs.reverse()
    res = []
    for t in range(width):
        v = 0
        for o in outs:
            v = (v << 1) | ((o >> t) & 1)
        res.append(v)
    return res


# ============================================================================ inputs to sweep

_GENERIC = {"ctf", "the", "capture", "flag", "edition", "finals", "final", "quals", "qualifier", "qualifiers",
            "online", "event", "competition", "cup", "challenge"}


def event_texts(profile, extra: Iterable[str] = ()) -> list[str]:
    """The texts to feed a transducer, best first, read from the event profile (never hard-coded):
    `extra` (operator-given), the brand as the profile's name writes it, punctuation kept ("PINK+" of
    "PINK+ CTF 2026": the `+` carried the last three flag characters), the flag prefixes, lower- and
    upper-case forms, the name without its year, the full name, the slug."""
    out: list[str] = []

    def add(s) -> None:
        s = " ".join(str(s or "").split())
        if s and len(s) <= MAX_TEXT and s not in out:
            out.append(s)

    for s in extra:
        add(s)
    words = (getattr(profile, "name", "") or "").split()
    lead = list(itertools.takewhile(lambda w: w.lower() not in _GENERIC and not (w.isdigit() and len(w) == 4), words))
    brand = " ".join(lead)
    prefixes = list(getattr(getattr(profile, "flag", None), "prefixes", ()) or ())
    add(brand)
    if len(lead) > 1:
        add(lead[0])
    for p in prefixes:
        add(p)
    for s in [brand, *prefixes]:
        add(s.lower())
        add(s.upper())
    add(" ".join(w for w in words if not (w.isdigit() and len(w) == 4)))
    add(" ".join(words))
    slug = getattr(profile, "slug", "") or ""
    add(slug)
    add(slug.upper())
    return out


# ========================================================================================= sweep

@dataclass(frozen=True)
class Reading:
    """One hypothesis whose output is wholly printable ASCII."""
    stream: str
    text: str
    kinds: tuple[tuple[int, str], ...]     # (symbol, kind) for every unknown symbol; () when all kinds are known
    readout: Readout
    flags: tuple[str, ...] = ()            # event-format flags found in the stream itself
    rank: tuple = field(default=(), compare=False)

    def kinds_text(self) -> str:
        if not self.kinds:
            return "kinds as drawn"
        if len({k for _, k in self.kinds}) == 1:
            return f"every gate {self.kinds[0][1]}"
        return ", ".join(f"symbol {s} {k}" for s, k in self.kinds)

    def to_dict(self) -> dict:
        return {"stream": self.stream, "text": self.text, "kinds": {str(s): k for s, k in self.kinds},
                "selectors": list(self.readout.selectors), "data": list(self.readout.data),
                "states": ["".join(map(str, s)) for s in self.readout.states],
                "msb_first": self.readout.msb_first, "out_msb_first": self.readout.out_msb_first,
                "flags": list(self.flags)}


@dataclass(frozen=True)
class Sweep:
    readings: tuple[Reading, ...]          # distinct streams, best first
    tried: int                             # transductions run
    truncated: bool                        # the hypothesis cap stopped the sweep
    notes: tuple[str, ...] = ()


def kind_assignments(netlist: Netlist, kinds: Sequence[str] = KINDS) -> list[tuple[tuple[int, str], ...]]:
    """Kind assignments for the unknown symbols, best first: every symbol the same kind, then (for at
    most three symbols) every mixed assignment. [()] when no gate is unknown."""
    for k in kinds:
        if k not in KINDS:
            raise SchematicError(f"unknown gate kind {k!r} (known: {', '.join(KINDS)})")
    syms = netlist.symbols
    if not syms:
        return [()]
    out = [tuple((s, k) for s in syms) for k in kinds]
    if 1 < len(syms) <= 3:
        for combo in itertools.product(kinds, repeat=len(syms)):
            if len(set(combo)) > 1:
                out.append(tuple(zip(syms, combo)))
    return out


def input_splits(netlist: Netlist) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    """(selectors, data) splits of the input devices, best first: 0 to 3 leading or trailing devices as
    the selector, the rest as data, kept when the data lines are 7 or 8 independent nets and no tie
    crosses the split. A tied follower is dropped from the data lines (its leader carries the bit)."""
    devs = netlist.inputs
    tied = dict(netlist.ties)
    out = []
    for k in (2, 1, 3, 0):
        for lead in (True, False):
            if k == 0 and not lead:
                continue
            if k > len(devs):
                continue
            sel = devs[:k] if lead else devs[len(devs) - k:]
            rest = devs[k:] if lead else devs[:len(devs) - k]
            if any((d in sel) != (netlist.root(d) in sel) for d in tied):
                continue
            data = tuple(d for d in rest if d not in tied)
            sel = tuple(d for d in sel if d not in tied)
            if len(data) in (7, 8) and (sel, data) not in out:
                out.append((sel, data))
    return out


def selector_schedules(k: int) -> list[tuple[tuple[int, ...], ...]]:
    """Selector schedules for k selector lines, best first: the non-zero states counting up (the first
    line as the high bit, then as the low bit), counting down, every state counting up, each state
    alone."""
    if k == 0:
        return [((),)]
    msb = list(itertools.product((0, 1), repeat=k))
    lsb = [s[::-1] for s in msb]
    out: list[tuple[tuple[int, ...], ...]] = []
    for seq in (msb[1:], lsb[1:], msb[:0:-1], lsb[:0:-1], msb, lsb, *[[s] for s in msb]):
        t = tuple(seq)
        if t not in out:
            out.append(t)
    return out


def _printable(vals: Sequence[int]) -> bool:
    return bool(vals) and all(0x20 <= v <= 0x7E for v in vals)


def sweep(netlist: Netlist, texts: Sequence[str], *, flag_format=None, kinds: Sequence[str] = KINDS,
          max_hypotheses: int = MAX_HYPOTHESES, stop=None) -> Sweep:
    """Run every hypothesis and keep the wholly printable readings, one per distinct stream.

    Order (best first): a reading that holds an event-format flag; then by kind assignment
    (kind_assignments order), text (texts order), split, schedule, bit orders. A stream that only
    echoes its input or repeats one character is dropped: it says nothing about the circuit. A text
    with a character too wide for a split's data lines is not fed there, and the notes say so.
    `stop` (a function, true when the caller's time budget has run out) ends the sweep early, as the
    hypothesis cap does: `truncated`, with a note naming which.
    """
    notes: list[str] = []
    if not 1 <= len(netlist.outputs) <= 8:
        return Sweep((), 0, False, (f"{len(netlist.outputs)} output device(s): a byte readout needs 1 to 8",))
    splits = input_splits(netlist)
    if not splits:
        return Sweep((), 0, False, (f"{len(netlist.independent)} independent input(s): no split leaves 7 or 8 data "
                                    "lines beside 0 to 3 selector lines",))
    assigns = kind_assignments(netlist, kinds)
    if len(netlist.symbols) > 3:
        notes.append(f"{len(netlist.symbols)} box symbols: only one kind for all of them was tried")
    best: dict[str, Reading] = {}
    tried, truncated, echoes = 0, "", 0
    wide: dict[str, int] = {}                  # text -> the fewest data lines it did not fit
    for (ai, assign), (ti, text), (si, (sel, data)) in itertools.product(
            enumerate(assigns), enumerate(texts), enumerate(splits)):
        if any(ord(c) >> len(data) for c in text):
            wide[text] = min(len(data), wide.get(text, len(data)))
            continue
        kmap = dict(assign)
        for hi, states in enumerate(selector_schedules(len(sel))):
            for vi, (msb, omsb) in enumerate(((True, True), (False, True), (True, False), (False, False))):
                if tried >= max_hypotheses:
                    truncated = f"stopped at the cap of {max_hypotheses} hypotheses"
                    break
                if stop is not None and stop():
                    truncated = f"stopped by the time budget after {tried} hypotheses"
                    break
                tried += 1
                ro = Readout(sel, data, states, msb, omsb)
                vals = transduce(netlist, text, ro, kmap)
                if not _printable(vals):
                    continue
                stream = "".join(map(chr, vals))
                if stream == text[:MAX_TEXT] or (len(stream) > 1 and len(set(stream)) == 1):
                    echoes += 1
                    continue
                flags = tuple(flag_format.find_flags(stream)) if flag_format is not None else ()
                rank = (0 if flags else 1, ai, ti, si, hi, vi)
                if stream not in best or rank < best[stream].rank:
                    best[stream] = Reading(stream, text, assign, ro, flags, rank)
            if truncated:
                break
        if truncated:
            break
    if truncated:
        notes.append(truncated)
    if wide:
        first = next(iter(wide))
        notes.append(f"{len(wide)} text(s) hold a character too wide for the data lines of a split and were not "
                     f"fed there (first: {first!r} on {wide[first]} lines)")
    if echoes:
        notes.append(f"{echoes} printable reading(s) only echoed the input or repeated one character")
    return Sweep(tuple(sorted(best.values(), key=lambda r: r.rank)), tried, bool(truncated), tuple(notes))


# ============================================================================== image -> netlist

@dataclass(frozen=True)
class Detection:
    is_schematic: bool          # the image is a circuit-editor export
    supported: bool             # ... and its netlist was read
    editor: str                 # logigator-like | box-and-wire | grid-canvas | ""
    reason: str
    gates: int = 0
    pitch: float = 0.0


@dataclass(frozen=True)
class Extraction:
    netlist: Netlist
    editor: str
    pitch: float                               # lattice pitch in pixels
    origin: tuple[float, float]                # pixel centre of lattice point (0, 0)
    wire_width: int
    size: tuple[int, int]                      # image width, height
    gate_boxes: tuple[tuple[int, int, int, int], ...]   # interior box of each gate, netlist order
    input_at: tuple[tuple[int, int], ...]      # pixel of each input device's wire end
    output_at: tuple[tuple[int, int], ...]
    stats: Mapping[str, int]                   # pins, junctions, crossings, h_segments, v_segments, symbols, dots
    issues: tuple[str, ...]                    # things read with a caveat (floating nets, ...)

    def detection(self) -> Detection:
        return Detection(True, True, self.editor, f"{len(self.netlist.gates)} gates on a {self.pitch:g}px lattice",
                         len(self.netlist.gates), self.pitch)


def _load(path):
    """The image as an RGB array. Pillow may use the IMAGE_FORMATS decoders only: it picks a decoder
    by content, not by name, and some of its other decoders start a program (EPS runs Ghostscript)."""
    np, Image = _imaging()
    from PIL import UnidentifiedImageError
    Image.init()
    why = lambda e: f"{type(e).__name__}: {e}".replace(str(path), Path(path).name)   # Pillow quotes the whole path
    kinds = f"{', '.join(IMAGE_FORMATS[:-1])} or {IMAGE_FORMATS[-1]}"
    try:
        im = Image.open(path, formats=[f for f in IMAGE_FORMATS if f in Image.OPEN])
    except Image.DecompressionBombError as e:   # Pillow's own cap, hit inside open(): the header alone was read
        raise Unexamined(f"over Pillow's pixel limit, not decoded ({e})") from e
    except UnidentifiedImageError as e:
        # The file was read and no decoder took it. With an image signature in front it is an image
        # whose header is damaged, and what it shows is unknown; without one it is not an image.
        if _image_head(Path(path)):
            raise Unexamined(f"starts as an image but its header is damaged, not decoded ({why(e)})") from e
        raise NotSchematic(f"not a readable {kinds} image ({why(e)})") from e
    except OSError as e:                        # no permission, gone, a folder: nothing of it was read
        raise Unexamined(f"the file could not be read ({why(e)})") from e
    except Exception as e:                      # a decoder that fails in a way of its own on the header
        raise Unexamined(f"the image header could not be read ({why(e)})") from e
    with im:
        w, h = im.size
        if w * h > MAX_PIXELS:
            raise Unexamined(f"image is {w}x{h}: over the {MAX_PIXELS}-pixel cap, not decoded")
        if min(w, h) < MIN_SIDE:
            raise NotSchematic(f"image is {w}x{h}: too small to hold a circuit")
        try:
            return np.asarray(im.convert("RGB"))
        except Exception as e:                 # Pillow raises many types on truncated or damaged pixel data
            raise Unexamined(f"a {im.format} image whose pixel data is truncated or damaged, not decoded in full "
                             f"({why(e)}): repair the file and run again") from e


def _palette(a):
    """(background, ink, symbol colour or None) as RGB triples, from a subsample. NotSchematic for an
    image without one dominant flat background and one line colour."""
    np, _ = _imaging()
    step = max(1, int((a.shape[0] * a.shape[1] / 1_500_000) ** 0.5))
    s = a[::step, ::step].reshape(-1, 3).astype(np.int64)
    key = (s[:, 0] << 16) | (s[:, 1] << 8) | s[:, 2]
    vals, counts = np.unique(key, return_counts=True)
    rgb = np.stack([(vals >> 16) & 255, (vals >> 8) & 255, vals & 255], axis=1)
    bg_i = int(counts.argmax())
    bg = rgb[bg_i]
    d_bg = np.abs(rgb - bg).sum(axis=1)
    near_bg = int(counts[d_bg <= 24].sum())
    if near_bg < 0.5 * counts.sum():
        raise NotSchematic(f"no flat background ({near_bg / counts.sum():.0%} of pixels near the commonest colour)")
    far = d_bg >= 60
    if not far.any() or counts[far].sum() < 0.001 * counts.sum():
        raise NotSchematic("no line art on the background")

    def pure(members):
        """The colour of a family (colours that are blends of the background with one colour): the
        commonest member names the direction; the pure colour is the member farthest along it that
        is still common. On thin anti-aliased strokes a blend can be commoner than the colour itself."""
        idx = np.flatnonzero(members)
        seed = idx[counts[idx].argmax()]
        ray = (rgb[seed] - bg).astype(float)
        t = ((rgb[idx] - bg) @ ray) / float(ray @ ray)
        off = np.abs(rgb[idx] - (bg + t[:, None] * ray)).sum(axis=1)
        fam = idx[(t > 0) & (off <= 30) & (counts[idx] >= 0.1 * counts[seed])]
        return rgb[fam[d_bg[fam].argmax()]]

    ink = pure(far)
    # A symbol colour is far from the background, from the ink and from every blend of the two
    # (anti-aliased line edges are blends, not a third colour).
    seg = (ink - bg).astype(float)
    t = np.clip(((rgb - bg) @ seg) / max(1.0, float(seg @ seg)), 0, 1)
    off_line = np.abs(rgb - (bg + t[:, None] * seg)).sum(axis=1)
    third = far & (np.abs(rgb - ink).sum(axis=1) >= 60) & (off_line >= 45)
    sym = None
    if third.any() and counts[third].sum() >= 0.002 * counts[far].sum():
        sym = pure(third)
    return bg, ink, sym


def _masks(a, bg, ink, sym):
    """(ink mask, symbol mask). An anti-aliased pixel is a blend of the background with the ink or
    with the symbol colour: it goes to the blend it lies on, and counts when it is at least half
    way (so a grey edge of a white symbol is never read as ink)."""
    np, _ = _imaging()
    h, w = a.shape[:2]
    ink_m = np.zeros((h, w), bool)
    sym_m = np.zeros((h, w), bool)
    bgv = bg.astype(np.int16)
    v_i = (ink - bg).astype(np.float32)
    v_s = None if sym is None else (sym - bg).astype(np.float32)
    for y in range(0, h, 1024):
        blk = a[y:y + 1024]
        nz = np.abs(blk.astype(np.int16) - bgv).sum(axis=2) > 24
        if not nz.any():
            continue
        px = blk[nz].astype(np.float32) - bg.astype(np.float32)
        t_i = px @ v_i / float(v_i @ v_i)
        if v_s is None:
            is_ink = t_i >= 0.5
        else:
            t_s = px @ v_s / float(v_s @ v_s)
            d_i = np.abs(px - np.clip(t_i, 0, 1)[:, None] * v_i).sum(axis=1)
            d_s = np.abs(px - np.clip(t_s, 0, 1)[:, None] * v_s).sum(axis=1)
            is_ink = (d_i <= d_s) & (t_i >= 0.5)
            sym_m[y:y + 1024][nz] = (d_i > d_s) & (t_s >= 0.5)
        ink_m[y:y + 1024][nz] = is_ink
    return ink_m, sym_m


def _runs(m):
    """The True runs along the rows of a 2-D mask, in raster order: (row, start, end) arrays, `end`
    exclusive. NotSchematic over MAX_RUNS runs (the arrays built from them would not fit in memory)."""
    np, _ = _imaging()
    h, w = m.shape
    pad = np.zeros((h, w + 2), np.int8)          # a False column each side, so no run crosses a row end
    pad[:, 1:-1] = m
    d = np.diff(pad.ravel())
    start = np.flatnonzero(d == 1)               # d[i] = pad[i + 1] - pad[i]: pad column c + 1 is mask column c
    if start.size > MAX_RUNS:
        raise NotSchematic(f"too fragmented to be a circuit drawing (over {MAX_RUNS} runs of ink)")
    end = np.flatnonzero(d == -1)
    row = start // (w + 2)
    return row, start - row * (w + 2), end - row * (w + 2)


def _wire_width(ink) -> int:
    """The stroke width: the commonest run length across sampled rows and columns."""
    np, _ = _imaging()
    lengths = []
    for m in (ink[::max(1, ink.shape[0] // 500)], ink[:, ::max(1, ink.shape[1] // 500)].T):
        _, start, end = _runs(m)
        lengths.append(end - start)
    r = np.concatenate(lengths)
    if r.size < 16:
        raise NotSchematic("too little line art")
    return int(np.bincount(np.minimum(r, 4096)).argmax())


def _long_runs(runs, shape, length: int):
    """The mask (of `shape`) of the pixels lying in one of `runs` (from _runs) that is at least `length`
    pixels long. `length` is made odd, as the centred window of a 1-D opening is."""
    np, _ = _imaging()
    row, start, end = runs
    keep = end - start >= (length | 1)
    step = np.zeros(shape[0] * shape[1] + 1, np.int8)        # +1 where a kept run starts, -1 just after it ends
    base = row[keep] * shape[1]
    step[base + start[keep]] += 1
    step[base + end[keep]] -= 1
    return np.cumsum(step[:-1], dtype=np.int8).reshape(shape).astype(bool)


def _long_share(runs, n: int, length: int):
    """For each of n rows: how many of its pixels lie in a run at least `length` (made odd) long."""
    np, _ = _imaging()
    row, start, end = runs
    keep = end - start >= (length | 1)
    return np.bincount(row[keep], weights=(end - start)[keep], minlength=n).astype(np.int64)


def _components(n: int, a, b):
    """The root of each node 0..n-1 of a graph with edges (a[i], b[i]): the smallest node of its
    connected component. A union-find without a Python loop over the edges: every root is hooked
    under the smallest root an edge joins it to, every path is shortened to its root, and the edges
    inside one tree are dropped, until none is left."""
    np, _ = _imaging()
    parent = np.arange(n)
    while a.size:
        ra, rb = parent[a], parent[b]
        cross = ra != rb
        if not cross.any():
            break
        a, b, ra, rb = a[cross], b[cross], ra[cross], rb[cross]
        np.minimum.at(parent, np.maximum(ra, rb), np.minimum(ra, rb))
        while True:
            up = parent[parent]
            if np.array_equal(up, parent):
                break
            parent = up
    return parent


class _Regions:
    """The connected regions of a mask (4-connected; 8-connected with `diagonal`), numbered from 1 in
    raster order of their first pixel. They are held as runs, so no label image is built.

    n            number of regions
    area[i]      pixels of region i          (index 0 is unused in every per-region array)
    y0, y1, x0, x1   its bounding box, end-exclusive
    """

    def __init__(self, mask, diagonal: bool = False):
        np, _ = _imaging()
        h, w = mask.shape
        self.shape = (h, w)
        self.row, self.start, self.end = row, start, end = _runs(mask)
        # runs as intervals on one line: rows are w + 2 apart there, so a run meets only runs of its
        # own row, and a run moved up one row overlaps exactly the runs it touches in the row above
        gs, ge = row * (w + 2) + start, row * (w + 2) + end
        reach = 1 if diagonal else 0
        first = np.searchsorted(ge, gs - (w + 2) - reach, side="right")
        count = np.maximum(np.searchsorted(gs, ge - (w + 2) + reach, side="left") - first, 0)
        below = np.repeat(np.arange(row.size), count)
        above = np.arange(int(count.sum())) - np.repeat(np.cumsum(count) - count, count) + np.repeat(first, count)
        roots, label = np.unique(_components(row.size, above, below), return_inverse=True)
        self.n = int(roots.size)
        self.label = label = label + 1                       # of each run
        k = self.n + 1
        self.area = np.bincount(label, weights=end - start, minlength=k).astype(np.int64)
        self.y0, self.x0 = np.full(k, h), np.full(k, w)
        self.y1, self.x1 = np.zeros(k, np.int64), np.zeros(k, np.int64)
        np.minimum.at(self.y0, label, row)
        np.minimum.at(self.x0, label, start)
        np.maximum.at(self.y1, label, row + 1)
        np.maximum.at(self.x1, label, end)
        self._by_label = np.argsort(label, kind="stable")
        self._at = np.searchsorted(label[self._by_label], np.arange(k + 1))

    def on_border(self):
        """Per region (index 0 unused): it touches the edge of the mask."""
        np, _ = _imaging()
        h, w = self.shape
        out = np.zeros(self.n + 1, bool)
        out[self.label[(self.row == 0) | (self.row == h - 1) | (self.start == 0) | (self.end == w)]] = True
        return out

    def crop(self, i: int):
        """Region i as a boolean array over its bounding box."""
        np, _ = _imaging()
        y0, x0 = int(self.y0[i]), int(self.x0[i])
        out = np.zeros((int(self.y1[i]) - y0, int(self.x1[i]) - x0), bool)
        for j in self._by_label[self._at[i]:self._at[i + 1]]:
            out[self.row[j] - y0, self.start[j] - x0:self.end[j] - x0] = True
        return out


@dataclass
class _Box:
    x0: int
    y0: int
    x1: int
    y1: int                      # interior, end-exclusive
    clipped: tuple               # (NW, NE, SW, SE) corner is cut off
    glyph: object                # 12x12 float signature of the symbol
    symbol: int = 0

    def edges(self):             # interior edges, as pixel-centre coordinates: left, right, top, bottom
        return (self.x0 - 0.5, self.x1 - 0.5, self.y0 - 0.5, self.y1 - 0.5)


def _find_boxes(ink, sym_m, w):
    """Box candidates: enclosed, rectangular background regions with a symbol inside. A region between
    wires can pass too (a label inside a wire loop); the lattice fit drops those, because wires run
    half a cell off every component outline."""
    np, Image = _imaging()
    reg = _Regions(~ink)
    heights, widths = reg.y1 - reg.y0, reg.x1 - reg.x0
    lo = max(12, 5 * w)
    enclosed = ~reg.on_border() & (heights >= lo) & (widths >= lo) & (reg.area >= 0.85 * heights * widths)
    boxes = []
    for i in np.flatnonzero(enclosed).tolist():
        bh, bw = int(heights[i]), int(widths[i])
        sl = (slice(int(reg.y0[i]), int(reg.y1[i])), slice(int(reg.x0[i]), int(reg.x1[i])))
        # the symbol: symbol-coloured pixels in the box, or (one-colour drawings) ink islands inside
        # it that are bigger than a grid dot. Either way it is smaller than the box.
        glyph = sym_m[sl].copy()
        isl = _Regions(ink[sl], diagonal=True)               # a small glyph's strokes touch diagonally
        for j in range(1, isl.n + 1):
            touches = isl.y0[j] == 0 or isl.x0[j] == 0 or isl.y1[j] == bh or isl.x1[j] == bw
            if not touches and max(isl.y1[j] - isl.y0[j], isl.x1[j] - isl.x0[j]) > 2 * w:
                glyph[isl.y0[j]:isl.y1[j], isl.x0[j]:isl.x1[j]] |= isl.crop(j)
        if int(glyph.sum()) < max(4, w * w):
            continue
        gy, gx = np.nonzero(glyph)
        if gy.max() - gy.min() + 1 > 0.85 * bh or gx.max() - gx.min() + 1 > 0.85 * bw:
            continue
        region = reg.crop(i)
        c = max(2, w)
        clipped = tuple(float(region[ys, xs].mean()) < 0.5 for ys, xs in (
            (slice(0, c), slice(0, c)), (slice(0, c), slice(bw - c, bw)),
            (slice(bh - c, bh), slice(0, c)), (slice(bh - c, bh), slice(bw - c, bw))))
        crop = glyph[gy.min():gy.max() + 1, gx.min():gx.max() + 1].astype(np.uint8) * 255
        sig = np.asarray(Image.fromarray(crop).resize((12, 12), Image.BILINEAR), dtype=float) / 255.0
        boxes.append(_Box(sl[1].start, sl[0].start, sl[1].stop, sl[0].stop, clipped, sig))
    return boxes


def _classify_symbols(boxes) -> int:
    """Number the boxes' symbols: two boxes share a class when their glyphs agree up to rendering
    jitter. Returns the number of classes."""
    np, _ = _imaging()
    reps: list = []
    for b in boxes:
        for k, rep in enumerate(reps):
            if float(np.abs(rep - b.glyph).mean()) <= 0.18:
                b.symbol = k
                break
        else:
            b.symbol = len(reps)
            reps.append(b.glyph)
    return len(reps)


def _bands(weights):
    """(centre, weight, thickness) of each run of consecutive non-zero entries of a 1-D profile."""
    np, _ = _imaging()
    nz = np.flatnonzero(weights)
    out = []
    if nz.size:
        for grp in np.split(nz, np.flatnonzero(np.diff(nz) > 1) + 1):
            wt = weights[grp].astype(float)
            out.append((float((grp * wt).sum() / wt.sum()), float(wt.sum()), int(grp.size)))
    return out


def _fit(coords_x, coords_y, p0, slack=0.03):
    """A square lattice through two coordinate sets (each on its own phase): (pitch, phase x, phase y),
    given a first pitch good to `slack`. Fitted outward from the middle: the coordinates near enough
    that the pitch error drifts under a quarter cell give the phase (a circular mean, so a few
    coordinates off the lattice do not move it) and a least-squares pitch over the ones within a fifth
    of a cell of that phase; then the radius grows fourfold until it holds every coordinate."""
    np, _ = _imaging()
    cx, cy = np.asarray(coords_x, float), np.asarray(coords_y, float)
    phase = lambda c, p: float(np.angle(np.exp(2j * np.pi * c / p).sum()) / (2 * np.pi) * p) % p if c.size else 0.0
    mid = [float(np.median(c)) if c.size else 0.0 for c in (cx, cy)]
    p, radius = float(p0), 0.25 / slack
    while True:
        near = [c[np.abs(c - m) <= radius * p] for c, m in zip((cx, cy), mid)]
        ax, ay = phase(near[0], p), phase(near[1], p)
        rows, rhs, spread = [], [], 0.0
        for c, a0, col in ((near[0], ax, 1), (near[1], ay, 2)):
            k = np.round((c - a0) / p)[_near(c, a0, p, 0.2 * p)]
            spread = max(spread, float(np.ptp(k)) if k.size else 0.0)
            for kk, cc in zip(k, c[_near(c, a0, p, 0.2 * p)]):
                row = [float(kk), 0.0, 0.0]
                row[col] = 1.0
                rows.append(row)
                rhs.append(cc)
        if spread >= 1:                                       # two coordinates a whole cell apart pin the pitch
            sol, *_ = np.linalg.lstsq(np.asarray(rows), np.asarray(rhs), rcond=None)
            if abs(sol[0] - p) <= slack * p:
                p = float(sol[0])
                ax, ay = phase(near[0], p), phase(near[1], p)
        if near[0].size == cx.size and near[1].size == cy.size:
            return p, ax, ay
        radius *= 4


def _near(c, phase, p, tol):
    """|c - phase| modulo p is within tol (array or scalar)."""
    np, _ = _imaging()
    d = np.abs((np.asarray(c, float) - phase + p / 2) % p - p / 2)
    return d <= tol


def _lattice(boxes, hbands, vbands, w):
    """(pitch, origin x, origin y, the boxes on it): the wire lattice. A component fills whole cells
    and wires run through cell centres, so the pitch is the largest that divides the boxes, puts
    their edges on one phase and puts the long wire lines half a cell off it. Candidates that are not
    on that lattice (a region between wires with a label in it) are dropped."""
    np, _ = _imaging()
    size = lambda b: (b.x1 - b.x0 + w / 2, b.y1 - b.y0 + w / 2)   # outline inside or outside the cell edge
    d_ref = float(np.median([min(size(b)) for b in boxes]))
    wx = np.array([(c, wt) for c, wt, th in vbands if th <= 3 * w] or [(0.0, 0.0)])
    wy = np.array([(c, wt) for c, wt, th in hbands if th <= 3 * w] or [(0.0, 0.0)])
    total = float(wx[:, 1].sum() + wy[:, 1].sum())
    need = max(1.0, 0.6 * len(boxes))                  # the real components are the majority
    why = "no pitch divides the component boxes"
    for n in range(1, 9):
        p0 = d_ref / n
        if p0 < max(6, 3 * w):
            break
        fits = [b for b in boxes if all(round(d / p0) >= 1 and abs(d / p0 - round(d / p0)) <= 0.15 for d in size(b))]
        if len(fits) < need:
            continue
        p0 = float(np.mean([d / round(d / p0) for b in fits for d in size(b)]))
        # the outline may lie inside or outside the cells, so a box's size is good to half a stroke
        p, ax, ay = _fit([e for b in fits for e in b.edges()[:2]], [e for b in fits for e in b.edges()[2:]], p0,
                         slack=max(0.03, 0.35 * w / p0))
        tol = max(1.0 + w, 0.15 * p)
        keep = [b for b in fits if _near(b.edges()[:2], ax, p, tol).all() and _near(b.edges()[2:], ay, p, tol).all()]
        if len(keep) < need:
            why = "the component boxes do not share one lattice"
            continue
        tw = 0.12 * p
        on = sum(float(c[_near(c[:, 0], a + p / 2, p, tw), 1].sum()) for c, a in ((wx, ax), (wy, ay)))
        edge = sum(float(c[_near(c[:, 0], a, p, tw), 1].sum()) for c, a in ((wx, ax), (wy, ay)))
        if total <= 0 or on < 0.2 * total or on + edge < 0.85 * total:
            why = "wires do not run half a cell off the component outlines (unsupported editor geometry)"
            continue
        # the wire lines span the whole drawing: fit the lattice to them
        fx = [float(c) for c in wx[_near(wx[:, 0], ax + p / 2, p, 0.2 * p), 0]] or [ax + p / 2]
        fy = [float(c) for c in wy[_near(wy[:, 0], ay + p / 2, p, 0.2 * p), 0]] or [ay + p / 2]
        p2, ox, oy = _fit(fx, fy, p, slack=0.02)
        if abs(p2 - p) > 0.02 * p:
            p2, ox, oy = p, ax + p / 2, ay + p / 2
        return p2, ox % p2, oy % p2, keep
    raise SchematicError(f"no wire lattice found: {why}")


DOT_MIN_PITCH = 6                # an editor's grid dots are at least this many wire widths apart
DOT_MIN_COVER = 0.25             # ... and sit on at least this share of the image's lattice points
DOT_MIN_SPAN = 0.5               # ... across at least this share of its width and of its height


def _dot_lattice(ink, w, rows, cols):
    """(pitch, dots) of a regular lattice of isolated dots no bigger than a wire is wide (an editor's
    grid), or (0, 0). It names the editor and marks a circuit canvas whose symbols are not boxes.
    `rows`, `cols`: the ink's runs along its rows and columns.

    A grid covers the canvas: its dots are DOT_MIN_PITCH wire widths apart or more, they sit on a
    quarter or more of the image's lattice points (wires and components hide the rest; the measured
    export shows six in ten), and they span half of each side. The specks that glyphs leave behind (a
    grid of digits, a page of text) are few, close together and bunched, and are not a grid."""
    np, _ = _imaging()
    h, wd = ink.shape
    n = 3 * w + 1
    reg = _Regions(ink & ~_long_runs(rows, ink.shape, n) & ~_long_runs(cols, ink.shape[::-1], n).T)
    side = reg.y1 - reg.y0
    square = np.flatnonzero((side == reg.x1 - reg.x0) & (side >= 1) & (side <= 2 * w))
    if square.size < 16:
        return 0.0, 0
    square = square[side[square] == np.bincount(side[square]).argmax()]       # the commonest dot size
    if square.size < 16:
        return 0.0, 0
    px, py = (reg.x0[square] + reg.x1[square] - 1) / 2, (reg.y0[square] + reg.y1[square] - 1) / 2
    gaps = np.diff(np.unique(np.round(px)))
    gaps = gaps[gaps > 2 * w]
    if gaps.size < 3:
        return 0.0, 0
    p = float(np.bincount(gaps.astype(int)).argmax())
    if p < DOT_MIN_PITCH * w:
        return 0.0, 0
    tol = max(1.0, 0.1 * p)
    on = _near(px, float(np.median(px % p)), p, tol) & _near(py, float(np.median(py % p)), p, tol)
    if on.mean() < 0.8 or on.sum() < DOT_MIN_COVER * (wd / p) * (h / p):
        return 0.0, 0
    if np.ptp(px[on]) < DOT_MIN_SPAN * wd or np.ptp(py[on]) < DOT_MIN_SPAN * h:
        return 0.0, 0
    return p, int(on.sum())


_DIRS = {"E": (1, 0), "W": (-1, 0), "S": (0, 1), "N": (0, -1)}
_OPP = {"E": "W", "W": "E", "S": "N", "N": "S"}


class _UF:
    def __init__(self):
        self.p: dict = {}

    def find(self, x):
        p = self.p
        p.setdefault(x, x)
        r = x
        while p[r] != r:
            r = p[r]
        while p[x] != r:
            p[x], x = r, p[x]
        return r

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


def extract(path) -> Extraction:
    """Vectorize a circuit-editor export. NotSchematic when the image is not one; SchematicError
    (naming the reason) when it is one this reader cannot turn into a netlist."""
    np, _ = _imaging()
    a = _load(path)
    H, W = a.shape[:2]
    bg, inkc, symc = _palette(a)
    ink, sym_m = _masks(a, bg, inkc, symc)
    del a
    w = _wire_width(ink)
    if w > max(H, W) // 40:
        raise NotSchematic(f"strokes are {w}px wide: blocks, not line art")
    rows, cols = _runs(ink), _runs(ink.T)
    probe = 6 * w + 1
    straight = _long_runs(rows, (H, W), probe) | _long_runs(cols, (W, H), probe).T
    lined = float(straight.sum()) / max(1, int(ink.sum()))
    del straight
    if lined < 0.5:
        raise NotSchematic(f"only {lined:.0%} of the ink is straight horizontal or vertical line")
    boxes = _find_boxes(ink, sym_m, w)
    dots_pitch, dots = _dot_lattice(ink, w, rows, cols)
    if not boxes:
        if dots:
            raise NoBoxes(f"a circuit canvas (dot grid every {dots_pitch:g}px) with no rectangular component "
                          "boxes: either its gates are drawn as distinctive shapes, which are not vectorized, or "
                          "this is a lossy, blurred or rescaled copy of a box circuit (read the original export)")
        raise NotSchematic("line art with no component boxes and no editor grid")
    # long lines for the lattice: longer than a lamp or a junction square, so only wires and outlines
    lmin = int(0.6 * float(np.median([min(b.x1 - b.x0, b.y1 - b.y0) for b in boxes])))
    hbands = _bands(_long_share(rows, H, lmin))
    vbands = _bands(_long_share(cols, W, lmin))
    candidates = len(boxes)
    try:
        p, ox, oy, boxes = _lattice(boxes, hbands, vbands, w)
    except SchematicError as e:
        if dots:                                # an editor canvas all the same: a circuit, unread
            raise
        raise NotSchematic(f"boxes and lines but {e}, and no editor grid") from None
    if p < 7 * w:
        raise SchematicError(f"{w}px wires on a {p:g}px lattice: too coarse to tell a crossing from a junction")
    symbols = _classify_symbols(boxes)
    ni, nj = int((W - 1 - ox) // p) + 1, int((H - 1 - oy) // p) + 1
    xs = [ox + i * p for i in range(ni)]
    ys = [oy + j * p for j in range(nj)]
    rnd = lambda v: int(math.floor(v + 0.5))

    def window(i, j, side):                 # ink share of a square window centred on a lattice point
        s = max(1, rnd(side))
        x0, y0 = max(0, rnd(xs[i] - (s - 1) / 2)), max(0, rnd(ys[j] - (s - 1) / 2))
        win = ink[y0:y0 + s, x0:x0 + s]
        return float(win.mean()) if win.size else 0.0

    # which lattice points lie inside a component box
    body: dict = {}
    for bi, b in enumerate(boxes):
        for i in range(max(0, int(math.ceil((b.x0 - w - ox) / p))), min(ni, int((b.x1 + w - ox) // p) + 1)):
            for j in range(max(0, int(math.ceil((b.y0 - w - oy) / p))), min(nj, int((b.y1 + w - oy) // p) + 1)):
                body[(i, j)] = bi
    pads = {(i, j) for i in range(ni) for j in range(nj)
            if (i, j) not in body and window(i, j, 0.5 * p) >= 0.9}       # lamps: a disc covers half a cell
    span = p / 2 - w / 2 - 1                                              # a stub: point to outline

    def half_edge(i, j, d):
        """Ink runs from lattice point (i, j) half a cell towards d, along the wire's own rows."""
        dx, dy = _DIRS[d]
        along, across = (xs[i], ys[j]) if dx else (ys[j], xs[i])
        lo, hi = (along + 1, along + span) if dx + dy > 0 else (along - span, along - 1)
        a0, a1 = rnd(lo), rnd(hi) + 1
        c0, c1 = rnd(across - (w - 1) / 2) - 1, rnd(across - (w - 1) / 2) + w + 1   # the wire's rows, a pixel of slack
        if a0 < 0 or a1 <= a0 or c0 < 0:
            return False
        strip = ink[c0:c1, a0:a1] if dx else ink[a0:a1, c0:c1]
        if strip.shape != ((c1 - c0, a1 - a0) if dx else (a1 - a0, c1 - c0)):
            return False                                                  # runs off the image
        return float(strip.any(axis=0 if dx else 1).mean()) >= 0.9

    he: dict = {}
    for i in range(ni):
        for j in range(nj):
            if (i, j) in body or (i, j) in pads:
                continue
            ds = tuple(d for d in "EWSN" if half_edge(i, j, d))
            if ds:
                he[(i, j)] = ds

    def runs_off(x, y, d):
        """The wire through pixel (x, y) carries on in direction d to the edge of the image: the edge
        cut it, it does not end on a device. (The edge is then under a cell away: a wire that went on
        for longer would have been followed to the next lattice point.)"""
        dx, dy = _DIRS[d]
        x, y = min(max(x, 0), W - 1), min(max(y, 0), H - 1)               # a wire end may round to just outside
        band = w // 2 + 1                                                 # the wire's rows, a pixel of slack
        if dx:
            strip = ink[max(0, y - band):y + band + 1, x:] if dx > 0 else ink[max(0, y - band):y + band + 1, :x + 1]
            return bool(strip.any(axis=0).all())
        strip = ink[y:, max(0, x - band):x + band + 1] if dy > 0 else ink[:y + 1, max(0, x - band):x + band + 1]
        return bool(strip.any(axis=1).all())

    uf = _UF()
    rail = lambda pt, d: (pt[0], pt[1], "H" if d in "EW" else "V")
    pins: dict = {bi: {s: [] for s in "EWSN"} for bi in range(len(boxes))}   # box -> side -> [(point, dir)]
    contacts: list = []                       # (rail, pixel x, pixel y): a wire end on a device
    cut = 0                                   # wire ends that are the image edge, not a device
    stats = {"pins": 0, "junctions": 0, "crossings": 0, "h_segments": 0, "v_segments": 0}
    for pt, ds in he.items():
        i, j = pt
        for d in ds:
            uf.find(rail(pt, d))
            dx, dy = _DIRS[d]
            q = (i + dx, j + dy)
            mid = (rnd(xs[i] + dx * p / 2), rnd(ys[j] + dy * p / 2))
            if q in body:
                pins[body[q]][_OPP[d]].append((pt, d))      # the box's side that faces this point
                stats["pins"] += 1
            elif q in pads:
                contacts.append((rail(pt, d), rnd(xs[i] + dx * p), rnd(ys[j] + dy * p)))
            elif _OPP[d] in he.get(q, ()):
                if d in "ES":
                    uf.union(rail(pt, d), rail(q, d))
                    stats["h_segments" if d == "E" else "v_segments"] += 1
            else:
                contacts.append((rail(pt, d), *mid))        # ends half-way: on some device's outline
                cut += runs_off(*mid, d)
        has_h, has_v = any(d in "EW" for d in ds), any(d in "SN" for d in ds)
        blob = window(i, j, 0.3 * p) >= 0.85
        if has_h and has_v:
            if len(ds) < 4 or blob:
                uf.union((i, j, "H"), (i, j, "V"))
                stats["junctions"] += len(ds) >= 3
            else:
                stats["crossings"] += 1
        elif len(ds) == 1 and not blob:
            d = ds[0]
            q = (i + _DIRS[d][0], j + _DIRS[d][1])
            if q not in body and q not in pads and _OPP[d] in he.get(q, ()):
                contacts.append((rail(pt, d), rnd(xs[i]), rnd(ys[j])))   # a bare wire end
                cut += runs_off(rnd(xs[i]), rnd(ys[j]), _OPP[d])

    # gates: the side with one pin is the output, the opposite side the inputs
    order = sorted(range(len(boxes)), key=lambda bi: ((boxes[bi].y0 + boxes[bi].y1) // 2, (boxes[bi].x0 + boxes[bi].x1) // 2))
    gid = {bi: f"g{k}" for k, bi in enumerate(order)}
    drivers: dict = {}            # net -> [gate id]
    gate_ins: dict = {}           # box -> [net]
    bad: list = []
    side_clip = {"W": (0, 2), "E": (1, 3), "N": (0, 1), "S": (2, 3)}
    for bi in order:
        b, sides = boxes[bi], pins[bi]
        used = [s for s in "EWSN" if sides[s]]
        out_side = None
        for s in used:
            o = _OPP[s]
            if len(sides[s]) == 1 and len(sides[o]) >= 2 and len(used) == 2:
                out_side = s
        if out_side is None and len(used) == 2 and used[1] == _OPP[used[0]] and all(len(sides[s]) == 1 for s in used):
            clip = [s for s in used if all(b.clipped[k] for k in side_clip[s])]
            out_side = clip[0] if len(clip) == 1 else None
        if out_side is None:
            bad.append(f"{gid[bi]} at ({b.x0},{b.y0}): pins {', '.join(f'{s}:{len(sides[s])}' for s in used) or 'none'}")
            continue
        in_side = _OPP[out_side]
        drivers.setdefault(uf.find(rail(*sides[out_side][0])), []).append(gid[bi])
        # input pins top to bottom (a side of a horizontal box) or left to right (the top or bottom of a vertical one)
        gate_ins[bi] = [uf.find(rail(*pd)) for pd in sorted(sides[in_side], key=lambda pd: (pd[0][1], pd[0][0]))]
    if bad:
        raise SchematicError(f"{len(bad)} of {len(boxes)} component boxes have no readable input and output side "
                             f"(first: {bad[0]})")
    short = [f"{', '.join(g)}" for g in drivers.values() if len(g) > 1]
    if short:
        raise SchematicError(f"{len(short)} net(s) are driven by more than one gate output (first: {short[0]}): "
                             "the wiring was misread")
    net_contacts: dict = {}
    for r, x, y in contacts:
        net_contacts.setdefault(uf.find(r), []).append((x, y))

    def physical(items):          # devices in a row read left to right, in a column top to bottom
        if not items:
            return []
        xr = max(x for (x, y), _ in items) - min(x for (x, y), _ in items)
        yr = max(y for (x, y), _ in items) - min(y for (x, y), _ in items)
        return sorted(items, key=(lambda it: (it[0][0], it[0][1])) if xr >= yr else (lambda it: (it[0][1], it[0][0])))

    in_devs = physical([(xy, net) for net, pts in net_contacts.items() if net not in drivers for xy in pts])
    out_devs = physical([(xy, net) for net, pts in net_contacts.items() if net in drivers for xy in pts])
    net_name: dict = {net: g[0] for net, g in drivers.items()}
    inputs, ties = [], []
    for k, (xy, net) in enumerate(in_devs):
        name = f"in{k}"
        inputs.append(name)
        if net in net_name:
            ties.append((name, net_name[net]))
        else:
            net_name[net] = name
    floating, issues = [], []
    gates = []
    for bi in order:
        refs = []
        for net in gate_ins[bi]:
            if net not in net_name:
                net_name[net] = f"nc{len(floating)}"
                floating.append(net_name[net])
            refs.append(net_name[net])
        gates.append(Gate(gid[bi], tuple(refs), None, boxes[bi].symbol))
    if floating:
        issues.append(f"{len(floating)} net(s) with no driver and no input device are held at 0 ({', '.join(floating[:4])})")
    netlist = Netlist(tuple(gates), tuple(inputs), tuple(net_name[net] for _, net in out_devs), tuple(ties), tuple(floating))
    if not netlist.outputs:
        issues.append("no output device found: no wire from a gate output ends on a lamp or a free end")
    if cut:
        issues.append(f"{cut} wire(s) run off the edge of the image and were read as devices: the image may be "
                      "a crop of the export")
    clip2 = sum(1 for b in boxes if sum(b.clipped) == 2)
    editor = "logigator-like" if clip2 >= 0.8 * len(boxes) and dots else "box-and-wire"
    stats.update(symbols=symbols, dots=dots, rejected_boxes=candidates - len(boxes))
    return Extraction(netlist, editor, round(p, 3), (round(ox, 2), round(oy, 2)), w, (W, H),
                      tuple((boxes[bi].x0, boxes[bi].y0, boxes[bi].x1, boxes[bi].y1) for bi in order),
                      tuple(xy for xy, _ in in_devs), tuple(xy for xy, _ in out_devs), stats, tuple(issues))


def detect(path) -> Detection:
    """Whether an image is a circuit-editor export and whether its netlist can be read. Never raises
    for image content (a missing imaging package is still a ToolMissing)."""
    try:
        return extract(path).detection()
    except (NotSchematic, Unexamined) as e:
        return Detection(False, False, "", str(e))
    except SchematicError as e:
        return Detection(True, False, e.editor, str(e))


# ========================================================================================== engine

def _image_head(path: Path) -> bool:
    """The file starts with a PNG, GIF, BMP or WebP signature. A file that cannot be read counts, so
    that it is named in the notes instead of passed over. For regular files only: opening a named
    pipe waits for a writer that never comes."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return True
    return (head.startswith(b"\x89PNG\r\n\x1a\n") or head[:6] in (b"GIF87a", b"GIF89a")
            or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")
            or (head[:2] == b"BM" and len(head) >= 14 and head[6:10] == b"\0\0\0\0"))


def _special(mode: int) -> str:
    return ("a named pipe" if stat.S_ISFIFO(mode) else "a socket" if stat.S_ISSOCK(mode)
            else "a device" if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) else "not a regular file")


def _scan(challenge_dir: Path) -> tuple[list[Path], list[tuple[Path, str]], list[tuple[Path, str]]]:
    """(every image file, the special files passed over, the entries that could not be looked at),
    each sorted by path; the last two carry what the entry is or why it was not looked at. The files
    come from the sweep's `unpacked/` copy when there is one, else `files/`, else the folder; recon
    output and links are left out. Only a regular file is ever opened: a named pipe, a socket or a
    device is named, not read (reading a pipe would wait for ever). An image is a file with an image
    extension or one that starts with an image signature: a handout PNG often has no extension, or
    the wrong one."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    root = next((challenge_dir / d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), challenge_dir)
    images, special, closed = [], [], []
    stack = [root]
    while stack:
        here = stack.pop()
        try:
            entries = sorted(here.iterdir(), reverse=True)
        except OSError as e:
            closed.append((here, f"the folder could not be listed ({e.strerror or type(e).__name__})"))
            continue
        for p in entries:
            try:
                mode = p.lstat().st_mode
            except OSError as e:
                closed.append((p, f"the entry could not be inspected ({e.strerror or type(e).__name__})"))
                continue
            if stat.S_ISLNK(mode):
                continue
            if stat.S_ISDIR(mode):
                if p.name not in SKIP_DIRS:
                    stack.append(p)
            elif not stat.S_ISREG(mode):
                special.append((p, _special(mode)))
            elif p.suffix.lower() in IMAGE_EXTS or _image_head(p):
                images.append(p)
    return sorted(images), sorted(special), sorted(closed)


def challenge_images(challenge_dir: Path) -> tuple[list[Path], list[Path]]:
    """(the images to examine, the images left out by the MAX_IMAGES cap), each sorted by path, from
    _scan(): regular files only, from `unpacked/`, else `files/`, else the folder."""
    images = _scan(challenge_dir)[0]
    return images[:MAX_IMAGES], images[MAX_IMAGES:]


def _wrap(body: str, profile, ff) -> str | None:
    prefixes = tuple(profile.flag.prefixes)
    if not prefixes:
        return None
    flag = f"{prefixes[0]}{{{body}}}"
    return flag if ff.is_flag(flag) else None


def _list_opt(name: str, v) -> list[str]:
    """A list option: a comma-separated string, or a list of strings (whole numbers are taken as their
    digits). Anything else is a ValueError that names the option."""
    if v is None or v == "":
        return []
    if isinstance(v, str):
        return [s for s in (x.strip() for x in v.split(",")) if s]
    if isinstance(v, (list, tuple)) and all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in v):
        return [str(x) for x in v]
    raise ValueError(f"logic_schematic: option {name}={v!r} is not a text or a list of texts")


def _kinds_opt(v) -> tuple[str, ...]:
    """The gate kinds to try: every one must be a known kind, whether or not the sweep gets as far
    as using it."""
    kinds = tuple(_list_opt("kinds", v))
    for k in kinds:
        if k not in KINDS:
            raise ValueError(f"logic_schematic: option kinds={v!r}: unknown gate kind {k!r} (known: {', '.join(KINDS)})")
    return kinds or KINDS


def _seconds_opt(v) -> float:
    try:
        if isinstance(v, bool):
            raise ValueError
        budget = float(v)
    except (TypeError, ValueError):
        raise ValueError(f"logic_schematic: option seconds={v!r} is not a number of CPU seconds") from None
    if not budget > 0:
        raise ValueError(f"logic_schematic: option seconds={v!r} must be more than 0")
    return budget


def _count_opt(name: str, v) -> int:
    """A whole number of 0 or more: an int, a float with no fraction, or their spelling as text."""
    n = None
    if isinstance(v, int) and not isinstance(v, bool):
        n = v
    elif isinstance(v, float) and v.is_integer():
        n = int(v)
    elif isinstance(v, str) and v.strip().isascii() and v.strip().isdigit():
        n = int(v.strip())
    if n is None or n < 0:
        raise ValueError(f"logic_schematic: option {name}={v!r} is not a whole number of 0 or more")
    return n


def _path_opt(name: str, v) -> Path | None:
    if v is None or v == "":
        return None
    if isinstance(v, (str, os.PathLike)):
        return Path(v)
    raise ValueError(f"logic_schematic: option {name}={v!r} is not a path")


_TRUE, _FALSE = ("true", "1", "yes", "on"), ("false", "0", "no", "off", "")


def _bool_opt(name: str, v) -> bool:
    """An on/off option: a boolean, 0 or 1, or one of the usual words in any case (`--opt wrap=True`
    arrives as the string "True"). Anything else is a ValueError, never a silent `off`."""
    if v is None or isinstance(v, bool):
        return bool(v)
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in _TRUE + _FALSE:
        return v.strip().lower() in _TRUE
    raise ValueError(f"logic_schematic: option {name}={v!r} is not true or false")


_BRACES = str.maketrans({"{": "\\x7b", "}": "\\x7d"})


def _reading_line(r: Reading) -> str:
    return f"{r.stream!r} <- {r.kinds_text()}, text {r.text!r}, {r.readout.describe()}"


def _defused(res, ff):
    """A result that names no flag, made safe to print. Intake scans an engine's output for the event
    flag format when its result has no flags (docs/CONTRACTS.md section 19), and one distinct match
    there is a found flag. A reading here is inferred, and one that holds `PREFIX{` is closed into a
    match by any later `}`, the result JSON's own included. So when the printed result would match,
    every brace in its text is spelled \\x7b / \\x7d, and a note says so. A result with flags is
    returned as it is: intake takes those flags and does not scan."""
    if res.flags or not ff.find_flags(res.to_json()):
        return res
    evidence = tuple(replace(e, detail=e.detail.translate(_BRACES), path=e.path and e.path.translate(_BRACES))
                     for e in res.evidence)
    return replace(res, evidence=evidence, notes=(
        res.notes.translate(_BRACES) + "; braces are written \\x7b and \\x7d in this result, so that an inferred "
        "reading does not read as a flag in the event format (a readings.json named under `written` has every "
        "stream as it was read)"))


def solve(challenge_dir, profile, **opts):
    """Engine contract. opts: wrap (true/false: return printable readings wrapped in the flag format
    as candidates), texts (extra input texts, tried first), kinds (gate kinds to try, default all),
    netlist (a to_dict() JSON file to use instead of reading an image), out (folder for netlist.json
    and readings.json; default <challenge>/recon/logic_schematic), max_hypotheses, seconds (CPU-time
    budget, default DEFAULT_SECONDS: images not reached and hypotheses not run are named). An option
    with a value of the wrong kind is a ValueError that names it, before anything is read."""
    from ctf import flagfmt
    return _defused(_solve(Path(challenge_dir), profile, opts), flagfmt.for_profile(profile))


def _solve(challenge_dir: Path, profile, opts):
    from ctf import flagfmt
    from ctf.result import Cost, Evidence, SolverResult

    t0 = _cpu()
    ff = flagfmt.for_profile(profile)
    cost = lambda: Cost(seconds=round(_cpu() - t0, 3))
    unknown = sorted(set(opts) - {"wrap", "texts", "kinds", "netlist", "out", "max_hypotheses", "seconds"})
    if unknown:
        raise ValueError(f"logic_schematic: unknown option {', '.join(unknown)}")
    wrap = _bool_opt("wrap", opts.get("wrap"))
    budget = _seconds_opt(opts.get("seconds", DEFAULT_SECONDS))
    spent = lambda: _cpu() - t0 >= budget
    max_hypotheses = _count_opt("max_hypotheses", opts.get("max_hypotheses", MAX_HYPOTHESES))
    kinds = _kinds_opt(opts.get("kinds"))
    given = _list_opt("texts", opts.get("texts"))
    texts = event_texts(profile, given)
    out_dir = _path_opt("out", opts.get("out")) or challenge_dir / "recon" / "logic_schematic"
    netlist_file = _path_opt("netlist", opts.get("netlist"))

    def rel(p):
        try:
            return str(Path(p).relative_to(challenge_dir))
        except ValueError:
            return str(p)

    notes: list[str] = []
    found: list[tuple[str, Netlist, str]] = []           # (source, netlist, description)
    unread: list[str] = []                               # images that may be a circuit and were not read
    long = [t for t in given if len(" ".join(t.split())) > MAX_TEXT]
    if long:
        notes.append(f"{len(long)} text(s) given with `texts` are over {MAX_TEXT} characters and were not fed "
                     f"(first: {long[0][:24]!r}...)")
    try:
        if netlist_file is not None:
            src = netlist_file if netlist_file.is_absolute() else challenge_dir / netlist_file
            try:
                found.append((rel(src), Netlist.from_dict(json.loads(src.read_text())), "netlist given by the operator"))
            except (OSError, ValueError) as e:
                return SolverResult("blocked", engine=ENGINE, cost=cost(), notes=f"netlist {rel(src)} is not usable: {e}")
        else:
            files, special, closed = _scan(challenge_dir)
            images, left_out = files[:MAX_IMAGES], files[MAX_IMAGES:]
            # a folder that could not be listed may hold the circuit; a pipe or a device never does
            unread += [f"{rel(p)}: not examined: {why}" for p, why in closed]
            if special:
                more = f" and {len(special) - MAX_IMAGES} more" if len(special) > MAX_IMAGES else ""
                notes.append(f"{len(special)} special file(s) not opened: "
                             + ", ".join(f"{rel(p)} ({what})" for p, what in special[:MAX_IMAGES]) + more)
            if left_out:
                names = ", ".join(rel(p) for p in left_out[:MAX_IMAGES])
                more = f" and {len(left_out) - MAX_IMAGES} more" if len(left_out) > MAX_IMAGES else ""
                unread.append(f"{len(left_out)} image(s) not examined, over the cap of {MAX_IMAGES} per challenge: "
                              f"{names}{more}")
            for k, img in enumerate(images):
                if spent():
                    unread.append(f"{len(images) - k} image(s) not examined, the budget of {budget:g}s CPU ran out "
                                  f"(option seconds): {', '.join(rel(p) for p in images[k:])}")
                    break
                try:
                    ex = extract(img)
                except NotSchematic as e:
                    notes.append(f"{rel(img)}: not a circuit export ({e})")
                    continue
                except Unexamined as e:
                    unread.append(f"{rel(img)}: not examined: {e}")
                    continue
                except SchematicError as e:
                    unread.append(f"{rel(img)}: a circuit export that could not be read: {e}")
                    continue
                nl = ex.netlist
                found.append((rel(img), nl, f"{ex.editor} export, {ex.pitch:g}px lattice: {len(nl.gates)} gates, "
                              f"{len(nl.inputs)} input devices ({len(nl.independent)} independent), "
                              f"{len(nl.outputs)} outputs, {ex.stats['symbols']} box symbol(s)"))
                notes += [f"{rel(img)}: {s}" for s in ex.issues]
    except ToolMissing as e:
        return SolverResult("blocked", engine=ENGINE, cost=cost(), notes=str(e))
    if not found:
        if unread:
            return SolverResult("unsure", engine=ENGINE, cost=cost(), notes="; ".join(unread + notes))
        return SolverResult("none", engine=ENGINE, cost=cost(), notes="; ".join(notes) or "no image file")

    def write(name, obj) -> bool:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / name).write_text(json.dumps(obj, indent=1) + "\n")
        except OSError as e:
            notes.append(f"could not write {rel(out_dir / name)}: {e.strerror or type(e).__name__}")
            return False
        written.append(rel(out_dir / name))
        return True

    evidence, readings, written, lost = [], [], [], []
    for k, (source, nl, what) in enumerate(found, start=1):  # every circuit found is read
        evidence.append(Evidence("match", what, path=source))
        pre = f"{k}-{Path(source).stem}." if len(found) > 1 else ""
        write(f"{pre}netlist.json", nl.to_dict())            # before the sweep: a sweep that is killed loses no netlist
        sw = sweep(nl, texts, flag_format=ff, kinds=kinds, stop=spent, max_hypotheses=max_hypotheses)
        notes += [f"{source}: {n}" for n in sw.notes]
        notes.append(f"{source}: {sw.tried} readout hypotheses over {len(texts)} text(s), {len(sw.readings)} printable")
        readings += [(source, r) for r in sw.readings]
        # every reading, best first: the sweep is bounded by its hypothesis cap, and the right reading
        # need not be among the first few hundred (the kinds are tried in a fixed order)
        if not write(f"{pre}readings.json", [r.to_dict() for r in sw.readings]):
            lost.append(f"{pre}readings.json")
    readings.sort(key=lambda sr: sr[1].rank)
    if written:
        notes.append(f"written: {', '.join(written)}")
    for source, r in readings[:MAX_READINGS]:
        evidence.append(Evidence("decode", _reading_line(r), path=source))
    # where the readings that this result does not show are: never a pointer to a file that is not there
    if lost:
        rest = f"the rest are not on disk: {', '.join(lost)} could not be written (option out names another folder)"
    else:
        rest = "readings.json has the rest" if len(found) == 1 else "the readings.json files have the rest"
    if len(readings) > MAX_READINGS:
        notes.append(f"{len(readings) - MAX_READINGS} more printable reading(s) are "
                     + (f"not shown here; {rest}" if lost else
                        "in readings.json only" if len(found) == 1 else "in the readings.json files only"))
    flags = list(dict.fromkeys(f for _, r in readings for f in r.flags))
    if flags:
        if len(flags) > MAX_READINGS:
            notes.insert(0, f"only the first {MAX_READINGS} are returned; {rest}")
        return SolverResult("candidate", flags=flags[:MAX_READINGS], evidence=evidence, engine=ENGINE, cost=cost(),
                            notes="; ".join([f"{len(flags)} flag(s) in the event format read off the circuit under "
                                             "an inferred gate kind and readout"] + unread + notes))
    if not readings:
        return SolverResult("unsure", evidence=evidence, engine=ENGINE, cost=cost(),
                            notes="; ".join(["a circuit was read but no gate kind and readout gives printable output "
                                             "for the event texts: read the netlist"] + unread + notes))
    if wrap:
        tries = [_wrap(r.stream, profile, ff) for _, r in readings]
        wrapped = list(dict.fromkeys(f for f in tries if f))
        if wrapped:
            unfit = tries.count(None)
            if unfit:
                notes.insert(0, f"{unfit} reading(s) cannot be a flag body in this event's format and were left unwrapped")
            if len(wrapped) > MAX_READINGS:
                notes.insert(0, f"only the first {MAX_READINGS} are returned; {rest}")
            return SolverResult("candidate", flags=wrapped[:MAX_READINGS], evidence=evidence, engine=ENGINE, cost=cost(),
                                notes="; ".join([f"{len(readings)} printable reading(s), wrapped in the flag format "
                                                 "by request, best first: inferred, not proven"] + unread + notes))
        notes.append("wrap was asked for but no reading fits the event flag format")
    return SolverResult("unsure", evidence=evidence, engine=ENGINE, cost=cost(),
                        notes="; ".join([f"{len(readings)} printable reading(s), none in the event flag format; "
                                         f"best first: {'; '.join(_reading_line(r) for _, r in readings[:3])}. A reading "
                                         "is a flag body at most: wrap it only if the brief says so (wrap=true)"]
                                        + unread + notes))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="logic_schematic.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("target", type=Path, help="a schematic image, or a netlist JSON file (the to_dict() form)")
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--text", action="append", default=[], help="an extra input text to feed, tried first")
    ap.add_argument("--kinds", help="comma-separated gate kinds to try (default: all)")
    ap.add_argument("--wrap", action="store_true", help="wrap printable readings in the event flag format")
    ap.add_argument("--netlist-out", type=Path, help="write the extracted netlist JSON here")
    a = ap.parse_args(argv)
    from ctf import event, flagfmt
    profile = event.load(a.event) if a.event else event.current()
    if not a.target.is_file():
        print(f"logic_schematic.py: no such file: {a.target}", file=sys.stderr)
        return 2
    try:
        kinds = _kinds_opt(a.kinds)
        if a.target.suffix.lower() == ".json":
            nl = Netlist.from_dict(json.loads(a.target.read_text()))
        else:
            ex = extract(a.target)
            nl = ex.netlist
            print(f"{ex.editor} export {ex.size[0]}x{ex.size[1]}, lattice {ex.pitch:g}px, wire {ex.wire_width}px: "
                  f"{len(nl.gates)} gates, {len(nl.inputs)} inputs ({len(nl.ties)} tied), {len(nl.outputs)} outputs; "
                  + ", ".join(f"{k} {v}" for k, v in ex.stats.items()))
            for s in ex.issues:
                print(f"issue: {s}")
    except (SchematicError, ToolMissing, ValueError) as e:
        print(f"logic_schematic.py: {e}", file=sys.stderr)
        return 2
    if a.netlist_out:
        a.netlist_out.write_text(json.dumps(nl.to_dict(), indent=1) + "\n")
    ff = flagfmt.for_profile(profile)
    sw = sweep(nl, event_texts(profile, a.text), flag_format=ff, kinds=kinds)
    for n in sw.notes:
        print(f"note: {n}")
    print(f"{sw.tried} hypotheses, {len(sw.readings)} printable reading(s)")
    for r in sw.readings[:MAX_READINGS]:
        print("  " + _reading_line(replace(r, stream=_wrap(r.stream, profile, ff) or r.stream) if a.wrap else r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
