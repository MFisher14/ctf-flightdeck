"""B-134: draws the circuit schematics tests/test_toolkits_logic_schematic.py reads (not a test module).

Nothing here comes from a challenge or an editor: every image is drawn with Pillow from lattice
coordinates, in the geometry measured on a Logigator export (docs/build-log/B-134.md):

  * a square lattice of cells `pitch` pixels wide; lattice point (i, j) is the centre of cell (i, j);
  * wires are `w`-pixel lines through cell centres; a grid dot (w x w) sits on every lattice point;
  * a component box fills whole cells; its outline is drawn just outside them, with the two corners
    of its output side cut off, and a symbol in the middle; a pin is a half-cell stub from the next
    lattice point to the outline (inputs one per cell on one side, the output in the first cell of
    the opposite side);
  * a junction is a filled square (3/8 of a cell) on a lattice point; a lamp is a disc one cell wide;
  * an input device is a one-cell box with a bar inside and a stub out of its bottom edge.

Canvas draws the primitives; draw_netlist() lays out and routes a whole netlist (it reads plain
attributes: .gates with .id and .ins, .inputs, .outputs, .ties, so this file does not import the
engine); nor_transducer() builds the gate list of a small NOR-only transducer.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from PIL import Image, ImageDraw, ImageFont

THEMES = {                       # background, ink, symbol colour
    "dark": ((34, 37, 38), (214, 56, 100), (255, 255, 255)),
    "light": ((255, 255, 255), (20, 20, 20), (20, 20, 20)),        # one colour: the symbol is ink too
    "blueprint": ((16, 44, 84), (240, 240, 240), (255, 196, 0)),
}
SIDES = {"E": (1, 0), "W": (-1, 0), "S": (0, 1), "N": (0, -1)}
OPPOSITE = {"E": "W", "W": "E", "S": "N", "N": "S"}


class Canvas:
    """A schematic drawn in lattice coordinates. `shift` moves every wire (x of vertical wires, y of
    horizontal wires) by that many pixels off the cell centre, as the measured export does."""

    def __init__(self, cols, rows, *, pitch=16, w=1, theme="dark", dots=True, shift=(0, 0)):
        self.cols, self.rows, self.p, self.w, self.shift = cols, rows, pitch, w, shift
        self.bg, self.ink, self.sym = THEMES[theme]
        self.im = Image.new("RGB", (cols * pitch, rows * pitch), self.bg)
        self.d = ImageDraw.Draw(self.im)
        if dots:
            for i in range(cols):
                for j in range(rows):
                    self._square(i, j, w)

    # ---- pixel helpers
    def centre(self, i, j):
        return i * self.p + self.p // 2 + self.shift[0], j * self.p + self.p // 2 + self.shift[1]

    def _span(self, c):                       # the pixels [a, b) of a w-wide line centred on c
        a = c - self.w // 2
        return a, a + self.w

    def _rect(self, x0, y0, x1, y1, fill=None):           # end-exclusive
        if x1 > x0 and y1 > y0:
            self.d.rectangle((x0, y0, x1 - 1, y1 - 1), fill=self.ink if fill is None else fill)

    def _square(self, i, j, side):
        cx, cy = self.centre(i, j)
        self._rect(cx - side // 2, cy - side // 2, cx - side // 2 + side, cy - side // 2 + side)

    # ---- primitives
    def wire(self, *pts):
        """A wire through the lattice points given, each leg horizontal or vertical."""
        for (i0, j0), (i1, j1) in zip(pts, pts[1:]):
            assert i0 == i1 or j0 == j1, "wires are axis-aligned"
            (x0, y0), (x1, y1) = self.centre(i0, j0), self.centre(i1, j1)
            xa, xb = self._span(min(x0, x1))[0], self._span(max(x0, x1))[1]
            ya, yb = self._span(min(y0, y1))[0], self._span(max(y0, y1))[1]
            self._rect(xa, ya, xb, yb)

    def stub(self, pt, side):
        """Half a cell of wire from lattice point `pt` to the edge of its cell on `side`."""
        i, j = pt
        cx, cy = self.centre(i, j)
        dx, dy = SIDES[side]
        if dx:
            edge = (i + 1) * self.p if dx > 0 else i * self.p
            xa, xb = (self._span(cx)[0], edge) if dx > 0 else (edge, self._span(cx)[1])
            self._rect(xa, self._span(cy)[0], xb, self._span(cy)[1])
        else:
            edge = (j + 1) * self.p if dy > 0 else j * self.p
            ya, yb = (self._span(cy)[0], edge) if dy > 0 else (edge, self._span(cy)[1])
            self._rect(self._span(cx)[0], ya, self._span(cx)[1], yb)

    def junction(self, i, j):
        self._square(i, j, max(self.w + 2, round(0.375 * self.p)))

    def lamp(self, i, j):
        cx, cy = self.centre(i, j)
        r = self.p // 2
        self.d.ellipse((cx - r, cy - r, cx + r - 1, cy + r - 1), fill=self.ink)

    def _clip_corner(self, cx, cy, sx, sy):
        """Cut the outline corner at interior corner (cx, cy); (sx, sy) point from it into the box.
        The corner square is cleared and closed again with a diagonal stroke, so the cut-off triangle
        is outside the box."""
        w, c = self.w, max(self.w + 2, round(0.19 * self.p))
        px = lambda u, v: (cx + u if sx > 0 else cx - 1 - u, cy + v if sy > 0 else cy - 1 - v)
        for u in range(-w, c):
            for v in range(-w, c):
                self.im.putpixel(px(u, v), self.bg)
        for t in range(c + w):                           # from the top outline down to the side outline
            for k in range(max(2, w)):
                u = c - 1 - t + k
                if u < c:
                    self.im.putpixel(px(u, -w + t), self.ink)

    def outline(self, i, j, cols, rows, clip=None):
        """The outline of a box filling cells [i, i+cols) x [j, j+rows), drawn outside them, with the
        inside cleared; the two corners of side `clip` are cut off."""
        p, w = self.p, self.w
        x0, y0, x1, y1 = i * p, j * p, (i + cols) * p, (j + rows) * p
        self._rect(x0 - w, y0 - w, x1 + w, y1 + w)
        self._rect(x0, y0, x1, y1, fill=self.bg)
        nw, ne, sw, se = (x0, y0, 1, 1), (x1, y0, -1, 1), (x0, y1, 1, -1), (x1, y1, -1, -1)
        for corner in {"E": (ne, se), "W": (nw, sw), "S": (sw, se), "N": (nw, ne), None: ()}[clip]:
            self._clip_corner(*corner)

    def box(self, i, j, *, ins=2, out="E", symbol="?", clip=True, cols=None, rows=None):
        """A component box with its top-left cell at (i, j). Horizontal boxes (out E or W) are 3 cells
        wide and one cell tall per input (at least 2); vertical ones the transpose. Returns
        (input pin points, output pin point): the lattice points the stubs end on."""
        if out in "EW":
            cols, rows = cols or 3, rows or max(2, ins)
        else:
            cols, rows = cols or max(2, ins), rows or 3
        self.outline(i, j, cols, rows, clip=out if clip else None)
        if symbol:
            font = ImageFont.load_default(size=max(8, int(0.62 * self.p)))
            self.d.text(((2 * i + cols) * self.p // 2, (2 * j + rows) * self.p // 2), symbol,
                        fill=self.sym, font=font, anchor="mm")
        if out == "E":
            in_pts, out_pt = [(i - 1, j + r) for r in range(ins)], (i + cols, j)
        elif out == "W":
            in_pts, out_pt = [(i + cols, j + r) for r in range(ins)], (i - 1, j)
        elif out == "S":
            in_pts, out_pt = [(i + c, j - 1) for c in range(ins)], (i + cols - 1, j + rows)
        else:
            in_pts, out_pt = [(i + c, j + rows) for c in range(ins)], (i, j - 1)
        for pt in in_pts:
            self.stub(pt, out)                            # towards the box: the way the signal flows
        self.stub(out_pt, OPPOSITE[out])
        return in_pts, out_pt

    def input_cell(self, i, j):
        """A one-cell input device; returns the lattice point below it, where its wire starts."""
        self.outline(i, j, 1, 1)
        y = j * self.p + round(0.75 * self.p)
        self._rect(i * self.p, y, (i + 1) * self.p, y + self.w)
        self.stub((i, j + 1), "N")
        return (i, j + 1)

    def label(self, i, j, text):
        """A text label with its marker square, starting in cell (i, j): decoration, wired to nothing."""
        self.junction(i, j)
        font = ImageFont.load_default(size=max(8, int(0.6 * self.p)))
        self.d.text(((i + 1) * self.p, j * self.p + self.p // 2), text, fill=self.sym, font=font, anchor="lm")

    def save(self, path):
        self.im.save(path)
        return path


# ----------------------------------------------------------------------------- whole-netlist layout

def draw_netlist(netlist, *, pitch=16, w=1, theme="dark", dots=True, shift=(0, 0), junction_squares=True,
                 labels=True, symbols=None) -> Canvas:
    """Lay a netlist out and route it: input devices in a row along the top, one vertical trunk per
    net on the left, the gates stacked in one column, the lamps stacked bottom right.

    Every pin, lamp and gate output gets a row of its own, so a horizontal wire meets a foreign trunk
    only as a plain four-way crossing, and its own trunk as a corner or a T (drawn with a junction
    square unless junction_squares is False). Tied input devices must be neighbours; every output
    must read a gate. A gate whose output nothing reads is drawn with its output pin unwired.
    `symbols` maps a gate id to the character drawn in its box (default "?").
    """
    gates = [(g.id, tuple(g.ins)) for g in netlist.gates]
    devices = list(netlist.inputs)
    tied = dict(netlist.ties)
    gate_ids = {gid for gid, _ in gates}
    assert all(o in gate_ids for o in netlist.outputs), "a lamp on an input's own net would read as an input device"
    used = {r for _, ins in gates for r in ins} | set(netlist.outputs)
    col = {d: 2 + k for k, d in enumerate(devices)}
    for gi, (gid, _) in enumerate(gates):
        col[gid] = 2 + len(devices) + gi
    box_i = 2 + len(devices) + len(gates) + 2          # boxes fill columns box_i .. box_i+2
    x_col = box_i + 4                                  # output pin at box_i+3, the return riser beside it
    lamp_col = x_col + 2
    row = 3
    pin_rows, ret_row, box_row = {}, {}, {}
    for gid, ins in gates:
        box_row[gid] = row
        pin_rows[gid] = [row + k for k in range(len(ins))]
        ret_row[gid] = row + max(2, len(ins))
        row += max(2, len(ins)) + 2
    lamp_rows = [row + 1 + k for k in range(len(netlist.outputs))]
    c = Canvas(lamp_col + 3, row + len(netlist.outputs) + 3, pitch=pitch, w=w, theme=theme, dots=dots, shift=shift)

    taps: dict = {}                                    # net -> rows where a horizontal wire meets its trunk
    for gid, ins in gates:
        for r, ref in zip(pin_rows[gid], ins):
            taps.setdefault(ref, []).append(r)
    for r, ref in zip(lamp_rows, netlist.outputs):
        taps.setdefault(ref, []).append(r)
    for d, to in tied.items():
        assert abs(col[d] - col[to]) == 1, "tied input devices must be neighbours"
        taps.setdefault(to, []).append(2)

    for d in devices:
        c.input_cell(col[d], 0)
    for d, to in tied.items():
        c.wire((col[d], 1), (col[d], 2), (col[to], 2))
    for gid, ins in gates:
        _, out_pt = c.box(box_i, box_row[gid], ins=len(ins), out="E", symbol=(symbols or {}).get(gid, "?"))
        if gid in used:                                # output pin -> riser -> back under the box to its trunk
            c.wire(out_pt, (x_col, box_row[gid]), (x_col, ret_row[gid]), (col[gid], ret_row[gid]))
    for net, rows_ in taps.items():
        start = ret_row.get(net, 1)                    # where the signal enters the trunk
        lo, hi = min([start] + rows_), max([start] + rows_)
        c.wire((col[net], lo), (col[net], hi))
        if junction_squares:
            for r in set(rows_) | ({start} if net in ret_row else set()):
                if lo < r < hi:
                    c.junction(col[net], r)
    for gid, ins in gates:
        for r, ref in zip(pin_rows[gid], ins):
            c.wire((col[ref], r), (box_i - 1, r))
    for r, ref in zip(lamp_rows, netlist.outputs):
        c.wire((col[ref], r), (lamp_col, r))
        c.lamp(lamp_col, r)
    if labels:
        c.label(box_i, 0, "out ->")
    return c


# ------------------------------------------------------------------------------- a NOR transducer

@dataclass
class Circuit:
    """A netlist under construction, in the plain shape draw_netlist() reads."""
    inputs: list
    gates: list = field(default_factory=list)          # objects with .id and .ins
    outputs: list = field(default_factory=list)
    ties: list = field(default_factory=list)

    @dataclass
    class G:
        id: str
        ins: tuple

    def gate(self, *ins) -> str:
        g = Circuit.G(f"n{len(self.gates)}", tuple(ins))
        self.gates.append(g)
        return g.id


def nor_transducer(masks=(0x03, 0x15, 0x1E), tie=True) -> Circuit:
    """A NOR-only transducer in the shape of the PINK 27 circuit, small enough to draw.

    Ten input devices: in0, in1 select; in2..in9 carry a character, top bit first, with in3 wired
    onto in2's net when `tie` (so seven independent data lines, as in the real export; without it
    in2 is left unread and in3..in9 carry the character). Eight lamps: the top one is NOR(x, NOT x)
    = 0, the other seven are the character's bits XORed with a mask the selector picks: masks[0] at
    selector 01, masks[1] at 10, masks[2] at 11. So under NOR gates a character c reads c^masks[0],
    c^masks[1], c^masks[2] at those three states.
    """
    c = Circuit(inputs=[f"in{k}" for k in range(10)])
    if tie:
        c.ties.append(("in3", "in2"))
    data = (["in2"] + [f"in{k}" for k in range(4, 10)]) if tie else [f"in{k}" for k in range(3, 10)]
    s0, s1 = "in0", "in1"
    inv = lambda a: c.gate(a, a)

    def xor(a, b):                                      # five NOR gates
        n = c.gate(a, b)
        return inv(c.gate(c.gate(a, n), c.gate(b, n)))

    ns1 = inv(s1)
    c.outputs.append(c.gate(s1, ns1))                   # the top lamp: always 0 under NOR
    made: dict = {(0, 1, 1): s0, (1, 0, 1): s1}         # value at selector (01, 10, 11) -> a net with it

    def selected(key):
        if key not in made:
            if key == (1, 1, 0):
                made[key] = xor(s0, s1)
            else:                                       # an AND of the selector lines or their inverses
                a = s0 if key in ((1, 0, 0),) else inv(s0)
                b = s1 if key in ((0, 1, 0),) else ns1
                made[key] = c.gate(a, b)
        return made[key]

    for k, d in enumerate(data):                        # k = 0 is bit 6
        key = tuple((m >> (6 - k)) & 1 for m in masks)
        if key == (0, 0, 0):
            c.outputs.append(inv(inv(d)))
        elif key == (1, 1, 1):
            c.outputs.append(inv(d))
        else:
            c.outputs.append(xor(d, selected(key)))
    return c
