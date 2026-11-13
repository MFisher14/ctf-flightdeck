#!/usr/bin/env python3
"""Serial-link captures (B-076): a `socat -v -x` hexdump log read back into the bytes each side sent,
and the XMODEM transfers inside it reassembled into the files they carried.

  .venv/bin/python solvers/toolkits/serial_capture.py <log>                    records, streams, transfers
  .venv/bin/python solvers/toolkits/serial_capture.py --out DIR <log>          also write each transfer to DIR
  .venv/bin/python solvers/toolkits/serial_capture.py --json <log>             the same as one JSON object

A socat log (`socat -v -x ...` writes it to stderr) is a list of records: a header
`> 2026/10/07 12:17:49.550551  length=132 from=0 to=131` (`>` one direction, `<` the other; `from`/`to`
the offsets of the record in its direction's stream) followed by rows of hex pairs and an ASCII column.
A row ends at 16 bytes or after a 0x0a byte, so the hex columns are read pair by pair, never counted as 16
per row, and every record is checked against its `length=` and `from`/`to`.

    parse_socat(data)  -> Log(records, notes, unparsed)
    stream(log, ">")   -> (bytes, gaps): one direction's bytes in order
    xmodem(log)        -> [Transfer]: XMODEM (128-byte SOH and 1K STX blocks, 8-bit checksum or CRC-16)
    members(data)      -> ([(name, bytes, open_it)], notes): what the sweep adds for a socat log

XMODEM, as the receiver saw it: NAK (checksum) or 'C' (CRC) starts a transfer, each block is
SOH|STX, blk, 255-blk, 128|1024 data bytes, then a checksum byte or a CRC-16/XMODEM (big-endian); a block
is kept only when its numbers and check hold AND the receiver ACKed it (a NAKed or failing block is
counted as rejected, a re-sent block already kept as a duplicate); EOT acknowledged ends the transfer and
the next NAK/'C' starts another. A block 1 (or a YMODEM block 0) the sender sends after its EOT also
starts another, whether or not the receiver ever ACKed that EOT: a receiver that leaves the EOT
unanswered and NAKs again later restarts the sender at block 1 (the Xenoglossophobia log's second
transfer); the first transfer is then marked eot_acked False. A log with no receiver side keeps the blocks whose checks hold, in
sequence, and says so. The 0x1A (SUB) padding of the last block is trimmed and counted: a file that
really ends in 0x1A bytes loses them (the count is printed). A block 0 that opens a transfer is a YMODEM
header: its file name is read, its bytes are not file data.

The sweep (ctf/sweep.py, through ctf/recover) adds each transfer as a member `socat/xmodem-<n>.<ext>`
and walks it in turn (flag search, archive walk, image and document recovery), so whatever the serial
link carried is swept like a handout file. A log with no transfer gives each direction's stream as
`socat/stream-gt.bin` / `socat/stream-lt.bin` instead (a flag cut across hexdump rows is whole there).

Output: `key = value` lines (decoded text printed as Python literals), then one SolverResult JSON
object as the last line: solved for one flag in the transfers or streams, candidate for several,
unsure when a transfer is a stego cover that harvested passphrases may open (the `next` line names the
step), none otherwise, blocked when the file is no socat log. Offline, standard library only; nothing
in the log is executed.
"""
from __future__ import annotations

import argparse
import binascii
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import event as ctf_event, flagfmt
    from ctf.result import Evidence, SolverResult
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import event as ctf_event, flagfmt
    from ctf.result import Evidence, SolverResult

ENGINE = "toolkits.serial_capture"
MAX_LOG = 256 << 20              # bytes of a log read (the sweep's own source limit)
MAX_TRANSFERS = 64
SOH, STX, EOT, ACK, NAK, CAN, CRC_START, SUB = 0x01, 0x02, 0x04, 0x06, 0x15, 0x18, 0x43, 0x1A

HEADER = re.compile(r"^([<>]) (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+length=(\d+) from=(\d+) to=(\d+)\s*$")
# One hexdump row: each byte as " %02x", then padding and two spaces before the ASCII column.
ROW = re.compile(r"^((?: [0-9a-fA-F]{2})+)(?=  |\s*$)")
HEAD_PROBE = re.compile(rb"^\s*[<>] \d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+length=\d+ from=\d+ to=\d+\s*\r?$", re.M)


@dataclass
class Record:
    direction: str               # ">" or "<"
    ts: str
    length: int
    start: int                   # from=
    end: int                     # to=
    line: int                    # 1-based line of the header
    data: bytes = b""

    @property
    def whole(self) -> bool:
        return len(self.data) == self.length and self.end - self.start + 1 == self.length


@dataclass
class Log:
    records: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    unparsed: int = 0            # lines that were neither a header, a hex row nor a separator


def looks_like_socat(data: bytes) -> bool:
    """True when the first kilobyte holds a socat record header."""
    return bool(HEAD_PROBE.search(bytes(data[:1024])))


def parse_socat(data) -> Log:
    """The records of a socat -v -x log, each with the bytes its hex rows give."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        text = bytes(data[:MAX_LOG]).decode("latin-1")
    else:
        text = str(data)
    log = Log()
    cur, rows = None, []

    def close():
        if cur is None:
            return
        cur.data = bytes(rows)
        if not cur.whole:
            log.notes.append(f"line {cur.line}: record {cur.direction} length={cur.length} from={cur.start} "
                             f"to={cur.end} holds {len(cur.data)} byte(s)")
        log.records.append(cur)

    for n, line in enumerate(text.splitlines(), 1):
        m = HEADER.match(line)
        if m:
            close()
            cur = Record(m.group(1), m.group(2), int(m.group(3)), int(m.group(4)), int(m.group(5)), n)
            rows = bytearray()
            continue
        if not line.strip() or line.strip() == "--":
            continue
        r = ROW.match(line)
        if r and cur is not None:
            rows += bytes.fromhex(r.group(1).replace(" ", ""))
        else:
            log.unparsed += 1
    close()
    if log.unparsed:
        log.notes.append(f"{log.unparsed} line(s) were neither a record header nor a hex row (a socat -v log "
                         f"without -x is not read)")
    return log


def stream(log: Log, direction: str) -> tuple[bytes, int]:
    """(bytes, gaps) of one direction in log order; a record whose `from` is not where the stream ends
    is a gap (bytes the log does not hold), counted."""
    out, gaps = bytearray(), 0
    for r in log.records:
        if r.direction != direction:
            continue
        if r.start != len(out) and r.data:
            gaps += 1
        out += r.data
    return bytes(out), gaps


# ---------------------------------------------------------------- XMODEM

def checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def crc16(data: bytes) -> int:
    """CRC-16/XMODEM (poly 0x1021, init 0)."""
    return binascii.crc_hqx(bytes(data), 0)


@dataclass
class Transfer:
    index: int
    mode: str = "unknown"        # checksum | crc | unknown (until a block settles it)
    data: bytearray = field(default_factory=bytearray)
    blocks: int = 0
    last_block: int = 0
    last_len: int = 0
    padding: int = 0
    eot: bool = False            # the sender ended the transfer with EOT
    eot_acked: bool = False      # ... and the receiver ACKed that EOT (never, with no receiver side)
    eot_sent: bool = False       # an EOT is out and not ACKed yet (a NAK of it keeps the transfer open)
    acked: bool = True          # False: the log has no receiver side; blocks kept by their checks alone
    rejected: int = 0
    duplicates: int = 0
    out_of_sequence: int = 0
    cancelled: bool = False
    ymodem_name: str | None = None
    frames: int = 0              # blocks the sender sent in this transfer, kept or not
    first_ts: str = ""
    last_ts: str = ""
    ended: bool = False

    @property
    def payload(self) -> bytes:
        return bytes(self.data)

    def kind(self) -> str:
        return extension(self.payload)

    def name(self) -> str:
        return f"xmodem-{self.index}.{self.kind()}"

    def summary(self) -> dict:
        return {"index": self.index, "name": self.name(), "mode": self.mode, "blocks": self.blocks,
                "bytes": len(self.data), "padding_trimmed": self.padding, "eot": self.eot, "eot_acked": self.eot_acked,
                "acked": self.acked,
                "rejected": self.rejected, "duplicates": self.duplicates, "out_of_sequence": self.out_of_sequence,
                "cancelled": self.cancelled, "ymodem_name": self.ymodem_name, "first": self.first_ts,
                "last": self.last_ts}


def extension(data: bytes) -> str:
    d = bytes(data[:16])
    for magic, ext in ((b"\xff\xd8\xff", "jpg"), (b"\x89PNG", "png"), (b"GIF8", "gif"), (b"%PDF", "pdf"),
                       (b"PK\x03\x04", "zip"), (b"7z\xbc\xaf", "7z"), (b"\x1f\x8b", "gz"), (b"BM", "bmp"),
                       (b".snd", "au"), (b"Rar!", "rar"), (b"\x7fELF", "elf")):
        if d.startswith(magic):
            return ext
    if d[:4] == b"RIFF" and d[8:12] == b"WAVE":
        return "wav"
    head = bytes(data[:4096])
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError as e:     # a character cut at the 4096-byte edge is still text
        text = head[:e.start].decode("utf-8") if len(data) > len(head) and e.start >= len(head) - 3 else None
    if text and all(c.isprintable() or c in "\t\r\n" for c in text):
        return "txt"
    return "bin"


def _frame_at(buf: bytearray, mode: str, prefer: str = "checksum"):
    """(consumed, block, data, check_mode, ok) of the frame at buf[0], or None while more bytes are needed.
    ok False with consumed 1: not a frame (blk + ~blk do not add to 255). With mode "unknown" both checks
    are tried, `prefer` first."""
    size = 1024 if buf[0] == STX else 128
    if len(buf) < 3:
        return None
    if (buf[1] + buf[2]) & 0xFF != 0xFF:
        return 1, None, None, mode, False
    body_end = 3 + size
    modes = (mode,) if mode in ("checksum", "crc") else \
        (("crc", "checksum") if prefer == "crc" else ("checksum", "crc"))
    for m in modes:
        need = body_end + (1 if m == "checksum" else 2)
        if len(buf) < need:
            if m == modes[-1]:
                return None
            continue
        data = bytes(buf[3:body_end])
        ok = (buf[body_end] == checksum(data)) if m == "checksum" else \
            (int.from_bytes(buf[body_end:body_end + 2], "big") == crc16(data))
        if ok:
            return need, buf[1], data, m, True
    # numbers hold, check fails: a damaged block (the receiver NAKs it)
    m = modes[0]
    return body_end + (1 if m == "checksum" else 2), buf[1], None, m, False


class _Xmodem:
    def __init__(self, receiver_side: bool):
        self.rx = receiver_side
        self.transfers: list[Transfer] = []
        self.cur: Transfer | None = None
        self.pending = None          # ("block", n, data, ts) | ("eot", ts)
        self.restart = None          # the mode of a NAK/'C' that answered a pending EOT (a retry or a restart)
        self.buf = bytearray()
        self.junk = 0
        self.notes: list[str] = []

    def _open(self, mode: str, ts: str) -> Transfer | None:
        if len(self.transfers) >= MAX_TRANSFERS:
            if self.cur is not None and not self.cur.ended:
                return self.cur
            self.notes.append(f"more than {MAX_TRANSFERS} transfers: the rest are not read")
            return None
        t = Transfer(len(self.transfers) + 1, mode=mode, acked=self.rx, first_ts=ts, last_ts=ts)
        self.transfers.append(t)
        self.cur = t
        return t

    def _keep(self, n: int, data: bytes, ts: str):
        t = self.cur
        if t is None or t.ended:
            t = self._open("unknown", ts)
            if t is None:
                return
        expected = (t.last_block + 1) & 0xFF
        if n == 0 and t.blocks == 0 and t.ymodem_name is None:
            name = data.split(b"\x00", 1)[0]
            t.ymodem_name = name.decode("latin-1") if name else ""
        elif n == expected:
            t.data += data
            t.blocks += 1
            t.last_block, t.last_len = n, len(data)
        elif t.blocks and n == t.last_block:
            t.duplicates += 1
        else:
            t.out_of_sequence += 1
        t.last_ts = ts

    def receiver(self, data: bytes, ts: str):
        for b in data:
            if b in (NAK, CRC_START):
                mode = "crc" if b == CRC_START else "checksum"
                if self.pending is not None:
                    if self.pending[0] == "block" and self.cur is not None:
                        self.cur.rejected += 1
                    else:            # a NAK of the EOT: the sender re-sends it, or restarts at block 1
                        self.restart = mode
                    self.pending = None
                    continue
                if self.cur is None or self.cur.ended:
                    self._open(mode, ts)
                elif self.cur.frames == 0:
                    self.cur.mode = mode     # the receiver's start, repeated (or changed) before any block
            elif b == ACK:
                p, self.pending = self.pending, None
                if p is None:
                    continue
                if p[0] == "block":
                    self._keep(p[1], p[2], ts)
                elif self.cur is not None:
                    self.cur.eot, self.cur.eot_acked, self.cur.ended, self.cur.last_ts = True, True, True, ts
                    self.cur.eot_sent, self.restart = False, None
            elif b == CAN and self.cur is not None and not self.cur.ended:
                self.cur.cancelled, self.cur.ended = True, True
                self.pending = None

    def sender(self, data: bytes, ts: str):
        self.buf += data
        while self.buf:
            b = self.buf[0]
            if b in (SOH, STX):
                after_eot = self.cur is not None and not self.cur.ended and self.cur.eot_sent
                if after_eot:       # past an unanswered EOT: a new transfer may use the other check
                    mode, prefer = "unknown", self.restart or self.cur.mode
                else:
                    mode = self.cur.mode if self.cur is not None and not self.cur.ended else "unknown"
                    prefer = "checksum"
                got = _frame_at(self.buf, mode, prefer)
                if got is None:
                    return
                used, n, block, m, ok = got
                del self.buf[:used]
                if n is None:
                    self.junk += 1
                    continue
                if not ok:
                    if self.cur is not None:
                        self.cur.rejected += 1
                        self.cur.frames += 1
                    continue
                if after_eot and n in (0, 1):
                    self._restart(ts)
                if self.cur is None or self.cur.ended:
                    if self._open(m, ts) is None:
                        return
                if self.cur.mode == "unknown":
                    self.cur.mode = m
                self.cur.frames += 1
                if self.pending is not None and self.pending[0] == "block" and self.cur is not None:
                    self.cur.rejected += 1          # a block sent again with no answer to the last in the log
                if self.rx:
                    self.pending = ("block", n, block, ts)
                else:
                    self._keep(n, block, ts)
            elif b == EOT:
                del self.buf[:1]
                if self.cur is None or self.cur.ended:
                    continue
                self.cur.eot_sent = True
                if self.rx:
                    self.pending = ("eot", ts)
                else:
                    self.cur.eot, self.cur.ended, self.cur.last_ts = True, True, ts
            elif b == CAN:
                del self.buf[:1]
                if self.cur is not None and not self.cur.ended:
                    self.cur.cancelled, self.cur.ended = True, True
            else:
                del self.buf[:1]
                self.junk += 1

    def _restart(self, ts: str):
        """A block 1 (or 0) after the current transfer's EOT, which the receiver never ACKed: the sender
        has finished that transfer and starts the next one."""
        t = self.cur
        t.eot, t.ended, t.eot_sent = True, True, False
        self.pending, self.restart = None, None
        self.notes.append(f"transfer {t.index}: the receiver never ACKed its EOT; the block sent after it "
                          f"({ts}) starts the next transfer")

    def finish(self) -> list[Transfer]:
        if self.buf:
            self.notes.append(f"{len(self.buf)} byte(s) of the sender's stream end inside a block")
        if self.junk:
            self.notes.append(f"{self.junk} sender byte(s) outside any XMODEM block")
        out = []
        for t in self.transfers:
            if t.eot_sent and not t.ended:    # the log ends on an EOT the receiver never ACKed
                t.eot, t.eot_sent = True, False
                self.notes.append(f"transfer {t.index}: the log ends with its EOT never ACKed")
            if not t.blocks:
                continue                      # a NAK/'C' with nothing sent after it
            if t.last_len:
                tail = t.data[len(t.data) - t.last_len:]
                keep = len(tail.rstrip(bytes([SUB])))
                t.padding = t.last_len - keep
                if t.padding:
                    del t.data[len(t.data) - t.padding:]
            out.append(t)
        for i, t in enumerate(out, 1):
            t.index = i
        return out


def _block_count(d: bytes) -> int:
    n, i = 0, 0
    while True:
        i = min((x for x in (d.find(b"\x01", i), d.find(b"\x02", i)) if x >= 0), default=-1)
        if i < 0 or i + 3 > len(d):
            return n
        got = _frame_at(bytearray(d[i:i + 1030]), "unknown")
        if got is not None and got[4]:
            n += 1
            i += got[0]
        else:
            i += 1


def sender_side(log: Log) -> str | None:
    """The direction that carries XMODEM blocks (more blocks whose checks hold), or None."""
    counts = {d: _block_count(stream(log, d)[0]) for d in (">", "<")}
    best = max(counts, key=counts.get)
    return best if counts[best] else None


def xmodem(log: Log) -> tuple[list[Transfer], list[str]]:
    """([Transfer], notes) of every XMODEM transfer in the log, in order."""
    side = sender_side(log)
    if side is None:
        return [], []
    other = "<" if side == ">" else ">"
    rx = any(r.direction == other and r.data for r in log.records)
    x = _Xmodem(rx)
    for r in log.records:
        (x.sender if r.direction == side else x.receiver)(r.data, r.ts)
    out = x.finish()
    notes = list(x.notes)
    if not rx:
        notes.append("the log holds no receiver side: blocks were kept by their checks alone, not by ACKs")
    return out, notes


def members(data: bytes) -> tuple[list, list]:
    """([(name, bytes, open_it)], notes): what a socat log gives the sweep. [] for anything else."""
    if not looks_like_socat(data):
        return [], []
    log = parse_socat(data)
    if not log.records:
        return [], log.notes
    notes = [f"socat log: {len(log.records)} record(s) "
             f"({sum(r.direction == '>' for r in log.records)} '>', {sum(r.direction == '<' for r in log.records)} '<')"]
    notes += log.notes[:20]
    transfers, xnotes = xmodem(log)
    notes += xnotes
    out = []
    for t in transfers:
        out.append((f"socat/{t.name()}", t.payload, True))
        notes.append(f"XMODEM transfer {t.index} ({t.mode}): {t.blocks} block(s) -> socat/{t.name()} "
                     f"({len(t.data)} bytes, {t.padding} padding byte(s) trimmed"
                     + ((", ended by EOT" + ("" if t.eot_acked or not t.acked else " (never ACKed)"))
                        if t.eot else ", no EOT") + ")")
    if not transfers:
        for d, tag in ((">", "gt"), ("<", "lt")):
            body, gaps = stream(log, d)
            if body:
                out.append((f"socat/stream-{tag}.bin", body, True))
                if gaps:
                    notes.append(f"direction {d}: {gaps} gap(s) in the stream (records missing from the log)")
    return out, notes


# ---------------------------------------------------------------- the command

def _flags(ff, data: bytes) -> list[str]:
    return ff.find_flags(bytes(data)) if ff is not None else []


def report(path: Path, ff, out_dir: Path | None = None) -> dict:
    raw = path.read_bytes()[:MAX_LOG]
    if not looks_like_socat(raw):
        return {"file": path.name, "socat": False}
    log = parse_socat(raw)
    transfers, xnotes = xmodem(log)
    res = {"file": path.name, "socat": True, "records": len(log.records),
           "directions": {d: sum(r.direction == d for r in log.records) for d in (">", "<")},
           "unwhole": sum(not r.whole for r in log.records), "notes": log.notes + xnotes,
           "transfers": [], "streams": [], "flags": [], "written": []}
    texts = []
    for t in transfers:
        s = t.summary()
        s["flags"] = _flags(ff, t.payload)
        if t.kind() == "txt":
            s["text"] = t.payload[:2000].decode("utf-8", "replace")
            texts.append(s["text"])
        res["transfers"].append(s)
        res["flags"] += [(f, t.name()) for f in s["flags"]]
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / t.name()).write_bytes(t.payload)
            res["written"].append(t.name())
    if not transfers:
        for d, tag in ((">", "gt"), ("<", "lt")):
            body, gaps = stream(log, d)
            if body:
                res["streams"].append({"direction": d, "bytes": len(body), "gaps": gaps})
                res["flags"] += [(f, f"stream {d}") for f in _flags(ff, body)]
    covers = [t for t in transfers if t.kind() in COVER_KINDS]
    res["covers"] = [t.name() for t in covers]
    res["passphrases"] = _passphrases(texts) if covers else []
    return res


COVER_KINDS = ("jpg", "bmp", "wav", "au")       # what steghide embeds in


def _passphrases(texts) -> list[str]:
    """Quoted strings of the transfers that are text: the passphrase harvest's first source."""
    try:
        here = str(Path(__file__).resolve().parent)
        if here not in sys.path:
            sys.path.insert(1, here)
        import passphrase_harvest
    except ImportError as e:            # named, never silent
        return [f"<passphrase_harvest not loaded: {e}>"]
    out = []
    for t in texts:
        for q in passphrase_harvest.quoted(t):
            if q not in out:
                out.append(q)
    return out


def render(res: dict) -> list[str]:
    if not res.get("socat"):
        return [f"== {res['file']}: not a socat -v -x log"]
    lines = [f"== {res['file']}: socat log, {res['records']} record(s) "
             f"({res['directions']['>']} '>', {res['directions']['<']} '<'), {res['unwhole']} not whole"]
    for n in res["notes"][:20]:
        lines.append(f"note = {n}")
    for t in res["transfers"]:
        lines.append(f"transfer = {t['name']} mode={t['mode']} blocks={t['blocks']} bytes={t['bytes']} "
                     f"padding={t['padding_trimmed']} eot={t['eot']} eot_acked={t['eot_acked']} acked={t['acked']} "
                     f"rejected={t['rejected']} "
                     f"duplicates={t['duplicates']}")
        if "text" in t:
            lines.append(f"transfer.text = {t['text'][:400]!r}")
    for s in res["streams"]:
        lines.append(f"stream = {s['direction']} {s['bytes']} bytes, {s['gaps']} gap(s)")
    for f, where in res["flags"]:
        lines.append(f"flag = {f!r} in {where}")
    for w in res.get("written", []):
        lines.append(f"written = {w}")
    if res["covers"]:
        lines.append(f"cover = {', '.join(res['covers'])} (steghide-capable)")
        lines.append(f"passphrases = {res['passphrases']!r}")
        lines.append("next = python solvers/toolkits/passphrase_harvest.py --steghide <the cover as written>"
                     " (the sandbox runs steghide; intake does not)")
    return lines


def solver_result(res: dict) -> SolverResult:
    if not res.get("socat"):
        return SolverResult("blocked", engine=ENGINE, notes=f"{res['file']}: not a socat -v -x log")
    found = list(dict.fromkeys(f for f, _ in res["flags"]))
    summary = (f"{res['file']}: {res['records']} socat record(s), {len(res['transfers'])} XMODEM transfer(s)"
               + "".join(f"; {t['name']} {t['bytes']} bytes" for t in res["transfers"][:6]))
    if found:
        ev = [Evidence("decode", f"{f} in {where} of the serial log", path=res["file"]) for f, where in res["flags"][:8]]
        return SolverResult("solved" if len(found) == 1 else "candidate", flags=found[:32], evidence=ev,
                            engine=ENGINE, notes=summary)
    if res["covers"] and res["passphrases"]:
        return SolverResult("unsure", engine=ENGINE,
                            notes=f"{summary}; steghide cover(s) {', '.join(res['covers'])} with "
                                  f"{len(res['passphrases'])} quoted passphrase candidate(s): run passphrase_harvest.py --steghide")
    return SolverResult("none", engine=ENGINE, notes=summary)


def _format():
    try:
        return flagfmt.current()
    except ctf_event.EventError as e:
        print(f"note = no event flag format ({e}): flags are not searched", flush=True)
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="serial_capture.py", description="socat -v -x serial log reader and XMODEM reassembly (B-076)")
    ap.add_argument("log")
    ap.add_argument("--out", default=None, help="write each XMODEM transfer to this folder")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    path = Path(a.log)
    if not path.is_file():
        print(f"serial_capture.py: no such file: {a.log}", file=sys.stderr)
        return 2
    ff = _format()
    res = report(path, ff, Path(a.out) if a.out else None)
    if a.json:
        print(json.dumps(res, indent=1, default=str))
    else:
        for line in render(res):
            print(line, flush=True)
    print(solver_result(res).to_json(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
