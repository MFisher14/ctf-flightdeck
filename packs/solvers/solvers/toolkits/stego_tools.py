#!/usr/bin/env python3
"""The sandbox side of `carve_stego` (backlog row 147): the stego, picture, audio, PDF, carving,
radio and disassembly programs of the image csctf-sandbox:2, each as one function.

  .venv/bin/python solvers/toolkits/stego_tools.py <file>... [--pass P]... [--wordlist FILE] [--sstv]
                                                   [--extract DIR] [--json]
  .venv/bin/python solvers/toolkits/stego_tools.py --tools          what the sandbox can run now

prints, per file, what each fitting program found: metadata, hidden-data capacity and payloads,
codes, recognised text, decoded tones, carved files. --extract writes every recovered payload,
picture and carved file under DIR. An agent's tool, off the clock: nothing here is a solver.

Everything runs inside the container of tools/sandbox.py (no network, read-only root, limits) by
`docker exec`; the bytes are copied in for the call and nothing is ever run on this Mac. When the
sandbox is down, or holds only the image csctf-sandbox:1, a call returns ok=False with the
reason in .note ("sandbox down: ...: not read") and the file counts as not read.

Never on a timed path. A call made while a clock runs (judge.clock(), or the replay child of
tools/preflight.py) returns ok=False, "on a timed path: not run", and makes no docker call.

Never guessing (AGENTS.md "Uncertain answers"). There is no solve_set here and no registry row:
these are findings for the lane's agent. What a finding may become:
  - a payload a program extracted whole under a passphrase the question states AND checked itself
    (steghide and stegseek: a CRC-32 over the payload; a PDF that IS encrypted and opens with the
    stated password), a QR or barcode text, DTMF digits, a POCSAG or AX.25 frame, an EXIF
    field: a fact read from the bytes. Its NAME or FORM is still unjudged in this category, so it
    goes to the judge as labels.pick, or by hand with `tools/verify.py --answers`.
  - OutGuess and SNOW have no check: a wrong key, or a file with nothing in it, still gives bytes
    (SNOW's are always letters). Their output is evidence, as are OCR text, a spectrogram read, an
    SSTV picture, zsteg's guesses and a decompiler's C: not a fact. Two tools or two readings
    that agree make a candidate; one alone is None.
  - a failure is a reading only when the program read the file: "the cover was not read whole",
    "not read" and "sandbox down" say nothing about the passphrase, the password or the content.
  - a value the caller hands over (passphrase, password, key, script, filter) reaches the program
    as written (sandbox.Lit): `flag{in}` is a passphrase, not the sandbox's {in} placeholder.
  - a passphrase is tried only when the question or the delivery states it. stegseek() takes the
    word list the QUESTION supplies (at most MAX_WORDS words) and nothing else: no rockyou, no
    generated list, and never an archive password (the project rule; those are asked of the player
    and stored with tools/password.py).

Each function takes bytes and returns a Rec:
  .ok      the program ran and did what was asked
  .text    its output as text (stdout, or the recovered text)
  .files   {name: bytes} it wrote (a payload, pictures, carved files)
  .data    a parsed value where there is one (a dict, a list), else None
  .note    one line: what happened, or why not
  .code    the program's exit status (None when it did not run)

  steghide_info(data, passphrase="")        capacity, and the embedded file's name when the passphrase opens it
  steghide_extract(data, passphrase="")     the embedded file (JPEG, BMP, WAV, AU)
  stegseek(data, words)                     the one word of the question's list that opens it, and the payload
  stegseek_seed(data)                       stegseek --seed: steghide data found with no passphrase (B-182)
  no_start()                                a block in which a call uses only a container already up (B-182)
  outguess_extract(data, key=None)          OutGuess payload of a JPEG or PNM
  jpeg_survey(data)                         JPEG DCT-coefficient LSB (jsteg variants) + pixel bit planes, in-process
  zsteg(data, everything=False)             LSB and trailing-data findings of a PNG or BMP, parsed
  stegsnow(data, password=None)             SNOW whitespace message of a text file
  exif(data, name="file")                   exiftool's JSON as a dict (every group, duplicates kept)
  pngcheck(data)                            chunk listing and CRC verdict
  ocr(data, psm=6, whitelist=None)          tesseract's text of a picture
  codes(data)                               [(symbology, text)] zbar reads in a picture
  pdf_info / pdf_text / pdf_images / pdf_attachments / pdf_decrypt(data, password) / pdf_qdf
  media_info(data)                          ffprobe's JSON
  to_wav(data, rate=22050, channels=1)      any audio or video container to 16-bit PCM WAV
  frames(data, fps=1, limit=20)             video frames as PNG
  spectrogram(data, width=1200, height=513, top_hz=None)   a spectrogram picture (sox), raw: no axes
  spectrogram_text(data, ...)               OCR of that picture (both polarities; to 8 kHz unless top_hz says more)
  render_sweep(name, data)                  in-process, no sandbox: spectrogram to Nyquist in bands + 5x7 glyphs; bit planes 0-2 rendered and read
  sstv_decode(data)                         the picture an SSTV recording carries (PNG)
  multimon(data, modes=("DTMF",))           multimon-ng's decoded lines (DTMF, AFSK1200, POCSAG512/1200/2400, ...)
  minimodem(data, baud=1200)                Bell/RTTY FSK text
  rtl433(data, name="g.cu8", rate=250000, flex=None, analyze=False)   rtl_433's JSON rows of an IQ file
  foremost(data) / scalpel-free carving, bulk_extractor(data)        carved files; feature files
  tsk(data, tool="fls", args=("-r", "-p"))  sleuthkit on a disk image (mmls, fsstat, fls, icat, tsk_recover)
  r2(data, commands, analyze="aa")          radare2 commands on a file, quiet, no colour
  decompile(data, function="main")          r2ghidra's C of one function (pdg)
  py(script, inputs=())                     a script of yours under the image's python3 -I
  survey(name, data, passphrases=(), words=None, sstv=False)   every fitting program on one file
"""
import contextlib
import functools
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent.parent / "tools"
KEY = "stego_tools"
MAX_WORDS = 20000           # a question's word list longer than this is not tried: that is a brute force
MAX_WORD = 256              # bytes of one word
NEEDS = "csctf-sandbox:2"


# 128 + a signal that ends a program before it is done: HUP INT QUIT ILL TRAP ABRT BUS FPE USR1 SEGV
# USR2 PIPE ALRM TERM XCPU XFSZ (the container's file-size limit: zbarimg on a huge picture) SYS.
# 137 (KILL) has its own line. ffmpeg's own statuses (183, 234 ...) are not among them.
DIED = tuple(128 + n for n in (1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 24, 25, 31))


class Rec:
    """One call's result (see the module text)."""

    def __init__(self, ok=False, text="", files=None, data=None, note="", code=None, tool=""):
        self.ok, self.text, self.files, self.data = ok, text, dict(files or {}), data
        self.note, self.code, self.tool = note, code, tool
        self.abnormal = ""          # set when the program was stopped, killed or crashed: not a reading
        self.raw = b""              # the program's stdout as bytes (text is its lossy decoding)

    def __repr__(self):
        return f"Rec(ok={self.ok}, tool={self.tool!r}, note={self.note!r}, files={sorted(self.files)}, text={self.text[:80]!r})"

    def __bool__(self):
        return bool(self.ok)


def _guard(fn):
    """A reader whose program was stopped at its time limit, killed, crashed or left too much says
    exactly that: ok=False, no data, no files, the reason ending ': not read'. Never 'nothing found'."""
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        r = fn(*args, **kwargs)
        if getattr(r, "abnormal", ""):
            r.ok, r.data, r.files, r.note = False, None, {}, r.abnormal
        return r
    return inner


def on_timed_path() -> bool:
    """True inside a timed window (this process holds judge.clock()) or in the replay child of
    tools/preflight.py: the same test as solvers/binary/facts.on_timed_path."""
    judge = sys.modules.get("judge")
    if judge is not None and getattr(judge, "_clock_depth", 0):
        return True
    return Path(sys.argv[0] if sys.argv else "").name == "preflight.py" and sys.argv[1:2] == ["--child"]


def _sandbox():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    import sandbox
    return sandbox


def _text(b) -> str:
    return (b or b"").decode("utf-8", "replace")


def _lit(value):
    """A value the caller did not write (a passphrase, a password, a key, a script, a filter) as an
    argument the sandbox passes on as written: `{in}` and `{out}` inside it are not placeholders."""
    try:
        return _sandbox().Lit(str(value))
    except Exception:           # no tools/sandbox.py: call() says so
        return str(value)


def _said(r, *expected) -> str:
    """What the program said besides its usual lines (a warning about the file itself, as 'Premature
    end of JPEG file'): '' when it said nothing else."""
    lines = [x.strip() for x in (getattr(r, "stderr", "") + "\n" + r.text).splitlines() if x.strip()]
    odd = [x for x in lines if not any(e in x for e in expected)]
    return odd[0][:160] if odd else ""


_START = [True]             # B-182: False while no_start() holds: a call never starts a container


@contextlib.contextmanager
def no_start():
    """Within this block a call only uses a sandbox container that is already up and fit
    (tools/sandbox.py run(start=False)); none is started, built or pulled. With none up, the call
    returns ok=False, 'sandbox down: not started ...: not read' (B-182, stego_exhaust)."""
    held = _START[0]
    _START[0] = False
    try:
        yield
    finally:
        _START[0] = held


def call(tool: str, args, inputs=(), timeout: float = 60.0, ok_codes=(0,)) -> Rec:
    """One program in the sandbox. inputs: (name, bytes) pairs; {in}, {in0}.., {out} in args as in
    tools/sandbox.py. ok is True when the exit status is in ok_codes. Never raises."""
    if on_timed_path():
        return Rec(note="on a timed path: not run", tool=tool)
    try:
        sb = _sandbox()
    except Exception as e:
        return Rec(note=f"sandbox down: tools/sandbox.py cannot be loaded ({type(e).__name__}): not read", tool=tool)
    try:
        r = sb.run(tool, [a if isinstance(a, str) else str(a) for a in args], inputs=list(inputs), timeout=timeout,
                   start=_START[0])
    except sb.SandboxDown as e:
        return Rec(note=f"sandbox down: {e}: not read", tool=tool)
    except Exception as e:
        return Rec(note=f"sandbox down: {type(e).__name__}: {e}: not read", tool=tool)
    out, err = _text(r.stdout), _text(r.stderr)
    rec = Rec(ok=r.code in ok_codes, text=out, files=r.files, code=r.code, tool=tool)
    rec.stderr, rec.raw = err, r.stdout or b""
    if r.timed_out:
        rec.ok, rec.note = False, f"{tool} was stopped after {timeout:g} s: not read"
    elif r.note:
        rec.ok, rec.note = False, f"{r.note}: not read"
    elif r.code == 137:
        rec.ok, rec.note = False, f"{tool} was killed (exit 137: the container's memory limit, most likely): not read"
    elif r.code in DIED:
        rec.ok, rec.note = False, f"{tool} crashed (exit {r.code}, signal {r.code - 128}): not read"
    if rec.note.endswith(": not read"):
        rec.abnormal = rec.note         # the program did not finish: whatever it left is no reading (_guard)
    elif not rec.ok:
        last = [x for x in (err or out).strip().splitlines() if x.strip()]
        rec.note = f"{tool} exit {r.code}" + (f": {last[-1].strip()[:200]}" if last else "")
    return rec


def available() -> Rec:
    """Which image the sandbox would use now and whether its tools are these (.data: the image tag)."""
    try:
        sb = _sandbox()
        ok, detail = sb.health()
        gen = sb.choose()
    except Exception as e:
        return Rec(note=f"sandbox down: {type(e).__name__}: {e}")
    if gen.image != NEEDS:
        return Rec(note=f"{NEEDS} is not built (tools/sandbox.py build): only the tools of {gen.image} run", data=gen.image)
    return Rec(ok=ok, note=detail, data=gen.image)


def _name(data: bytes, default: str = "file") -> str:
    """A file name with the extension its magic gives: several programs go by the extension."""
    d = data[:16]
    for magic, ext in ((b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"BM", "bmp"), (b"GIF8", "gif"),
                       (b"%PDF", "pdf"), (b"fLaC", "flac"), (b"OggS", "ogg"), (b"ID3", "mp3"), (b".snd", "au"),
                       (b"II*\0", "tif"), (b"MM\0*", "tif"), (b"\x1aE\xdf\xa3", "mkv")):
        if d.startswith(magic):
            return f"{default}.{ext}"
    if d[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return f"{default}.wav"
    if d[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return f"{default}.avi"
    if d[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return f"{default}.webp"
    if data[4:8] == b"ftyp":
        return f"{default}.mp4"
    return f"{default}.bin"


# ---- steghide, stegseek, outguess, zsteg, stegsnow ---------------------------------------------------------

@_guard
def steghide_info(data: bytes, passphrase: str = "") -> Rec:
    """`steghide info` under one passphrase ('' is the empty passphrase, which is a real one). .data:
    {format, capacity, embedded: name or None, size, encrypted, compressed}. ok is True when the
    cover was read; `embedded` is set only when the passphrase opened it. A wrong passphrase and a
    file with nothing in it look the same to steghide: embedded None says only 'not with this'."""
    r = call("steghide", ["info", "-p", _lit(passphrase), "{in}"], [(_name(data, "cover"), data)], ok_codes=(0, 1))
    text = r.text + getattr(r, "stderr", "")
    info = {"format": None, "capacity": None, "embedded": None, "size": None, "encrypted": None, "compressed": None}
    m = re.search(r"format:\s*(.+)", text)
    info["format"] = m.group(1).strip() if m else None
    m = re.search(r"capacity:\s*(.+)", text)
    info["capacity"] = m.group(1).strip() if m else None
    m = re.search(r'embedded file "([^"]*)"', text)
    if m:
        info["embedded"] = m.group(1)
    elif "embedded data" in text:
        info["embedded"] = ""
    m = re.search(r"size:\s*(.+)", text)
    info["size"] = m.group(1).strip() if m else None
    m = re.search(r"encrypted:\s*(.+)", text)
    info["encrypted"] = m.group(1).strip() if m else None
    m = re.search(r"compressed:\s*(.+)", text)
    info["compressed"] = m.group(1).strip() if m else None
    r.data = info
    if r.code is not None:
        r.ok = info["format"] is not None
        odd = _said(r, "format:", "capacity:", "could not extract any data", "embedded ", "size:", "encrypted:", "compressed:", '":')
        r.note = (f"steghide: embedded file {info['embedded']!r} under this passphrase" if info["embedded"] is not None
                  else f"steghide: nothing opened with this passphrase, and the cover is damaged ({odd}): no reading of the passphrase" if r.ok and odd
                  else "steghide: nothing opened with this passphrase" if r.ok
                  else "steghide: " + (text.strip().splitlines() or ["not a cover it reads"])[-1][:160])
    return r


@_guard
def steghide_extract(data: bytes, passphrase: str = "") -> Rec:
    """The file steghide embedded, under one passphrase: .files {'payload': bytes}, .data the bytes."""
    r = call("steghide", ["extract", "-sf", "{in}", "-p", _lit(passphrase), "-xf", "{out}/payload", "-f"],
             [(_name(data, "cover"), data)])
    got = r.files.get("payload")
    r.ok = r.code == 0 and got is not None
    r.data = got if r.ok else None
    if r.code is not None:
        # "could not extract any data with that passphrase" is steghide's one line for a wrong
        # passphrase and for an empty cover. Anything else it said is about the file (not a format
        # it reads, a JPEG cut short): then the failure is no reading of the passphrase at all.
        odd = "" if r.ok else _said(r, "could not extract any data")
        r.note = (f"steghide: {len(got)} bytes extracted" if r.ok
                  else f"steghide: the cover was not read whole ({odd}): no reading of the passphrase" if odd
                  else "steghide: nothing extracted with this passphrase")
    return r


def clean_words(words) -> list:
    """The question's word list as stegseek gets it: text lines, no blanks, no duplicates, order kept."""
    if isinstance(words, (bytes, bytearray)):
        words = bytes(words).decode("utf-8", "replace")
    if isinstance(words, str):
        words = words.splitlines()
    out, seen = [], set()
    for w in words:
        w = str(w).rstrip("\r\n")
        if w and w not in seen and len(w.encode("utf-8")) <= MAX_WORD and "\n" not in w and "\r" not in w:
            seen.add(w)
            out.append(w)
    return out


@_guard
def stegseek(data: bytes, words) -> Rec:
    """Try the words THE QUESTION SUPPLIES as steghide passphrases (stegseek --crack). .data:
    {'passphrase': word, 'name': embedded name} when exactly this list opened it; .files
    {'payload': bytes}. A list of more than MAX_WORDS words, or no list, is refused: this is not a
    brute force, and never the way to an archive password."""
    words = clean_words(words)
    if not words:
        return Rec(note="stegseek: no word list (it takes the one the question supplies, nothing else)", tool="stegseek")
    if len(words) > MAX_WORDS:
        return Rec(note=f"stegseek: {len(words)} words is a brute force (limit {MAX_WORDS}): refused", tool="stegseek")
    wl = ("\n".join(words) + "\n").encode("utf-8")
    r = call("stegseek", ["--crack", "-sf", "{in0}", "-wl", "{in1}", "-xf", "{out}/payload", "-f"],
             [(_name(data, "cover"), data), ("words.txt", wl)], timeout=120, ok_codes=(0, 1))
    text = r.text + getattr(r, "stderr", "")
    m = re.search(r'Found passphrase: "(.*)"', text)
    name = re.search(r'Original filename: "(.*)"', text)
    got = r.files.get("payload")
    r.ok = bool(m) and got is not None
    r.data = {"passphrase": m.group(1), "name": name.group(1) if name else None} if r.ok else None
    if r.code is not None:
        odd = "" if r.ok else _said(r, "StegSeek ", "Could not find a valid passphrase", "Progress:")
        r.note = (f"stegseek: opened by {m.group(1)!r} of the {len(words)} supplied words, {len(got)} bytes" if r.ok
                  else f"stegseek: the cover was not read whole ({odd}): no reading of the {len(words)} supplied words" if odd
                  else f"stegseek: none of the {len(words)} supplied words opens it")
    return r


_SEED = re.compile(r'Found \(possible\) seed:\s*"?([0-9A-Fa-f]{1,8})"?')
_NO_SEED = "Could not find a valid seed"


@_guard
def stegseek_seed(data: bytes) -> Rec:
    """`stegseek --seed` (B-182): whether steghide hid data in a JPEG, BMP, WAV or AU cover, found by
    trying steghide's whole 32-bit seed space, so with no passphrase and no word list. ok is True when
    stegseek gave its verdict: .data None when it found no seed (no steghide data in this cover),
    else {'seed', 'size', 'algorithm', 'name'}; .files {'payload': bytes} when the data was not
    encrypted and stegseek wrote it out (encrypted data still needs its passphrase). Output in any
    other form is ok=False with the reason: never read as 'no seed'."""
    r = call("stegseek", ["--seed", "-sf", "{in}", "-xf", "{out}/payload", "-f"], [(_name(data, "cover"), data)],
             timeout=600, ok_codes=(0, 1))
    if r.code is None:
        return r
    text = r.text + getattr(r, "stderr", "")
    m = _SEED.search(text)
    if m:
        size = re.search(r"Plain size:\s*(.+)", text)
        alg = re.search(r"Encryption Algorithm:\s*(\S+)", text)
        name = re.search(r'Original filename:\s*"(.*)"', text)
        r.ok = True
        r.data = {"seed": m.group(1).lower(), "size": size.group(1).strip() if size else None,
                  "algorithm": alg.group(1) if alg else None, "name": name.group(1) if name else None}
        got = r.files.get("payload")
        r.note = (f"stegseek --seed: steghide data (seed {r.data['seed']}), {len(got)} bytes extracted" if got is not None
                  else f"stegseek --seed: steghide data (seed {r.data['seed']}, encryption "
                       f"{r.data['algorithm'] or 'unknown'}), not extracted: it needs the passphrase")
    elif _NO_SEED in text:
        r.ok, r.data, r.files = True, None, {}
        r.note = "stegseek --seed: no steghide seed in this cover"
    else:
        last = [x for x in text.strip().splitlines() if x.strip()]
        r.ok, r.data, r.files = False, None, {}
        r.note = f"stegseek --seed: output not understood (exit {r.code}" + (f": {last[-1][:160]}" if last else "") + ")"
    return r


@_guard
def outguess_extract(data: bytes, key: str = None) -> Rec:
    """OutGuess's payload of a JPEG or PNM, with the key the question states (None: the default key).
    OutGuess has no check of its own and always writes something: bytes that are not text or a
    known format are noise, and .data['plausible'] says which (printable text, or a recognised
    magic). Evidence, never a proof that the key is right or that anything was embedded."""
    args = ["-r"] + (["-k", _lit(key)] if key is not None else []) + ["{in}", "{out}/payload"]
    r = call("outguess", args, [(_name(data, "cover"), data)])
    got = r.files.get("payload")
    r.ok = r.code == 0 and bool(got)
    plausible = bool(got) and (_printable(got) or _name(got, "x") != "x.bin")
    r.data = {"payload": got, "plausible": plausible} if r.ok else None
    if r.code is not None:
        r.note = (f"outguess: {len(got)} bytes, {'plausible (OutGuess has no check: evidence, not proof)' if plausible else 'noise by the look of it: probably nothing embedded or a wrong key'}"
                  if r.ok else "outguess: nothing extracted" + (f" ({_said(r, 'Reading ', 'Extracting usable bits')})" if _said(r, 'Reading ', 'Extracting usable bits') else ""))
    return r


def _printable(b: bytes) -> bool:
    if not b:
        return False
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(c.isprintable() or c in "\r\n\t" for c in s)


@_guard
def zsteg(data: bytes, everything: bool = False) -> Rec:
    """zsteg's findings of a PNG or BMP. .data: [{'channel': 'b1,rgb,lsb,xy', 'kind': 'text'|'file'|
    'other', 'value': ...}]. zsteg reports whatever looks like text or a file in ANY bit plane, so a
    line is a lead to confirm (carve_stego.lsb_extract with the same plane), never an answer."""
    r = call("zsteg", (["-a"] if everything else []) + ["--no-color", "{in}"], [(_name(data, "img"), data)],
             timeout=180 if everything else 60)
    rows = []
    refused = re.search(r"^\[!\] .*$", r.text, re.M)       # '[!] #<ZPNG::NotSupported: Unsupported header ...' with exit 0
    for line in r.text.replace("\r", "\n").splitlines():
        m = re.match(r"^(\S+)\s+\.\.\s+(text|file|zlib):\s*(.*)$", line.strip())
        if m:
            value = m.group(3).strip()
            if m.group(2) == "text" and len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            rows.append({"channel": m.group(1), "kind": m.group(2), "value": value})
        else:
            m = re.match(r"^(\S+)\s+\.\.\s+(.*)$", line.strip())
            if m and m.group(2).strip():
                rows.append({"channel": m.group(1), "kind": "other", "value": m.group(2).strip()})
    why = refused.group(0)[4:120].split(" in #<File")[0] if refused else ""
    if r.code is not None and refused and not rows and not r.abnormal:
        r.ok, r.data = False, None      # nothing but its refusal: the picture was not read
        r.note = f"zsteg: not a PNG or BMP it reads ({why}): not read"
        return r
    r.data = rows if r.ok else None
    if r.code is not None and r.ok:
        r.note = f"zsteg: {len(rows)} findings" + (f"; it also said: {why}" if why else "")
    return r


@_guard
def jpeg_survey(data: bytes) -> Rec:
    """JPEG-domain extraction in-process (pure Python, nothing executed; research ticket #9): jsteg and
    variant DCT-coefficient LSBs per component plus the decoded pixels' bit planes. .data is
    jpeg_stego.survey()'s dict; ok is True only for a self-validated (CRC / checksum) payload, which is in
    .text; unproven readings are .data['candidates'] (unsure) and never ok."""
    r = Rec(tool="jpeg_stego")
    try:
        if str(HERE) not in sys.path:
            sys.path.append(str(HERE))
        import jpeg_stego
        import time
        res = jpeg_stego.survey(data, deadline=time.monotonic() + 20.0)
    except Exception as e:
        r.note = f"jpeg_stego: not read ({type(e).__name__})"
        return r
    r.data = res
    if res["plain"] is not None:
        r.ok = True
        r.text = res["plain"].decode("utf-8", "replace")
        r.raw = res["plain"]
        r.note = f"jpeg_stego: self-validated payload via {res['method']}"
    else:
        r.note = f"jpeg_stego: no proven payload; {len(res['candidates'])} unsure candidate(s)"
    return r


def stegsnow(data: bytes, password: str = None) -> Rec:
    """The message SNOW hid in trailing whitespace (compressed mode, -C), under the password the
    question states. SNOW has no check of its own: a wrong password gives other bytes, not an error,
    so .data is the message only when it is printable text, and a short one still proves little."""
    r = call("stegsnow", ["-C"] + (["-p", _lit(password)] if password is not None else []) + ["{in}"], [("text.txt", data)])
    plain = r.ok and bool(r.text.strip()) and "�" not in r.text and all(c.isprintable() or c in "\r\n\t" for c in r.text)
    r.data = r.text if plain else None
    if r.code is not None and r.ok:
        r.note = (f"stegsnow: {len(r.text)} characters (SNOW has no check: any trailing blanks decode to letters; evidence only)" if plain
                  else "stegsnow: nothing" if not r.text.strip()
                  else "stegsnow: bytes that are not text (a wrong password, or nothing hidden): not a message")
    return r


# ---- metadata, OCR, codes ----------------------------------------------------------------------------------

@_guard
def exif(data: bytes, name: str = None) -> Rec:
    """exiftool's reading as one dict {'Group:Tag': value} (-a -u -G1, numbers as numbers for GPS
    with -c %.6f). The sandbox's own File:* and System:* rows describe the copy, not the file.
    ExifTool:Warning and ExifTool:Error are kept ('[minor] Trailer data after PNG IEND chunk' is
    a lead); with an ExifTool:Error the file was not read and ok is False."""
    r = call("exiftool", ["-j", "-a", "-u", "-G1", "-c", "%.6f", "{in}"], [(name or _name(data), data)], ok_codes=(0, 1))
    try:
        row = json.loads(r.text)[0]
        row = {k: v for k, v in row.items() if not k.startswith(("System:", "ExifTool:ExifToolVersion")) and k != "SourceFile"}
        said = [f"{k.split(':', 1)[1]}: {v}" for k, v in row.items() if k.startswith("ExifTool:")]
        r.data, r.ok = row, not any(k.startswith("ExifTool:Error") for k in row)
        r.note = (f"exiftool: {len([k for k in row if not k.startswith('ExifTool:')])} tags" + (f"; {'; '.join(said)[:200]}" if said else "")
                  if r.ok else f"exiftool: not read ({'; '.join(said)[:200]})")
    except (ValueError, IndexError, KeyError):
        r.data = None
        if r.code is not None:
            r.ok = False
            r.note = r.note or "exiftool: no reading"
    return r


@_guard
def pngcheck(data: bytes) -> Rec:
    r = call("pngcheck", ["-v", "-t", "-7", "{in}"], [(_name(data, "img"), data)], ok_codes=(0, 1, 2))
    if r.code is not None:
        r.data = {"valid": r.code == 0, "chunks": re.findall(r"chunk (\w{4}) at offset (0x[0-9a-f]+), length (\d+)", r.text)}
        r.ok = True
        r.note = f"pngcheck: {'no errors' if r.code == 0 else 'ERRORS'}, {len(r.data['chunks'])} chunks"
    return r


@_guard
def ocr(data: bytes, psm: int = 6, whitelist: str = None, lang: str = "eng") -> Rec:
    """tesseract's text of a picture. psm 6: one block of text; 7: one line; 11: sparse text.
    whitelist limits the characters (e.g. '0123456789ABCDEF-'). OCR text is evidence, not a fact:
    0/O, 1/l/I and missing characters are the usual errors."""
    args = ["{in}", "stdout", "--psm", str(psm), "-l", lang]
    if whitelist:
        args += ["-c", _lit(f"tessedit_char_whitelist={whitelist}")]
    r = call("tesseract", args, [(_name(data, "img"), data)], timeout=90)
    r.data = [x.strip() for x in r.text.splitlines() if x.strip()] if r.ok else None
    if r.code is not None and r.ok:
        r.note = f"tesseract: {len(r.data)} lines"
    return r


@_guard
def codes(data: bytes) -> Rec:
    """The QR codes and barcodes zbar reads in a picture: .data [(symbology, text)], one row per
    code (zbarimg --xml: a text with line breaks in it stays one code). With exactly one code its
    text is the code's own bytes when they are UTF-8 (.files['first.bin'] holds them as read);
    with several, or bytes that are not UTF-8, the text is zbar's charset conversion, which is a
    guess for anything but ASCII. A picture zbar could not load is 'not read', never '0 codes'.
    (The venv's zxing-cpp in carve_stego.decode_codes reads Aztec, DataMatrix and PDF417 too; two
    readers that agree are better than one.)"""
    import base64
    name = _name(data, "img")
    r = call("zbarimg", ["-q", "--nodbus", "--xml", "{in}"], [(name, data)], ok_codes=(0, 4))
    if r.code is None or r.abnormal:
        return r
    if r.code not in (0, 4):
        r.ok, r.data = False, None
        r.note = f"zbar: the picture was not read (exit {r.code}: {_said(r) or 'it said nothing'}): not read"
        return r
    found = []
    for m in re.finditer(r"<symbol type='([^']*)'[^>]*>.*?<data(?P<attr>[^>]*)><!\[CDATA\[(?P<body>.*?)\]\]></data></symbol>", r.text, re.S):
        body = m.group("body")
        if "format='base64'" in m.group("attr"):
            try:
                body = base64.b64decode(body).decode("utf-8", "replace")
            except ValueError:
                r.ok, r.data, r.note = False, None, "zbar: a code's data could not be decoded: not read"
                return r
        found.append((m.group(1), body))
    if r.text.count("<symbol ") != len(found):       # a symbol this reading did not take apart
        r.ok, r.data, r.note = False, None, f"zbar: {r.text.count('<symbol ')} codes, {len(found)} of them parsed: not read"
        return r
    r.files = {}
    if len(found) == 1:
        one = call("zbarimg", ["-q", "--nodbus", "--oneshot", "-Sbinary", "--raw", "{in}"], [(name, data)], ok_codes=(0, 4))
        if one.ok and one.raw and not one.abnormal:
            r.files = {"first.bin": one.raw}
            try:
                found[0] = (found[0][0], one.raw.decode("utf-8"))
            except UnicodeDecodeError:
                pass
    r.data, r.ok = found, True
    r.text = "\n".join(f"{k}:{v}" for k, v in found)
    guess = any(not v.isascii() for _, v in found) and not (len(found) == 1 and r.files)
    r.note = f"zbar: {len(found)} codes" + ("; text beyond ASCII is zbar's charset guess" if guess else "")
    return r


# ---- PDF ---------------------------------------------------------------------------------------------------

@_guard
def pdf_info(data: bytes, password: str = None) -> Rec:
    """pdfinfo's fields as a dict, and qpdf's encryption line in .data['encryption']."""
    pw = ["-upw", _lit(password)] if password is not None else []
    r = call("pdfinfo", pw + ["{in}"], [("doc.pdf", data)], ok_codes=(0, 1, 3))
    info = {}
    for line in r.text.splitlines():
        k, sep, v = line.partition(":")
        if sep:
            info[k.strip()] = v.strip()
    q = call("qpdf", ["--show-encryption"] + ([_lit(f"--password={password}")] if password is not None else []) + ["{in}"],
             [("doc.pdf", data)], ok_codes=(0, 2, 3))
    info["encryption"] = (q.text.strip() or getattr(q, "stderr", "").strip()).splitlines()[:6]
    r.data = info
    if r.code is not None:
        r.ok = bool(info.get("Pages")) or r.code == 0
        locked = "password" in (" ".join(info["encryption"]) + getattr(r, "stderr", "")).lower()
        r.note = (f"pdfinfo: {info.get('Pages', '?')} pages" if r.ok
                  else "pdfinfo: encrypted, it opens only with the password the question states" if locked
                  else r.note or "pdfinfo: not read")
    return r


@_guard
def pdf_text(data: bytes, password: str = None, layout: bool = True) -> Rec:
    args = (["-upw", _lit(password)] if password is not None else []) + (["-layout"] if layout else []) + ["{in}", "-"]
    r = call("pdftotext", args, [("doc.pdf", data)])
    if r.code is not None and r.ok:
        r.note = f"pdftotext: {len(r.text)} characters"
    return r


@_guard
def pdf_images(data: bytes, password: str = None) -> Rec:
    """Every image object of the PDF in its own format (pdfimages -all)."""
    args = (["-upw", _lit(password)] if password is not None else []) + ["-all", "{in}", "{out}/img"]
    r = call("pdfimages", args, [("doc.pdf", data)])
    if r.code is not None and r.ok:
        r.note = f"pdfimages: {len(r.files)} images"
    return r


@_guard
def pdf_attachments(data: bytes, password: str = None) -> Rec:
    """The embedded files of the PDF (pdfdetach -saveall)."""
    args = (["-upw", _lit(password)] if password is not None else []) + ["-saveall", "-o", "{out}", "{in}"]
    r = call("pdfdetach", args, [("doc.pdf", data)])
    if r.code is not None and r.ok:
        r.note = f"pdfdetach: {len(r.files)} attachments"
    return r


@_guard
def pdf_decrypt(data: bytes, password: str) -> Rec:
    """The PDF without its encryption, under the password the question states (never a guess).
    ok is True, and .data the plain PDF, only when the PDF IS encrypted and qpdf opened it with this
    password (the note says so when that password is the empty one: such a PDF opens for anybody
    and proves no password). A PDF that is not encrypted is ok=False with its own note (any
    password 'works' on it), and so is a damaged one: neither says the password is wrong."""
    enc = call("qpdf", ["--is-encrypted", "{in}"], [("doc.pdf", data)], ok_codes=(0, 2))
    if enc.code is None or enc.abnormal:
        return enc
    if enc.code != 0:
        damaged = _said(enc)
        enc.ok, enc.data = False, None
        enc.note = (f"qpdf: the PDF was not read ({damaged}): no reading of the password" if damaged
                    else "qpdf: the PDF is not encrypted: no password is needed, and this one is not proven by it")
        return enc
    r = call("qpdf", [_lit(f"--password={password}"), "--decrypt", "{in}", "{out}/plain.pdf"], [("doc.pdf", data)], ok_codes=(0, 3))
    got = r.files.get("plain.pdf")
    r.ok = got is not None and r.code in (0, 3)
    r.data = got if r.ok else None
    if r.code is not None:
        wrong = "invalid password" in getattr(r, "stderr", "")
        r.note = (f"qpdf: decrypted, {len(got)} bytes" + (" (with the EMPTY password: the PDF opens for anybody)" if password == "" else "") if r.ok
                  else "qpdf: not decrypted with this password (invalid password)" if wrong
                  else f"qpdf: the PDF was not read ({_said(r) or f'exit {r.code}'}): no reading of the password")
    return r


@_guard
def pdf_qdf(data: bytes) -> Rec:
    """The PDF rewritten readable (qpdf --qdf: streams uncompressed, object streams off): .data bytes."""
    r = call("qpdf", ["--qdf", "--object-streams=disable", "{in}", "{out}/qdf.pdf"], [("doc.pdf", data)], ok_codes=(0, 3))
    got = r.files.get("qdf.pdf")
    r.ok, r.data = got is not None, got
    if r.code is not None:
        r.note = f"qpdf: {len(got)} bytes readable" if r.ok else r.note or "qpdf: not rewritten"
    return r


# ---- audio and video ---------------------------------------------------------------------------------------

@_guard
def media_info(data: bytes, name: str = None) -> Rec:
    r = call("ffprobe", ["-v", "error", "-of", "json", "-show_format", "-show_streams", "{in}"], [(name or _name(data, "media"), data)])
    try:
        r.data = json.loads(r.text)
        r.note = f"ffprobe: {len(r.data.get('streams', []))} streams" if r.ok else r.note
    except ValueError:
        r.data = None
    return r


@_guard
def to_wav(data: bytes, rate: int = 22050, channels: int = 1, name: str = None, filters: str = None) -> Rec:
    """Any audio (or a video's sound) as 16-bit PCM WAV: .data the bytes. filters: an ffmpeg -af
    chain (e.g. 'areverse', 'atempo=0.5', 'pan=mono|c0=c0-c1' for a hidden difference channel)."""
    args = ["-v", "error", "-y", "-i", "{in}", "-vn", "-ac", str(channels), "-ar", str(rate)]
    args += (["-af", _lit(filters)] if filters else []) + ["-c:a", "pcm_s16le", "{out}/audio.wav"]
    r = call("ffmpeg", args, [(name or _name(data, "media"), data)], timeout=120)
    got = r.files.get("audio.wav")
    r.ok, r.data = r.code == 0 and bool(got), got
    if r.code is not None and r.ok:
        r.note = f"ffmpeg: {len(got)} bytes of WAV at {rate} Hz"
    return r


@_guard
def frames(data: bytes, fps: float = 1.0, limit: int = 20, name: str = None) -> Rec:
    """Frames of a video (or an animated GIF) as PNG, fps a second, at most `limit`."""
    r = call("ffmpeg", ["-v", "error", "-y", "-i", "{in}", "-vf", f"fps={fps}", "-frames:v", str(int(limit)), "{out}/frame-%04d.png"],
             [(name or _name(data, "media"), data)], timeout=120)
    r.ok = r.code == 0 and bool(r.files)
    if r.code is not None and r.ok:
        r.note = f"ffmpeg: {len(r.files)} frames"
    return r


@_guard
def spectrogram(data: bytes, width: int = 1200, height: int = 513, top_hz: int = None, light: bool = False) -> Rec:
    """A spectrogram of the first channel as PNG (sox, raw: no axes or legend, monochrome; height
    is 2^n+1 rows). top_hz: resample so the picture ends at that frequency (text drawn low in the
    band fills the picture). light=True: dark marks on white, which OCR and QR readers prefer."""
    wav = to_wav(data, rate=(2 * top_hz if top_hz else 44100))
    if not wav.ok:
        return Rec(note=wav.note or "not audio ffmpeg reads", tool="sox", code=wav.code)
    args = ["{in}", "-n", "remix", "1", "spectrogram", "-r", "-m", "-x", str(int(width)), "-y", str(int(height)), "-z", "70"]
    args += (["-l"] if light else []) + ["-o", "{out}/spectrogram.png"]
    r = call("sox", args, [("audio.wav", wav.data)], timeout=120)
    got = r.files.get("spectrogram.png")
    r.ok, r.data = r.code == 0 and bool(got), got
    if r.code is not None and r.ok:
        r.note = f"sox: spectrogram {width}x{height}"
    return r


def spectrogram_text(data: bytes, width: int = 1200, heights=(129, 257), top_hz: int = 8000, whitelist: str = None) -> Rec:
    """OCR of the spectrogram at each height, dark and light. .data: {'129-dark': [lines], ...};
    .text holds the lines at least two of those readings give alike. A read, not a fact (0 and O,
    1 and I, a space that is not there): look at the pictures in .files, and change top_hz when
    the writing sits elsewhere in the band (None: the whole band of a 44.1 kHz recording)."""
    out, files = {}, {}
    for h in heights:
        for key, light in (("dark", False), ("light", True)):
            s = spectrogram(data, width, h, top_hz, light)
            if not s.ok:
                return s
            files[f"spectrogram-{h}-{key}.png"] = s.data
            t = ocr(s.data, psm=6, whitelist=whitelist)
            if t.code is None or t.abnormal:
                return t
            out[f"{h}-{key}"] = t.data or []
    seen = {}
    for lines in out.values():
        for x in set(lines):
            seen[x] = seen.get(x, 0) + 1
    agreed = [x for x, n in seen.items() if n >= 2]
    return Rec(ok=True, text="\n".join(agreed), files=files, data=out, tool="sox+tesseract",
               note=f"spectrogram OCR: {len(out)} readings, {len(agreed)} lines read alike at least twice", code=0)


@_guard
def sstv_decode(data: bytes, skip: float = 0.0) -> Rec:
    """The picture an SSTV recording carries (colaclanth/sstv: Martin, Scottie, Robot, PD, Pasokon
    modes by their VIS code), as PNG in .data. Slow: about a second per 3 s of sound."""
    wav = to_wav(data, rate=44100)
    if not wav.ok:
        return Rec(note=wav.note or "not audio ffmpeg reads", tool="sstv", code=wav.code)
    r = call("sstv", ["-d", "{in}", "-o", "{out}/sstv.png"] + (["-s", str(skip)] if skip else []), [("audio.wav", wav.data)], timeout=300)
    got = r.files.get("sstv.png")
    r.ok, r.data = bool(got), got
    said = [x.strip() for x in re.split(r"[\r\n]+", r.text + "\n" + getattr(r, "stderr", "")) if x.strip() and "%" not in x]
    r.text = "\n".join(said)                    # without the progress bar
    mode = re.search(r"Detected SSTV mode (.+)", r.text)
    if r.code is not None:
        r.note = (f"sstv: {mode.group(1).strip() if mode else 'a picture'}, {len(got)} bytes of PNG" if r.ok
                  else f"sstv: no picture (exit {r.code}: {said[-1][:160] if said else 'it said nothing'})")
    return r


MULTIMON_MODES = ("DTMF", "AFSK1200", "AFSK2400", "POCSAG512", "POCSAG1200", "POCSAG2400", "FLEX", "EAS", "UFSK1200",
                  "CLIPFSK", "FMSFSK", "HAPN4800", "FSK9600", "ZVEI1", "ZVEI2", "ZVEI3", "DZVEI", "PZVEI", "EEA", "EIA",
                  "CCIR", "MORSE_CW", "X10")


@_guard
def multimon(data: bytes, modes=("DTMF",), invert: bool = False) -> Rec:
    """multimon-ng's decoded lines of a recording (resampled to 22050 Hz mono, as it wants). modes:
    names of MULTIMON_MODES. .data: {'lines': [...], 'dtmf': 'digits', 'pocsag': [...], 'afsk': [...],
    'morse': 'TEXT' (with the mode MORSE_CW, asked alone: its text has no prefix)}.
    invert=True flips the FSK polarity (a POCSAG recording with nothing in it: try both)."""
    bad = [m for m in modes if m not in MULTIMON_MODES]
    if bad:
        return Rec(note=f"multimon: unknown mode {bad[0]}", tool="multimon-ng")
    wav = to_wav(data, rate=22050)
    if not wav.ok:
        return Rec(note=wav.note or "not audio ffmpeg reads", tool="multimon-ng", code=wav.code)
    raw = wav.data[wav.data.index(b"data") + 8:] if b"data" in wav.data[:4096] else wav.data[44:]
    args = ["-q", "-t", "raw"] + (["-i"] if invert else [])
    for m in modes:
        args += ["-a", m]
    r = call("multimon-ng", args + ["{in}"], [("audio.raw", raw)], timeout=120)
    lines = [x.strip() for x in r.text.splitlines() if x.strip()]
    r.data = {"lines": lines,
              "dtmf": "".join(m.group(1) for x in lines for m in [re.match(r"^DTMF: (.)$", x)] if m),
              "pocsag": [x for x in lines if x.startswith("POCSAG")],
              "afsk": [x for x in lines if x.startswith(("AFSK", "APRS"))],
              "morse": (" ".join(x for x in lines if not re.match(r"^[A-Z0-9_]+: ", x)).strip() if "MORSE_CW" in modes else "")}
    if r.code is not None and r.ok:
        r.note = f"multimon-ng: {len(lines)} lines"
    return r


@_guard
def minimodem(data: bytes, baud="1200", args=()) -> Rec:
    """minimodem's text of an FSK recording (baud: a rate or 'rtty', 'tdd', 'same', 'callerid')."""
    wav = to_wav(data, rate=48000)
    if not wav.ok:
        return Rec(note=wav.note or "not audio ffmpeg reads", tool="minimodem", code=wav.code)
    r = call("minimodem", ["--rx", "-q", "-f", "{in}", *map(_lit, args), str(baud)], [("audio.wav", wav.data)], timeout=120)
    if r.code is not None and r.ok:
        r.note = f"minimodem: {len(r.text)} characters"
    return r


@_guard
def rtl433(data: bytes, name: str = "g.cu8", rate: int = 250000, flex: str = None, analyze: bool = False, args=()) -> Rec:
    """rtl_433 on a recorded IQ file. The name's extension says the sample format (.cu8, .cs16,
    .cf32, .ook, .sr ...). flex: a flex decoder spec ('n=x,m=OOK_PWM,s=400,l=1200,r=8000,g=2000')
    for a signal no built-in device matches; analyze=True adds the pulse analyzer's text (-A).
    .data: the JSON rows it decoded."""
    argv = ["-r", "{in}", "-s", str(int(rate)), "-F", "json"] + (["-X", _lit(flex)] if flex else []) + (["-A"] if analyze else []) + list(map(_lit, args))
    r = call("rtl_433", argv, [(Path(name).name, data)], timeout=120)
    rows = []
    for line in r.text.splitlines():
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    r.data = rows
    r.analysis = getattr(r, "stderr", "")
    if r.code is not None and r.ok:
        r.note = f"rtl_433: {len(rows)} decoded rows"
    return r


# ---- carving, file systems ---------------------------------------------------------------------------------

@_guard
def foremost(data: bytes, types: str = None) -> Rec:
    """foremost's carved files ({'jpg/00000001.jpg': bytes, ...}) and its audit.txt in .text."""
    args = ["-Q"] + (["-t", types] if types else []) + ["-i", "{in}", "-o", "{out}/carved"]
    r = call("foremost", args, [("image.bin", data)], timeout=180)
    audit = r.files.pop("carved/audit.txt", b"")
    r.files = {k[len("carved/"):]: v for k, v in r.files.items() if k.startswith("carved/")}
    r.text = _text(audit)
    if r.code is not None and r.ok:
        r.note = f"foremost: {len(r.files)} files carved"
    return r


@_guard
def bulk_extractor(data: bytes, scanners=()) -> Rec:
    """bulk_extractor's non-empty feature files ({'email.txt': bytes, 'url.txt': ...}); .data:
    {feature file: [(offset, feature)]} without the comment lines."""
    args = ["-q", "-1", "-o", "{out}/be"]
    for s in scanners:
        args += ["-e", s]
    r = call("bulk_extractor", args + ["{in}"], [("image.bin", data)], timeout=300)
    feats, rows = {}, {}
    for k, v in r.files.items():
        name = k[len("be/"):] if k.startswith("be/") else k
        if not name.endswith(".txt") or "histogram" in name:
            continue
        got = []
        for line in _text(v).splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                got.append((parts[0], parts[1]))
        if got:
            feats[name], rows[name] = v, got
    r.files, r.data = feats, rows
    if r.code is not None and r.ok:
        r.note = f"bulk_extractor: {sum(len(v) for v in rows.values())} features in {len(rows)} files"
    return r


TSK = ("mmls", "fsstat", "fls", "icat", "tsk_recover")


@_guard
def tsk(data: bytes, tool: str = "fls", args=("-r", "-p")) -> Rec:
    """One sleuthkit program on a disk image: mmls (partitions), fsstat, fls (-r -p: every path,
    -d: deleted only), icat <inode> (the file's bytes in .files['stdout']), tsk_recover."""
    if tool not in TSK:
        return Rec(note=f"tsk: {tool} is not one of {', '.join(TSK)}", tool=tool)
    if tool == "tsk_recover":
        r = call(tool, [*map(_lit, args), "{in}", "{out}/recovered"], [("disk.img", data)], timeout=180)
        r.files = {k[len("recovered/"):]: v for k, v in r.files.items() if k.startswith("recovered/")}
    elif tool == "icat":
        if not args:
            return Rec(note="icat: it needs the inode as its last argument (fls names it)", tool=tool)
        r = call("icat", [*map(_lit, args[:-1]), "{in}", _lit(args[-1])], [("disk.img", data)], timeout=120)
        if r.code is not None and r.ok:     # the bytes of a file are not text: take them raw
            r.files, r.data, r.text = {"stdout": r.raw}, r.raw, ""
            r.note = f"icat: {len(r.raw)} bytes"
        return r
    else:
        r = call(tool, [*map(_lit, args), "{in}"], [("disk.img", data)], timeout=120)
    if r.code is not None and r.ok:
        r.note = f"{tool}: {len(r.text.splitlines())} lines" if tool != "tsk_recover" else f"tsk_recover: {len(r.files)} files"
    return r


# ---- radare2 and the decompiler ----------------------------------------------------------------------------

@_guard
def r2(data: bytes, commands, analyze: str = "aa", timeout: float = 120.0, name: str = "sample.bin") -> Rec:
    """radare2 commands on a file (static: the file is never run; -n is not used, so headers are
    parsed). commands: a string or a list ('iI', 'iz', 'afl', 'pdf @ main', 'izz~flag').
    analyze: the analysis command run first ('' none, 'aa', 'aaa')."""
    if isinstance(commands, (list, tuple)):
        commands = "; ".join(commands)
    script = "; ".join(x for x in (analyze, commands) if x)
    r = call("r2", ["-q", "-e", "scr.color=0", "-e", "scr.interactive=false", "-e", "bin.relocs.apply=true", "-c", _lit(script), "{in}"],
             [(name, data)], timeout=timeout)
    if r.code is not None and r.ok:
        r.note = f"r2: {len(r.text.splitlines())} lines"
    return r


@_guard
def decompile(data: bytes, function: str = "main", timeout: float = 180.0) -> Rec:
    """The Ghidra decompiler's C of one function (r2ghidra's pdg, no JVM). Evidence to read, never
    an answer by itself: a constant or a string in it is confirmed in the bytes (r2 'iz', 'px')."""
    r = r2(data, f"pdg @ {function}", analyze="aaa", timeout=timeout)
    if r.code is not None and r.ok:
        r.ok = bool(r.text.strip()) and "{" in r.text
        r.note = f"r2ghidra: {len(r.text.splitlines())} lines of C for {function}" if r.ok else f"r2ghidra: nothing for {function}"
    return r


@_guard
def py(script: str, inputs=(), args=(), timeout: float = 120.0) -> Rec:
    """A script of YOURS under the image's python3 -I, with the files as {in1}, {in2} ... after it
    (numpy, scipy, Pillow, pyzbar, pypdf, scapy, python-evtx, regipy, LnkParse3, extract-msg and
    fickling are there). For a parser you would not run on this Mac. It writes under its working
    folder, which comes back in .files."""
    ins = [("script.py", script.encode("utf-8"))] + [tuple(x) for x in inputs]
    argv = ["{in0}"] + [f"{{in{i}}}" for i in range(1, len(ins))] + [_lit(a) for a in args]
    r = call("python3", argv, ins, timeout=timeout)
    if r.code is not None and r.ok:
        r.note = f"python3: {len(r.text.splitlines())} lines"
    return r


@_guard
def render_sweep(name: str, data: bytes, seconds: float = 40.0) -> Rec:
    """A drawn message read in-process, no sandbox (B-126, render_ocr_sweep): a PCM WAV's spectrogram
    from 0 Hz to Nyquist in overlapping bands, both polarities, and exact 5x7 glyphs on seven tones; a
    PNG or BMP's bit planes 0-2 of every channel, the structured ones rendered. tesseract on PATH
    reads them. .text: the lines read (a flag of the current event a keyless decode reaches comes
    first, as 'FLAG ...'); .files: the renderings worth a look; .data: the sweep's report. A read, not
    a fact."""
    r = Rec(tool="render_ocr_sweep")
    if on_timed_path():
        r.note = "on a timed path: not run"
        return r
    try:
        if str(HERE) not in sys.path:
            sys.path.append(str(HERE))
        import render_ocr_sweep
        got = render_ocr_sweep.survey_read(name, data, seconds)
    except Exception as e:
        r.note = f"render_ocr_sweep: not read ({type(e).__name__}: {e})"
        return r
    r.ok, r.text, r.files, r.data, r.note = got["ok"], got["text"], dict(got["files"]), got["data"], got["note"]
    return r


# ---- one file, every fitting program -----------------------------------------------------------------------

def survey(name: str, data: bytes, passphrases=(), words=None, sstv: bool = False) -> list:
    """Every fitting program on one file: [(what, Rec)], in the order an agent reads them. The
    empty passphrase is always tried for steghide; `passphrases` and `words` only as the question
    gives them. Stops at the first 'sandbox down' (one row says so); the in-process render sweep of a
    WAV, PNG or BMP comes first, so it is read even then."""
    out = []

    def add(what, rec):
        out.append((what, rec))
        return not rec.note.startswith(("sandbox down", "on a timed path"))

    kind = _name(data, "x").split(".")[-1]
    text_like = kind == "bin" and _printable(data[:4096])
    if kind in ("wav", "png", "bmp"):               # B-126: spectrogram_text below stops at 8 kHz; ocr() reads only the cover
        add("render sweep (spectrogram to Nyquist, bit planes 0-2)", render_sweep(name, data))
    if not add("exiftool", exif(data, _name(data, Path(name).stem or "file"))):
        return out
    if kind in ("jpg", "bmp", "wav", "au"):
        tried = [""] + [p for p in passphrases if p != ""]
        for p in tried:
            info = steghide_info(data, p)
            add(f"steghide info (passphrase {p!r})", info)
            if info.data and info.data.get("embedded") is not None:
                add(f"steghide extract (passphrase {p!r})", steghide_extract(data, p))
                break
        else:
            if words is not None:
                add("stegseek (the question's word list)", stegseek(data, words))
    if kind == "jpg":
        for k in [None] + list(passphrases):
            got = outguess_extract(data, k)
            if got.ok and got.data["plausible"]:
                add(f"outguess (key {k!r})", got)
    if kind == "jpg":
        add("jpeg_stego (DCT + pixel planes)", jpeg_survey(data))
    if kind in ("png", "bmp"):
        add("zsteg", zsteg(data))
    if kind == "png":
        add("pngcheck", pngcheck(data))
    if kind in ("jpg", "png", "bmp", "gif", "tif", "webp"):
        add("zbar", codes(data))
        add("tesseract", ocr(data, psm=11))
    if kind == "pdf":
        add("pdfinfo", pdf_info(data))
        add("pdftotext", pdf_text(data))
        add("pdfdetach", pdf_attachments(data))
        add("pdfimages", pdf_images(data))
    if kind in ("wav", "flac", "ogg", "mp3", "au", "mp4", "mkv", "avi"):
        add("ffprobe", media_info(data))
        add("multimon-ng", multimon(data, ("DTMF", "AFSK1200", "POCSAG512", "POCSAG1200", "POCSAG2400")))
        add("spectrogram OCR", spectrogram_text(data))
        if sstv:
            add("sstv", sstv_decode(data))
    if kind in ("mp4", "mkv", "avi", "gif"):
        add("frames", frames(data))
    if text_like:
        add("stegsnow", stegsnow(data))
        for p in passphrases:
            add(f"stegsnow (password {p!r})", stegsnow(data, p))
    if kind == "bin" and not text_like:
        add("foremost", foremost(data))
        add("bulk_extractor", bulk_extractor(data))
    return out


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    if argv == ["--tools"]:
        a = available()
        print(("STEGO TOOLS up: " if a.ok else "STEGO TOOLS down: ") + a.note)
        return 0 if a.ok else 1
    files, passes, words, want_sstv, extract, as_json = [], [], None, False, None, False
    it = iter(argv)
    for a in it:
        if a == "--pass":
            passes.append(next(it, ""))
        elif a == "--wordlist":
            words = Path(next(it)).read_bytes()
        elif a == "--sstv":
            want_sstv = True
        elif a == "--extract":
            extract = Path(next(it))
        elif a == "--json":
            as_json = True
        elif a.startswith("--"):
            print(f"stego_tools: unknown option {a}", file=sys.stderr)
            return 2
        else:
            files.append(Path(a))
    report = []
    for path in files:
        data = path.read_bytes()
        rows = survey(path.name, data, passes, words, want_sstv)
        if not as_json:
            print(f"== {path.name} ({len(data)} bytes)")
        for what, rec in rows:
            report.append({"file": path.name, "what": what, "ok": rec.ok, "note": rec.note, "text": rec.text[:4000],
                           "files": {k: len(v) for k, v in rec.files.items()},
                           "data": rec.data if isinstance(rec.data, (dict, list, str, int, type(None))) else None})
            if not as_json:
                print(f"  {'ok ' if rec.ok else '-- '} {what}: {rec.note}")
                shown = rec.text.strip().splitlines()[:12] if what not in ("exiftool", "ffprobe", "zsteg") else []
                if what == "zsteg":
                    shown = [f"{x['channel']}  {x['kind']}: {x['value']}" for x in (rec.data or [])[:12]]
                if what == "exiftool" and rec.data:
                    shown = [f"{k}: {v}" for k, v in rec.data.items() if not k.startswith("File:")][:30]
                for line in shown:
                    print(f"        {line[:200]}")
            if extract is not None:
                for k, v in rec.files.items():
                    dest = extract / path.name / re.sub(r"[^A-Za-z0-9._-]+", "_", what) / k
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(v)
    if as_json:
        print(json.dumps(report, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
