#!/usr/bin/env python3
"""B-250: the Warmups lane residuals folded into crib_decode's one pass.

  .venv/bin/python -m pytest tests/test_b250_warmups_residuals.py

No network, no token, no challenge file: every fixture (an ITA1 tape, a headerless yEnc text, a DTMF
recording, a QR picture, a Chicken program, an Enigma M4 message, keyed records) is built here, with
an encoder written in this file from the published tables, independent of the module under test.
Each behaviour has a counterpart that fails when the reader is missing or wrong:

  ITA1          Baudot's continental code reads both bit orders; the blank of the shift in force is a
                space; a national-use figure, a short tape and non-binary text are refused; a slug read
                through it is a case-lossy CANDIDATE (warmups.case/ita1), never plain.
  yEnc          headerless yEnc with escapes and line wraps; ASCII, headed and non-text outputs refused.
  DTMF          a PCM WAV's keys re-enter the search (big decimal, '*'-separated decimal list); silence
                is nothing; with the family removed the flag is not reached.
  QR            a PNG QR re-enters the search; an oversized image and junk behind a PNG magic refuse.
  Chicken       B-055's VM completed with peck/fr/BBQ (esolangs.org); a program's entity output re-enters
                through the html step to the flag.
  Enigma M4     thin Beta/Gamma + thin B/C equal the M3's B/C at position A over a long message (so the
                thin wheel never steps); stated M4 keys parse; bad wheels are loud; crib_decode reads a
                stated M4 message as its enigma candidate.
  B6 digits     kbdw and Vigenere-family chains get a third digit option that undoes a writer who moved
                the digits too; other chains do not.
  per-variant   a Mastery record under an xorkey day chain whose variant has its own key is read with
  xor           that key, found at the one place of the sentence it fits.
"""
import atexit
import base64
import contextlib
import io
import math
import os
import shutil
import struct
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_ROOT = Path(tempfile.mkdtemp(prefix="b250-"))
atexit.register(shutil.rmtree, _ROOT, True)
(_ROOT / "_ledger").mkdir(parents=True)
os.environ["CTF_WORKDIR"] = str(_ROOT)
os.environ["CTF_TESTING"] = "1"
os.environ.setdefault("CTF_EVENT", "huntress")   # the flag-format path (solve_blob) resolves a profile
os.environ.pop("CTF_TOKEN", None)

import crib_decode as C  # noqa: E402
import labels  # noqa: E402
import warmup_residuals as R  # noqa: E402
from _shadowed import common_module  # noqa: E402

K = common_module("classical")
chicken = R._chicken_vm()

FLAG = "flag{0123456789abcdef0123456789abcdef}"
SLUG = "amber-falcon-river-42"
# A generous engine budget: the search ends as soon as the flag is reached, so this is no upper bound on
# the test's time, and it keeps a loaded machine (rule 16) from cutting the search before it gets there.
BUDGET = 30.0


def strict_read(blob: bytes, want: bytes):
    """The names under which the one-pass strict search reads `blob` to exactly `want`."""
    return [name for name, out in C._strict_steps(blob) if out == want]


@contextlib.contextmanager
def residuals_removed():
    C.unregister_family(C._RES_FAMILY)
    try:
        yield
    finally:
        C._RES_FAMILY = C.register_family("warmup_residuals", R.NAMES, R.steps, R.step_fn)


# --------------------------------------------------------------------------------------------- ITA1

# The ITA1 letters and figures as published (bit I first), written out here as an encoder.
ITA1_LET = {"a": "10000", "b": "00110", "c": "10110", "d": "11110", "e": "01000", "f": "01110", "g": "01010",
            "h": "11010", "i": "01100", "j": "10010", "k": "10011", "l": "11011", "m": "01011", "n": "01111",
            "o": "11100", "p": "11111", "q": "10111", "r": "00111", "s": "00101", "t": "10101", "u": "10100",
            "v": "11101", "w": "01101", "x": "01001", "y": "00100", "z": "11001"}
ITA1_FIG = {"1": "10000", "2": "01000", "3": "00100", "4": "10100", "5": "11100", "6": "10010", "7": "01010",
            "8": "00110", "9": "10110", "0": "11110", "!": "10101", ",": "01001", ":": "11001", "-": "00111",
            "(": "10011", ")": "01011", "?": "01101", ";": "00101"}
LTRS, FIGS = "00001", "00010"


def ita1_tape(text: str, rev: bool = False, sep: str = " ") -> bytes:
    out, figs = [], False
    for ch in text.lower():
        if ch == " ":
            out.append(FIGS if figs else LTRS)       # the blank of the shift in force
        elif ch in ITA1_LET:
            if figs:
                out.append(LTRS)
                figs = False
            out.append(ITA1_LET[ch])
        else:
            if not figs:
                out.append(FIGS)
                figs = True
            out.append(ITA1_FIG[ch])
    return sep.join(g[::-1] if rev else g for g in out).encode()


def test_ita1_reads_the_sentence_in_both_bit_orders():
    plain = (C.CRIB + SLUG).lower().encode()
    tape = ita1_tape(C.CRIB + SLUG)
    assert R.d_ita1(tape) == plain
    assert R.d_ita1rev(ita1_tape(C.CRIB + SLUG, rev=True)) == plain
    assert R.d_ita1(ita1_tape(C.CRIB + SLUG, sep="")) == plain        # one unbroken run of bits
    assert R.d_ita1rev(tape) != plain                                  # the order is not ignored
    # every figure the table carries
    assert R.d_ita1(ita1_tape("x 1234567890 !,:-()?; y")) == b"x 1234567890 !,:-()?; y"


def test_ita1_shift_blanks_are_spaces_and_shifts():
    # LTRS while in letters is a space; FIGS while in letters is only a shift; FIGS in figures a space.
    tape = " ".join([ITA1_LET["a"], LTRS, ITA1_LET["b"], FIGS, ITA1_FIG["1"], FIGS, ITA1_FIG["2"], LTRS,
                     ITA1_LET["c"], ITA1_LET["d"], ITA1_LET["e"], ITA1_LET["f"]]).encode()
    assert R.d_ita1(tape) == b"a b1 2cdef"


def test_ita1_refuses_what_it_cannot_read():
    # A national-use figure (the figure of F, which the sources leave open) is refused, never guessed.
    bad = " ".join([ITA1_LET["a"]] * 8 + [FIGS, ITA1_LET["f"]]).encode()
    assert R.d_ita1(bad) is None
    assert R.d_ita1(" ".join([ITA1_LET["a"]] * 7).encode()) is None        # under the floor of 8 codes
    assert R.d_ita1(b"10000 10000 10000 10000 10000 10000 10000 1000") is None   # a group of four bits
    assert R.d_ita1(b"hello world, not a tape at all") is None
    assert R.d_ita1(" ".join([FIGS, ITA1_FIG["1"]] * 6).encode()) is None   # figures only: no letter


def test_ita1_slug_is_a_case_lossy_candidate_never_plain():
    tape = ita1_tape(C.CRIB + SLUG)
    got = C.solve_blob(tape, budget=BUDGET)
    assert got is not None
    assert labels.is_unsure(got[0]), got[0]
    assert "warmups.case/ita1" in got[0] and SLUG in got[0]
    assert C.LAST["key"] == "warmups.case/ita1"
    # the counterpart: without the B-250 family the built-in battery does not read an ITA1 tape
    with residuals_removed():
        assert strict_read(tape, (C.CRIB + SLUG).lower().encode()) == []
        assert "ita1" not in C._STRICT_NAMES


# ------------------------------------------------------------------------------------ headerless yEnc

def yenc(data: bytes, over_escape=(), line: int = 0) -> bytes:
    out, col = bytearray(), 0
    for x in data:
        y = (x + 42) & 255
        if y in (0, 10, 13, 61) or y in over_escape:
            out += bytes([61, (y + 64) & 255])
        else:
            out.append(y)
        col += 1
        if line and col % line == 0:
            out += b"\r\n"
    return bytes(out)


def test_yencraw_reads_escapes_and_line_wraps():
    plain = ("the flag is " + FLAG).encode()
    assert R.d_yencraw(yenc(plain)) == plain
    # an encoder may escape any byte; '=' then the byte 64 higher
    assert R.d_yencraw(yenc(plain, over_escape={ord("f") + 42, ord("a") + 42})) == plain
    assert R.d_yencraw(yenc(plain, line=10)) == plain                  # line breaks are not data


def test_yencraw_refusals():
    plain = ("the flag is " + FLAG).encode()
    assert R.d_yencraw(plain) is None                                   # all ASCII: not yEnc of text
    assert R.d_yencraw(b"=ybegin line=128 size=5 name=x\n" + yenc(plain)) is None   # headed: d_yenc's
    assert R.d_yencraw(bytes(range(128, 200))) is None                  # decodes to no text
    assert R.d_yencraw(yenc(plain)[:-1] + b"=") is None                 # a dangling escape
    assert R.d_yencraw(yenc(b"abc")) is None                            # under the floor


def test_yencraw_reaches_the_flag_and_only_through_the_family():
    blob = yenc(("the flag is " + FLAG).encode())
    got = C.solve_blob(blob, budget=BUDGET)
    assert got is not None and got[0] == FLAG
    assert got[1] == [["yencraw"]]
    with residuals_removed():
        assert strict_read(blob, ("the flag is " + FLAG).encode()) == []


# ----------------------------------------------------------------------------------- DTMF from audio

_LOW = {"1": 697, "2": 697, "3": 697, "A": 697, "4": 770, "5": 770, "6": 770, "B": 770,
        "7": 852, "8": 852, "9": 852, "C": 852, "*": 941, "0": 941, "#": 941, "D": 941}
_HIGH = {"1": 1209, "4": 1209, "7": 1209, "*": 1209, "2": 1336, "5": 1336, "8": 1336, "0": 1336,
         "3": 1477, "6": 1477, "9": 1477, "#": 1477, "A": 1633, "B": 1633, "C": 1633, "D": 1633}


def dtmf_wav(keys: str, rate: int = 8000, tone: float = 0.08, gap: float = 0.06) -> bytes:
    """A 16-bit mono PCM WAV of the keys, each a two-tone burst (the DTMF standard's pairs)."""
    samples = []
    for k in keys:
        for i in range(int(rate * tone)):
            t = i / rate
            samples.append(0.45 * (math.sin(2 * math.pi * _LOW[k] * t) + math.sin(2 * math.pi * _HIGH[k] * t)))
        samples += [0.0] * int(rate * gap)
    return pcm_wav(samples, rate)


def pcm_wav(samples, rate: int = 8000) -> bytes:
    data = b"".join(struct.pack("<h", int(v * 32000)) for v in samples)
    fmt = struct.pack("<HHIIHH", 1, 1, rate, rate * 2, 2, 16)
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmt
            + b"data" + struct.pack("<I", len(data)) + data)


def test_dtmf_keys_reenter_as_text():
    wav = dtmf_wav("102*108*97#1A")
    assert R.d_dtmfwav(wav) == b"102*108*97#1A"
    assert R.d_dtmfwavsep(wav) == b"102 108 97 1A"
    assert R.d_dtmfwavsep(dtmf_wav("12345")) is None                    # no separator key: nothing to split
    assert R.d_dtmfwav(pcm_wav([0.0] * 8000)) is None                    # a second of silence
    noise = [math.sin(i * i * 0.37) * 0.5 for i in range(8000)]
    assert R.d_dtmfwav(pcm_wav(noise)) is None                          # no key pair in it
    assert R.d_dtmfwav(b"RIFF....WAVEjunk" * 4) is None                 # not readable PCM


def test_an_unsure_dtmf_reading_is_refused(monkeypatch):
    # carve_stego calls a recording cut short (longer than it was asked to read) unsure: no reading.
    wav = dtmf_wav("12345678")                                         # 1.12 s of keys
    monkeypatch.setattr(R, "_DTMF_MEMO", {})
    assert R.d_dtmfwav(wav) == b"12345678"
    monkeypatch.setattr(R, "_DTMF_MEMO", {})
    monkeypatch.setattr(R, "DTMF_SECONDS", 0.5)
    assert R.d_dtmfwav(wav) is None


def test_dtmf_recording_reaches_the_flag():
    wav = dtmf_wav("*".join(str(b) for b in FLAG.encode()))
    got = C.solve_blob(base64.b64encode(wav), budget=BUDGET)
    assert got is not None and got[0] == FLAG
    assert "dtmfwavsep" in got[1][0], got[1]
    with residuals_removed():
        assert [n for n, o in C._strict_steps(wav) if o and o.startswith(b"102")] == []


def test_a_missing_dtmf_reader_is_a_named_loud_refusal(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(R, "TOOLKITS", tmp_path)          # a checkout without the toolkit files
    monkeypatch.setattr(R, "_CARVE", [])
    monkeypatch.setattr(R, "_DTMF_MEMO", {})
    monkeypatch.setattr(R, "MISSING", {})
    assert R.d_dtmfwav(dtmf_wav("1234")) is None
    assert "carve_stego" in R.MISSING["dtmfwav"]
    assert "dtmfwav reader is unavailable" in capsys.readouterr().err


# ----------------------------------------------------------------------------------- QR from an image

def qr_png(payload: bytes, box: int = 3, border: int = 2) -> bytes:
    import qrcode
    q = qrcode.QRCode(box_size=box, border=border)
    q.add_data(payload)
    q.make()
    buf = io.BytesIO()
    q.make_image().save(buf, format="PNG")
    return buf.getvalue()


def test_qr_image_reenters_the_search():
    payload = base64.b64encode(FLAG.encode())
    png = qr_png(payload)
    assert R.d_qrimg(png) == payload
    got = C.solve_blob(png, budget=BUDGET)
    assert got is not None and got[0] == FLAG
    assert got[1] == [["qrimg", "b64"]], got[1]


def test_qr_refusals(monkeypatch):
    png = qr_png(b"hello qr")
    monkeypatch.setattr(R, "_QR_MEMO", {})
    monkeypatch.setattr(R, "QR_MAX_PIXELS", 100)          # the picture is far larger than that
    assert R.d_qrimg(png) is None
    monkeypatch.setattr(R, "QR_MAX_PIXELS", 512 * 512)
    monkeypatch.setattr(R, "_QR_MEMO", {})
    assert R.d_qrimg(png) == b"hello qr"
    assert R.d_qrimg(b"\x89PNG\r\n\x1a\n" + b"junk" * 50) is None     # the magic but no picture
    # only the four declared formats are opened (a TIFF Pillow could read is not this reader's shape)
    from PIL import Image
    buf = io.BytesIO()
    Image.open(io.BytesIO(png)).save(buf, format="TIFF")
    assert R.d_qrimg(buf.getvalue()) is None and list(R.steps(buf.getvalue())) == []
    with residuals_removed():
        assert strict_read(png, b"hello qr") == []


# ------------------------------------------------------------------------------------------- Chicken

PUSH = lambda v: v + 10   # noqa: E731  the opcode that pushes literal v


def test_chicken_peck_fr_bbq_semantics():
    # peck: value 7 into slot 2 (the first execution slot), then load it back with pick source 0.
    _, st = chicken.run([PUSH(99), PUSH(7), PUSH(2), 7, PUSH(2), 6, 0], with_stack=True)
    assert st[2] == 7 and st[-1] == 7
    # fr: a true condition skips the next opcode (push 5); a false one does not.
    _, st = chicken.run([PUSH(1), PUSH(1), 8, PUSH(5), PUSH(6)], with_stack=True)
    assert st[2:] == [6]
    _, st = chicken.run([PUSH(0), PUSH(1), 8, PUSH(5), PUSH(6)], with_stack=True)
    assert st[2:] == [5, 6]
    # a counted loop with fr: 3, then subtract 1 while non-zero (jump back 5 opcodes from after fr)
    prog = [PUSH(3),                      # counter
            PUSH(1), 3,                   # counter - 1
            PUSH(2), 6, 0,                # load slot 2 (the counter) as the condition
            PUSH(0), PUSH(9), 3,          # offset 0 - 9 = -9: back to PUSH(1)
            8]
    _, st = chicken.run(prog, with_stack=True)
    assert st[2:] == [0]
    # BBQ: the reference interpreter's HTML-escaped character
    assert chicken.run([PUSH(72), 9, PUSH(105), 9, 2]) == b"&#72;&#105;"


def chicken_program(text: str) -> bytes:
    ops = []
    for i, ch in enumerate(text.encode()):
        ops += [ch + 10, 9] + ([2] if i else [])
    return ("\n".join(" ".join(["chicken"] * op) for op in ops) + "\n").encode()


def test_chicken_program_reaches_the_flag():
    prog = chicken_program(FLAG)
    assert R.d_chicken(prog) == "".join("&#%d;" % b for b in FLAG.encode()).encode()
    got = C.solve_blob(prog, budget=BUDGET)
    assert got is not None and got[0] == FLAG
    assert got[1] == [["chicken", "html"]], got[1]
    with residuals_removed():
        assert [n for n, o in C._strict_steps(prog) if o and b"&#102;" in o] == []


def test_chicken_signature_refusals():
    assert R.d_chicken(b"chicken chicken\nchicken\n") is None          # fewer than three lines
    assert R.d_chicken(b"chicken\nchicken duck\nchicken\nchicken\n") is None
    bbq = " ".join(["chicken"] * 9).encode()
    assert R.d_chicken(b"chicken\n" + bbq + b"\nchicken\n") is None      # BBQ of a string: the VM refuses


# ----------------------------------------------------------------------------------------- Enigma M4

LONG = ("NICEWORKDECODINGTHISWARMUP" * 30)   # 780 letters: past a full turn of the middle rotor


@pytest.mark.parametrize("refl,thin", [("B", "Beta"), ("C", "Gamma")])
def test_m4_with_thin_wheel_at_a_is_the_m3(refl, thin):
    for rotors, rings, start, plug in ((("I", "II", "III"), "ABC", "QEV", "AB CD"),
                                       (("VI", "VIII", "IV"), "XYZ", "ZZA", ""),
                                       (("V", "III", "I"), "AAA", "DQV", "PO ML IU KJ")):
        m3 = K.enigma(LONG, rotors, refl, rings, start, plug)
        m4 = K.enigma(LONG, (thin,) + rotors, refl, "A" + rings, "A" + start, plug)
        assert m4 == m3
    # the counterpart: the thin wheel matters (Beta in front of thin C is not reflector C)
    assert K.enigma(LONG, ("Beta", "I", "II", "III"), "C", "AAAA", "AAAA") != K.enigma(LONG, ("I", "II", "III"), "C")
    # and a thin wheel moved off A is not the M3 any more, but is its own inverse
    ct = K.enigma_m4(LONG, (thin, "II", "IV", "I"), refl, "AAAA", "KAAA")
    assert ct != K.enigma(LONG, ("II", "IV", "I"), refl, "AAA", "AAA")
    assert K.enigma_m4(ct, (thin, "II", "IV", "I"), refl, "AAAA", "KAAA") == LONG


def test_m4_bad_settings_are_loud():
    with pytest.raises(ValueError):
        K.enigma_m4("ABC", ("I", "II", "IV", "V"), "B", "AAAA", "AAAA")     # no thin wheel first
    with pytest.raises(ValueError):
        K.enigma_m4("ABC", ("Beta", "II", "IV", "V"), "A", "AAAA", "AAAA")  # no thin A reflector
    with pytest.raises(ValueError):
        K.enigma_m4("ABC", ("Beta", "II", "IV", "V"), "B", "AAA", "AAAA")   # three rings for four wheels
    assert K.enigma_m4("ABC", ("Beta", "II", "IV", "V"), "UKW-B thin", "AAAA", "AAAA") == \
        K.enigma_m4("ABC", ("Beta", "II", "IV", "V"), "B", "AAAA", "AAAA")


def test_m4_settings_are_read_from_a_prompt():
    per_line = ("Rotor 1: Gamma, Start: Q, Ring: A\nRotor 2: IV, Start: R, Ring: B\nRotor 3: II, Start: S, Ring: C\n"
                "Rotor 4: V, Start: T, Ring: D\nReflector: UKW C thin\nPlugboard: AB CD EF\n")
    got = K.enigma_settings(per_line)
    assert got["rotors"] == ("Gamma", "IV", "II", "V") and got["start"] == "QRST" and got["rings"] == "ABCD"
    assert got["reflector"] == "C" and got["plugboard"] == "AB CD EF"
    one_line = K.enigma_settings("Rotors: Beta II IV I\nStart: ABCD\nReflector: B\n")
    assert one_line["rotors"] == ("Beta", "II", "IV", "I") and one_line["start"] == "ABCD"
    assert one_line["rings"] == "AAAA" and "rings=AAAA" in one_line["assumed"]
    # an M3 key still reads as before, and a thin wheel among three is no key
    assert K.enigma_settings("Rotors: I II III\nStart: ABC\n")["rotors"] == ("I", "II", "III")
    assert K.enigma_settings("Rotor 1: Beta\nRotor 2: II\nRotor 3: IV\n") is None


def test_crib_decode_reads_a_stated_m4_message():
    ct = K.enigma_m4(C.CRIB + SLUG, ("Gamma", "IV", "II", "V"), "C", "ABCD", "QRST", "AB CD EF")
    blob = ("Rotor 1: Gamma, Start: Q, Ring: A\nRotor 2: IV, Start: R, Ring: B\nRotor 3: II, Start: S, Ring: C\n"
            "Rotor 4: V, Start: T, Ring: D\nReflector: UKW C thin\nPlugboard: AB CD EF\n" + ct + "\n").encode()
    got = C.solve_blob(blob, budget=BUDGET)
    assert got is not None and labels.is_unsure(got[0]) and SLUG in got[0]
    assert C.LAST["route"] == "enigma" and C.LAST["slug"] == SLUG


# ------------------------------------------------------------------------ B6: keyed digit options

def _digit_writer(plain: str, key: str, kind: str, every: bool = False) -> str:
    """A Vigenere-family writer whose alphabet takes the digits in: letters mod 26, digits mod 10, the key
    advancing over both (and over every other character with `every`)."""
    ks = [ord(c) - 97 for c in key]
    out, i = [], 0
    for c in plain:
        if c.isalpha() or c.isdigit():
            k = ks[i % len(ks)]
            if c.isalpha():
                base = 65 if c.isupper() else 97
                x = ord(c) - base
                y = {"vigenere": x + k, "variant": x - k, "beaufort": k - x}[kind] % 26
                out.append(chr(y + base))
            else:
                x = int(c)
                out.append(str({"vigenere": x + k, "variant": x - k, "beaufort": k - x}[kind] % 10))
            i += 1
        else:
            out.append(c)
            i += every
    return "".join(out)


@pytest.mark.parametrize("kind", ["vigenere", "beaufort", "variant"])
@pytest.mark.parametrize("every", [False, True])
def test_keyed_digit_option_undoes_a_writer_who_moved_the_digits(kind, every):
    plain = C.CRIB + SLUG
    cipher = _digit_writer(plain, "lemon", kind, every)
    # the letters-only key (classical.py) reads the sentence and leaves the digits as written
    read = K.vigenere_decrypt(cipher, "lemon", kind, every)
    assert read[:-2] == plain[:-2] and read[-2:] == cipher[-2:]
    seen = read[len(C.CRIB):]
    options = dict(C._digit_options(seen, ("b64", "%s:lemon%s" % (kind, "+" if every else ""))))
    assert options["as_is"] == seen
    assert options["keyed"] == SLUG


def test_kbdw_digit_option_moves_the_digit_row():
    # a writer who moved letters n keys right in their rows moved 1234567890 n keys right too
    row = "1234567890"
    for n in (1, -1, 2):
        written = SLUG[:-2] + "".join(row[(row.index(c) + n) % 10] for c in SLUG[-2:])
        options = dict(C._digit_options(written, ("kbdw:%d" % n,)))
        assert options["kbdrow"] == SLUG, n


def test_other_chains_get_no_keyed_option():
    for chain in (("rot13",), ("atbash",), ("caesar3",), (), ("affine:3.5",), ("b64",)):
        names = [name for name, _ in C._digit_options(SLUG, chain)]
        assert "keyed" not in names and "kbdrow" not in names, chain


def test_the_keyed_option_is_offered_unsure_through_answer():
    answer, key = C._answer(SLUG, ("vigenere:lemon",), None)
    assert labels.is_unsure(answer) and key == "warmups.digits/vigenere"
    third = R.keyed_digit_option(SLUG, ("vigenere:lemon",), C.CRIB)
    assert third[0] == "keyed" and third[1] in answer


# ------------------------------------------------------------------------- per-variant repeating xor

def _xor(b: bytes, k: bytes) -> bytes:
    return bytes(x ^ k[i % len(k)] for i, x in enumerate(b))


def test_a_variant_record_is_read_with_its_own_xor_key(monkeypatch):
    day = b"\x11\x22\x33"
    crib = C.CRIB.encode()
    first = _xor(crib[:40], b"KEY")                       # this variant's own key
    middle = _xor(crib[40:], b"\x05\x06\x07\x08")         # another, at its own place in the sentence
    as_day = _xor(crib[:40], day)                         # the day's key still reads its records
    slug_only = _xor(SLUG.encode(), b"\x09\x0a")          # no sentence to read a key off: left alone
    monkeypatch.setattr(C, "_day_chain", lambda slot, *a, **k: ("xorkey:" + day.hex(),))
    parts = [(1, first), (2, middle), (3, as_day), (4, slug_only)]
    out = C._keyed_extra(parts, False, [{} for _ in parts], time.perf_counter() + BUDGET)
    assert out[0] == {C.CRIB[:40]: ("xorkey:" + b"KEY".hex(),)}
    assert out[1] == {C.CRIB[40:]: ("xorkey:05060708",)}
    assert out[2] == {C.CRIB[:40]: ("xorkey:" + day.hex(),)}
    assert list(out[3].values()) == [("xorkey:" + day.hex(),)]   # the day's chain, as before
    # the chain replays: the record read by the step it names gives the text
    assert C._apply_chain(("xorkey:" + b"KEY".hex(),), first) == C.CRIB[:40]


def test_variant_xor_declines_without_one_place():
    # a record that is not the sentence under any repeating key gives nothing
    assert C._variant_xor(("xorkey:112233",), bytes(range(60))) is None


# ------------------------------------------------------------------- verification round 1 (B-250 review)

def test_variant_xor_declines_a_record_that_fits_two_places():
    # A record the sentence reads at two places under two different repeating keys: its 24 bytes are the
    # sentence's first 24 under a 12-byte key, and its first 12 are also the sentence's last 12 under 'AB'.
    # Which key the writer used is not known, so the record is not read (one place only is the safety rule).
    crib = C.CRIB.encode()
    tail = crib[-12:]
    k1 = bytes(crib[i] ^ tail[i] ^ b"AB"[i % 2] for i in range(12))
    record = _xor(crib[:24], k1)
    assert K.crib_xor(record, crib[:24]) == k1                       # it fits the start under k1 ...
    assert K.crib_xor(record[:12], tail) == b"AB"                    # ... and the end under 'AB'
    assert C._variant_xor(("xorkey:112233",), record) is None
    # the counterpart: the same 24 bytes under a key that fits only at the start are read
    one = _xor(crib[:24], b"KEYKEYKEYKEY")
    assert C._variant_xor(("xorkey:112233",), one) == (("xorkey:" + b"KEY".hex(),), C.CRIB[:24])


def test_variant_xor_takes_no_one_byte_key():
    # a one-byte key is a single-byte xor (its own step reads it), not a variant's repeating key
    crib = C.CRIB.encode()
    assert C._variant_xor(("xorkey:112233",), _xor(crib[:40], b"\x07")) is None
    assert C._variant_xor(("xorkey:112233",), _xor(crib[:40], b"\x07\x08")) == (("xorkey:0708",), C.CRIB[:40])


def test_a_record_the_days_key_reads_keeps_the_days_chain(monkeypatch):
    # The day's key 11221122 reads the record into the sentence: its chain stays as the day wrote it, and the
    # record is not re-keyed (re-deriving would name the shorter 1122, a chain the day never had).
    day = b"\x11\x22\x11\x22"
    record = _xor(C.CRIB.encode()[:40], day)
    monkeypatch.setattr(C, "_day_chain", lambda slot, *a, **k: ("xorkey:" + day.hex(),))
    out = C._keyed_extra([(1, record)], False, [{}], time.perf_counter() + BUDGET)
    assert out == [{C.CRIB[:40]: ("xorkey:" + day.hex(),)}]


def test_qr_two_payloads_in_one_matrix_decline(monkeypatch):
    png = qr_png(b"hello qr")
    qm = R._qr_module()
    assert qm is not None, R.MISSING
    monkeypatch.setattr(R, "_QR_MEMO", {})
    # the toolkit (not the reader under test) reports two different payloads for the sampled matrix
    monkeypatch.setattr(qm, "decode_matrix", lambda matrix: [{"bytes": b"first"}, {"bytes": b"second"}])
    assert R.d_qrimg(png) is None
    # the counterpart: the same payload twice is one payload
    monkeypatch.setattr(R, "_QR_MEMO", {})
    monkeypatch.setattr(qm, "decode_matrix", lambda matrix: [{"bytes": b"first"}, {"bytes": b"first"}])
    assert R.d_qrimg(png) == b"first"


def test_m4_settings_refuse_a_second_thin_wheel():
    # Beta first is an M4 only when the three wheels after it are stepping rotors: a second thin wheel is no key
    assert K.enigma_settings("Rotor 1: Beta\nRotor 2: Gamma\nRotor 3: IV\nRotor 4: I\n") is None
    assert K.enigma_settings("Rotor 1: II\nRotor 2: Beta\nRotor 3: IV\nRotor 4: I\n") is None
    assert K.enigma_settings("Rotor 1: Beta\nRotor 2: II\nRotor 3: IV\nRotor 4: I\n")["rotors"] == ("Beta", "II", "IV", "I")


def test_chicken_peck_into_the_input_slot_is_loud():
    with pytest.raises(chicken.ChickenError, match="slot 1"):
        chicken.run([PUSH(5), PUSH(1), 7])
    with pytest.raises(chicken.ChickenError, match="slot 0"):
        chicken.run([PUSH(5), PUSH(0), 7])
    _, st = chicken.run([PUSH(5), PUSH(2), 7], with_stack=True)    # slot 2, the first execution slot, is fine
    assert st[2:] == [5]


def test_chicken_arithmetic_on_the_program_list_is_a_chicken_error():
    # pick source 0 index 0 is the program itself; adding a number to it is the VM's loud error, not a TypeError
    with pytest.raises(chicken.ChickenError, match="cannot add"):
        chicken.run([PUSH(0), 6, 0, PUSH(1), 2])
    prog = chicken.source_of([PUSH(0), 6, 0, PUSH(1), 2]).encode()
    assert R.d_chicken(prog) is None


# A Chicken program that doubles a string forever: slot 2 = "chicken"; loop: load slot 2 twice, add, peck the
# result back into slot 2, then jump back 14 opcodes (fr on a true condition).
_DOUBLER = [1,
            PUSH(2), 6, 0, PUSH(2), 6, 0, 2,          # slot 2 + slot 2
            PUSH(2), 7,                               # back into slot 2
            PUSH(1), PUSH(0), PUSH(14), 3, 8]         # condition 1, offset 0 - 14: back to the loop's start


def test_chicken_string_doubling_hits_the_cap():
    # 7 * 2**14 bytes passes the 64 KiB cap on the 14th pass (about 200 opcodes). The step budget of 250 lets
    # 17 passes run (7 * 2**17 bytes: harmless) so the string cap, not the step cap, must be what stops it.
    with pytest.raises(chicken.ChickenError, match="string value exceeds the output cap"):
        chicken.run(_DOUBLER, steps=250)
    # the counterpart: a few passes stop on the step cap, and one pass doubles the string
    with pytest.raises(chicken.ChickenError, match="step cap"):
        chicken.run(_DOUBLER, steps=1 + 14 * 3)
    _, st = chicken.run(_DOUBLER[:10], with_stack=True)
    assert st[2:] == ["chicken" * 2]


def test_d_chicken_reads_a_three_line_program():
    prog = chicken.source_of([PUSH(36), PUSH(36), 2]).encode() + b"\n"     # 36 + 36 = 72, 'H'
    assert R.d_chicken(prog) == b"H"
    assert R.d_chicken(chicken.source_of([PUSH(72), PUSH(0)]).encode()) is None   # two lines: under the floor


def test_dtmf_one_key_and_a_separator_led_single_run_are_refused(monkeypatch):
    monkeypatch.setattr(R, "_DTMF_MEMO", {})
    # one key is too little to re-enter as text
    assert R.d_dtmfwav(dtmf_wav("7")) is None
    assert R.d_dtmfwav(dtmf_wav("79")) == b"79"
    # a separator only before (or after) one run splits nothing: the plain reading already carries it
    assert R.d_dtmfwav(dtmf_wav("*123")) == b"*123"
    assert R.d_dtmfwavsep(dtmf_wav("*123")) is None
    assert R.d_dtmfwavsep(dtmf_wav("123#")) is None
    assert R.d_dtmfwavsep(dtmf_wav("12*3")) == b"12 3"
