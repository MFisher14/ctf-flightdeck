#!/usr/bin/env python3
"""Named WAV-stego tool catalog plus an offline password sweep (B-130, lane stego, wave: Pink 29
"White Noise", a 50-point / 71-solve row that stayed unsolved after the event's largest token spend).

Pink 29 ate ~1.96B agent tokens on bespoke probes (DSSS, seeded-position LSB/MSB, SSTV/DTMF/Morse)
and never found the embedding rule. The one idea left untried was a NAMED consumer WAV-stego tool
(S-Tools 4, WavSteg, ...) with a short password. This module is that Layer-1 audio lane: it

  1. FINGERPRINTS a WAV against the catalog of named consumer stego tools, and
  2. runs every extraction algorithm we can REPRODUCE faithfully in pure Python, each with an
     OFFLINE password sweep over a small committed wordlist (data/wav_stego_passwords.txt).

It sits next to solvers/toolkits/audio_stego.py (whose wav_channels / build_wav / aiff_samples it
reuses) and signal_stego_depth.read_audio, and hands self-validated payloads back the same way
stego_containers does. No network, no sandbox for the reproduced readers, nothing executed, and the
flag is never used or submitted: a found payload is a fact to hand the player, nothing more.

NEVER-WRONG RULE (the whole module turns on it): a payload is PLAIN only when it proves itself --
  * the pwlsb reader's 4-byte magic AND a CRC-32 over the payload both match (odds a wrong password
    passes: < 2**-64), or
  * stego_containers.validate_container returns a self-validated container (CRC/checksum), or
  * steghide's own CRC-32 validates (via stego_containers.steghide_channel, sandbox, off the clock).
Anything else -- a printable-looking LSB start, a structural-only file match, a named proprietary
tool whose crypto we do NOT reproduce -- is an UNSURE candidate or a human step, never plain.

THE PASSWORD-SWEEP EXCEPTION (documented): stego_tools.py / stego_containers.py forbid trying any
passphrase the question did not state. This module is the ONE deliberate exception: load_wordlist()
tries a small committed list of common stego passphrases. It is allowed because every candidate is
self-checked by magic+CRC (a wrong word cannot produce a false positive), the list is small and
committed (not a brute force), the sweep is fully offline, and it is applied ONLY to the stego
passphrase of the reproduced pwlsb reader -- NEVER to an archive password (those stay the player's,
via solvers/common/archive_passwords.py) and never to steghide beyond the question's own word list.

Public API (bytes in, a Reading out; nothing executed or written):

  catalog()                              the named-tool catalog as CatalogEntry rows
  fingerprint(data)                      which catalog tools the carrier looks like, + what to run now
  load_wordlist(extra=())                the committed sweep list (+ any extra words), de-duped
  recover_wavsteg(data)                  stego-lsb WavSteg: sequential N-LSB, self-checked by container
  recover_pwlsb(data, passwords)         password-seeded LSB container (magic+len+CRC32), the sweep core
  index_stream(password, num_samples)    the pwlsb placement: a deterministic distinct-index stream
  offline_sweep(data, *, passwords=None, question_words=(), use_sandbox=False)
                                         run every reproduced reader + the sweep; the ONE plain or
                                         the catalog's human steps

No `solve_set`, no `signals`: a hand tool, like audio_stego.py and stego_tools.py.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(COMMON), str(HERE)):
    if _p not in sys.path:
        sys.path.append(_p)

import audio_stego          # noqa: E402  (wav_channels, build_wav, aiff_samples)
import stego_containers     # noqa: E402  (validate_container, steghide_channel, Finding)

WORDLIST = HERE / "data" / "wav_stego_passwords.txt"
PWLSB_MAGIC = b"PWL1"               # the reproduced password-seeded container's header magic
MAX_SWEEP_PAYLOAD = 1 << 16         # bytes of payload the sweep will read+validate from one carrier
MAX_PWLSB_SAMPLES = 1 << 23         # samples the index stream will range over (bounded)
MAX_WORD_BYTES = 128                # a wordlist entry longer than this is skipped
WAVSTEG_LSB = (1, 2, 3, 4)          # bits-per-sample the WavSteg reader sweeps
CONTAINER_READ_CAP = 1 << 18        # bytes pulled from a sequential-LSB stream before giving up


# --------------------------------------------------------------------------- the Reading

@dataclass
class Reading:
    """One sweep's verdict. plain is set ONLY for a self-validated payload (see the never-wrong rule);
    candidates are established-but-unproven readings; human_steps name the named tools we cannot run."""
    plain: bytes | None = None
    validated: bool = False
    tool: str = ""                      # which reproduced reader proved it
    method: str = ""                    # how (e.g. "pwlsb magic+crc32, password '<6 chars, starts s>'")
    password: str | None = None         # the passphrase that opened it (a finding to hand the player)
    kind: str | None = None             # sniff() of the payload
    candidates: list = field(default_factory=list)   # [(name, value)] unsure
    need_password: bool = False
    notes: list = field(default_factory=list)
    human_steps: list = field(default_factory=list)

    def __bool__(self):
        return self.plain is not None or bool(self.candidates) or self.need_password


def mask(value) -> str:
    """How a passphrase is shown in any note: its length and first character only (never the whole
    value in a log line). The full value lives in Reading.password for the player."""
    if value is None:
        return "<none>"
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value)
    if not value:
        return "<empty>"
    first = value[0] if value[0].isalnum() else "?"
    return f"<{len(value)} chars, starts {first}>"


# --------------------------------------------------------------------------- the named-tool catalog

@dataclass(frozen=True)
class CatalogEntry:
    key: str
    name: str
    aliases: tuple
    carriers: tuple
    password: bool               # the tool takes a passphrase
    reproduced: bool             # we extract it faithfully in pure Python (so the sweep can run it)
    self_check: str              # how a correct extraction proves itself (or "" when none)
    human_step: str              # what the operator must do when we cannot reproduce it
    refs: str                    # one-line note on the published algorithm / fingerprint


CATALOG = (
    CatalogEntry(
        key="wavsteg", name="WavSteg (stego-lsb / stegolsb)",
        aliases=("stego-lsb", "stegolsb", "lsbsteg", "wav-steg"),
        carriers=("wav",), password=False, reproduced=True,
        self_check="the recovered bytes are a self-validating container (CRC/checksum/magic)",
        human_step="",
        refs="MIT stego-lsb: payload bits written into the low N bits of each PCM sample, "
             "sequential, MSB-first; no header, so acceptance is via validate_container only."),
    CatalogEntry(
        key="pwlsb", name="password-seeded LSB container (S-Tools-family mechanism)",
        aliases=("stools-mechanism", "seeded-lsb", "password-lsb"),
        carriers=("wav",), password=True, reproduced=True,
        self_check="a 4-byte magic and a CRC-32 over the payload",
        human_step="",
        refs="the reproducible, self-checking core shared by password-seeded LSB audio tools: a "
             "passphrase seeds the per-bit sample placement and a magic+len+CRC32 header proves the "
             "read. This is what the OFFLINE wordlist sweep runs; it is NOT byte-exact S-Tools."),
    CatalogEntry(
        key="steghide", name="Steghide (WAV/AU cover)",
        aliases=("steghide-wav",), carriers=("wav", "au"), password=True, reproduced=False,
        self_check="steghide's own CRC-32 over the payload",
        human_step="run the reproduced reader via tools/sandbox.py (stego_containers.steghide_channel, "
                   "off the clock); it is self-checking, but needs the csctf-sandbox image.",
        refs="steghide embeds a CRC-32; extraction is self-proving. Handled by stego_containers, "
             "which only tries the empty passphrase and the question's own word list."),
    CatalogEntry(
        key="stools4", name="S-Tools 4 (Andy Brown)",
        aliases=("s-tools", "stools"), carriers=("wav",), password=True, reproduced=False,
        self_check="",
        human_step="run S-Tools 4 by hand on a Windows host (NEVER here: it is a Windows binary; do "
                   "not run it natively, under wine, or in Docker). Try the committed wordlist and "
                   "the question's words as the passphrase.",
        refs="proprietary: a passphrase seeds pseudo-random LSB placement and selects the cipher "
             "(IDEA/DES/3DES/MDC). The crypto is not reproduced, so an S-Tools payload cannot be "
             "self-checked here -- the pwlsb reader covers the reproducible mechanism only."),
    CatalogEntry(
        key="invisible_secrets", name="Invisible Secrets 4 (NeoByte)",
        aliases=("invisiblesecrets", "invsecrets"), carriers=("wav",), password=True, reproduced=False,
        self_check="",
        human_step="run Invisible Secrets by hand on a Windows host (never here). The container and "
                   "crypto (AES/Blowfish/Twofish/...) are undocumented.",
        refs="proprietary, undocumented container + passphrase crypto. Fingerprint + human step only."),
    CatalogEntry(
        key="xiao", name="Xiao Steganography",
        aliases=("xiao-steganography",), carriers=("wav", "bmp"), password=True, reproduced=False,
        self_check="",
        human_step="run Xiao Steganography by hand on a Windows host (never here). Proprietary "
                   "header + RC4/3DES passphrase crypto.",
        refs="proprietary, undocumented. Fingerprint + human step only."),
    CatalogEntry(
        key="openpuff", name="OpenPuff",
        aliases=("open-puff", "puff"), carriers=("wav",), password=True, reproduced=False,
        self_check="",
        human_step="run OpenPuff by hand (never here). It needs up to three passwords, carrier "
                   "chains, scrambling and AES/3DES: not reproducible from the carrier alone.",
        refs="multi-password, multi-carrier, whitening + AES. Fingerprint + human step only."),
)


def catalog() -> tuple:
    return CATALOG


def _entry(key: str) -> CatalogEntry:
    for e in CATALOG:
        if e.key == key:
            return e
    raise KeyError(key)


# --------------------------------------------------------------------------- the wordlist

def load_wordlist(extra=()) -> list:
    """The committed sweep list plus any `extra` words, de-duplicated in order (committed first).
    Fails loudly (FileNotFoundError) if the committed list is missing -- no silent empty sweep."""
    if not WORDLIST.exists():
        raise FileNotFoundError(f"the committed WAV-stego wordlist is missing: {WORDLIST} "
                                "(a missing corpus must fail loudly, not sweep nothing)")
    words, seen = [], set()
    for line in WORDLIST.read_text(encoding="utf-8").splitlines():
        line = line.rstrip("\r\n")
        if not line or line.lstrip().startswith("#"):
            continue
        if line not in seen and len(line.encode("utf-8")) <= MAX_WORD_BYTES:
            seen.add(line)
            words.append(line)
    for w in extra:
        w = str(w)
        if w and w not in seen and len(w.encode("utf-8")) <= MAX_WORD_BYTES:
            seen.add(w)
            words.append(w)
    return words


# --------------------------------------------------------------------------- WAV samples

def _flat_samples(data: bytes):
    """(info-ish dict, flat interleaved int sample list) of a PCM WAV or AIFF, or None.
    Reuses audio_stego so the catalog and the transform lane read the same bytes the same way."""
    got = audio_stego.wav_channels(data)
    if got:
        info, chans = got
        n = min((len(c) for c in chans), default=0)
        flat = [chans[c][f] for f in range(n) for c in range(len(chans))]
        return {"rate": info["rate"], "bits": info["bits"], "channels": len(chans)}, flat
    aiff = audio_stego.aiff_samples(data)
    if aiff:
        rate, bits, chans = aiff
        n = min((len(c) for c in chans), default=0)
        flat = [chans[c][f] for f in range(n) for c in range(len(chans))]
        return {"rate": rate, "bits": bits, "channels": len(chans), "aiff": True}, flat
    return None


# --------------------------------------------------------------------------- pwlsb: placement + header

def index_stream(password, num_samples: int):
    """The pwlsb bit placement: a deterministic stream of DISTINCT sample indices in [0, num_samples),
    seeded by the passphrase only (so it is prefix-stable -- the header's positions are the same
    whether the caller reads 96 bits or the whole record). idx_i = SHA-256(password || i) mod n, with
    collisions skipped. Reproducible: the embedder and the reader both call this. Yields indefinitely
    (up to num_samples distinct values); the caller takes as many as it needs."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    n = int(num_samples)
    if n <= 0:
        return
    seen = set()
    key = hashlib.sha256(b"wav-stego-pwlsb\x00" + bytes(password)).digest()
    i = 0
    while len(seen) < n:
        h = hashlib.sha256(key + i.to_bytes(8, "big")).digest()
        idx = int.from_bytes(h[:8], "big") % n
        i += 1
        if idx in seen:
            continue
        seen.add(idx)
        yield idx


def _bits_at(samples, indices) -> list:
    return [samples[k] & 1 for k in indices]


def _bits_to_bytes(bits) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for k in range(8):
            byte = (byte << 1) | (bits[i + k] & 1)
        out.append(byte)
    return bytes(out)


def _bytes_to_bits(data: bytes) -> list:
    return [(b >> (7 - k)) & 1 for b in data for k in range(8)]


def pwlsb_record(payload: bytes) -> bytes:
    """The pwlsb record bytes for a payload: MAGIC(4) + len(u32 LE) + crc32(u32 LE) + payload. The
    reader parses exactly this; build_pwlsb_wav() lays it into a carrier (its own round-trip test
    cross-checks it against the suite's independent embedder)."""
    import zlib
    body = bytes(payload)
    return PWLSB_MAGIC + struct.pack("<II", len(body), zlib.crc32(body) & 0xFFFFFFFF) + body


def build_pwlsb_wav(cover: bytes, payload: bytes, password) -> bytes:
    """Embed `payload` into PCM-WAV `cover` under `password`, in the reproduced pwlsb layout, and
    return new WAV bytes. This is the published algorithm the reader inverts; a dedicated test
    round-trips it AND cross-checks its bytes against the suite's independent embedder (the main
    recovery tests use that independent embedder, so the reader is never tested against itself).
    Raises ValueError when the cover is too small or not PCM WAV."""
    got = audio_stego.wav_channels(cover)
    if not got:
        raise ValueError("cover is not a PCM WAV this embedder reads")
    info, chans = got
    n = min(len(c) for c in chans)
    nch = len(chans)
    record = pwlsb_record(payload)
    bits = _bytes_to_bits(record)
    total = n * nch
    if len(bits) > total:
        raise ValueError(f"cover holds {total} samples, payload needs {len(bits)} bits")
    stream = index_stream(password, total)
    positions = [next(stream) for _ in range(len(bits))]
    for pos, bit in zip(positions, bits):
        f, c = divmod(pos, nch)
        # setting the integer's low bit is the same op for signed and unsigned PCM (audio_stego
        # round-trips 8-bit as unsigned and the rest as signed, so the int value is what matters).
        chans[c][f] = (chans[c][f] & ~1) | bit
    return audio_stego.build_wav(info["rate"] or 8000, info["bits"], chans)


def _read_pwlsb_with(samples, password):
    """Read one pwlsb record from `samples` under `password`. Returns payload bytes on a full
    magic+len+CRC match, else None. Cheap for a wrong password: it reads 96 header bits, and only a
    matching magic makes it read the payload."""
    import zlib
    total = len(samples)
    if total < 96:
        return None
    cap = min(total, MAX_PWLSB_SAMPLES)
    stream = index_stream(password, cap)
    try:
        header_idx = [next(stream) for _ in range(96)]
    except StopIteration:
        return None
    header = _bits_to_bytes(_bits_at(samples, header_idx))
    if len(header) < 12 or header[:4] != PWLSB_MAGIC:
        return None
    length, crc = struct.unpack_from("<II", header, 4)
    if not (1 <= length <= MAX_SWEEP_PAYLOAD) or 96 + length * 8 > cap:
        return None
    try:
        payload_idx = [next(stream) for _ in range(length * 8)]
    except StopIteration:
        return None
    payload = _bits_to_bytes(_bits_at(samples, payload_idx))[:length]
    if len(payload) == length and (zlib.crc32(payload) & 0xFFFFFFFF) == crc:
        return payload
    return None


def recover_pwlsb(data: bytes, passwords) -> Reading:
    """The offline password sweep over the reproduced pwlsb layout. Tries each password until the
    magic+CRC proves a payload (never-wrong: a wrong word cannot pass). Returns a Reading with plain
    set on the first match, or notes that nothing in the list opened it."""
    got = _flat_samples(data)
    if not got:
        return Reading(notes=["not a PCM WAV or AIFF this reader decodes: pwlsb sweep not run"])
    _, samples = got
    tried = 0
    for pw in passwords:
        tried += 1
        payload = _read_pwlsb_with(samples, pw)
        if payload is not None:
            import carve_stego as cs
            return Reading(plain=payload, validated=True, tool="pwlsb",
                           method=f"pwlsb magic+crc32, password {mask(pw)}", password=str(pw),
                           kind=cs.sniff(payload),
                           notes=[f"pwlsb: self-validated {len(payload)}-byte payload after {tried} word(s)"])
    return Reading(notes=[f"pwlsb: none of the {tried} swept word(s) opened a pwlsb container"])


# --------------------------------------------------------------------------- WavSteg (sequential N-LSB)

def recover_wavsteg(data: bytes) -> Reading:
    """stego-lsb WavSteg: payload bits live in the low N bits of each PCM sample, sequential. We do
    not know N, so sweep N in 1..4 and accept a plane ONLY when validate_container self-validates the
    recovered bytes. PLAIN when exactly one distinct validated payload is found across every N;
    printable-but-unproven starts become candidates (unsure)."""
    got = _flat_samples(data)
    if not got:
        return Reading(notes=["not a PCM WAV or AIFF this reader decodes: WavSteg read not run"])
    _, samples = got
    plains = {}             # payload bytes -> method
    cand_seen = set()
    candidates = []
    for num_lsb in WAVSTEG_LSB:
        mask_bits = (1 << num_lsb) - 1
        bits = []
        for s in samples:
            v = s & mask_bits
            for k in range(num_lsb - 1, -1, -1):     # MSB-first within the N stolen bits
                bits.append((v >> k) & 1)
            if len(bits) >= CONTAINER_READ_CAP * 8:
                break
        blob = _bits_to_bytes(bits)
        f = stego_containers.validate_container(blob)
        tag = f"wavsteg N={num_lsb}"
        if f.plain is not None:
            plains.setdefault(bytes(f.plain), f"{tag}: {f.method}")
        else:
            for name, value in f.candidates:
                key = (name, value if isinstance(value, str) else bytes(value))
                if key not in cand_seen:
                    cand_seen.add(key)
                    candidates.append((f"{name} ({tag})", value))
    if len(plains) == 1:
        import carve_stego as cs
        payload, method = next(iter(plains.items()))
        return Reading(plain=payload, validated=True, tool="wavsteg", method=method,
                       kind=cs.sniff(payload),
                       notes=[f"WavSteg: self-validated {len(payload)}-byte payload ({method})"])
    if len(plains) > 1:
        return Reading(candidates=candidates,
                       notes=[f"WavSteg: {len(plains)} distinct self-validated payloads; ambiguous, no plain"])
    return Reading(candidates=candidates,
                   notes=["WavSteg: no self-validating container in N=1..4" if not candidates
                          else "WavSteg: only unproven printable starts (unsure)"])


# --------------------------------------------------------------------------- fingerprint

def fingerprint(data: bytes) -> dict:
    """Which catalog tools the carrier could be from, and what to run now. Heuristics only -- a WAV
    rarely identifies its tool -- so this never returns a payload; it ranks the lane:

      {carrier, run_now: [keys of reproduced readers to run], human: [(key, reason)], notes: [...]}

    run_now is the automated Layer-1 lane (the whole point of B-130: try the named-tool lane before a
    deep bespoke search). human lists the named tools we cannot reproduce, each with its step."""
    out = {"carrier": None, "run_now": [], "human": [], "notes": []}
    got = _flat_samples(data)
    if not got:
        out["notes"].append("not a PCM WAV or AIFF: the named WAV-stego lane does not apply")
        return out
    info, samples = got
    out["carrier"] = ("aiff" if info.get("aiff") else "wav")
    out["notes"].append(f"{out['carrier'].upper()} PCM: {info['channels']} ch, {info.get('rate')} Hz, "
                        f"{info['bits']} bit, {len(samples)} samples")
    # the reproduced readers always run (cheap, offline, self-checking)
    out["run_now"] = ["wavsteg", "pwlsb"]
    # trailing bytes after the RIFF data chunk are a weak hint of an append-style tool
    if out["carrier"] == "wav":
        import carve_stego as cs
        wi = cs.wav_info(data)
        if wi and wi["data_offset"] is not None:
            end = wi["data_offset"] + wi["data_size"]
            if end + 8 < len(data):
                out["notes"].append(f"{len(data) - end} bytes trail the RIFF data chunk "
                                    "(appended payload?): carve the tail as well")
    # the named proprietary tools: human steps (never run here)
    for e in CATALOG:
        if not e.reproduced and out["carrier"] in e.carriers:
            out["human"].append((e.key, e.human_step))
    return out


# --------------------------------------------------------------------------- the whole lane

def offline_sweep(data: bytes, *, passwords=None, question_words=(), use_sandbox: bool = False) -> Reading:
    """Run every reproduced reader plus the offline password sweep, in cost order, and return the ONE
    self-validated plain, or a Reading that carries the unsure candidates and the named tools' human
    steps. `passwords` overrides the committed list; `question_words` are added to it. `use_sandbox`
    also tries steghide (stego_containers.steghide_channel, off the clock) -- a sandbox tool, so it
    is off by default. Never raises on bad input; a non-WAV carrier returns a note."""
    fp = fingerprint(data)
    if fp["carrier"] is None:
        return Reading(notes=fp["notes"])

    reading = Reading(notes=list(fp["notes"]))

    # 1) WavSteg (no password): cheapest, self-checked by the container.
    w = recover_wavsteg(data)
    reading.notes += w.notes
    if w.plain is not None:
        w.notes = reading.notes
        w.human_steps = [f"{k}: {s}" for k, s in fp["human"]]
        return w
    reading.candidates += w.candidates

    # 2) the offline password sweep over the reproduced pwlsb layout.
    words = list(passwords) if passwords is not None else load_wordlist(extra=question_words)
    p = recover_pwlsb(data, words)
    reading.notes += p.notes
    if p.plain is not None:
        p.notes = reading.notes
        p.candidates = reading.candidates
        p.human_steps = [f"{k}: {s}" for k, s in fp["human"]]
        return p

    # 3) steghide (self-checking, but it needs the sandbox): only when asked, and only the empty
    #    passphrase + the question's own words (stego_containers enforces that; NOT the sweep list).
    if use_sandbox:
        try:
            f = stego_containers.steghide_channel(data, words=("\n".join(question_words) if question_words else None))
        except Exception as e:            # noqa: BLE001 - the sandbox path must never crash the lane
            f = None
            reading.notes.append(f"steghide: not run ({type(e).__name__})")
        if f is not None:
            reading.notes.append(f.note)
            if f.plain is not None:
                import carve_stego as cs
                return Reading(plain=bytes(f.plain), validated=True, tool="steghide", method=f.method,
                               kind=cs.sniff(bytes(f.plain)), notes=reading.notes,
                               human_steps=[f"{k}: {s}" for k, s in fp["human"]])
            if f.need_password:
                reading.need_password = True

    # nothing reproduced proved a payload: hand back candidates + the named tools' human steps.
    reading.human_steps = [f"{k}: {s}" for k, s in fp["human"]]
    if not reading.candidates and not reading.need_password:
        reading.notes.append("no reproduced reader proved a payload; if this is a named consumer tool "
                             "(S-Tools/Invisible Secrets/Xiao/OpenPuff) run it by hand per the human steps")
    return reading


# --------------------------------------------------------------------------- command

def _render(path, r: Reading) -> None:
    import hashlib as _h
    import carve_stego as cs
    print(f"== {path}")
    for note in r.notes:
        print(f"   note   {note}")
    if r.plain is not None:
        # never print the payload bytes (they may be the flag): only its shape.
        print(f"   PLAIN  tool={r.tool} method={r.method} {len(r.plain)} bytes "
              f"sha256={_h.sha256(r.plain).hexdigest()[:16]} kind={cs.sniff(r.plain)}")
        if r.password is not None:
            print(f"          passphrase available to the player: {mask(r.password)}")
    for name, value in r.candidates[:12]:
        shown = value if isinstance(value, str) else f"{len(value)} bytes"
        print(f"   unsure {name}: {shown[:120] if isinstance(shown, str) else shown}")
    if r.need_password:
        print("   STOP   a passphrase is expected but none offline opened it: ask the player")
    for step in r.human_steps:
        print(f"   human  {step}")


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    if argv[0] == "--catalog":
        for e in CATALOG:
            flag = "reproduced" if e.reproduced else "human-step"
            print(f"{e.key:18} {flag:11} pw={'y' if e.password else 'n'}  {e.name}")
            print(f"                   {e.refs}")
        return 0
    want_sandbox, words, files = False, [], []
    it = iter(argv)
    for a in it:
        if a == "--sandbox":
            want_sandbox = True
        elif a == "--word":
            words.append(next(it, ""))
        elif a.startswith("--"):
            print(f"wav_stego_tools: unknown option {a}", file=sys.stderr)
            return 2
        else:
            files.append(a)
    for path in files:
        data = Path(path).read_bytes()
        r = offline_sweep(data, question_words=tuple(words), use_sandbox=want_sandbox)
        _render(path, r)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
