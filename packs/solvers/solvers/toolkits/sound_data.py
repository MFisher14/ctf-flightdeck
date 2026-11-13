#!/usr/bin/env python3
"""Data-over-sound decoder hub: ONE obvious entry per sound-encoding archetype (CSCTF audio / misc).

CTF audio challenges hide a payload in a WAV one of a few standard ways. This module is the single
dispatcher that routes each to the right tool and, where a decoder is not worth re-implementing,
prints the exact offline recipe. It is OFFLINE and STATIC: a WAV is *analysed*, never "played", and
nothing here submits -- it prints decoded payloads as CANDIDATES for you to read and highlights any
CSCTF{...} / CTF{...} hit for you to reason about and submit once through the guard.

Archetypes and where each goes:

  (a) ggwave            data-over-sound (ultrasonic or audible FSK chirps; 2025 "Brainrottalk").
                        decode_ggwave() uses the pip `ggwave` codec when importable (one-shot decode
                        of the whole int16 buffer, the file's own samplerate fed to ggwave). When
                        ggwave is NOT importable it prints the exact `ggwave` CLI / one-liner recipe.
  (b) DTMF              dual-tone phone keypad in a REAL recording. Routed to carve_stego.dtmf
                        (Goertzel power at the eight DTMF frequencies over 20 ms windows) + dtmf_read
                        for the "sure" flag. The SYMBOLIC side -- a list of tone pairs or key presses
                        you already read off a table/OCR -> digits/letters -- is keypad.py.
  (c) CyberSonics tones one tone block per character, freq = base + step*code (or nearest-cluster).
                        Routed to audio_tones.decode (FFT peak per block, linear/cluster/XOR modes).
  (d) AFSK/Bell202/FSK  a soft-modem (Bell 202, 1200-baud packet, RTTY) or Morse-from-audio. We do
      & Morse-from-audio NOT re-implement a modem -- recipes() prints the Docker multimon-ng /
                        minimodem invocations (run via tools/sandbox.py).

Container formats other than WAV (mp3/m4a/flac/ogg without the soundfile path): transcode to a PCM
WAV with ffmpeg INSIDE the sandbox first (`tools/sandbox.py`), then point this at the wav.

API:
  load_wav(path)            -> WavData(int16 mono bytes, samplerate, nframes, nchannels, source)
  decode_ggwave(path)       -> {available, payload, candidates, recipe, ...}
  decode_dtmf(path)         -> {keys, sure, candidates, ...}   (via carve_stego)
  decode_tones(path, **kw)  -> audio_tones.decode result (CyberSonics)
  recipes()                 -> str   (the multimon-ng / minimodem / ggwave-cli recipe card)
  analyze(path)             -> {archetypes: {...}, flags: [...]}   (try a, b, c; point at d)
  find_flags(text|iterable) -> [CSCTF{...}, ...]

CLI:
  sound_data.py <wavfile>            # auto: try ggwave, DTMF, tones; print the modem/Morse recipe
  sound_data.py ggwave <wavfile>     # ggwave codec (or the recipe if ggwave is absent)
  sound_data.py dtmf   <wavfile>     # DTMF via Goertzel
  sound_data.py tones  <wavfile> ... # CyberSonics tone ladder (forwards flags to audio_tones)
  sound_data.py recipes              # print the modem / Morse / ggwave-cli recipe card
  [--json]
"""
import argparse
import json
import sys
import wave
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

try:
    import numpy as np
except Exception:  # pragma: no cover - numpy is a venv dependency
    np = None

try:
    import soundfile as sf
except Exception:  # pragma: no cover - soundfile is optional (WAV works without it)
    sf = None

FLAG_RE = flagfmt.TEXT

MAX_SAMPLES = 48 * 1024 * 1024          # bound on frames read from one recording
GGWAVE_RATE = 48000                     # ggwave's native samplerate


# ---- recipes (printed when a decoder is not worth re-implementing) ----------------------------

GGWAVE_CLI_RECIPE = """\
ggwave not importable in this venv. Decode the WAV offline with the ggwave codec:

  # python one-liner (reads a PCM-16 WAV, feeds the whole buffer to ggwave):
  .venv/bin/python - <<'PY'
  import ggwave, wave, numpy as np
  w = wave.open("CHALLENGE.wav"); sr = w.getframerate()
  raw = w.readframes(w.getnframes())
  a = np.frombuffer(raw, dtype=np.int16)
  if w.getnchannels() > 1: a = a.reshape(-1, w.getnchannels()).mean(1).astype(np.int16)
  inst = ggwave.init({**ggwave.getDefaultParameters(), "sampleRateInp": float(sr)})
  print(ggwave.decode(inst, a.tobytes()))
  PY

  # or the reference CLI if you have the ggwave repo built:
  ggwave-to-file -h                         # (encode side)
  # decode: build ggwave's `ggwave-rx` / `waveshare` example and pipe the WAV in,
  # or use the browser tool at https://waver.ggerganov.com (offline bundle)."""

MODEM_RECIPE = """\
AFSK / Bell 202 / 1200-baud packet / RTTY / Morse-from-audio: do NOT re-implement a modem.
Demodulate in the Docker sandbox (offline, --network none):

  python3 tools/sandbox.py run --in a.wav  multimon-ng -a MORSE_CW {in}     # Morse (CW) tones
  python3 tools/sandbox.py run --in a.wav  multimon-ng -a AFSK1200 {in}     # Bell 202 / APRS 1200
  python3 tools/sandbox.py run --in a.wav  multimon-ng -a POCSAG512 {in}    # pager POCSAG
  python3 tools/sandbox.py run --in a.wav  minimodem --rx 1200 {in}         # generic 1200-baud FSK
  python3 tools/sandbox.py run --in a.wav  minimodem --rx 300  {in}         # Bell 103 / RTTY-ish
  python3 tools/sandbox.py run --in a.wav  ffprobe {in}                     # container / sample rate

multimon-ng wants 22050 Hz mono s16le; if it is silent, transcode first:
  python3 tools/sandbox.py run --in a.wav  ffmpeg -i {in} -ar 22050 -ac 1 -f s16le - | multimon-ng -t raw -a AFSK1200 -"""


def recipes() -> str:
    """The offline recipe card for the archetypes this module routes out (modem/Morse) plus ggwave."""
    return MODEM_RECIPE + "\n\n" + "ggwave (if the codec is unavailable):\n" + GGWAVE_CLI_RECIPE


# ---- WAV loading (stdlib first, soundfile for flac/ogg/float) ----------------------------------

class WavData:
    """Mono int16 PCM view of a recording: `.pcm` (bytes, little-endian s16), `.samplerate`,
    `.nframes` (mono frames), `.nchannels` (original), `.source` ('wave' | 'soundfile')."""

    __slots__ = ("pcm", "samplerate", "nframes", "nchannels", "source")

    def __init__(self, pcm, samplerate, nframes, nchannels, source):
        self.pcm = pcm
        self.samplerate = samplerate
        self.nframes = nframes
        self.nchannels = nchannels
        self.source = source

    def int16(self):
        """numpy int16 array of the mono samples (requires numpy)."""
        if np is None:
            raise RuntimeError("numpy is required")
        return np.frombuffer(self.pcm, dtype=np.int16)


def _to_mono_int16(arr, nchannels):
    """Mix an interleaved int-or-float array down to mono int16 bytes."""
    if np is None:
        raise RuntimeError("numpy is required to load audio")
    a = np.asarray(arr)
    was_float = np.issubdtype(a.dtype, np.floating)
    orig_dtype = a.dtype
    if nchannels and nchannels > 1 and a.ndim == 1:
        a = a.reshape(-1, nchannels)
    if a.ndim == 2:
        a = a.mean(axis=1)                 # may promote integer samples to float; units are unchanged
    if was_float:
        a = np.clip(a, -1.0, 1.0)
        a = np.round(a * 32767.0).astype(np.int16)
    elif orig_dtype != np.int16:
        # scale any wider integer width down to int16 (units preserved through the mean)
        info = np.iinfo(orig_dtype)
        a = (a.astype(np.float64) / max(abs(info.min), info.max) * 32767.0).round().astype(np.int16)
    else:
        a = np.round(a).astype(np.int16)   # int16 means are already in sample units; just re-round
    return a.astype(np.int16).tobytes(), a.size


def load_wav(path):
    """Load a recording to a mono int16 WavData. Uses the stdlib `wave` module for PCM WAV (no
    dependency); falls back to soundfile for float WAV / flac / ogg. Raises on an unreadable file."""
    path = Path(path)
    # stdlib wave first: handles 8/16/24/32-bit PCM WAV with no third-party dependency.
    try:
        with wave.open(str(path), "rb") as w:
            sr = w.getframerate()
            ch = w.getnchannels()
            width = w.getsampwidth()
            nframes = min(w.getnframes(), MAX_SAMPLES)
            raw = w.readframes(nframes)
        if np is None:
            raise RuntimeError("numpy is required to load audio")
        if width == 1:                       # unsigned 8-bit
            a = (np.frombuffer(raw, dtype=np.uint8).astype(np.int16) - 128) * 256
        elif width == 2:
            a = np.frombuffer(raw[:len(raw) // 2 * 2], dtype=np.int16)
        elif width == 4:
            a = (np.frombuffer(raw[:len(raw) // 4 * 4], dtype=np.int32).astype(np.float64) / 2147483648.0 * 32767.0)
            a = a.astype(np.int16)
        elif width == 3:                     # packed 24-bit
            b = np.frombuffer(raw[:len(raw) // 3 * 3], dtype=np.uint8).reshape(-1, 3).astype(np.int32)
            v = (b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16))
            v = np.where(v & 0x800000, v - 0x1000000, v)
            a = (v.astype(np.float64) / 8388608.0 * 32767.0).astype(np.int16)
        else:
            raise wave.Error(f"unsupported sample width {width}")
        pcm, n = _to_mono_int16(a, ch)
        return WavData(pcm, int(sr), n, int(ch), "wave")
    except (wave.Error, EOFError):
        pass
    # soundfile fallback: float WAV, flac, ogg, etc.
    if sf is None:
        raise RuntimeError(f"{path} is not a readable PCM WAV and soundfile is unavailable "
                           "(transcode to PCM WAV with ffmpeg in the sandbox first)")
    try:
        data, sr = sf.read(str(path), always_2d=True, frames=MAX_SAMPLES)
    except sf.LibsndfileError:
        return WavData(b"", 0, 0, 1, "soundfile")
    if data.shape[0] > MAX_SAMPLES:
        data = data[:MAX_SAMPLES]
    ch = data.shape[1]
    pcm, n = _to_mono_int16(data.reshape(-1) if ch == 1 else data, ch)
    return WavData(pcm, int(sr), n, int(ch), "soundfile")


# ---- (a) ggwave ------------------------------------------------------------------------------

def decode_ggwave(path):
    """Decode a data-over-sound WAV with the ggwave codec.

    Returns {available, payload, candidates, recipe, samplerate, note}. When ggwave is importable
    it initialises the codec at the file's samplerate and does a one-shot decode of the whole int16
    buffer (ggwave resamples internally); `payload` is the decoded string or None. When ggwave is
    NOT importable, `available` is False and `recipe` holds the exact offline recipe to run instead.
    """
    out = {"available": False, "payload": None, "candidates": [], "recipe": GGWAVE_CLI_RECIPE,
           "samplerate": None, "note": None}
    try:
        import ggwave
    except Exception:
        out["note"] = "ggwave not importable; see recipe"
        return out
    out["available"] = True
    try:
        ggwave.disableLog()
    except Exception:
        pass
    wd = load_wav(path)
    out["samplerate"] = wd.samplerate
    if not wd.pcm or wd.samplerate <= 0:
        out["note"] = "no readable PCM audio for ggwave"
        return out
    params = ggwave.getDefaultParameters()
    params["sampleRateInp"] = float(wd.samplerate)
    # wd.pcm is little-endian int16 PCM, so decode it as ggwave I16 (4); a few captures carry a raw
    # F32 bit pattern packed into the PCM, so fall back to the default F32 (5) if I16 finds nothing.
    res = None
    for sample_format in (4, 5):
        params["sampleFormatInp"] = sample_format
        inst = ggwave.init(params)
        try:
            res = ggwave.decode(inst, wd.pcm)
        except Exception:
            res = None
        finally:
            ggwave.free(inst)
        if res:
            break
    if res:
        payload = res.decode("utf-8", "replace") if isinstance(res, (bytes, bytearray)) else str(res)
        out["payload"] = payload
        out["candidates"].append(("ggwave", payload))
    else:
        out["note"] = "ggwave found no payload (wrong file, partial capture, or non-ggwave audio)"
    return out


# ---- (b) DTMF (real recording) ----------------------------------------------------------------

def decode_dtmf(path):
    """DTMF keys of a real WAV recording, via carve_stego's Goertzel decoder.

    Returns {keys, sure, candidates, note}. `keys` is the key string ('' = none, None = not readable
    PCM). `sure` is carve_stego.dtmf_read's confidence (False when the capture was truncated or the
    keys shift with the 20 ms window phase). The symbolic side (a tone-pair list / key presses you
    read off a table) is keypad.py, not this."""
    out = {"keys": None, "sure": False, "candidates": [], "note": None}
    try:
        import carve_stego as cs
    except Exception as e:  # pragma: no cover - carve_stego ships with the repo
        out["note"] = f"carve_stego unavailable: {e}"
        return out
    data = Path(path).read_bytes()
    try:
        keys, sure = cs.dtmf_read(data)
    except Exception as e:
        out["note"] = f"dtmf decode error: {e}"
        return out
    out["keys"], out["sure"] = keys, bool(sure)
    if keys:
        out["candidates"].append(("dtmf", keys))
        if not sure:
            out["note"] = "low confidence: re-check (truncated capture or tones near one window long)"
    elif keys == "":
        out["note"] = "no DTMF detected (not a keypad recording, or tones off the 8 standard freqs)"
    else:
        out["note"] = "not a readable PCM WAV for DTMF"
    return out


# ---- (c) CyberSonics tone ladder --------------------------------------------------------------

def decode_tones(path, **kwargs):
    """Decode a CyberSonics tone-ladder WAV via audio_tones.decode (FFT peak per tone block).

    kwargs are forwarded to audio_tones.decode (block_ms, mode, base, step, offset, xor, silence_frac).
    Returns the audio_tones result dict, or {'note': ...} if audio_tones / soundfile is unavailable."""
    try:
        import audio_tones as at
    except Exception as e:
        return {"note": f"audio_tones unavailable ({e}); run it directly once soundfile is present"}
    return at.decode(Path(path), **kwargs)


# ---- flags + top-level analysis ---------------------------------------------------------------

def find_flags(obj):
    """Every CSCTF{...}/CTF{...} hit in a string or any nested strings of a dict/list, de-duped."""
    hits = []

    def walk(x):
        if isinstance(x, str):
            hits.extend(FLAG_RE.findall(x))
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                walk(v)

    walk(obj)
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def analyze(path):
    """Try the decodable archetypes (ggwave, DTMF, CyberSonics tones) and point at the modem/Morse
    recipe. Returns {file, archetypes: {ggwave, dtmf, tones}, flags, recipe_pointer}. Offline; never
    submits -- read the candidates and the highlighted flags, then submit once through the guard."""
    path = Path(path)
    archetypes = {}
    try:
        archetypes["ggwave"] = decode_ggwave(path)
    except Exception as e:
        archetypes["ggwave"] = {"note": f"ggwave path error: {e}"}
    try:
        archetypes["dtmf"] = decode_dtmf(path)
    except Exception as e:
        archetypes["dtmf"] = {"note": f"dtmf path error: {e}"}
    try:
        archetypes["tones"] = decode_tones(path)
    except Exception as e:
        archetypes["tones"] = {"note": f"tones path error: {e}"}
    return {"file": str(path), "archetypes": archetypes, "flags": find_flags(archetypes),
            "recipe_pointer": "run `sound_data.py recipes` for AFSK/Bell202/FSK/Morse (multimon-ng/minimodem)"}


# ---- CLI --------------------------------------------------------------------------------------

def _report_analyze(result):
    lines = [f"file: {result['file']}"]
    gg = result["archetypes"].get("ggwave", {})
    lines.append(f"[ggwave]  available={gg.get('available')}  payload={gg.get('payload')!r}"
                 + (f"  ({gg['note']})" if gg.get("note") else ""))
    dt = result["archetypes"].get("dtmf", {})
    lines.append(f"[dtmf]    keys={dt.get('keys')!r}  sure={dt.get('sure')}"
                 + (f"  ({dt['note']})" if dt.get("note") else ""))
    tn = result["archetypes"].get("tones", {})
    if tn.get("note"):
        lines.append(f"[tones]   {tn['note']}")
    else:
        cands = tn.get("candidates", [])
        best = cands[0][1] if cands else None
        lines.append(f"[tones]   blocks={tn.get('n_blocks')}  best={best!r}")
    lines.append(f"[modem]   {result['recipe_pointer']}")
    flags = result.get("flags", [])
    for f in flags:
        lines.append(f"  >>> FLAG: {f}")
    if not flags:
        lines.append("  (no flag in the event's format; read the candidate payloads above, and try `recipes` for a soft-modem)")
    return "\n".join(lines)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    ap = argparse.ArgumentParser(description="Data-over-sound decoder hub (offline).")
    ap.add_argument("mode", nargs="?", default=None,
                    help="ggwave | dtmf | tones | recipes | <wavfile> (bare file = auto)")
    ap.add_argument("rest", nargs=argparse.REMAINDER,
                    help="wavfile [and extra args forwarded to the tones decoder]")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)

    sub = {"ggwave", "dtmf", "tones", "recipes", "auto"}
    if args.mode in sub:
        mode = args.mode
        rest = args.rest
    elif args.mode is None:
        print(recipes())
        return 0
    else:                                   # bare path -> auto
        mode = "auto"
        rest = [args.mode] + args.rest

    # argparse.REMAINDER swallows a trailing "--json" into `rest`; honour it (the tones
    # subcommand keeps its own --json, since it forwards `rest` to audio_tones' CLI).
    want_json = args.json or ("--json" in rest)
    if mode != "tones" and "--json" in rest:
        rest = [a for a in rest if a != "--json"]
    args.json = want_json

    if mode == "recipes":
        print(recipes())
        return 0

    if not rest:
        print("sound_data.py: a wav file is required", file=sys.stderr)
        return 2
    p = Path(rest[0])
    if not p.is_file():
        print(f"sound_data.py: {rest[0]} is not a file", file=sys.stderr)
        return 2

    if mode == "ggwave":
        result = decode_ggwave(p)
        if args.json:
            print(json.dumps(result, ensure_ascii=False))
        else:
            if result["available"]:
                print(f"ggwave payload: {result['payload']!r}  (sr={result['samplerate']}Hz)")
                if result.get("note"):
                    print(result["note"])
            else:
                print(result["recipe"])
            for f in find_flags(result):
                print(f"  >>> FLAG: {f}")
        return 0

    if mode == "dtmf":
        result = decode_dtmf(p)
        if args.json:
            print(json.dumps(result, ensure_ascii=False))
        else:
            print(f"dtmf keys: {result['keys']!r}  sure={result['sure']}")
            if result.get("note"):
                print(result["note"])
            for f in find_flags(result):
                print(f"  >>> FLAG: {f}")
        return 0

    if mode == "tones":
        # forward remaining args straight to audio_tones' own CLI for full control
        try:
            import audio_tones as at
        except Exception as e:
            print(f"audio_tones unavailable: {e}", file=sys.stderr)
            return 2
        return at.main(rest + (["--json"] if args.json else []))

    # auto
    result = analyze(p)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, default=str))
    else:
        print(_report_analyze(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
