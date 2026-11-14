#!/usr/bin/env python3
"""Day 29 sample (variant diffing): one program delivered as two optimization builds.

The delivery carries two d29-- ELFs of the same program at two optimization levels,
`d29--sample-O0.elf` (the unoptimized build) and `d29--sample-O3.elf` (the optimized
build), each with the lane's HCFG config container. The questions name the build with
the words `optimized` / `unoptimized`, NOT the file's `O3` / `O0` tag, so generic.py's
side-by-side build reader (row 307, which derives the build word from the file names)
cannot map them and leaves every build-specific id None. This module reads each
build-specific id from the member the question's own words name ("the unique d29--
member whose basename ends O3.elf"), and reads the prefix-level common config only when
every d29-- member's CRC-valid HCFG record is byte-for-byte equal (the question's rule).

The ids, by how they are read:

  d29_analysis_optimized_format        the O3 member classified by magic (generic.py's
  d29_analysis_optimized_machine       rule and judged keys: elf plain, e_machine as an
  d29_analysis_unoptimized_format      integer under binary.machine/integer; a PE build
  d29_analysis_unoptimized_machine     of a Mastery variant reads the same way)
  d29_analysis_optimized_config_<name> the O3 member's backward-scan CRC-valid HCFG record
  d29_analysis_config_<name>           the common value, only when both builds' CRC-valid
                                       HCFG payloads are byte-for-byte equal, else None

What is left OUT of the result (artifact_sha256_1/2) is build-independent and answered by
generic.py through the dispatcher. Every answer is read from the bytes: a container or CPU
whose name was never judged stays unsure (generic.py builds that), and a fact that cannot
be read is None, never a default. Nothing in a fixture is executed.

Rules kept (docs/ops/contracts.md, "Uncertain answers"):
  - config members are plain strings read from a CRC-valid HCFG record (hcfg.find's layout).
  - format and machine go through generic.known_answers, so they are plain exactly as long
    as the judge's name for that container/CPU holds, and unsure otherwise.
  - the prefix-level common config is plain only when the builds agree byte-for-byte; a
    divergence (a decoy build, a tampered record) is None, never one build's value (row 507).
  - the member a build id names is read from the question text ("basename ends <x>"), else from
    the lane's build-word seed (build_conventions.json, B-040: optimized/unoptimized -> the member
    suffixes that name that build), and only then the built-in optimized->O3 / unoptimized->O0
    fallback. A later variant that renames the role tag (fast/slow for O3/O0) is followed from the
    seed with no new code, and the seed is tried before the built-in default so a missing or
    malformed seed still reads the original Day 29 delivery (loud, never a silent fall-through).
"""
import json
import sys
import pathlib

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent / "common"))
import labels  # noqa: F401  (the dispatcher puts solvers/common on the path only after this import)

import importlib.util
import re

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import hcfg

PREFIX = "d29"
# The build word in d29_analysis_<build>_<field> -> the member basename suffix it names, tried in order:
# the question text (SUFFIX_RE), then the build-word seed (CONV_PATH, B-040), then this built-in default
# last. The default is kept in code so a missing or malformed seed still reads the original delivery.
_DEFAULT_BUILD_SUFFIX = {"optimized": ["o3.elf"], "unoptimized": ["o0.elf"]}
# The B-040 seed the generic reader consults instead of a day-specific table: {build word: [suffix, ...]}.
CONV_PATH = pathlib.Path(__file__).resolve().parent / "build_conventions.json"
_CONV_CACHE = {}
BUILD_RE = re.compile(r"analysis_(optimized|unoptimized)_(.+)")
# A prefix-level config field with no build word (the common value across the role builds).
COMMON_CONFIG_RE = re.compile(r"analysis_(?:config_[a-z0-9_]+|xor_key_hex)")
SUFFIX_RE = re.compile(r"basename ends ([A-Za-z0-9._-]+\.[A-Za-z0-9]+)", re.I)


def _note(text):
    text = "".join(c if c.isprintable() else "?" for c in str(text))[:400]
    print(f"[d29] {text}", file=sys.stderr)


def _generic():
    """solvers/binary/generic.py, loaded under a unique name so another lane's generic.py never
    shadows it (the ladder runs from the script-analysis folder, which has one too)."""
    name = "binary_generic"
    mod = sys.modules.get(name)
    if mod is not None and callable(getattr(mod, "known_answers", None)):
        return mod
    g = sys.modules.get("generic")
    if g is not None and callable(getattr(g, "known_answers", None)):
        try:
            if pathlib.Path(getattr(g, "__file__", "") or "").resolve() == (HERE / "generic.py"):
                return g
        except (OSError, TypeError, ValueError):
            pass
    try:
        spec = importlib.util.spec_from_file_location(name, HERE / "generic.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    except (Exception, SystemExit) as e:
        _note(f"generic.py could not be loaded ({type(e).__name__}: {e}); format/machine stay unanswered")
        return None


def _members(files):
    """[(name, bytes)] of the delivery's top-level d29-- members (never an archive-nested name)."""
    out = []
    for n, b in files.items():
        if not isinstance(n, str) or " -> " in n or not isinstance(b, (bytes, bytearray)):
            continue
        if n.rsplit("/", 1)[-1].lower().startswith(PREFIX + "--"):
            out.append((n, bytes(b)))
    return out


def _select(members, suffix):
    """The one d29-- member whose basename ends `suffix`, or None (no match, or more than one)."""
    if not suffix:
        return None
    suffix = suffix.lower()
    hits = [(n, b) for n, b in members if n.rsplit("/", 1)[-1].lower().endswith(suffix)]
    return hits[0] if len(hits) == 1 else None


def _backward_record(data):
    """The CRC-32-valid HCFG container with the largest offset: scanning backward from the end of the
    member, the first magic hit that is CRC-valid, as the questions state. None when none is CRC-valid."""
    try:
        good = [c for c in hcfg.containers(data) if c.get("crc_ok")]
    except Exception as e:
        _note(f"reading the HCFG records raised {type(e).__name__}: {e}")
        return None
    return max(good, key=lambda c: c["offset"]) if good else None


def _config_value(cfg, field):
    """The plain string value of analysis_config_<name>, analysis_config_crc32_hex or
    analysis_xor_key_hex from one CRC-valid record, or None. Only a non-empty string member has a
    judged plain form; anything else (absent, null, a number) is left None, not guessed."""
    if cfg is None:
        return None
    if field == "analysis_xor_key_hex":
        return f"0x{cfg['key']:02x}"
    if not field.startswith("analysis_config_"):
        return None
    name = field[len("analysis_config_"):]
    if name == "crc32_hex":
        return f"0x{cfg['crc32']:08x}"
    obj = cfg.get("json") if isinstance(cfg.get("json"), dict) else {}
    value = obj.get(name)
    return value if isinstance(value, str) and value else None


def _build_conventions():
    """{build word: [member suffix, ...]} from the B-040 seed, cached on the file's stat. A missing file
    is empty (the built-in default still applies); a malformed one is reported once and read as empty, so
    the reader never silently follows a broken seed."""
    path = CONV_PATH
    try:
        st = path.stat()
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    hit = _CONV_CACHE.get(path)
    if hit is not None and hit[0] == sig:
        return hit[1]
    data = {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("not a JSON object")
        for build, suffixes in raw.items():
            if isinstance(build, str) and isinstance(suffixes, list):
                data[build.strip().lower()] = [s.strip().lower() for s in suffixes
                                               if isinstance(s, str) and s.strip()]
    except (OSError, ValueError) as e:
        _note(f"{path.name}: {e}; using the built-in O3/O0 fallback")
        data = {}
    _CONV_CACHE[path] = (sig, data)
    return data


def _suffix_candidates(q, build):
    """The member suffixes a build id may name, best first: the question text, then the seed's suffixes
    for the build, then the built-in default, each added once."""
    out = []
    m = SUFFIX_RE.search(q.get("question") or "") if isinstance(q, dict) else None
    if m:
        out.append(m.group(1).lower())
    for suffix in _build_conventions().get(build, ()):
        if suffix and suffix not in out:
            out.append(suffix)
    for suffix in _DEFAULT_BUILD_SUFFIX.get(build, ()):
        if suffix not in out:
            out.append(suffix)
    return out


def _select_build(members, q, build):
    """The one d29-- member a build id names: the first suffix candidate that selects exactly one."""
    for suffix in _suffix_candidates(q, build):
        member = _select(members, suffix)
        if member is not None:
            return member
    return None


def _header_answer(gen, member, base_field, q, ctx):
    """generic.known_answers for one header field (format, machine) on the one member a build id names:
    plain under a judged container/CPU name, unsure otherwise, read by magic over the whole file."""
    if gen is None:
        return None
    fmt = q.get("answer_format") if isinstance(q, dict) and isinstance(q.get("answer_format"), dict) else None
    try:
        got = gen.known_answers(PREFIX, [base_field], {member[0]: member[1]}, ctx,
                                {base_field: fmt} if fmt else None)
    except (Exception, SystemExit) as e:
        _note(f"{base_field}: generic.known_answers raised {type(e).__name__}: {e}; left unanswered")
        return None
    return got.get(base_field) if isinstance(got, dict) else None


def _common_record(members):
    """The common CRC-valid HCFG record when every d29-- member has one and all their payloads are
    byte-for-byte equal (the question's rule), else None: a divergence is no established common value."""
    if len(members) < 2:
        return None
    recs = [_backward_record(b) for _, b in members]
    if any(r is None or not r.get("crc_ok") for r in recs):
        return None
    if len({bytes(r["plain"]) for r in recs}) != 1:
        _note("the role builds' HCFG payloads are not byte-for-byte equal: no common config value")
        return None
    return recs[0]


def answers(questions, files, ctx):
    """{qid: answer} for the d29 ids this module reads. artifact_sha256_* are left OUT for generic.py."""
    out = {}
    if not isinstance(files, dict):
        return out
    members = _members(files)
    if not members:
        return out
    gen = _generic()
    common = _common_record(members)
    for q in questions or []:
        qid = q.get("qid") if isinstance(q, dict) else None
        if not isinstance(qid, str) or "_" not in qid:
            continue
        field = qid.split("_", 1)[1]
        bm = BUILD_RE.fullmatch(field)
        if bm:
            build, rest = bm.group(1), bm.group(2)
            member = _select_build(members, q, build)
            if member is None:
                _note(f"{qid}: no single d29-- member for build {build!r}; left to generic.py")
                continue
            base_field = "analysis_" + rest
            if base_field.startswith("analysis_config_") or base_field == "analysis_xor_key_hex":
                out[qid] = _config_value(_backward_record(member[1]), base_field)
            else:
                value = _header_answer(gen, member, base_field, q, ctx)
                if value is not None:
                    out[qid] = value
        elif COMMON_CONFIG_RE.fullmatch(field):
            # Plain only when the builds agree byte-for-byte; a divergence is a decision (None), never
            # one build's value (never-guess, row 507). Set the id either way so generic cannot pick one.
            out[qid] = _config_value(common, field) if common is not None else None
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        blob = pathlib.Path(path).read_bytes()
        rec = _backward_record(blob)
        print(path)
        if rec is None:
            print("  no CRC-valid HCFG record")
        else:
            print(f"  HCFG at {rec['offset']:#x} key=0x{rec['key']:02x} crc32=0x{rec['crc32']:08x}")
            for k, v in (rec.get("json") or {}).items():
                print(f"    {k} = {v}")
