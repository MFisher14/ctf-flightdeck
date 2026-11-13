#!/usr/bin/env python3
"""A synthesizer for Batch specimens: a test fixture, not a solver.

Usage:
  python3 solvers/script-analysis/bat_synth.py <specimen.cmd|.bat> [...]   print each file's features
                                                                           and whether it is regenerated

Every Batch specimen seen on Days 3 and 4 (108 distinct files) is the output of
one template with twelve features, and synth() regenerates each of them byte
for byte from features(text) and parts(text). The features and their values:

  naming       fragment and accumulator names: fragment/recovered_configuration, h/cfg, v_a/cfg,
               FrAg/ReCoVeReD, item/item9                                          (PROFILES)
  join         how the accumulator is assembled: pct %a%, bang !a!, call (call set "V=%%a%%"),
               for (for %%G in (0 1 2 3) do call set "V=%%V%%%%a%%G%%")             (JOINS)
  wrapper      what stands around the join, always exactly one: none, goto, call, forl_call,
               ifdef, errorlevel                                                   (WRAPPERS)
  set_kw       set or SeT            }  together the four SET styles                (SET_STYLES)
  quote        quoted, quoted&rem, caret
  separator    the command separator shown in a skipped line: pipe, amp, dpipe, damp (SEPARATORS)
  neutral      one inert statement, or none                                        (NEUTRALS)
  spacing      single or double (a blank line between blocks)  }
  fixture_rem  an extra `rem analyst reconstruction fixture`   }  four line styles   (LINE_STYLES)
  unused_label an extra `:HUNTRESS_UNUSED` block               }
  codec        representation|transform of the HUNTRESS-MATERIAL comment (6 x 6)   (REPRESENTATIONS,
                                                                                    TRANSFORMS)
  ext_tag      the HUNTRESS-EXTENSION comment: cmd or bat                          (EXT_TAGS)

sample() draws seeded random specimens around made-up plans, and product() walks
every combination of the features that shape the code (46,080), so a change to
bat_cmd.py or batch.py can be checked against the whole grammar and not only
the files on disk. Tests build out-of-grammar cases by passing their own
control_lines to synth() or by editing its output.
"""
import base64
import itertools
import random
import re
import sys

PROFILES = {"fragment": "recovered_configuration", "h": "cfg", "v_a": "cfg", "FrAg": "ReCoVeReD", "item": "item9"}
JOINS = ("pct", "bang", "call", "for")
WRAPPERS = ("none", "goto", "call", "forl_call", "ifdef", "errorlevel")
SET_STYLES = (("set", "quoted"), ("SeT", "quoted"), ("set", "quoted&rem"), ("set", "caret"))
SEPARATORS = {
    "pipe": "echo HUNTRESS_SEPARATOR | findstr HUNTRESS >nul",
    "amp": "ver >nul & rem HUNTRESS separator ampersand",
    "dpipe": "(ver >nul) || (rem HUNTRESS separator double pipe)",
    "damp": "ver >nul && rem HUNTRESS separator double ampersand",
}
NEUTRALS = ("string_join", "dead_label", "arithmetic", "opaque_branch", "environment_probe", "none")
LINE_STYLES = (("single", False, False), ("double", False, False), ("single", True, False), ("single", False, True))
REPRESENTATIONS = ("base64_literal", "hex_pairs", "decimal_bytes", "reversed_text", "split_fragments", "plain_fragments")
TRANSFORMS = ("identity", "reverse", "xor_5a", "add_7", "rotate_left", "reverse_xor")
EXT_TAGS = ("cmd", "bat")

# The plans the generator writes, by specimen file stem: steps, adapters, stage count, the next
# stage's language, and the indicator fields in order ({id} is ten hex digits, {n} eight).
PLANS = {
    "host-context": ("decode_configuration,return_configuration", ("set", "call", "for"), "1", ("none",),
                     (("host_id", "host-{id}"),)),
    "memory-stage": ("acquire_remote,dispatch_memory", ("bitsadmin.exe", "certutil.exe", "curl.exe"), "1", ("none",),
                     (("url", "https://{id}.example.invalid/{n}.dat"),)),
    "embedded-write": ("decode_embedded,write_file", ("certutil.exe", "expand.exe", "extrac32.exe"), "1", ("none",),
                       (("file_path", "C:\\Users\\Public\\HuntressLab\\stage-{id}.dat"),)),
    "remote-write": ("acquire_remote,write_file", ("bitsadmin.exe", "certreq.exe", "curl.exe"), "1", ("none",),
                     (("url", "https://{id}.example.invalid/{n}.dat"),
                      ("file_path", "C:\\Users\\Public\\HuntressLab\\stage-{id}.dat"))),
    "outbound-transfer": ("locate_local,prepare_transfer,upload_remote", ("bitsadmin.exe", "curl.exe", "makecab.exe"),
                          "1", ("none",),
                          (("source_path", "C:\\Users\\Public\\HuntressLab\\collect-{id}.cab"),
                           ("upload_url", "https://{id}.example.invalid/upload"))),
    "local-dispatch": ("locate_local,dispatch_process", ("call", "cmd.exe", "start"), "1", ("none",),
                       (("file_path", "C:\\Users\\Public\\HuntressLab\\stage-{id}.dat"),)),
    "impact-plan": ("enumerate_targets,transform_content,write_recovery_note", ("cipher.exe", "compact.exe", "for"),
                    "1", ("none",),
                    (("file_path", "C:\\Users\\Public\\HuntressLab\\stage-{id}.dat"), ("extension", ".{id}.locked"),
                     ("note_name", "RECOVER-{id}.txt"))),
    "staged-handoff": ("acquire_remote,write_file,dispatch_process,handoff_script",
                       ("cmd.exe", "cscript.exe", "mshta.exe", "powershell.exe", "regsvr32.exe", "rundll32.exe"), "4",
                       ("batch", "jscript", "powershell"),
                       (("url", "https://{id}.example.invalid/{n}.dat"),
                        ("file_path", "C:\\Users\\Public\\HuntressLab\\stage-{id}.dat"), ("next_stage", "stage-{id}.js"))),
}
PLANS["relay-handoff"] = PLANS["staged-handoff"]
GRAPHS = ("single", "linear", "diamond", "fan_out", "fallback_retry", "same_language", "cross_language")


# ---- pieces ---------------------------------------------------------------------------------------

def split_plan(plan: str, n: int = 4) -> list:
    """The generator's fragments: n pieces, all but the last of the same (rounded-up) length."""
    k = -(-len(plan) // n)
    return [plan[i * k:(i + 1) * k] for i in range(n)]


def encode_material(plan: str, rep: str, transform: str) -> str:
    """The HUNTRESS-MATERIAL text for a plan: the transform over its bytes, then the representation."""
    b = plan.encode("utf-8")        # every plan on record is ASCII, where the two are the same bytes
    b = {"identity": lambda: b,
         "reverse": lambda: b[::-1],
         "xor_5a": lambda: bytes(x ^ 0x5A for x in b),
         "add_7": lambda: bytes((x + 7) & 0xFF for x in b),
         "rotate_left": lambda: bytes(((x << 1) & 0xFF) | (x >> 7) for x in b),
         "reverse_xor": lambda: bytes(x ^ 0x33 for x in b[::-1])}[transform]()
    if rep == "hex_pairs":
        return b.hex()
    if rep == "decimal_bytes":
        return ".".join(str(x) for x in b)
    text = base64.b64encode(b).decode("ascii")
    if rep == "reversed_text":
        return text[::-1]
    if rep in ("base64_literal", "split_fragments", "plain_fragments"):
        return text
    raise ValueError(f"unknown representation {rep!r}")


def frag_line(kw: str, quote: str, name: str, value: str) -> str:
    if quote == "quoted":
        return f'{kw} "{name}={value}"'
    if quote == "quoted&rem":
        return f'{kw} "{name}={value}"& rem HUNTRESS quote compound'
    if quote == "caret":
        return f"{kw} {name}=" + value.replace("|", "^|")
    raise ValueError(f"unknown quote style {quote!r}")


def recovery(join: str, frag: str, accum: str, n: int = 4) -> list:
    """The join: the lines that assemble the accumulator from the n fragments."""
    if join == "pct":
        return [f'set "{accum}=' + "".join(f"%{frag}{i}%" for i in range(n)) + '"']
    if join == "bang":
        return [f'set "{accum}=' + "".join(f"!{frag}{i}!" for i in range(n)) + '"']
    if join == "call":
        return [f'call set "{accum}=' + "".join(f"%%{frag}{i}%%" for i in range(n)) + '"']
    if join == "for":
        return [f'set "{accum}="',
                f'for %%G in ({" ".join(str(i) for i in range(n))}) do call set "{accum}=%%{accum}%%%%{frag}%%G%%"']
    raise ValueError(f"unknown join {join!r}")


def control(wrapper: str, rec: list) -> list:
    """The join's lines inside one wrapper."""
    if wrapper == "none":
        return list(rec)
    if wrapper == "goto":
        return ["goto :HUNTRESS_DISPATCH", ":HUNTRESS_DISPATCH"] + rec
    if wrapper == "call":
        return ["call :HUNTRESS_RECOVER", "goto :HUNTRESS_EMIT", ":HUNTRESS_RECOVER"] + rec + ["exit /b 0", ":HUNTRESS_EMIT"]
    if wrapper == "forl_call":
        return (["for /l %%Q in (1,1,1) do call :HUNTRESS_RECOVER", "goto :HUNTRESS_EMIT", ":HUNTRESS_RECOVER"] + rec
                + ["exit /b 0", ":HUNTRESS_EMIT"])
    if wrapper == "ifdef":
        return ['set "HUNTRESS_READY=1"', "if defined HUNTRESS_READY " + rec[0]] + rec[1:]
    if wrapper == "errorlevel":
        return ["ver >nul", "if errorlevel 1 exit /b 1"] + rec
    raise ValueError(f"unknown wrapper {wrapper!r}")


def synth(f: dict, frags: list, material: str, neutral_hex: str, plan_echo: str, control_lines: list = None) -> str:
    """The specimen for a feature dict. frags: the fragment values in order. material: the
    HUNTRESS-MATERIAL text. neutral_hex: the neutral statement's value. plan_echo: what the --plan
    path prints. control_lines replaces the wrapper and join (for out-of-grammar cases)."""
    accum = f.get("accum") or PROFILES[f["frag"]]
    blocks = ["@echo off", "setlocal EnableExtensions EnableDelayedExpansion",
              f"rem HUNTRESS-CODEC:{f['rep']}|{f['transform']}", f"rem HUNTRESS-MATERIAL:{material}"]
    if f.get("fixture_rem"):
        blocks.append("rem analyst reconstruction fixture")
    blocks += [f"rem HUNTRESS-EXTENSION:{f['ext_tag']}", 'if /i "%~1"=="--inspect" goto :HUNTRESS_INSPECT',
               'if /i "%~1"=="--plan" goto :HUNTRESS_PLAN', "exit /b 0", ":HUNTRESS_INSPECT"]
    # Lines of one block are separated by a bare LF and blocks by CRLF, as in the generator's output.
    blocks.append("\n".join(frag_line(f["set_kw"], f["quote"], f"{f['frag']}{i}", v) for i, v in enumerate(frags)))
    blocks.append("\n".join(["goto :HUNTRESS_SEPARATOR_DONE", SEPARATORS[f["separator"]], ":HUNTRESS_SEPARATOR_DONE"]))
    blocks.append("rem no neutral statements" if f["neutral"] == "none" else f'set "neutral_{f["neutral"]}={neutral_hex}"')
    lines = control_lines if control_lines is not None else control(f["wrapper"], recovery(f["join"], f["frag"], accum, len(frags)))
    blocks.append("\n".join(lines))
    blocks += [f"echo(!{accum}!", "exit /b 0"]
    if f.get("unused_label"):
        blocks += [":HUNTRESS_UNUSED", "goto :HUNTRESS_PLAN"]
    blocks += [":HUNTRESS_PLAN", "echo " + plan_echo, "exit /b 0"]
    j = "\r\n\r\n" if f["spacing"] == "double" else "\r\n"
    return j.join(blocks) + j


def specimen(f: dict, plan: str, neutral_hex: str = "0badc0de", plan_echo: str = "plan summary", control_lines: list = None) -> str:
    """synth() for a plan: its fragments and its material are derived from the plan and the codec."""
    return synth(f, split_plan(plan), encode_material(plan, f["rep"], f["transform"]), neutral_hex, plan_echo, control_lines)


# ---- reading a real specimen back -----------------------------------------------------------------

def features(text: str) -> dict:
    """The twelve features of a specimen that follows the template (KeyError or AttributeError if not)."""
    f = {}
    lines = re.split(r"\r\n|\n|\r", text)
    f["spacing"] = "double" if sum(1 for line in lines if not line.strip()) > 5 else "single"
    m = re.search(r"HUNTRESS-CODEC:([\w.-]+)\|([\w.-]+)", text)
    f["rep"], f["transform"] = m.group(1), m.group(2)
    f["ext_tag"] = re.search(r"HUNTRESS-EXTENSION:(\w+)", text).group(1)
    f["fixture_rem"] = "rem analyst reconstruction fixture" in text
    f["unused_label"] = ":HUNTRESS_UNUSED" in text
    fm = re.search(r'(?m)^(set|SeT|SET|Set)\s+("?)([A-Za-z_]\w*?)0=(.*)$', text)
    f["set_kw"], f["frag"] = fm.group(1), fm.group(3)
    if "& rem HUNTRESS quote compound" in fm.group(0):
        f["quote"] = "quoted&rem"
    else:
        f["quote"] = "quoted" if fm.group(2) == '"' else "caret"
    at = next(i for i, line in enumerate(lines) if line.strip() == "goto :HUNTRESS_SEPARATOR_DONE")
    f["separator"] = {v: k for k, v in SEPARATORS.items()}[lines[at + 1].strip()]
    m = re.search(r'set "neutral_(\w+)=', text)
    f["neutral"] = m.group(1) if m else "none"
    start = next(i for i, line in enumerate(lines) if line.strip() == ":HUNTRESS_SEPARATOR_DONE")
    end = next(i for i, line in enumerate(lines) if line.strip().startswith("echo(!"))
    body = [line.strip() for line in lines[start + 1:end] if line.strip() and not line.strip().startswith('set "neutral_')
            and line.strip() != "rem no neutral statements"]
    f["accum"] = re.match(r"echo\(!(\w+)!", lines[end].strip()).group(1)
    joined = "\n".join(body)
    if re.search(r"for %%G in \(0 1 2 3\) do call set", joined):
        f["join"] = "for"
    elif re.search(r'call set "\w+=%%', joined):
        f["join"] = "call"
    elif re.search(r'set "\w+=!\w+0!', joined):
        f["join"] = "bang"
    else:
        f["join"] = "pct"
    if any(line == "ver >nul" for line in body) and any(line.startswith("if errorlevel") for line in body):
        f["wrapper"] = "errorlevel"
    elif any(line.startswith("if defined HUNTRESS_READY") for line in body):
        f["wrapper"] = "ifdef"
    elif any(line.startswith("for /l") for line in body):
        f["wrapper"] = "forl_call"
    elif any(line == "call :HUNTRESS_RECOVER" for line in body):
        f["wrapper"] = "call"
    elif any(line == "goto :HUNTRESS_DISPATCH" for line in body):
        f["wrapper"] = "goto"
    else:
        f["wrapper"] = "none"
    return f


def parts(text: str, f: dict) -> tuple:
    """What synth() takes besides the features: (fragment values, material, neutral hex, plan echo)."""
    frags = []
    for i in range(4):
        m = re.search(r'(?m)^(?:set|SeT)\s+"?%s%d=(.*?)("?(?:& rem HUNTRESS quote compound)?)\r?$' % (re.escape(f["frag"]), i), text)
        frags.append(m.group(1).replace("^|", "|") if f["quote"] == "caret" else m.group(1))
    material = re.search(r"HUNTRESS-MATERIAL:(.*?)\r?$", text, re.M).group(1)
    m = re.search(r'set "neutral_\w+=(\w+)"', text)
    return frags, material, m.group(1) if m else "", re.findall(r"(?m)^echo (.*?)\r?$", text)[-1]


def rebuild(text: str) -> str:
    """The specimen regenerated from its own features: equal to text for every file of the template."""
    f = features(text)
    return synth(f, *parts(text, f))


# ---- made-up specimens ----------------------------------------------------------------------------

def make_plan(rng: random.Random, stem: str = None) -> str:
    """A plan in the generator's vocabulary with made-up identifiers."""
    steps, adapters, stages, languages, fields = PLANS[stem or rng.choice(sorted(PLANS))]
    ident, n = "%010x" % rng.getrandbits(40), "%08x" % rng.getrandbits(32)
    head = [("v", "1"), ("steps", steps), ("adapter", rng.choice(adapters)), ("stage_count", stages),
            ("graph", rng.choice(GRAPHS)), ("next_language", rng.choice(languages)), ("campaign_id", f"campaign-{ident}")]
    return "|".join(f"{k}={v}" for k, v in head + [(k, v.format(id=ident, n=n)) for k, v in fields])


def product():
    """Every combination of the features that shape the code (5 x 4 x 6 x 4 x 4 x 6 x 4 = 46,080),
    as feature dicts without a codec or extension tag."""
    for frag, join, wrapper, (kw, quote), sep, neutral, (spacing, fixture, unused) in itertools.product(
            PROFILES, JOINS, WRAPPERS, SET_STYLES, SEPARATORS, NEUTRALS, LINE_STYLES):
        yield {"frag": frag, "join": join, "wrapper": wrapper, "set_kw": kw, "quote": quote, "separator": sep,
               "neutral": neutral, "spacing": spacing, "fixture_rem": fixture, "unused_label": unused}


def sample(n: int, seed: int = 0):
    """n seeded random specimens: yields (features, plan, text). Same seed, same specimens."""
    rng = random.Random(seed)
    for _ in range(n):
        kw, quote = rng.choice(SET_STYLES)
        spacing, fixture, unused = rng.choice(LINE_STYLES)
        f = {"frag": rng.choice(sorted(PROFILES)), "join": rng.choice(JOINS), "wrapper": rng.choice(WRAPPERS),
             "set_kw": kw, "quote": quote, "separator": rng.choice(sorted(SEPARATORS)), "neutral": rng.choice(NEUTRALS),
             "spacing": spacing, "fixture_rem": fixture, "unused_label": unused,
             "rep": rng.choice(REPRESENTATIONS), "transform": rng.choice(TRANSFORMS), "ext_tag": rng.choice(EXT_TAGS)}
        plan = make_plan(rng)
        yield f, plan, specimen(f, plan, neutral_hex="%08x" % rng.getrandbits(32), plan_echo=f"{f['frag']} summary")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        try:
            with open(path, "rb") as fh:
                text = fh.read().decode("utf-8", "replace")
        except OSError as e:
            sys.exit(f"bat_synth.py: cannot read {path}: {e.strerror or e}")
        try:
            f = features(text)
            same = rebuild(text) == text
        except (AttributeError, KeyError, StopIteration, IndexError):
            print(f"{path}\n  not a specimen of the template")
            continue
        print(f"{path}\n  " + " ".join(f"{k}={v}" for k, v in f.items()) + f"\n  regenerated byte for byte: {same}")
