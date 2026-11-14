#!/usr/bin/env python3
"""B-247: offline Script-lane variants, the Game-Master-free transform set of the Huntress `tests/variants.py`
(backlog rows 32, 114, 236, 463, 501, 526, 542), on synthetic specimens.

  .venv/bin/python -I tests/script_variants.py [--ext .yml] [--how d_retag] [--json PATH]

The Huntress harness replayed every saved attempt (challenge files, a judge's key) through the armed solver; the
master holds neither (docs/migration/ARCHIVED.md: Huntress-bound, Game Master fixtures). What is kept is the part
that needs no judge: the rewrites an author makes to a specimen that carries the plan as a tagged comment and a
descriptor copy, and the rule that a rewording may cost an answer (None) but never give a wrong one.

What is made. specimen(ext, plan) writes the plan the way the extension's carrier does (CARRIERS: Day 8's
`HUNTRESS_ANALYSIS_V1:<TAG>-<payload>` comment and a `descriptor_<id>` literal; the Day 21 GitHub Actions job with
the `HUNTRESS_DESCRIPTOR` env key and a `run: ':'` step; the Day 27 Dockerfile ARG/LABEL; an HCL locals block).
variant(ext, how) rewrites it:

  none            the specimen as written (the baseline: every field plain)
  d_retag         both copies under the next tag (B64 > HEX > HB64 > FRAG > B64)
  d_frag_dash     both copies as FRAG, the hex pieces joined by `-`
  d_frag_colon    both copies as FRAG, the hex pieces joined by `:`
  d_comment       the literal copy emptied (the comment alone carries the plan)
  d_literal       the comment line removed (the literal alone carries it)
  d_reorder       the plan's fields in another order (`steps=` second, the indicators before the profiles)
  d_cut           the comment's payload cut in half, the literal whole: a plain answer must be the plan's
  d_cut_both      both copies cut alike inside the url's value: the url is never answered
  d_differs       the literal holds ANOTHER plan (campaign, url and file path changed): every field None
  d_wrapped       the comment's payload wrapped over three comment lines, the literal removed: the plan is
                  read without its last field (one copy), never a wrong value
  d_wrapped_both  the wrapped comment and the literal: every field plain
  d_windows_path  the plan's file_path a Windows path with backslashes (row 501): every field plain, the path
                  exactly as written
  d_lyr_windows_path
                  the same plan under Day 23's layered tag (`LYR-hex_b64-<payload>`, both copies), which the folded
                  day23_fold reader rewrites to a PLAIN plan (row 501: it rejected a backslash before): every field
                  plain

The extensions (SCRIPT_EXTS) are the Huntress list, widened by row 463 to the Day 21 and Day 22 newcomers
(.yml .groovy .gs .csx .rb .pl .ahk .proj .nsi) and by B-247 to HCL (.tf). Every one is descriptor-only here: no
material transform (the Huntress Lang classes rewrote a real specimen's own longest literal, which a synthetic
specimen does not have).

KNOWN lists the variants whose miss is the lane's deliberate rule, each with its reason: they are graded `safe`
(any field may be None, none wrong), and run() marks them `known`. A reader change that answers one of them is
seen in the table (`known` with no field open) and the entry is then taken out.

How it is graded (grade): the specimen is read by the lane's generic.read. A field the plan holds that is
answered with another value is WRONG, the serious failure; a field left out is None. Each transform says what it
expects (EXPECT): `plain` (every field), `cut` (every field but the last, and that one never wrong), `none` (no
field at all), `safe` (any subset, none wrong), `no_url` (the url never answered).

The Script lane is Huntress's: its unsure picks (one_copy) read the judged label seed of the event profile. main()
runs as `--event` (default huntress) with a temporary CTF_WORKDIR, so no operator ledger is read; a caller of run()
sets the environment itself (the test does).

Exit 1 when any variant answered wrong or missed its expectation, 0 otherwise, 2 on a usage problem. Nothing is
run, nothing is read from disk, no network.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_LANE = str(REPO / "solvers" / "script-analysis")
if _LANE not in sys.path:
    sys.path.insert(0, _LANE)

PLAN = ("v=3|language={lang}|role=downloader|verdict=malicious|attack=T1105|adapter=http_get|host_profile=cli|"
        "obfuscation_profile=b64|stage_profile=single|next_language=none|stage_count=2|"
        "steps=fetch_url,write_file|campaign_id=CMP-4471|url=https://ex.invalid/a/b.bin|file_path=C:/t/b.bin")
WINDOWS_PATH = "C:\\ProgramData\\h\\b.bin"

SCRIPT_EXTS = (".ps1", ".js", ".vbs", ".py", ".sh", ".php", ".bat", ".cmd", ".mof", ".applescript", ".au3",
               ".mjs", ".lua", ".ts", ".escript", ".exs", ".dockerfile",
               # row 463: the Day 21 base's newcomers, and Day 22's first .nsi
               ".yml", ".groovy", ".gs", ".csx", ".rb", ".pl", ".ahk", ".proj", ".nsi",
               # B-247: the HCL carrier of row 462
               ".tf")
DESCRIPTOR_ONLY = SCRIPT_EXTS
TRANSFORMS = ("none", "d_retag", "d_frag_dash", "d_frag_colon", "d_comment", "d_literal", "d_reorder", "d_cut",
              "d_cut_both", "d_differs", "d_wrapped", "d_wrapped_both", "d_windows_path", "d_lyr_windows_path")
EXPECT = {"none": "plain", "d_retag": "plain", "d_frag_dash": "plain", "d_frag_colon": "plain",
          "d_comment": "plain", "d_literal": "plain", "d_reorder": "plain", "d_cut": "safe",
          "d_cut_both": "no_url", "d_differs": "none", "d_wrapped": "cut", "d_wrapped_both": "plain",
          "d_windows_path": "plain", "d_lyr_windows_path": "plain"}
# (ext, transform): why the lane leaves a field open there on purpose (graded `safe`; see the docstring).
KNOWN = {
    (".sh", "d_comment"): "the emptied literal `descriptor_<id>=\"\"` right under the comment reads as more of its "
                          "payload (descriptor.wrapped_old, the reading of before Day 27): the comment is one copy and "
                          "its last field unsure, a cost and never a wrong value",
    (".escript", "d_literal"): "an Erlang `build_plan() -> \"<payload>\".` alone is read by plan_codec as a piece "
                               "(its `.`): one copy, the last field open",
    (".proj", "d_lyr_windows_path"): "an XML attribute copy (`descriptor_<id>=\"..\" />`) is one copy even with a "
                                     "forward-slash path (the last field an unsure pick); with a backslash the "
                                     "rewrite is kept only when read back whole, so nothing is answered",
    (".escript", "d_wrapped_both"):"the wrapped comment's second copy is the Erlang function literal, which no "
                                    "reader takes as a whole copy: one copy, the last field open",
}
D_NEXT = {"B64": "HEX", "HEX": "HB64", "HB64": "FRAG", "FRAG": "B64"}

# ext: (comment leader, the descriptor copy with {p} for its payload, the lines around it)
CARRIERS = {
    ".ps1": ("#", '$descriptor_ab12cd34 = "{p}"', "Write-Output 'ok'"),
    ".js": ("//", 'var descriptor_ab12cd34 = "{p}";', "var ok = 1;"),
    ".vbs": ("'", 'descriptor_ab12cd34 = "{p}"', "WScript.Echo \"ok\""),
    ".py": ("#", 'descriptor_ab12cd34 = "{p}"', "print('ok')"),
    ".sh": ("#", 'descriptor_ab12cd34="{p}"', "echo ok"),
    ".php": ("//", '$descriptor_ab12cd34 = "{p}";', "echo 'ok';"),
    ".bat": ("REM", 'set "descriptor_ab12cd34={p}"', "@echo off"),
    ".cmd": ("REM", 'set "descriptor_ab12cd34={p}"', "@echo off"),
    ".mof": ("//", 'instance of Huntress_Plan\n{{\n    descriptor_ab12cd34 = "{p}";\n}};', "#pragma namespace(\"\\\\\\\\.\\\\root\\\\cimv2\")"),
    ".applescript": ("--", 'property descriptor_ab12cd34 : "{p}"', "display dialog \"ok\""),
    ".au3": (";", 'Local $descriptor_ab12cd34 = "{p}"', "ConsoleWrite(\"ok\")"),
    ".mjs": ("//", 'export const descriptor_ab12cd34 = "{p}";', "export const ok = 1;"),
    ".lua": ("--", 'local descriptor_ab12cd34 = "{p}"', "print(\"ok\")"),
    ".ts": ("//", 'const descriptor_ab12cd34: string = "{p}";', "const ok: number = 1;"),
    ".escript": ("%", 'build_plan() -> "{p}".', "main(_) -> ok."),
    ".exs": ("#", 'descriptor_ab12cd34 = "{p}"', "IO.puts(\"ok\")"),
    ".dockerfile": ("#", 'ARG HUNTRESS_DESCRIPTOR="{p}"\nLABEL huntress.analysis.descriptor=$HUNTRESS_DESCRIPTOR',
                    "FROM alpine:3.19"),
    ".yml": ("#", "jobs:\n  analyze:\n    runs-on: ubuntu-latest\n    env:\n      HUNTRESS_DESCRIPTOR: \"{p}\"\n"
                  "    steps:\n      - run: ':'", "name: analyze\non: push"),
    ".groovy": ("//", 'def descriptor_ab12cd34 = "{p}"', "println 'ok'"),
    ".gs": ("//", 'var descriptor_ab12cd34 = "{p}";', "function main() {}"),
    ".csx": ("//", 'var descriptor_ab12cd34 = "{p}";', "Console.WriteLine(\"ok\");"),
    ".rb": ("#", 'descriptor_ab12cd34 = "{p}"', "puts 'ok'"),
    ".pl": ("#", 'my $descriptor_ab12cd34 = "{p}";', "print \"ok\\n\";"),
    ".ahk": (";", 'descriptor_ab12cd34 := "{p}"', "MsgBox, ok"),
    ".proj": (None, '<Project>\n  <HuntressPlan descriptor_ab12cd34="{p}" />\n</Project>',
              '<?xml version="1.0" encoding="utf-8"?>'),
    ".nsi": (";", '!define descriptor_ab12cd34 "{p}"', "OutFile \"ok.exe\""),
    ".tf": ("#", 'locals {{\n  HUNTRESS_DESCRIPTOR = "{p}"\n}}', 'terraform {{}}'),
}


class NotApplicable(Exception):
    """The transform does not fit this specimen."""


def plan_for(ext: str, file_path: str | None = None) -> str:
    plan = PLAN.format(lang=ext.lstrip(".") or "text")
    if file_path is not None:
        plan = plan.replace("file_path=C:/t/b.bin", "file_path=" + file_path)
    return plan


def encode(tag: str, plan: str, sep: str = ".") -> str:
    raw = plan.encode("ascii")
    if tag == "B64":
        return base64.b64encode(raw).decode()
    if tag == "HEX":
        return raw.hex()
    if tag == "HB64":
        return base64.b64encode(raw).hex()
    if tag == "FRAG":
        return sep.join(re.findall(".{1,24}", raw.hex()))
    if tag == "LYR":                          # Day 23: hex first, base64 over it, named in that order
        return "hex_b64-" + base64.b64encode(raw.hex().encode()).decode()
    raise ValueError(tag)


def other_plan(plan: str) -> str:
    """The plan with its campaign, url and file path changed (d_differs' second plan)."""
    out = []
    for f in plan.split("|"):
        k, eq, v = f.partition("=")
        if k == "campaign_id":
            v += "ALT"
        elif k == "url":
            v = v.replace("://", "://alt-", 1)
        elif k == "file_path":
            v += ".alt"
        out.append(f"{k}={v}" if eq else f)
    return "|".join(out)


def _comment(ext: str, body: str) -> str:
    lead = CARRIERS[ext][0]
    return f"<!-- {body} -->" if lead is None else f"{lead} {body}"


def specimen(ext: str, plan: str, tag: str = "B64", comment_payload=None, literal_payload=None,
             comment=True, literal=True, wrap=0, sep: str = ".") -> str:
    """The plan written in `ext`'s carrier (see CARRIERS)."""
    lead, copy, around = CARRIERS[ext]
    payload = encode(tag, plan, sep)
    cp = payload if comment_payload is None else comment_payload
    # an LYR tag names its layers before its payload; the literal copy holds the payload alone
    lp = (payload.split("-", 1)[1] if tag == "LYR" else payload) if literal_payload is None else literal_payload
    lines = [around.replace("{{", "{").replace("}}", "}")]
    if comment:
        body = f"HUNTRESS_ANALYSIS_V1:{tag}-{cp}"
        if wrap:
            first = f"HUNTRESS_ANALYSIS_V1:{tag}-"
            k = len(cp) // wrap + 1
            pieces = [cp[i:i + k] for i in range(0, len(cp), k)]
            if lead is None:
                lines.append("<!-- " + first + pieces[0])
                lines.extend("     " + p for p in pieces[1:-1])
                lines.append("     " + pieces[-1] + " -->")
            else:
                lines.append(f"{lead} {first}{pieces[0]}")
                lines.extend(f"{lead} {p}" for p in pieces[1:])
        else:
            lines.append(_comment(ext, body))
    lines.append(copy.format(p=lp if literal else ""))
    return "\n".join(lines) + "\n"


def variant(ext: str, how: str):
    """(file name, text, the plan a reader should give, expectation) for one extension and transform."""
    if ext not in CARRIERS:
        raise NotApplicable(f"no carrier for {ext}")
    if how not in EXPECT:
        raise NotApplicable(how)
    plan = plan_for(ext)
    name = f"specimen{ext}"
    if how == "none":
        return name, specimen(ext, plan), plan, EXPECT[how]
    if how == "d_retag":
        return name, specimen(ext, plan, tag=D_NEXT["B64"]), plan, EXPECT[how]
    if how in ("d_frag_dash", "d_frag_colon"):
        return name, specimen(ext, plan, tag="FRAG", sep="-" if how == "d_frag_dash" else ":"), plan, EXPECT[how]
    if how == "d_comment":
        return name, specimen(ext, plan, literal=False), plan, EXPECT[how]
    if how == "d_literal":
        return name, specimen(ext, plan, comment=False), plan, EXPECT[how]
    if how == "d_reorder":
        fields = plan.split("|")
        key = lambda f: f.split("=", 1)[0]          # noqa: E731
        head = [f for f in fields if key(f) == "v"]
        steps = [f for f in fields if key(f) == "steps"]
        iocs = [f for f in fields if key(f) in ("campaign_id", "url", "file_path")]
        rest = [f for f in fields if f not in head + steps + iocs]
        new = "|".join(head + steps + iocs + rest)
        return name, specimen(ext, new), new, EXPECT[how]
    if how == "d_cut":
        payload = encode("B64", plan)
        return name, specimen(ext, plan, comment_payload=payload[:len(payload) // 2]), plan, EXPECT[how]
    if how == "d_cut_both":
        at = plan.index("|url=") + len("|url=https://") + 4
        cut = encode("B64", plan[:at]).rstrip("=")
        return name, specimen(ext, plan, comment_payload=cut, literal_payload=cut), plan, EXPECT[how]
    if how == "d_differs":
        return name, specimen(ext, plan, literal_payload=encode("B64", other_plan(plan))), plan, EXPECT[how]
    if how == "d_wrapped":
        return name, specimen(ext, plan, literal=False, wrap=3), plan, EXPECT[how]
    if how == "d_wrapped_both":
        return name, specimen(ext, plan, wrap=3), plan, EXPECT[how]
    if how == "d_windows_path":
        wp = plan_for(ext, WINDOWS_PATH)
        lp = encode("B64", wp)
        return name, specimen(ext, wp, literal_payload=lp), wp, EXPECT[how]
    if how == "d_lyr_windows_path":
        wp = plan_for(ext, WINDOWS_PATH)
        return name, specimen(ext, wp, tag="LYR"), wp, EXPECT[how]
    raise NotApplicable(how)


# The asked fields: the answer id's last word, the plan key it is read from, and the question's text. The
# file path is the plan's last field as written (d_reorder moves it): the one a one-copy reading leaves unsure.
ASKED = (("campaign", "campaign_id", "Recover the exact synthetic campaign identifier."),
         ("adapter", "adapter", "Recover the exact adapter named by the reconstructed plan."),
         ("url", "url", "Recover the exact url indicator."),
         ("file-path", "file_path", "Recover the exact file_path indicator."))


def questions(member: str, stem: str) -> list:
    return [{"id": f"{stem}-{f}", "qid": f"{stem}-{f}", "answer_id": f"{stem}-{f}", "member": member,
             "artifact": f"evidence.zip -> {member}", "question": t} for f, _k, t in ASKED]


def solve(name: str, text: str, stem: str) -> dict:
    """The lane's answers (analyze.solve_set, the armed entry point) to the ASKED questions of one specimen."""
    import analyze
    with contextlib.redirect_stderr(io.StringIO()):
        return analyze.solve_set(questions(name, stem), {name: text.encode("utf-8")}, {}) or {}


def plain(v) -> bool:
    """A plain answer: a value sent as it stands (None is no answer; `??..` is an unsure pick)."""
    return isinstance(v, str) and v != "" and not v.startswith("??")


def grade(answers: dict, stem: str, truth: str, expect: str) -> dict:
    """{'wrong': [(field, got, want)], 'unplain': [field], 'ok': bool} of one specimen's answers against its plan."""
    import plan_codec
    want = plan_codec.flatten(truth)
    got = {f: answers.get(f"{stem}-{f}") for f, _k, _t in ASKED}
    wrong = [(f, got[f], want.get(k)) for f, k, _t in ASKED if plain(got[f]) and got[f] != want.get(k)]
    unplain = [f for f, _k, _t in ASKED if not plain(got[f])]
    if expect == "plain":
        ok = not unplain
    elif expect == "cut":
        ok = unplain == ["file-path"]
    elif expect == "none":
        ok = len(unplain) == len(ASKED)
    elif expect == "no_url":
        ok = "url" in unplain
    else:                                     # safe
        ok = True
    return {"wrong": wrong, "unplain": unplain, "ok": ok and not wrong}


def run(exts=SCRIPT_EXTS, hows=TRANSFORMS) -> list:
    rows = []
    for ext in exts:
        for how in hows:
            try:
                name, text, truth, expect = variant(ext, how)
            except NotApplicable as e:
                rows.append({"ext": ext, "how": how, "na": str(e)})
                continue
            known = KNOWN.get((ext, how))
            stem = f"{ext.lstrip('.')}-variant-{how.replace('_', '-')}"
            g = grade(solve(name, text, stem), stem, truth, "safe" if known else expect)
            rows.append({"ext": ext, "how": how, "expect": "safe" if known else expect, "known": bool(known), **g})
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ext", action="append", help="an extension of SCRIPT_EXTS (repeatable)")
    ap.add_argument("--how", action="append", help="a transform of TRANSFORMS (repeatable)")
    ap.add_argument("--json", help="write the full table here")
    ap.add_argument("--event", default="huntress", help="the event profile whose label seed the picks read")
    args = ap.parse_args(argv)
    import os
    import tempfile
    os.environ["CTF_EVENT"] = args.event
    os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="script_variants_")
    exts = tuple(args.ext or SCRIPT_EXTS)
    hows = tuple(args.how or TRANSFORMS)
    bad = [e for e in exts if e not in CARRIERS] + [h for h in hows if h not in EXPECT]
    if bad:
        print(f"unknown: {', '.join(bad)}", file=sys.stderr)
        return 2
    rows = run(exts, hows)
    wrong = sum(len(r.get("wrong", ())) for r in rows)
    failed = [r for r in rows if "ok" in r and not r["ok"]]
    for r in failed:
        print(f"FAIL {r['ext']} {r['how']} expect={r['expect']} wrong={r['wrong']} unplain={r['unplain']}")
    print(f"VARIANTS lane=script variants={sum('ok' in r for r in rows)} wrong={wrong} failed={len(failed)} "
          f"known={sum(bool(r.get('known')) for r in rows)} na={sum('na' in r for r in rows)}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1))
    return 1 if failed or wrong else 0


if __name__ == "__main__":
    sys.exit(main())
