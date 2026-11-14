#!/usr/bin/env python3
"""Day 18 live fix: Google Apps Script (.gs) specimens store their version-3 descriptor split over a JS array.

Shape (base of Day 18):

    // HUNTRESS_ANALYSIS_V1:SPLIT
    const HUNTRESS_ANALYSIS_V1_SPLIT_<id> = [ "<TAG>-<pay", "load>", ... ].join("");
    function buildAnalysisPlan_<id>() {
      const encoded_<id> = [ "<pay", "load>", ... ].join("");     # the same payload, no tag
      return Object.freeze({ descriptor: encoded_<id> });
    }

Each joined array is one string. The tagged one is the comment's copy (`TAG-payload`), the other the
descriptor literal's (bare payload). The pieces are joined here and handed to the shipped descriptor reader
in the form it reads whole (the tagged comment and a `descriptor_<id>` literal), and every question is then
answered by generic.answer() exactly as for any other descriptor specimen: two copies that agree prove the
plan, one copy alone is read as one copy, and copies that differ answer nothing.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

ARRAY = re.compile(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[([^\]]*)\]\s*\.join\(\s*(["\'])\3\s*\)', re.S)
ITEM = re.compile(r'"([^"\\]*)"|\'([^\'\\]*)\'')


def _generic():
    for key in ("generic", "script_analysis_generic"):
        mod = sys.modules.get(key)
        try:
            if mod is not None and Path(getattr(mod, "__file__", "") or "").resolve() == HERE / "generic.py":
                return mod
        except OSError:
            pass
    return None


def _arrays(text):
    out = []
    for m in ARRAY.finditer(text):
        body = m.group(2)
        items = ITEM.findall(body)
        # every non-blank token of the body must be a quoted string or a comma
        rest = ITEM.sub("", body)
        if rest.replace(",", "").strip():
            return None
        out.append((m.group(1), "".join(a or b for a, b in items)))
    return out


def synth(text):
    """The text the descriptor reader reads whole, or None when the shape is not exactly this one."""
    if "HUNTRESS_ANALYSIS_V1:SPLIT" not in text:
        return None
    arrays = _arrays(text)
    if not arrays:
        return None
    tagged = [v for n, v in arrays if n.upper().startswith("HUNTRESS_ANALYSIS")]
    others = [v for n, v in arrays if not n.upper().startswith("HUNTRESS_ANALYSIS")]
    if len(tagged) != 1 or len(others) > 1:
        return None
    tag_payload = tagged[0]
    m = re.match(r"^([A-Z0-9]+)-(.+)$", tag_payload, re.S)
    if not m:
        return None
    lines = [f"// HUNTRESS_ANALYSIS_V1:{tag_payload}"]
    if others:
        if others[0] != m.group(2):
            return None                      # two copies that differ: nothing is proven
        lines.append(f'const descriptor_split = "{others[0]}";')
    return "\n".join(lines) + "\n"


def shapes(text, questions):
    gen = _generic()
    if gen is None:
        return {}
    s = synth(text or "")
    if s is None:
        return {}
    info = gen.read("specimen.gs", s.encode())
    if not info.get("plan"):
        return {}
    info["role_q"] = next((q for q in questions if gen.asks_role(q)), None)
    out = {}
    for q in questions:
        try:
            v = gen.answer(q, info)
        except Exception as e:  # noqa: BLE001
            print(f"[shapes_gs] {q.get('qid')} raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if v is not None and v != "":
            out[q["qid"]] = v
    print(f"[shapes_gs] plan read from the joined SPLIT arrays: {info.get('plan_text')}", file=sys.stderr)
    return out
