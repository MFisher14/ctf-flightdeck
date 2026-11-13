#!/usr/bin/env python3
"""Day 28 review: deterministic descriptor coverage must not hide behind ``None``.

Pins two independently byte-derived cases found when next_components became a
coverage gate:

* complete encoded literals in exact Batch/functional host declarations prove
  their final plan field, with or without the tagged comment;
* two identical descriptor copies cut inside a field prove every complete
  key=value pair before that field, but not the cut field or anything later.

Conflicting, extended and block-commented literals remain fail-closed.  No
network or Game Master state is used.
"""

import base64
import contextlib
import io
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SA = REPO / "solvers" / "script-analysis"
sys.dont_write_bytecode = True
os.environ["CTF_TESTING"] = "1"
sys.path[:0] = [str(SA), str(REPO / "solvers" / "common")]

import analyze  # noqa: E402
import lang_escript  # noqa: E402


PLAN = ("v=3|language=terraform_hcl|role=benign_utility|verdict=benign|attack=none|adapter=local_parser|"
        "host_profile=standalone|obfuscation_profile=plain_hex|stage_profile=single_descriptor|"
        "next_language=powershell|stage_count=2|steps=decode_configuration,return_configuration|"
        "campaign_id=TERRAFORM_HCL-f919da2b|url=https://terraform-f919da2b.example.invalid/stage|"
        "file_path=/tmp/huntress-terraform/.f919da2b.stage")
FIELDS = dict(part.split("=", 1) for part in PLAN.split("|"))
HEX = PLAN.encode().hex()
B64 = base64.b64encode(PLAN.encode()).decode()
EXACT = {"kind": "exact_text", "syntax": "exact artifact-derived value only"}


def questions(member):
    rows = []
    for suffix in ("role", "attack", "adapter", "host-profile", "obfuscation", "stage-profile",
                   "next-language", "stage-count", "steps", "campaign", "url", "file-path"):
        qid = "future-benign-" + suffix
        fmt = ({"kind": "enum", "accepted_values": ["benign_utility", "launcher"]} if suffix == "role"
               else {"kind": "pattern", "syntax": "MITRE ATT&CK technique ID, or none for the benign graph"}
               if suffix == "attack"
               else {"kind": "integer", "syntax": "base-10 integer"} if suffix == "stage-count"
               else {"kind": "ordered_tokens", "syntax":
                     "exact tokens joined by > with no surrounding spaces or explanatory text"} if suffix == "steps"
               else EXACT)
        wording = ("Map the decoded ordered behavior graph using this precedence: decode_configuration followed "
                   "by return_configuration is benign/none." if suffix == "attack"
                   else "Recover the artifact-derived value.")
        rows.append({"id": qid, "qid": qid, "answer_id": qid, "artifact": "evidence.zip -> " + member,
                     "member": member, "question": wording,
                     "answer_format": fmt, "normalization": "trim"})
    return rows


def solve(member, text):
    with contextlib.redirect_stderr(io.StringIO()):
        return analyze.solve_set(questions(member), {member: text.encode()}, {"partial": {}, "set": 0}) or {}


def expected():
    return {
        "future-benign-role": FIELDS["role"],
        "future-benign-attack": FIELDS["attack"],
        "future-benign-adapter": FIELDS["adapter"],
        "future-benign-host-profile": FIELDS["host_profile"],
        "future-benign-obfuscation": FIELDS["obfuscation_profile"],
        "future-benign-stage-profile": FIELDS["stage_profile"],
        "future-benign-next-language": FIELDS["next_language"],
        "future-benign-stage-count": FIELDS["stage_count"],
        "future-benign-steps": FIELDS["steps"].replace(",", ">"),
        "future-benign-campaign": FIELDS["campaign_id"],
        "future-benign-url": FIELDS["url"],
        "future-benign-file-path": FIELDS["file_path"],
    }


HOSTS = {
    "future.btm": ('@echo off\n{comment}set "descriptor_1={payload}"\nexit /b 0\n'),
    "future.escript": ('{comment}-module(plan_1).\n-export([build_plan/0]).\n'
                       'build_plan() -> "{payload}".\n'),
    "future.lfe": ('{comment}(defmodule plan_1\n  (export (build-plan 0)))\n'
                   '(defun build-plan () "{payload}")\n'),
    "future.hs": ('module Main where\n{comment}buildPlan :: String\nbuildPlan = "{payload}"\n'
                  'main :: IO ()\nmain = putStrLn buildPlan\n'),
    "future.cr": ('{comment}def build_plan; "{payload}"; end\nputs build_plan\n'),
    "future.clj": ('(ns plan-1)\n{comment}(defn build-plan [] "{payload}")\n(println (build-plan))\n'),
    "future.fsx": ('{comment}let buildPlan () = "{payload}"\nprintfn "%s" (buildPlan ())\n'),
    "future.gleam": ('import gleam/io\n{comment}pub fn build_plan() -> String {{ "{payload}" }}\n'
                     'pub fn main() {{ io.println(build_plan()) }}\n'),
}
COMMENT = {
    ".btm": ":: HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
    ".escript": "% HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
    ".lfe": ";; HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
    ".hs": "-- HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
    ".cr": "# HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
    ".clj": ";; HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
    ".fsx": "// HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
    ".gleam": "// HUNTRESS_ANALYSIS_V1:B64-{payload}\n",
}


def whole_hosts():
    want = expected()
    checked = 0
    for member, frame in HOSTS.items():
        ext = Path(member).suffix
        # A matching tagged comment plus the grammar-bounded literal.
        comment = COMMENT[ext].format(payload=B64)
        text = frame.format(comment=comment, payload=B64)
        got = solve(member, text)
        assert got == want, (member, "two copies", {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v})
        # The declaration grammar alone proves where the literal ends.  Batch's
        # exact host is the HEX form used by both descriptor_ and Material_.
        literal = frame.format(comment="", payload=HEX).replace("descriptor_1", "Material_1")
        got = solve(member, literal)
        assert got == want, (member, "literal", {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v})
        checked += 2
    return f"{checked} complete host forms reproduce all {len(want)} fields"


def cut_prefix():
    at = PLAN.index("|url=") + len("|url=https://") + 4
    cut = PLAN[:at].encode().hex()
    member = "future.php"
    text = (f"<?php\n// HUNTRESS_ANALYSIS_V1:HEX-{cut}\n"
            f"$descriptor_1 = '{cut}';\n")
    got = solve(member, text)
    want = expected()
    for qid in ("future-benign-role", "future-benign-attack", "future-benign-adapter",
                "future-benign-host-profile", "future-benign-obfuscation", "future-benign-stage-profile",
                "future-benign-next-language", "future-benign-stage-count", "future-benign-steps",
                "future-benign-campaign"):
        assert got.get(qid) == want[qid], (qid, got.get(qid), want[qid])
    assert got.get("future-benign-url") is None, got.get("future-benign-url")
    assert got.get("future-benign-file-path") is None, got.get("future-benign-file-path")
    return "10 complete prefix fields plain; cut url and later file_path open"


def clojure_awk_forms():
    want = expected()
    wrapped = "\n".join(B64[i:i + 48] for i in range(0, len(B64), 48))
    clj = ('(ns huntress.fixture)\n'
           f'(def Material_1 (clojure.string/replace "{wrapped}" "\\n" ""))\n'
           '(println (count Material_1))\n')
    assert solve("future.clj", clj) == want

    cut = len(B64) // 2
    awk = ('#!/usr/bin/awk -f\nBEGIN {\n'
           f'part0 = "{B64[:cut]}"\npart1 = "{B64[cut:]}"\n'
           'Material_1 = part0 part1\n    print length(Material_1)\n}\n')
    assert solve("future.awk", awk) == want
    return "Clojure newline removal and AWK adjacent variables reproduce all fields"


def refusals():
    member = "future.hs"
    other = PLAN.replace("TERRAFORM_HCL-f919da2b", "TERRAFORM_HCL-conflict")
    other64 = base64.b64encode(other.encode()).decode()
    conflict = HOSTS[member].format(comment=COMMENT[".hs"].format(payload=B64), payload=other64)
    got = solve(member, conflict)
    assert not any(v is not None and not str(v).startswith("??") for v in got.values()), got

    extended = HOSTS[member].format(comment="", payload=HEX).replace('"\nmain ::', '" ++ suffix\nmain ::')
    got = solve(member, extended)
    assert got.get("future-benign-file-path") is None, got.get("future-benign-file-path")

    commented = HOSTS[member].format(comment="", payload=HEX).replace(
        f'buildPlan = "{HEX}"', f'{{-\nbuildPlan = "{HEX}"\n-}}')
    got = solve(member, commented)
    assert got.get("future-benign-file-path") is None, got.get("future-benign-file-path")
    return "conflict, extension and block-comment decoys remain non-plain"


def erlang_static_forms():
    member = "future.escript"
    want = expected()
    ints = ", ".join(str(ord(ch)) for ch in B64)
    escaped = "".join(f"\\x{{{ord(ch):02x}}}" for ch in B64[:6]) + B64[6:]
    cut1, cut2 = len(B64) // 3, len(B64) * 2 // 3
    pieces = (B64[:cut1], B64[cut1:cut2], B64[cut2:])
    forms = {
        "integer charlist": f"[{ints}]",
        "escaped string": f'"{escaped}"',
        "joined strings": " ++ ".join(repr(p).replace("'", '"') for p in pieces),
        "lists append": "lists:append([" + ", ".join(repr(p).replace("'", '"') for p in pieces) + "])",
    }
    for name, expr in forms.items():
        text = ("-module(fixture).\n% inert static-analysis fixture\n"
                'codec_1() -> "base64|identity".\n'
                f"material_1() -> {expr}.\n"
                '% decode and dispatch\nmain(_) -> io:format("~p~n", [length(material_1())]).\n')
        got = solve(member, text)
        assert got == want, (name, {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v})
    helpers = "\n".join(f'part{i}() -> "{piece}".' for i, piece in enumerate(pieces))
    text = ("-module(fixture).\n% inert static-analysis fixture\n"
            'codec_1() -> "base64|identity".\n' + helpers + "\n"
            "material_1() -> part0() ++ part1() ++ part2().\n"
            '% decode and dispatch\nmain(_) -> io:format("~p~n", [length(material_1())]).\n')
    assert solve(member, text) == want

    other = PLAN.replace("benign_utility", "downloader").replace("attack=none", "attack=T1105")
    other64 = base64.b64encode(other.encode()).decode()
    decoy = text.replace("material_1() ->", f'old_1() -> "{other64}".\nmaterial_1() ->')
    # Pin the language reader's authority check directly.  ``analyze`` is
    # deliberately allowed to fall back to the older generic reader when a
    # language reader refuses a file; the cumulative qdiff matrix separately
    # verifies that its exact decoy_plan host remains unanswered end-to-end.
    assert lang_escript._material(decoy) is None
    return f"{len(forms) + 1} static expression families exact; second complete plan refused"


# pytest entry points: each case raises on a wrong reading. The runner below is the direct-run path; it is
# guarded so importing this file under pytest runs nothing at collection time.
def test_whole_hosts():
    whole_hosts()


def test_cut_prefix():
    cut_prefix()


def test_clojure_awk_forms():
    clojure_awk_forms()


def test_erlang_static_forms():
    erlang_static_forms()


def test_refusals():
    refusals()


if __name__ == "__main__":
    FAILED = []
    for name, fn in (("whole functional hosts", whole_hosts), ("identical cut copies", cut_prefix),
                     ("Clojure/AWK hosts", clojure_awk_forms),
                     ("static Erlang expressions", erlang_static_forms), ("adversarial refusals", refusals)):
        try:
            print(f"pass  {name}: {fn()}")
        except Exception as e:  # noqa: BLE001
            FAILED.append(name)
            print(f"FAIL  {name}: {type(e).__name__}: {e}")

    if FAILED:
        print(f"\n{len(FAILED)} FAILED: {FAILED}")
        raise SystemExit(1)
    print("\nall passed")
