"""B-247: the Script lane's residual readers (solvers/script-analysis/residuals.py, js_modern.py), their wiring into
generic.read, the guards around them (generic's changed-list guard, shapes_py/lang_sh after a cut descriptor,
day23_fold's backslash plans) and the offline variants harness (tests/script_variants.py).

Every specimen is synthetic, built in the test: a version-3 plan (all fifteen fields, stage_count equal to the
steps), encoded and written into a carrier. Nothing is executed.
"""
from __future__ import annotations

import base64
import codecs
import contextlib
import gzip
import io
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

import js_modern
import plan_codec
import residuals as rs

# This lane's generic.py, not solvers/binary/generic.py (SH-05).
generic = plan_codec.own("generic")

REPO = Path(__file__).resolve().parent.parent
LANE = REPO / "solvers" / "script-analysis"

PLAN = ("v=3|language=yml|role=downloader|verdict=malicious|attack=T1105|adapter=http_get|host_profile=cli|"
        "obfuscation_profile=b64|stage_profile=single|next_language=none|stage_count=2|"
        "steps=fetch_url,write_file|campaign_id=CMP-4471|url=https://ex.invalid/a/b.bin|file_path=C:/t/b.bin")
OTHER = PLAN.replace("CMP-4471", "CMP-9999")
FP = "C:/t/b.bin"


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


B64, B64_OTHER = b64(PLAN), b64(OTHER)


def read(name: str, text: str) -> dict:
    with contextlib.redirect_stderr(io.StringIO()):
        return generic.read(name, text)


def taken(info: dict) -> bool:
    return bool(info.get("plan")) and not info.get("cut") and not info.get("ambiguous")


def refused(info: dict) -> bool:
    return not info.get("plan") and bool(info.get("ambiguous"))


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


@pytest.fixture(autouse=True)
def _residuals_on(monkeypatch):
    monkeypatch.setattr(generic, "RESIDUALS", True)
    monkeypatch.delenv("CTF_HIDE", raising=False)


# ============================================================================================= the exact key

KEY_FORMS = {
    "yaml quoted (Actions job env)": f'jobs:\n  analyze:\n    env:\n      HUNTRESS_DESCRIPTOR: "{B64}"\n',
    "yaml single quotes": f"env:\n  HUNTRESS_DESCRIPTOR: '{B64}'\n",
    "yaml plain": f"env:\n  HUNTRESS_DESCRIPTOR: {B64}\n",
    "yaml quoted key": f'env:\n  "HUNTRESS_DESCRIPTOR": "{B64}"\n',
    "json": f'{{"env": {{"HUNTRESS_DESCRIPTOR": "{B64}", "X": "1"}}}}\n',
    "dockerfile ENV pairs": f"FROM alpine\nENV A=1 HUNTRESS_DESCRIPTOR={B64} C=2\n",
    "dockerfile ARG quoted": f'FROM alpine\nARG HUNTRESS_DESCRIPTOR="{B64}"\n',
    "dockerfile old ENV K V": f"FROM alpine\nENV HUNTRESS_DESCRIPTOR {B64}\n",
    "hcl": f'locals {{\n  HUNTRESS_DESCRIPTOR = "{B64}"\n}}\n',
    "toml": f'[env]\nHUNTRESS_DESCRIPTOR = "{B64}" # the plan\n',
    "dotenv": f"HUNTRESS_DESCRIPTOR={B64}\n",
    "shell :=": f'HUNTRESS_DESCRIPTOR := "{B64}"\n',
}


@pytest.mark.parametrize("label", sorted(KEY_FORMS))
def test_the_exact_key_is_a_whole_copy_in_every_config_form(label):
    copies = rs.key_copies(KEY_FORMS[label])
    assert len(copies) == 1, copies
    assert copies[0].whole, copies[0]
    assert B64 in copies[0].values


def test_a_block_scalar_and_a_heredoc_are_joined_whole():
    lines = "".join("    " + B64[i:i + 60] + "\n" for i in range(0, len(B64), 60))
    block = rs.key_copies("env:\n  HUNTRESS_DESCRIPTOR: |\n" + lines + "  other: 1\n")
    folded = rs.key_copies("env:\n  HUNTRESS_DESCRIPTOR: >-\n" + lines + "next: 2\n")
    heredoc = rs.key_copies(f'locals {{\n  HUNTRESS_DESCRIPTOR = <<EOT\n{lines}EOT\n}}\n')
    for got in (block, folded, heredoc):
        assert len(got) == 1 and got[0].whole and B64 in got[0].values, got
    assert block[0].form == "block" and heredoc[0].form == "heredoc"
    # the block ends at the first line indented no deeper than its key: `other: 1` is not part of it
    assert all("other" not in v for v in block[0].values)


NOT_A_COPY = {
    "a use with $": f'run: echo "$HUNTRESS_DESCRIPTOR"\nX: "{B64}"\n',
    "a use with ${}": f'LABEL d=${{HUNTRESS_DESCRIPTOR}}\nX="{B64}"\n',
    "a longer name": f'env:\n  HUNTRESS_DESCRIPTOR_OLD: "{B64}"\n',
    "a prefixed name": f'env:\n  X_HUNTRESS_DESCRIPTOR: "{B64}"\n',
    "lower case": f'env:\n  huntress_descriptor: "{B64}"\n',
    "a mention in prose": f"# HUNTRESS_DESCRIPTOR holds the plan\nX: 1\n",
    "a shell comparison": f'if [ $HUNTRESS_DESCRIPTOR = "{B64_OTHER}" ]; then exit 1; fi\n',
    "a shell default": f": ${{HUNTRESS_DESCRIPTOR:={B64_OTHER}}}\n",
}


@pytest.mark.parametrize("label", sorted(NOT_A_COPY))
def test_a_use_or_another_name_is_no_key_copy(label):
    assert rs.key_copies(NOT_A_COPY[label]) == []


def test_a_quoted_value_glued_to_more_is_not_whole():
    got = rs.key_copies(f'env:\n  HUNTRESS_DESCRIPTOR: "{B64[:60]}" + "{B64[60:]}"\n')
    assert len(got) == 1 and not got[0].whole


def test_a_yml_key_beside_its_tagged_comment_is_the_second_copy():
    text = f"# HUNTRESS_ANALYSIS_V1:B64-{B64}\n" + KEY_FORMS["yaml quoted (Actions job env)"]
    info = read("ci.yml", text)
    assert taken(info) and info["plan"]["file_path"] == FP
    assert info["two_copies"] is True
    assert any("HUNTRESS_DESCRIPTOR key agrees" in n for n in info["notes"])


@pytest.mark.parametrize("name,text", [
    ("ci.yml", f'# HUNTRESS_ANALYSIS_V1:B64-{B64}\nenv:\n  HUNTRESS_DESCRIPTOR: "{B64_OTHER}"\n'),
    # the Day 27 shape that was answered from the comment alone: the key among other pairs on an ENV line
    ("Dockerfile", f"FROM alpine\n# HUNTRESS_ANALYSIS_V1:B64-{B64}\nENV A=1 HUNTRESS_DESCRIPTOR={B64_OTHER} C=2\n"),
    ("main.tf", f'# HUNTRESS_ANALYSIS_V1:B64-{B64}\nlocals {{\n  HUNTRESS_DESCRIPTOR = "{B64_OTHER}"\n}}\n'),
])
def test_a_key_that_disagrees_with_the_tagged_comment_refuses_the_file(name, text):
    info = read(name, text)
    assert refused(info), info.get("plan_text")
    assert any("B-247" in n for n in info["notes"])


def test_the_disagreeing_env_pair_was_answered_from_the_comment_without_the_reader(monkeypatch):
    # the control: the same Dockerfile with the residual readers off goes out with the comment's plan
    monkeypatch.setattr(generic, "RESIDUALS", False)
    info = read("Dockerfile", f"FROM alpine\n# HUNTRESS_ANALYSIS_V1:B64-{B64}\nENV A=1 HUNTRESS_DESCRIPTOR={B64_OTHER} C=2\n")
    assert taken(info) and info["plan"]["campaign_id"] == "CMP-4471"


def test_two_key_copies_that_disagree_refuse_the_file():
    # no tagged comment: an ARG and an ENV of the exact key that give two plans
    text = f'FROM alpine\nARG HUNTRESS_DESCRIPTOR="{DEEP}"\nENV HUNTRESS_DESCRIPTOR={deep(OTHER)}\n'
    info = read("Dockerfile", text)
    assert refused(info) and any("2 different plans" in n for n in info["notes"])


def test_a_wrapped_block_scalar_alone_is_read_whole():
    lines = "".join("    " + B64[i:i + 60] + "\n" for i in range(0, len(B64), 60))
    text = "env:\n  HUNTRESS_DESCRIPTOR: |\n" + lines + "other: 1\n"
    info = read("ci.yml", text)
    assert taken(info) and info["source"] == "residuals" and info["plan"]["file_path"] == FP


def test_a_wrapped_block_scalar_is_cut_without_the_reader(monkeypatch):
    monkeypatch.setattr(generic, "RESIDUALS", False)
    lines = "".join("    " + B64[i:i + 60] + "\n" for i in range(0, len(B64), 60))
    info = read("ci.yml", "env:\n  HUNTRESS_DESCRIPTOR: |\n" + lines + "other: 1\n")
    assert "file_path" not in (info.get("plan") or {})


def test_a_rotated_key_value_is_not_read():
    # row 462: the key alone is read only through the decoders, never a rotation guessed
    info = read("ci.yml", f"env:\n  HUNTRESS_DESCRIPTOR: \"{codecs.encode(PLAN, 'rot13')}\"\n")
    assert not info.get("plan")


# ============================================================================================= wrapped comments

def wrapped_lines(lead: str, payload: str, n: int = 3) -> str:
    k = len(payload) // n + 1
    parts = [payload[i:i + k] for i in range(0, len(payload), k)]
    return f"{lead} HUNTRESS_ANALYSIS_V1:B64-{parts[0]}\n" + "".join(f"{lead} {p}\n" for p in parts[1:])


def test_comment_copies_joins_a_wrapped_comment():
    got = rs.comment_copies(wrapped_lines("#", B64) + "echo ok\n")
    joined = [c for c in got if c.lines > 1]
    assert len(joined) == 1 and joined[0].payload == B64 and joined[0].lines == 3


def test_a_wrapped_comment_stops_at_prose_and_at_another_marker():
    prose = rs.comment_copies(f"# HUNTRESS_ANALYSIS_V1:B64-{B64[:60]}\n# built by the ops team\n")
    assert all(c.lines == 1 for c in prose)
    two = rs.comment_copies(f"# HUNTRESS_ANALYSIS_V1:B64-{B64[:60]}\n# HUNTRESS_ANALYSIS_V1:B64-{B64[60:]}\n")
    assert all(c.lines == 1 for c in two)


def test_a_wrapped_comment_in_a_block_comment_is_joined():
    k = len(B64) // 3 + 1
    p = [B64[i:i + k] for i in range(0, len(B64), k)]
    text = f"/*\n * HUNTRESS_ANALYSIS_V1:B64-{p[0]}\n * {p[1]}\n * {p[2]} */\nvar ok = 1;\n"
    joined = [c for c in rs.comment_copies(text) if c.lines > 1]
    assert len(joined) == 1 and joined[0].payload == B64


def test_a_wrapped_comment_alone_is_one_copy_without_its_last_field():
    info = read("a.sh", wrapped_lines("#", B64) + "echo ok\n")
    assert info.get("cut") is True and info["source"] == "residuals"
    assert "file_path" not in info["plan"] and info["plan"]["url"] == "https://ex.invalid/a/b.bin"
    assert info["one_copy"] == ("file_path", FP) and info["one_copy_wrapped"] is True


def test_a_wrapped_comment_alone_gives_nothing_without_the_reader(monkeypatch):
    monkeypatch.setattr(generic, "RESIDUALS", False)
    info = read("a.sh", wrapped_lines("#", B64) + "echo ok\n")
    assert not info.get("plan")


def test_a_wrapped_comment_and_an_agreeing_literal_are_whole():
    info = read("a.sh", wrapped_lines("#", B64) + f'descriptor_ab="{B64}"\n')
    assert taken(info) and info["plan"]["file_path"] == FP


def test_a_wrapped_comment_in_a_comment_block_with_a_literal_is_whole():
    # comment-in-comment: the line-comment leader `* //` inside a block comment, wrapped over three lines
    k = len(B64) // 3 + 1
    p = [B64[i:i + k] for i in range(0, len(B64), k)]
    text = (f"/*\n * // HUNTRESS_ANALYSIS_V1:B64-{p[0]}\n * // {p[1]}\n * // {p[2]}\n */\n"
            f'var descriptor_ab = "{B64}";\n')
    info = read("a.js", text)
    assert taken(info) and info["plan"]["file_path"] == FP


def test_a_wrapped_comment_whose_join_differs_from_the_literal_is_refused():
    info = read("a.sh", wrapped_lines("#", B64) + f'descriptor_ab="{B64_OTHER}"\n')
    assert not info.get("plan") or info["plan"].get("campaign_id") is None


def test_comment_in_comment_older_plan_beside_a_live_pair_is_still_refused():
    # the dead-text rule stands: an older tagged plan in a comment block beside the live pair is a second plan
    text = (f"/*\n// HUNTRESS_ANALYSIS_V1:B64-{B64_OTHER}\n*/\n// HUNTRESS_ANALYSIS_V1:B64-{B64}\n"
            f'var descriptor_ab = "{B64}";\n')
    assert refused(read("a.js", text))


# ============================================================================================= v=4 plans

def test_a_v4_plan_is_complete_and_its_wrapped_comment_reads_with_a_literal():
    v4 = PLAN.replace("v=3", "v=4")
    assert rs.complete(v4) and not rs.complete(PLAN.rsplit("|", 1)[0])
    info = read("a.sh", wrapped_lines("#", b64(v4)) + f'descriptor_ab="{b64(v4)}"\n')
    assert taken(info) and info["plan"]["v"] == "4" and info["plan"]["file_path"] == FP


# ============================================================================================= untagged depth

def deep(plan: str) -> str:
    """base64 over zlib over hex over base64: deeper than descriptor.decode's own free search reads."""
    return base64.b64encode(zlib.compress(b64(plan).encode().hex().encode())).decode()


DEEP = deep(PLAN)


def test_deep_plans_peels_text_and_compression_layers():
    got = rs.deep_plans(DEEP)
    assert [t for t, _ in got] == [PLAN]
    assert "inflate" in got[0][1] and "hex" in got[0][1]


def test_deep_plans_reads_gzip_and_base32():
    value = base64.b32encode(gzip.compress(PLAN.encode())).decode()
    assert [t for t, _ in rs.deep_plans(value)] == [PLAN]


def test_a_deep_literal_is_read_whole():
    info = read("a.py", f'descriptor_ab = "{DEEP}"\n')
    assert taken(info) and info["source"] == "residuals" and info["plan"]["file_path"] == FP


def test_a_deep_literal_gives_nothing_without_the_reader(monkeypatch):
    monkeypatch.setattr(generic, "RESIDUALS", False)
    assert not read("a.py", f'descriptor_ab = "{DEEP}"\n').get("plan")


def test_a_long_xor_key_is_fixed_by_the_plan_crib():
    key = b"k3y-0f-11ch"                       # 11 bytes: longer than the 1-4 byte keys the lane tried
    data = xor(PLAN.encode(), key)
    got = rs.xor_plans(data)
    assert [t for t, _ in got] == [PLAN] and got[0][1] == "xor_crib_" + key.hex()
    info = read("a.py", f'descriptor_ab = "{base64.b64encode(data).decode()}"\n')
    assert taken(info) and info["plan"]["campaign_id"] == "CMP-4471"


@pytest.mark.parametrize("key", [b"Kq7zP", b"Kq7zP2", b"Kq7zP2m", b"Kq7zP2mX", b"Kq7zP2mXa", b"Kq7zP2mXa9"])
def test_a_crib_fixed_xor_key_of_any_length_under_the_crib_is_read(key):
    # 5..10 bytes: shorter than the longest key the 13-byte crib `v=3|language=` fixes, so its period must be found
    data = xor(PLAN.encode(), key)
    got = rs.xor_plans(data)
    assert [t for t, _ in got] == [PLAN] and got[0][1] == "xor_crib_" + key.hex()


def test_a_key_longer_than_the_crib_is_read_only_from_a_literal_of_the_file():
    key = ("q" * 7 + "Zx9" * 11).encode()       # 40 bytes, longer than any crib
    data = base64.b64encode(xor(PLAN.encode(), key)).decode()
    assert rs.xor_plans(xor(PLAN.encode(), key)) == []
    assert taken(read("a.py", f'K = "{key.decode()}"\ndescriptor_ab = "{data}"\n'))
    assert not read("a.py", f'descriptor_ab = "{data}"\n').get("plan")


def test_a_tagged_comment_the_descriptor_refuses_is_read_by_its_deep_layers():
    # the B64 tag's own decode gives zlib bytes, no plan: descriptor.py refuses the comment, the deep peel reads it
    inner = base64.b64encode(zlib.compress(B64.encode().hex().encode())).decode()
    text = f"# HUNTRESS_ANALYSIS_V1:B64-{inner}\necho ok\n"
    info = read("a.sh", text)
    assert info["source"] == "residuals" and info["plan"]["campaign_id"] == "CMP-4471"
    assert str(info.get("descriptor_why") or "").startswith(rs.COMMENT_UNREAD) or info.get("descriptor")


def test_a_refused_comment_is_not_lifted_when_the_blind_reader_reads_another_plan():
    inner = base64.b64encode(zlib.compress(B64.encode().hex().encode())).decode()
    k = len(B64_OTHER) // 3 + 1
    other = " + ".join(f'"{B64_OTHER[i:i + k]}"' for i in range(0, len(B64_OTHER), k))
    text = f"// HUNTRESS_ANALYSIS_V1:B64-{inner}\nconst material_q = {other};\n"
    info = read("a.js", text)
    assert info.get("plan", {}).get("campaign_id") != "CMP-4471"


def test_a_cut_comment_beside_a_whole_key_is_its_piece():
    hexed = PLAN.encode().hex()
    half = hexed[:101]                         # an odd cut: the comment alone decodes to nothing
    text = f"FROM alpine\n# HUNTRESS_ANALYSIS_V1:HEX-{half}\nARG HUNTRESS_DESCRIPTOR=\"{hexed}\"\n"
    r = rs.reading(text, "dockerfile")
    assert any(w.kind == "comment-piece" and w.plan_text == PLAN for w in r.witnesses)
    info = read("Dockerfile", text)
    assert taken(info) and info["plan"]["file_path"] == FP


def _lift(text: str) -> dict:
    info = {"text": text, "ext": ".dockerfile", "plan": {}, "notes": []}
    assert rs.apply(info, rs.reading(text, "dockerfile")) == "lifted"
    return info


def test_a_cut_comment_is_no_second_copy_of_the_key_it_heads():
    # generic.dead_conflict skips its decoy scan when two_copies is set: a key and its own cut comment are one
    # copy, so the flag stays down; two independent whole keys that agree are two copies, so it goes up
    hexed = PLAN.encode().hex()
    deep = base64.b64encode(zlib.compress(hexed.encode())).decode()      # beyond plan_codec: the lift reads it
    key = f'ARG HUNTRESS_DESCRIPTOR="{hexed}"\n'
    piece = f"# HUNTRESS_ANALYSIS_V1:HEX-{hexed[:101]}\n"
    alone = _lift("FROM alpine\n" + key)
    assert alone["two_copies"] is False
    assert any("(key; 1 copy)" in n for n in alone["notes"]), alone["notes"]
    with_piece = _lift("FROM alpine\n" + piece + key)
    assert with_piece["plan"]["file_path"] == FP and with_piece["two_copies"] is False
    note = next(n for n in with_piece["notes"] if "read whole by the residual readers" in n)
    assert "(key; 1 copy, and 1 cut tagged comment that is its head)" in note, note
    two = _lift(f'FROM alpine\n{key}ENV HUNTRESS_DESCRIPTOR="{hexed}"\n')
    assert two["two_copies"] is True
    assert any("(key; 2 copies)" in n for n in two["notes"]), two["notes"]
    # through generic.read: the flag the lane's later checks see
    info = read("Dockerfile", "FROM alpine\n" + piece + key)
    assert taken(info) and info["source"] == "residuals" and info["two_copies"] is False
    info = read("Dockerfile", f'FROM alpine\nARG HUNTRESS_DESCRIPTOR="{deep}"\nENV HUNTRESS_DESCRIPTOR="{deep}"\n')
    assert taken(info) and info["source"] == "residuals" and info["two_copies"] is True


def test_a_cut_comment_heading_two_disagreeing_keys_is_the_piece_of_neither():
    hexed, hexed_other = PLAN.encode().hex(), OTHER.encode().hex()
    assert hexed[:101] == hexed_other[:101]
    text = (f"FROM alpine\n# HUNTRESS_ANALYSIS_V1:HEX-{hexed[:101]}\nARG HUNTRESS_DESCRIPTOR=\"{hexed}\"\n"
            f"ENV HUNTRESS_DESCRIPTOR=\"{hexed_other}\"\n")
    r = rs.reading(text, "dockerfile")
    assert sorted(w.plan_text for w in r.witnesses if w.kind == "key") == sorted([PLAN, OTHER])
    assert [w for w in r.witnesses if w.kind == "comment-piece"] == []


def test_a_key_value_that_gives_two_plans_is_no_whole_copy(monkeypatch):
    # one value two decoders read two ways: neither reading is a whole copy, and it heads no cut comment
    real = rs._plans
    monkeypatch.setattr(rs, "_plans", lambda v, b, keys=(), deep_ok=True:
                        ([(PLAN, "a"), (OTHER, "b")], False) if v == B64 else real(v, b, keys, deep_ok))
    r = rs.reading(f'env:\n  HUNTRESS_DESCRIPTOR: "{B64}"\n', "yml")
    keyed = [w for w in r.witnesses if w.kind == "key"]
    assert sorted(w.plan_text for w in keyed) == sorted([PLAN, OTHER]) and not any(w.whole for w in keyed)


def test_a_refusal_clears_a_one_copy_pick():
    # an earlier reader left a one-copy pick (the last field, unsure); two key copies that disagree refuse the
    # file, and the pick must go with the plan
    text = f'FROM alpine\nARG HUNTRESS_DESCRIPTOR="{DEEP}"\nENV HUNTRESS_DESCRIPTOR={deep(OTHER)}\n'
    info = {"text": text, "ext": "", "notes": [], "plan": {}, "one_copy": ("file_path", FP),
            "one_copy_wrapped": True}
    assert rs.apply(info) == "refused"
    assert "one_copy" not in info and "one_copy_wrapped" not in info and not info["plan"]


def test_noise_is_no_plan():
    noise = base64.b64encode(bytes((i * 37 + 11) % 256 for i in range(160))).decode()
    assert rs.deep_plans(noise) == []
    assert not read("a.py", f'descriptor_ab = "{noise}"\n').get("plan")


def test_more_values_than_the_bound_lift_nothing():
    # the deep literal comes first, so it IS decoded (a whole witness stands); the filler after it runs the value
    # bound over, and an unread value could be a second plan: the read witness must not be lifted
    filler = "".join(f'descriptor_f{i} = "{b64("filler value number %03d padded" % i)}"\n'
                     for i in range(rs.MAX_VALUES + 2))
    text = f'descriptor_ab = "{DEEP}"\n' + filler
    r = rs.reading(text, "py")
    assert r.over and any("more than" in n for n in r.notes)
    assert [(w.kind, w.whole, w.plan_text) for w in r.witnesses] == [("deep-literal", True, PLAN)]
    info = {"text": text, "ext": ".py", "plan": {}, "notes": []}
    assert rs.apply(info, r) is None and not info["plan"]
    # the control: under the bound the deep literal is lifted
    small = {"text": f'descriptor_ab = "{DEEP}"\n', "ext": ".py", "plan": {}, "notes": []}
    assert rs.apply(small) == "lifted"


def test_short_key_values_do_not_spend_the_value_bound():
    # a key value under MIN_VALUE is no copy and is never decoded: many of them leave the bound for real copies
    shorts = "".join(f"HUNTRESS_DESCRIPTOR=s{i:02d}\n" for i in range(rs.MAX_VALUES + 4))
    text = shorts + f'descriptor_ab = "{DEEP}"\n'
    r = rs.reading(text, "py")
    assert not r.over and [w.kind for w in r.witnesses] == ["deep-literal"]
    assert rs.apply({"text": text, "ext": ".py", "plan": {}, "notes": []}, r) == "lifted"


def test_inflate_refuses_bytes_behind_the_stream():
    stream = zlib.compress(PLAN.encode())
    assert rs._inflate(stream) == PLAN.encode()                       # the control
    assert rs._inflate(stream + b"trailing-junk") is None
    # nor does the deep peel read a plan from a deflate stream with more behind it
    assert rs.deep_plans(base64.b64encode(stream).decode()) != []
    assert rs.deep_plans(base64.b64encode(stream + b"trailing-junk").decode()) == []


# ============================================================================================= batch `set`

def test_bat_copies_reads_quoted_and_bare_sets():
    q = rs.bat_copies(f'@echo off\nset "descriptor_ab={B64}"\n')
    bare = rs.bat_copies(f"@echo off\nset descriptor_ab={B64}\n")
    assert len(q) == 1 and q[0].whole and q[0].values == [B64]
    assert len(bare) == 1 and bare[0].whole and bare[0].values == [B64]
    assert rs.bat_copies("set descriptor_ab=short\n") == []          # a value under MIN_VALUE is no copy


@pytest.mark.parametrize("text", [
    f"set descriptor_ab=%PREFIX%{B64}\n",                           # an expansion
    f"set descriptor_ab={B64[:60]} {B64[60:]}\n",                    # a blank inside
    f'set "descriptor_ab={B64[:80]}"\nset "descriptor_ab=%descriptor_ab%{B64[80:]}"\n',   # set twice: a piece
])
def test_a_bat_value_that_is_not_its_text_is_not_whole(text):
    assert all(not c.whole for c in rs.bat_copies(text))


def test_a_bat_set_that_disagrees_with_the_tagged_comment_refuses_the_file():
    text = f'@echo off\nREM HUNTRESS_ANALYSIS_V1:B64-{B64}\nset "descriptor_ab={B64_OTHER}"\n'
    assert refused(read("a.bat", text))


def test_a_bat_set_alone_and_beside_an_agreeing_comment():
    alone = read("a.cmd", f'@echo off\nset "descriptor_ab={B64}"\n')
    assert taken(alone) and alone["source"] == "residuals"
    both = read("a.bat", f'@echo off\nREM HUNTRESS_ANALYSIS_V1:B64-{B64}\nset "descriptor_ab={B64}"\n')
    assert taken(both) and both["two_copies"] is True


def test_a_bat_set_is_read_only_in_a_batch_file():
    # `set "descriptor_x=.."` in a .sh is no batch copy
    assert all(w.kind != "bat" for w in rs.reading(f'set "descriptor_ab={B64_OTHER}"\n', "sh").witnesses)


# ============================================================================================= modern JavaScript

CODES = ",".join(str(c ^ 7) for c in B64.encode())


@pytest.mark.parametrize("src,name", [
    (f'const d = [{CODES}].map(c => String.fromCharCode(c ^ 7)).join("");\n', "d"),
    (f'const head = "{B64[:40]}";\nconst tail = "{B64[40:]}";\nlet d = `${{head}}${{tail}}`;\n', "d"),
    (f"const codes = [{','.join(str(c) for c in B64.encode())}];\nconst d = String.fromCharCode(...codes);\n", "d"),
    (f'const d = [{CODES}].reduce((acc, c) => acc + String.fromCharCode(c ^ 7), "");\n', "d"),
    (f'const parts = ["{B64[:50]}", "{B64[50:]}"];\nconst d = parts.filter(p => p.length > 0).join("");\n', "d"),
])
def test_js_modern_follows_arrow_template_spread_and_array_methods(src, name):
    got = js_modern.values(src)
    assert got.why is None and got.strings.get(name) == B64, (got.why, got.strings)


def test_js_modern_decodes_atob_and_buffer():
    src = (f'const a = atob("{b64(B64)}");\n'
           f'const b = Buffer.from("{B64.encode().hex()}", "hex").toString("utf8");\n'
           f'const c = Buffer.from("{B64}", "base64").toString();\n')
    got = js_modern.values(src)
    assert got.strings["a"] == B64 and got.strings["b"] == B64 and got.strings["c"] == PLAN


def test_a_value_a_failed_statement_may_have_shaped_is_not_trusted():
    src = (f'let parts = ["{B64[:50]}", "{B64[50:]}"];\nrequire("fs").patch(parts);\n'
           f'const d = parts.join("");\nconst e = "{B64}";\n')
    got = js_modern.values(src)
    assert "d" in got.untrusted and "d" not in got.strings
    assert got.strings["e"] == B64                 # nothing joins e to the failed statement


def test_a_failed_statement_after_the_value_is_final_costs_nothing():
    got = js_modern.values(f'const d = atob("{b64(B64)}");\nWScript.Echo(d);\n')
    assert got.strings.get("d") == B64 and got.failed == 1


def test_a_form_outside_the_subset_is_named():
    got = js_modern.values("const f = ({a, b}) => a + b;\n")
    assert got.strings == {} and "outside the followed subset" in got.why


def test_the_interpreter_is_bounded():
    got = js_modern.values("let s = \"\";\nwhile (true) { s = s + \"a\"; }\nconst d = \"x\";\n")
    assert got.why is not None and "step bound" in got.why


def test_a_computed_js_descriptor_is_read_whole():
    text = f'const head = "{B64[:40]}";\nconst descriptor_ab = atob(`${{head}}{B64[40:]}`);\n'
    info = read("a.js", text)
    assert taken(info) and info["source"] == "residuals" and info["plan"]["file_path"] == FP


def test_a_computed_js_value_that_disagrees_with_the_comment_refuses():
    text = (f"// HUNTRESS_ANALYSIS_V1:B64-{B64}\nconst head = \"{B64_OTHER[:40]}\";\n"
            f"const descriptor_ab = `${{head}}{B64_OTHER[40:]}`;\n")
    assert refused(read("a.js", text))


def test_a_value_nothing_could_follow_leaves_the_computed_copy_one_copy():
    # another top-level string a failed statement assigns may be the value the code really builds: the computed
    # plan is one copy, taken without its last field
    text = (f'let extra = "tail";\nextra = extra + require("os").hostname();\n'
            f'const head = "{B64[:40]}";\nconst descriptor_ab = atob(`${{head}}{B64[40:]}`);\n')
    info = read("a.js", text)
    assert info.get("cut") is True and info["source"] == "residuals" and "file_path" not in info["plan"]
    assert any("not trusted" in n for n in info["notes"])


def test_a_computed_piece_of_another_value_is_no_whole_copy():
    r = rs.Reading()
    src = f'const a = atob("{b64(B64)}");\nconst b = a + "{"Q" * 8}";\n'
    rs.js_witnesses(src, r, rs._Budget())
    a = [w for w in r.witnesses if w.name == "a"]
    assert a and not a[0].whole


# ============================================================================================= multi-host

def ps_enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


INNER = f"# HUNTRESS_ANALYSIS_V1:B64-{B64}\n$descriptor_ab = \"{B64}\"\nWrite-Output 'ok'\n"


def test_a_script_nested_two_hosts_deep_is_read():
    middle = f"powershell -NoProfile -EncodedCommand {ps_enc(INNER)}\n"
    outer = f"@echo off\npowershell.exe -NoProfile -EncodedCommand {ps_enc(middle)}\n"
    info = read("run.bat", outer)
    assert taken(info) and info.get("route") == "multi_host" and info["plan"]["file_path"] == FP


def test_one_host_is_generic_encoded_host():
    one = read("run.bat", f"@echo off\npowershell.exe -EncodedCommand {ps_enc(INNER)}\n")
    assert taken(one) and one.get("route") == "encoded_host"


def test_material_beside_the_outer_host_leaves_the_nested_script_unread():
    # an unquoted run of encoded material beside the host may be a copy nothing reads (generic._region_alone)
    noise = base64.b64encode(bytes((i * 53 + 7) % 256 for i in range(60))).decode()
    middle = f"powershell -NoProfile -EncodedCommand {ps_enc(INNER)}\n"
    beside = f"@echo off\nset CFG={noise}\npowershell.exe -NoProfile -EncodedCommand {ps_enc(middle)}\n"
    assert not read("run.bat", beside).get("plan")


def test_an_innermost_script_with_two_markers_is_not_read_by_multi_host():
    # two tagged comments in the nested script: not the one-marker shape multi_host proves, even when they agree
    two_marks = f"# HUNTRESS_ANALYSIS_V1:B64-{B64}\n" + INNER
    for inner, want in ((INNER, True), (two_marks, False)):
        middle = f"powershell -NoProfile -EncodedCommand {ps_enc(inner)}\n"
        info = {"text": f"@echo off\npowershell.exe -EncodedCommand {ps_enc(middle)}\n", "plan": {}, "notes": []}
        assert rs.multi_host(info, "run.bat") is want and bool(info["plan"]) is want


def test_nesting_deeper_than_the_bound_is_not_read(monkeypatch):
    middle = f"powershell -NoProfile -EncodedCommand {ps_enc(INNER)}\n"
    outer = f"@echo off\npowershell.exe -NoProfile -EncodedCommand {ps_enc(middle)}\n"
    monkeypatch.setattr(rs, "MAX_HOSTS", 1)
    assert not read("run.bat", outer).get("plan")


def test_multi_host_leaves_one_level_to_encoded_host():
    # one host is generic.encoded_host's own reading; multi_host claims only a script nested two or more deep
    one = {"text": f"@echo off\npowershell.exe -EncodedCommand {ps_enc(INNER)}\n", "plan": {}, "notes": []}
    assert rs.multi_host(one, "run.bat") is False and not one["plan"]
    middle = f"powershell -NoProfile -EncodedCommand {ps_enc(INNER)}\n"
    two = {"text": f"@echo off\npowershell.exe -EncodedCommand {ps_enc(middle)}\n", "plan": {}, "notes": []}
    assert rs.multi_host(two, "run.bat") is True and two["route"] == "multi_host"


# ============================================================================================= changed lists

PIECES = [B64[i:i + 24] for i in range(0, len(B64), 24)]


def _list_py(first: str = "", change: str = "") -> str:
    items = ([f'"{first}"'] if first else []) + [f'"{p}"' for p in PIECES]
    joined = "parts[1:]" if first else "parts"
    return f"parts = [{', '.join(items)}]\n{change}plan = \"\".join({joined})\n"


def campaign(info: dict):
    return (info.get("plan") or {}).get("campaign_id")


def _list_js(change: str = "") -> str:
    items = ", ".join(f'"{p}"' for p in PIECES)
    return f"const parts = [{items}];\n{change}const plan = parts.join(\"\");\n"


def test_a_list_swapped_by_a_tuple_assignment_is_a_changed_list():
    assert campaign(read("a.py", _list_py())) == "CMP-4471"        # the control: the list as written
    info = read("a.py", _list_py(change="parts[3], parts[4] = parts[4], parts[3]\n"))
    assert not info.get("plan") and info.get("dead_text")


def test_a_list_swapped_by_a_destructuring_assignment_is_a_changed_list():
    assert campaign(read("a.js", _list_js())) == "CMP-4471"
    info = read("a.js", _list_js(change="[parts[3], parts[4]] = [parts[4], parts[3]];\n"))
    assert not info.get("plan") and info.get("dead_text")


def test_a_keyword_argument_is_no_swap():
    assert campaign(read("a.py", _list_py(change='print(parts[0], end="")\n'))) == "CMP-4471"


NOTE = "this list holds the build configuration for the nightly job, do not edit"
OLD_MATERIAL_LIST = r"[\[({][ \t\r\n]*(?:[\"'][^\"'\r\n]{0,15}[\"'][ \t]*,[ \t\r\n]*)?[\"'`][A-Za-z0-9+/=._:-]{16,}"


def test_a_list_whose_first_item_is_a_long_note_is_still_guarded(monkeypatch):
    text = _list_py(first=NOTE, change=f'parts[3] = "{B64_OTHER[48:72]}"\n')
    assert campaign(read("a.py", _list_py(first=NOTE))) == "CMP-4471"   # the control: nothing changes the list
    assert not read("a.py", text).get("plan")
    # before B-247 the list was passed over (one short item allowed before the material): the plan as written
    monkeypatch.setattr(generic, "_MATERIAL_LIST", __import__("re").compile(OLD_MATERIAL_LIST))
    assert campaign(read("a.py", text)) == "CMP-4471"


# ============================================================================================= the wiring

def _open_info(text=f'descriptor_ab = "{DEEP}"\n'):
    return {"text": text, "ext": ".py", "plan": {}, "notes": []}


def _without(monkeypatch, name):
    real = plan_codec.optional
    monkeypatch.setattr(plan_codec, "optional", lambda n: None if n == name else real(n))


def test_a_missing_residuals_module_fails_loudly(monkeypatch):
    _without(monkeypatch, "residuals")
    with pytest.raises(RuntimeError, match="residuals.py"):
        generic.by_residual(_open_info())


def test_a_missing_descriptor_fails_loudly_through_by_residual(monkeypatch):
    _without(monkeypatch, "descriptor")
    with pytest.raises(rs.MissingModule, match="descriptor.py"):
        generic.by_residual(_open_info())


def test_a_missing_js_modern_fails_loudly(monkeypatch):
    _without(monkeypatch, "js_modern")
    with pytest.raises(rs.MissingModule, match="js_modern.py"):
        generic.by_residual({"text": "const d = `x`;\n", "ext": ".js", "plan": {}, "notes": []})


@pytest.mark.parametrize("hidden", ["residuals", "descriptor"])
def test_a_module_hidden_on_purpose_is_a_note(monkeypatch, hidden):
    monkeypatch.setenv("CTF_TESTING", "1")
    monkeypatch.setenv("CTF_HIDE", hidden)
    info = _open_info()
    assert generic.by_residual(info) is None
    assert info["plan"] == {} and any("CTF_HIDE" in n for n in info["notes"])


def test_a_bug_inside_the_readers_is_a_note(monkeypatch):
    def boom(*_a, **_k):
        raise ValueError("synthetic")
    monkeypatch.setattr(rs, "apply", boom)
    info = _open_info()
    assert generic.by_residual(info) is None and any("residuals raised ValueError" in n for n in info["notes"])


def test_a_lift_must_hold_every_field_already_read():
    info = {"text": f'descriptor_ab = "{DEEP}"\n', "ext": ".py", "notes": [],
            "plan": {"campaign_id": "CMP-0000"}, "cut": True}
    assert rs.apply(info) == "refused" and not info["plan"]


def test_another_refusal_is_never_lifted():
    # the file was refused by another reader (two plans, dead text): a residual copy does not overrule that
    info = {"text": f'descriptor_ab = "{DEEP}"\n', "ext": ".py", "notes": [], "plan": {}, "ambiguous": True,
            "descriptor_why": "the comment and the literal give different plans"}
    assert rs.apply(info) is None and info["plan"] == {} and info["ambiguous"] is True


def test_a_one_copy_reading_does_not_drop_a_field_already_read():
    # what was read (one copy, whole as far as it goes) holds the last field the wrapped copy would leave out
    info = {"text": wrapped_lines("#", B64) + "echo ok\n", "ext": ".sh", "notes": [],
            "plan": plan_codec.flatten(PLAN), "one_copy": ("file_path", FP)}
    assert rs.apply(info) is None and info["plan"]["file_path"] == FP


def test_file_keys_is_bounded():
    text = "".join(f'k{i} = "key-{i:03d}-material"\n' for i in range(rs.MAX_KEYS + 10))
    keys = rs.file_keys(text)
    assert len(keys) == rs.MAX_KEYS and keys[0] == b"key-000-material"


def test_a_settled_plan_is_not_replaced():
    info = {"text": f'descriptor_ab = "{DEEP}"\n', "ext": ".py", "notes": [],
            "plan": plan_codec.flatten(PLAN), "source": "descriptor"}
    assert rs.apply(info) is None and info["source"] == "descriptor"


def test_an_incomplete_plan_is_not_lifted():
    text = f'descriptor_ab = "{deep(PLAN.rsplit("|", 1)[0])}"\n'
    assert [w.kind for w in rs.reading(text, "py").witnesses] == ["deep-literal"]     # read, a whole literal
    info = _open_info(text)
    assert rs.apply(info) is None and not info["plan"]                               # but no whole plan


def test_a_file_over_the_size_bound_is_not_read(monkeypatch):
    monkeypatch.setattr(rs, "MAX_TEXT", 64)
    r = rs.reading(f'descriptor_ab = "{DEEP}"\n', "py")
    assert r.witnesses == [] and any("characters" in n for n in r.notes)


# ============================================================================================= the CLIs

def _cli(script: str, *args, tmp_path=None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(LANE / script), *args], capture_output=True, text=True,
                          timeout=600, cwd=tmp_path)


def test_the_residuals_cli_prints_each_copy(tmp_path):
    spec = tmp_path / "ci.yml"
    spec.write_text(f"# HUNTRESS_ANALYSIS_V1:B64-{B64}\nenv:\n  HUNTRESS_DESCRIPTOR: \"{B64_OTHER}\"\n")
    out = _cli("residuals.py", str(spec), tmp_path=tmp_path)
    assert out.returncode == 0, out.stderr
    assert "key whole" in out.stdout and "2 different plans" in out.stdout
    assert _cli("residuals.py", tmp_path=tmp_path).returncode == 2
    assert _cli("residuals.py", str(tmp_path / "missing.yml"), tmp_path=tmp_path).returncode == 1


def test_the_js_modern_cli_prints_the_values(tmp_path):
    spec = tmp_path / "a.js"
    spec.write_text(f'const d = atob("{b64("hello world value")}");\n')
    out = _cli("js_modern.py", str(spec), tmp_path=tmp_path)
    assert out.returncode == 0 and "d = 'hello world value'" in out.stdout
    assert _cli("js_modern.py", tmp_path=tmp_path).returncode == 2


# ============================================================================================= shapes_py, lang_sh

CUT_BOTH = PLAN[:PLAN.index("|url=") + len("|url=https://") + 4]
CUT_B64 = b64(CUT_BOTH).rstrip("=")


@pytest.mark.parametrize("ext,text", [
    (".py", f"print('ok')\n# HUNTRESS_ANALYSIS_V1:B64-{CUT_B64}\ndescriptor_ab = \"{CUT_B64}\"\n"),
    (".sh", f"echo ok\n# HUNTRESS_ANALYSIS_V1:B64-{CUT_B64}\ndescriptor_ab=\"{CUT_B64}\"\n"),
])
def test_a_descriptor_cut_alike_in_both_copies_answers_no_cut_value(ext, text, monkeypatch, tmp_path):
    # backlog: shapes_py.py (and lang_sh) answered the url of a cut descriptor plain from the literal alone
    import analyze
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    name = "specimen" + ext
    qs = [{"id": f"x-{f}", "qid": f"x-{f}", "answer_id": f"x-{f}", "member": name, "question": f"Recover the {f}."}
          for f in ("campaign", "url", "file-path")]
    with contextlib.redirect_stderr(io.StringIO()):
        got = analyze.solve_set(qs, {name: text.encode()}, {}) or {}
    assert got.get("x-campaign") == "CMP-4471"
    assert "x-url" not in got and "x-file-path" not in got


def test_shapes_py_and_lang_sh_see_a_cut_descriptor_as_settled():
    import lang_sh
    import shapes_py
    text = f"# HUNTRESS_ANALYSIS_V1:B64-{CUT_B64}\ndescriptor_ab = \"{CUT_B64}\"\n"
    assert shapes_py.refused(text) and lang_sh._refused("a.sh", text)
    whole = f"# HUNTRESS_ANALYSIS_V1:B64-{B64}\ndescriptor_ab = \"{B64}\"\n"
    assert not shapes_py.refused(whole) and not lang_sh._refused("a.sh", whole)


# ============================================================================================= day23_fold (row 501)

WIN = PLAN.replace("file_path=C:/t/b.bin", "file_path=C:\\ProgramData\\h\\b.bin")
LYR = base64.b64encode(WIN.encode().hex().encode()).decode()


@pytest.mark.parametrize("ext,lead,lit", [
    (".js", "//", 'var descriptor_ab = "{p}";'),
    (".py", "#", 'descriptor_ab = "{p}"'),
    (".vbs", "'", 'descriptor_ab = "{p}"'),
    (".ps1", "#", "$descriptor_ab = '{p}'"),
])
def test_a_windows_path_lyr_plan_is_rewritten_and_read_back_as_itself(ext, lead, lit):
    import day23_fold
    text = f"{lead} HUNTRESS_ANALYSIS_V1:LYR-hex_b64-{LYR}\n" + lit.format(p=LYR) + "\n"
    with contextlib.redirect_stderr(io.StringIO()):
        new = day23_fold._rewrite(text, "specimen" + ext)
    assert new is not None and "PLAIN-" in new and LYR not in new
    info = read("specimen" + ext, new)
    assert taken(info) and info["plan"]["file_path"] == "C:\\ProgramData\\h\\b.bin"


def _read_back_only(monkeypatch, spelled):
    """generic.read (the dependency) standing in for a lane whose literal reader takes only one spelling."""
    def fake(member, data):
        t = data.decode() if isinstance(data, bytes) else data
        ok = spelled in t
        return {"plan_text": WIN if ok else None, "cut": False, "ambiguous": not ok}
    monkeypatch.setattr(generic, "read", fake)


@pytest.mark.parametrize("spelled", ["C:\\\\ProgramData", "C:\\ProgramData\\h"])
def test_the_backslash_rewrite_keeps_the_spelling_the_lane_reads_back(monkeypatch, spelled):
    import day23_fold
    text = f'// HUNTRESS_ANALYSIS_V1:LYR-hex_b64-{LYR}\nvar descriptor_ab = "{LYR}";\n'
    _read_back_only(monkeypatch, spelled)
    with contextlib.redirect_stderr(io.StringIO()):
        new = day23_fold._backslash_rewrite(text, {LYR: WIN}, "specimen.js")
    literal = new.splitlines()[1]                # the comment's tag is _rewrite's own part, before this step
    assert spelled in literal and LYR not in literal


def test_the_backslash_rewrite_gives_up_when_no_spelling_reads_back(monkeypatch):
    import day23_fold
    _read_back_only(monkeypatch, "never-in-the-text")
    with contextlib.redirect_stderr(io.StringIO()):
        assert day23_fold._backslash_rewrite(f'var descriptor_ab = "{LYR}";\n', {LYR: WIN}, "specimen.js") is None


def test_a_backslash_plan_not_read_back_whole_is_not_rewritten():
    import day23_fold
    # an XML attribute is one copy (`/>` behind it): neither spelling reads back whole, so nothing is substituted
    text = (f"<!-- HUNTRESS_ANALYSIS_V1:LYR-hex_b64-{LYR} -->\n<Project>\n"
            f'  <Plan descriptor_ab="{LYR}" />\n</Project>\n')
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert day23_fold._rewrite(text, "specimen.proj") is None
    assert "backslash" in err.getvalue()


# ============================================================================================= the variants harness

def test_the_variants_harness_answers_no_field_wrong(monkeypatch, tmp_path):
    import script_variants as sv
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    rows = sv.run()
    assert {r["ext"] for r in rows} == set(sv.SCRIPT_EXTS) and not [r for r in rows if "na" in r]
    assert [r for r in rows if r["wrong"]] == []
    assert [(r["ext"], r["how"], r["unplain"]) for r in rows if not r["ok"]] == []
    assert {(r["ext"], r["how"]) for r in rows if r["known"]} == set(sv.KNOWN)
    for ext in (".yml", ".groovy", ".gs", ".csx", ".rb", ".pl", ".ahk", ".proj", ".nsi", ".tf"):
        assert ext in sv.SCRIPT_EXTS                 # row 463's newcomers and the HCL carrier


def test_the_variants_harness_sees_the_residual_shapes(monkeypatch, tmp_path):
    # the harness is not blind to the readers it covers: with them off, the wrapped variants miss their mark
    import script_variants as sv
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(generic, "RESIDUALS", False)
    rows = sv.run((".yml", ".tf", ".bat"), ("d_wrapped", "d_wrapped_both", "d_differs", "d_literal"))
    failed = {(r["ext"], r["how"]) for r in rows if not r["ok"]}
    assert {(".yml", "d_wrapped_both"), (".tf", "d_wrapped"), (".bat", "d_differs"), (".bat", "d_literal")} <= failed


def test_a_variant_answered_wrong_is_graded_wrong():
    import script_variants as sv
    truth = sv.plan_for(".js")
    stem = "js-variant-x"
    good = {f"{stem}-campaign": "CMP-4471", f"{stem}-adapter": "http_get",
            f"{stem}-url": "https://ex.invalid/a/b.bin", f"{stem}-file-path": "C:/t/b.bin"}
    assert sv.grade(good, stem, truth, "plain") == {"wrong": [], "unplain": [], "ok": True}
    bad = dict(good, **{f"{stem}-url": "https://ex.i"})
    g = sv.grade(bad, stem, truth, "safe")
    assert not g["ok"] and g["wrong"] == [("url", "https://ex.i", "https://ex.invalid/a/b.bin")]
    cut = {k: v for k, v in good.items() if not k.endswith("file-path")}
    assert sv.grade(cut, stem, truth, "cut")["ok"] and not sv.grade(cut, stem, truth, "plain")["ok"]
    assert sv.grade({}, stem, truth, "none")["ok"] and not sv.grade(good, stem, truth, "none")["ok"]


def test_the_variants_cli_reports_and_exits(tmp_path):
    out = subprocess.run([sys.executable, "-I", str(REPO / "tests" / "script_variants.py"), "--ext", ".yml",
                          "--how", "d_differs", "--json", str(tmp_path / "t.json")], capture_output=True, text=True,
                         timeout=600, cwd=tmp_path)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "VARIANTS lane=script variants=1 wrong=0 failed=0" in out.stdout and (tmp_path / "t.json").is_file()
    bad = subprocess.run([sys.executable, "-I", str(REPO / "tests" / "script_variants.py"), "--ext", ".nope"],
                         capture_output=True, text=True, timeout=600, cwd=tmp_path)
    assert bad.returncode == 2
