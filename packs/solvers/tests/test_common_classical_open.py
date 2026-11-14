"""B-125: classical.crack wired into the opener (intake), the substring-crib rail fence, the dictionary
polish for substitution, and the decoded lines that give wrapper instructions.

Every cipher text is made here from plain text written for this test (the encoders are the library's
own; the rail and substitution readers are checked against plain text the test holds, not against
the encoder's output). The intake test uses a fake platform adapter and the repo's real manifests; no
network is used.
"""
from __future__ import annotations

import dataclasses
import json
import random
import sys
from pathlib import Path

import pytest

from ctf import event, flagfmt, paths
from ctf.result import SolverResult

REPO = paths.repo_root()
sys.path.insert(0, str(REPO / "solvers" / "common"))
from _shadowed import common_module, module_at  # noqa: E402

C = common_module("classical")
# The path is one string so the coverage report (ctf/engines/coverage.py) counts this file as a test of the engine.
O = module_at(REPO / "solvers/common/classical_open.py", "classical_open_b125")

SPOOKY = event.load("spooky")
FF = flagfmt.for_profile(SPOOKY)

# A flag mid-sentence after an underscore, as in the Spooky rail-fence drop (written for this test).
RAIL_PLAIN = "Carve_the_lantern_and_read_what_glows:_spooky{r41l5_r0ll_4r0und}"
RAIL_FLAG = "spooky{r41l5_r0ll_4r0und}"

LETTER = """My dearest Margaret,

Every night since you left the village I have walked down to the old mill and waited by the water.
The lamps in the windows go out one by one, and the whole valley turns quiet and cold.
I keep thinking about the summer we spent painting the fence behind the church, and how the paint
dried on our hands for weeks afterwards. Mother still asks about you whenever the post arrives.
Something strange has happened here, and I must tell you about it before the winter comes.
There is a figure that stands at the edge of the forest each evening, never moving, never speaking.
The farmers say it has been there for a hundred years, though nobody can remember seeing it before.
I have tried to follow it twice, but each time the path changed beneath my feet and I found myself
back at the gate of the cemetery with the moon behind me and my lantern burning low.
If you are reading this, please do not come back until the frost has gone from the fields.
I have written the important part below, the way we used to hide our notes when we were children.
the lantern keeps the dark away. remember to use underscores instead of spaces and wrap it properly.
Please keep this letter somewhere safe, and burn it if anyone else starts asking questions.
With all my love and every good wish for the new year,

Your brother Thomas
"""
INSTRUCTION = "the lantern keeps the dark away. remember to use underscores instead of spaces and wrap it properly."


def _key(seed: int) -> str:
    perm = list(C.A)
    random.Random(seed).shuffle(perm)
    return "".join(perm)


def _swap(alphabet: str, *pairs) -> str:
    a = list(alphabet)
    for x, y in pairs:
        i, j = C.A.index(x), C.A.index(y)
        a[i], a[j] = a[j], a[i]
    return "".join(a)


# ---------------------------------------------------------------- crib_railfence, contains mode

def test_prefix_crib_misses_a_wrapper_mid_sentence_and_contains_finds_the_one_setting():
    ct = C.railfence_encrypt(RAIL_PLAIN, 5, 3)
    assert C.crib_railfence(ct, "spooky{") is None                    # prefix mode: unchanged
    assert C.crib_railfence(ct, "spooky{", contains=True) == (5, 3)
    assert C.railfence_decrypt(ct, 5, 3) == RAIL_PLAIN
    assert C.crib_railfence(ct, "Carve_the", contains=False) == (5, 3)  # a real prefix still reads


def test_contains_crib_is_case_exact_unless_folded():
    ct = C.railfence_encrypt(RAIL_PLAIN, 4, 0)
    assert C.crib_railfence(ct, "SPOOKY{", contains=True) is None
    assert C.crib_railfence(ct, "SPOOKY{", contains=True, fold=True) == (4, 0)
    assert C.crib_railfence(ct, "CARVE_THE", fold=True) == (4, 0)
    assert C.crib_railfence(ct, "CARVE_THE") is None


def test_contains_crib_refuses_missing_characters_and_ambiguous_readings():
    ct = C.railfence_encrypt(RAIL_PLAIN, 4, 0)
    assert C.crib_railfence(ct, "spooky{X", contains=True) is None     # X is not in the cipher text
    assert C.crib_railfence(ct, "a", contains=True) is None            # in nearly every reading
    assert C.crib_railfence(ct, "", contains=True) is None


def test_railfence_holding_lists_every_setting_whose_reading_holds_the_crib_best_first():
    ct = C.railfence_encrypt(RAIL_PLAIN, 6, 2)
    held = C.railfence_holding(ct, "spooky{")
    # other start offsets of six rails scramble only the ends: they hold the crib too
    assert [(r, o) for r, o, _ in held][0] == (6, 2) and held[0][2] == RAIL_PLAIN
    assert len(held) == 3 and all(RAIL_FLAG in t for _, _, t in held)
    assert C.crib_railfence(ct, "spooky{", contains=True) is None        # not one: None, as documented
    assert C.railfence_holding(ct, "SPOOKY{") == [] and len(C.railfence_holding(ct, "SPOOKY{", fold=True)) == 3
    assert C.railfence_holding(ct, "") == [] and C.railfence_holding(ct, "spooky{Q") == []


def test_crack_reports_the_contains_rail_as_a_crib_reading_from_the_minimum_crib_length():
    ct = C.railfence_encrypt(RAIL_PLAIN, 5, 3)
    got = C.crack(ct, crib="spooky{", seconds=1.0)
    assert ("crib", "rail:5.3", RAIL_PLAIN) in got
    short = "spooky{"[:C.RAIL_CONTAINS_MIN - 1]
    assert C.crib_railfence(ct, short, contains=True, fold=True) == (5, 3)   # it would read ...
    assert not [n for how, n, _ in C.crack(ct, crib=short, seconds=1.0) if how == "crib" and "rail" in n]  # ... but is not asked


def test_crack_reports_every_holding_setting_and_none_when_too_many_hold_the_crib():
    ct = C.railfence_encrypt(RAIL_PLAIN, 6, 2)
    names = [n for how, n, _ in C.crack(ct, crib="spooky{", seconds=1.0) if how == "crib"]
    assert sorted(names) == ["rail:6.0", "rail:6.2", "rail:6.6"]
    ct = C.railfence_encrypt(RAIL_PLAIN, 5, 3)
    assert len(C.railfence_holding(ct, "_and_", fold=True)) > C.RAIL_HOLDERS_MAX     # nine settings
    assert not [n for how, n, _ in C.crack(ct, crib="_and_", seconds=1.0) if how == "crib" and "rail:" in n]


def test_crack_reads_a_reversed_rail_fence_with_a_crib_mid_sentence():
    ct = C.railfence_encrypt(RAIL_PLAIN, 3, 1)[::-1]
    got = C.crack(ct, crib="SPOOKY{", seconds=1.0)
    assert ("crib", "reverse+rail:3.1", RAIL_PLAIN) in got


# ---------------------------------------------------------------- substitution polish

def test_polish_swaps_confusable_pairs_back_and_names_them():
    key = _key(11)
    ct = C.substitution_encrypt(LETTER, key)
    bad = _swap(key, ("p", "f"), ("m", "w"))
    assert C.substitution_decrypt(ct, bad) != LETTER
    alphabet, plain, swaps = C.polish_substitution(ct, bad)
    assert plain == LETTER and alphabet == key
    assert sorted(swaps) == ["fp", "mw"]


def test_polish_leaves_a_right_key_alone_even_with_a_non_dictionary_word():
    text = LETTER.replace("the lantern keeps", "eyez see the lantern keeps")
    key = _key(5)
    ct = C.substitution_encrypt(text, key)
    alphabet, plain, swaps = C.polish_substitution(ct, key)
    assert (alphabet, plain, swaps) == (key, text, [])
    assert "eyez" in plain


def test_polish_takes_only_a_permutation():
    with pytest.raises(ValueError):
        C.polish_substitution("abc", "abc")
    with pytest.raises(ValueError):
        C.polish_substitution("abc", "a" * 26)


def test_coverage_uses_words_with_breaks_and_segments_without():
    assert C.coverage("the water and the mill") == 1.0
    assert C.coverage("thewaterandthemill") == pytest.approx(1.0)
    assert C.coverage("qzx vvk jjq") == 0.0


# ---------------------------------------------------------------- instruction lines

def test_instruction_lines_name_each_cue_and_skip_plain_prose():
    got = {e["line"]: e for e in C.instruction_lines(LETTER, ["spooky"])}
    line = LETTER.splitlines().index(INSTRUCTION) + 1
    assert got[line]["text"] == INSTRUCTION
    assert got[line]["why"] == ["underscores", "spaces", "wrap", "lower case line"]
    cont = LETTER.splitlines().index("back at the gate of the cemetery with the moon behind me and my lantern burning low.") + 1
    assert cont not in got                  # lower case, but it carries on the sentence above
    assert set(got) == {line}


def test_instruction_lines_flag_the_template_and_the_wrapper():
    text = ("Read this first.\nThe answer is spooky{x}.\nPut it in SPOOKY {} at the end.\n"
            "Nothing here.\nKeep it in lower case and in the flag format.\nUse curly braces.")
    got = {e["line"]: e["why"] for e in C.instruction_lines(text, ["spooky"], FF.find_flags)}
    assert got[2] == ["flag format", "names the wrapper", "names the answer"]
    assert got[3] == ["names the wrapper"]
    assert got[5] == ["format", "case"]
    assert got[6] == ["braces"]
    assert 1 not in got and 4 not in got
    assert "spookyish" not in str(C.instruction_lines("A spookyish tale.", ["spooky"]))
    assert C.instruction_lines("A spookyish tale.", ["spooky"]) == []


# ---------------------------------------------------------------- the opener

def test_decode_takes_printable_utf8_text_drops_only():
    assert O.decode(b"abc\r\ndef\n") == ("abc\ndef", None)
    assert O.decode(b"x" * (O.MAX_BYTES + 1))[0] is None
    assert O.decode(b"\xff\xfe\x00a")[1] == "not UTF-8 text"
    assert "control" in O.decode(b"abc\x01def")[1]
    assert O.decode(b"\n\n  \n")[1] == "empty"


def test_shape_of_tells_a_short_drop_from_letter_shaped_text():
    short, lettered, _ = O.shape_of(RAIL_PLAIN)
    assert short and not lettered
    short, lettered, _ = O.shape_of(LETTER)
    assert short and lettered
    long_digits = " ".join(["12345 67890"] * 600)
    short, lettered, _ = O.shape_of(long_digits)
    assert not short and not lettered
    op = O.open_text(long_digits, FF, seconds=1.0)
    assert not op.taken and op.hits == [] and "not opened" in op.shape[-1]


def test_several_holding_settings_that_agree_on_the_flag_are_still_solved():
    ct = C.railfence_encrypt(RAIL_PLAIN, 6, 2)
    op = O.open_text(ct, FF, seconds=3.0)
    assert op.flags == [RAIL_FLAG] and O.result_of(op, "d.txt", None).status == "solved"
    # three holding settings, each read by crack() and again by the opener's rail loop: three readings
    texts = [r for _, _, r in op.readings]
    assert len(texts) >= 3 and len(set(texts)) == len(texts)


def test_a_rail_fence_drop_with_the_wrapper_mid_sentence_is_solved():
    ct = C.railfence_encrypt(RAIL_PLAIN, 4, 0)
    op = O.open_text(ct, FF, seconds=3.0)
    assert op.taken and op.flags == [RAIL_FLAG] and op.proven(RAIL_FLAG)
    res = O.result_of(op, "drop.txt", None)
    assert res.status == "solved" and res.flags == (RAIL_FLAG,)
    assert "rail:4.0" in res.evidence[0].detail and res.evidence[0].path == "drop.txt"
    # crack() and the opener's own railfence_holding loop both return the rail reading: it is kept once
    texts = [r for _, _, r in op.readings]
    assert RAIL_PLAIN in texts and len(set(texts)) == len(texts)


def test_a_wrapper_after_an_underscore_needs_the_bytes_search():
    # The text form's left boundary refuses '_spooky{': the reason flags_in searches bytes.
    assert FF.find_flags(RAIL_PLAIN) == []
    assert O.flags_in(FF)(RAIL_PLAIN) == [RAIL_FLAG]


def test_a_flag_already_in_the_file_is_the_sweeps_and_not_a_hit():
    text = "plain note: spooky{already_here} and nothing else to read here at all"
    op = O.open_text(text, FF, seconds=1.0)
    assert op.taken and op.hits == []
    assert O.result_of(op, "n.txt", None).status == "none"


def test_scored_only_flags_are_candidates_not_solved():
    op = O.Opening(taken=True, hits=[O.Hit("spooky{a}", "score", "rail:3.0", "x spooky{a}")])
    assert O.result_of(op, "f", None).status == "candidate"
    op.hits.append(O.Hit("spooky{b}", "crib", "rail:4.0", "y spooky{b}"))
    res = O.result_of(op, "f", None)
    assert res.status == "candidate" and res.flags == ("spooky{a}", "spooky{b}")   # two flags: not one proof


def test_a_substitution_letter_is_cracked_polished_and_its_instruction_line_reported():
    ct = C.substitution_encrypt(LETTER, _key(11))
    op = O.open_text(ct, FF, seconds=6.0)
    assert op.substitution and op.hits == []
    hits = [e for _, e in op.lines if e["text"] == INSTRUCTION]
    assert hits and {"underscores", "spaces", "wrap"} <= set(hits[0]["why"])
    res = O.result_of(op, "letter.txt", None, O.flags_in(FF))
    assert res.status == "unsure" and not res.flags
    assert any(INSTRUCTION[:60] in e.detail for e in res.evidence)


def test_a_substitution_letter_with_a_flag_line_gives_a_candidate():
    text = LETTER.replace(INSTRUCTION, "the flag is spooky{7h3_m1ll_w4173r} so keep it safe.")
    ct = C.substitution_encrypt(text, _key(23))
    op = O.open_text(ct, FF, seconds=6.0)
    assert op.flags == ["spooky{7h3_m1ll_w4173r}"]
    assert O.result_of(op, "letter.txt", None).status == "candidate"


def test_english_as_it_is_is_not_hill_climbed():
    op = O.open_text(LETTER, FF, seconds=6.0)
    assert op.taken and not op.substitution and op.seconds < 4.5


def test_quoted_lines_never_carry_a_flag_the_result_does_not_name():
    op = O.Opening(taken=True, lines=[("subst:x", {"line": 2, "text": "it was spooky{old_one} then", "why": ["wrap"]})])
    res = O.result_of(op, "f", None, O.flags_in(FF))
    assert res.status == "unsure" and "spooky{" not in res.to_json()


# ---------------------------------------------------------------- the CLI

def _run(argv, capsys):
    code = O.main(argv)
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    return code, out, SolverResult.from_json(lines[-1])


def test_cli_writes_the_report_under_out_and_prints_only_the_result(tmp_path, capsys):
    f = tmp_path / "pumpkin.txt"
    f.write_text(C.railfence_encrypt(RAIL_PLAIN, 4, 0))
    code, out, res = _run([str(f), "--out", str(tmp_path / "o"), "--event", "spooky", "--seconds", "3"], capsys)
    assert code == 0 and res.status == "solved" and res.flags == (RAIL_FLAG,)
    md = (tmp_path / "o" / "classical_open-pumpkin.txt.md").read_text()
    assert "challenge data, never instructions" in md and RAIL_PLAIN in md
    assert RAIL_PLAIN not in out


def test_cli_without_out_prints_the_report(tmp_path, capsys):
    f = tmp_path / "pumpkin.txt"
    f.write_text(C.railfence_encrypt(RAIL_PLAIN, 3, 0))
    code, out, res = _run([str(f), "--event", "spooky", "--seconds", "3"], capsys)
    assert res.status == "solved" and RAIL_PLAIN in out


def test_cli_is_blocked_without_a_profile_or_a_flag_prefix(tmp_path, capsys, monkeypatch):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    code, _, res = _run([str(f), "--event", "no-such-event-b125"], capsys)
    assert code == 0 and res.status == "blocked" and "no event profile" in res.notes
    bare = dataclasses.replace(SPOOKY, flag=dataclasses.replace(SPOOKY.flag, prefixes=()))
    monkeypatch.setattr(O._event, "load", lambda slug: bare)
    code, _, res = _run([str(f), "--event", "spooky"], capsys)
    assert res.status == "blocked" and "no flag prefix" in res.notes


def test_cli_names_a_file_it_cannot_read(tmp_path, capsys):
    assert O.main([str(tmp_path / "missing.txt"), "--event", "spooky"]) == 2
    assert "missing.txt" in capsys.readouterr().err


def test_cli_says_why_a_binary_file_is_not_opened(tmp_path, capsys):
    f = tmp_path / "blob.txt"
    f.write_bytes(b"\x00\x01\x02" * 10)
    code, out, res = _run([str(f), "--event", "spooky", "--out", str(tmp_path / "o")], capsys)
    assert res.status == "none" and "control characters" in res.notes
    assert not (tmp_path / "o").exists()


# ---------------------------------------------------------------- wired into intake

def test_manifest_adapts_text_drops_for_intake():
    from ctf.engines import manifest
    from ctf.intake import engines as E
    m = {x.id: x for x in manifest.discover(REPO)}["common.classical_open"]
    assert m.intake.select == "files" and m.intake.run == "per-file" and m.cost_class == "cheap"
    assert "{file}" in m.intake.args and "{out}" in m.intake.args
    assert not m.has("legacy-output")
    assert E.files_matching(m.intake.match, [(Path("pumpkin_head_message.txt"), b"x")])
    assert not E.files_matching(m.intake.match, [(Path("a.png"), b"\x89PNG")])


class _Adapter:
    kind = "fake"

    def __init__(self, ch, files):
        self.ch, self.files = ch, files

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def test_intake_runs_the_opener_on_a_text_drop_and_finds_the_rail_fence_flag(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    ct = C.railfence_encrypt(RAIL_PLAIN, 4, 0)
    ch = Challenge(id="7", name="Heads", category="crypto", points=428,
                   description="rolling, rolling, near the rails", files=(FileRef("pumpkin.txt"),))
    rep = I.intake_one("7", SPOOKY, adapter=_Adapter(ch, {"pumpkin.txt": ct.encode()}), workdir=tmp_path / "wd",
                       options=I.Options(net_guard="hook", record=False))
    runs = [r for r in rep.runs if r.engine == "common.classical_open"]
    assert runs and runs[0].status == "ok" and runs[0].result_status == "solved"
    assert rep.status == "solved" and rep.result.flags == (RAIL_FLAG,)
    report = rep.dir / "recon" / "engines" / "common.classical_open" / "classical_open-pumpkin.txt.md"
    assert RAIL_PLAIN in report.read_text()
    saved = json.loads((rep.dir / "recon" / "intake.json").read_text())
    assert any(r["engine"] == "common.classical_open" for r in saved["engines_run"])


def test_router_sends_classical_briefs_here_but_a_text_file_alone_does_not():
    from ctf.engines import router
    ids = [h.manifest.id for h in router.route("crypto", "A letter, but it seems to have been scrambled around.")]
    assert "common.classical_open" in ids
    assert "common.classical_open" in [h.manifest.id for h in router.route("crypto", "rolling, near the rails")]
    assert "common.classical_open" not in [h.manifest.id for h in router.route("crypto", "an rsa modulus")]
    assert "common.classical_open" not in [h.manifest.id for h in router.route("web", "scrambled login")]


def test_long_letter_shaped_text_is_taken_though_it_is_not_a_short_drop():
    long = (LETTER + "\n") * 4
    short, lettered, _ = O.shape_of(long)
    assert not short and lettered
    op = O.open_text(long, FF, seconds=2.0)
    assert op.taken and not op.substitution          # English as it is: taken, not hill-climbed


def test_the_opener_polishes_the_hill_climbs_key(monkeypatch):
    key = _key(11)
    ct = C.substitution_encrypt(LETTER, key)
    bad = _swap(key, ("p", "f"))
    # the hill climb is stubbed to leave the p/f confusion the real one left on the Spooky letter
    monkeypatch.setattr(O.classical, "crack_substitution",
                        lambda text, seconds=3.0: [(-4.0, bad, C.substitution_decrypt(text, bad))])
    op = O.open_text(ct, FF, seconds=4.0)
    assert op.substitution and op.polish == ["fp"]
    name, reading = next((n, r) for how, n, r in op.readings if n.startswith("subst:"))
    assert reading == LETTER and name == "subst:" + key + "+polish:fp"
    # the polished reading's line comes first; crack()'s own scored readings of the same line
    # (unpolished, so 'froferly') may follow it, as a line of another reading
    cues = [(n, e["text"]) for n, e in op.lines if "underscores" in e["why"]]
    assert cues[0] == (name, INSTRUCTION)
    assert all(n != name for n, _ in cues[1:])


def test_a_wrapper_shorter_than_cracks_minimum_is_read_on_every_holding_setting():
    spec = dataclasses.replace(SPOOKY.flag, prefixes=("ctf",), case="exact")
    ff = flagfmt.for_profile(dataclasses.replace(SPOOKY, flag=spec))
    assert len("ctf{") < C.RAIL_CONTAINS_MIN
    plain = "Carve_the_lantern_and_read_what_glows:_ctf{r41l5_r0ll_4r0und}"
    ct = C.railfence_encrypt(plain, 3, 0)
    assert len(C.railfence_holding(ct, "ctf{")) == 3     # the other two are the text turned round
    op = O.open_text(ct, ff, seconds=3.0)
    assert op.flags == ["ctf{r41l5_r0ll_4r0und}"] and op.proven("ctf{r41l5_r0ll_4r0und}")
    assert {h.name for h in op.hits if h.how == "crib"} == {"rail:3.0"}
    assert O.result_of(op, "d.txt", None).status == "solved"


def test_holding_settings_that_disagree_on_the_flag_are_candidates():
    spec = dataclasses.replace(SPOOKY.flag, prefixes=("ctf",), case="exact")
    ff = flagfmt.for_profile(dataclasses.replace(SPOOKY, flag=spec))
    plain = "Carve_the_lantern_and_read_what_glows:_ctf{r41l5_r0ll_4r0und}"
    op = O.open_text(C.railfence_encrypt(plain, 5, 0), ff, seconds=3.0)
    assert "ctf{r41l5_r0ll_4r0und}" in op.flags and len(op.flags) > 1      # a wrong offset reads another
    assert O.result_of(op, "d.txt", None).status == "candidate"


# ---------------------------------------------------------------- boundaries

def _exact_ctf():
    spec = dataclasses.replace(SPOOKY.flag, prefixes=("ctf",), case="exact")
    return flagfmt.for_profile(dataclasses.replace(SPOOKY, flag=spec))


def test_decode_takes_a_file_of_exactly_max_bytes():
    assert O.decode(b"a" * O.MAX_BYTES) == ("a" * O.MAX_BYTES, None)


def test_a_lower_case_line_is_odd_only_in_a_text_of_capitalised_sentences():
    lower = "\n\n".join(["the mill stands quiet by the water tonight."] * 4)
    assert all("lower case line" not in e["why"] for e in C.instruction_lines(lower, ["spooky"]))
    mixed = lower.replace("the mill", "The mill", 3)                 # three of four now capitalised
    got = [e for e in C.instruction_lines(mixed, ["spooky"]) if "lower case line" in e["why"]]
    assert [e["line"] for e in got] == [7]


def test_a_text_without_word_breaks_is_not_letter_shaped():
    blob = C.letters(LETTER)                                          # the same letters, no word breaks
    assert len(blob) >= O.LETTER_MIN
    short, lettered, _ = O.shape_of(blob)
    assert short and not lettered
    assert O.shape_of(LETTER)[1]
    long_blob = blob * 5
    assert len(long_blob) > O.SHORT_MAX
    assert not O.open_text(long_blob, FF, seconds=1.0).taken


def test_an_exact_case_wrapper_is_not_folded_for_the_rail_search():
    ff = _exact_ctf()
    plain = "Carve_the_lantern_and_read_what_glows:_CTF{r41l5_r0ll_4r0und}"
    op = O.open_text(C.railfence_encrypt(plain, 4, 0), ff, seconds=2.0)
    assert op.flags == []
    assert not [n for how, n, _ in op.readings if how == "crib"]       # CTF{ is not ctf{ in this event


def test_crack_asks_the_rail_fence_about_a_crib_of_exactly_the_minimum_length():
    crib = "spook"
    assert len(crib) == C.RAIL_CONTAINS_MIN
    ct = C.railfence_encrypt(RAIL_PLAIN, 5, 3)
    assert [(r, o) for r, o, _ in C.railfence_holding(ct, crib, fold=True)] == [(5, 3)]
    assert not RAIL_PLAIN.lower().startswith(crib)                     # no prefix-crib step reads it
    rails = [(n, t) for how, n, t in C.crack(ct, crib=crib, seconds=1.0) if how == "crib" and "rail:" in n]
    assert rails == [("rail:5.3", RAIL_PLAIN)]


def test_crack_reports_exactly_the_maximum_number_of_holding_settings():
    ct = C.railfence_encrypt(RAIL_PLAIN, 5, 1)
    held = C.railfence_holding(ct, "ooky{", fold=True)
    assert len(held) == C.RAIL_HOLDERS_MAX
    names = {n for how, n, _ in C.crack(ct, crib="ooky{", seconds=1.0) if how == "crib" and "rail:" in n}
    assert names == {"rail:%d.%d" % (r, o) for r, o, _ in held} == {"rail:5.0", "rail:5.1", "rail:5.2", "rail:5.7"}


def test_the_opener_reads_a_short_wrapper_held_by_exactly_the_maximum_number_of_settings():
    ff = _exact_ctf()
    plain = "Carve_the_lantern_and_read_what_glows:_ctf{r41l5_r0ll_4r0und}"
    ct = C.railfence_encrypt(plain, 4, 3)
    held = C.railfence_holding(ct, "ctf{")
    assert len(held) == C.RAIL_HOLDERS_MAX and len("ctf{") < C.RAIL_CONTAINS_MIN   # crack() does not ask
    op = O.open_text(ct, ff, seconds=3.0)
    assert {h.name for h in op.hits if h.how == "crib"} == {"rail:%d.%d" % (r, o) for r, o, _ in held}
    assert op.flags == ["ctf{r41l5_r0ll_4r0und}"]
    assert O.result_of(op, "d.txt", None).status == "solved"


# Not English as it is (coverage under ENGLISH_ALREADY) and not letter-shaped (no substitution hill
# climb), so the readings the stub gives are searched for cue lines.
_NOISE = "\n".join(["4f 9a 0c 7e 21 b3 58 d6", "e0 13 9b 7a c4 62 0f 88"] * 3)


def _stub_crack(monkeypatch, readings):
    monkeypatch.setattr(O.classical, "crack", lambda text, crib=None, pattern=None, seconds=2.0: list(readings))


def test_cue_lines_at_one_line_number_in_two_readings_are_both_reported(monkeypatch):
    first = "use underscores instead of spaces here\n" + _NOISE
    second = "wrap the answer in curly braces\n" + _NOISE
    _stub_crack(monkeypatch, [("crib", "rail:5.0", first), ("crib", "rail:5.3", second),
                              ("crib", "rail:5.7", first.replace(_NOISE, "zz"))])
    op = O.open_text(_NOISE, FF, seconds=1.0)
    assert [(n, e["line"], e["text"]) for n, e in op.lines] == [
        ("rail:5.0", 1, "use underscores instead of spaces here"),
        ("rail:5.3", 1, "wrap the answer in curly braces")]       # the third repeats the first: once


def test_a_reading_that_is_the_text_as_it_is_is_not_a_decoded_reading(monkeypatch):
    text = "use underscores instead of spaces here\n" + _NOISE
    assert C.instruction_lines(text, ["spooky"])                    # the cue is in the file as it is
    _stub_crack(monkeypatch, [("crib", "noop", text)])
    op = O.open_text(text, FF, seconds=1.0)
    assert op.taken and op.readings == [] and op.lines == []
    assert O.result_of(op, "n.txt", None, O.flags_in(FF)).status == "none"


def test_a_reversed_rail_fence_with_a_short_wrapper_is_read():
    ff = _exact_ctf()
    plain = "Carve_the_lantern_and_read_what_glows:_ctf{r41l5_r0ll_4r0und}"
    op = O.open_text(C.railfence_encrypt(plain, 4, 1)[::-1], ff, seconds=3.0)
    assert op.flags == ["ctf{r41l5_r0ll_4r0und}"]
    assert any(h.name.startswith("reverse+rail:") and h.how == "crib" for h in op.hits)
    assert O.result_of(op, "d.txt", None).status == "solved"
