"""B-116: the white-box language-model prefix probe (solvers/toolkits/model_prefix_probe.py).

Everything is synthetic (tests/b116_models.py): a tiny decoder in the Qwen2 tensor layout whose
weights make it "remember" one made-up string, random decoders checked against a loop-per-position
reference forward pass, a byte-level BPE vocabulary of a dozen merges, and a scripted stand-in model
for the probe's own logic. No real model, no torch, no network. Budgets are CPU time or a step clock.
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import types
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import b116_models as fx  # noqa: E402

from ctf import event, flagfmt  # noqa: E402
from ctf.result import SolverResult  # noqa: E402
from solvers.toolkits import model_prefix_probe as pp  # noqa: E402

pytestmark = pytest.mark.needs_tool("py:numpy")

REPO = Path(__file__).resolve().parents[1]
SPOOKY, CSCTF = event.load("spooky"), event.load("csctf")
FF_SPOOKY, FF_CSCTF = flagfmt.for_profile(SPOOKY), flagfmt.for_profile(CSCTF)
BODY = "numpy_probe_42}"                       # what the synthetic memorizer says after an opening brace
BUDGET = 600.0


def _unknown_profile():
    import datetime
    return event.parse({
        "slug": "b116-probe", "name": "B-116 probe", "dates": {"start": datetime.date(2026, 1, 1),
                                                               "end": datetime.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b116.test"},
        "flag": {"prefixes": [], "body": "[^}\\n]{1,256}", "case": "prefix-insensitive"},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["localhost"]},
    }, src="<test>")


def _zip_challenge(tmp_path, model=None, **kw):
    ch = tmp_path / "the-model-knows-synthetic"
    fx.write_zip(ch / "files" / "dist.zip", fx.model_files(model or fx.memorizer(), **kw))
    return ch


def _folder_challenge(tmp_path, model=None, **kw):
    ch = tmp_path / "folder-challenge"
    fx.write_folder(ch / "files" / "model", fx.model_files(model or fx.memorizer(), **kw))
    return ch


# ---------------------------------------------------------------- the numpy decoder against the definition

@pytest.mark.parametrize("label, kw", [
    ("tied, biases, grouped-query", dict(hidden=16, layers=2, heads=4, kv_heads=2, inner=24, tied=True, bias=True)),
    ("untied head, no bias", dict(hidden=16, layers=2, heads=4, kv_heads=4, inner=12, tied=False, bias=False)),
    ("one key/value head for all", dict(hidden=24, layers=3, heads=6, kv_heads=1, inner=20, tied=True, bias=True)),
])
def test_decoder_logits_equal_the_reference_forward_pass(label, kw):
    bias = kw.pop("bias")
    config = fx.decoder_config(40, **kw)
    weights = fx.random_decoder_weights(config, seed=3, bias=bias)
    ids = [3, 17, 5, 5, 39, 0, 21, 8, 30, 17, 2]
    want = fx.reference_logits(config, weights, ids)
    got = pp.NumpyDecoder(config, weights).forward(ids)
    assert got.shape == (len(ids), 40) and got.dtype == np.float32
    assert np.abs(want).max() > 3                              # the comparison is not between two near-zero tables
    assert np.abs(got - want).max() < 2e-3, label
    assert [int(r.argmax()) for r in got] == [int(r.argmax()) for r in want]


def test_key_value_cache_gives_the_same_logits_as_one_pass():
    config = fx.decoder_config(40, 16, layers=2, heads=4, kv_heads=2, inner=24, tied=True)
    dec = pp.NumpyDecoder(config, fx.random_decoder_weights(config, seed=4))
    ids = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    whole = dec.forward(ids)
    cache = dec.new_cache()
    parts = [dec.forward(ids[:4], cache), dec.forward(ids[4:5], cache), dec.forward(ids[5:], cache)]
    assert np.abs(np.concatenate(parts) - whole).max() < 1e-4
    assert cache[0][0].shape[1] == len(ids)                    # the cache holds one key per token seen
    assert np.abs(dec.forward(ids, last_only=True) - whole[-1]).max() < 1e-5


def test_a_later_token_never_changes_an_earlier_position():
    config = fx.decoder_config(40, 16, layers=2, heads=4, kv_heads=2, inner=24, tied=True)
    dec = pp.NumpyDecoder(config, fx.random_decoder_weights(config, seed=5))
    a, b = dec.forward([1, 2, 3, 4, 5]), dec.forward([1, 2, 3, 30, 31])
    assert np.abs(a[:3] - b[:3]).max() < 1e-5 and np.abs(a[3:] - b[3:]).max() > 1e-2


def test_position_matters_through_the_rotary_encoding():
    """The same token after the same token, one position later, must not give the same logits."""
    config = fx.decoder_config(40, 16, layers=2, heads=4, kv_heads=2, inner=24, tied=True)
    dec = pp.NumpyDecoder(config, fx.random_decoder_weights(config, seed=6))
    out = dec.forward([7, 9, 9, 9])
    assert np.abs(out[2] - out[3]).max() > 1e-3


@pytest.mark.parametrize("change, message", [
    (lambda c, w: w.pop("model.layers.1.mlp.up_proj.weight"), "lack tensor 'model.layers.1.mlp.up_proj.weight'"),
    (lambda c, w: w.__setitem__("model.layers.0.self_attn.k_proj.weight", np.zeros((16, 16), np.float32)),
     "'model.layers.0.self_attn.k_proj.weight' has shape \\[16, 16\\], expected \\[8, 16\\]"),
    (lambda c, w: c.__setitem__("hidden_act", "gelu"), "hidden_act 'gelu'"),
    (lambda c, w: c.__setitem__("num_attention_heads", 3), "do not form attention heads"),
    (lambda c, w: c.pop("hidden_size"), "lacks a decoder size"),
    (lambda c, w: (c.__setitem__("tie_word_embeddings", False)), "no lm_head.weight"),
])
def test_decoder_refuses_a_layout_it_does_not_run(change, message):
    config = fx.decoder_config(40, 16, layers=2, heads=4, kv_heads=2, inner=24, tied=True)
    weights = fx.random_decoder_weights(config, seed=1)
    change(config, weights)
    with pytest.raises(pp.ProbeError, match=message):
        pp.NumpyDecoder(config, weights)


def test_decoder_refuses_tokens_and_positions_outside_the_model():
    config = fx.decoder_config(40, 16, layers=1, heads=4, kv_heads=2, inner=24, tied=True)
    config["max_position_embeddings"] = 6
    dec = pp.NumpyDecoder(config, fx.random_decoder_weights(config, seed=1))
    with pytest.raises(pp.ProbeError, match="token id 40 is outside the model's 40 token vocabulary"):
        dec.forward([1, 40])
    with pytest.raises(pp.ProbeError, match="7 tokens is past the model's 6 positions"):
        dec.forward(list(range(7)))
    with pytest.raises(pp.ProbeError, match="no token to run"):
        dec.forward([])


# ---------------------------------------------------------------- byte-level BPE

def _tokenizer(tokenizer_json=False, model=None):
    model = model or fx.memorizer()
    files = fx.model_files(model, tokenizer_json=tokenizer_json, weights=False)
    md = pp.ModelDir(root=None, names=tuple(files))
    md.read_bytes = lambda name: files.get(name)               # a folder held in memory
    return pp.ByteBPE.from_model(md, "qwen2"), model


def _texts(tok, ids):
    return [tok.decode([i], special=True) for i in ids]


@pytest.mark.parametrize("tokenizer_json", [False, True])
def test_bpe_applies_the_merges_and_keeps_special_tokens_whole(tokenizer_json):
    tok, model = _tokenizer(tokenizer_json)
    assert _texts(tok, tok.encode("CSCTF{numpy_probe_42}")) == \
        ["C", "S", "C", "T", "F", "{", "num", "py", "_p", "robe", "_", "4", "2", "}"]
    ids = tok.encode("<|im_start|>user\nhi<|im_end|>")
    assert ids[0] == model["added"]["<|im_start|>"] and ids[-1] == model["added"]["<|im_end|>"]
    assert tok.decode(ids, special=True) == "<|im_start|>user\nhi<|im_end|>" and tok.decode(ids) == "user\nhi"
    assert tok.size == len(model["vocab"]) + len(model["added"])


def test_both_tokenizer_file_layouts_give_the_same_ids():
    text = "The numpy probe: 42 <|im_end|> ok"
    assert _tokenizer(False)[0].encode(text) == _tokenizer(True)[0].encode(text)


def test_bpe_round_trips_unicode_and_whitespace():
    tok, _ = _tokenizer()
    text = "The café costs 12€ — naïve?\n\n  日本語\tok '\x7f' don't"
    assert tok.decode(tok.encode(text)) == text


def test_lower_ranked_merge_wins():
    vocab, added = fx.tiny_vocab([("a", "b"), ("b", "c")])
    first = pp.ByteBPE(vocab, [("a", "b"), ("b", "c")], added, pp.translate_split(pp.GPT2_SPLIT))
    second = pp.ByteBPE(vocab, [("b", "c"), ("a", "b")], added, pp.translate_split(pp.GPT2_SPLIT))
    assert _texts(first, first.encode("abc")) == ["ab", "c"] and _texts(second, second.encode("abc")) == ["a", "bc"]
    assert _texts(first, first.encode("abab")) == ["ab", "ab"]                # every occurrence is merged


def test_split_patterns_follow_unicode_letters_and_numbers():
    qwen, gpt2 = pp.translate_split(pp.QWEN_SPLIT), pp.translate_split(pp.GPT2_SPLIT)
    assert qwen.findall("ab 123") == ["ab", " ", "1", "2", "3"]              # Qwen: one digit at a time
    assert gpt2.findall("ab 123") == ["ab", " 123"]
    assert qwen.findall("le café naïve") == ["le", " café", " naïve"]         # accented letters are letters
    assert qwen.findall("don't x{y} {9}") == ["don", "'t", " x", "{y", "}", " {", "9", "}"]
    assert qwen.findall("日本語٣") == ["日本語", "٣"]                          # CJK letters, an Arabic-Indic digit
    with pytest.raises(pp.ProbeError, match="Unicode class"):
        pp.translate_split(r"\p{Han}+")


def test_nfc_normalizer_is_applied_when_the_tokenizer_names_it():
    with_nfc, _ = _tokenizer(True)                                           # tokenizer.json names NFC
    without, _ = _tokenizer(False)
    assert with_nfc.encode("é") == with_nfc.encode("é")
    assert without.encode("é") != without.encode("é")


def _memory_model(files):
    md = pp.ModelDir(root=None, names=tuple(files))
    md.read_bytes = lambda name: files.get(name)
    return md


def test_tokenizers_that_are_not_byte_level_bpe_need_a_runtime():
    unigram = {"tokenizer.json": json.dumps({"model": {"type": "Unigram", "vocab": []}}).encode()}
    with pytest.raises(pp.NeedsTool, match="'Unigram' model, not byte-level BPE") as err:
        pp.ByteBPE.from_model(_memory_model(unigram))
    assert err.value.tools == ("py:torch", "py:transformers")
    partial = {"vocab.json": json.dumps({"a": 0, "b": 1}).encode(), "merges.txt": b"#version: 0.2\na b\n"}
    with pytest.raises(pp.NeedsTool, match="lacks 254 of the 256 single-byte tokens"):
        pp.ByteBPE.from_model(_memory_model(partial))
    with pytest.raises(pp.NeedsTool, match="no tokenizer.json and no vocab.json"):
        pp.ByteBPE.from_model(_memory_model({"tokenizer.model": b"sentencepiece"}))


# ---------------------------------------------------------------- the probe's own logic, on a scripted model

class ScriptedModel:
    """A stand-in for the model (not for the probe): one token per character, and the next token is
    whatever `rule(text so far)` says, with a stated probability. Token 0 ends the text; token 300 is
    the two-character token "}."."""
    backend, label = "scripted", "scripted model"
    stop_ids = frozenset({0})
    VOCAB = 301

    def __init__(self, rule, chat: bool = False):
        self.rule, self.chat, self.notes, self.seen = rule, chat, [], []

    def encode(self, text):
        return [ord(c) + 1 for c in text]

    def decode(self, ids, special=False):
        return "".join("}." if i == 300 else chr(i - 1) for i in ids if i > 0)

    def has_token(self, text):
        return self.chat

    def _logits(self, state):
        token, p = self.rule(self.decode(state))
        logits = np.full(self.VOCAB, math.log((1 - p) / (self.VOCAB - 1)))
        logits[token] = math.log(p)
        return logits

    def start(self, ids):
        self.seen.append(self.decode(ids))
        return self._logits(list(ids)), list(ids)

    def step(self, token, state):
        state.append(token)
        return self._logits(state), state


def _says(body: str, after: str, p=0.99, end_token=None):
    """rule: once the text contains `after`, say `body` one character at a time, else end the text."""
    def rule(text):
        at = text.rfind(after)
        if at < 0:
            return 0, 0.9
        done = text[at + len(after):]
        if not body.startswith(done) or done == body:
            return 0, 0.9
        if end_token is not None and len(done) == len(body) - 1:
            return end_token, p
        prob = p[len(done)] if isinstance(p, (list, tuple)) else p
        return ord(body[len(done)]) + 1, prob
    return rule


def test_complete_records_each_step_and_stops_at_the_brace():
    model = ScriptedModel(_says("abc}", "X{", p=[0.99, 0.8, 0.97, 0.6]))
    done = pp.complete(model, pp.Prompt("raw", "raw 'X{'", "X{", "X{"), top_k=3)
    assert done.text == "abc}" and done.stopped == "brace"
    assert [s["text"] for s in done.steps] == ["a", "b", "c", "}"]
    assert [round(s["p"], 4) for s in done.steps] == [0.99, 0.8, 0.97, 0.6]
    assert all(len(s["top"]) == 3 and s["top"][0] == (s["text"], s["p"]) for s in done.steps)
    assert all(s["top"][0][1] > s["top"][1][1] for s in done.steps)
    assert done.min_p == pytest.approx(0.6) and done.mean_p == pytest.approx((0.99 + 0.8 + 0.97 + 0.6) / 4)


@pytest.mark.parametrize("probs, memorized", [
    ([0.99, 0.99, 0.99, 0.99], True),
    ([0.99, 0.99, 0.99, 0.45], False),          # one token below MEMORIZED_MIN
    ([0.85, 0.85, 0.85, 0.85], False),          # every token likely, the mean below MEMORIZED_MEAN
    ([0.999, 0.999, 0.61, 0.999], True),
    ([0.999] * 10 + [0.4], False),              # a high mean (0.94) does not excuse one unlikely token
])
def test_memorized_needs_every_token_likely_and_a_high_mean(probs, memorized):
    body = "abcdefghijklmnop"[:len(probs) - 1] + "}"
    done = pp.complete(ScriptedModel(_says(body, "X{", p=probs)), pp.Prompt("raw", "x", "X{", "X{"))
    assert len(done.steps) == len(probs) and done.memorized is memorized


def test_complete_stop_reasons():
    prompt = pp.Prompt("raw", "x", "X{", "X{")
    assert pp.complete(ScriptedModel(_says("abc}", "Y{")), prompt).stopped == "eos"
    long = pp.complete(ScriptedModel(_says("a" * 50 + "}", "X{")), prompt, max_new_tokens=5)
    assert long.stopped == "length" and long.text == "aaaaa" and len(long.steps) == 5
    ticks = iter(range(100))
    cut = pp.complete(ScriptedModel(_says("abcdef}", "X{")), prompt, spent=lambda: next(ticks) >= 2)
    assert cut.stopped == "budget" and cut.text == "abc"
    with pytest.raises(pp.ProbeError, match="encodes to no token"):
        pp.complete(ScriptedModel(_says("a}", "X{")), pp.Prompt("raw", "empty", "", ""))


def test_the_flag_is_the_lead_plus_the_text_up_to_the_first_brace():
    model = ScriptedModel(_says("abc}", "spooky{", end_token=300))              # the last token is "}."
    report = pp.probe(model, FF_SPOOKY)
    assert list(report["flags"]) == ["spooky{abc}"] and report["complete"]
    assert [c.text for c in report["flags"]["spooky{abc}"]] == ["abc}.", "abc}."]
    assert [c.prompt.text for c in report["completions"]] == ["spooky{", "The flag is spooky{"]


def test_a_completion_with_unprintable_characters_is_not_a_flag():
    report = pp.probe(ScriptedModel(_says("a\x01c}", "spooky{")), FF_SPOOKY)
    assert report["flags"] == {} and [c.stopped for c in report["completions"]] == ["brace", "brace"]


def test_with_no_known_lead_a_flag_shaped_completion_is_still_found():
    ff = flagfmt.for_profile(_unknown_profile())
    model = ScriptedModel(_says(" zzz{abc}", "The flag is"))
    report = pp.probe(model, ff)
    assert model.seen == ["The flag is"] and list(report["flags"]) == ["zzz{abc}"]
    assert pp.judge(report["flags"], ff.known)[0] == "candidate"


def test_the_events_own_lead_goes_first_and_the_others_only_when_it_finds_nothing():
    any_lead = ScriptedModel(_says("abc}", "{"))                                # completes every lead the same way
    report = pp.probe(any_lead, FF_CSCTF)
    assert list(report["flags"]) == ["CSCTF{abc}"]
    assert any_lead.seen == ["CSCTF{", "The flag is CSCTF{"]                    # the other leads were never asked
    only_flag = ScriptedModel(_says("abc}", "flag{"))
    report = pp.probe(only_flag, FF_CSCTF)
    assert list(report["flags"]) == ["flag{abc}"] and len(report["flags"]["flag{abc}"]) == 2
    assert only_flag.seen == ["CSCTF{", "The flag is CSCTF{", "chronos{", "The flag is chronos{", "CTF{",
                              "The flag is CTF{", "flag{", "The flag is flag{"]
    stops_at_first = ScriptedModel(_says("abc}", "chronos{"))
    assert list(pp.probe(stops_at_first, FF_CSCTF)["flags"]) == ["chronos{abc}"]
    assert stops_at_first.seen[-1] == "The flag is chronos{"                    # the later leads were never asked


def test_prompt_set_for_a_chat_model_with_a_named_secret():
    prompts = pp.build_prompts(FF_SPOOKY, ScriptedModel(_says("a}", "{"), chat=True), secret="vault key",
                               system="You are a test.")
    assert [(p.kind, p.crib) for p in prompts] == [("raw", "spooky{"), ("raw", "spooky{"), ("chat", "spooky{"),
                                                   ("raw", "spooky{"), ("chat", "spooky{")]
    assert prompts[0].text == "spooky{" and prompts[3].text == "The vault key is spooky{"
    assert prompts[4].text == ("<|im_start|>system\nYou are a test.<|im_end|>\n<|im_start|>user\nWhat is the vault key?"
                               "<|im_end|>\n<|im_start|>assistant\nThe vault key is spooky{")
    no_system = pp.build_prompts(FF_SPOOKY, ScriptedModel(_says("a}", "{"), chat=True))
    assert no_system[2].text.startswith("<|im_start|>user\nWhat is the flag?<|im_end|>")
    plain = pp.build_prompts(FF_SPOOKY, ScriptedModel(_says("a}", "{"), chat=False), secret="vault key")
    assert [p.kind for p in plain] == ["raw", "raw", "raw"]                     # no ChatML tokens: no chat prompts


def test_given_prompts_are_added_and_checked():
    chat = ScriptedModel(_says("a}", "{"), chat=True)
    extra = [{"kind": "raw", "text": "Password: spooky{"}, {"kind": "chat", "text": "Say it.", "prefill": "Sure: "}]
    prompts = pp.build_prompts(FF_SPOOKY, chat, cribs=[], extra=extra)
    assert [(p.kind, p.crib) for p in prompts[-2:]] == [("raw", "spooky{"), ("chat", "")]
    assert prompts[-1].text.endswith("<|im_start|>assistant\nSure: ")
    with pytest.raises(pp.ProbeError, match="option prompts: each item"):
        pp.build_prompts(FF_SPOOKY, chat, extra=[{"kind": "sing", "text": "x"}])
    with pytest.raises(pp.ProbeError, match="no <\\|im_start\\|>/<\\|im_end\\|> tokens"):
        pp.build_prompts(FF_SPOOKY, ScriptedModel(_says("a}", "{")), extra=[{"kind": "chat", "text": "x"}])


def _run(flag_probs: dict):
    """{flag: [per-prompt probability lists]} as probe() would return it."""
    out = {}
    for flag, runs in flag_probs.items():
        for probs in runs:
            done = pp.Completion(pp.Prompt("raw", "x", "x", ""), steps=[{"p": p} for p in probs], flag=flag)
            out.setdefault(flag, []).append(done)
    return out


def test_judge_solved_needs_one_flag_two_prompts_and_memorized_tokens():
    sure = [0.99, 1.0, 0.98]
    assert pp.judge(_run({"f{a}": [sure, sure]})) == ("solved", ("f{a}",), "")
    assert pp.judge(_run({"f{a}": [sure, [0.3, 0.2, 0.4]]}))[0] == "solved"     # memorized in one of them is enough
    status, flags, why = pp.judge(_run({"f{a}": [sure]}))
    assert (status, flags) == ("candidate", ("f{a}",)) and why == "only one prompt reached it"
    status, _flags, why = pp.judge(_run({"f{a}": [[0.4, 0.3], [0.6, 0.2]]}))
    assert status == "candidate" and "memorized-level" in why
    status, _flags, why = pp.judge(_run({"f{a}": [sure, sure]}), known=False)
    assert status == "candidate" and "not known yet" in why
    assert pp.judge({}) == ("none", (), "no completion closes a flag")


def test_judge_orders_competing_flags_by_agreement_then_probability():
    sure, weak = [0.99, 0.99], [0.4, 0.5]
    status, flags, why = pp.judge(_run({"f{one}": [weak], "f{two}": [sure, sure], "f{three}": [sure]}))
    assert status == "candidate" and flags == ("f{two}", "f{three}", "f{one}") and "several different" in why


# ---------------------------------------------------------------- end to end on the synthetic memorizer

def test_solve_reads_the_model_from_inside_the_zip_and_recovers_the_string(tmp_path):
    ch = _zip_challenge(tmp_path)
    result = pp.solve(ch, SPOOKY, budget_s=BUDGET)
    assert result.status == "solved" and result.flags == ("spooky{" + BODY,), result.notes
    assert result.engine == "toolkits.model_prefix_probe"
    assert "numpy backend on dist.zip!model/; 3 prompt(s)" in result.notes
    assert "chat system prompt 'You are a synthetic test model.'" in result.notes
    line = result.evidence[0].detail
    assert "3 of 3 prompt(s) greedy-decode to it" in line and "3 memorized" in line
    assert "'num'(1.000) 'py'(1.000) '_p'(1.000) 'robe'(1.000) '_'(1.000) '4'(1.000) '2'(1.000) '}'(1.000)" in line
    assert sorted(p.name for p in (ch / "files").iterdir()) == ["dist.zip"]     # read in place, nothing extracted
    assert SolverResult.from_json(result.to_json()) == result


def test_solve_on_a_folder_with_tokenizer_json_and_float32_weights(tmp_path):
    result = pp.solve(_folder_challenge(tmp_path, tokenizer_json=True, dtype="float32"), SPOOKY, budget_s=BUDGET)
    assert result.status == "solved" and result.flags == ("spooky{" + BODY,)
    assert "numpy backend on model; 3 prompt(s)" in result.notes


def test_only_the_events_own_spelling_is_returned_when_several_leads_are_accepted(tmp_path):
    result = pp.solve(_zip_challenge(tmp_path), CSCTF, budget_s=BUDGET, secret="vault key")
    assert result.status == "solved" and result.flags == ("CSCTF{" + BODY,)
    assert "5 prompt(s)" in result.notes                                       # 3 + the two that name the secret


def test_a_string_the_model_only_weakly_prefers_is_a_candidate(tmp_path):
    result = pp.solve(_zip_challenge(tmp_path, fx.memorizer(strength=0.1)), SPOOKY, budget_s=BUDGET)
    assert result.status == "candidate" and result.flags == ("spooky{" + BODY,)
    assert "no prompt decodes it with memorized-level token probabilities" in result.notes
    assert "0 memorized" in result.evidence[0].detail


def test_unknown_flag_format_finds_nothing_to_complete(tmp_path):
    """With no known lead the prompts end in a word, not a brace: this memorizer says nothing."""
    result = pp.solve(_zip_challenge(tmp_path), _unknown_profile(), budget_s=BUDGET)
    assert result.status == "none" and "no completion closes a flag" in result.notes
    assert "raw 'The flag is' -> '' (eos)" in result.notes


def test_a_step_clock_budget_stops_the_probe_and_is_reported(tmp_path):
    ticks = iter(range(10_000))
    result = pp.solve(_zip_challenge(tmp_path), SPOOKY, budget_s=3, clock=lambda: float(next(ticks)))
    assert result.status in ("none", "candidate") and "CPU budget of 3 s spent" in result.notes
    assert result.status != "solved"


# ---------------------------------------------------------------- finding the model; what cannot be run

def test_no_model_is_none_and_a_config_that_is_not_a_models_is_ignored(tmp_path):
    ch = tmp_path / "web"
    (ch / "files").mkdir(parents=True)
    (ch / "files" / "config.json").write_text(json.dumps({"debug": True, "port": 8080}))
    result = pp.solve(ch, SPOOKY)
    assert result.status == "none" and "no Hugging Face model folder" in result.notes and "model_path" in result.notes


def test_weights_that_were_not_shipped_block_with_the_human_step(tmp_path):
    ch = tmp_path / "ch"
    fx.write_folder(ch / "files" / "model", fx.model_files(fx.memorizer(), weights=False))
    result = pp.solve(ch, SPOOKY)
    assert result.status == "blocked"
    assert "no *.safetensors weights: fetching them is a human step; then pass --opt model_path=" in result.notes


def test_pickled_weights_are_refused_by_name(tmp_path):
    ch = tmp_path / "ch"
    folder = fx.write_folder(ch / "files" / "model", fx.model_files(fx.memorizer(), weights=False))
    (folder / "pytorch_model.bin").write_bytes(b"\x80\x04N.")
    result = pp.solve(ch, SPOOKY)
    assert result.status == "blocked" and "pytorch_model.bin, a pickle" in result.notes and "never loaded" in result.notes


def test_model_path_points_at_weights_fetched_by_hand(tmp_path):
    elsewhere = fx.write_folder(tmp_path / "downloads" / "the-model", fx.model_files(fx.memorizer()))
    ch = tmp_path / "ch"
    (ch / "files").mkdir(parents=True)
    by_folder = pp.solve(ch, SPOOKY, model_path=str(elsewhere), budget_s=BUDGET)
    assert by_folder.status == "solved" and "numpy backend on the-model" in by_folder.notes
    z = fx.write_zip(tmp_path / "downloads" / "m.zip", fx.model_files(fx.memorizer()), prefix="")
    by_zip = pp.solve(ch, SPOOKY, model_path=str(z), budget_s=BUDGET)
    assert by_zip.status == "solved" and "numpy backend on m.zip" in by_zip.notes
    missing = pp.solve(ch, SPOOKY, model_path=str(tmp_path / "nope"))
    assert missing.status == "blocked" and "does not exist" in missing.notes
    empty = pp.solve(ch, SPOOKY, model_path=str(ch))
    assert empty.status == "blocked" and "holds no config.json" in empty.notes


def test_a_symlinked_model_in_the_challenge_is_not_followed(tmp_path):
    """A link in the challenge folder could point anywhere on the host: discovery does not follow it.
    A model_path given by the operator may be links (a Hugging Face cache snapshot) and is followed."""
    outside = fx.write_folder(tmp_path / "elsewhere" / "model", fx.model_files(fx.memorizer()))
    ch = tmp_path / "linked"
    (ch / "files" / "model").mkdir(parents=True)
    for p in outside.iterdir():
        (ch / "files" / "model" / p.name).symlink_to(p)
    assert pp.find_models(ch) == []
    (ch / "files" / "model" / "config.json").unlink()                         # a real config, linked weights
    (ch / "files" / "model" / "config.json").write_bytes((outside / "config.json").read_bytes())
    models = pp.find_models(ch)
    assert len(models) == 1 and not any(n.endswith(".safetensors") for n in models[0].names)
    by_path = pp.find_models(ch, model_path=str(ch / "files" / "model"))
    assert any(n.endswith(".safetensors") for n in by_path[0].names)
    zipped = _zip_challenge(tmp_path / "z")
    linked = tmp_path / "linked-zip"
    (linked / "files").mkdir(parents=True)
    (linked / "files" / "dist.zip").symlink_to(zipped / "files" / "dist.zip")   # a zip outside, by a link
    assert pp.find_models(linked) == [] and len(pp.find_models(zipped)) == 1


def test_an_extracted_copy_and_its_zip_are_one_model(tmp_path):
    ch = _zip_challenge(tmp_path)
    fx.write_folder(ch / "files" / "extracted" / "model", fx.model_files(fx.memorizer()))
    fx.write_folder(ch / "recon" / "engines" / "model", fx.model_files(fx.memorizer()))
    models = pp.find_models(ch)
    assert [m.label for m in models] == ["model"] and models[0].root == ch / "files" / "extracted" / "model"


def test_an_architecture_the_numpy_runner_does_not_know_needs_a_runtime(tmp_path, monkeypatch):
    ch = _folder_challenge(tmp_path, fx.memorizer(model_type="gpt2"))
    result = pp.solve(ch, SPOOKY, backend="numpy")
    assert result.status == "blocked"
    assert result.notes.startswith("needs_tool py:torch, py:transformers: model: model type 'gpt2' is not one")
    monkeypatch.setitem(sys.modules, "torch", None)                             # no torch on this host
    monkeypatch.setitem(sys.modules, "transformers", None)
    auto = pp.solve(ch, SPOOKY)
    assert auto.status == "blocked" and "needs_tool py:torch, py:transformers" in auto.notes
    assert "the transformers backend cannot stand in" in auto.notes and "not installed (torch)" in auto.notes


def test_same_layout_under_another_model_type_runs_only_on_request(tmp_path):
    ch = _folder_challenge(tmp_path, fx.memorizer(model_type="llama"))
    assert pp.solve(ch, SPOOKY, backend="numpy").status == "blocked"
    result = pp.solve(ch, SPOOKY, backend="numpy", arch="llama-like", budget_s=BUDGET)
    assert result.status == "solved" and result.flags == ("spooky{" + BODY,)
    assert "model type 'llama' run on the numpy decoder by request" in result.notes and "unchecked" in result.notes


def test_weights_too_large_for_the_host_block_with_the_size(tmp_path):
    result = pp.solve(_zip_challenge(tmp_path), SPOOKY, max_ram_gb=0.0001)
    assert result.status == "blocked" and "GiB as float32, over the 0.0 GiB this host allows" in result.notes


def test_running_out_of_memory_is_a_named_block_not_a_crash(tmp_path, monkeypatch):
    def no_room(self, names=None, astype=None):
        raise MemoryError
    monkeypatch.setattr(pp.tensors_mod.SafetensorsFile, "read", no_room)        # the host cannot hold the weights
    result = pp.solve(_zip_challenge(tmp_path), SPOOKY)
    assert result.status == "blocked" and "ran out of memory" in result.notes and "dist.zip!model/" in result.notes


def test_a_decoder_tensor_missing_from_the_weights_is_named(tmp_path):
    model = fx.memorizer()
    del model["weights"]["model.layers.1.mlp.down_proj.weight"]
    result = pp.solve(_folder_challenge(tmp_path, model), SPOOKY, backend="numpy")
    assert result.status == "blocked"
    assert "lack 1 tensor(s) of the decoder layout" in result.notes and "model.layers.1.mlp.down_proj.weight" in result.notes


def test_tensors_outside_the_layout_are_reported_not_used(tmp_path):
    model = fx.memorizer()
    model["weights"]["secret.note"] = np.arange(8, dtype=np.float32)
    result = pp.solve(_folder_challenge(tmp_path, model), SPOOKY, budget_s=BUDGET)
    assert result.status == "solved" and "1 tensor(s) outside the decoder layout were not used: secret.note" in result.notes


def test_weights_split_over_two_shards_are_joined_and_a_repeat_is_refused(tmp_path):
    model = fx.memorizer()
    files = fx.model_files(model)
    del files["model.safetensors"]
    names = sorted(model["weights"])
    half = {k: model["weights"][k].astype("float16") for k in names[:len(names) // 2]}
    rest = {k: model["weights"][k].astype("float16") for k in names[len(names) // 2:]}
    files["model-00001-of-00002.safetensors"] = fx.safetensors_bytes(half)
    files["model-00002-of-00002.safetensors"] = fx.safetensors_bytes(rest)
    ch = tmp_path / "shards"
    folder = fx.write_folder(ch / "files" / "model", files)
    result = pp.solve(ch, SPOOKY, budget_s=BUDGET)
    assert result.status == "solved" and result.flags == ("spooky{" + BODY,)
    (folder / "model-00003-of-00002.safetensors").write_bytes(fx.safetensors_bytes({names[0]: half[names[0]]}))
    twice = pp.solve(ch, SPOOKY)
    assert twice.status == "blocked" and f"tensor {names[0]!r} is in two weight shards" in twice.notes


def test_special_tokens_listed_only_in_tokenizer_config_are_found(tmp_path):
    model = fx.memorizer()
    files = fx.model_files(model, weights=False)
    del files["added_tokens.json"]
    files["tokenizer_config.json"] = json.dumps({"tokenizer_class": "Qwen2Tokenizer", "added_tokens_decoder": {
        str(i): {"content": text, "special": True} for text, i in model["added"].items()}}).encode()
    tok = pp.ByteBPE.from_model(_memory_model(files), "qwen2")
    assert tok.encode("<|im_end|>") == [model["added"]["<|im_end|>"]]
    del files["tokenizer_config.json"]
    bare = pp.ByteBPE.from_model(_memory_model(files), "qwen2")
    assert len(bare.encode("<|im_end|>")) > 1                                   # without the list it is plain text


def test_the_default_memory_limit_comes_from_the_host(tmp_path, monkeypatch):
    monkeypatch.setattr(pp, "physical_ram", lambda: 100_000)                    # a host with 100 kB of RAM
    small = pp.solve(_zip_challenge(tmp_path), SPOOKY)
    assert small.status == "blocked" and "this host allows the numpy runner" in small.notes
    monkeypatch.setattr(pp, "physical_ram", lambda: None)                       # unknown: a fixed limit, said so
    unknown = pp.solve(_zip_challenge(tmp_path / "b"), SPOOKY, budget_s=BUDGET)
    assert unknown.status == "solved" and "the host's RAM could not be read" in unknown.notes
    assert "held to 8.0 GiB of float32 weights" in unknown.notes
    monkeypatch.setattr(pp, "UNKNOWN_RAM_LIMIT", 100_000)                       # the fixed limit is applied
    over = pp.solve(_zip_challenge(tmp_path / "c"), SPOOKY)
    assert over.status == "blocked" and "this host allows the numpy runner" in over.notes
    given = pp.solve(_zip_challenge(tmp_path / "d"), SPOOKY, budget_s=BUDGET, max_ram_gb=1)
    assert given.status == "solved" and "could not be read" not in given.notes  # a given limit needs no note


def test_a_tokenizer_with_more_ids_than_the_model_embeds_is_refused(tmp_path):
    model = fx.memorizer()
    model["added"]["<|extra|>"] = max(model["added"].values()) + 500
    result = pp.solve(_folder_challenge(tmp_path, model), SPOOKY, backend="numpy")
    assert result.status == "blocked" and "but the model embeds" in result.notes


@pytest.mark.parametrize("opts, message", [
    ({"backend": "onnx"}, "option backend='onnx' is not auto, numpy or transformers"),
    ({"arch": "gpt2"}, "option arch='gpt2' is not llama-like"),
    ({"budget_s": -1}, "option budget_s=-1 must be positive"),
    ({"max_new_tokens": "many"}, "option max_new_tokens='many' is not a number"),
    ({"top_k": True}, "option top_k=True is not a number"),
    ({"secret": ""}, "option secret must be a short phrase"),
    ({"prompts": "raw"}, "option prompts must be a list"),
    ({"system": 5}, "option system must be text"),
])
def test_a_wrong_option_blocks_with_its_name(tmp_path, opts, message):
    result = pp.solve(_zip_challenge(tmp_path), SPOOKY, **opts)
    assert result.status == "blocked" and message in result.notes


def test_default_system_prompt_is_read_as_text_never_rendered():
    files = fx.model_files(fx.memorizer(), weights=False)
    assert pp.default_system(_memory_model(files)) == "You are a synthetic test model."
    only_vars = dict(files, **{"chat_template.jinja": b"{{- '<|im_start|>system\\n' + messages[0]['content'] + '<|im_end|>\\n' }}"})
    assert pp.default_system(_memory_model(only_vars)) is None
    in_config = {k: v for k, v in files.items() if k != "chat_template.jinja"}
    in_config["tokenizer_config.json"] = json.dumps(
        {"chat_template": "{{ '<|im_start|>system\\nBe terse.<|im_end|>\\n' }}"}).encode()
    assert pp.default_system(_memory_model(in_config)) == "Be terse."
    assert pp.default_system(_memory_model({"config.json": b"{}"})) is None and pp.default_system(None) is None


# ---------------------------------------------------------------- the transformers backend, against stand-in libraries

class _FakeLogits:
    def __init__(self, row):
        self.row = row

    def __getitem__(self, key):
        assert key == (0, -1)
        return self

    def float(self):
        return self

    def cpu(self):
        return self

    def numpy(self):
        return self.row


def _fake_libraries(calls):
    """Stand-ins for torch and transformers: a character-level tokenizer and a model that says
    `abc}` after an opening brace. They record how they were loaded."""
    torch = types.ModuleType("torch")
    torch.long = "long"

    class _NoGrad:
        def __enter__(self):
            calls.append("no_grad")

        def __exit__(self, *exc):
            return False

    torch.no_grad = _NoGrad
    torch.tensor = lambda data, dtype=None: {"data": data, "dtype": dtype}

    class Tokenizer:
        unk_token_id = 0

        def encode(self, text, add_special_tokens=True):
            assert add_special_tokens is False
            return [ord(c) + 1 for c in text]

        def decode(self, ids, skip_special_tokens=False):
            return "".join(chr(i - 1) for i in ids if i > 1)

        def convert_tokens_to_ids(self, text):
            return 1 if text == "</s>" else 0

    class Model:
        def eval(self):
            calls.append("eval")

        def __call__(self, input_ids=None, past_key_values=None, use_cache=None):
            assert input_ids["dtype"] == "long" and use_cache is True and len(input_ids["data"]) == 1
            seen = (past_key_values or []) + list(input_ids["data"][0])
            text = "".join(chr(i - 1) for i in seen)
            body, at = "abc}", text.rfind("{")
            said = text[at + 1:] if at >= 0 else None
            nxt = ord(body[len(said)]) + 1 if said is not None and body.startswith(said) and said != body else 1
            row = np.full(200, -20.0)
            row[nxt] = 5.0
            return types.SimpleNamespace(logits=_FakeLogits(row), past_key_values=seen)

    transformers = types.ModuleType("transformers")

    def loader(kind, made):
        def from_pretrained(path, **kw):
            calls.append((kind, path, kw))
            return made()
        return types.SimpleNamespace(from_pretrained=from_pretrained)

    transformers.AutoTokenizer = loader("tokenizer", Tokenizer)
    transformers.AutoModelForCausalLM = loader("model", Model)
    return torch, transformers


def test_transformers_backend_loads_locally_safely_and_drives_the_probe(tmp_path, monkeypatch):
    calls = []
    torch, transformers = _fake_libraries(calls)
    monkeypatch.setitem(sys.modules, "torch", torch)
    monkeypatch.setitem(sys.modules, "transformers", transformers)
    monkeypatch.setenv("HF_HUB_OFFLINE", "0")                                   # the operator's own setting
    monkeypatch.delenv("TRANSFORMERS_OFFLINE", raising=False)
    at_load = []
    real = transformers.AutoModelForCausalLM.from_pretrained
    transformers.AutoModelForCausalLM.from_pretrained = lambda path, **kw: (
        at_load.append({k: os.environ.get(k) for k in pp.OFFLINE_ENV}), real(path, **kw))[1]
    ch = _folder_challenge(tmp_path, fx.memorizer(model_type="gpt2"))
    result = pp.solve(ch, SPOOKY, budget_s=BUDGET)                              # auto: numpy declines, transformers runs
    assert result.status == "solved" and result.flags == ("spooky{abc}",), result.notes
    assert "transformers backend on model" in result.notes and "numpy backend not used" in result.notes
    loads = [c for c in calls if isinstance(c, tuple)]
    folder = str(ch / "files" / "model")
    assert loads[0] == ("tokenizer", folder, {"local_files_only": True, "trust_remote_code": False})
    assert loads[1] == ("model", folder, {"local_files_only": True, "trust_remote_code": False, "use_safetensors": True})
    assert "eval" in calls and "no_grad" in calls
    assert at_load == [{"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}]  # offline while loading ...
    assert os.environ["HF_HUB_OFFLINE"] == "0" and "TRANSFORMERS_OFFLINE" not in os.environ   # ... put back after


def test_the_offline_switches_are_set_before_the_libraries_are_imported(monkeypatch, tmp_path):
    """huggingface_hub reads HF_HUB_OFFLINE when it is first imported, so the switch has to be in the
    environment at import time. Stand-in modules record the environment their import runs under."""
    import importlib.abc
    import importlib.util
    torch, transformers = _fake_libraries([])
    made, seen = {"torch": torch, "transformers": transformers}, {}

    class Finder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, name, path=None, target=None):
            return importlib.util.spec_from_loader(name, self) if name in made else None

        def create_module(self, spec):
            return made[spec.name]

        def exec_module(self, module):
            seen[module.__name__] = {k: os.environ.get(k) for k in pp.OFFLINE_ENV}

    for name in made:                                                           # absent, so the import runs
        monkeypatch.setitem(sys.modules, name, None)
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(sys, "meta_path", [Finder()] + sys.meta_path)
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    monkeypatch.delenv("TRANSFORMERS_OFFLINE", raising=False)
    model = pp.find_models(_folder_challenge(tmp_path, fx.memorizer(model_type="gpt2")))[0]
    pp.load_transformers_runner(model)
    on = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
    assert seen == {"torch": on, "transformers": on}
    assert not any(k in os.environ for k in pp.OFFLINE_ENV)                     # restored: they were unset


def test_transformers_backend_refuses_a_zip_and_pickled_weights(tmp_path, monkeypatch):
    torch, transformers = _fake_libraries([])
    monkeypatch.setitem(sys.modules, "torch", torch)
    monkeypatch.setitem(sys.modules, "transformers", transformers)
    zipped = pp.solve(_zip_challenge(tmp_path), SPOOKY, backend="transformers")
    assert zipped.status == "blocked" and "reads a folder; extract the model from the zip" in zipped.notes
    ch = tmp_path / "bin"
    folder = fx.write_folder(ch / "files" / "model", fx.model_files(fx.memorizer(), weights=False))
    (folder / "pytorch_model.bin").write_bytes(b"\x80\x04N.")
    pickled = pp.solve(ch, SPOOKY, backend="transformers")
    assert pickled.status == "blocked" and "pickled weights are never loaded" in pickled.notes


@pytest.mark.needs_tool("py:torch", "py:transformers")
def test_numpy_decoder_matches_transformers_on_a_random_qwen2(tmp_path):
    """With the real libraries installed (they are not in requirements): the numpy decoder and the
    Hugging Face Qwen2 implementation agree on a small random model's logits."""
    import torch
    import transformers
    torch.manual_seed(0)
    config = transformers.Qwen2Config(vocab_size=64, hidden_size=32, intermediate_size=48, num_hidden_layers=2,
                                      num_attention_heads=4, num_key_value_heads=2, max_position_embeddings=64,
                                      tie_word_embeddings=True)
    model = transformers.Qwen2ForCausalLM(config).eval()
    model.save_pretrained(tmp_path / "m", safe_serialization=True)
    files = pp.ModelDir(root=tmp_path / "m", names=tuple(p.name for p in (tmp_path / "m").iterdir()))
    weights = {}
    for sf in files.safetensors():
        weights.update(sf.read(astype="float32"))
    ids = [3, 17, 5, 5, 39, 0, 21, 8]
    with torch.no_grad():
        want = model(input_ids=torch.tensor([ids])).logits[0].numpy()
    got = pp.NumpyDecoder(json.loads((tmp_path / "m" / "config.json").read_text()), weights).forward(ids)
    assert np.abs(got - want).max() < 1e-3


# ---------------------------------------------------------------- wiring: manifest, router, runner

def test_manifest_is_heavy_and_not_an_intake_engine():
    from ctf.engines import manifest
    m = {x.id: x for x in manifest.discover(REPO)}["toolkits.model_prefix_probe"]
    assert m.entry_raw == "solvers.toolkits.model_prefix_probe:solve" and m.cost_class == "heavy"
    assert m.intake is None and m.needs_tools == ("py:numpy",)


def test_router_sends_white_box_model_briefs_here(tmp_path):
    from ctf.engines import router
    brief = ("You have been given a chat model that knows the vault key. Recover the exact flag string "
             "memorized by the model. You have white-box access.")
    assert router.route("ML", brief)[0].manifest.id == "toolkits.model_prefix_probe"
    assert "toolkits.model_prefix_probe" in [h.manifest.id for h in router.route("AI/ML (white-box model)", brief)]
    folder = fx.write_folder(tmp_path / "files" / "model", fx.model_files(fx.memorizer(), weights=False))
    assert "toolkits.model_prefix_probe" in [h.manifest.id for h in router.route("misc", "a strange archive", folder)]
    assert "toolkits.model_prefix_probe" not in [h.manifest.id for h in router.route("misc", "a strange archive")]


def test_ctf_run_prints_the_solver_result(tmp_path):
    from ctf.engines import runner
    ch = _zip_challenge(tmp_path)
    cmd = runner.command("toolkits.model_prefix_probe", [str(ch), "--event", "spooky", "--opt", "secret=vault key"],
                         record=False)
    cp = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, env={**os.environ, "CTF_WORKDIR": str(tmp_path)})
    assert cp.returncode == 0, cp.stderr
    result = SolverResult.from_json(cp.stdout.strip().splitlines()[-1])
    assert result.status == "solved" and result.flags == ("spooky{" + BODY,) and "5 prompt(s)" in result.notes


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
