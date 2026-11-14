"""B-112, the offline half: the Discord snapshot, the ingest paths and the analyzer (ctf/discordrecon.py),
plus the [discord] profile table. Every server text is written here; nothing is read from a real server."""
from __future__ import annotations

import base64
import codecs
import datetime as dt
import json
import stat

import pytest

import discord_fake
from ctf import discordrecon as dr
from ctf import event, eventscaffold, humanops, ledger

P = discord_fake.profile()

RULES = """**Server rules**
Flag format: RECON{Th4nk_Y0u_F0r_R34d1ng!!}
- Respect everyone
- Every team has four players
- Cheating is forbidden
- Only attack challenge hosts
- No flag sharing
- { is a brace
- Smile
- m ore fun
- 4 hours of sleep
- r est
- t ime
- _ is an underscore
- B e nice
- 0 tolerance
- y es
- ! important
- } done
"""
ACROSTIC = "RECON{Sm4rt_B0y!}"
DECOY = "RECON{Th4nk_Y0u_F0r_R34d1ng!!}"


def snap_of(*items):
    s = dr.Snapshot()
    s.add(items)
    return s


def by_value(rep):
    return {c.value: c for c in rep.candidates}


# ------------------------------------------------------------------------------- acrostics and decoys

def test_first_character_of_each_bullet_spells_the_flag_and_outranks_the_format_example():
    rep = dr.analyze(snap_of(*dr.ingest_text(RULES, where="#rules", kind="rules")), P)
    got = by_value(rep)
    assert got[ACROSTIC].kind == "acrostic-flag" and got[ACROSTIC].in_format
    assert "first character of each" in got[ACROSTIC].how and got[ACROSTIC].where == "#rules"
    assert got[DECOY].kind == "decoy-flag" and "format example" in got[DECOY].how
    assert rep.candidates[0].value == ACROSTIC and rep.candidates[-1].value == DECOY
    assert rep.flags() == [ACROSTIC]                       # the decoy is not offered as a flag
    assert rep.flags(decoys=True) == [ACROSTIC, DECOY]
    # exactly one acrostic flag: the "_" bullet is read as written, not skipped as markup
    assert [c.value for c in rep.candidates if c.kind == "acrostic-flag"] == [ACROSTIC]


def test_an_acrostic_needs_every_bullet_in_order():
    lines = RULES.split("\n")
    lines.remove("- Smile")
    rep = dr.analyze(snap_of(*dr.ingest_text("\n".join(lines), where="#rules", kind="rules")), P)
    assert ACROSTIC not in by_value(rep)
    assert by_value(rep)["RECON{m4rt_B0y!}"].kind == "acrostic-flag"   # what the bullets now spell


def test_bold_bullets_numbered_lists_and_emoji_bullets_are_read_through():
    bold = "\n".join(f"- **{w}**" for w in ["Rope", "Eel", "Cod", "Oar", "Net", "{x", "Ahoy", "}"])
    numbered = "\n".join(f"{n}. {w}" for n, w in enumerate(["Rope", "Eel", "Cod", "Oar", "Net", "{x", "Bow", "}"], 1))
    emoji = "\n".join(f"\U0001F539 {w}" for w in ["Rope", "Eel", "Cod", "Oar", "Net", "{x", "Cat", "}"])
    rep = dr.analyze(snap_of(dr.Item("rules", "#a", bold), dr.Item("rules", "#b", numbered),
                             dr.Item("rules", "#c", emoji)), P)
    got = by_value(rep)
    assert got["RECON{A}"].where == "#a" and "markup skipped" in got["RECON{A}"].how
    assert got["RECON{B}"].where == "#b" and "markup" not in got["RECON{B}"].how
    assert got["RECON{C}"].where == "#c"
    assert all(got[v].kind == "acrostic-flag" for v in ("RECON{A}", "RECON{B}", "RECON{C}"))


def test_last_characters_and_bullets_among_prose_are_read():
    last = "\n".join(["cleaR", "ablE", "arC", "hellO", "opeN", "is {", "a Z", "ok }"])
    # every bullet is followed by a line of prose, so only the bullets spell it
    mixed = "\n".join(f"* {w}\nsee above" for w in ["Rope", "Eel", "Cod", "Oar", "Net", "{x", "Q", "}"])
    got = by_value(dr.analyze(snap_of(dr.Item("message", "#a", last), dr.Item("message", "#b", mixed)), P))
    assert "last character of each line" in got["RECON{Z}"].how
    assert "first character of each bullet" in got["RECON{Q}"].how


def test_an_acrostic_runs_across_the_messages_of_one_channel_in_posting_order():
    words = ["Rope", "Eel", "Cod", "Oar", "Net", "{ brace", "Kelp", "} end"]
    items = [dr.Item("message", "#rules", w, seq=n) for n, w in enumerate(words, 1)]
    other = [dr.Item("message", "#chat", w, seq=n) for n, w in enumerate(["Zed", "Yak"], 1)]
    rep = dr.analyze(snap_of(*reversed(items), *other), P)             # stored out of order
    c = by_value(rep)["RECON{K}"]
    assert c.kind == "acrostic-flag" and "the messages of #rules" in c.how
    # the same messages spread over two channels spell nothing
    split = [dr.Item("message", "#a" if n % 2 else "#b", w, seq=n) for n, w in enumerate(words, 1)]
    assert not [c for c in dr.analyze(snap_of(*split), P).candidates if c.kind == "acrostic-flag"]


def test_a_non_flag_acrostic_is_a_reading_not_a_candidate_and_prefixed_ones_come_first():
    plain = "\n".join(["Sail", "Hull", "Oar", "Reef", "Eel"])
    prefixed = "\n".join(["Rope", "Eel", "Cod", "Oar", "Net", "Wave", "Isle", "Sea", "Hull"])
    rep = dr.analyze(snap_of(dr.Item("message", "#a", plain), dr.Item("message", "#b", prefixed)), P)
    assert not rep.candidates
    assert [(r.text, r.prefixed) for r in rep.readings] == [("RECONWISH", True), ("SHORE", False)]
    assert rep.readings[0].where == "#b"
    short = dr.analyze(snap_of(dr.Item("message", "#a", "Sail\nHull\nOar")), P)
    assert not short.readings                               # under MIN_READING_UNITS


def test_decoys_placeholder_body_and_brief_quoted_values():
    s = snap_of(dr.Item("pin", "#general", "the prize: RECON{...}"),
                dr.Item("message", "#general", "found it RECON{your_flag_here} lol"),
                dr.Item("channel-topic", "#watch", "RECON{qu0ted_in_brief}"),
                dr.Item("channel-topic", "#real", "RECON{r34l_0n3}"),
                dr.Item("message", "#help", "Flags look like this:\nRECON{n3xt_l1ne}"))
    rep = dr.analyze(s, P, brief="Submit like RECON{qu0ted_in_brief}")
    got = by_value(rep)
    assert got["RECON{...}"].kind == "decoy-flag" and "placeholder" in got["RECON{...}"].how
    assert got["RECON{your_flag_here}"].kind == "decoy-flag"
    assert got["RECON{qu0ted_in_brief}"].kind == "decoy-flag" and "brief" in got["RECON{qu0ted_in_brief}"].how
    assert got["RECON{n3xt_l1ne}"].kind == "decoy-flag"     # the cue sits on the line above
    assert got["RECON{r34l_0n3}"].kind == "flag"
    assert rep.flags() == ["RECON{r34l_0n3}"]
    # without the brief the quoted one is an ordinary literal flag
    assert by_value(dr.analyze(s, P))["RECON{qu0ted_in_brief}"].kind == "flag"


def test_a_format_cue_after_the_flag_on_the_same_line_makes_it_a_decoy():
    s = snap_of(dr.Item("pin", "#rules", "RECON{s4mpl3_0nly} is the format"),
                dr.Item("pin", "#news", "RECON{w1nn3r_0n3} goes to the fastest team"),
                dr.Item("pin", "#next", "RECON{n0t_th1s_l1ne}\nthat was the format, not a flag"))
    got = by_value(dr.analyze(s, P))
    assert got["RECON{s4mpl3_0nly}"].kind == "decoy-flag" and "'format'" in got["RECON{s4mpl3_0nly}"].how
    assert got["RECON{w1nn3r_0n3}"].kind == "flag"
    assert got["RECON{n0t_th1s_l1ne}"].kind == "flag"       # only the rest of its own line counts


# ------------------------------------------------------------------------------- other candidate kinds

def test_recognition_words_plain_quoted_and_german_and_wrapped_form():
    s = snap_of(dr.Item("channel-topic", "#watch", "The watch is broadcasting. Recognition word: **halyard**"),
                dr.Item("bot-status", "bot Watch", "password is mizzenmast today"),
                dr.Item("pin", "#de", "Das Kennwort lautet Leuchtturm."),
                dr.Item("message", "#x", "code-word = `bowline`"))
    got = by_value(dr.analyze(s, P))
    assert got["halyard"].kind == "recognition" and got["halyard"].wrapped == "RECON{halyard}"
    assert "(quoted)" in got["halyard"].how and got["halyard"].where == "#watch"
    assert got["mizzenmast today"].kind == "recognition" and got["mizzenmast today"].wrapped is None
    assert got["Leuchtturm"].kind == "recognition"
    assert got["bowline"].kind == "recognition"
    assert not any(c.in_format for c in got.values())


def test_prose_about_a_flag_or_password_is_not_a_recognition_word():
    s = snap_of(dr.Item("message", "#a", "the flag is hidden somewhere in this server"),
                dr.Item("message", "#b", "your password is not shared with anyone"),
                dr.Item("message", "#c", "flags are fun"),
                dr.Item("channel-name", "#password-is-swordfish", "password is swordfish"))   # a name, not text
    assert dr.analyze(s, P).candidates == []


def test_a_flag_word_outside_the_format_scores_below_a_recognition_word():
    s = snap_of(dr.Item("message", "#a", "flag: seahorse"), dr.Item("message", "#b", "code word: seagull"))
    got = by_value(dr.analyze(s, P))
    assert got["seahorse"].score == dr.FLAG_WORD_SCORE < got["seagull"].score == dr.SCORES["recognition"]


def test_encoded_flags_are_decoded_strict_above_loose_and_decode_can_be_turned_off():
    b64 = base64.b64encode(b"RECON{b64_in_a_topic}").decode()
    rot = codecs.encode("RECON{r0t_thirteen}", "rot13")
    s = snap_of(dr.Item("channel-topic", "#a", f"nothing to see {b64} move along"),
                dr.Item("channel-topic", "#b", rot))
    rep = dr.analyze(s, P)
    got = by_value(rep)
    assert got["RECON{b64_in_a_topic}"].kind == "decoded-flag" and got["RECON{b64_in_a_topic}"].score == 85
    assert "b64" in got["RECON{b64_in_a_topic}"].how
    assert got["RECON{r0t_thirteen}"].score == dr.LOOSE_DECODE_SCORE and "loose" in got["RECON{r0t_thirteen}"].how
    assert rep.candidates[0].value == "RECON{b64_in_a_topic}"
    assert dr.analyze(s, P, decode=False).candidates == []


def test_hidden_tag_characters_spoilers_and_zero_width_runs():
    tagged = "nothing here" + "".join(chr(0xE0000 + ord(c)) for c in "RECON{t4g_ch4rs}")
    other = "plain" + "".join(chr(0xE0000 + ord(c)) for c in "psst")
    s = snap_of(dr.Item("member-about", "member Author", tagged),
                dr.Item("member-about", "member Other", other),
                dr.Item("message", "#a", "look ||beneath the tarp|| here"),
                dr.Item("message", "#b", "a ||RECON{sp01ler_fl4g}|| b"),
                dr.Item("message", "#c", "x" + "​‌" * 6 + "y"))
    rep = dr.analyze(s, P)
    got = by_value(rep)
    assert got["RECON{t4g_ch4rs}"].kind == "hidden-flag" and got["RECON{t4g_ch4rs}"].where == "member Author"
    assert got["beneath the tarp"].kind == "spoiler"
    assert got["RECON{sp01ler_fl4g}"].kind == "flag"        # a flag inside a spoiler is a flag, listed once
    assert len(rep.candidates) == 3
    assert any("member Other" in n and "'psst'" in n for n in rep.notes)
    assert any("#c" in n and "12 zero-width" in n for n in rep.notes)


def test_zero_width_runs_are_noted_from_eight_characters():
    s = snap_of(dr.Item("message", "#seven", "x" + "\u200b" * 7 + "y"),
                dr.Item("message", "#eight", "x" + "\u200c" * 8 + "y"))
    notes = dr.analyze(s, P).notes
    assert any("#eight" in n and "8 zero-width" in n for n in notes)
    assert not any("#seven" in n for n in notes)


def test_tag_characters_spell_spaces_too():
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "hi there")
    rep = dr.analyze(snap_of(dr.Item("member-about", "member Spacer", "plain" + hidden)), P)
    assert any("member Spacer" in n and "8 invisible tag character(s) spell 'hi there'" in n for n in rep.notes)


def test_braceless_names_only_in_name_kinds_and_only_with_a_tail():
    s = snap_of(dr.Item("emoji", "emoji", "RECONwish_granted"), dr.Item("role", "roles", "recon-crew"),
                dr.Item("emoji", "emoji", "RECON"), dr.Item("emoji", "emoji", "anchor"),
                dr.Item("sticker", "stickers", "REC"), dr.Item("message", "#a", "RECONwords in a message"))
    got = by_value(dr.analyze(s, P))
    assert set(got) == {"RECONwish_granted", "recon-crew"}
    assert got["RECONwish_granted"].kind == "braceless" and got["RECONwish_granted"].wrapped == "RECON{wish_granted}"
    assert got["recon-crew"].wrapped == "RECON{crew}"


def test_challenge_words_rank_the_item_that_mentions_them():
    s = snap_of(dr.Item("channel-topic", "#lobby", "code word: capstan"),
                dr.Item("channel-topic", "#watch", "The watch is broadcasting. Recognition word: halyard"))
    cues = dr.cue_words("Comms Check", "Report the recognition word the watch is broadcasting on Discord.")
    assert cues == ("comms", "recognition", "word", "watch", "broadcasting")       # stop words dropped
    plain = dr.analyze(s, P)
    assert [c.value for c in plain.candidates] == ["capstan", "halyard"]            # first seen, equal score
    ranked = dr.analyze(s, P, cues=cues)
    assert [c.value for c in ranked.candidates] == ["halyard", "capstan"]
    top = ranked.candidates[0]
    assert top.score == dr.SCORES["recognition"] + dr.CUE_BONUS_MAX and "mentions" in top.how


def test_the_same_value_is_one_candidate_kept_at_its_strongest():
    s = snap_of(dr.Item("message", "#a", "code word: RECON{tw1ce}"), dr.Item("pin", "#a", "RECON{tw1ce}"),
                dr.Item("message", "#b", "format: RECON{tw1ce}"))
    rep = dr.analyze(s, P)
    assert [(c.value, c.kind) for c in rep.candidates] == [("RECON{tw1ce}", "flag")]


def test_prefix_case_follows_the_event_rule():
    insensitive = event.parse({
        "slug": "ci", "name": "ci", "dates": {"start": dt.date(2027, 1, 1), "end": dt.date(2027, 1, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["RECON"], "case": "prefix-insensitive"},
        "rules": {"submit_mode": "manual", "flag_sharing": "allowed", "ai_on_platform": "allowed"}}, src="t")
    s = snap_of(dr.Item("pin", "#a", "recon{l0wer_prefix}"))
    assert dr.analyze(s, P, decode=False).candidates == []                     # exact case: not this event's
    exact = dr.analyze(s, P).candidates                                        # only a loose case-change reaches one
    assert [(c.kind, c.score) for c in exact] == [("decoded-flag", dr.LOOSE_DECODE_SCORE)]
    got = dr.analyze(s, insensitive).candidates
    assert [(c.value, c.kind) for c in got] == [("RECON{l0wer_prefix}", "flag")]   # normalized spelling


# ------------------------------------------------------------------------------- snapshot and ingest

def test_snapshot_round_trip_dedupe_and_owner_only_file(tmp_path):
    s = dr.Snapshot(guild={"id": "1", "name": "Fleet"})
    a = dr.Item("pin", "#a", "one", author="x", seq=3, source="api")
    assert s.add([a, dr.Item("message", "#a", "two"), dr.Item("message", "#a", "   ")], source="api",
                 notes=["#locked: not readable"], now=5.0) == 2
    assert s.add([a, dr.Item("pin", "#b", "one")], now=6.0) == 1               # same place and text: once
    assert [c["added"] for c in s.captures] == [2, 1] and s.notes() == ["#locked: not readable"]
    assert s.counts() == {"pin": 2, "message": 1}
    path = dr.save(s, dr.snapshot_path(tmp_path))
    assert path == tmp_path / "discord" / "snapshot.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    back = dr.load(path)
    assert back.items == s.items and back.guild == s.guild and back.captures == s.captures
    assert not list(path.parent.glob("*.tmp"))


@pytest.mark.parametrize("doc, needle", [
    ({"schema": 2, "items": []}, "schema 1"),
    ({"schema": 1, "items": [], "extra": 1}, "unknown snapshot key"),
    ({"schema": 1, "items": [{"kind": "nope", "where": "#a", "text": "x"}]}, "unknown item kind"),
    ({"schema": 1, "items": [{"kind": "pin", "text": "x"}]}, "lacks 'where'"),
    ({"schema": 1, "items": [{"kind": "pin", "where": "#a", "text": "x", "token": "t"}]}, "unknown key"),
    ({"schema": 1, "items": "x"}, "lists"),
])
def test_a_bad_snapshot_is_refused_by_name(tmp_path, doc, needle):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(dr.DiscordReconError, match=needle):
        dr.load(p)


def test_a_missing_snapshot_names_the_human_step(tmp_path):
    with pytest.raises(dr.DiscordReconError, match="human step.*discord checklist"):
        dr.load(dr.snapshot_path(tmp_path))
    assert dr.load_or_new(dr.snapshot_path(tmp_path)).items == []


def test_ingest_text_keeps_lines_and_needs_a_place(tmp_path):
    f = tmp_path / "rules.txt"
    f.write_bytes(RULES.replace("\n", "\r\n").encode())
    guild, items, fmt = dr.ingest_file(f, where="#rules", kind="rules")
    assert fmt == "text" and guild == {} and len(items) == 1
    assert items[0].text == RULES.strip("\n") and items[0].kind == "rules" and items[0].source == "paste"
    with pytest.raises(dr.DiscordReconError, match="--where"):
        dr.ingest_file(f)
    empty = tmp_path / "empty.txt"
    empty.write_text("  \n")
    with pytest.raises(dr.DiscordReconError, match="empty"):
        dr.ingest_file(empty, where="#x")


def test_ingest_a_chat_export(tmp_path):
    export = {"guild": {"id": "9", "name": "Fleet"},
              "channel": {"id": "11", "name": "rules", "topic": "Read me", "category": "Bridge"},
              "messages": [
                  {"id": "1", "content": "first", "author": {"name": "adm", "nickname": "The Admiral"}, "isPinned": True},
                  {"id": "2", "content": "", "author": {"name": "bot"},
                   "embeds": [{"title": "T", "description": "D", "fields": [{"name": "n", "value": "v"}],
                               "footer": {"text": "F"}}], "attachments": [{"fileName": "map.png"}]},
                  {"id": "3", "content": "", "author": {"name": "nobody"}}]}
    f = tmp_path / "export.json"
    f.write_text(json.dumps(export))
    guild, items, fmt = dr.ingest_file(f)
    assert fmt == "export" and guild == {"id": "9", "name": "Fleet"}
    got = [(i.kind, i.where, i.text, i.author, i.seq) for i in items]
    assert got == [("channel-name", "#rules", "rules", "", 0), ("channel-topic", "#rules", "Read me", "", 0),
                   ("category-name", "category Bridge", "Bridge", "", 0),
                   ("pin", "#rules", "first", "The Admiral", 1),
                   ("message", "#rules", "T\nD\nn\nv\nF\nmap.png", "bot", 2),
                   ("guild-name", "server", "Fleet", "", 0)]
    assert all(i.source == "export" for i in items)


def test_ingest_format_detection_fails_loudly(tmp_path):
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(dr.DiscordReconError, match="neither a snapshot.*nor a chat export"):
        dr.ingest_file(other)
    with pytest.raises(dr.DiscordReconError, match="not a chat export"):
        dr.ingest_file(other, as_="export")
    with pytest.raises(dr.DiscordReconError, match="not a Discord snapshot"):
        dr.ingest_file(other, as_="snapshot")
    assert dr.ingest_file(other, as_="text", where="#x")[2] == "text"          # the player's call
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(snap_of(dr.Item("pin", "#a", "x")).to_dict()))
    assert dr.ingest_file(snap)[2] == "snapshot"
    with pytest.raises(dr.DiscordReconError, match="names its own places"):
        dr.ingest_file(snap, where="#a")
    broken = tmp_path / "broken.json"
    broken.write_text("{")
    with pytest.raises(dr.DiscordReconError, match="not JSON"):
        dr.ingest_file(broken, as_="export")
    with pytest.raises(dr.DiscordReconError, match="cannot be read"):
        dr.ingest_file(tmp_path / "absent.txt", where="#x")
    with pytest.raises(dr.DiscordReconError, match="unknown input format"):
        dr.ingest_file(snap, as_="html")


def test_an_oversized_item_is_refused_not_cut(monkeypatch):
    monkeypatch.setattr(dr, "MAX_ITEM_CHARS", 50)
    with pytest.raises(dr.DiscordReconError, match="60 characters, over the 50-character item limit"):
        dr.ingest_text("x" * 60, where="#a")
    assert dr.ingest_text("x" * 50, where="#a")[0].text == "x" * 50
    with pytest.raises(dr.DiscordReconError, match="message 1 of #a is 51 characters"):
        dr.ingest_export({"channel": {"name": "a"}, "messages": [{"id": "1", "content": "y" * 51}]})
    with pytest.raises(dr.DiscordReconError, match="the topic of #a"):
        dr.ingest_export({"channel": {"name": "a", "topic": "t" * 51}, "messages": []})


def test_acrostic_readings_are_capped_with_a_note(monkeypatch):
    monkeypatch.setattr(dr, "MAX_READINGS", 1)
    s = snap_of(dr.Item("message", "#a", "Sail\nHull\nOar\nReef\nEel"),
                dr.Item("message", "#b", "Mast\nOar\nUrn\nNet\nDeck"))
    rep = dr.analyze(s, P)
    assert [r.text for r in rep.readings] == ["SHORE"]
    assert any("1 more acrostic reading" in n for n in rep.notes)


def test_ingest_refuses_an_oversized_file(tmp_path, monkeypatch):
    f = tmp_path / "big.txt"
    f.write_text("x" * 200)
    monkeypatch.setattr(dr, "MAX_INGEST_BYTES", 100)
    with pytest.raises(dr.DiscordReconError, match="over the 100-byte ingest limit"):
        dr.ingest_file(f, where="#x")


@pytest.mark.parametrize("rel", [
    "Library/Application Support/discord/Local Storage/leveldb/000005.ldb",
    "Library/Application Support/discordcanary/Cache/data_1",
    ".config/discord/Local Storage/leveldb/LOG",
    "AppData/Roaming/Discord/Local Storage/leveldb/000003.log",
])
def test_the_local_discord_app_data_is_never_an_input(tmp_path, rel):
    f = tmp_path / "home" / rel
    f.parent.mkdir(parents=True)
    f.write_text("RECON{from_the_cache}")
    with pytest.raises(dr.DiscordReconError, match="local Discord app's data folder"):
        dr.ingest_file(f, where="#cache")
    with pytest.raises(dr.DiscordReconError, match="never read"):
        dr.refuse_app_data(f.parent)


def test_a_folder_merely_named_discord_is_fine(tmp_path):
    f = tmp_path / "work" / "discord" / "rules.txt"
    f.parent.mkdir(parents=True)
    f.write_text("hello")
    assert dr.refuse_app_data(f) == f.resolve()
    assert dr.ingest_file(f, where="#rules")[1][0].text == "hello"


def test_the_fence_denies_the_same_app_folder():
    # ctf/fence.py is the solver-side rule this module's own refusal mirrors
    from ctf import fence
    tables = [v for v in vars(fence).values() if isinstance(v, tuple) and v and isinstance(v[0], tuple)]
    assert any("Library/Application Support/discord" in row for table in tables for row in table)


def test_message_text_reads_embeds_polls_and_stickers():
    m = {"content": " hi ", "embeds": [{"author": {"name": "A"}, "title": "T"}, "junk"],
         "sticker_items": [{"name": "wave"}], "attachments": [{"filename": "a.txt", "description": "alt"}],
         "poll": {"question": {"text": "Which?"}, "answers": [{"poll_media": {"text": "This"}}]}}
    assert dr.message_text(m) == "hi\nT\nA\na.txt\nalt\nwave\nWhich?\nThis"
    assert dr.message_text({}) == ""


# ------------------------------------------------------------------------------- checklist, report, card

def test_checklist_marks_what_the_snapshot_covers():
    none = {p.key: p for p in dr.checklist(None)}
    assert not any(p.done for p in none.values()) and none["members"].by_bot is False
    s = snap_of(dr.Item("channel-topic", "#a", "t"), dr.Item("emoji", "emoji", "e"), dr.Item("emoji", "emoji", "f"))
    got = {p.key: p for p in dr.checklist(s)}
    assert got["topics"].done and got["expressions"].have == 2 and not got["rules"].done and not got["join"].done
    text = dr.render_checklist(dr.checklist(s), capture="forbidden", challenge="77")
    assert "challenge 77" in text and "[x] Every channel's details" in text and "[ ] The rules channel" in text
    assert "capture = \"forbidden\"" in text and "discord capture" not in text
    assert "python -m ctf discord capture" in dr.render_checklist(dr.checklist(s), capture="bot")


def test_report_lists_candidates_readings_and_notes():
    s = snap_of(*dr.ingest_text(RULES, where="#rules", kind="rules"),
                dr.Item("message", "#a", "Sail\nHull\nOar\nReef\nEel"))
    s.captures[-1]["notes"] = ["#locked: pins: not readable by the bot (HTTP 403)"]
    rep = dr.analyze(s, P)
    text = dr.render_report(rep, title="T", top=1)
    assert text.startswith("# T\n") and f"`{ACROSTIC}`" in text and DECOY not in text and "(1 more not shown)" in text
    assert "`SHORE`" in text and "#locked: pins: not readable" in text
    assert DECOY in dr.render_report(rep)
    empty = dr.render_report(dr.analyze(snap_of(dr.Item("message", "#a", "hello")), P))
    assert "No candidate" in empty
    d = rep.to_dict()
    assert d["candidates"][0]["value"] == ACROSTIC and d["items"] == 2 and d["event"] == "recon-test"


def test_request_card_is_opened_once_per_challenge(tmp_path):
    card, created = dr.request_card(P, "77", name="Comms Check", workdir=tmp_path)
    again, created2 = dr.request_card(P, "77", workdir=tmp_path)
    other, created3 = dr.request_card(P, "78", workdir=tmp_path)
    assert created and not created2 and created3 and again.id == card.id != other.id
    assert card.kind == "discord" and card.challenge_id == "77" and "Comms Check" in card.ask
    assert "discord ingest" in card.need
    assert len([r for r in ledger.read(tmp_path) if r["event"] == humanops.EV_CARD]) == 2
    humanops.HumanOps(P, tmp_path).answer(card.id, "done")
    assert dr.request_card(P, "77", workdir=tmp_path)[1] is True               # answered: a new ask opens a new card
    with pytest.raises(dr.DiscordReconError, match="challenge id"):
        dr.request_card(P, " ", workdir=tmp_path)


def test_analyze_challenge_reads_the_brief_and_writes_the_report(tmp_path):
    chal = tmp_path / "77-comms-check"
    chal.mkdir()
    (chal / "challenge.json").write_text(json.dumps({
        "id": 77, "name": "Comms Check", "tags": [{"value": "discord"}, "wave1"],
        "description": "Report the recognition word the watch is broadcasting. Format RECON{qu0ted}"}))
    s = snap_of(dr.Item("channel-topic", "#lobby", "code word: capstan"),
                dr.Item("channel-topic", "#watch", "The watch is broadcasting. Recognition word: halyard"),
                dr.Item("pin", "#x", "RECON{qu0ted}"))
    rep, path = dr.analyze_challenge(s, P, chal)
    assert path == chal / "recon" / "discord.md"
    assert [c.value for c in rep.candidates] == ["halyard", "capstan", "RECON{qu0ted}"]
    assert rep.candidates[-1].kind == "decoy-flag"
    text = path.read_text()
    assert "challenge 77 (Comms Check)" in text and "`halyard (wrapped: RECON{halyard})`" in text
    assert dr.read_challenge(chal)["description"].endswith("discord wave1")
    assert dr.read_challenge(chal)["discord_only"] is True
    bare = tmp_path / "9-no-json"
    bare.mkdir()
    assert dr.read_challenge(bare) == {"id": "9", "name": "", "description": "", "discord_only": False,
                                       "bare": None}
    assert dr.read_challenge(chal)["bare"] is True
    assert dr.analyze_challenge(s, P, bare, write=False)[1] is None and not (bare / "recon").exists()
    (bare / "challenge.json").write_text("{")
    with pytest.raises(dr.DiscordReconError, match="cannot be read as JSON"):
        dr.read_challenge(bare)


@pytest.mark.parametrize("doc, want", [
    ({"description": "The flag is somewhere on the discord"}, True),                     # nothing else to work on
    ({"description": "Stuck? Ask on Discord.", "files": ["pwn.zip"]}, False),            # a handout
    ({"description": "Stuck? Ask on Discord.", "connection_info": "nc host 1337"}, False),   # a target
    ({"description": "Find me.", "tags": ["discord"], "files": ["x.zip"]}, True),         # tagged: always
    ({"description": "Find me.", "tags": [{"value": "Discord"}]}, True),
    ({"description": "Find me."}, False),
    ({"name": "Discordian Citizen", "description": "Somewhere."}, True),               # named for it
    ({"description": "Our discord server's channel topics hold the answer"}, True),
    # inline material that only mentions Discord as the place to ask: not in the server
    ({"description": "Decrypt: 4f2a9c1b77e0d3. Questions? Ask on Discord."}, False),
    ({"description": "Decrypt: 4f2a9c1b77e0d3. Open a ticket in the Discord server if the checker is down."},
     False),
    ({"description": "Decrypt: 4f2a9c1b77e0d3. Ping us on Discord."}, False),       # ping is not a pin
    ({"description": "Decrypt: 4f2a9c1b77e0d3. Made by the Discord crew."}, False),
    # people are not support: the admins and organizers are who hid it
    ({"description": "The admins hid the flag in our Discord server"}, True),
    ({"description": "Join our Discord and find the flag the organizers pinned"}, True),
    ({"description": "Report the recognition word posted in our Discord"}, True),
    # joining, and an invite link, are recon cues (the classic sanity brief)
    ({"description": "Sanity check: join discord.gg/abc"}, True),
    ({"description": "https://discord.gg/abc-123"}, True),
    ({"description": "Welcome! discord.com/invite/abc"}, True),
    ({"description": "Join our Discord!"}, True),
    # a help word still wins, joining included
    ({"description": "Decrypt: 4f2a9c1b77e0d3. Join our Discord for updates."}, False),
    ({"description": "Decrypt: 4f2a9c1b77e0d3. Join discord.gg/abc for help."}, False),
    ({"description": "Decrypt: 4f2a9c1b77e0d3. Ask an admin in the Discord server."}, False),
    ({"description": "Decrypt: 4f2a9c1b77e0d3. If stuck, look in the Discord server."}, False),
    # "ask" loses to a bot: asking the bot is the recon
    ({"description": "Ask the Discord bot for the flag"}, True),
    # sentences are judged one at a time: a support sentence beside a recon one does not veto it
    ({"description": "The flag is in our Discord server. Questions? Ask an admin."}, True),
    ({"description": "Find the flag on our Discord! Stuck? Open a ticket"}, True),
    ({"description": "Ask on Discord if stuck. The flag is in the handout channel"}, False),
])
def test_a_challenge_lives_in_the_server_when_tagged_or_bare(tmp_path, doc, want):
    d = tmp_path / "5-x"
    d.mkdir()
    (d / "challenge.json").write_text(json.dumps({"id": 5, **doc}))
    ch = dr.read_challenge(d)
    assert ch["discord_only"] is want
    assert ch["bare"] is (not doc.get("files") and not doc.get("connection_info"))


# ------------------------------------------------------------------------------- the [discord] profile table

BASE = {"slug": "demo", "name": "Demo", "dates": {"start": dt.date(2027, 1, 1), "end": dt.date(2027, 1, 3)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["DEMO"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "allowed", "ai_on_platform": "allowed"}}


def parse(discord=None):
    data = {**BASE, **({"discord": discord} if discord is not None else {})}
    return event.parse(data, src="demo.toml")


def test_profile_discord_defaults_are_forbidden_and_name_only_the_variable():
    d = parse().discord
    assert (d.capture, d.api_base, d.token_env, d.guild_id) == \
        ("forbidden", "https://discord.com/api/v10", "CTF_DISCORD_TOKEN", None)
    assert parse({}).discord == d
    got = parse({"capture": "bot", "api_base": "http://127.0.0.1:9/api/v10/", "token_env": "CTF_DISCORD_BOT",
                 "guild_id": " 123456 "}).discord
    assert (got.capture, got.api_base, got.token_env, got.guild_id) == \
        ("bot", "http://127.0.0.1:9/api/v10", "CTF_DISCORD_BOT", "123456")
    assert parse({"guild_id": ""}).discord.guild_id is None


@pytest.mark.parametrize("table, needle", [
    ({"capture": "user"}, "discord.capture must be one of forbidden, bot"),
    ({"capture": True}, "discord.capture"),
    ({"api_base": "discord.com/api"}, "discord.api_base must be an http"),
    ({"api_base": "https://user:pw@discord.com/api"}, "discord.api_base"),
    ({"api_base": "https://discord.com/api?x=1"}, "discord.api_base"),
    ({"token_env": "DISCORD_TOKEN"}, "NAME of a CTF_\\* environment variable"),
    ({"token_env": "CTF_TOKEN"}, "platform credential"),
    ({"token_env": "CTF_COOKIE"}, "platform credential"),
    ({"guild_id": "my-server"}, "discord.guild_id must be the server's numeric id"),
    ({"guild_id": 123456}, "discord.guild_id"),
    ({"bot_token": "x"}, "unknown key\\(s\\): discord.bot_token"),
])
def test_profile_discord_table_is_validated(table, needle):
    with pytest.raises(event.EventError, match=needle):
        parse(table)


def test_a_token_pasted_into_token_env_is_refused_without_being_echoed():
    pasted = "not-a-real-token.b112.pasted-by-mistake"
    with pytest.raises(event.EventError) as e:
        parse({"token_env": pasted})
    assert pasted not in str(e.value) and "never the token itself" in str(e.value)


def test_a_new_event_is_scaffolded_with_capture_forbidden():
    data = eventscaffold.profile_data(
        "newev", name="New", start=dt.date(2027, 2, 1), end=dt.date(2027, 2, 2), kind="manual",
        submit_mode="manual", ai_on_platform="allowed", flag_sharing="allowed")
    assert data["discord"] == {"capture": "forbidden", "api_base": "https://discord.com/api/v10",
                               "token_env": "CTF_DISCORD_TOKEN", "guild_id": ""}
    assert eventscaffold.validate(data, "newev").discord.capture == "forbidden"
