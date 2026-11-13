#!/usr/bin/env python3
"""Offline self-test of the Binary lane's STATED multi-record HCFG config selector
(solvers/binary/record_select.py, wired into generic.answers via generic.record_pool).

  .venv/bin/python -I solvers/binary/selftest.py [-v]

No network and no token: everything is built from synthetic HCFG records in memory. Nothing from
challenges/ is read and nothing is executed from any fixture. It reports a pass/fail count and exits
non-zero if anything failed.

What is checked (the research-ticket-#3 bright line -- select the CRC-valid record the question's STATED
selector names; NEVER plain since fix round 2 of the review of KB-3: a byte-proven, unambiguous selector in any
wording, the generator's own frame included, -> a one-option labels.pick tagged with the text and named for the
delivery, anything ambiguous/unproven -> labels.candidates or None, NEVER a guessed record):

  precheck    states_selector() is False for the real Day-24/25 common-config and per-build question
              texts (the zero-change guarantee), True for each selector form.
  select      ordinal / Nth / last, version, campaign and patch-diff role selectors each resolve the
              right record and answer its tagged one-option pick when byte-proven and unambiguous.
  end-to-end  the same, driven through generic.answers() on a synthetic two-record d26 delivery,
              including the member-name role mapping and the row-507 divergent-builds interaction.
  never-wrong adversarial: an ambiguous selector, an out-of-range ordinal, a selector resolving to a
              non-day record, and two differing records with no selector all yield candidates/None and
              NEVER a wrong plain answer; records that AGREE on a field are never plain either.
  static      the Day-30 lone/static adapter opts every d01--d29 contract out, recognizes an arbitrary
              Single Solve id, selects one executable by bytes rather than id/name, and refuses ambiguity.
"""
import io
import json
import struct
import sys
import zlib
from contextlib import redirect_stderr
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import labels            # noqa: E402
import record_select as rs   # noqa: E402
from _shadowed import module_at  # noqa: E402
generic = module_at(HERE / "generic.py", "binary_generic")   # script-analysis has a generic.py too
import static_re         # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    if VERBOSE or not ok:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))


# ---- synthetic HCFG records ----------------------------------------------------------------------

def make_record(obj, version=1, key=0x5a):
    """A CRC-valid HCFG record (the lane's layout) carrying JSON `obj`."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    enc = bytes(b ^ key for b in payload)
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return b"HCFG" + bytes([version, key]) + struct.pack("<HI", len(enc), crc) + enc


def cfg(day=26, variant=0, **extra):
    v = f"{variant:03d}"
    obj = {"campaign": f"BR{day:02d}-{v}", "domain": f"node-{v}.day{day}.example.invalid",
           "url": f"https://node-{v}.day{day}.example.invalid/api/BR{day:02d}-{v}",
           "mutex": f"Global\\\\HuntressBR{day:02d}_{v}"}
    obj.update(extra)
    return obj


def member_with(records):
    """A non-image .bin member carrying the given raw HCFG records back to back (with filler)."""
    out = b"\x00\x10junk-prefix\x00"
    for r in records:
        out += r + b"\x00\x00padding\x00\x00"
    return out


def as_pool(members):
    """generic.record_pool over a {name: bytes} dict for prefix d26 (file order)."""
    return generic.record_pool(list(members.items()), 26)


def q(qid, text, kind="exact_text"):
    return {"id": qid, "qid": qid, "question": text, "answer_format": {"kind": kind}}


def answers(files, questions):
    buf = io.StringIO()
    with redirect_stderr(buf):
        return generic.answers("d26", questions, dict(files), {})


def render_for(records):
    names = set()
    for r in records:
        j = r.get("json") or {}
        names.update(j)

    def render(field, rec):
        if field == "analysis_hcfg_version":
            v = rec.get("version")
            return str(v) if isinstance(v, int) else None
        return generic.config_answer(field, rec, lambda: names, "", None)[0]
    return render


def pick_of(value, want):
    """A ONE-option labels.pick of `want` under a key tagged with the question text (`+t<crc32>`): the reading of a
    stated selector in any wording but the generator's own frame (fix round 2 of the review of KB-3: the established
    forms, an ordinal, a version, a campaign, a role, are never plain; the judge's acceptance of that wording turns
    it plain, and only for that wording)."""
    if not labels.is_unsure(value) or is_candidate(value):
        return False
    parsed = labels.parse(value)
    return bool(parsed) and "+t" in parsed.key and [o for _, o in parsed.options] == [want]


def is_candidate(value):
    if not labels.is_unsure(value):
        return False
    try:
        parsed = labels.parse(value)
        return getattr(parsed, "key", "").endswith(labels.CANDIDATE_MARK)
    except Exception:
        return labels.is_unsure(value)


# ---- precheck: the zero-change guarantee ---------------------------------------------------------

def test_precheck():
    common = ("In evidence.zip, Decode both d24-- role members and require their config objects to be "
              "byte-for-byte equal before using the common value. ... accept the first CRC32-valid HCFG "
              "JSON record. Locate the unique CRC32-valid HCFG record: ... byte 4 is version, byte 5 is "
              "the XOR key ... the decoded HCFG JSON object's top-level campaign property.")
    perbuild = ("In evidence.zip, Use the unique d24-- member whose basename ends corrected.jar. ... "
                "accept the first CRC32-valid HCFG JSON record. ... top-level campaign property.")
    check("precheck: Day-24 common-config text is not a selector", not rs.states_selector(common))
    # KB-3: "the unique member whose basename ends corrected.jar" IS a stated member selector now. It is only
    # asked of a prefix-level config id left None (generic.answers); the per-build ids that carry this text
    # (analysis_corrected_config_*) are not config fields there and are role_answers', so no saved answer moves.
    check("precheck: Day-24 per-build text is a basename selector (KB-3)", rs.states_selector(perbuild))
    for form in ("read the second HCFG record", "use record #2", "the last HCFG record",
                 "the 2nd config record", "where version is 2", "campaign BR26-001",
                 "the corrected build's config", "the vulnerable binary"):
        check(f"precheck: selector detected in {form!r}", rs.states_selector(form))


# ---- select() unit tests --------------------------------------------------------------------------

def test_select_unit():
    recs = as_pool({"d26--sample.bin": member_with([make_record(cfg(variant=0), version=1, key=0x41),
                                                    make_record(cfg(variant=1), version=2, key=0x42)])})
    check("select: two records built", len(recs) == 2, f"got {len(recs)}")
    render = render_for(recs)

    # ordinal
    v, note = rs.select("analysis_config_campaign", "use the second HCFG record", recs, render, 26)
    check("select ordinal(second) -> BR26-001, a tagged pick", pick_of(v, "BR26-001"), f"{v!r} {note}")
    v, _ = rs.select("analysis_config_campaign", "use the first record", recs, render, 26)
    check("select ordinal(first) -> BR26-000, a tagged pick", pick_of(v, "BR26-000"), repr(v))
    v, _ = rs.select("analysis_config_campaign", "the last config record", recs, render, 26)
    check("select last -> BR26-001, a tagged pick", pick_of(v, "BR26-001"), repr(v))

    # version
    v, _ = rs.select("analysis_config_domain", "where the header version is 2", recs, render, 26)
    check("select version(2) -> record 1 domain, a tagged pick", pick_of(v, "node-001.day26.example.invalid"), repr(v))
    v, _ = rs.select("analysis_hcfg_version", "the second record", recs, render, 26)
    check("select ordinal -> hcfg_version '2', a tagged pick", pick_of(v, "2"), repr(v))

    # campaign
    v, _ = rs.select("analysis_config_url", "campaign BR26-000", recs, render, 26)
    check("select campaign(BR26-000) -> record 0 url, a tagged pick",
          pick_of(v, "https://node-000.day26.example.invalid/api/BR26-000"), repr(v))


def test_select_role():
    recs = as_pool({"d26--sample.bin": member_with([
        make_record(cfg(variant=0, role="vulnerable"), key=0x41),
        make_record(cfg(variant=1, role="corrected"), key=0x42)])})
    render = render_for(recs)
    v, note = rs.select("analysis_config_campaign", "the corrected build's config campaign", recs, render, 26)
    check("select role-marker(corrected) -> BR26-001, a tagged pick", pick_of(v, "BR26-001"), f"{v!r} {note}")
    v, _ = rs.select("analysis_config_campaign", "the vulnerable build's config campaign", recs, render, 26)
    check("select role-marker(vulnerable) -> BR26-000, a tagged pick", pick_of(v, "BR26-000"), repr(v))

    # role via campaign token (no role field)
    recs2 = as_pool({"d26--sample.bin": member_with([
        make_record({"campaign": "BR26-000-vulnerable", "domain": "a.example.invalid"}, key=0x41),
        make_record({"campaign": "BR26-000-corrected", "domain": "b.example.invalid"}, key=0x42)])})
    render2 = render_for(recs2)
    v, _ = rs.select("analysis_config_domain", "the corrected config", recs2, render2, 26)
    check("select role-via-campaign-token(corrected) -> b, a tagged pick", pick_of(v, "b.example.invalid"), repr(v))


def test_select_member_role():
    # the role word maps to the MEMBER it came from (two members, divergent configs)
    files = {"d26--sample-vulnerable.bin": member_with([make_record(cfg(variant=0), key=0x41)]),
             "d26--sample-corrected.bin": member_with([make_record(cfg(variant=1), key=0x42)])}
    recs = as_pool(files)
    render = render_for(recs)
    check("member-role: two records across two members", len(recs) == 2, f"got {len(recs)}")
    v, note = rs.select("analysis_config_campaign", "the corrected build's config campaign", recs, render, 26)
    check("select member-name(corrected) -> BR26-001, a tagged pick", pick_of(v, "BR26-001"), f"{v!r} {note}")


# ---- end-to-end through generic.answers() --------------------------------------------------------

def test_end_to_end():
    files = {"d26--sample.bin": member_with([make_record(cfg(variant=0, role="vulnerable"), version=1, key=0x41),
                                             make_record(cfg(variant=1, role="corrected"), version=2, key=0x42)])}
    # With no selector, the common config id stays None (generic's never-guess fallback).
    out = answers(files, [q("d26_analysis_config_campaign",
                            "Decode the HCFG record and submit the campaign property.")])
    check("e2e: no selector -> common config None", out["d26_analysis_config_campaign"] is None,
          repr(out["d26_analysis_config_campaign"]))
    # With a stated selector, the right record is read: a tagged one-option pick in these wordings (fix round 2).
    out = answers(files, [q("d26_analysis_config_campaign", "In the corrected build, submit the campaign property."),
                          q("d26_analysis_config_url", "Read the second HCFG record and submit the url property.")])
    check("e2e: role selector -> BR26-001, a tagged pick", pick_of(out["d26_analysis_config_campaign"], "BR26-001"),
          repr(out["d26_analysis_config_campaign"]))
    check("e2e: ordinal selector -> url of record 1, a tagged pick",
          pick_of(out["d26_analysis_config_url"], "https://node-001.day26.example.invalid/api/BR26-001"),
          repr(out["d26_analysis_config_url"]))
    # The generator's own frame of a member selector passes the allow-list: the `frame_` reading.
    framed = {"d26--sample-vulnerable.bin": member_with([make_record(cfg(variant=0), key=0x41)]),
              "d26--sample-corrected.bin": member_with([make_record(cfg(variant=1), key=0x42)])}
    # (the judged literal-first procedure: these synthetic members store their record raw, which a literal scan
    # reads; a frame whose procedure the record was not read by is a reading, not plain)
    out = answers(framed, [q("d26_analysis_config_campaign",
                             "In evidence.zip, Use the unique d26-- member whose basename ends corrected.bin. "
                             "First test literal HCFG occurrences in the member; then test every non-overlapping "
                             "Latin-1 run matching [A-Za-z0-9+/]{100,}={0,2} by Base64-decoding it. Accept the first "
                             "CRC32-valid HCFG JSON record in that order. "
                             "Submit the exact string value of the decoded HCFG JSON object's top-level campaign "
                             "property, without JSON quotes.")])
    # (the fourth review of fix round 2: nothing of record_select is plain, the frame is its `frame_` reading's pick)
    check("e2e: the generator's frame of a basename selector -> BR26-001, the frame reading's tagged pick",
          pick_of(out["d26_analysis_config_campaign"], "BR26-001")
          and "/recsel_frame_" in labels.parse(out["d26_analysis_config_campaign"]).key,
          repr(out["d26_analysis_config_campaign"]))


def test_end_to_end_divergent_builds():
    # Two role builds with DIVERGENT configs + per-build ids present (row-507 guard fires), and a
    # common config id whose TEXT names the corrected build -> its record, a tagged pick (fix round 2).
    files = {"d26--sample-vulnerable.jar": member_with([make_record(cfg(variant=0), key=0x41)]),
             "d26--sample-corrected.jar": member_with([make_record(cfg(variant=1), key=0x42)])}
    qs = [q("d26_analysis_corrected_config_campaign",
            "Use the unique d26-- member whose basename ends corrected.jar. ... campaign property."),
          q("d26_analysis_vulnerable_config_campaign",
            "Use the unique d26-- member whose basename ends vulnerable.jar. ... campaign property."),
          q("d26_analysis_config_domain", "In the corrected build, submit the config domain property.")]
    out = answers(files, qs)
    check("e2e divergent: corrected common domain, a tagged pick",
          pick_of(out["d26_analysis_config_domain"], "node-001.day26.example.invalid"),
          repr(out["d26_analysis_config_domain"]))


# ---- never-wrong / adversarial -------------------------------------------------------------------

def test_never_wrong():
    recs = as_pool({"d26--sample.bin": member_with([make_record(cfg(variant=0), key=0x41),
                                                    make_record(cfg(variant=1), key=0x42)])})
    render = render_for(recs)

    # an unproven semantic selector ("the patched build" -- no marker, no member) -> candidates, never plain
    v, note = rs.select("analysis_config_campaign", "the patched build's config campaign", recs, render, 26)
    check("adversarial: unproven role -> candidates (unsure), not plain",
          v is not None and is_candidate(v), f"{v!r} {note}")
    check("adversarial: unproven role never a real campaign plain",
          not (isinstance(v, str) and not labels.is_unsure(v)), repr(v))

    # an out-of-range ordinal cannot resolve -> fallback (differing campaigns) -> candidates, not record 1
    v, _ = rs.select("analysis_config_campaign", "the 5th HCFG record", recs, render, 26)
    check("adversarial: out-of-range ordinal -> candidates, not plain", is_candidate(v), repr(v))

    # a selector resolving to a NON-day record is not read plain
    other = as_pool({"d26--sample.bin": member_with([make_record(cfg(day=99, variant=0), key=0x41),
                                                     make_record(cfg(day=99, variant=1), key=0x42)])})
    v, _ = rs.select("analysis_config_campaign", "the first HCFG record", other, render_for(other), 26)
    check("adversarial: selector to non-day record -> not plain", not (isinstance(v, str)
          and not labels.is_unsure(v)) and v != "BR99-000", repr(v))

    # records that AGREE on a field, but a role no record is proven to carry: the agreement of the pool proves nothing
    # about the record the text names (it may stand outside the pool), so it is never plain; the agreed value is a
    # one-option candidates pick, probed on the untimed base (review of KB-3: the first build answered it plain)
    agree = as_pool({"d26--sample.bin": member_with([
        make_record({"campaign": "BR26-000", "domain": "same.day26.example.invalid"}, key=0x41),
        make_record({"campaign": "BR26-001", "domain": "same.day26.example.invalid"}, key=0x42)])})
    v, _ = rs.select("analysis_config_domain", "the patched build's domain", agree, render_for(agree), 26)
    check("adversarial: records agree, role unproven -> a one-option candidates pick, not plain",
          is_candidate(v) and [o for _, o in labels.parse(v).options] == ["same.day26.example.invalid"], repr(v))
    # a selector that names BOTH records of an agreeing pool answers their value as the reading's tagged pick (fix
    # round 2: plain before; an established form is never plain, and no record outside the two renders the value)
    twin = as_pool({"d26--sample.bin": member_with([
        make_record({"campaign": "BR26-000", "domain": "same.day26.example.invalid"}, version=1, key=0x41),
        make_record({"campaign": "BR26-001", "domain": "same.day26.example.invalid"}, version=1, key=0x42)])})
    v, _ = rs.select("analysis_config_domain", "the HCFG record with version 1", twin, render_for(twin), 26)
    check("adversarial: a selector naming both of two agreeing records -> their value, a tagged pick",
          pick_of(v, "same.day26.example.invalid"), repr(v))
    v, _ = rs.select("analysis_config_campaign", "the HCFG record with version 1", twin, render_for(twin), 26)
    check("adversarial: ...and the field they differ on is a candidates pick, not plain", is_candidate(v), repr(v))

    # fewer than two records -> nothing
    one = as_pool({"d26--sample.bin": member_with([make_record(cfg(variant=0), key=0x41)])})
    v, _ = rs.select("analysis_config_campaign", "the second record", one, render_for(one), 26)
    check("adversarial: single record -> None", v is None, repr(v))


def test_end_to_end_adversarial():
    # Through generic.answers(): an ambiguous selector must never produce a wrong plain config answer.
    files = {"d26--sample.bin": member_with([make_record(cfg(variant=0), key=0x41),
                                             make_record(cfg(variant=1), key=0x42)])}
    out = answers(files, [q("d26_analysis_config_campaign", "the patched build's config campaign")])
    v = out["d26_analysis_config_campaign"]
    plain_wrong = isinstance(v, str) and not labels.is_unsure(v) and v in ("BR26-000", "BR26-001")
    check("e2e adversarial: ambiguous selector never a wrong plain campaign", not plain_wrong, repr(v))
    check("e2e adversarial: ambiguous selector -> candidates or None", v is None or is_candidate(v), repr(v))


def test_lone_static_contract():
    question = q("answer", "Statically disassemble function check_key and return its instruction count.", "integer")
    question["member"] = None
    ctx = {"attempt": {"mode": "single_solve", "challenge": "reverse-engineering-day-30"},
           "delivery_name": "challenge.bin"}
    # _kind needs a structurally readable ELF identification header; no parser is asked in this selection test.
    elf = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 32
    ctx["delivery"] = elf
    check("static: arbitrary id is a recognized lone Single Solve contract",
          static_re.eligible([question], {"challenge.bin": elf}, ctx))
    selected = static_re.select_artifact(question, {"challenge.bin": elf}, ctx)
    check("static: sole executable selected independently of qid/name",
          selected is not None and selected[1] == elf and selected[2] == "elf", repr(selected))
    older = dict(question, qid="d29_analysis_disassembly", id="d29_analysis_disassembly")
    check("static: every d01--d29 contract is an absolute opt-out",
          not static_re.eligible([older], {"challenge.bin": elf}, ctx))
    older_route = {"attempt": {"mode": "single_solve",
                                "_challenge_id": "binary-reverse-engineering-day-01-c-elf-orientation"}}
    check("static: an unprefixed historical route is also an absolute opt-out",
          not static_re.eligible([question], {"challenge.bin": elf}, older_route))
    other = elf + b"different"
    check("static: two distinct executables are ambiguous and never first-file guessed",
          static_re.select_artifact(question, {"one.bin": elf, "two.bin": other}, ctx) is None)
    timed = {"attempt": {"mode": "mastery", "challenge": "reverse-engineering-day-30/mastery"}}
    check("static: a timed route is an absolute opt-out", not static_re.eligible([question], {}, timed))
    deadline = {"attempt": {"mode": "single_solve", "challenge": "reverse-engineering-day-30",
                            "deadline": "2026-10-30T09:00:30-04:00"}}
    check("static: any deadline is an absolute opt-out", not static_re.eligible([question], {}, deadline))
    check("static: covers without attempt context fails closed", not static_re.eligible([question]))


def main():
    test_precheck()
    test_select_unit()
    test_select_role()
    test_select_member_role()
    test_end_to_end()
    test_end_to_end_divergent_builds()
    test_never_wrong()
    test_end_to_end_adversarial()
    test_lone_static_contract()
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [r for r in RESULTS if not r[1]]
    print(f"\nselftest: {passed} passed, {len(failed)} failed, {len(RESULTS)} total")
    for name, _, detail in failed:
        print(f"  FAIL {name}: {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
