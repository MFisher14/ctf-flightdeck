#!/usr/bin/env python3
"""Two-record patch-diff FACTS (KB-3, the Day 27 build; loaded by name from record_select.diff_answers, which
generic.patch_diff_answers asks, from evidence.closing() after every other reader (the stated wrapper, the sidecar,
the stated definition, the tagged trailer), for an id they all left None).

Day 24 was patch-diffing: a vulnerable and a corrected build side by side, and the questions asked each
build's config (record_select / role_answers read those). A later patch-diff day can ask about the DIFFERENCE
itself: which config field changed, its value in the patched build, how many fields changed, the byte offset
of the patch. This module answers those, and only those, from the prefix's CRC-valid HCFG records:

  * exactly TWO distinct CRC-valid records that name the prefix's day (campaign BR<day>-...) are the pair;
    any other count, or a record that is not CRC-valid, is None (a third record, a decoy of another day and a
    CRC-broken record are never part of the pair);
  * the changed config key is the one key whose value differs and whose key set is the same in both (an added
    or removed key is not "a changed field": None); two or more differing keys give no single field: None;
  * the patched / original side is read only from the byte-proven role marker of a record (the member name's
    segment or a role field of the record's own JSON; record_select._role_matches), never from the order.

Every answer is UNSURE: a ONE-option labels.pick under binary.patch_diff/<fact>+<field>+t<tag> where the fact is
one reading of one established difference (a changed key's name, the changed count, the patched side's value), or a
labels.candidates under binary.patch_diff/<fact>+<field>+t<tag>#candidates where the question leaves the reading
open (the byte offset of the patch: of the member file, of the decoded payload, of the record). Nothing is ever
plain: no day has judged a name for these ids. Every option's name carries the pair's scope (`<reading>@<SHA-256 of
the exact delivery and two payloads>`, fix round 2 of the review of KB-3): the judge's acceptance answers that delivery, replayed, and
never another variant plain, because the reader carries out a few words of the question and not the rest. `<field>` is the id's own field part and `<tag>` the eight hex digits
of the normalised question text (judged_forms.norm_text, the day masked): a name the judge accepts for one id under
one wording is a reading of that id and that wording only. The first build keyed a fact alone, so after ONE
acceptance every later id that classified the same way answered the config-diff fact plain whatever it asked, and a
rejection on an unrelated id poisoned the right reading (review of KB-3, a3).

The ids are selected by their own words (a diff token and a fact token in the id's field part) AND by the text: a fact
of a CONFIG (the changed key, its count, a side's value) is read only when the question text itself names the config
(config, HCFG or JSON), an offset or a size of the patch only when it names the config or its record, payload or
container. `diff_symbol_name`, `patch_member_name` and `diff_count` of an instruction patch, or a typed read at a file
offset, ask about something else and stay another reader's (review of KB-3: an id claimed from its words alone was
never offered to the readers that run later). The text must also STATE a difference (differ, change, modified, the
patch, delta, ...; DIFF_TEXT), not only the id: a count of one build's keys is not the count of the differing ones.
The weak words (`member`, `name`, `attribute`, `number`, `total`) count only beside a word that says config, field,
key or property. A day that asks none of them never reaches the pool.
"""
import hashlib
import re
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "common"))
import labels            # noqa: E402

# "patched" is a SIDE word, not a difference word: `analysis_patched_config_<member>` is a per-build config id.
DIFF_TOKENS = {"patch", "diff", "delta", "changed", "change", "changes", "modified", "differ", "differs",
               "differing", "difference", "differences", "mutation", "tampered"}
PATCHED_SIDE = {"patched", "corrected", "fixed", "new", "after", "updated", "newer"}
ORIGINAL_SIDE = {"vulnerable", "original", "unpatched", "old", "before", "baseline", "base", "unfixed",
                 "older"}
KEY_TOKENS = {"field", "key", "property"}
WEAK_KEY_TOKENS = {"member", "name", "attribute"}
VALUE_TOKENS = {"value", "string", "text", "content"}
COUNT_TOKENS = {"count", "fields", "keys", "properties"}
WEAK_COUNT_TOKENS = {"number", "total"}
CONTEXT_TOKENS = {"config", "field", "fields", "key", "keys", "property", "properties", "hcfg", "json"}
OFFSET_TOKENS = {"offset", "position", "pos", "index", "address", "location"}
SIZE_TOKENS = {"size", "length", "len", "bytes"}
CONFIG_WORDS = re.compile(r"\b(?:config|configuration|hcfg|json)\b")
# an offset or a size of the patch is read as a difference of the CONFIG record (its payload, the record, the member's
# bytes): the text must say it is about one, or the id is some other reader's (a typed read at a file offset, a count
# of instructions)
RECORD_WORDS = re.compile(r"\b(?:config|configuration|hcfg|json|payload|record|container)\b")
# Every fact needs the TEXT to state a difference with a word of difference, not only the id (fix round 2 of the review
# of KB-3): `d27_analysis_patch_key_count` asked as "How many config keys does the patched build hold?" counts the keys
# of one build, and the count of DIFFERING keys would be judged against it. On a variant where every key differs the
# two coincide, and an acceptance there would turn the next variant's differing count plain. `patched`, "the patch",
# "the diff" name the builds or the change, and say nothing of which fact is asked.
DIFF_TEXT = re.compile(r"\b(?:differ\w*|different|difference\w*|chang\w*|modif\w*|alter\w*|tamper\w*|mutat\w*)\b")
# ...and no negation or complement: "How many config keys did the patch NOT change?" and the count of the changed
# ones coincide where half the keys changed, and the next variant would answer the changed count plain
NEG_TEXT = re.compile(r"\b(?:not|no|never|none|nor|unchanged|unmodified|untouched|unaltered|same|identical|equal|"
                      r"except\w*|excluding|besides|remain\w*|kept|keeps|preserv\w*|other|apart|beyond)\b|n't\b")
# an offset is read only as the FIRST difference: "the last differing byte" and the first coincide where one byte
# differs, and the next variant would answer the first one plain
OFFSET_FIRST = re.compile(r"\bfirst\b")
OFFSET_NOT_FIRST = re.compile(r"\b(?:last|final|end|ending|every|each|all|second|third|next|later)\b")


def _tokens(s):
    return [t for t in re.split(r"[^0-9a-z]+", str(s).lower()) if t]


def _field_of(qid):
    """The id's field part: after a `setN.` prefix and the day (`d27_`), lower case, `[0-9a-z_]` only."""
    q = re.sub(r"^set\d+\.", "", str(qid))
    return re.sub(r"[^0-9a-z_]+", "_", (q.split("_", 1)[1] if "_" in q else q).lower())


def _tag(text):
    """Eight hex digits that name the question text as judged_syntax.json keeps it (judged_forms.norm_text)."""
    try:
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import judged_forms
        norm = judged_forms.norm_text(text or "")
    except Exception:
        norm = " ".join(str(text or "").lower().split())
    return f"{zlib.crc32(norm.encode()):08x}"


def _key(fact, qid, text):
    """binary.patch_diff/<fact>+<field>+t<tag>: one key an id and a wording (see the module docstring)."""
    return f"binary.patch_diff/{fact}+{_field_of(qid)}+t{_tag(text)}"


def classify(qid, text=""):
    """The fact a question id asks about the patch difference: ('key'|'value'|'count'|'offset'|'size',
    side or None), or None when the id is no diff question. Read from the id's own words (after the day
    prefix and `analysis`) and from the question text, which must state a difference (DIFF_TEXT) and no negation
    (NEG_TEXT), and name the config (key, count, value) or its record, payload or container (offset, size; an offset
    only as the FIRST difference); never from the text alone."""
    body = qid.split("_", 1)[1] if isinstance(qid, str) and "_" in qid else str(qid)
    toks = [t for t in _tokens(body) if t != "analysis"]
    if not (set(toks) & DIFF_TOKENS):
        return None
    side = "patched" if set(toks) & PATCHED_SIDE else ("original" if set(toks) & ORIGINAL_SIDE else None)
    s = set(toks)
    named = str(text or "").lower()
    if not DIFF_TEXT.search(named) or NEG_TEXT.search(named):
        return None                 # the id's words say a difference, the question does not (or negates it)
    if s & OFFSET_TOKENS:
        if not (RECORD_WORDS.search(named) and OFFSET_FIRST.search(named)) or OFFSET_NOT_FIRST.search(named):
            return None
        return "offset", side
    kind = None
    if s & COUNT_TOKENS or (s & WEAK_COUNT_TOKENS and s & CONTEXT_TOKENS):
        if not (s & VALUE_TOKENS):
            kind = "count"
    if kind is None and s & VALUE_TOKENS:
        kind = "value"
    if kind is None and s & SIZE_TOKENS:
        return ("size", side) if RECORD_WORDS.search(named) else None
    if kind is None and (s & KEY_TOKENS or (s & WEAK_KEY_TOKENS and s & CONTEXT_TOKENS)):
        kind = "key"
    if kind is None:
        return None
    # a fact of the config: the question must say it is about the config (an instruction patch has a "count",
    # a "member name" and a "symbol name" too)
    if not CONFIG_WORDS.search(named):
        return None
    return kind, side


def _names_day(rec, day):
    j = rec.get("json")
    camp = j.get("campaign") if isinstance(j, dict) else None
    m = re.match(r"BR(\d{2})-", camp) if isinstance(camp, str) else None
    return day is not None and m is not None and int(m.group(1)) == day


def pair_of(records, day):
    """(a, b): the two distinct CRC-valid day records of the pool in file order, or None unless there are
    exactly two (a third of the day, or fewer than two, is not a patch-diff pair)."""
    mine = [r for r in records if r.get("crc_ok") and isinstance(r.get("json"), dict) and _names_day(r, day)]
    uniq, seen = [], set()
    for r in mine:
        ident = r.get("plain")
        if ident not in seen:
            seen.add(ident)
            uniq.append(r)
    return (uniq[0], uniq[1]) if len(uniq) == 2 else None


def changed_keys(a, b):
    """The sorted keys whose values differ between two records' JSON objects, or None when the key sets
    differ (an added or removed key is not a changed field)."""
    ja, jb = a["json"], b["json"]
    if set(ja) != set(jb):
        return None
    return sorted(k for k in ja if ja[k] != jb[k])


def _side_of(records, pair, side, rs):
    """The pair record the byte-proven role markers name as `side` ('patched' or 'original'), or None. A
    record is of a side when its member name (a basename segment) or its own JSON (a role field, a campaign
    token) carries a word of it; the side is proven only when exactly one record of the pair is of it and
    not of the opposite side, and the other record is not of it at all."""
    words = PATCHED_SIDE if side == "patched" else ORIGINAL_SIDE
    opp = ORIGINAL_SIDE if side == "patched" else PATCHED_SIDE
    idx = [next(i for i, r in enumerate(records) if r is p) for p in pair]
    mine, theirs = set(), set()
    for w in words:
        mine |= set(rs._role_matches(records, w))
    for w in opp:
        theirs |= set(rs._role_matches(records, w))
    only = [k for k in (0, 1) if idx[k] in mine and idx[k] not in theirs]
    other_marked = [k for k in (0, 1) if idx[k] in mine]
    if len(only) == 1 and other_marked == only:
        return pair[only[0]]
    return None


FIRST_DIFF_BLOCK = 1 << 16


def _first_diff(x, y):
    """The index of the first byte where x and y differ; the shorter length when one is a prefix of the other;
    None when they are equal. Compared a block at a time (a bytes comparison is a memcmp), then halved inside
    the first block that differs: a byte loop over two 32 MiB builds took 1.2 s for one patch-offset id, inside
    a timed window and again for every Mastery set (review of KB-3, a6)."""
    n = min(len(x), len(y))
    i = 0
    while i < n:
        j = min(i + FIRST_DIFF_BLOCK, n)
        if x[i:j] != y[i:j]:
            lo, hi = i, j                       # [lo, hi) differs: keep the half that does
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if x[lo:mid] != y[lo:mid]:
                    hi = mid
                else:
                    lo = mid
            return lo
        i = j
    return n if len(x) != len(y) else None


def _fmt_offsets(value, hex_first):
    dec, hx = str(value), f"0x{value:x}"
    return [("hex", hx), ("decimal", dec)] if hex_first else [("decimal", dec), ("hex", hx)]


def _pair_scope(pa, pb, members=()):
    """A content-strong name for this delivery and pair of decoded payloads.

    This scope can turn a judge-accepted reading plain when the same delivery is replayed, so CRC-32 summaries are
    not identities: two chosen-collision artifacts could otherwise share an accepted label. Length-prefix every
    component so concatenation boundaries cannot alias, and retain the full SHA-256 digest.
    """
    h = hashlib.sha256()
    for name, data in members or ():
        m = data if isinstance(data, bytes) else (bytes(data) if isinstance(data, bytearray) else b"")
        nb = str(name).encode("utf-8", "replace")
        h.update(len(nb).to_bytes(8, "big"))
        h.update(nb)
        h.update(len(m).to_bytes(8, "big"))
        h.update(m)
    a = bytes(pa) if isinstance(pa, (bytes, bytearray)) else b""
    b = bytes(pb) if isinstance(pb, (bytes, bytearray)) else b""
    for payload in (a, b):
        h.update(len(payload).to_bytes(8, "big"))
        h.update(payload)
    return h.hexdigest()


def _distinct(opts):
    """The options whose value no other option shares. Two readings that render the same value on this variant (the
    record at offset 0 of its member: its record offset and its member offset coincide) cannot be told apart by an
    acceptance, and the name accepted would answer the next variant, where they differ, plain (fix round 2 of the
    review of KB-3): both are dropped."""
    count = {}
    for _name, value in opts:
        count[value] = count.get(value, 0) + 1
    return [(name, value) for name, value in opts if count[value] == 1]


def answer_for(kind, side, text, records, pair, members, rs, qid="", memo=None):
    """The unsure answer for one diff fact of the pair, or None when it is not established. `qid` and `text`
    scope the key (see _key); `memo` keeps a member comparison the ids of one prefix share. Every option is named
    `<reading>@<scope>`, the scope naming this pair of records (_pair_scope): an acceptance is a fact of THIS delivery,
    plain when the same delivery is replayed, a pick again on any other variant. Fix round 2 of the review of KB-3:
    the reader reads a few words of the question and leaves the rest ("changed to an empty string", "URL-valued",
    "still XOR-encoded", "shortened", "without any URL scheme", "negative if it got shorter"), and an acceptance on a
    variant where the rest did not matter turned the same wording plain and wrong on the next one."""
    a, b = pair
    pa, pb = a.get("plain"), b.get("plain")
    if memo is not None and "scope" in memo:
        scope = memo["scope"]                    # one delivery, one scope: the members are hashed once a prefix
    else:
        scope = "@" + _pair_scope(pa, pb, members)
        if memo is not None:
            memo["scope"] = scope
    ck = changed_keys(a, b)
    if kind == "key":
        if ck is None or len(ck) != 1:
            return None
        return labels.pick(_key("changed_key", qid, text), [("config_key" + scope, ck[0])])
    if kind == "count":
        if ck is None:
            return None
        return labels.pick(_key("changed_count", qid, text), [("differing_keys" + scope, str(len(ck)))])
    if kind == "value":
        if ck is None or len(ck) != 1 or side is None:
            return None
        rec = _side_of(records, pair, side, rs)
        if rec is None:
            return None
        v = rec["json"][ck[0]]
        if not isinstance(v, str):
            return None
        return labels.pick(_key(f"{side}_value", qid, text), [("changed_key_value" + scope, v)])
    hex_first = bool(re.search(r"\b0x\b|\bhex(?:adecimal)?\b", (text or "").lower()))
    if kind == "offset":
        opts = []
        if isinstance(pa, (bytes, bytearray)) and isinstance(pb, (bytes, bytearray)):
            d = _first_diff(bytes(pa), bytes(pb))
            if d is not None:
                opts += [(f"payload_first_diff_{n}{scope}", v) for n, v in _fmt_offsets(d, hex_first)]
                opts += [(f"record_first_diff_{n}{scope}", v) for n, v in _fmt_offsets(d + 12, hex_first)]
        ma, mb = a.get("_member_index"), b.get("_member_index")
        if ma is not None and mb is not None and ma != mb:
            if memo is None:
                memo = {}
            at = (id(members[ma][1]), id(members[mb][1]))
            if at not in memo:
                memo[at] = _first_diff(members[ma][1], members[mb][1])
            d = memo[at]
            if d is not None:
                # where the two member FILES first differ is no position of the record: a build stamp or padding
                # before it moves it anywhere
                opts += [(f"member_first_diff_{n}{scope}", v) for n, v in _fmt_offsets(d, hex_first)]
        opts = _distinct(opts)
        return labels.candidates(_key("diff_offset", qid, text), opts[:12]) if opts else None
    if kind == "size":
        opts = []
        if isinstance(pa, (bytes, bytearray)) and isinstance(pb, (bytes, bytearray)) and len(pa) == len(pb):
            opts.append(("payload_differing_bytes" + scope, str(sum(1 for x, y in zip(pa, pb) if x != y))))
        if isinstance(pa, (bytes, bytearray)) and isinstance(pb, (bytes, bytearray)):
            opts.append(("payload_length_delta" + scope, str(abs(len(pa) - len(pb)))))
        opts = _distinct(opts)
        return labels.candidates(_key("diff_size", qid, text), opts) if opts else None
    return None


def diff_answers(questions, members, get_records, day, rs, qid_of):
    """{qid: unsure value} for the open questions that ask a patch-difference fact, over the prefix's record
    pool; {} unless the pool holds exactly two distinct CRC-valid records of the day. `rs` is record_select
    (for the role markers). `get_records` is the pool, or a callable that builds it."""
    asked = []
    for q in questions:
        qid = qid_of(q)
        c = classify(qid, q.get("question") or "")
        if c is not None:
            asked.append((q, qid, c))
    if not asked:
        return {}
    records = get_records() if callable(get_records) else get_records
    pair = pair_of(records, day)
    if pair is None:
        return {}
    keys = set(pair[0]["json"]) | set(pair[1]["json"])
    out, memo = {}, {}
    for q, qid, (kind, side) in asked:
        toks = _tokens(qid.split("_", 1)[1] if "_" in qid else qid)
        if "config" in toks and toks.index("config") + 1 < len(toks) and \
                "_".join(toks[toks.index("config") + 1:]) in keys:
            continue                # a config member of a build (config_<key>) is a per-build question
        try:
            v = answer_for(kind, side, q.get("question") or "", records, pair, members, rs, qid, memo)
        except Exception as e:      # one id's failure costs that id only
            print(f"[patch_diff] {qid}: raised {type(e).__name__}: {e}", file=sys.stderr)
            v = None
        if v is not None:
            out[qid] = v
    return out
