#!/usr/bin/env python3
"""FOLDED INTO THE SHIPPED SOLVER (build night 2026-10-23): this was Day 23's in-run day_patch.py and is now loaded
by analyze.solve_set by name (day23_fold.patch), before the day_patch.py hook, so no live fix is needed for it.
Day 23 live fix (owner, script-analysis). The new tag `HUNTRESS_ANALYSIS_V1:LYR-<l1>_<l2>[_<l3>]-<payload>`
names its layers in ENCODING order (the plan is encoded by l1 first, l2 over that, ...), the payload being the
outermost result; decode = undo the last label first. Labels: hex, b64, b32, rev, frag (pieces joined by one
separator). Derived from the bytes only: a payload is accepted only when the decoded text is a plan by
descriptor.plan_text (the shipped grammar).

The decoded plan is substituted for the payload (comment and the bare literal copy alike) under the PLAIN tag,
and the shipped solver answers that text; its answers fill only ids it left None. Nothing is guessed. Since the
Day 27 review of the variants track a tag is rewritten only when its payload is the whole value (nothing but a
closer behind it on its line, no next line that reads as more of it, no copy that runs on into more of its
alphabet), and only whole copies are replaced: _rewrite."""
import base64
import contextlib
import io
import re
import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

LYR = re.compile(r"(HUNTRESS_ANALYSIS_V\d+:)LYR-([A-Za-z0-9_]+?)-([^\s\"'*<>\\]+)")
# Linear: every piece is a delimited string and the separator alternatives cannot match the same text.
ARR = re.compile(r'\[\s*((?:"[^"\\\n]*"(?:\s*,\s*|\s+)?)+)\]\.join\(""\)')
MAX_SCAN = 1 << 21      # bytes of text rewritten; a larger specimen is left as it is
LYRJ = re.compile(r"^LYR-([A-Za-z0-9_]+?)-(.+)$", re.S)
SEPS = ".-:,|;_ \t"


def _plan(label, payload):
    """The one plan the tag's payload decodes to (plan_layers: generic label table, depth 8, inverse search for
    an unknown label, accepted by the plan grammar alone), or None."""
    import plan_layers
    return plan_layers.decode_plan(label, payload)


# Day 27 (review of the variants track): a tag is rewritten only when its payload is the whole value. A tag whose
# comment goes on in its next line decodes, from its first line alone, to a plan PREFIX the grammar accepts (a hex
# or base64 head cut on a byte or group boundary); written back as a whole `PLAIN-` tag it read as whole (generic's
# cut False), and `str.replace` spliced the same prefix into the head of a whole literal copy. -indicator went out
# PLAIN as the cut plan's "first present" key, -file-path and -path-leaf PLAIN and truncated (Day 23 LYR specimens
# wrapped at 80 to 98 %: 41 of 160 wrong with the literal emptied, 11 of 160 with it kept).
#   A copy of a payload ends where no character of its alphabet stands: letters and digits, `+/_.:,%-` and every
# character of the payload itself. `=` closes a base64 or base32 text and never opens one, so it counts only behind
# a copy (`set "X=<payload>"` is a whole copy).
_ALPHA_MORE = frozenset("+/_.:,%-")
MAX_COPIES = 64          # copies of one payload looked at; a file with more is not rewritten


def _alpha(c, own):
    return c.isalnum() or c in _ALPHA_MORE or c in own


def _whole_at(text, i, n, own, tag_starts=()):
    """Whether the copy text[i:i+n] stands whole: no character of its alphabet right behind it, and none right
    before it (`=` aside), unless it is another tag's payload (whose front is the tag's own `-`)."""
    if i + n < len(text):
        c = text[i + n]
        if c == "=" or _alpha(c, own):
            return False
    if i > 0 and i not in tag_starts:
        c = text[i - 1]
        if c != "=" and _alpha(c, own):
            return False
    return True


def _copies_whole(text, payload, skip=(), tag_starts=()):
    """Whether every copy of `payload` in `text` that does not begin inside a `skip` span stands whole. A copy that
    runs on into more of its alphabet holds the payload as a piece of a longer value, and the tag may then itself be
    that piece (a wrapped comment's first line beside the whole literal). More than MAX_COPIES copies say no."""
    own, n, count = frozenset(payload), len(payload), 0
    i = text.find(payload)
    while i >= 0:
        if not any(a <= i < b for a, b in skip):
            count += 1
            if count > MAX_COPIES or not _whole_at(text, i, n, own, tag_starts):
                return False
        i = text.find(payload, i + 1)
    return True


def _replace_whole(text, payload, plan):
    """`text` with every whole copy of `payload` (_whole_at) replaced by `plan`; a copy that runs on into more of
    its alphabet is left as it stands (it was str.replace: a prefix spliced into a longer literal)."""
    own, n, out, pos = frozenset(payload), len(payload), [], 0
    i = text.find(payload)
    while i >= 0:
        if _whole_at(text, i, n, own):
            out.append(text[pos:i])
            out.append(plan)
            pos = i + n
            i = text.find(payload, pos)
        else:
            i = text.find(payload, i + 1)
    out.append(text[pos:])
    return "".join(out)


# A line break written as an escape inside a literal (`\n`, `\r\n`): a whole tagged script held in one escaped
# literal (row 371's escaped embedding; Day 25's .csx hosts: `"// HUNTRESS_ANALYSIS_V1:LYR-..-<payload>\n#nullable
# enable\n..."`). The payload's line in that script ends at the escape, and its next line is what follows it.
_ESC_NL = re.compile(r"(?:\\r)?\\n")
_CSX_NULLABLE = re.compile(
    r"[ \t]*#nullable[ \t]+(?:enable|disable|restore)"
    r"(?:[ \t]+(?:annotations|warnings))?[ \t]*(?://[^\r\n]*)?\r?"
)
_CSX_DESCRIPTOR = re.compile(
    r'\b(?:(?:public|private|protected|internal|static|readonly|const)\s+)*'
    r'(?:string|var)\s+descriptor_[A-Za-z0-9_]+\s*=\s*"([^"\\\r\n]+)"\s*;'
)
_HASH_DIRECTIVE = re.compile(r"[ \t]*#[ \t]*[A-Za-z][^\r\n]*\r?")
MAX_CSX_DESCRIPTOR_COPIES = 8


def _line_rest(text, m, used):
    """(rest of the payload's line, the embedded script after it or None): what stands behind the payload up to the
    end of its line, and, when that begins with an escaped line break, the rest of the embedded script with its
    escaped breaks made real ones (beginning with that break)."""
    start = m.start(4) + len(used)
    nl = text.find("\n", start)
    rest = text[start:nl if nl >= 0 else len(text)].rstrip("\r")
    if not _ESC_NL.match(rest):
        return rest, None
    return "", _ESC_NL.sub("\n", rest)


def _continues(text, m, used, plan, names):
    """Whether the line after the tag's own line reads as more of its payload; in an escaped embedding, the embedded
    script's next line. First descriptor.continued (the tag line's own leader, the encoding alphabet of the payload,
    a plain-word line that, joined to the payload, decodes to another plan); then, for any alphabet (base85, ascii85,
    z85 and base45 hold punctuation and blanks that rule does not read as payload: such wraps went out PLAIN and
    truncated), whether the next lines, each without its leader and a closer, joined to the payload decode to
    another plan than the payload alone."""
    import descriptor
    import plan_layers

    def rejoin(more):
        if len(used) + len(more) > plan_layers.MAX_PAYLOAD:
            return False
        other = plan_layers.decode_plan(names, used + more)
        return other is not None and other != plan

    seg = text[text.rfind("\n", 0, m.start()) + 1:m.start()]
    _rest, embedded = _line_rest(text, m, used)
    if embedded is not None:
        src, end, lead = embedded, 0, re.split(r'\\n|"', seg)[-1].strip()
    else:
        nl = text.find("\n", m.start(4) + len(used))
        if nl < 0:
            return False
        src, end, lead = text, (nl - 1 if nl > 0 and text[nl - 1] == "\r" else nl), seg.strip()
    if descriptor.continued(src, end, used, lead, rejoin if names else None, used):
        return True
    if not names:
        return False
    alphabet = descriptor._alphabet(used) | {"="}
    if re.search(r"\s", used):
        alphabet |= {" ", "\t"}                            # base45 text holds blanks
    # A payload of an alphabet with punctuation a line of code is written in (ascii85, base85, Z85 and their kind):
    # a next line of that alphabet that reads as encoded text (16 characters or more, or 8 or more of three of the
    # four kinds: small and capital letters, digits, punctuation) is taken for more of it even when the joined text
    # does not decode (a partial last group, a line continuation the payload's own alphabet holds); not rewriting
    # costs coverage only, a cut plan written back whole is a wrong PLAIN answer.
    exotic = bool(set(used) - set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_.:,%- \t"))
    more, at = "", end
    for _ in range(descriptor.CONT_JOIN):
        nxt = descriptor.next_line(src, at, lead)        # Day 27 (script residuals): past blank lines
        if not nxt:
            break
        bodies = _rejoin_bodies(nxt.group(1), lead, alphabet)
        if not bodies:
            break
        if any(rejoin(more + b) for b in bodies):
            return True
        if exotic and any(_encoded_look(b) for b in bodies):
            return True
        more, at = more + bodies[0], nxt.end()
    return False


def _encoded_look(s):
    """Whether a run reads as encoded text rather than a word or a name of code: no blank, not letters only, and 16
    characters or more, or 8 or more holding three of small letters, capitals, digits and punctuation."""
    if re.search(r"\s", s) or s.isalpha() or len(s) < 8:
        return False
    kinds = sum(1 for k in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]") if re.search(k, s))
    return len(s) >= 16 or kinds >= 3


def _rejoin_bodies(raw, lead, alphabet):
    """Readings of a next line as more of a payload, for the any-alphabet test of _continues: without the tag line's
    own leader or a comment leader (descriptor.LEADER, CONT_LEADER), without a closer or a line continuation behind
    it, its longest field, and its text after the first one or two fields; only those made of the payload's
    alphabet (descriptor._alphabet), at most 12."""
    import descriptor
    out = []
    st = raw.lstrip(" \t")
    bases = [raw.strip(), raw[descriptor.LEADER.match(raw).end():], raw[descriptor.CONT_LEADER.match(raw).end():]]
    if lead and st.startswith(lead):
        bases.insert(1, st[len(lead):])
    for b in bases:
        b = b.strip()
        for c in (b, descriptor._closer_off(b).strip(), b[:-1].rstrip() if b.endswith("\\") else b):
            fields = c.split()
            for x in [c] + ([max(fields, key=len)] + [" ".join(fields[k:]) for k in (1, 2) if len(fields) > k]
                            if len(fields) > 1 else []):
                if x and x not in out and set(x) <= alphabet:
                    out.append(x)
    return out[:12]


def _clean_tail(text, m, used):
    """Whether nothing but blanks, or a comment closer the descriptor reader takes off (descriptor.CLOSER: ` */`,
    ` -->`, `?>`), stands behind the payload on its line (or the payload's line in an escaped embedding ends right
    there). The reader takes a `PLAIN-` tag's payload to its line's end and glues whatever else stands there into
    the plan's last value (`next_stage=stage-1.py";`, `.."+"<rest>";` behind a payload cut by a string join): such a
    tag is not rewritten."""
    import descriptor
    tail = _line_rest(text, m, used)[0].rstrip()
    return not tail or descriptor.CLOSER.fullmatch(tail) is not None


def _note(why):
    print(f"[day23_fold] NOTE {why}", file=sys.stderr)


def _csx_nullable_copies(text, m, used, member):
    """Whether a C# ``#nullable`` line is a directive, not more encoded payload.

    The continuation guard is intentionally conservative for arbitrary source lines.  A ``.csx``
    specimen can prove this one boundary structurally when the next physical line is exactly a C#
    nullable directive and one or more typed ``descriptor_*`` literals independently hold the
    complete, byte-identical payload.  Up to eight identical literal witnesses are bounded here;
    one differing, untyped or ninth copy refuses the shape.

    The return value is the literal-copy count.  ``patch`` uses counts above one to keep the newly
    supported redundant-literal shape candidate-only, so this coverage cannot widen plain output.
    """
    if not isinstance(member, str) or not member.lower().endswith(".csx"):
        return 0
    end = text.find("\n", m.start(4) + len(used))
    if end < 0:
        return 0
    next_end = text.find("\n", end + 1)
    line = text[end + 1:next_end if next_end >= 0 else len(text)]
    if _CSX_NULLABLE.fullmatch(line) is None:
        return 0
    literals = [hit.group(1) for hit in _CSX_DESCRIPTOR.finditer(text)]
    if not 1 <= len(literals) <= MAX_CSX_DESCRIPTOR_COPIES or any(value != used for value in literals):
        return 0
    return len(literals) if text.count(used) == len(literals) + 1 else 0


def _csx_nullable_boundary(text, m, used, member):
    return bool(_csx_nullable_copies(text, m, used, member))


def _csx_hash_directive_after(text, m, used, member):
    """Whether a ``.csx`` tag's next physical line is hash-prefixed source syntax.

    A C# directive may be a real boundary, but no generic directive proves that the tag's first
    line is a complete payload. Only _csx_nullable_copies supplies the independently equal typed
    witness needed to cross that boundary. Other languages keep their established continuation
    rules: in particular, WMI MOF uses ``#pragma namespace`` after every complete descriptor tag.
    """
    if not isinstance(member, str) or not member.lower().endswith(".csx"):
        return False
    end = text.find("\n", m.start(4) + len(used))
    if end < 0:
        return False
    next_end = text.find("\n", end + 1)
    line = text[end + 1:next_end if next_end >= 0 else len(text)]
    return _HASH_DIRECTIVE.fullmatch(line) is not None


def _redundant_csx_nullable(text, member):
    """Whether one exact LYR tag has two-plus identical typed descriptor witnesses."""
    try:
        import plan_layers
        matches = list(plan_layers.TAG_RE.finditer(text))
        if len(matches) != 1:
            return False
        m = matches[0]
        plan, used = plan_layers.plan_for_tag(m.group(2), m.group(3), text, m.start(4), m.group(4))
        return plan is not None and _csx_nullable_copies(text, m, used, member) > 1
    except Exception:
        return False


def _rewrite(text, member=None):
    if len(text) > MAX_SCAN or '.join("")' not in text and "HUNTRESS_ANALYSIS_V" not in text:
        return None
    import plan_layers
    seen = {}
    parts, pos = [], 0
    tag_starts = frozenset(m.start(4) for m in plan_layers.TAG_RE.finditer(text))
    for m in plan_layers.TAG_RE.finditer(text):
        if m.start() < pos:
            continue
        plan, used = plan_layers.plan_for_tag(m.group(2), m.group(3), text, m.start(4), m.group(4))
        # B-247 (row 501): a backslash (a Windows path, `file_path=C:\..`) is written escaped where a literal needs
        # it (_BACKSLASH below), no longer a reason to leave the tag unread. A quote or a line break still is.
        if plan is None or "\n" in plan or '"' in plan or "'" in plan:
            continue
        try:
            if not _clean_tail(text, m, used):
                _note(f"the {m.group(2)} tag at offset {m.start()} has more than a closer behind its payload on its "
                      f"line: written as a PLAIN tag that text would join its plan's last value; not rewritten")
                continue
            nullable_copies = _csx_nullable_copies(text, m, used, member)
            if _csx_hash_directive_after(text, m, used, member) and not nullable_copies:
                _note(f"the {m.group(2)} tag at offset {m.start()} is followed by hash-prefixed source syntax, but "
                      "has no exact .csx nullable boundary with an equal typed descriptor witness; not rewritten")
                continue
            if (_continues(text, m, used, plan, plan_layers.labels_of(m.group(3))) and not nullable_copies):
                _note(f"the {m.group(2)} tag at offset {m.start()} goes on in its next line (a wrapped comment): its "
                      f"first line alone decodes to a plan that may be a prefix; not rewritten")
                continue
            if not _copies_whole(text, used, ((m.start(4), m.start(4) + len(used)),), tag_starts):
                _note(f"a copy of the {m.group(2)} tag's payload (offset {m.start()}) runs on into more of its "
                      f"alphabet: the tag may hold a piece of the value; not rewritten")
                continue
        except Exception as e:  # noqa: BLE001 - a check that fails proves nothing whole: the tag is left as it is
            _note(f"the {m.group(2)} tag at offset {m.start()} could not be checked ({type(e).__name__}); not rewritten")
            continue
        seen[used] = plan
        parts.append(text[pos:m.start()])
        parts.append(m.group(1) + "PLAIN-" + plan)
        pos = m.start(4) + len(used)
    parts.append(text[pos:])
    new = "".join(parts)

    def pieces(m):
        return "".join(re.findall(r'"([^"\\\n]*)"', m.group(1)))

    def arr1(m, src=new):
        mm = plan_layers.TAG_JOINED.match(pieces(m))
        if not mm:
            return m.group(0)
        plan = plan_layers.decode_plan(mm.group(2), mm.group(3)) if plan_layers.tag_prefix_ok(mm.group(1)) else None
        if plan is None or '"' in plan or "\n" in plan:
            return m.group(0)
        if not _copies_whole(src, mm.group(3), ((m.start(), m.end()),)):
            _note("a copy of a joined tag's payload runs on into more of its alphabet; not rewritten")
            return m.group(0)
        seen[mm.group(3)] = plan
        return '["PLAIN-' + _js_escaped(plan) + '"].join("")'    # a JavaScript string: `\` is written `\\`

    new = ARR.sub(arr1, new)

    def arr2(m):
        j = pieces(m)
        if j in seen:
            return '["' + _js_escaped(seen[j]) + '"].join("")'
        return m.group(0)

    new = ARR.sub(arr2, new)
    if not seen:
        return None
    if not any("\\" in plan for plan in seen.values()):
        for payload, plan in seen.items():
            new = _replace_whole(new, payload, plan)
        return new
    return _backslash_rewrite(new, seen, member)


def _js_escaped(plan):
    return plan.replace("\\", "\\\\")


def _backslash_rewrite(new, seen, member):
    """B-247 (row 501): the whole literal copies of a plan that holds a backslash. Whether a literal undoes `\\`
    depends on its language and quotes (C, Python and JavaScript strings do; VBScript, PowerShell's single quotes
    and a shell's do not), so each spelling is tried, escaped first and then as it stands, and the first whose
    rewritten text the lane reads back as the very plan decoded (generic.read) is kept. When neither does, the tag
    is not rewritten: a safe no-substitution, never a plan read otherwise."""
    import plan_codec
    generic = plan_codec.own("generic")
    want = set(seen.values())
    for spell in (_js_escaped, lambda p: p):
        out = new
        for payload, plan in seen.items():
            out = _replace_whole(out, payload, spell(plan))
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                got = generic.read(member or "specimen.txt", out.encode("utf-8"))
        except Exception as e:  # noqa: BLE001 - a read that fails proves nothing: try the next spelling
            _note(f"reading back a backslash plan's rewrite raised {type(e).__name__}; that spelling is not kept")
            continue
        if got.get("plan_text") in want and not got.get("cut") and not got.get("ambiguous"):
            return out
    _note("a plan with a backslash is not read back as itself in either spelling of its literal; not rewritten")
    return None


import json as _json
import labels  # noqa: E402

JOIN = "|"
INDICATOR_ORDER = ("url", "upload_url", "next_stage", "file_path", "cron_path", "schedule_path", "task_path",
                   "registry_path", "task_name", "note_name", "recovery_note", "host_id")
# The plan keys the judge took as the first indicator present: the seven names of the order its question states
# ("URL, upload URL, next-stage file, file path, schedule path, recovery-note name, host id", the one wording of
# all 2,090 -indicator questions of Days 23 to 26), each CORRECT in a judged batch on those days. The order's
# other keys are the fold's own guesses (a synonym of a listed name, or a key the stated order does not name):
# never judged as an indicator, so one of them first is an unsure pick of its own (_indicator), never plain.
JUDGED_INDICATORS = frozenset(("url", "upload_url", "next_stage", "file_path", "schedule_path", "note_name", "host_id"))
SYN_FMT = {"kind": "exact_text", "syntax": "exact artifact-derived value only, without quotes or explanatory text "
                                           "unless quotes are part of the value"}


FIELD_WORDS = ("campaign-token", "url-host", "path-leaf", "indicator", "style", "carrier", "secondary", "tertiary", "obfuscation", "url")
# The only field words whose branch reads `plan` (_plan_of). When a specimen asks none of them, _plan_of is not
# called at all: the plan it would read is never used, so skipping it changes no answer (perf, 2026-10-24). The
# Day 18 Mastery asks none of these, so its 655 specimens skip _plan_of entirely.
_PLAN_FIELDS = frozenset(("campaign-token", "url-host", "path-leaf", "indicator", "carrier", "obfuscation"))


_SET_PREFIX = re.compile(r"^set\d+\.")
_FIELD_RES = tuple((w, re.compile(r"-[0-9a-f]{6}-" + re.escape(w) + "$")) for w in FIELD_WORDS)
_TAILS = {}          # qid text -> its field word: a pure function of the text (perf, Day 27 speed build)


def _tail(qid):
    """The field word an id ends in (FIELD_WORDS, first match in their order), or "". The same patterns as
    before, compiled once, and each id's word kept: patch() asks it of every question two or three times."""
    q = str(qid)
    got = _TAILS.get(q)
    if got is None:
        got = ""
        q2 = _SET_PREFIX.sub("", q)
        for w, rx in _FIELD_RES:
            if rx.search(q2):
                got = w
                break
        if len(_TAILS) > 65536:
            _TAILS.clear()
        _TAILS[q] = got
    return got


def _plain(v):
    return isinstance(v, str) and v != "" and not v.startswith("??")


def _first(v):
    """A plain string for a plain answer, the first option of an unsure one, else None. Only for comparing a
    joined value with a shipped plain answer (`extends` below): nothing derives an answer from it (_proven)."""
    if _plain(v):
        return v
    try:
        got = labels.parse(v) if isinstance(v, str) else None
        if got:
            return str(got[1][0][1])
    except Exception:  # noqa: BLE001
        pass
    return None


def _proven(v):
    """A plain answer as it stands, else None: the only source a derived answer (a campaign token, a url host, a
    path leaf, a part of a joined style) may rest on. The first option of an unsure answer proves nothing (a
    `one_copy` pick holds the value a cut copy may hold cut, a pick's first spelling is one the judge has not
    accepted, a candidates pick is one of several values), and the judge accepting the DERIVATION's name
    (after_first_hyphen, hostname, last_segment, joined_bar) says nothing about that value. Day 27: a wrapped
    tagged comment with no literal left `-file-path` unsure as one_copy `/tmp/h`, and `-path-leaf` went out
    PLAIN as `h` under the judged script.path_leaf/any.last_segment."""
    return v if _plain(v) else None


def _nested(plan_text):
    """Whether a JSON plan holds structure plan_codec.flatten does not lift whole into its flat table: an object or
    a list inside a nested object, a list that holds an object or a list, more than one nested object (with two,
    which of them the question means is not known), a nested object that names a key of the top level, or a JSON
    text that does not parse here. An indicator may stand there, ahead in the order of the first one the flat table
    shows (review of the variants track, Day 27: a url under `values.network` or in `values.endpoints[0]` was
    invisible and file_path went out PLAIN "first present"). None of the 2,205 JSON plans of the saved Script
    deliveries of Days 1 to 26 (20,344 distinct member texts) is so: each has one nested object, `values`."""
    if not isinstance(plan_text, str) or not plan_text.lstrip().startswith("{"):
        return False
    try:
        d = _json.loads(plan_text)
    except ValueError:
        return True
    if not isinstance(d, dict) or sum(1 for v in d.values() if isinstance(v, dict)) > 1:
        return True
    names = {k for k, v in d.items() if not isinstance(v, dict)}
    for v in d.values():
        if isinstance(v, list) and any(isinstance(x, (dict, list)) for x in v):
            return True
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if isinstance(v2, (dict, list)) or k2 in names:
                    return True
                names.add(k2)
    return False


def _plan_of(member, data, questions=(), loose=False):
    """(plan, cut, meta): the plan generic.read gives the specimen (a JScript plan's `values` lifted to the top),
    whether generic took it WITHOUT ITS LAST FIELD (`info["cut"]`: a piece of its material, one copy of a
    descriptor, a plan shorter than its version, a binary carrier's strings), and what else bears on an answer
    derived from it: meta["nested"] (_nested) and meta["one_copy"] (the key of the last field a WRAPPED comment's
    plan was taken without: the sibling id that asks it holds that cut copy's value). A cut plan's values are whole,
    but a key it lacks is NOT proven absent: the left-out last field (and whatever a piece did not reach) may be it.

    Read as generic.answers reads it (review of the variants track, Day 27): `loose` when the member is the strings
    of a binary carrier (analyze's ctx["strings_views"]; generic.read's loose_lines, whose last value is not
    trusted), and a descriptor plan that lacks a field the specimen's questions ask (generic.DESCRIPTOR_FIELDS) is no
    plan, as generic.answers takes it ("a cut plan, nothing is answered from it"). Before, the fold read the
    strings of a UTF-16 .py as a whole plan the main path cut, and answered its next_stage PLAIN."""
    import plan_codec
    generic = plan_codec.own("generic")      # never `import generic`: solvers/binary has one too (SH-05)
    meta = {"nested": False, "one_copy": None}
    try:
        info = generic.read(member, data, bool(loose))
        plan = dict(info.get("plan") or {})
        cut = bool(info.get("cut"))
        oc = info.get("one_copy")
        if isinstance(oc, (tuple, list)) and oc and info.get("one_copy_wrapped"):
            meta["one_copy"] = str(oc[0])        # a wrapped comment's left-out field (generic: one_copy_wrapped)
        meta["nested"] = _nested(info.get("plan_text"))
        if info.get("descriptor") and plan and questions:
            asked = {generic.DESCRIPTOR_FIELDS[t] for t in (generic.tail_of(q) for q in generic.with_fields(list(questions)))
                     if t in generic.DESCRIPTOR_FIELDS}
            if asked - (info.get("descriptor_keys") or set(plan)) and not info.get("short_format"):
                plan, cut = {}, False
    except Exception:  # noqa: BLE001
        plan, cut = {}, False
    vals = plan.get("values")
    if isinstance(vals, dict):
        for k, v in vals.items():
            plan.setdefault(k, v)
    return plan, cut, meta


# The order every saved -indicator question states (all 2,090 of Days 23 to 26: "... submit the first indicator
# present in the decoded descriptor using this order: URL, upload URL, next-stage file, file path, schedule path,
# recovery-note name, host id."), as the plan keys its names stand for, and those names as _stated_order reads them.
STATED_ORDER = ("url", "upload_url", "next_stage", "file_path", "schedule_path", "note_name", "host_id")
ORDER_ITEMS = {"url": "url", "upload url": "upload_url", "next stage file": "next_stage", "file path": "file_path",
               "schedule path": "schedule_path", "recovery note name": "note_name", "host id": "host_id"}
_ORDER_LIST = re.compile(r"(?i)\border\b[ \t]*[:=][ \t]*([^.;:\n]+)")
_ORDER_SPLIT = re.compile(r"(?i),|>|\bthen\b|\band\b|\bor\b")
_ITEM_RE = re.compile(r"\b(recovery note name|next stage file|schedule path|upload url|file path|host id|url)\b")
# Words that ask for another indicator than the first present one, or for several (a text holding one is not
# answered: which indicator it asks is not this fold's to say).
_NOT_FIRST = re.compile(r"(?i)\b(?:last|final|second|third|fourth|fifth|latest|lowest|bottom|reversed?|absent|missing|"
                        r"except|besides|indicators)\b|\bother\s+than\b|\b(?:every|each|all)\s+(?:of\s+the\s+)?"
                        r"(?:present\s+)?indicator")


def _norm(s):
    return re.sub(r"\s+", " ", re.sub(r"[-_]", " ", s.lower())).strip()


def _stated_order(text):
    """The order an -indicator question states, as plan keys (review of the variants track, Day 27: the fold walked
    its own order whatever the text said). STATED_ORDER for the judged wording, and for a text that states no
    order (the id's field word answers it, as before: a cosmetic rewording never stops the lane); another tuple for
    the same names in another order, or a part of them; None for a text that asks something else: another than the
    first present (_NOT_FIRST), or a list holding a name the table does not know or one name twice."""
    if not isinstance(text, str) or not text.strip():
        return STATED_ORDER
    if _NOT_FIRST.search(text):
        return None
    m = _ORDER_LIST.search(text)
    if m:
        keys = []
        for item in _ORDER_SPLIT.split(m.group(1)):
            x = re.sub(r"^(?:the|an?) ", "", _norm(item))
            if not x:
                continue
            k = ORDER_ITEMS.get(x)
            if k is None or k in keys:
                return None
            keys.append(k)
        return tuple(keys) if keys else None
    keys = [ORDER_ITEMS[x] for x in _ITEM_RE.findall(_norm(text))]
    if len(keys) < 2:
        return STATED_ORDER
    return tuple(keys) if len(set(keys)) == len(keys) else None


def _indicator(qid, plan, cut, nested=False, text=""):
    """The `-indicator` answer ("the first indicator present in the decoded descriptor using this order: URL,
    upload URL, next-stage file, file path, ..."): the plan's first key in INDICATOR_ORDER, under the judged key
    script.indicator/any.first_present, or None.

    "First present" is an ABSENCE claim about every key ahead of the one taken, and only a whole plan proves an
    absence. A cut plan (`_plan_of`) has whole values, but the field generic left out, and whatever a piece of
    the material did not reach, may be a key ahead in the order, so from a cut plan only the order's first key
    (url) is answered. Day 27, tests/variants.py --lane script wrong=44 (every one this id, in Day 23 to 26
    Python specimens; the branch is the Day 23 live fix as folded by 942ef7b): the plans end
    `..|file_path=C:/ProgramData/HuntressLab/.update-N.py|next_stage=stage-N.py`, and with the material cut
    over variables (`vars`, `comments`; `concat` and `decoy` for one specimen) generic read the plan without
    next_stage, and file_path went out PLAIN. A key that is there with no text value (empty, or not a string)
    is the first one present all the same: it is not passed over for the next key; the id stays open. And a
    first key the judge never took as an indicator (not in JUDGED_INDICATORS: whether it stands for a name of
    the stated order, and where, is unjudged) is an unsure pick under a key of its own,
    script.indicator/any.first_present_<key>, which a base probe settles.

    The review's fix round: no absence is proven either by a JSON plan whose structure is deeper than its flat
    table (`nested`, _nested), or for an order the question does not state (`text`, _stated_order): a text that
    asks another than the first present indicator is not answered, and the same names in another order are an
    unsure pick under script.indicator/any.first_present_reordered (the judge took the first-present reading in
    the stated order only), never plain."""
    order = _stated_order(text)
    if order is None:
        print(f"[day23_fold] NOTE {qid}: the question asks for another than the first indicator present, or names "
              f"an indicator this fold does not know; left open", file=sys.stderr)
        return None
    if nested:
        print(f"[day23_fold] NOTE {qid}: the plan's JSON nests deeper than its flat table, so no indicator ahead of "
              f"the first one seen is proven absent; left open", file=sys.stderr)
        return None
    if order != STATED_ORDER:
        return _reordered(qid, plan, cut, order)
    for i, k in enumerate(INDICATOR_ORDER):
        if k not in plan:
            continue
        v = plan[k]
        if not (isinstance(v, str) and v):
            print(f"[day23_fold] NOTE {qid}: the plan's first indicator in the order, {k!r}, has no text value; "
                  f"left open", file=sys.stderr)
            return None
        if cut and i > 0:
            print(f"[day23_fold] NOTE {qid}: the plan was read without its last field, so no indicator ahead of "
                  f"{k!r} in the order is proven absent; left open", file=sys.stderr)
            return None
        if k not in JUDGED_INDICATORS:
            return labels.pick(f"script.indicator/any.first_present_{k}", [("first_present", v)])
        return labels.pick("script.indicator/any.first_present", [("first_present", v)])
    return None


def _reordered(qid, plan, cut, order):
    """The first indicator present in the order a reworded question states (`order`, plan keys), an unsure pick
    under script.indicator/any.first_present_reordered, or None: from a cut plan only the order's first key, a key
    with no text value is no answer, and where a key this fold only guesses at (INDICATOR_ORDER beyond the judged
    seven) stands in the stated order is unknown, so a plan holding one is not answered."""
    if any(k in plan for k in INDICATOR_ORDER if k not in JUDGED_INDICATORS):
        print(f"[day23_fold] NOTE {qid}: the question states its own order and the plan holds an indicator key it "
              f"does not name; left open", file=sys.stderr)
        return None
    for i, k in enumerate(order):
        if k not in plan:
            continue
        v = plan[k]
        if not (isinstance(v, str) and v) or (cut and i > 0):
            return None
        return labels.pick("script.indicator/any.first_present_reordered", [("stated_order", v)])
    return None


def _ps_json(text):
    """The one JSON object a PowerShell specimen's FromBase64String('..') literals decode to, or None: none, or two
    that differ (which of them is the specimen's configuration is not known; the fold read the first one alone, review
    of the variants track, Day 27). Each of the 606 saved .ps1 member texts that holds such a literal holds one, flat:
    strings and lists of strings."""
    found = []
    for m in re.finditer(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", text):
        try:
            d = _json.loads(base64.b64decode(m.group(1)).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(d, dict) and d not in found:
            found.append(d)
        if len(found) > 1:
            return None
    return found[0] if found else None


def _ps_fields(d):
    # "The one https value", "the first wallet_/RECOVERY/Global\ value" are claims about the whole object: a value
    # nested in an object or a list of objects or lists may be another one (review of the variants track, Day 27;
    # every saved object is flat), so a nested object answers nothing.
    if any(isinstance(v, dict) or (isinstance(v, list) and any(isinstance(x, (dict, list)) for x in v))
           for v in d.values()):
        return None, None, None
    vals = list(d.values())
    strs = [v for v in vals if isinstance(v, str)]
    lists = [v for v in vals if isinstance(v, list) and v]
    urls = [v for v in strs if v.startswith("https://")]
    url = urls[0] if len(urls) == 1 else None
    if len(urls) > 1:
        url = labels.candidates("script.url/powershell.json_https", [("first_https", urls[0]), ("last_https", urls[-1])])
    wallet = next((v for v in strs if v.startswith("wallet_")), None)
    note = next((v for v in strs if v.startswith("RECOVERY")), None)
    mutex = next((v for v in strs if v.startswith("Global\\")), None)
    ua = next((v for v in strs if v.startswith("Mozilla/")), None)
    ext = next((v for v in strs if v.startswith(".locked")), None)
    if wallet:
        return url, wallet, mutex
    if note:
        return url, note, ext
    if lists:
        return url, str(lists[0][0]), ua
    return url, None, None


def _batch_shape(text):
    """The code's own expansion form of the line that assembles the plan variable (batch.expansion_shape's order:
    FOR, CALL, delayed, percent); the third style label,
    5 of 5 judged specimens on Day 23."""
    t = "\n".join(l for l in text.splitlines() if not re.match(r"\s*(rem\b|::)", l, re.I))
    if re.search(r"(?i)\bfor\s+%%\w\s+in\s*\([^)]*\)\s+do\s+call\s+set\b", t):
        return "for_indirect"
    if re.search(r"(?i)\bcall\s+set\b[^\n]*%%[^%\s]+%%%%", t):
        return "call_double"
    if re.search(r"(?i)\bset\s+\"?\w+=(?:!\w+!){2,}", t):
        return "delayed"
    if re.search(r"(?i)\bset\s+\"?\w+=(?:%\w+%){2,}", t):
        return "percent"          # judged on Day 23 (batch-2222ac-style), unlike the expansion field's `delayed`
    return None


def _style(member, comp, qs_all, files_seen, answers):
    """(parts, raw, key): the joined style's parts as the language module answers them on three synthetic
    questions (`raw`: plain, unsure or None) and as a derived answer may rest on them (`parts`: _proven), and the
    joined key."""
    import analyze
    stem = member.split(".")[0]
    text = bytes(files_seen[member]).decode("utf-8", "replace") if member in files_seen else ""
    if comp == "jscript":
        import jscript
        info = jscript.analyze(text)
        parts = [info.get("function_style"), info.get("invocation_style"), info.get("property_style")]
        return parts, list(parts), "script.style/js.joined"
    fields = {"batch": ("graph", "control", "expansion"), "vbscript": ("representation", "transform", "control")}[comp]
    base = [q for q in qs_all if _tail(q["qid"]) == "style"][0]
    syn = [dict(base, qid=f"{comp}-{stem}-{f}", id=f"{comp}-{stem}-{f}", field=f, question="") for f in fields]
    with contextlib.redirect_stderr(io.StringIO()):
        r = analyze.solve_set(syn, files_seen, {}) or {}
    # A part the module answered unsure is no part (_proven): the joined key's accepted name says nothing about
    # the first spelling of an unjudged field, so such a composite stays open (Day 27). On the saved Day 23 to 26
    # specimens a VBScript specimen's three parts are plain; a Batch specimen's graph and control are plain and its
    # expansion part is None (these questions carry the style question's format, not the expansion enum), so its
    # composite is made from batch.statement_form in patch(), never from that part.
    raw = [r.get(q["qid"]) for q in syn]
    return [_proven(v) for v in raw], raw, f"script.style/{comp}.joined"


def _sibling(cur, qid, word, sib, one_copy):
    """The plain answer of the sibling id a derived id rests on (`<id without word><sib>`), else None. None also
    when the sibling asks the last field a WRAPPED comment's plan was taken without (`one_copy`): its answer is that
    cut copy's value (review of the variants track, Day 27). Its pick is unsure under one_copy_wrapped today, which
    _proven already refuses; this holds should that key ever take a name. An unwrapped copy's one_copy answer, plain
    by its extension's judged name (script.file_path/ahk.one_copy, /escript.one_copy), still derives: the .ahk path
    leaves of the saved Day 23 to 26 Time Trials and Masteries (152 judged answers) are derived so."""
    if one_copy:
        return None
    return _proven(cur.get(qid[: -len(word)] + sib))


def _one_copy_leaf(cur, qid, ext, wrapped=False):
    """An unsure leaf derived from the one byte-established value of an unwrapped one-copy file path.

    The file-path spelling is not yet judged, so its leaf cannot use the accepted ``any.last_segment`` key: that
    would turn it plain.  Keep the derived fact under a fresh extension/shape key until the judge accepts its name.
    A wrapped copy remains refused because its final value may itself be cut (Day 27 guard).
    """
    if wrapped:
        return None
    raw = cur.get(qid[: -len("-path-leaf")] + "-file-path")
    parsed = labels.parse(raw) if isinstance(raw, str) else None
    expected = f"script.file_path/{ext or 'ext'}.one_copy"
    if parsed is None or parsed.key != expected or len(parsed.options) != 1:
        return None
    name, path = parsed.options[0]
    if name != "as_read" or not isinstance(path, str) or not path.strip():
        return None
    leaf = re.split(r"[\\/]", path.rstrip("/\\"))[-1]
    if not leaf:
        return None
    return labels.pick(f"script.path_leaf/{ext or 'ext'}.one_copy_leaf", [("last_segment_of_as_read", leaf)])


# analyze.solve_set passes its ctx to patch() (ctx["strings_views"]: the members read as a binary carrier's strings).
PATCH_TAKES_CTX = True


def patch(member, questions, answers, files, ctx=None):
    out = {}
    data = files.get(member)
    if not isinstance(data, (bytes, bytearray)):
        for k, v in files.items():
            if k == member or k.endswith(member):
                data = v
                break
    if not isinstance(data, (bytes, bytearray)):
        return out
    data = bytes(data)
    text = data.decode("utf-8", "replace")
    asked = {q["qid"] for q in questions}
    # The strings of a binary carrier (analyze.strings_view or container_view named the member): their line ends
    # are not the file's own and the general path does not trust the plan's last value (generic.read loose_lines).
    # The plan read here and the rewritten text solved here are read the same way (review of the variants track).
    loose = isinstance(ctx, dict) and member in (ctx.get("strings_views") or ())
    used = data
    if "LYR-" in text or "HUNTRESS_ANALYSIS_V" in text:
        redundant_nullable = _redundant_csx_nullable(text, member)
        new = _rewrite(text, member=member)
        if new is not None:
            used = new.encode("utf-8")
            import analyze
            with contextlib.redirect_stderr(io.StringIO()):
                sub = analyze.solve_set(list(questions), {member: used}, {"strings_views": {member}} if loose else {})
            for qid, v in (sub or {}).items():
                if qid in asked and v is not None and answers.get(qid) is None:
                    if redundant_nullable and isinstance(v, str) and labels.parse(v) is None:
                        field = _tail(qid).replace("-", "_")
                        v = labels.candidates(
                            f"script.{field}/csx.redundant_identical#candidates",
                            [("identical_descriptor_copies", v)],
                        )
                    out[qid] = v
    cur = dict(answers)
    cur.update(out)
    plan, cut, meta = (_plan_of(member, used, questions, loose) if any(_tail(q["qid"]) in _PLAN_FIELDS for q in questions)
                       else ({}, False, {}))
    oc = meta.get("one_copy")
    ps = _ps_json(text) if member.lower().endswith(".ps1") else None
    comp = member.split(".")[-1]
    for q in questions:
        qid = q["qid"]
        f = _tail(qid)
        cprefix = qid.split("-")[0]
        try:
            val = None
            if f == "campaign-token":
                cid = plan.get("campaign_id") or _sibling(cur, qid, "-campaign-token", "-campaign", oc == "campaign_id")
                if isinstance(cid, str) and "-" in cid:
                    val = labels.pick("script.campaign_token/any.after_first_hyphen",
                                      [("after_first_hyphen", cid.split("-", 1)[1])])
            elif f == "url-host":
                u = plan.get("url") or _sibling(cur, qid, "-url-host", "-url", oc == "url")
                if isinstance(u, str) and "://" in u:
                    host = u.split("://", 1)[1].split("/", 1)[0].split(":")[0]
                    val = labels.pick("script.url_host/any.hostname", [("hostname", host)])
            elif f == "path-leaf":
                p = plan.get("file_path") or _sibling(cur, qid, "-path-leaf", "-file-path", oc == "file_path")
                if isinstance(p, str) and p:
                    val = labels.pick("script.path_leaf/any.last_segment",
                                      [("last_segment", re.split(r"[\\/]", p.rstrip("/\\"))[-1])])
                elif not p:
                    val = _one_copy_leaf(cur, qid, comp, wrapped=oc == "file_path")
            elif f == "indicator":
                # an absence claim: a whole plan only (but for the order's first key), in the order the question
                # states, from a JSON plan no deeper than its flat table
                val = _indicator(qid, plan, cut, meta.get("nested", False), q.get("question") or q.get("text") or "")
            elif f == "carrier" and cprefix == "python":
                c, w = plan.get("carrier"), plan.get("windows_chain")
                if isinstance(c, str) and c and isinstance(w, str) and w:
                    val = labels.pick("script.carrier/py.carrier_chain", [("carrier_chain", c + JOIN + w)])
            elif f == "obfuscation" and cprefix == "python":
                sy, ob = plan.get("syntax"), plan.get("obfuscation")
                if isinstance(sy, str) and sy and isinstance(ob, str) and ob:
                    val = labels.pick("script.obfuscation/py.syntax_obfuscation", [("syntax_obfuscation", sy + JOIN + ob)])
            elif f == "style" and cprefix in ("jscript", "batch", "vbscript"):
                parts, raw, key = _style(member, cprefix, questions, {member: used}, cur)
                if parts and all(isinstance(x, str) and x for x in parts):
                    val = labels.pick(key, [("joined_bar", JOIN.join(parts))])
                elif cprefix == "batch" and parts[0] and parts[1] and isinstance(raw[2], str) and raw[2].startswith("??"):
                    # The module answered the expansion part UNSURE (review of the variants track, Day 27): before
                    # the _proven rule this composite was an unsure script.style/batch.joined pick (its first
                    # spelling); the statement_form path below would now send it PLAIN, a widening. It stays
                    # unsure: the candidates pick of the ambiguous case, statement_form's form (when definite) and
                    # the module's own options first in the probe order.
                    import batch as _bat
                    FORMS = ("percent", "delayed", "call_double", "for_indirect")
                    sf = _bat.statement_form(text)
                    got = labels.parse(raw[2]) if isinstance(raw[2], str) else None
                    hint = ([sf] if sf in FORMS else []) + [str(o[1]) for o in ((got or (None, []))[1] or ())
                                                            if str(o[1]) in FORMS]
                    guess = _batch_shape(text)
                    order = list(dict.fromkeys(hint + ([guess] if guess in FORMS else []) + list(FORMS)))
                    val = labels.candidates("script.style/batch.expansion#cand",
                                            [(f"expansion_{h}", f"{parts[0]}|{parts[1]}|{h}") for h in order])
                elif cprefix == "batch" and parts[0] and parts[1]:
                    # The batch `style` composite is `<graph>|<control>|<expansion form>`. graph and control are
                    # deterministic and are parts[0]/parts[1]. The third label is the per-specimen expansion form
                    # of the ONE descriptor reconstruction statement, which Day 23 judged PLAIN under the
                    # expansion enum.
                    #   batch.statement_form reads that one statement, uniqueness-guarded. When it is DEFINITE it
                    # is a byte-exact fact -- proven on every saved specimen (Days 23+24: 153/153 always definite
                    # and never wrong; Days 23-25 together: 243/243 batch-style ids, graph|control|statement_form
                    # == key.json, 0 mismatch, _batch_shape never needed) and the Day 25 Time Trial accepted all
                    # 9 composites at the first send. So when it is DEFINITE we ship the composite PLAIN, exactly
                    # as JScript and VBScript ship their joined style (`labels.pick(... joined_bar ...)` resolving
                    # to a judged name): the batch expansion form is no longer withheld from the Mastery gate.
                    # This replaces Day 25's live fix day_patch.py, now folded here (it read the SAME
                    # batch.statement_form, with _batch_shape as a weaker fallback it shipped plain too; we are
                    # stricter -- see below -- and never ship _batch_shape plain).
                    #   When statement_form is None (2+ joins, or a form it does not list -- no real specimen so
                    # far) the third label is AMBIGUOUS: the original fold kept it unsure because on Day 23 the
                    # same graph|control (fan_out|direct) resolved to delayed, for_indirect AND percent on three
                    # specimens. We honour that: such a case is NEVER shipped plain. It stays an UNSURE
                    # labels.candidates pick (row 346), probed per id at runtime, with _batch_shape only a head
                    # hint for the probe order (labels.candidates front-loads the split key's already-accepted
                    # names and ignores the order we pass, so the hint only matters before any name is accepted).
                    import batch as _bat
                    FORMS = ("percent", "delayed", "call_double", "for_indirect")
                    sf = _bat.statement_form(text)
                    if sf in FORMS:
                        val = f"{parts[0]}|{parts[1]}|{sf}"          # byte-exact, plain (never-wrong)
                    else:
                        guess = _batch_shape(text)
                        head = [guess] if guess in FORMS else []
                        order = head + [h for h in FORMS if h != guess]
                        val = labels.candidates("script.style/batch.expansion#cand",
                                                [(f"expansion_{h}", f"{parts[0]}|{parts[1]}|{h}") for h in order])
            elif cprefix == "powershell" and ps is not None and f in ("url", "secondary", "tertiary"):
                url, sec, ter = _ps_fields(ps)
                if f == "url" and url:
                    val = url
                elif f == "secondary" and sec:
                    val = labels.pick("script.secondary/powershell.scenario_indicator", [("by_scenario", sec)])
                elif f == "tertiary" and ter:
                    val = labels.pick("script.tertiary/powershell.scenario_indicator", [("by_scenario", ter)])
            have = cur.get(qid)
            open_id = have is None or (isinstance(have, str) and have.startswith("??"))
            # Fills open ids only; a plain answer stands. The one exception is a joined field (python carrier and
            # obfuscation, the judge's `a|b` form of Day 23): the shipped plain answer is one component of the
            # joined value read from the same plan, so the join only extends it.
            extends = (f in ("carrier", "obfuscation") and cprefix == "python" and _plain(have)
                       and have in (_first(val) or "").split(JOIN) and _first(val) != have)
            if val is not None and val != have and (open_id or extends):
                out[qid] = val
            elif val is None and f in ("carrier", "obfuscation") and cprefix == "python" and _plain(have) \
                    and JOIN not in have:
                # Day 27 (script residuals): the joined field (`carrier|windows_chain`, `syntax|obfuscation`: the
                # judge's form for every hex-id Python specimen of Days 23 to 26) answered with ONE of its parts, plain,
                # and no plan here to join it with (the general path read none or a cut one, while shapes_py read the
                # head of a material cut into a suffix variable): the part alone is not the field, so it is withdrawn.
                print(f"[day23_fold] NOTE {qid}: {have!r} is one part of the joined {f} field and no plan read here "
                      f"gives the other; withdrawn", file=sys.stderr)
                out[qid] = None
        except Exception as e:  # noqa: BLE001
            print(f"[day_patch] {qid} raised {type(e).__name__}: {e}", file=sys.stderr)
    return out
