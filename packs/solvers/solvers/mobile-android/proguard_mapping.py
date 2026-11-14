#!/usr/bin/env python3
"""ProGuard / R8 / DexGuard mapping.txt deobfuscation reader (deep-backlog "mobile" row, low/small).

  .venv/bin/python solvers/mobile-android/proguard_mapping.py <mapping.txt|file.apk>

A `mapping.txt` (the retrace mapping R8/ProGuard writes) ships in or beside an APK when a
challenge asks you to reverse the obfuscation: "what is the original name of class a.b.c",
"what was com.example.LoginManager renamed to". Before this module no mobile reader resolved an
obfuscation mapping, so `codec_search` -> `apk_facts` returned None for such a question.

What it does: parse the mapping into a byte-exact bidirectional index (class, method, field) and
resolve the ONE symbol a question names, in the ONE direction a direction word states. The whole
format is a documented plain-text grammar, so the resolution is a deterministic lookup, not a
guess. Never-guess (AGENTS.md, "Uncertain answers"):

  unsure  the resolved name, labels.pick('mobile.deobf/<class|method|field>', [(form, value)]):
          for a class the full name and its simple name are two spellings of ONE established
          fact; for a member the one name. The route is new, so nothing the judge has accepted
          exists for it yet -- tools/verify.py probes it on the untimed base, one request each,
          never on a clock. The accepted spelling then answers the next variant.
  None    no mapping present; the question states no direction word (or both); it names zero or
          two resolvable symbols; a symbol whose counterpart is not unique; anything ambiguous.

It never executes anything and reads only text (text-is-data). An ANS- code is not a symbol, so
this reader never produces one and never touches the lane's answer-code path. It only ever ADDS
an answer where `apk_facts` had None, and only when a mapping member is present (no saved fixture
has one), so it changes nothing already answered: proven by
`tools/preflight.py --regress mobile-android` (changed=0).
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import labels  # noqa: E402

MAX_MAPPING_BYTES = 16 << 20   # a member larger than this is not read as a mapping
MAX_LINES = 400_000            # a mapping larger than this is not fully walked (bounded, never a clock)

# A class line: "<original fqcn> -> <obfuscated fqcn>:" at column zero, nothing indented.
_CLASS = re.compile(r"^([\w$.]+) -> ([\w$.]+):\s*$")
# A member line: indented, "<stuff> -> <obf>". The stuff is parsed by _member.
_MEMBER = re.compile(r"^\s+(.+?) -> ([\w$<>]+)\s*$")
# A Java identifier / dotted-or-inner name as it appears in a question ("a.b.c", "onCreate",
# "com.example.Foo$Bar"). Resolution against the mapping filters out ordinary English words.
_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:[.$][A-Za-z_$][A-Za-z0-9_$]*)*")

# Direction words. The word says what the ANSWER is, hence what the token in the question is.
_WANT_ORIGINAL = frozenset("""original originally originalname real realname source sourcename
    deobfuscated deobfuscate deobfuscation demangle demangled unobfuscated unmapped unminified
    unscrambled""".split())
_WANT_OBFUSCATED = frozenset("""obfuscated obfuscate obfuscation renamed rename mapped mapping
    mangled minified shortened scrambled""".split())
_KIND_CLASS = frozenset("class clazz".split())
_KIND_METHOD = frozenset("method function constructor".split())
_KIND_FIELD = frozenset("field property variable attribute".split())


def _member(left):
    """(kind, name) for the left side of a member line, or None. kind is 'method' or 'field'.

    left is e.g. "1:3:void onCreate(android.os.Bundle):11:13", "int counter",
    "java.lang.String getName()". The name is the identifier that is renamed."""
    left = re.sub(r"^\d+:\d+:", "", left).strip()   # drop a leading line-range
    paren = left.find("(")
    if paren >= 0:                                   # a method: name is the token before "("
        head = left[:paren].rstrip()
        m = re.search(r"([A-Za-z_$<][\w$<>]*)$", head)
        return ("method", m.group(1)) if m else None
    parts = left.split()                             # a field: "<type> <name>"
    if len(parts) >= 2 and re.fullmatch(r"[A-Za-z_$][\w$]*", parts[-1]):
        return ("field", parts[-1])
    return None


class Mapping:
    """A parsed mapping.txt: byte-exact, bidirectional, with uniqueness recorded.

    A name whose counterpart is not unique (the same obfuscated name seen for two different
    originals, or the reverse) is dropped from the index, so a lookup never returns a wrong or
    arbitrary counterpart -- it returns None and the reader answers None."""

    def __init__(self):
        self.cls_orig_of_obf = {}     # obfuscated fqcn -> original fqcn
        self.cls_obf_of_orig = {}     # original  fqcn -> obfuscated fqcn
        # per class (keyed by both the orig and the obf fqcn): name -> set of (kind, counterpart).
        # A set, because within one class an obfuscated name may legitimately name both a field
        # and a method (separate namespaces); the asked kind disambiguates, else it is refused.
        self._mem_orig_of_obf = {}    # class fqcn (any) -> {obf member name  -> {(kind, orig name)}}
        self._mem_obf_of_orig = {}    # class fqcn (any) -> {orig member name -> {(kind, obf name)}}
        # global member maps: name -> set of (kind, counterpart) across all classes
        self.mem_orig_of_obf = {}     # obf member name  -> {(kind, orig name)}
        self.mem_obf_of_orig = {}     # orig member name -> {(kind, obf name)}
        self.classes = 0
        self.members = 0

    @staticmethod
    def _put_unique(fwd, rev, k, v):
        """Record k->v in fwd and v->k in rev. Any collision (a key already bound to a different
        value) sets that entry to None, the sentinel a lookup reads as 'absent or ambiguous', so a
        later identical pair can never resurrect it and no arbitrary counterpart is ever returned."""
        fwd[k] = v if (k not in fwd) else (fwd[k] if fwd[k] == v else None)
        rev[v] = k if (v not in rev) else (rev[v] if rev[v] == k else None)

    def _add_class(self, orig, obf):
        self.classes += 1
        self._put_unique(self.cls_obf_of_orig, self.cls_orig_of_obf, orig, obf)
        self._mem_orig_of_obf.setdefault(orig, {})
        self._mem_orig_of_obf.setdefault(obf, {})
        self._mem_obf_of_orig.setdefault(orig, {})
        self._mem_obf_of_orig.setdefault(obf, {})

    def _add_member(self, cls_orig, cls_obf, kind, orig_name, obf_name):
        self.members += 1
        for c in (cls_orig, cls_obf):
            self._mem_orig_of_obf[c].setdefault(obf_name, set()).add((kind, orig_name))
            self._mem_obf_of_orig[c].setdefault(orig_name, set()).add((kind, obf_name))
        self.mem_orig_of_obf.setdefault(obf_name, set()).add((kind, orig_name))
        self.mem_obf_of_orig.setdefault(orig_name, set()).add((kind, obf_name))

    def class_in_direction(self, token, want_original):
        """The counterpart of a class fqcn `token` in the wanted direction, or None (not a class
        name, or its counterpart is not unique)."""
        table = self.cls_orig_of_obf if want_original else self.cls_obf_of_orig
        v = table.get(token)
        return v  # None covers both "absent" and "ambiguous" (stored as None)

    def member_in_direction(self, token, want_original, scope=None, kind=None):
        """(kind, counterpart) for a member name `token`, or None. With `scope` (a class fqcn
        that is in the mapping) the name is resolved within that one class; without it the name
        must be globally unique across every class. `kind` ('method' or 'field'), when given,
        first narrows the candidates to that kind. The result is returned only when exactly one
        candidate remains after narrowing; anything still ambiguous is None."""
        if scope is not None:
            table = self._mem_orig_of_obf if want_original else self._mem_obf_of_orig
            got = (table.get(scope) or {}).get(token)
        else:
            table = self.mem_orig_of_obf if want_original else self.mem_obf_of_orig
            got = table.get(token)
        if not got:
            return None
        cands = {c for c in got if kind is None or c[0] == kind}
        return next(iter(cands)) if len(cands) == 1 else None


def parse(data):
    """Parse mapping.txt bytes/str into a Mapping, or None when it is not a mapping file.

    A mapping must have at least one class line with the `orig -> obf:` arrow; otherwise None."""
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_MAPPING_BYTES:
            return None
        text = bytes(data).decode("utf-8", "replace")
    elif isinstance(data, str):
        text = data
    else:
        return None
    mp = Mapping()
    cur_orig = cur_obf = None
    for i, line in enumerate(text.splitlines()):
        if i > MAX_LINES:
            break
        if not line or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():                       # a member of the current class
            if cur_orig is None:
                continue
            m = _MEMBER.match(line)
            if not m:
                continue
            got = _member(m.group(1))
            if got:
                mp._add_member(cur_orig, cur_obf, got[0], got[1], m.group(2))
            continue
        c = _CLASS.match(line)                       # a class line
        if c:
            cur_orig, cur_obf = c.group(1), c.group(2)
            mp._add_class(cur_orig, cur_obf)
        else:
            cur_orig = cur_obf = None                # an unparsable top-level line ends the class
    return mp if mp.classes else None


def _looks_like_mapping_name(name):
    base = name.rsplit("/", 1)[-1].lower()
    return base.endswith(".txt") and ("mapping" in base or base in ("retrace.txt", "proguard.txt"))


_SKIP_MEMBER = re.compile(r"(^|/)(AndroidManifest\.xml|classes[0-9]*\.dex|assets/huntress_puzzle\.json)$")


def read_members(members):
    """The mapping.txt of a delivery, parsed, or None. A member is read as a mapping when its
    name says so (``*mapping*.txt``) or when a text member clearly has the grammar (>= 8 class
    lines and at least one indented member line). Conservative on purpose: a false positive is
    still harmless because `answer` only fires on a real deobfuscation question."""
    if not isinstance(members, dict):
        return None
    # name-named mappings first
    named = [n for n, b in members.items()
             if isinstance(b, (bytes, bytearray)) and _looks_like_mapping_name(n)
             and len(b) <= MAX_MAPPING_BYTES]
    for n in sorted(named):
        mp = parse(members[n])
        if mp is not None:
            return mp
    # otherwise a text member whose content is unmistakably a mapping
    for n in sorted(members):
        b = members.get(n)
        if (not isinstance(b, (bytes, bytearray)) or not b or len(b) > MAX_MAPPING_BYTES
                or _SKIP_MEMBER.search(n) or b"\x00" in b[:4096]):
            continue
        head = bytes(b[:1 << 20])
        if head.count(b" -> ") < 8 or b":\n" not in head:
            continue
        mp = parse(b)
        if mp is not None and mp.classes >= 8 and mp.members >= 1:
            return mp
    return None


def _class_forms(fqcn):
    simple = fqcn.rsplit(".", 1)[-1]
    simple = simple.rsplit("$", 1)[-1]
    opts = [("full", fqcn)]
    if simple and simple != fqcn:
        opts.append(("simple", simple))
    return opts


def _wordset(text):
    return set(re.findall(r"[a-z]+", str(text).lower()))


def resolve(mapping, text):
    """The one symbol a question `text` names, resolved. Returns (kind, [(form, value), ...]) or
    None. Never-wrong: a direction word is required, and exactly one symbol must resolve."""
    if mapping is None:
        return None
    words = _wordset(text)
    want_original = bool(words & _WANT_ORIGINAL)
    want_obf = bool(words & _WANT_OBFUSCATED)
    if want_original == want_obf:          # neither, or both -> no clear direction
        return None
    kind_class = bool(words & _KIND_CLASS)
    want_method, want_field = bool(words & _KIND_METHOD), bool(words & _KIND_FIELD)
    kind_member = want_method or want_field
    kind_want = "method" if (want_method and not want_field) else ("field" if (want_field and not want_method) else None)

    tokens = []
    for m in _TOKEN.finditer(str(text)):
        t = m.group(0)
        if t not in tokens:
            tokens.append(t)
    dotted = [t for t in tokens if "." in t or "$" in t]
    bare = [t for t in tokens if "." not in t and "$" not in t]

    # classes the question names (dotted tokens that resolve as a class in the wanted direction)
    class_hits = []
    class_scope = []        # class fqcns present in the mapping, as scope for a member lookup
    for t in dotted:
        v = mapping.class_in_direction(t, want_original)
        if v is not None:
            class_hits.append((t, v))
        if t in mapping.cls_orig_of_obf or t in mapping.cls_obf_of_orig:
            class_scope.append(t)

    # a class-scoped member: "the original name of method X in class a.b.c". A member kind word
    # plus exactly one named class is unambiguously a question about that class's member.
    if kind_member and len(class_scope) == 1:
        scope = class_scope[0]
        mem_hits = []
        for t in bare:
            got = mapping.member_in_direction(t, want_original, scope=scope, kind=kind_want)
            if got is not None:
                mem_hits.append((t, got))
        if len(mem_hits) == 1:
            kind, val = mem_hits[0][1]
            return kind, [("name", val)]
        return None

    results = []
    if not kind_member:                     # a class question (or unspecified): dotted class hits
        for _t, v in class_hits:
            results.append(("class", _class_forms(v)))
    if not kind_class:                      # a member question (or unspecified): global-unique members
        for t in bare:
            got = mapping.member_in_direction(t, want_original, kind=kind_want)
            if got is not None:
                results.append((got[0], [("name", got[1])]))
    # de-duplicate identical results, then require exactly one
    uniq = []
    for r in results:
        if r not in uniq:
            uniq.append(r)
    return uniq[0] if len(uniq) == 1 else None


def answer(q, mapping):
    """The answer to one question, given a parsed mapping: an unsure labels.pick value under
    `mobile.deobf/<kind>`, or None. See the module text. `answer` returns non-None ONLY for a
    genuine deobfuscation question, so it never shadows an `apk_facts` answer."""
    if mapping is None or not isinstance(q, dict):
        return None
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    if str(fmt.get("kind") or "").lower() in ("json", "integer", "ordered_tokens", "mitre_attack_id"):
        return None
    text = " ".join(str(q.get(k) or "") for k in ("question", "prompt", "qid", "id"))
    got = resolve(mapping, text)
    if got is None:
        return None
    kind, options = got
    options = [(n, v) for n, v in options if isinstance(v, str) and v]
    return labels.pick("mobile.deobf/%s" % kind, options) if options else None


def main(argv):
    import io
    import zipfile
    if argv and argv[0] in ("-h", "--help"):
        print("usage: proguard_mapping.py <mapping.txt|file.apk>")
        return 0
    if len(argv) != 1:
        print("proguard_mapping.py: expected exactly one mapping or APK", file=sys.stderr)
        return 2
    try:
        blob = Path(argv[0]).read_bytes()
        mp = None
        if blob[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                    members = {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}
                mp = read_members(members)
            except Exception:
                mp = None
        if mp is None:
            mp = parse(blob)
        if mp is None:
            print("not a ProGuard/R8 mapping")
            return 1
        print("classes %d  members %d" % (mp.classes, mp.members))
        shown = 0
        for obf, orig in sorted(mapping_items(mp.cls_orig_of_obf)):
            print("  class %-40s <- %s" % (orig, obf))
            shown += 1
            if shown >= 20:
                print("  ...")
                break
        return 0
    except Exception as exc:
        print(f"proguard_mapping.py: {exc}", file=sys.stderr)
        return 2


def mapping_items(d):
    return [(k, v) for k, v in d.items() if v is not None]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
