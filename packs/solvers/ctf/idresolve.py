"""Contract-mismatch id resolver (B-010): map renamed question ids onto known field readers, fail closed.

A platform that asks typed questions (the Game Master's `slot0_entry_point`, `set2.cpp_xor_key`,
`roster-sha256`) sometimes renames the ids of an old challenge. The readers still have the
capability; only the name changed, and a lane whose dispatch keys on the exact id (or on the id's first
word) stops with `contract_mismatch` or answers nothing. This module decides, per asked id, which
*known* id it is, from data alone, and refuses whenever that is not certain.

    cat = Catalog(known=["d01_analysis_entry_point", ...], strip=r"(?:d\\d+_)?(?:analysis_)?")
    r = resolve("set1.slot0_entry_point", cat)        # Resolution(status="mapped", target=..., ...)
    rep = resolve_all(questions, cat, members=names)  # Report: .ok, .problems(), .to_json()
    answers, rep = answer_through(solve_set, questions, files, ctx, catalog=cat)
    cat = load_conventions(path)                      # a lane's convention file (TOML, below)

What a known id is: an id a reader is proven on (the ids of a saved base attempt, a lane's field
table). Its *field names* are its canonical spelling and that spelling with the catalog's `strip`
head removed (`d01_analysis_entry_point` -> `entry_point`). Rules, in order; the first that applies
decides, and a later rule never overrides an earlier refusal:

  exact     the id (after a leading `setN.`) is a known id.
  spelling  its canonical form (lower case, every run of non-alphanumerics one `_`) is exactly one
            known id's canonical form (`roster-md5` vs `roster_md5`).
  alias     the convention file's `[ids]` table names it; the target must be a known id.
  scope     a convention scope's `match` regex matches the id's start (`slot(?P<n>\\d+)_`,
            `cpp_`); the rest is a field looked up in the scope's `fields` table, else among the
            field names of the known ids that start with the scope's `prefix`. A matching scope
            decides: no field there is a refusal, not a fall-through.
  stem      with delivered member names: the id is `<member stem>_<field>` for exactly one member
            and one known field (`roster-sha256` with roster.csv delivered -> `sha256`). Two members
            with that stem (evidence-note.txt beside evidence-note.md, or note.tar.gz beside
            note.txt) are ambiguous.
  field     the whole id is the field name of exactly one known id.

Fail closed: no rule -> `unmatched`; more than one candidate -> `ambiguous`; two asked ids that land
on the same field of the same sample -> both `ambiguous`. Matching is by whole field name only: an
asked field is never matched to a known one that merely ends with it (`symbols` is not
`exported_symbols`), and an asked id is never shortened to a known one (`thumbnail_md5` is not `md5`)
except by the stem rule, which needs the delivered file to prove the dropped words.

answer_through() is the adapter a lane solver wraps around its own solve_set: it hands the inner
solver the known ids (with the members a scope selects, renamed as the scope says), maps the answers
back, and leaves every unresolved id None. A mapped answer of the literal `none` is kept only when the
asked question's own answer format allows the literal none (permits_literal_none); otherwise None.

Convention file (TOML; unknown keys are an error):

    known = ["d01_analysis_entry_point", "d01_artifact_sha256_1"]   # optional; added to the catalog
    strip = '(?:d\\d+_)?(?:analysis_|artifact_)?'                   # optional; default DEFAULT_STRIP

    [ids]                       # asked id -> known id
    url = "d02_analysis_config_url"

    [[scope]]
    name = "slot"               # required
    match = 'slot(?P<n>\\d+)_'  # required; matched at the start of the id (after setN.)
    prefix = "d01_"             # known ids this scope may resolve to
    fields = { sha256 = "artifact_sha256_1" }   # field -> known id without the prefix
    members = '(?:^|[-_.])slot[-_]?0*{n}(?!\\d)' # which delivered members the sample is ({n}: the number)
    hand_as = "d01-"            # members are handed to the inner solver as <hand_as><basename>
    single = true               # exactly one distinct member body, else the scope's ids stay None
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

EXACT, MAPPED, UNMATCHED, AMBIGUOUS = "exact", "mapped", "unmatched", "ambiguous"
RESOLVED = (EXACT, MAPPED)

DEFAULT_STRIP = r"(?:(?:d|day)\d+_)?"
SET_PREFIX = re.compile(r"set(\d+)\.(.+)\Z", re.S)
SET_MEMBERS = r"(?<!\d)0*{n}(?=\.[A-Za-z0-9]+$)"   # the runner's set rule: delivery-02.apk serves set 2
_SCOPE_KEYS = {"name", "match", "prefix", "fields", "members", "hand_as", "single"}
_TOP_KEYS = {"known", "strip", "ids", "scope"}


class ConventionError(ValueError):
    """A convention file or catalog that cannot be used as written (named key, file and reason)."""


def canon(text) -> str:
    """Lower case, every run of characters other than [a-z0-9] one `_`, no `_` at either end."""
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")


def _stem(name: str) -> tuple[str, str]:
    """(stem without the last extension, stem before the first dot) of a member's basename, canonical."""
    base = str(name).replace("\\", "/").rsplit("/", 1)[-1]
    core = base.lstrip(".")
    last = core.rsplit(".", 1)[0] if "." in core else ""
    first = core.split(".", 1)[0] if "." in core else ""
    return canon(last), canon(first)


@dataclass(frozen=True)
class Scope:
    name: str
    match: re.Pattern
    prefix: str = ""
    fields: tuple = ()          # ((canon field, known-id tail), ...)
    members: str | None = None  # regex template; {n} is the scope's number
    hand_as: str = ""
    single: bool = False

    def field_alias(self, fld: str):
        return dict(self.fields).get(fld)

    def select(self, files: dict, n) -> tuple[dict | None, str]:
        """(members handed to the inner solver, why not). None when the scope's sample is not proven."""
        pool = {k: v for k, v in (files or {}).items() if isinstance(v, (bytes, bytearray))}
        if self.members is None:
            return dict(pool), ""
        try:
            pat = re.compile(self.members.replace("{n}", str(int(n)) if n is not None else ""), re.I)
        except re.error as e:
            return None, f"scope {self.name}: members regex does not compile ({e})"
        where = f"scope {self.name}{'' if n is None else ' ' + str(n)}"
        # Bodies are counted over the delivered (source) names, before any renaming: two members that share
        # a basename (a/slot-0.elf, b/slot-0.elf) must never overwrite each other and pass as one sample.
        src = {}
        for name, data in pool.items():
            base = str(name).replace("\\", "/").rsplit("/", 1)[-1]
            if pat.search(base):
                src[str(name)] = (base, bytes(data))
        if not src:
            return None, f"{where}: no delivered member matches"
        bodies = {data for _, data in src.values()}
        if self.single and len(bodies) != 1:
            return None, (f"{where}: {len(bodies)} distinct member bodies ({', '.join(sorted(src))}), "
                          f"not one sample")
        picked, came_from = {}, {}
        for name in sorted(src):
            base, data = src[name]
            hand = f"{self.hand_as}{base}"
            if hand in picked and picked[hand] != data:
                return None, (f"{where}: {came_from[hand]} and {name} would both be handed on as {hand} "
                              f"with different bodies")
            picked.setdefault(hand, data)
            came_from.setdefault(hand, name)
        if self.single:
            first = sorted(picked)[0]
            picked = {first: picked[first]}
        return picked, ""


@dataclass(frozen=True)
class Resolution:
    qid: str                     # the id as asked
    status: str                  # exact | mapped | unmatched | ambiguous
    target: str | None = None    # the known id, when resolved
    rule: str = ""               # exact | spelling | alias | scope-alias | scope-field | stem | field
    selector: tuple | None = None  # (scope name, number or None) | ("file", member name) | None
    set: int | None = None       # N of a leading setN.
    candidates: tuple = ()
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.status in RESOLVED

    def line(self) -> str:
        if self.status == EXACT:
            return f"{self.qid}: exact"
        if self.status == MAPPED:
            where = ""
            if self.selector is not None:
                where = f" [{self.selector[0]}{'' if self.selector[1] is None else ' ' + str(self.selector[1])}]"
            return f"{self.qid} -> {self.target} ({self.rule}){where}"
        extra = f" (candidates: {', '.join(self.candidates)})" if self.candidates else ""
        return f"{self.qid}: {self.status.upper()} {self.reason}{extra}"

    def to_dict(self) -> dict:
        return {"qid": self.qid, "status": self.status, "target": self.target, "rule": self.rule,
                "selector": list(self.selector) if self.selector is not None else None, "set": self.set,
                "candidates": list(self.candidates), "reason": self.reason}


class Catalog:
    """The known ids a lane's readers are proven on, plus the lane's naming conventions."""

    def __init__(self, known: Iterable[str], *, strip: str = DEFAULT_STRIP, ids: dict | None = None,
                 scopes: Iterable[Scope] = ()):
        self.known = tuple(dict.fromkeys(str(k) for k in known if isinstance(k, str) and k))
        if not self.known:
            raise ConventionError("a catalog with no known ids resolves nothing; give the ids a reader is proven on")
        try:
            self.strip = re.compile(strip or "")
        except re.error as e:
            raise ConventionError(f"strip regex {strip!r} does not compile: {e}") from None
        self.ids = {canon(k): str(v) for k, v in (ids or {}).items()}
        self.scopes = tuple(scopes)
        self._known_set = set(self.known)
        self._by_canon: dict[str, set] = {}
        self._by_field: dict[str, set] = {}
        for k in self.known:
            c = canon(k)
            self._by_canon.setdefault(c, set()).add(k)
            for name in self.field_names(k):
                self._by_field.setdefault(name, set()).add(k)

    def field_names(self, known_id: str) -> set:
        c = canon(known_id)
        names = {c}
        m = self.strip.match(c)
        if m and 0 < m.end() < len(c):
            names.add(c[m.end():].strip("_"))
        return {n for n in names if n}

    def is_known(self, known_id) -> bool:
        return known_id in self._known_set

    def by_field(self, fld: str, prefix: str = "") -> list:
        """Known ids with field name fld; with a prefix, only ids whose canonical form is the prefix's
        words followed by more words (`d01_` takes d01_*, never d010_*)."""
        p = canon(prefix)
        return sorted(k for k in self._by_field.get(fld, ()) if not p or canon(k).startswith(p + "_"))

    def by_spelling(self, text: str) -> list:
        return sorted(self._by_canon.get(canon(text), ()))

    @classmethod
    def from_attempt(cls, attempt: dict, **kw) -> "Catalog":
        """The answer ids of a saved attempt (its questions' ids, a leading setN. removed)."""
        if not isinstance(attempt, dict):
            raise ConventionError("an attempt must be a JSON object with a questions list")
        ids = [str(i) for i in attempt.get("answer_ids") or [] if isinstance(i, str)]
        for q in attempt.get("questions") or []:
            if isinstance(q, dict) and isinstance(q.get("id"), str):
                ids.append(q["id"])
        ids = [m.group(2) if (m := SET_PREFIX.fullmatch(i)) else i for i in ids]
        if not ids:
            raise ConventionError("the attempt carries no question ids")
        return cls(ids, **kw)

    def extended(self, known: Iterable[str]) -> "Catalog":
        return Catalog(list(self.known) + list(known), strip=self.strip.pattern, ids=self.ids, scopes=self.scopes)


# ---- convention files ---------------------------------------------------------------------------------

def load_conventions(path, *, known: Iterable[str] = ()) -> Catalog:
    """A Catalog from a lane's convention TOML (module docstring), with `known` ids added. Loud on a
    missing file, unknown key, bad regex or an alias whose target is no known id."""
    p = Path(path)
    if not p.is_file():
        raise ConventionError(f"convention file not found: {p}")
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConventionError(f"{p}: not valid TOML ({e})") from None
    return conventions_from_dict(data, known=known, source=str(p))


def conventions_from_dict(data: dict, *, known: Iterable[str] = (), source: str = "<conventions>") -> Catalog:
    bad = set(data) - _TOP_KEYS
    if bad:
        raise ConventionError(f"{source}: unknown key(s) {sorted(bad)}; allowed {sorted(_TOP_KEYS)}")
    k = data.get("known", [])
    if not isinstance(k, list) or not all(isinstance(x, str) for x in k):
        raise ConventionError(f"{source}: known must be a list of strings")
    ids = data.get("ids", {})
    if not isinstance(ids, dict) or not all(isinstance(v, str) for v in ids.values()):
        raise ConventionError(f"{source}: [ids] must map an id to a known id (strings)")
    scopes = []
    seen = set()
    for i, s in enumerate(data.get("scope", [])):
        where = f"{source}: scope #{i + 1}"
        if not isinstance(s, dict):
            raise ConventionError(f"{where}: must be a table")
        bad = set(s) - _SCOPE_KEYS
        if bad:
            raise ConventionError(f"{where}: unknown key(s) {sorted(bad)}; allowed {sorted(_SCOPE_KEYS)}")
        for req in ("name", "match"):
            if not isinstance(s.get(req), str) or not s[req]:
                raise ConventionError(f"{where}: {req} is required (a non-empty string)")
        if s["name"] in seen:
            raise ConventionError(f"{where}: duplicate scope name {s['name']!r}")
        seen.add(s["name"])
        try:
            rx = re.compile(s["match"])
        except re.error as e:
            raise ConventionError(f"{where} ({s['name']}): match regex does not compile: {e}") from None
        if s.get("members") is not None:
            if not isinstance(s["members"], str):
                raise ConventionError(f"{where} ({s['name']}): members must be a regex string")
            try:
                re.compile(s["members"].replace("{n}", "0"))
            except re.error as e:
                raise ConventionError(f"{where} ({s['name']}): members regex does not compile: {e}") from None
        flds = s.get("fields", {})
        if not isinstance(flds, dict) or not all(isinstance(v, str) for v in flds.values()):
            raise ConventionError(f"{where} ({s['name']}): fields must map a field to a known-id tail (strings)")
        for key in ("prefix", "hand_as"):
            if key in s and not isinstance(s[key], str):
                raise ConventionError(f"{where} ({s['name']}): {key} must be a string")
        if "single" in s and not isinstance(s["single"], bool):
            raise ConventionError(f"{where} ({s['name']}): single must be true or false")
        scopes.append(Scope(name=s["name"], match=rx, prefix=s.get("prefix", ""),
                            fields=tuple((canon(a), b) for a, b in flds.items()), members=s.get("members"),
                            hand_as=s.get("hand_as", ""), single=s.get("single", False)))
    cat = Catalog(list(k) + list(known), strip=data.get("strip", DEFAULT_STRIP), ids=ids, scopes=scopes)
    drift = [f"[ids] {a} -> {b}" for a, b in ids.items() if not cat.is_known(b)]
    drift += [f"scope {s.name}: {f} -> {s.prefix}{t}" for s in cat.scopes for f, t in s.fields
              if not cat.is_known(s.prefix + t)]
    if drift and k:
        # A file that lists its own known ids must agree with itself; with ids from elsewhere a target that
        # is not proven this time is refused at resolve time instead.
        raise ConventionError(f"{source}: alias target(s) not among the known ids: {'; '.join(drift)}")
    return cat


# ---- resolving -----------------------------------------------------------------------------------------

def _qid_of(q) -> str:
    if isinstance(q, str):
        return q
    if isinstance(q, dict):
        for key in ("id", "qid", "answer_id"):
            if isinstance(q.get(key), str) and q[key]:
                return q[key]
    raise ConventionError(f"a question with no id: {str(q)[:120]}")


def _decide(qid, cands, rule, selector, set_n, none_reason) -> Resolution:
    if len(cands) == 1:
        return Resolution(qid, MAPPED, cands[0], rule, selector, set_n)
    if len(cands) > 1:
        return Resolution(qid, AMBIGUOUS, None, rule, selector, set_n, tuple(cands),
                          f"{rule}: {len(cands)} known ids fit")
    return Resolution(qid, UNMATCHED, None, rule, selector, set_n, (), none_reason)


def resolve(qid: str, catalog: Catalog, members: Iterable[str] = ()) -> Resolution:
    """One asked id against the catalog (module docstring for the rules). members: delivered member
    names for the stem rule; leave the delivery itself (the archive) out."""
    if not isinstance(qid, str) or not qid:
        raise ConventionError(f"a question id must be a non-empty string, not {qid!r}")
    m = SET_PREFIX.fullmatch(qid)
    set_n, rest = (int(m.group(1)), m.group(2)) if m else (None, qid)
    if catalog.is_known(rest):
        return Resolution(qid, EXACT, rest, "exact", None, set_n)
    spelled = catalog.by_spelling(rest)
    if spelled:
        return _decide(qid, spelled, "spelling", None, set_n, "")
    c = canon(rest)
    if c in catalog.ids:
        target = catalog.ids[c]
        if catalog.is_known(target):
            return Resolution(qid, MAPPED, target, "alias", None, set_n)
        return Resolution(qid, UNMATCHED, None, "alias", None, set_n, (target,),
                          f"the convention names {target}, which is not a known id")
    for scope in catalog.scopes:
        sm = scope.match.match(rest)
        if not sm:
            continue
        n = sm.groupdict().get("n")
        n = int(n) if n is not None and str(n).isdigit() else None
        selector = (scope.name, n)
        fld = canon(rest[sm.end():])
        if not fld:
            return Resolution(qid, UNMATCHED, None, "scope", selector, set_n, (),
                              f"scope {scope.name}: no field after the scope's words")
        tail = scope.field_alias(fld)
        if tail is not None:
            target = scope.prefix + tail
            if catalog.is_known(target):
                return Resolution(qid, MAPPED, target, "scope-alias", selector, set_n)
            return Resolution(qid, UNMATCHED, None, "scope-alias", selector, set_n, (target,),
                              f"scope {scope.name}: the convention names {target}, which is not a known id")
        return _decide(qid, catalog.by_field(fld, scope.prefix), "scope-field", selector, set_n,
                       f"scope {scope.name}: no known field {fld!r}"
                       + (f" under {scope.prefix!r}" if scope.prefix else ""))
    pairs = set()
    for name in members or ():
        last, first = _stem(name)
        for stem in {last, first} - {""}:
            if c.startswith(stem + "_"):
                for k in catalog.by_field(c[len(stem) + 1:]):
                    pairs.add((str(name), k))
    if pairs:
        leaves = sorted({p[0] for p in pairs})
        targets = sorted({p[1] for p in pairs})
        if len(pairs) == 1:
            leaf, target = next(iter(pairs))
            return Resolution(qid, MAPPED, target, "stem", ("file", leaf), set_n)
        return Resolution(qid, AMBIGUOUS, None, "stem", None, set_n, tuple(f"{a} -> {b}" for a, b in sorted(pairs)),
                          f"stem: {len(leaves)} member(s) and {len(targets)} field(s) fit")
    return _decide(qid, catalog.by_field(c), "field", None, set_n,
                   "no known id, alias, scope, member stem or field name fits")


@dataclass
class Report:
    resolutions: tuple = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return all(r.resolved for r in self.resolutions)

    @property
    def mapped(self) -> list:
        return [r for r in self.resolutions if r.status == MAPPED]

    @property
    def unresolved(self) -> list:
        return [r for r in self.resolutions if not r.resolved]

    def problems(self) -> list:
        """One line per id that is not resolved: what a lane's covers() returns (fail closed)."""
        return [r.line() for r in self.unresolved]

    def to_json(self) -> dict:
        return {"ok": self.ok, "counts": {s: sum(r.status == s for r in self.resolutions)
                                          for s in (EXACT, MAPPED, UNMATCHED, AMBIGUOUS)},
                "resolutions": [r.to_dict() for r in self.resolutions]}


def resolve_all(questions, catalog: Catalog, members: Iterable[str] = ()) -> Report:
    """Every asked id. Two asked ids of one set that resolve to the same known id of the same sample
    are both made ambiguous: one field cannot answer two questions that the platform asks apart."""
    members = tuple(members or ())
    rs = [resolve(_qid_of(q), catalog, members) for q in questions or []]
    seen: dict = {}
    for i, r in enumerate(rs):
        if r.resolved:
            seen.setdefault((r.set, r.selector, r.target), []).append(i)
    for key, idx in seen.items():
        if len({rs[i].qid for i in idx}) > 1:
            others = tuple(sorted({rs[i].qid for i in idx}))
            for i in idx:
                r = rs[i]
                rs[i] = Resolution(r.qid, AMBIGUOUS, None, r.rule, r.selector, r.set, others,
                                   f"{len(others)} asked ids land on {key[2]} of one sample")
    return Report(tuple(rs))


def covers(questions, catalog: Catalog, members: Iterable[str] = ()) -> list:
    """The lane contract hook: problem lines, empty when every id resolves."""
    return resolve_all(questions, catalog, members).problems()


# ---- answering through the resolver -------------------------------------------------------------------

_NONE_WORDS = re.compile(r"""(?:\bliteral\s+(?:token\s+|word\s+|value\s+|string\s+)?["'`]?none\b|["'`]none["'`])""", re.I)


def permits_literal_none(question) -> bool:
    """Whether the asked question's answer format allows the literal `none`: it is an accepted value, or
    the syntax names the literal none (`use the literal none only when ...`, `` `none` ``). A bare word
    none in a sentence ("none of the above") is not permission."""
    if not isinstance(question, dict):
        return False
    fmt = question.get("answer_format") if isinstance(question.get("answer_format"), dict) else {}
    accepted = fmt.get("accepted_values")
    if isinstance(accepted, list) and any(isinstance(a, str) and a.strip().lower() == "none" for a in accepted):
        return True
    return bool(_NONE_WORDS.search(str(fmt.get("syntax") or "")))


def _is_none(value) -> bool:
    return isinstance(value, str) and value.strip().lower() == "none"


def _default_log(msg: str) -> None:
    print(f"[idresolve] {msg}", file=sys.stderr)


def member_names(files: dict, ctx=None) -> list:
    """Delivered member names for the stem rule: every bytes member except the delivery itself."""
    delivery = ctx.get("delivery_name") if isinstance(ctx, dict) else None
    return [n for n, d in (files or {}).items() if isinstance(d, (bytes, bytearray)) and n != delivery]


def set_pool(files: dict, n: int, template: str = SET_MEMBERS) -> dict:
    """The delivered members that serve set n: basenames matching the template with {n} filled in
    (default: the number just before the extension, delivery-02.apk / evidence-2.zip for set 2)."""
    pat = re.compile(template.replace("{n}", str(int(n))), re.I)
    return {k: v for k, v in (files or {}).items()
            if isinstance(v, (bytes, bytearray)) and pat.search(str(k).replace("\\", "/").rsplit("/", 1)[-1])}


def answer_through(solve: Callable, questions, files: dict, ctx=None, *, catalog: Catalog,
                   members: Iterable[str] | None = None, set_members: str | None = None,
                   log: Callable[[str], None] = _default_log):
    """({asked key: answer or None}, Report). solve(questions, files, ctx) -> {qid: answer} is the lane's
    own solver; it is called once per sample (selector) with questions whose qid/id are the known ids.
    The asked key is a question's `qid` when it has one, else its `id`. With set_members (a regex
    template, SET_MEMBERS for the usual one), a `setN.` question reads only the members of set N: one
    delivery per set, never a neighbour's. Without set_members the caller hands one set per call (the
    runner does): mapped ids of two or more sets in one call are refused, since the pooled deliveries
    do not say which set each belongs to. Each set gets its own inner call, so two sets never put the
    same known id into one call. Nothing is guessed: an unresolved id, a set or sample whose members
    are not proven, a solver that raised, and a mapped literal none the asked format does not allow are
    all None, each with one log line. The inner solver gets its own ctx copy without `partial`, so its
    known-id answers never reach the caller's partial answers."""
    questions = [q for q in questions or [] if isinstance(q, dict)]
    if set_members is not None:
        try:
            re.compile(str(set_members).replace("{n}", "0"))
        except re.error as e:
            raise ConventionError(f"set_members regex {set_members!r} does not compile: {e}") from None
    if members is None:
        members = member_names(files, ctx)
    report = resolve_all(questions, catalog, members)
    scopes = {s.name: s for s in catalog.scopes}
    out, jobs = {}, {}
    sets = sorted({r.set for r in report.resolutions if r.resolved and r.set is not None})
    pooled_sets = set_members is None and len(sets) > 1
    for q, r in zip(questions, report.resolutions):
        key = q.get("qid") or q.get("id")
        out[key] = None
        if not r.resolved:
            log(r.line() + "; left unanswered")
            continue
        if pooled_sets and r.status == MAPPED and r.set is not None:
            log(f"{r.qid}: questions of sets {', '.join(map(str, sets))} in one call and no set_members, so the "
                f"delivery that serves set {r.set} is not proven; left unanswered")
            continue
        jobs.setdefault((r.set, r.selector), []).append((q, r, key))
    for (set_n, selector), items in jobs.items():
        pool, why = dict(files or {}), ""
        if set_n is not None and set_members is not None:
            pool = set_pool(files, set_n, set_members)
            if not pool:
                pool, why = None, f"set {set_n}: no delivered member matches {set_members!r}"
        if pool is None:
            sub = None
        elif selector is None:
            sub = pool
        elif selector[0] == "file":
            name = selector[1]
            sub, why = ({name: pool[name]}, "") if name in pool else (None, f"member {name} is not delivered"
                                                                     + (f" for set {set_n}" if set_n is not None else ""))
        else:
            sub, why = scopes[selector[0]].select(pool, selector[1])
        if sub is None:
            for _, r, key in items:
                log(f"{r.qid}: {why}; left unanswered")
            continue
        inner = []
        for q, r, _ in items:
            if r.status == EXACT:
                inner.append(q)
                continue
            asked = q.get("qid") or q.get("id")
            text = str(q.get("question") or "")
            inner.append({**q, "qid": r.target, "id": r.target, "answer_id": r.target,
                          "question": text.replace(str(asked), r.target) if asked else text})
        sub_ctx = dict(ctx) if isinstance(ctx, dict) else {}
        sub_ctx.pop("partial", None)
        try:
            got = solve(inner, sub, sub_ctx) or {}
        except Exception as e:   # one sample's failure costs its own ids
            for _, r, key in items:
                log(f"{r.qid}: the solver raised {type(e).__name__}: {str(e)[:160]}; left unanswered")
            continue
        for (q, r, key), iq in zip(items, inner):
            value = got.get(iq.get("qid") or iq.get("id"))
            if r.status == MAPPED and _is_none(value) and not permits_literal_none(q):
                log(f"{r.qid}: the reader of {r.target} said none, and the asked format does not allow the "
                    f"literal none; left unanswered")
                value = None
            out[key] = value
    return out, report


class ResolvingSolver:
    """A lane solver (solve_set + covers) that answers renamed ids through another lane solver."""

    def __init__(self, catalog: Catalog, solve: Callable, *, set_members: str | None = None,
                 log: Callable[[str], None] = _default_log):
        if not callable(solve):
            raise ConventionError("ResolvingSolver needs the inner solver's solve_set (a callable)")
        self.catalog, self._solve, self._log, self.set_members = catalog, solve, log, set_members
        self.last_report: Report | None = None

    @classmethod
    def from_conventions(cls, path, solve: Callable, *, known: Iterable[str] = (), **kw) -> "ResolvingSolver":
        return cls(load_conventions(path, known=known), solve, **kw)

    def solve_set(self, questions, files, ctx):
        answers, self.last_report = answer_through(self._solve, questions, files, ctx, catalog=self.catalog,
                                                   set_members=self.set_members, log=self._log)
        if isinstance(ctx, dict):
            ctx["id_resolution"] = self.last_report.to_json()
            partial = ctx.get("partial")
            if isinstance(partial, dict):
                partial.update({k: v for k, v in answers.items() if v is not None})
        return answers

    def covers(self, questions, members: Iterable[str] = ()) -> list:
        """Problem lines for the lane contract hook. members: the delivered member names, when the caller
        has them; without them every stem-rule id (`roster-sha256`) is reported unmatched, which is the
        fail-closed answer before the files are in hand (solve_set, which has the files, may answer it)."""
        return covers(questions, self.catalog, members)


def load_questions(path) -> list:
    """Questions from a JSON file: a status/attempt body with `questions`, a list of question objects,
    or a list of id strings. Read as data only."""
    p = Path(path)
    if not p.is_file():
        raise ConventionError(f"questions file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ConventionError(f"{p}: not JSON ({e})") from None
    if isinstance(data, dict):
        data = data.get("questions")
    if not isinstance(data, list) or not data:
        raise ConventionError(f"{p}: no questions (want a list, or an object with a questions list)")
    for q in data:
        _qid_of(q)
    return data
