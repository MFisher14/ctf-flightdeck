"""Bash (.sh) specimens of the Script Analysis lane, read as data: lang_sh.

answers(questions, files, ctx) -> {qid: answer}, one specimen's questions at a time (analyze.solve_new).
What this module leaves out (or None) is filled by generic.py, and control flow is always left to it (census).

The plan is the one encoded literal of the fixture. In a shell, quoted pieces with nothing between them
('aaa''bbb', "aaa"'bbb', $'\\x41'"b") are ONE word, "${A}${B}" joins earlier assignments, NAME+= appends and
NAME=( .. ) is an array: every assignment is read with the shell's own word rules (word_at, assignments), so
the material is read whole and the plan's last field is never cut. Nothing in the fixture is run: the words
are scanned by a small tokenizer, then decoded by plan_codec (string_forms for the representation, undo for
the crib-checked transform).

The word reader answers only what it can prove (whole_plan):
  - one plan, or plans that are all prefixes of the longest one (an array element, a += half);
  - no assignment of the same alphabet and comparable length that is neither part of that word nor a plan
    by itself (two variables joined only at run time: the word may be a piece);
  - no heredoc in the file (its body is data the reader cannot place);
  - it extends every plan plan_codec.reading gives for the file (raw, and with touching pieces joined).
Otherwise the file goes the owner's way of Day 6 (touching quoted pieces joined into one literal, an
indicator only from a plan read whole), and what that leaves goes to generic.

Steps keep the owner's rule: the plan's tokens joined by '>', plain when the answer_format syntax states
'joined by >' and 'no surrounding spaces', else labels.pick(generic.STEPS_KEY, ...) (generic.step_list).
"""
import importlib.util
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.append(str(HERE.parent / "common"))
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))
import labels  # noqa: E402


def _lane(name):
    """This folder's own <name>.py (solvers/binary has a generic.py too): the loaded one, else by path.

    Returns None if the sibling file is absent, so this module still imports and its shell-parsing helpers
    stay usable. The question-answering path leans on `generic` (and `plan_codec`): answers() answers
    nothing, and says why on stderr, when either is missing."""
    path = HERE / f"{name}.py"
    if not path.exists():
        return None
    for key in (name, f"script_analysis_{name}"):
        mod = sys.modules.get(key)
        if mod is not None and pathlib.Path(getattr(mod, "__file__", "") or "").resolve() == path:
            return mod
    key = f"script_analysis_{name}" if name in sys.modules else name
    spec = importlib.util.spec_from_file_location(key, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


plan_codec = _lane("plan_codec")
generic = _lane("generic")

# ---------------------------------------------------------------- the shell word reader (complex racer, Day 6)

ASSIGN_RE = re.compile(r'(?:^|(?<=[\s;&|(]))(?:(?:readonly|declare|typeset|local|export)(?:\s+-[A-Za-z]+)*\s+)?'
                       r'([A-Za-z_][A-Za-z0-9_]*)(\+?)=', re.M)
ANSI = {'n': 10, 't': 9, 'r': 13, 'a': 7, 'b': 8, 'f': 12, 'v': 11, 'e': 27, 'E': 27,
        '\\': 92, "'": 39, '"': 34, '?': 63}
END = set(' \t\r\n;&|<>()')
ANSI_ESC = re.compile(r'x([0-9A-Fa-f]{1,2})|([0-7]{1,3})|(.)', re.S)
DOLLAR = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)')
HEREDOC = re.compile(r'(?<!<)<<(?!<)-?[ \t]*(?:\'[^\'\n]+\'|"[^"\n]+"|\\?[A-Za-z_][A-Za-z0-9_]*)')
MIN_WORD = 16          # shorter words are names, keys and counters, never the material


def _dollar(text, i, env):
    """A $NAME or ${NAME} of an earlier literal assignment; anything else is no literal (None)."""
    m = DOLLAR.match(text, i)
    if not m:
        return None, i + 1
    return env.get(m.group(1) or m.group(2)), m.end()


def word_at(text, i, env):
    """(value, end) of the shell word at text[i]; value None when a part is not a literal this reader
    knows (a command substitution, an unknown variable). Never runs anything."""
    out, n = [], len(text)
    while i < n and text[i] not in END:
        c = text[i]
        if c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                return None, n
            out.append(text[i + 1:j]); i = j + 1
        elif c == '$' and text[i + 1:i + 2] == "'":
            i += 2
            while i < n and text[i] != "'":
                if text[i] == '\\' and i + 1 < n:
                    m = ANSI_ESC.match(text, i + 1)
                    if m.group(1):
                        out.append(chr(int(m.group(1), 16)))
                    elif m.group(2):
                        out.append(chr(int(m.group(2), 8) & 255))
                    else:
                        out.append(chr(ANSI[m.group(3)]) if m.group(3) in ANSI else '\\' + m.group(3))
                    i = m.end()
                else:
                    out.append(text[i]); i += 1
            i += 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == '\\' and i + 1 < n and text[i + 1] in '$`"\\\n':
                    if text[i + 1] != '\n':
                        out.append(text[i + 1])
                    i += 2
                elif text[i] == '$':
                    v, i = _dollar(text, i, env)
                    if v is None:
                        return None, i
                    out.append(v)
                elif text[i] == '`':
                    return None, i
                else:
                    out.append(text[i]); i += 1
            i += 1
        elif c == '$':
            v, i = _dollar(text, i, env)
            if v is None:
                return None, i
            out.append(v)
        elif c == '\\' and i + 1 < n:
            if text[i + 1] != '\n':
                out.append(text[i + 1])
            i += 2
        elif c == '`':
            return None, i
        else:
            out.append(c); i += 1
    return ''.join(out), i


def assignments(text):
    """[(name, value)] of every assignment whose value is a literal word, in file order. An array
    NAME=( w w ... ) gives each element (as NAME[]), then the elements joined with nothing."""
    env, out = {}, []
    for m in ASSIGN_RE.finditer(text):
        name, add, i = m.group(1), m.group(2), m.end()
        if text[i:i + 1] == '(':
            elems, j = [], i + 1
            while j < len(text):
                while j < len(text) and text[j] in ' \t\r\n':
                    j += 1
                if j >= len(text) or text[j] == ')':
                    break
                if text[j] == '#':
                    k = text.find('\n', j)
                    j = len(text) if k < 0 else k
                    continue
                v, k = word_at(text, j, env)
                if k == j:
                    break
                if v is not None:
                    elems.append(v)
                j = k
            out += [(name + '[]', v) for v in elems]
            if elems:
                out.append((name, ''.join(elems)))
            continue
        v, _ = word_at(text, i, env)
        if v is None:
            continue
        v = env.get(name, '') + v if add else v
        env[name] = v
        out.append((name, v))
    return out


def _emit(how, data):
    yield how, list(data)


def _word_plans(v):
    """[(plan text, representation, transform)] one word decodes to."""
    out = []
    for how, data in plan_codec.string_forms(v, _emit):
        for tr, raw in plan_codec.undo(data):
            t = plan_codec.looks_like_plan(raw)
            if t:
                out.append((t, how, tr))
    return out


def _part(s, word):
    """Whether the literal or word `s` is a part of `word`: inside it as written, or once its $'..' escapes
    are read (the escaped spelling of a piece)."""
    if s in word:
        return True
    if '\\' in s:
        v, _ = word_at("$'" + s + "'", 0, {})
        return bool(v) and v in word
    return False


def whole_plan(text, why=None):
    """(plan text, representation, transform, variable, word) of the material read as whole shell words, or None.

    A piece of the material (one array element, the first half of a += append, a variable joined into it)
    is a part of the longest word, and what it decodes to alone is no second plan (its last value, or the
    byte at its edge, is cut). Any other word that decodes to a plan must give a prefix of the longest one;
    two plans that differ otherwise are two materials, and none is taken. The longest word is taken as whole
    only when no other word or literal of its alphabet and of at least half its length is left over
    (neither a part of it nor a plan by itself): such a word may be the rest of a material the script joins
    only at run time. `why`, a list, gets one line when no plan is taken."""
    def no(reason):
        if why is not None:
            why.append(reason)
        return None

    if HEREDOC.search(text):
        return no("a heredoc: its body is data this reader cannot place")
    words = [(name, v) for name, v in assignments(text) if len(v) >= MIN_WORD]
    found, gave = [], set()
    for name, v in words:
        for t, how, tr in _word_plans(v):
            found.append((t, how, tr, name, v))
            gave.add(v)
    if not found:
        return no("no assignment decodes to a plan")
    best = max(found, key=lambda f: len(f[0]))
    word = best[4]
    if any(not best[0].startswith(f[0]) for f in found if f[4] not in word):
        return no(f"{len({f[0] for f in found})} plans that differ")
    kind = plan_codec._alphabet(word)
    if kind:
        rest = [v for _, v in words] + [s for _, _, s, _ in plan_codec._literals(text)]
        for v in rest:
            if v not in gave and 2 * len(v) >= len(word) and plan_codec._alphabet(v) == kind and not _part(v, word):
                return no(f"another word of its alphabet ({len(v)} characters) is not part of it: "
                          f"it may be a piece")
    return best


_HEX = frozenset("0123456789abcdefABCDEF")
_B64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def _related(other, name) -> bool:
    """Whether two variable names may hold pieces of one material: one extends the other, or they share a stem."""
    if not other or not name or other == name:
        return False
    return other.startswith(name) or name.startswith(other) or plan_codec._stem(other) == plan_codec._stem(name)


def _word_alphabet(word: str) -> set:
    """The characters more of `word` may hold: its own, and the whole hex or base64 alphabet its letters and digits
    belong to (a rest need not hold every character of the head, nor the head every character of the rest)."""
    own = set(word) | {"="}
    core = {c for c in own if c.isalnum()}
    return own | (_HEX if core <= _HEX else _B64 if core <= _B64 else set())


def head_piece(text, plan_text, word=None, name=None) -> bool:
    """Day 27 (script residuals): whether plan_codec shows the word's plan going on past it: a longer plan that begins
    with it (plan_codec.longest), or its literal's rest in another value of its dict, a related name (the suffix
    variable `Material_x_tail='<rest>'`) or a function's return (plan_codec.continued_plans). The word reader took
    such a head whole and its cut last value went out PLAIN (`file_path=C:/ProgramData/HuntressLab`).
    With the `word` given, plan_codec is asked only when some other value could be its rest: written in the word's
    alphabet, no part of it, and eight characters or more, or four or more under a name related to the word's
    (`name`: NAME<more>, or one stem). Short words beside the material (`'0600'`, `'left'`, `'wget'`: 35 of the 60
    saved Day 6 to 9 shell words) are no rest, and the full reading plan_codec would make here is one this module's
    answers otherwise never need (Day 9's Mastery: +0.11 s)."""
    try:
        if word is not None:
            own = _word_alphabet(word)

            def rest(v, n=None):
                if len(v) < 4 or v == word or not set(v) <= own or _part(v, word):
                    return False
                return len(v) >= 8 or (n is not None and _related(n, name))
            if not (any(rest(v, n) for n, v in assignments(text))
                    or any(rest(s) for _, _, s, _ in plan_codec._literals(text))):
                return False
        return (plan_codec.head_of(plan_text, plan_codec.longest(text, ".sh"))
                or plan_text in plan_codec.continued_plans(text, ".sh"))
    except Exception:  # noqa: BLE001 - a check that fails proves nothing whole: the owner's reading instead
        return True


def outside(text, best, why=None):
    """Whether every plan plan_codec finds in the file (its own sources: literals, joins, bare tokens,
    number lists) agrees with the word reader's: a prefix of it, or read from a part of its word. A plan
    from anywhere else that is not a prefix (a decoy, a longer copy) is a doubt the word reader cannot
    settle, and it answers nothing."""
    plan_text, word = best[0], best[4]
    cribs = plan_codec.hooks("sh")[0]
    cribs = plan_codec.CRIBS + [c for c in cribs if c not in plan_codec.CRIBS] if cribs else None
    for _how, data, _grade, s in plan_codec._sources(text, plan_codec._literals(text), cribs):
        for _tr, raw in plan_codec.undo(data, cribs):
            t = plan_codec.looks_like_plan(raw)
            if not t or plan_text.startswith(t) or (s is not None and _part(s, word)):
                continue
            again = None if t.startswith('{') else plan_codec.PLAN_START.search(t, 1)
            if again and plan_text.startswith(t[:again.start()]):
                continue                       # two copies in one candidate: the first ends where the second begins
            if why is not None:
                why.append(f"plan_codec reads another plan from {'a number list' if s is None else f'a literal of {len(s)} characters'}")
            return False
    return True


# ---------------------------------------------------------------- the owner's way (Day 6 base, live on its clocks)
# Touching quoted pieces ('ab''cd') are rewritten as one single-quoted literal, then plan_codec.reading decodes;
# an indicator is answered only when reading grades the plan whole (no note).

_RUN = re.compile(r"(?:'[^']*'|\"[^\"\\$`]*\"){2,}")
_PART = re.compile(r"'([^']*)'|\"([^\"\\$`]*)\"")
_IND = re.compile(r"exact\s+([A-Za-z_][A-Za-z0-9_]*)\s+indicator", re.I)


def _joined(text):
    def one(m):
        body = ''.join(a if a is not None else b for a, b in _PART.findall(m.group(0)))
        return m.group(0) if "'" in body else "'" + body + "'"
    return _RUN.sub(one, text)


def _text(files, member):
    data = files.get(member)
    if data is None:
        for k, v in files.items():
            if pathlib.Path(k).name == member:
                data = v
                break
    return None if data is None else plan_codec.text_of(data)


def _steps(v):
    if v is None:
        return None      # a plan without steps: str(None) was read as the one step `None` and answered plain
    items = [str(x).strip() for x in v] if isinstance(v, (list, tuple)) else [s.strip() for s in re.split(r"[,>]", str(v))]
    items = [s for s in items if s]
    return items or None


def _asks_graph(q):
    """Whether the ordered steps are asked: the id's field word (`-steps`). Only an id that names no field is
    read by its wording, as before Day 12, whose role and attack questions say "behavior graph" too."""
    said = generic.id_asks(q, "steps")
    if said is not None:
        # The advanced-syntax family (`bash-advanced-<name>-steps`, Day 7) was never this reading's: its text
        # ("the ordered analysis steps") did not match the words below, and generic.py answered it, whole or
        # nothing. It stays there, now by its id; the owner's any-reading answer is for the behavior graphs.
        return said and generic.bare_id(q).split("-")[1:2] != ["advanced"]
    qt = q.get("question") or ""
    return "behavior graph" in qt and ">" in qt and "separator" in qt


def _steps_answer(q, plan):
    st = _steps(plan.get("steps")) if plan else None
    if not st:
        return None
    # The one rule of the lane (generic.step_list, review of 2026-10-12): plain only as `a>b` where the syntax
    # states `>` and no spaces, else unsure under the lane's one key, so one probe settles every extension.
    return generic.step_list(q, ",".join(st), st)


class _Readings:
    """plan_codec.reading of the file as written and with touching pieces joined, each computed once."""

    def __init__(self, text):
        self.text, self._got = text, {}

    def get(self, joined):
        if joined not in self._got:
            self._got[joined] = plan_codec.reading(_joined(self.text) if joined else self.text, "sh")
        return self._got[joined]

    def whole(self):
        got, note = self.get(True)
        return plan_codec.flatten(got[0]) if got and not note else {}

    def any(self):
        for joined in (True, False):
            got, _note = self.get(joined)
            if got:
                return plan_codec.flatten(got[0])
        return {}


def _owner(qs, rd):
    """Day 6's live answers: steps from any plan reading gives, an indicator only from a plan read whole."""
    out, whole, anyp = {}, None, None
    for q in qs:
        if _asks_graph(q):
            if anyp is None:
                anyp = rd.any()
            out[q["qid"]] = _steps_answer(q, anyp)
            continue
        m = _IND.search(q.get("question") or "")
        if m:
            if whole is None:
                whole = rd.whole()
            # An indicator question only where the id agrees: the text's key is one the id's own field word can
            # mean (`-host-id` and host_id), or the id names no field. An id that asks for something else
            # (`-steps`, `-role`) is not answered here whatever its text names: generic's, by the id.
            if generic.names_field(q) and not generic.near_key(generic.tail_of(q), m.group(1)):
                continue
            key = generic.tail_of(q).replace("-", "_")
            if not (generic.names_field(q) and key in whole):
                key = m.group(1)
            v = whole.get(key)
            if v is not None and str(v) != "":
                out[q["qid"]] = str(v)
    return out


# ---------------------------------------------------------------- answers

def _from_words(member, qs, text, rd, got):
    plan_text, how, transform, var, _word = got
    info = {"name": member, "ext": ".sh", "text": text, "plan_text": plan_text, "how": how,
            "transform": transform, "plan": plan_codec.flatten(plan_text),
            "label": plan_codec.label_of(text, ".sh"), "census": None, "notes": [], "ambiguous": False,
            "cut": False, "role_q": next((q for q in qs if generic.asks_role(q)), None)}
    print(f"[lang_sh] {member}: plan read whole from {var} as {how} | {transform}", file=sys.stderr)
    out = {}
    for q in qs:
        if generic.is_control(q) or generic.tail_of(q) in ("representation", "transform"):
            continue                  # census and the codec label: generic's route, unchanged
        if _asks_graph(q):
            out[q["qid"]] = _steps_answer(q, info["plan"])
            continue
        v = generic.answer(q, info)
        if v is None or v == "":
            continue
        out[q["qid"]] = generic.formatted(q, generic.listed(q, v))   # as generic.answers checks its own
    for note in info["notes"]:
        print(f"[lang_sh]   {note}", file=sys.stderr)
    return out


def _refused(member, text) -> bool:
    """Whether the file carries a tagged descriptor from which the general path took NO plan (generic.read: the
    copies differ, one is cut or decorated, two plans). Review of 2026-10-12: the owner's reading then answered
    from the literal alone, a cut url plain. Only a file with a descriptor is read a second time."""
    mod = plan_codec.optional("descriptor")
    try:
        if mod is None or not hasattr(mod, "present") or not mod.present(text):
            return False
        info = generic.read(member or "specimen.sh", text)
    except Exception:  # noqa: BLE001 - a check that fails proves nothing about the file: refused
        return True
    # B-247 (backlog: this reader answering other fields plain from a refused descriptor): a descriptor the general
    # path took CUT (its copies agree on a plan that stops inside its last value: d_cut_both) is settled as far as
    # it goes; the literal read alone here gave the cut url plain. Nothing past the cut is answered from a copy.
    return bool(info.get("descriptor")) and (bool(info.get("ambiguous")) and not info.get("plan")
                                             or bool(info.get("cut")))


def specimen(member, qs, files):
    text = _text(files, member) if member else None
    if not text:
        return {}
    if _refused(member, text):
        print(f"[lang_sh] {member}: the general path refused the file's tagged descriptor: nothing is answered from "
              f"one of its copies", file=sys.stderr)
        return {}
    rd, why = _Readings(text), []
    qs = generic.with_fields(qs)     # the field word of every id, for both readings below
    try:
        got = whole_plan(text, why)
        if got is not None and head_piece(text, got[0], got[4], got[3]):
            why.append("plan_codec reads its word going on (a longer plan, or its rest in a dict entry, a related "
                       "name, a function's return): the word may be a head")
            got = None
        if got is not None and outside(text, got, why):
            return _from_words(member, qs, text, rd, got)
    except Exception as e:  # noqa: BLE001 - the word reader's failure costs its own answers only
        why.append(f"the word reader raised {type(e).__name__}: {e}")
    print(f"[lang_sh] {member}: no whole plan from shell words ({'; '.join(why) or 'none'}); the owner's reading",
          file=sys.stderr)
    return _owner(qs, rd)


def answers(questions, files, ctx):
    missing = [n for n, m in (("generic", generic), ("plan_codec", plan_codec)) if m is None]
    if missing:
        # specimen() calls generic.with_fields outside any try: without the sibling there is no answer path.
        print(f"[lang_sh] {', '.join(m + '.py' for m in missing)} not found beside lang_sh.py: no answers",
              file=sys.stderr)
        return {}
    out = {}
    by_member = {}
    for q in questions:
        by_member.setdefault(q.get("member") or (q.get("artifact") or "").split("->")[-1].strip(), []).append(q)
    for member, qs in by_member.items():
        out.update(specimen(member, qs, files))
    return {k: v for k, v in out.items() if v is not None}
