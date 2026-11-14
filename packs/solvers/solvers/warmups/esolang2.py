"""Arbitrary-payload esolang readers for Warmups (wave 15 crypto/esolang breadth build, 2026-10-24).

Why this file exists
--------------------
The Warmups lane's standing weakness is morning-of adaptation to a NEW encoding, and the esolang
family is a classic "decode this program and submit the slug" warmup shape. An audit of what is
already shipped shows the arbitrary-payload esolangs that are covered, and so are NOT duplicated:

  Brainfuck, Ook!, Short Ook              solvers/common/classical.py       (crib_decode d_bf; Short Ook
                                          and lowercase ook since row 546 only)
  COW, Whitespace, Befunge-93,            solvers/warmups/esolangs.py       (crib_decode d_cow and M)
  Malbolge, JSFuck, Deadfish
  Alphuck, Pikalang, Blub, Spoon          solvers/warmups/esolang.py        (ESL, wave 4)

The gap named in docs/retro/ctf-solver-gap-analysis.md (A-mid Warmups: "Shakespeare / Rockstar /
Befunge-98 / Chef") is the remaining set of TURING-complete, arbitrary-OUTPUT esolangs a warmup can
use to carry a slug. This file adds the two of those with a self-contained, deterministic,
no-input execution model that maps cleanly onto a bounded VM:

  chef         David Morgan-Mar's "Chef" (mixing bowls, baking dishes, Liquefy, Serves)
  shakespeare  Hasselstrom & Aslund's "Shakespeare Programming Language" (SPL)

Befunge-98 is NOT added: the common case is already read by esolangs.befunge (-93), and the -98
superset (fingerprints, stack-stack, self-modification) has no deterministic bounded subset worth
the risk. Rockstar is NOT added: it is a full dynamic language with no small deterministic core.
Both are recorded as deliberately-left in the build report.

NEVER WRONG
-----------
Nothing here is answered on a language's own name. A reading is plain ONLY because crib_decode's
search confirms the program's output continues the exact 87-character sentence (crib_decode.CRIB);
the read() helper applies that same crib gate for standalone / test use. A blob that merely parses
as Chef or SPL but prints anything other than the sentence yields NOTHING, never a wrong slug. The
interpreters are deliberately STRICT: any construct they do not fully model (a loop, an auxiliary
recipe, an input read, a non-deterministic op such as Chef's "Mix well", a word outside the known
grammar) makes the WHOLE program yield None -- never a partial or guessed output. An incomplete
interpreter therefore costs coverage, never correctness: a program it cannot model is None, and the
crib gate rejects any output that is not the sentence, so a wrong slug can never be emitted.

warm() safety
-------------
Pure functions, no I/O, no global mutable state, no clock of their own (an internal deadline is
derived per call from time.perf_counter()), no import of crib_decode. Bounded by the program length,
a hard step cap, an output cap and a wall-clock backstop. Safe to call from a timed solve and from a
warm thread alike.

Wiring (this module changes no shipped file; the build-lead mirrors the ESL hookup in crib_decode.py):

    BY_NAME   {step name: decoder(bytes) -> bytes | None}
    NAMES     frozenset(BY_NAME)
    _which(cur) -> tuple of applicable step names (a cheap anchored-signature gate)
    steps(cur)  -> list[(name, bytes)]
    step_fn(name) -> decoder(bytes) -> bytes | None

    1. `import esolang2 as ESL2` with the same try/except guard as `import esolang as ESL`.
    2. in `_strict_steps`, after `yield from ESL.steps(cur)`, add
       `if ESL2 is not None: yield from ESL2.steps(cur)`.
    3. next to the ESL merge, add `if ESL2 is not None: _STRICT_NAMES |= set(ESL2.NAMES);
       _FORM_NAMES |= set(ESL2.NAMES)`.
    4. in `_step_fn`, add `if ESL2 is not None and name in ESL2.NAMES: return ESL2.step_fn(name)`.

Every name here is strict (a deterministic info-complete transform), so each is in _STRICT_NAMES and
its chain is answered plain when the crib matches. No saved Warmups payload is read by any reader
here (the test proves it on the shipped fixtures), so no earlier day can move.
"""

import math
import re
import sys
import time

# -- bounds ---------------------------------------------------------------------------------------
STEPS = 2_000_000         # hard step cap of each interpreter
OUTPUT = 65_536           # bytes a program may print before it is abandoned (None)
TICK = 1 << 14            # steps between two looks at the wall clock
READER_TIME = 0.05        # wall-clock backstop (s) one reader call may run (COW's COW_TIME)
MAX_PROG = 256 * 1024     # bytes of a program a reader runs (esolang source is verbose)
MIN_PROG = 24             # bytes below which nothing is attempted (noise)
MAX_UNICHR = 0x10FFFF     # a printed code point above this, or a surrogate, is a refusal


def _text(b):
    """A byte payload as a str within the size bounds, or None. Chef and SPL are Latin-1-clean
    source; a payload outside the size bounds, or holding a NUL, is refused before any work."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    b = bytes(b)
    if not (MIN_PROG <= len(b) <= MAX_PROG) or b"\x00" in b:
        return None
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return b.decode("latin-1")
        except UnicodeDecodeError:
            return None


def _deadline():
    return time.perf_counter() + READER_TIME


def _as_char(value: int):
    """The one printed character of a numeric value, or None when it is not a valid code point.
    Chef liquid output and SPL 'Speak your mind' both print chr(value)."""
    if value < 0 or value > MAX_UNICHR or 0xD800 <= value <= 0xDFFF:
        return None
    return chr(value)


# =================================================================================================
# Chef  (David Morgan-Mar, 2002; esolangs.org/wiki/Chef)
# =================================================================================================
#
# Execution model, strict subset:
#   - Ingredients define named values with a state (dry -> printed as a number; liquid -> printed
#     as a character). A mixing bowl and a baking dish are stacks of (value, is_liquid) items.
#   - Supported Method statements: Put, Fold, Add/Remove/Combine/Divide [dry ingredients],
#     Liquefy (ingredient | contents of the bowl), Stir, Clean, Pour, Set aside is refused.
#   - Serves N prints the first N baking dishes, each from the top of the stack downwards.
#   - REFUSED (whole program -> None): loops ("... until <verbed>"), auxiliary recipes
#     ("Serve with"), input ("Take ... from refrigerator"), non-determinism ("Mix ... well"),
#     "Refrigerate", and any statement the parser does not recognise. This keeps the reader
#     never-wrong: it only ever emits the exact deterministic output of a fully-modelled program.

_CHEF_ORD = re.compile(r"^(\d+)(?:st|nd|rd|th)$")
_CHEF_HDR_INGREDIENTS = re.compile(r"(?m)^[ \t]*Ingredients\.[ \t]*$")
_CHEF_HDR_METHOD = re.compile(r"(?m)^[ \t]*Method\.[ \t]*$")
# A dry measure forces a number; a liquid measure forces a character; otherwise unspecified (dry-ish).
_CHEF_DRY = {"g", "kg", "pinch", "pinches"}
_CHEF_LIQUID = {"ml", "l", "dash", "dashes"}
_CHEF_EITHER = {"cup", "cups", "teaspoon", "teaspoons", "tablespoon", "tablespoons"}
_CHEF_HEAP = {"heaped", "level"}


def _chef_bowl_index(words, i):
    """(ordinal, next-index) for an optional 'the [Nth] mixing bowl' / 'baking dish' starting at
    words[i]; ordinal defaults to 1. Returns (None, i) when no bowl phrase is there."""
    j = i
    if j < len(words) and words[j] == "the":
        j += 1
    n = 1
    if j < len(words):
        m = _CHEF_ORD.match(words[j])
        if m:
            n = int(m.group(1))
            j += 1
    # expect 'mixing bowl' or 'baking dish'
    if j + 1 < len(words) and words[j] == "mixing" and words[j + 1] == "bowl":
        return n, j + 2
    if j + 1 < len(words) and words[j] == "baking" and words[j + 1] == "dish":
        return n, j + 2
    return None, i


def _chef_parse_ingredients(block: str):
    """{name: (value, is_liquid)} from the ingredient lines, or None on a malformed line. A value
    may be absent (an ingredient only read from input), recorded as None and refused if used."""
    out = {}
    for raw in block.splitlines():
        line = raw.strip()
        if not line:
            continue
        words = line.split()
        i, value = 0, None
        if words and words[0].lstrip("-").isdigit():
            try:
                value = int(words[0])
            except ValueError:                 # over the int-string digit limit: unusable
                return None
            i = 1
        is_liquid = False
        if i < len(words) and words[i] in _CHEF_HEAP:          # heaped/level -> dry measure follows
            i += 1
            if i < len(words) and (words[i] in _CHEF_DRY or words[i] in _CHEF_EITHER):
                i += 1
        elif i < len(words) and words[i] in _CHEF_DRY:
            i += 1
        elif i < len(words) and words[i] in _CHEF_LIQUID:
            is_liquid = True
            i += 1
        elif i < len(words) and words[i] in _CHEF_EITHER:
            i += 1
        name = " ".join(words[i:]).strip()
        if not name:
            return None
        out[name] = (value, is_liquid)
    return out or None


def _chef_split_statements(block: str):
    """The Method statements: the first paragraph after 'Method.' (up to a blank line), split on
    sentence-final periods; the 'Serves N.' count is read from anywhere in the block (the spec puts
    it in its own trailing paragraph). Returns (statements, serves_n) or None when unusable."""
    # The method statements are the first non-blank paragraph.
    para = []
    for ln in block.splitlines():
        if not ln.strip() and para:
            break
        if ln.strip():
            para.append(ln.strip())
    text = " ".join(para)
    if not text:
        return None
    serves_n = None
    sm = re.search(r"(?i)\bServes\s+(\d+)", block)
    if sm:
        serves_n = int(sm.group(1))
    # Split into sentences on '.' / '!' (each Chef statement ends with a period). A 'Serves'
    # statement that fell inside the paragraph ends the statement list.
    statements = []
    for s in re.split(r"[.!]", text):
        s = s.strip()
        if not s:
            continue
        if s.lower().startswith("serves"):
            break
        statements.append(s)
    return statements, serves_n


def _chef_run(ingredients, statements, serves_n, deadline):
    """Execute the strict Chef subset. Returns printed bytes or None (refusal on any unmodelled
    construct, an undefined value used, an empty-bowl op, or a bad code point)."""
    if serves_n is None:
        return None
    bowls = {}            # index -> list[[value, is_liquid]] (top == end)
    dishes = {}           # index -> list[[value, is_liquid]]
    ing = {k: list(v) for k, v in ingredients.items()}   # name -> [value, is_liquid]

    def bowl(n):
        return bowls.setdefault(n, [])

    def dish(n):
        return dishes.setdefault(n, [])

    def value_of(name):
        if name not in ing or ing[name][0] is None:
            raise _Refuse
        return ing[name][0]

    steps = 0
    for s in statements:
        steps += 1
        if steps > STEPS:
            return None
        if not (steps & (TICK - 1)) and time.perf_counter() > deadline:
            return None
        words = s.split()
        if not words:
            continue
        verb = words[0]
        low = s.lower()
        try:
            if " until " in low:                       # loop close (and so some loop open): refuse
                return None
            if verb == "Put":
                # Put <ingredient> into [the [Nth]] mixing bowl
                name, rest = _chef_take_name(words, 1, ("into",))
                n, _ = _chef_bowl_index(rest, 1) if rest and rest[0] == "into" else (1, 0)
                if name is None or n is None:
                    return None
                bowl(n).append([value_of(name), ing[name][1]])
            elif verb == "Fold":
                name, rest = _chef_take_name(words, 1, ("into",))
                n, _ = _chef_bowl_index(rest, 1) if rest and rest[0] == "into" else (1, 0)
                if name is None or n is None or name not in ing or not bowl(n):
                    return None
                top = bowl(n).pop()
                ing[name] = [top[0], ing[name][1]]
            elif verb in ("Add", "Remove", "Combine", "Divide"):
                r = _chef_arith(verb, words, ing, bowls, value_of)
                if r is None:
                    return None
            elif verb in ("Liquefy", "Liquify"):
                if low.startswith(("liquefy contents", "liquify contents")):
                    n, _ = _chef_bowl_index(words, 3)   # "contents of [the [Nth]] mixing bowl"
                    if n is None:
                        n = 1
                    for item in bowl(n):
                        item[1] = True
                else:
                    name = " ".join(words[1:]).strip()
                    if name not in ing:
                        return None
                    ing[name][1] = True
            elif verb == "Stir":
                r = _chef_stir(words, ing, bowls, value_of)
                if r is None:
                    return None
            elif verb == "Clean":
                n, _ = _chef_bowl_index(words, 1)
                if n is None:
                    return None
                bowls[n] = []
            elif verb == "Pour":
                # Pour contents of [the [Nth]] mixing bowl into [the [Nth]] baking dish
                if not low.startswith("pour contents"):
                    return None
                try:
                    into = words.index("into")
                except ValueError:
                    return None
                nb, _ = _chef_bowl_index(words, 3)
                nd, _ = _chef_bowl_index(words, into + 1)
                if nb is None or nd is None:
                    return None
                dish(nd).extend([list(it) for it in bowl(nb)])
            elif verb in ("Mix",):                      # "Mix ... well": non-deterministic -> refuse
                return None
            elif verb in ("Take",):                     # input -> refuse
                return None
            elif verb in ("Refrigerate", "Serve"):      # Refrigerate / Serve with aux -> refuse
                return None
            elif verb in ("Set",):                      # "Set aside" (loop break) -> refuse
                return None
            else:
                return None                              # an unmodelled statement -> refuse
        except _Refuse:
            return None

    out = bytearray()
    for n in range(1, serves_n + 1):
        d = dishes.get(n, [])
        for value, is_liquid in reversed(d):            # top of the stack printed first
            if is_liquid:
                ch = _as_char(value)
                if ch is None:
                    return None
                out += ch.encode("utf-8")
            else:
                out += str(value).encode("ascii")
            if len(out) > OUTPUT:
                return None
    return bytes(out) or None


class _Refuse(Exception):
    pass


def _chef_take_name(words, i, stops):
    """(name, rest) where name is the ingredient words[i:j] up to the first stop word, rest is
    words[j:]. (None, words) when no name precedes a stop."""
    j = i
    while j < len(words) and words[j] not in stops:
        j += 1
    name = " ".join(words[i:j]).strip()
    return (name or None), words[j:]


def _chef_arith(verb, words, ing, bowls, value_of):
    """Add/Remove/Combine/Divide [dry ingredients] [to|from|into [the [Nth]] mixing bowl]. Modifies
    the top of the bowl in place. Returns True or None (refusal)."""
    if verb == "Add" and len(words) >= 3 and words[1] == "dry" and words[2] == "ingredients":
        total = sum(v[0] for v in ing.values() if v[0] is not None and not v[1])
        n, _ = _chef_find_bowl(words, 3)
        bowls.setdefault(n, []).append([total, False])
        return True
    stops = ("to", "from", "into")
    name, rest = _chef_take_name(words, 1, stops)
    if name is None or name not in ing or ing[name][0] is None:
        return None
    n, _ = _chef_find_bowl(rest, 1) if rest and rest[0] in stops else (1, 0)
    if n is None:
        return None
    b = bowls.setdefault(n, [])
    if not b:
        return None
    a = b[-1][0]
    x = value_of(name)
    if verb == "Add":
        b[-1][0] = a + x
    elif verb == "Remove":
        b[-1][0] = a - x
    elif verb == "Combine":
        b[-1][0] = a * x
    elif verb == "Divide":
        if x == 0:
            return None
        b[-1][0] = int(a / x) if (a < 0) != (x < 0) and a % x else a // x
    return True


def _chef_find_bowl(words, i):
    n, _ = _chef_bowl_index(words, i)
    return (1 if n is None else n), i


def _chef_stir(words, ing, bowls, value_of):
    """Stir [the [Nth] mixing bowl] for N minutes  |  Stir <ingredient> into the [Nth] mixing bowl.
    Rolls the top of the bowl down by N places. Returns True or None."""
    low = " ".join(words).lower()
    m = re.search(r"for\s+(\d+)\s+minute", low)
    if m:
        n, _ = _chef_bowl_index(words, 1)
        if n is None:
            n = 1
        depth = int(m.group(1))
    else:
        try:
            into = words.index("into")
        except ValueError:
            return None
        name = " ".join(words[1:into]).strip()
        if name not in ing or ing[name][0] is None:
            return None
        n, _ = _chef_bowl_index(words, into + 1)
        if n is None:
            return None
        depth = value_of(name)
    b = bowls.setdefault(n, [])
    if not b or depth < 0:
        return True
    top = b.pop()
    pos = max(0, len(b) - depth)
    b.insert(pos, top)
    return True


def d_chef(b):
    """Chef source -> printed bytes, or None. Strict: any unmodelled construct refuses the whole
    program (see _chef_run)."""
    t = _text(b)
    if t is None:
        return None
    mi = _CHEF_HDR_INGREDIENTS.search(t)
    mm = _CHEF_HDR_METHOD.search(t)
    if not mi or not mm or mm.start() <= mi.end():
        return None
    ingredients = _chef_parse_ingredients(t[mi.end():mm.start()])
    if ingredients is None:
        return None
    parsed = _chef_split_statements(t[mm.end():])
    if parsed is None:
        return None
    statements, serves_n = parsed
    if not statements:
        return None
    try:
        return _chef_run(ingredients, statements, serves_n, _deadline())
    except Exception:
        return None


# =================================================================================================
# Shakespeare Programming Language  (Hasselstrom & Aslund, 2001; esolangs.org/wiki/Shakespeare)
# =================================================================================================
#
# Execution model, strict subset:
#   - The Dramatis Personae declares characters (integer value + a stack each).
#   - Acts and Scenes carry roman-numeral labels used by "Let us proceed to scene/act <roman>".
#   - [Enter A and B] / [Exit A] / [Exeunt] move at most two characters on stage. A speaking
#     character addresses the OTHER character on stage; a line sets or reads the addressed one.
#   - Value phrases: nothing (0), reflexives, a noun phrase (sign * 2^adjectives), and the
#     arithmetic forms (sum/difference/product/quotient/remainder/twice/square/cube/square root/
#     factorial). Output: "Speak your mind" (character), "Open your heart" (number). Stack:
#     "Remember" (push), "Recall" (pop). Conditionals: a question sets a flag, "If so/If not"
#     gates the following action (an assignment, an output, or a goto).
#   - REFUSED (whole program -> None): input ("Listen to your heart", "Open your mind"), more than
#     two characters on stage, a word outside the known grammar in a value position, a goto to an
#     unknown label, and any line the parser does not recognise. Never-wrong as above.

# Negative nouns are worth -1; every other known noun (positive or neutral) is worth +1. The noun
# lexicon is only needed to find a noun-phrase boundary inside an arithmetic phrase; a plain
# assignment takes the last word as the noun, so an unlisted noun still assigns.
_SPL_NEG = {
    "bastard", "beggar", "blister", "codpiece", "coward", "curse", "death", "devil", "draught",
    "famine", "flirt-gill", "goat", "hate", "hell", "hog", "hound", "leech", "lie", "microsoft",
    "pig", "plague", "starvation", "toad", "war", "wolf",
}
_SPL_POS = {
    "angel", "bird", "blossom", "cat", "chihuahua", "cow", "daughter", "door", "fellow", "flower",
    "gentleman", "hair", "happiness", "hamster", "hero", "horse", "joy", "king", "lamp", "lantern",
    "lord", "man", "moon", "morning", "nephew", "niece", "pony", "puppy", "purse", "rainbow",
    "roman", "rose", "sister", "sky", "smile", "son", "squirrel", "stone", "summer", "sun",
    "sunflower", "sunrise", "sunshine", "tree", "uncle", "wind", "aunt", "brother", "cousin",
    "father", "mother", "grandfather", "grandmother", "animal", "plum", "kingdom", "heaven",
}
_SPL_NOUNS = _SPL_NEG | _SPL_POS
_SPL_ARTICLES = {"a", "an", "the", "my", "your", "his", "her", "its", "our", "their", "thy", "thine"}
_SPL_FIRST = {"myself", "i", "me"}
_SPL_SECOND = {"yourself", "thyself", "thee", "thou", "you"}
_SPL_ROMAN = {"i": 1, "ii": 2, "iii": 3, "iv": 4, "v": 5, "vi": 6, "vii": 7, "viii": 8, "ix": 9,
              "x": 10, "xi": 11, "xii": 12, "xiii": 13, "xiv": 14, "xv": 15, "xvi": 16, "xvii": 17,
              "xviii": 18, "xix": 19, "xx": 20}
_SPL_ADJ_FACT_CAP = 170        # factorial bounded so a parse cannot run away (170! overflows float, int is fine but capped)
_SPL_ADJ_SHIFT_CAP = 64        # a noun phrase with more adjectives than this is refused (runaway 2^k)


class _SPLRefuse(Exception):
    pass


def _spl_words(s):
    """Lower-cased word tokens of a sentence, apostrophes and hyphens kept inside a word."""
    return re.findall(r"[a-z][a-z'-]*", s.lower())


def _spl_value(words, i, me, you):
    """(value, next-index) for the value phrase starting at words[i]. Raises _SPLRefuse on an
    unparseable phrase. `me` is the speaker's value, `you` the addressed character's value."""
    if i >= len(words):
        raise _SPLRefuse
    w = words[i]
    if w in ("nothing", "zero"):
        return 0, i + 1
    if w in _SPL_FIRST:
        return me, i + 1
    if w in _SPL_SECOND:
        return you, i + 1
    if w == "twice":
        v, j = _spl_value(words, i + 1, me, you)
        return 2 * v, j
    if w == "the":
        return _spl_the(words, i + 1, me, you)
    # a plain noun phrase: [adjective...] noun, the noun being the first known noun (or the token
    # before the next connective when none is listed -- a lenient boundary, safe behind the crib).
    return _spl_noun_phrase(words, i, me, you)


_SPL_CONNECT = {"and", "if", "we", "let", "you", "speak", "open", "remember", "recall", "am", "is",
                "are", "listen", "be"}


def _spl_noun_phrase(words, i, me, you):
    j = i
    if words[j] in _SPL_ARTICLES:
        j += 1
    start = j
    noun_at = None
    while j < len(words):
        if words[j] in _SPL_NOUNS:
            noun_at = j
            break
        if words[j] in _SPL_CONNECT:
            break
        j += 1
    if noun_at is None:
        # no listed noun before a connective: treat the last consumed word as the noun (lenient).
        if j <= start:
            raise _SPLRefuse
        noun_at = j - 1
    nadj = noun_at - start
    if nadj < 0 or nadj > _SPL_ADJ_SHIFT_CAP:
        raise _SPLRefuse
    sign = -1 if words[noun_at] in _SPL_NEG else 1
    return sign * (1 << nadj), noun_at + 1


def _spl_the(words, i, me, you):
    """A phrase that began with 'the': sum/difference/product/quotient/remainder/square/cube/
    square root/factorial, or 'the <noun phrase>'."""
    def expect(tok, at):
        if at >= len(words) or words[at] != tok:
            raise _SPLRefuse
        return at + 1

    if i < len(words):
        w = words[i]
        if w == "sum":
            j = expect("of", i + 1)
            a, j = _spl_value(words, j, me, you)
            j = expect("and", j)
            b, j = _spl_value(words, j, me, you)
            return a + b, j
        if w == "difference":
            j = expect("between", i + 1)
            a, j = _spl_value(words, j, me, you)
            j = expect("and", j)
            b, j = _spl_value(words, j, me, you)
            return a - b, j
        if w == "product":
            j = expect("of", i + 1)
            a, j = _spl_value(words, j, me, you)
            j = expect("and", j)
            b, j = _spl_value(words, j, me, you)
            return a * b, j
        if w == "quotient":
            j = expect("between", i + 1)
            a, j = _spl_value(words, j, me, you)
            j = expect("and", j)
            b, j = _spl_value(words, j, me, you)
            if b == 0:
                raise _SPLRefuse
            return int(a / b), j
        if w == "remainder":
            j = expect("of", i + 1)
            j = expect("the", j)
            j = expect("quotient", j)
            j = expect("between", j)
            a, j = _spl_value(words, j, me, you)
            j = expect("and", j)
            b, j = _spl_value(words, j, me, you)
            if b == 0:
                raise _SPLRefuse
            return int(math.fmod(a, b)), j
        if w == "square":
            if i + 1 < len(words) and words[i + 1] == "root":
                j = expect("of", i + 2)
                a, j = _spl_value(words, j, me, you)
                if a < 0:
                    raise _SPLRefuse
                return math.isqrt(a), j
            j = expect("of", i + 1)
            a, j = _spl_value(words, j, me, you)
            return a * a, j
        if w == "cube":
            j = expect("of", i + 1)
            a, j = _spl_value(words, j, me, you)
            return a * a * a, j
        if w == "factorial":
            j = expect("of", i + 1)
            a, j = _spl_value(words, j, me, you)
            if a < 0 or a > _SPL_ADJ_FACT_CAP:
                raise _SPLRefuse
            return math.factorial(a), j
    # 'the <noun phrase>'
    return _spl_noun_phrase(words, i - 1, me, you)   # include 'the' as the article


def _spl_parse(t):
    """(lines, scenes) where lines is a flat list of executable items and scenes maps
    (act, scene) -> line index. Returns None on a structural problem."""
    # Characters: lines before the first Act of the form "Name, description."
    body_start = 0
    first_act = re.search(r"(?mi)^[ \t]*Act\s+[ivxlcdm]+\s*:", t)
    header = t[:first_act.start()] if first_act else t
    chars = set()
    for ln in header.splitlines():
        m = re.match(r"^([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)\s*,", ln.strip())
        if m:
            chars.add(m.group(1))
    if not chars or not first_act:
        return None
    return chars, first_act.start()


def _spl_run(t, deadline):
    parsed = _spl_parse(t)
    if parsed is None:
        return None
    chars, start = parsed

    # Tokenise the body into a flat item list, recording scene/act labels.
    items = []                      # ("act", n) | ("scene", n) | ("enter", [names]) | ("exit",[names])
                                    # | ("exeunt", []) | ("line", speaker, sentence)
    labels = {}                     # (act, scene) -> item index
    cur_act = None
    body = t[start:]
    # Pull bracketed stage directions out as their own tokens on their own lines.
    body = re.sub(r"\[([^\]]*)\]", lambda m: "\n[" + m.group(1).strip() + "]\n", body)
    lines = body.split("\n")
    buf_speaker = None
    buf = []

    def flush():
        nonlocal buf, buf_speaker
        if buf_speaker is not None:
            text = " ".join(buf).strip()
            for sent in re.split(r"(?<=[.!?])\s+", text):
                sent = sent.strip()
                if sent:
                    items.append(("line", buf_speaker, sent))
        buf, buf_speaker = [], None

    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        ma = re.match(r"(?i)^Act\s+([ivxlcdm]+)\s*:", s)
        if ma:
            flush()
            cur_act = _SPL_ROMAN.get(ma.group(1).lower())
            if cur_act is None:
                return None
            items.append(("act", cur_act))
            continue
        ms = re.match(r"(?i)^Scene\s+([ivxlcdm]+)\s*:", s)
        if ms:
            flush()
            sc = _SPL_ROMAN.get(ms.group(1).lower())
            if sc is None or cur_act is None:
                return None
            labels[(cur_act, sc)] = len(items)
            items.append(("scene", sc))
            continue
        if s.startswith("["):
            flush()
            inner = s[1:].rstrip("]").strip()
            low = inner.lower()
            if low.startswith("enter"):
                names = _spl_names(inner[5:], chars)
                items.append(("enter", names))
            elif low.startswith("exeunt"):
                names = _spl_names(inner[6:], chars)
                items.append(("exeunt", names))
            elif low.startswith("exit"):
                names = _spl_names(inner[4:], chars)
                items.append(("exit", names))
            else:
                return None
            continue
        m = re.match(r"^([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)\s*:\s*(.*)$", s)
        if m and m.group(1) in chars:
            flush()
            buf_speaker = m.group(1)
            if m.group(2).strip():
                buf.append(m.group(2).strip())
        elif buf_speaker is not None:
            buf.append(s)
        else:
            return None
    flush()

    return _spl_exec(items, labels, chars, deadline)


def _spl_names(text, chars):
    names = []
    for tok in re.split(r"\s+and\s+|,", text):
        tok = tok.strip().rstrip(".!?")
        if tok in chars:
            names.append(tok)
    return names


def _spl_exec(items, labels, chars, deadline):
    values = {c: 0 for c in chars}
    stacks = {c: [] for c in chars}
    on_stage = []                 # at most 2
    out = bytearray()
    flag = None                   # last question's boolean
    pc, steps = 0, 0
    while pc < len(items):
        steps += 1
        if steps > STEPS:
            return None
        if not (steps & (TICK - 1)) and time.perf_counter() > deadline:
            return None
        it = items[pc]
        kind = it[0]
        if kind in ("act", "scene"):
            pc += 1
            continue
        if kind == "enter":
            for n in it[1]:
                if n not in on_stage:
                    on_stage.append(n)
            if len(on_stage) > 2:
                return None
            pc += 1
            continue
        if kind == "exit":
            for n in it[1]:
                if n in on_stage:
                    on_stage.remove(n)
            pc += 1
            continue
        if kind == "exeunt":
            if it[1]:
                for n in it[1]:
                    if n in on_stage:
                        on_stage.remove(n)
            else:
                on_stage = []
            pc += 1
            continue
        # a line
        speaker, sent = it[1], it[2]
        if speaker not in on_stage:
            return None
        others = [c for c in on_stage if c != speaker]
        if len(others) != 1:
            return None
        addr = others[0]
        r = _spl_line(sent, speaker, addr, values, stacks, out, labels, flag)
        if r is None:
            return None
        action, payload = r
        if action == "flag":
            flag = payload
        elif action == "goto":
            if payload not in labels:
                return None
            pc = labels[payload]
            flag = None
            continue
        elif action == "halt":
            break
        if len(out) > OUTPUT:
            return None
        pc += 1
    return bytes(out) or None


def _spl_line(sent, speaker, addr, values, stacks, out, labels, flag):
    """Execute one sentence. Returns (action, payload):
       ("ok", None) | ("flag", bool) | ("goto", (act,scene)) | ("halt", None), or None to refuse."""
    low = sent.lower().strip().rstrip(".!?").strip()
    me, you = values[speaker], values[addr]

    # Conditional prefix: "if so, <rest>" / "if not, <rest>"
    m = re.match(r"^if\s+(so|not)\s*,?\s*(.*)$", low)
    if m:
        want = (m.group(1) == "so")
        rest = m.group(2).strip()
        if not rest:
            return ("ok", None)
        if flag is None or flag != want:
            return ("ok", None)
        return _spl_line(rest, speaker, addr, values, stacks, out, labels, None)

    # Goto
    mg = re.match(r"^(?:let us|we shall|we must)\s+(?:proceed to|return to)\s+(scene|act)\s+([ivxlcdm]+)", low)
    if mg:
        rn = _SPL_ROMAN.get(mg.group(2))
        if rn is None:
            return None
        if mg.group(1) == "scene":
            # proceed within the current act: find any label with this scene whose act matches a
            # recorded one. Since act is implicit, resolve against the nearest act of this scene.
            target = _spl_scene_target(labels, rn)
            if target is None:
                return None
            return ("goto", target)
        else:
            target = _spl_act_target(labels, rn)
            if target is None:
                return None
            return ("goto", target)

    # Output
    if re.search(r"\b(speak your mind|open your voice|open your mind to)\b", low):
        pass  # fallthrough handled below for exact phrases
    if "speak your mind" in low:
        ch = _as_char(you)
        if ch is None:
            return None
        out += ch.encode("utf-8")
        return ("ok", None)
    if "open your heart" in low:
        out += str(you).encode("ascii")
        return ("ok", None)
    # Input -> refuse
    if "listen to your heart" in low or "open your mind" in low:
        return None

    # Stack
    if low.startswith("remember"):
        rest = low[len("remember"):].strip()
        words = _spl_words(rest)
        try:
            v, _ = _spl_value(words, 0, me, you)
        except _SPLRefuse:
            return None
        stacks[addr].append(v)
        return ("ok", None)
    if low.startswith("recall"):
        if not stacks[addr]:
            return None
        values[addr] = stacks[addr].pop()
        return ("ok", None)

    # Question -> set flag
    mq = re.match(r"^(?:am i|are you|is\b.*)", low)
    if low.endswith("?") or "as good as" in low or " better than" in low or " worse than" in low \
            or re.search(r"\bas\s+\w+\s+as\b", low):
        fv = _spl_question(low, me, you, speaker, addr, values)
        if fv is None:
            return None
        return ("flag", fv)

    # Assignment: "you are <phrase>" / "you <phrase>" / "<addr> is <phrase>"
    ma = re.match(r"^(?:you are|you|thou art|thou)\s+(.*)$", low)
    if not ma:
        # "<name> is as <adj> as <phrase>" style assignment to the addressed character
        ma = re.match(r"^\w[\w'-]*\s+(?:is|are)\s+(.*)$", low)
    if ma:
        phrase = ma.group(1).strip()
        phrase = re.sub(r"^as\s+\w+\s+as\s+", "", phrase)   # "as <adj> as <noun phrase>"
        words = _spl_words(phrase)
        try:
            v, _ = _spl_value(words, 0, me, you)
        except _SPLRefuse:
            return None
        values[addr] = v
        return ("ok", None)

    return None


def _spl_question(low, me, you, speaker, addr, values):
    """A comparison question -> bool, or None to refuse. Supports 'as <adj> as' (equality) and
    '<comparative> than' (greater/less)."""
    # Resolve the two operands around the comparator.
    m = re.search(r"\bas\s+\w+\s+as\s+(.*)$", low)
    if m:
        left = me if low.startswith("am i") else you
        words = _spl_words(m.group(1))
        try:
            right, _ = _spl_value(words, 0, me, you)
        except _SPLRefuse:
            return None
        return left == right
    m = re.search(r"(.*?)\b(better|more|bigger|greater|worse|less|smaller)\s+than\s+(.*)$", low)
    if m:
        try:
            lw = _spl_words(re.sub(r"^(?:is|are|am i)\s+", "", m.group(1).strip()))
            lv, _ = _spl_value(lw, 0, me, you) if lw else (you, 0)
            rv, _ = _spl_value(_spl_words(m.group(3)), 0, me, you)
        except _SPLRefuse:
            return None
        if m.group(2) in ("better", "more", "bigger", "greater"):
            return lv > rv
        return lv < rv
    return None


def _spl_scene_target(labels, scene):
    cands = [k for k in labels if k[1] == scene]
    if not cands:
        return None
    return min(cands)


def _spl_act_target(labels, act):
    cands = [k for k in labels if k[0] == act]
    if not cands:
        return None
    return min(cands)


def d_shakespeare(b):
    """Shakespeare (SPL) source -> printed bytes, or None. Strict (see _spl_run)."""
    t = _text(b)
    if t is None:
        return None
    try:
        return _spl_run(t, _deadline())
    except Exception:
        return None


# =================================================================================================
# registry (esolang.py interface)
# =================================================================================================
BY_NAME = {"chef": d_chef, "shakespeare": d_shakespeare}
NAMES = frozenset(BY_NAME)

# Cheap anchored signature gates. A base64/hex/decimal warmup blob matches none of them, so the
# common path pays one failed search per gate and no interpreter runs. Each decoder re-checks
# itself exactly, so a signature match is never by itself an answer.
_GATE_CHEF = re.compile(rb"(?ms)^[ \t]*Ingredients\.[ \t]*$.*?^[ \t]*Method\.[ \t]*$")
_GATE_SPL = re.compile(rb"(?i)\[\s*(?:enter|exeunt|exit)\b")
_GATE_SPL_ACT = re.compile(rb"(?im)^[ \t]*Act\s+[ivxlcdm]+\s*:")


def _which(cur) -> tuple:
    """The step names whose signature a payload could match (a cheap gate). Each decoder still
    checks itself exactly, so a signature match is never by itself an answer."""
    if not isinstance(cur, (bytes, bytearray, memoryview)):
        return ()
    b = bytes(cur)
    if not (MIN_PROG <= len(b) <= MAX_PROG) or b"\x00" in b:
        return ()
    names = []
    if _GATE_CHEF.search(b):
        names.append("chef")
    if _GATE_SPL.search(b) and _GATE_SPL_ACT.search(b):
        names.append("shakespeare")
    return tuple(names)


def steps(cur) -> list:
    """[(name, bytes)]: what the readers of this module make of one payload."""
    out = []
    for name in _which(cur):
        try:
            o = BY_NAME[name](cur)
        except Exception:
            o = None
        if o:
            out.append((name, o))
    return out


def step_fn(name: str):
    """The decoder (bytes -> bytes or None) of one step by its name, or None. Like esolang's
    step_fn, the returned function re-checks the signature with _which so a chain cannot apply a
    reader to a payload its gate would reject."""
    fn = BY_NAME.get(name)
    if fn is None:
        return None

    def f(b):
        return fn(b) if name in _which(b) else None

    f.__name__ = "d_" + name
    return f


# -- crib-gated reader (standalone / test use; mirrors crib_decode's search) ----------------------
CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "


def read(blob, crib: str = CRIB):
    """Every (name, decoded text) this module reads whose decode CONTINUES the crib sentence. This
    is the never-wrong gate the full solver applies: a reader is answered plain only when its bytes
    reproduce the exact sentence, so a decoy that merely parses yields NOTHING, not a wrong slug."""
    found = []
    for name, out in steps(blob):
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text.startswith(crib):
            found.append((name, text))
    return found


# -- encoders (tests and round-trip only; never used by the solver) -------------------------------
def chef_encode(data: bytes) -> bytes:
    """A straight-line Chef recipe that prints `data`: one ingredient per byte, pushed in reverse so
    the baking dish prints forward, liquefied, poured, served."""
    lines = ["Printer Souffle.", "", "Ingredients."]
    names = []
    for idx, byte in enumerate(data):
        name = "ingredient%d" % idx
        names.append(name)
        lines.append("%d ml %s" % (byte, name))        # ml -> liquid -> printed as a character
    lines += ["", "Method."]
    for idx in range(len(data) - 1, -1, -1):            # reverse: last byte pushed first
        lines.append("Put %s into the mixing bowl." % names[idx])
    lines.append("Liquefy contents of the mixing bowl.")
    lines.append("Pour contents of the mixing bowl into the baking dish.")
    lines += ["", "Serves 1.", ""]
    return "\n".join(lines).encode("utf-8")


def _spl_int_phrase(n: int) -> str:
    """An SPL value phrase equal to the non-negative integer n, built from powers of two (a noun
    with k adjectives == 2^k) summed together. 0 == 'nothing'."""
    if n == 0:
        return "nothing"
    bits = [k for k in range(n.bit_length()) if (n >> k) & 1]
    terms = []
    for k in bits:
        terms.append("a " + "furry " * k + "cat")       # cat == +1, each 'furry' doubles -> 2^k
    phrase = terms[0]
    for term in terms[1:]:
        phrase = "the sum of %s and %s" % (phrase, term)
    return phrase


def shakespeare_encode(data: bytes) -> bytes:
    """A minimal SPL program that prints `data`: Romeo sets Juliet to each code point and has her
    speak her mind. Deterministic, no input."""
    lines = ["The Printer.", "", "Romeo, a young man.", "Juliet, a young woman.", "",
             "Act I: The printing.", "", "Scene I: The output.", "", "[Enter Romeo and Juliet]", ""]
    for byte in data:
        lines.append("Romeo: You are %s. Speak your mind." % _spl_int_phrase(byte))
    lines += ["", "[Exeunt]", ""]
    return "\n".join(lines).encode("utf-8")


ENCODERS = {"chef": chef_encode, "shakespeare": shakespeare_encode}


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: esolang2.py <file> [...]", file=sys.stderr)
        return 2
    for path in argv:
        try:
            raw = open(path, "rb").read()
        except OSError as e:
            print("%s: %s" % (path, e.strerror or e), file=sys.stderr)
            continue
        hit = read(raw) or steps(raw)
        if hit:
            for name, out in hit:
                shown = out if isinstance(out, str) else out[:400]
                print("%s: %s -> %r" % (path, name, shown))
        else:
            print("%s: no reader takes it" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
