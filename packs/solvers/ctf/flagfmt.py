"""The single flag/proof format source, compiled from the event profile.

    from ctf import flagfmt
    ff = flagfmt.for_profile(event.load("csctf"))
    ff.find_flags(text_or_bytes)      # [str, ...] distinct, in order of first appearance
    ff.is_flag(s)                     # whole string (after strip) is one flag
    ff.normalize(s)                   # canonical spelling for dedupe (ValueError if not a flag)
    ff.find_proofs(...), ff.is_proof(s)   # the profile's optional [proof] token (e.g. proof_<hex32>)

    flagfmt.find_flags(data)          # same, against ctf.event.current()
    flagfmt.current()                 # the active event's FlagFormat (cached; follows CTF_EVENT)
    flagfmt.TEXT / BYTES              # compiled-pattern stand-ins for the active event (finditer, spans)
    flagfmt.PROOF_TEXT / PROOF_BYTES  # the same for the [proof] token (match nothing without one; has_proof())
    flagfmt.PACKED_TEXT               # TEXT without the left boundary, for fixed-width/binary records (R-16)
    flagfmt.cribs(), LEAD_TEXT/BYTES  # the event's flag leads `PREFIX{` for cribs and signatures (R-16)
    flagfmt.shape_reportable(tok)     # may a broad shape match be reported as a flag (never CSS) (R-16)

Pattern: (?<![A-Za-z0-9_]) (PREFIX1|PREFIX2|...) \\{ (?:BODY) \\}
  * in text, the left boundary stops `xCSCTF{..}` and CSS-ish `a{...}` from matching (the widened
    per-file regexes collided with CSS); prefixes are literal (re.escape). Bytes input drops the
    left boundary: in binary data a flag often follows a random letter byte;
  * an empty prefix list means the format is not known yet: any word prefix
    [A-Za-z][A-Za-z0-9_]{0,31} matches, and FlagFormat.known is False;
  * case: exact | prefix-insensitive (prefix any case, body exact) | insensitive (whole match).

After unit B-001a no other module defines a flag regex: callers use this file.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import env
from . import event as _event

_LEFT = r"(?<![A-Za-z0-9_])"
_RIGHT = r"(?![A-Za-z0-9_])"
UNKNOWN_PREFIX = r"[A-Za-z][A-Za-z0-9_]{0,31}"


def _prefix_group(spec: _event.FlagSpec) -> str:
    if not spec.prefixes:
        return UNKNOWN_PREFIX
    # Longest first so `CSCTF` is tried before `CTF` (both literal; the boundary decides the rest).
    alts = "|".join(re.escape(p) for p in sorted(spec.prefixes, key=len, reverse=True))
    return f"(?i:{alts})" if spec.case == "prefix-insensitive" else f"(?:{alts})"


def flag_pattern(spec: _event.FlagSpec) -> str:
    return f"{_LEFT}{_prefix_group(spec)}\\{{(?:{spec.body})\\}}"


def proof_pattern(spec: _event.ProofSpec) -> str:
    return f"{_LEFT}(?:{spec.pattern}){_RIGHT}"


# The body of a proof-SHAPED token (PROOF_SHAPE): any token characters after the proof's literal lead.
PROOF_SHAPE_BODY = r"[A-Za-z0-9_.:-]{4,128}"
# The flag shape of ANY event (BRACE_TEXT): a short word, then {...} with no brace or newline inside.
BRACE_BODY = r"[^{}\r\n]{2,256}"
_LEAD_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def literal_lead(pattern: str) -> str:
    """The literal text every match of a proof `pattern` starts with: 'proof_' for 'proof_[0-9a-f]{32}'.
    '' when the pattern has no fixed literal start (it opens with a class, group or escape, or has a
    top-level alternation). A quantifier after the run takes its last character off the lead."""
    depth, in_class, esc = 0, False, False
    for ch in pattern:                                   # a top-level `|` means no common lead
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            return ""
    n = 0
    while n < len(pattern) and pattern[n] in _LEAD_CHARS:
        n += 1
    lead = pattern[:n]
    if pattern[n:n + 1] in ("?", "*", "+") or re.match(r"\{\d*(?:,\d*)?\}", pattern[n:]):
        lead = lead[:-1]
    return lead


def _compile(pattern: str, case: str) -> tuple[re.Pattern, re.Pattern]:
    """(text regex, bytes regex). Binary data has no word boundaries (a flag often sits right after
    a random letter byte), so the bytes form drops the left boundary; the text form keeps it."""
    flags = re.IGNORECASE if case == "insensitive" else 0
    assert pattern.startswith(_LEFT)
    return re.compile(pattern, flags), re.compile(pattern[len(_LEFT):].encode("ascii"), flags)


def _packed(pattern: str, case: str) -> re.Pattern:
    """The text form WITHOUT the left boundary (R-16): for text decoded from fixed-width records and
    binary fields, where a flag can sit straight after a digit or letter of the previous field. The
    bytes form's rule, for callers that already hold the decoded str."""
    assert pattern.startswith(_LEFT)
    return re.compile(pattern[len(_LEFT):], re.IGNORECASE if case == "insensitive" else 0)


def _lead(spec: _event.FlagSpec) -> tuple[re.Pattern, re.Pattern]:
    """(text, bytes) regexes for the flag LEAD: a prefix and its opening brace (`CSCTF{`), under the
    event's case rule and with no left boundary. For signatures and leads: "this starts like a flag"."""
    src = _prefix_group(spec) + r"\{"
    flags = re.IGNORECASE if spec.case == "insensitive" else 0
    return re.compile(src, flags), re.compile(src.encode("ascii"), flags)


def _find(rx: re.Pattern, brx: re.Pattern, data: str | bytes | bytearray | memoryview) -> list[str]:
    if isinstance(data, str):
        hits = (m.group(0) for m in rx.finditer(data))
    elif isinstance(data, (bytes, bytearray, memoryview)):
        hits = (m.group(0).decode("latin-1") for m in brx.finditer(bytes(data)))
    else:
        raise TypeError(f"find_* takes str or bytes, not {type(data).__name__}")
    return list(dict.fromkeys(hits))


@dataclass(frozen=True)
class FlagFormat:
    spec: _event.FlagSpec
    proof: _event.ProofSpec | None = None

    def __post_init__(self):
        object.__setattr__(self, "pattern", flag_pattern(self.spec))
        rx, brx = _compile(self.pattern, self.spec.case)
        object.__setattr__(self, "regex", rx)
        object.__setattr__(self, "bregex", brx)
        object.__setattr__(self, "packed_regex", _packed(self.pattern, self.spec.case))
        lrx, lbrx = _lead(self.spec)
        object.__setattr__(self, "lead_regex", lrx)
        object.__setattr__(self, "lead_bregex", lbrx)
        if self.proof is not None:
            object.__setattr__(self, "proof_pattern", proof_pattern(self.proof))
            prx, pbrx = _compile(self.proof_pattern, self.proof.case)
            # Broad "seen" form (any case): a reader that must notice a near-miss spelling (an uppercase
            # proof that should make an auto-return ambiguous) scans with this; only proof_regex returns.
            parx = re.compile(self.proof_pattern, re.IGNORECASE)
            lead = literal_lead(self.proof.pattern)
            # Broader still: the proof's literal lead with ANY token body (proof_AAAA, proof_future-x).
            # Surfaced as a candidate and counted as ambiguity, never returned. No literal lead: the
            # any-case form is the broadest shape that is still this event's proof.
            psrx = (re.compile(f"(?i){_LEFT}{re.escape(lead)}{PROOF_SHAPE_BODY}{_RIGHT}") if lead else parx)
        else:
            object.__setattr__(self, "proof_pattern", None)
            prx = pbrx = parx = psrx = None
        object.__setattr__(self, "proof_regex", prx)
        object.__setattr__(self, "proof_bregex", pbrx)
        object.__setattr__(self, "proof_regex_anycase", parx)
        object.__setattr__(self, "proof_shape_regex", psrx)

    @property
    def known(self) -> bool:
        return self.spec.known

    # -- flags
    def find_flags(self, data: str | bytes) -> list[str]:
        return _find(self.regex, self.bregex, data)

    def is_flag(self, s: str) -> bool:
        return isinstance(s, str) and self.regex.fullmatch(s.strip()) is not None

    def cribs(self) -> tuple[str, ...]:
        """Each known prefix with its opening brace (`CSCTF{`), in profile order (the first is the
        event's own spelling): the known plaintext a crib attack starts from. LookupError when the
        format has no known prefix: there is then no flag crib to assume."""
        if not self.spec.prefixes:
            raise LookupError("this event's flag format has no known prefix, so there is no flag crib: "
                              "pass the crib the challenge states")
        return tuple(f"{p}{{" for p in self.spec.prefixes)

    def normalize(self, s: str) -> str:
        """Canonical spelling for dedupe: stripped; prefix rewritten to the profile's spelling under
        prefix-insensitive; lower-cased under insensitive. Raises ValueError for a non-flag."""
        t = s.strip() if isinstance(s, str) else s
        if not self.is_flag(t):
            raise ValueError("not a flag in this event's format")
        if self.spec.case == "insensitive":
            return t.lower()
        if self.spec.case == "prefix-insensitive" and self.spec.prefixes:
            pre, rest = t.split("{", 1)
            for cand in self.spec.prefixes:
                if cand.lower() == pre.lower():
                    return f"{cand}{{{rest}"
        return t

    # -- proofs
    def _need_proof(self) -> None:
        if self.proof_regex is None:
            raise LookupError("this event profile defines no [proof] format")

    def find_proofs(self, data: str | bytes) -> list[str]:
        self._need_proof()
        return _find(self.proof_regex, self.proof_bregex, data)

    def is_proof(self, s: str) -> bool:
        self._need_proof()
        return isinstance(s, str) and self.proof_regex.fullmatch(s.strip()) is not None


_CACHE: dict[tuple, FlagFormat] = {}


def for_profile(profile: _event.EventProfile) -> FlagFormat:
    key = (profile.flag, profile.proof)
    ff = _CACHE.get(key)
    if ff is None:
        ff = _CACHE[key] = FlagFormat(profile.flag, profile.proof)
    return ff


_CURRENT: dict[str, FlagFormat] = {}


def current() -> FlagFormat:
    """The FlagFormat of the active event (ctf.event.current()). Cheap enough for an engine's hot loop
    (well under a microsecond with $CTF_EVENT set): cached per CTF_EVENT value, so changing CTF_EVENT is
    seen on the next call; a profile edited on disk is seen by the next process (or after
    clear_current_cache()). Raises ctf.event.EventError when no event resolves."""
    slug = env.get("CTF_EVENT")
    if not slug:
        return for_profile(_event.current())
    ff = _CURRENT.get(slug)
    if ff is None:
        ff = _CURRENT[slug] = for_profile(_event.load(slug))   # load raises EventError naming the problem
    return ff


def clear_current_cache() -> None:
    """Forget the per-CTF_EVENT cache of current() (after editing a profile in a running process)."""
    _CURRENT.clear()


def _cur(profile):
    return for_profile(profile) if profile is not None else current()


def has_proof(profile: _event.EventProfile | None = None) -> bool:
    """True when the event defines a [proof] token (find_proofs/is_proof would otherwise raise)."""
    return _cur(profile).proof is not None


class _Live:
    """A stand-in for a compiled pattern that follows the active event on every use, for callers that
    need match objects (spans, finditer, sub): `flagfmt.TEXT.finditer(s)` is
    `flagfmt.current().regex.finditer(s)`. Not a re.Pattern: pass it to nothing that type-checks."""
    __slots__ = ("_name", "_get")

    def __init__(self, name, get):
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_get", get)

    def __getattr__(self, attr):
        return getattr(self._get(), attr)

    def __setattr__(self, attr, value):
        raise AttributeError(f"flagfmt.{self._name} is read-only")

    def __repr__(self):
        return f"<flagfmt.{self._name}: follows the active event>"


# An event with no [proof] has no proof tokens: a scan for them finds nothing (it is not an error to
# look). Code that must know whether proofs exist asks has_proof(); ff.find_proofs() still raises.
NO_PROOF_TEXT = re.compile(r"(?!)")
NO_PROOF_BYTES = re.compile(rb"(?!)")


def _proof_attr(attr, none):
    rx = getattr(current(), attr)
    return none if rx is None else rx


_SHAPES: dict[tuple, FlagFormat] = {}


def shape(profile: _event.EventProfile | None = None) -> FlagFormat:
    """Flag-SHAPED under the event's body and case, with ANY word prefix (the unknown-format form of
    this event). For broad "seen" scans only -- a decoy baseline, a candidate shown to the player, an
    off-format token that must make an auto-return ambiguous -- never a return or submit gate."""
    spec = _cur(profile).spec
    key = (spec.body, spec.case)
    ff = _SHAPES.get(key)
    if ff is None:
        ff = _SHAPES[key] = FlagFormat(_event.FlagSpec(prefixes=(), body=spec.body, case=spec.case))
    return ff


TEXT = _Live("TEXT", lambda: current().regex)                   # flags in str
BYTES = _Live("BYTES", lambda: current().bregex)                # flags in bytes (no left boundary)
# R-16: text decoded from fixed-width records or binary fields (no left boundary, like BYTES), and the
# flag lead (`PREFIX{` under the event's case rule) for signatures and "interesting string" leads.
PACKED_TEXT = _Live("PACKED_TEXT", lambda: current().packed_regex)
LEAD_TEXT = _Live("LEAD_TEXT", lambda: current().lead_regex)
LEAD_BYTES = _Live("LEAD_BYTES", lambda: current().lead_bregex)
SHAPE_TEXT = _Live("SHAPE_TEXT", lambda: shape().regex)        # any-prefix shape, broad "seen" only
SHAPE_BYTES = _Live("SHAPE_BYTES", lambda: shape().bregex)
PROOF_TEXT = _Live("PROOF_TEXT", lambda: _proof_attr("proof_regex", NO_PROOF_TEXT))
PROOF_BYTES = _Live("PROOF_BYTES", lambda: _proof_attr("proof_bregex", NO_PROOF_BYTES))
PROOF_ANYCASE = _Live("PROOF_ANYCASE", lambda: _proof_attr("proof_regex_anycase", NO_PROOF_TEXT))  # broad "seen"
PROOF_SHAPE = _Live("PROOF_SHAPE", lambda: _proof_attr("proof_shape_regex", NO_PROOF_TEXT))   # broader "seen"

# Any event's flag shape, whatever the active event: word{...}. Seen-only, like SHAPE_TEXT: under an
# event that pays off in proofs, a brace token in a payoff is another token family, so it can only make
# the payoff ambiguous. Built through FlagFormat so the boundary rules are the ones above.
BRACE_TEXT = FlagFormat(_event.FlagSpec(prefixes=(), body=BRACE_BODY, case="exact")).regex


# A CSS declaration: `color: red`, `--gap:4px !important`, `background:url(x:y)` (R-16). The property
# must be a CSS property name (below), a custom property (`--gap`) or vendor-prefixed (`-webkit-x`):
# `flag{http://x}`, `x{note: see below}` and `picoCTF{key:value}` are not CSS. CSS_PROPERTIES is a
# FIXED allowlist (standard and shipping properties as of 2026; single-letter SVG geometry such as `x`
# or `r` is left out on purpose, so `x{y:1}` stays a flag candidate). A property CSS adds later is not
# recognised until it is added here: a rule that uses only such properties reads as not CSS, so the
# report channels may report it as a flag.
_CSS_DECL = re.compile(r"\s*(-{0,2}[A-Za-z][A-Za-z0-9-]*)\s*:\s*[^;{}\s][^;{}]*")
_CSS_VENDOR = re.compile(r"--[A-Za-z0-9_-]+|-(?:webkit|moz|ms|o)-[a-z][a-z-]*", re.IGNORECASE)
CSS_PROPERTIES = frozenset("""
accent-color align-content align-items align-self alignment-baseline all animation animation-delay
animation-direction animation-duration animation-fill-mode animation-iteration-count animation-name
animation-play-state animation-timing-function appearance aspect-ratio backdrop-filter
backface-visibility background background-attachment background-blend-mode background-clip
background-color background-image background-origin background-position background-position-x
background-position-y background-repeat background-size block-size border border-block
border-block-color border-block-end border-block-start border-block-style border-block-width
border-bottom border-bottom-color border-bottom-left-radius border-bottom-right-radius
border-bottom-style border-bottom-width border-collapse border-color border-end-end-radius
border-end-start-radius border-image border-image-outset border-image-repeat border-image-slice
border-image-source border-image-width border-inline border-inline-color border-inline-end
border-inline-start border-inline-style border-inline-width border-left border-left-color
border-left-style border-left-width border-radius border-right border-right-color border-right-style
border-right-width border-spacing border-start-end-radius border-start-start-radius border-style
border-top border-top-color border-top-left-radius border-top-right-radius border-top-style
border-top-width border-width bottom box-decoration-break box-shadow box-sizing break-after
break-before break-inside caption-side caret-color clear clip clip-path clip-rule color color-scheme
column-count column-fill column-gap column-rule column-rule-color column-rule-style column-rule-width
column-span column-width columns contain container container-name container-type content
content-visibility counter-increment counter-reset counter-set cursor direction display
dominant-baseline empty-cells fill fill-opacity fill-rule filter flex flex-basis flex-direction
flex-flow flex-grow flex-shrink flex-wrap float flood-color flood-opacity font font-display
font-family font-feature-settings font-kerning font-optical-sizing font-size font-size-adjust
font-stretch font-style font-synthesis font-variant font-variant-caps font-variant-ligatures
font-variant-numeric font-variation-settings font-weight gap grid grid-area grid-auto-columns
grid-auto-flow grid-auto-rows grid-column grid-column-end grid-column-gap grid-column-start grid-gap
grid-row grid-row-end grid-row-gap grid-row-start grid-template grid-template-areas
grid-template-columns grid-template-rows hanging-punctuation height hyphens image-rendering
inline-size inset inset-block inset-block-end inset-block-start inset-inline inset-inline-end
inset-inline-start isolation justify-content justify-items justify-self left letter-spacing
lighting-color line-break line-clamp line-height list-style list-style-image list-style-position
list-style-type margin margin-block margin-block-end margin-block-start margin-bottom margin-inline
margin-inline-end margin-inline-start margin-left margin-right margin-top marker marker-end
marker-mid marker-start mask mask-clip mask-composite mask-image mask-mode mask-origin
mask-position mask-repeat mask-size mask-type max-block-size max-height max-inline-size max-width
min-block-size min-height min-inline-size min-width mix-blend-mode object-fit object-position
offset offset-anchor offset-distance offset-path offset-rotate opacity order orphans outline
outline-color outline-offset outline-style outline-width overflow overflow-anchor overflow-wrap
overflow-x overflow-y overscroll-behavior overscroll-behavior-x overscroll-behavior-y padding
padding-block padding-block-end padding-block-start padding-bottom padding-inline
padding-inline-end padding-inline-start padding-left padding-right padding-top page-break-after
page-break-before page-break-inside paint-order perspective perspective-origin place-content
place-items place-self pointer-events position print-color-adjust quotes resize right rotate
row-gap ruby-position scale scroll-behavior scroll-margin scroll-margin-block scroll-margin-bottom
scroll-margin-inline scroll-margin-left scroll-margin-right scroll-margin-top scroll-padding
scroll-padding-block scroll-padding-bottom scroll-padding-inline scroll-padding-left
scroll-padding-right scroll-padding-top scroll-snap-align scroll-snap-stop scroll-snap-type
scrollbar-color scrollbar-gutter scrollbar-width shape-image-threshold shape-margin shape-outside
shape-rendering speak src stop-color stop-opacity stroke stroke-dasharray stroke-dashoffset
stroke-linecap stroke-linejoin stroke-miterlimit stroke-opacity stroke-width tab-size table-layout
text-align text-align-last text-anchor text-combine-upright text-decoration text-decoration-color
text-decoration-line text-decoration-style text-decoration-thickness text-emphasis text-indent
text-justify text-orientation text-overflow text-rendering text-shadow text-size-adjust
text-transform text-underline-offset text-underline-position top touch-action transform
transform-box transform-origin transform-style transition transition-delay transition-duration
transition-property transition-timing-function translate unicode-bidi unicode-range user-select
vector-effect vertical-align visibility white-space widows width will-change word-break
word-spacing word-wrap writing-mode z-index zoom
anchor-name anchor-scope animation-composition animation-range animation-range-end
animation-range-start animation-timeline contain-intrinsic-block-size contain-intrinsic-height
contain-intrinsic-inline-size contain-intrinsic-size contain-intrinsic-width dynamic-range-limit
field-sizing font-language-override font-palette font-synthesis-position font-synthesis-small-caps
font-synthesis-style font-synthesis-weight font-variant-alternates font-variant-east-asian
font-variant-emoji font-variant-position forced-color-adjust hyphenate-character
hyphenate-limit-chars image-orientation image-resolution initial-letter inset-area
interpolate-size math-depth math-shift math-style object-view-box offset-position overflow-block
overflow-clip-margin overflow-inline overlay overscroll-behavior-block overscroll-behavior-inline
position-anchor position-area position-try position-try-fallbacks position-try-order
position-visibility reading-flow reading-order ruby-align scroll-margin-block-end
scroll-margin-block-start scroll-margin-inline-end scroll-margin-inline-start
scroll-padding-block-end scroll-padding-block-start scroll-padding-inline-end
scroll-padding-inline-start scroll-timeline scroll-timeline-axis scroll-timeline-name text-box
text-box-edge text-box-trim text-decoration-skip text-decoration-skip-ink text-emphasis-color
text-emphasis-position text-emphasis-style text-spacing-trim text-wrap text-wrap-mode
text-wrap-style timeline-scope transition-behavior view-timeline view-timeline-axis
view-timeline-inset view-timeline-name view-transition-class view-transition-name
white-space-collapse
""".split())


def _css_property(name: str) -> bool:
    return name.lower() in CSS_PROPERTIES or _CSS_VENDOR.fullmatch(name) is not None


def _css_decl(decl: str) -> bool:
    m = _CSS_DECL.fullmatch(decl)
    return m is not None and _css_property(m.group(1))


def css_like(token: str) -> bool:
    """True when a brace token reads as a CSS rule: the text inside its last opening brace is a list
    of `property: value` declarations (`btn{color:red}`, `a{margin:0;padding:0;}`, the inner rule of
    `screen{.a{color:red}`), every property a CSS property name (CSS_PROPERTIES, `--custom`,
    `-webkit-...`). The broad shape scans (SHAPE_TEXT, BRACE_TEXT, PAYOFF_OTHER) match such tokens
    under a broad body; they may stay in seen and decoy sets, never in a flag channel."""
    if not isinstance(token, str) or "{" not in token:
        return False
    inner = token.rsplit("{", 1)[1]
    if inner.endswith("}"):
        inner = inner[:-1]
    decls = inner.split(";")
    if len(decls) > 1 and not decls[-1].strip():
        decls = decls[:-1]                          # a trailing ';'
    return all(_css_decl(d) for d in decls)


def shape_reportable(token: str, profile: _event.EventProfile | None = None) -> bool:
    """Whether a broad shape match may be REPORTED as a flag (a player-flag line, a `flags` list, a
    flag answer form): it is in the event's flag or proof format, or it is not CSS-shaped. Seen and
    decoy sets keep every shape match; only what is reported as a flag is filtered (R-16)."""
    ff = _cur(profile)
    if ff.is_flag(token) or (ff.proof is not None and ff.is_proof(token)):
        return True
    return not css_like(token)


class Filtered:
    """A compiled-pattern stand-in: the matches of `base` (TEXT, PROOF_TEXT, ...) whose text passes
    `keep(str) -> bool`. For a refinement that is not a format of its own (e.g. "a proof whose hex is a
    version-4 UUID"), so the refinement needs no second regex. finditer/search/findall/fullmatch only."""

    def __init__(self, base, keep, name: str):
        self.base, self.keep, self.name = base, keep, name

    @property
    def pattern(self) -> str:
        return f"{self.base.pattern} [{self.name}]"

    def finditer(self, s):
        return (m for m in self.base.finditer(s) if self.keep(m.group(0)))

    def search(self, s):
        return next(self.finditer(s), None)

    def findall(self, s):
        return [m.group(0) for m in self.finditer(s)]

    def fullmatch(self, s):
        m = self.base.fullmatch(s)
        return m if m is not None and self.keep(m.group(0)) else None


# -- payoff tokens. What a live target (a web app, a service) hands out when it is beaten: an event whose
# profile defines [proof] pays off in PROOF tokens (Huntress: proof_<32 hex>, exchanged on the platform
# for the flag), every other event in flags. A reader's never-wrong rule runs on these stand-ins, so one
# reader serves both token models; a proof is never reported as a flag candidate and a flag-shaped
# token in a proof event's payoff is ambiguity, never the answer.

def payoff_kind(profile: _event.EventProfile | None = None) -> str:
    """'proof' when the event defines a [proof] token, else 'flag'."""
    return "proof" if has_proof(profile) else "flag"


def by_payoff(proof_form, flag_form, name: str) -> _Live:
    """A stand-in that is `proof_form` while the active event pays off in proofs, else `flag_form`
    (both compiled patterns or stand-ins). For a reader's own refinement (e.g. a UUID-v4 filter)."""
    return _Live(name, lambda: proof_form if has_proof() else flag_form)


PAYOFF_TEXT = by_payoff(PROOF_TEXT, TEXT, "PAYOFF_TEXT")          # the exact payoff: the only return
PAYOFF_ANYCASE = by_payoff(PROOF_ANYCASE, TEXT, "PAYOFF_ANYCASE")  # seen: decoys, baselines, ambiguity
PAYOFF_SHAPE = by_payoff(PROOF_SHAPE, TEXT, "PAYOFF_SHAPE")      # payoff-shaped near misses: seen only
PAYOFF_OTHER = by_payoff(BRACE_TEXT, SHAPE_TEXT, "PAYOFF_OTHER")  # other-family/foreign shapes: seen only


def uuid4_token(token: str) -> bool:
    """The token's last 32 hex digits form a version-4 RFC 4122 UUID: every early judged Huntress web
    proof had these nibbles, but the format never promised them (a validator, never a gate)."""
    hexpart = token.rsplit("_", 1)[-1]
    return len(hexpart) == 32 and hexpart[12] == "4" and hexpart[16] in "89ab"


# A payoff with the UUID-v4 validator: a proof whose hex is a v4 UUID; under a flag event, the flag.
PAYOFF_UUID4 = by_payoff(Filtered(PROOF_TEXT, uuid4_token, "uuid4"), TEXT, "PAYOFF_UUID4")


def find_flags(data: str | bytes, profile: _event.EventProfile | None = None) -> list[str]:
    return _cur(profile).find_flags(data)


def find_flags_packed(data: str | bytes, profile: _event.EventProfile | None = None) -> list[str]:
    """find_flags for fixed-width records and binary fields: no left boundary in either form, since a
    flag may follow a digit or letter of the previous field. Bytes are scanned as bytes (matches
    decoded latin-1); text with the packed form, so a caller keeps its own decoding of the text."""
    ff = _cur(profile)
    return _find(ff.packed_regex, ff.bregex, data)


def cribs(profile: _event.EventProfile | None = None) -> tuple[str, ...]:
    """The active (or given) event's flag leads, `PREFIX{`, in profile order. See FlagFormat.cribs."""
    return _cur(profile).cribs()


def is_flag(s: str, profile: _event.EventProfile | None = None) -> bool:
    return _cur(profile).is_flag(s)


def normalize(s: str, profile: _event.EventProfile | None = None) -> str:
    return _cur(profile).normalize(s)
