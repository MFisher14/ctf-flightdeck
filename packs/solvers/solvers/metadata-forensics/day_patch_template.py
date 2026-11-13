#!/usr/bin/env python3
"""Metadata Forensics live fix, to fill in. Copy this whole file to your unique role-owned candidate
(`day_patch_live_owner_dev.py`, `day_patch_live_standby_dev.py`, `day_patch_live_helper1_dev.py` or
`day_patch_live_helper2_dev.py`) and add one line per new property or spelling to the two tables below; the rest is
fixed. Never write day_patch.py or day_patch_live.py by hand: run `tools/promote.py metadata-forensics --day N <candidate>`, then
after PROMOTE OK run `tools/resume_ready.py publish --day N --lane metadata-forensics`; a helper adds
`--require-exact`. The helper flag refuses any unsure/skipped saved answer, while the ordinary owner/standby path
preserves untimed probing. Its consumer alone resumes the lane.

  ALIAS  the question's name -> a registered name that reads the SAME structure. The answer
         is what the registered name gives, plain when that one is plain. Only for a pure
         synonym: a plain answer is replaced afterwards only by override() (below).
  NEW    the question's name -> (extractor, format class). The extractor is fn(name, data):
         the value read from the bytes, None when the field is absent, or raise M.Unknown
         when the bytes do not settle it. The answer is unsure under the name asked until one
         probe on the base is accepted, then plain. A doubtful spelling of a registered fact
         goes here too, with that fact's extractor:
             "tiff.page_dimensions_pixels": (M.lookup("tiff.ifd0_dimensions_pixels").fn, "wxh"),

Format classes: what the extractor returns, then the options in the order they are probed.
  integer   int: integer                    bool   bool: true_false
  text      str: raw, trimmed               label  str (a name this module chose): lower, upper
  hex       lowercase hex str: hex_lower, hex_upper
  uuid      a GUID read from BINARY as its 32 lowercase hex digits in written order (8-4-4-4-12):
            hyphen_lower, hyphen_upper, compact_lower, compact_upper, braces_upper. A GUID read
            as TEXT as M.Stored(the text exactly as the file has it): that text first, then those.
  wxh       (width, height): wxh            float  number: 4dp, 3dp, 2dp, 6dp
  list      list of str: comma, comma_space, space, json_compact
  intlist   list of int: comma, comma_space, space, json_compact
  any       a value of a key-value container, by its type (int, bool, float, str, bytes, datetime)
  forms     [(form name, text)] the extractor wrote itself, names from M.FORM_NAMES, best first
  number    int: 0x_hex_lower, hex_lower, integer
  code      (the spec's constant name or None, int): constant, integer, 0x_hex_lower
  u8hex u16hex u32hex u64hex   int of that width: the padded 0x form first, then the minimal ones
  ownhex    (32 or 64, int) for a field as wide as its file: the padded 0x form of that width first
  serial    int: hex_lower, integer, colon_hex_lower, ...       octal  int: octal_4, octal, 0o, integer
  timestamp (y, mo, d, h, mi, s, is_utc): iso_z, iso, iso_space, exif    unixtime  int seconds: unix, iso_z, ...
  filetime  int (100 ns since 1601)   mactime  int (s since 1904)   stamps  [(y, mo, d, h, mi, s)]
  unixlist  list of int seconds       version  (major, minor): 1.02, then 1.2   dotted  (major, minor): 2.4, then 2.04
  basename  str   encoding  str (utf-8, utf-16le)   marker  int 0 to 255 (a JPEG marker byte)   exif  an EXIF tag's value
  elfclass  32 or 64   endian  "little" or "big"   id3version  (major, revision)
M.FORMATS[<class>] is (every option name, the formatter); the formatter raises TypeError on another type.

Helpers a NEW extractor may call (all loaded already; RF, RM and MSI are set below):
  M.Unknown(why)                 raise it when the bytes do not settle the fact (the answer is None)
  M.Ambiguous([(form, text)])    raise it when one fact has several writings: unsure, in that order
  M.lookup(name).fn              the extractor of a registered property, to reuse under a new name
  RF.of(parse, get)              an extractor: None where parse(d) is None, else get(parse(d))
  RF.one(values, what)           the only value, None for none, M.Unknown for several
  M.CFB_MAGIC, M._cfb(d), M._cfb_dir(d)   a compound file (OLE2): header fields; [(entry name, type)]
  RM._ole_field(n, d, field)     a SummaryInformation field (title, subject, author, revision_number, ...)
  RF._msi(d), RF.msi_name(s)     [(decoded stream name, is a table)] of an MSI, None for another file;
                                 one stream name decoded
  MSI._db(d)                     an MSI's string pool and schema: ["tables"], ["columns"][table], ["streams"]
  MSI._table(d, table)           (column names, rows as tuples) of one table; None when it is not there
  MSI._column(d, table, column)  every row's cell of one column;  MSI._property(d, name)  one Property row's Value
  MSI.guid(text)                 a GUID read as text, as M.Stored;  MSI._cab(d)  the embedded cabinet
  RM._pex(d)                     a PE's headers and sections (None when the file is no PE)
  olefile                        is in .venv: olefile.OleFileIO(io.BytesIO(d)).openstream(path).read()
A NEW line for a field of a container:
    "msi.arp_contact_text": (lambda n, d: MSI._property(d, "ARPCONTACT"), "text"),

properties_strict.py asks answer() about a question it answered None or unsure, never about
a plain answer, and keeps its own answer when answer() returns None. handles(q) is True only
when the answer will be plain, so covers() never lets a clock start for an unsure one.

A WRONG PLAIN ANSWER of the shipped solver (the judge rejected it: its id is BAD in gaps.json)
is replaced one way only: define override(q, answer, files, ctx) in this role-owned candidate (the commented
function at the end of this file). When it exists it is asked about EVERY question, after
answer(), with the answer that would be returned. What it returns:
  a text         replaces the answer: a plain value, or labels.pick('metadata.<...>', options)
  WITHDRAW       the answer becomes None (nothing is sent for the id)
  anything else  (None, the same answer) leaves the answer as it is
Each replacement prints `NOTE <id>: <old> replaced by the Metadata live patch (<new>)` on stderr; a raise
costs nothing, the answer stands. Name the ids it touches exactly: it is asked about all of
them, on every variant and every set of a Mastery. This template defines no override, so as it
stands it changes no answer.

When the file narrows a fact to a few DIFFERENT values and nothing proves which one the judge
asks (backlog row 346: two stored fields that could each be meant), answer() or override()
returns a candidate pick, never one of them plain. Each option's name names the HYPOTHESIS,
never the value, best evidence first, at most 12:
    M.labels.candidates("metadata.format/msi.version", [("product_version", a), ("file_version", b)])
It stays unsure until the judge accepts a name (verify.py probes it on the base; run.py only on an
attempt with no deadline), and the accepted name answers the next variant plain.

Before the lane is resumed, replay the base (no request is made):
  .venv/bin/python tools/preflight.py --replay <attempt dir>
The UNKNOWN PROPERTY page in its solver_stderr lists the delivered file's registered facts.
"""
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _strict():
    """properties_strict.py beside this file, loaded once per process under a name of its
    own: the runner holds the solver under another name, and this file is loaded per set."""
    name = "metadata_strict_for_patch_" + re.sub(r"\W", "_", str(HERE))
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / "properties_strict.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sys.modules[name] = mod
    return sys.modules[name]


M = _strict()
RF = M.MORE_MODULES.get("readers_formats.py")   # of, one, _msi, msi_name (see the docstring)
RM = M.MORE_MODULES.get("readers_more.py")      # _ole_field, _pex
MSI = M.MORE_MODULES.get("readers_msi.py")      # _db, _table, _column, _property, guid, _cab

# ----------------------------------------------------------------------------- fill in
ALIAS = {
    # "gif.lsd_dimensions_pixels": "gif.logical_screen_dimensions_pixels",
}
NEW = {
    # "wav.sample_rate_hz": (lambda n, d: int.from_bytes(d[24:28], "little") if d[8:12] == b"WAVE" else None, "integer"),
}
# ----------------------------------------------------------------------------- fixed

for _name, _target in ALIAS.items():
    if M.lookup(_target) is None:
        raise KeyError(f"ALIAS {_name}: {_target} is not a registered property")
for _name, (_fn, _fmt) in NEW.items():
    if _fmt not in M.FORMATS:
        raise KeyError(f"NEW {_name}: no format class {_fmt!r}; the classes are {sorted(M.FORMATS)}")


def _prop(key):
    """The Prop the tables give for a canonical property name, or None. It carries the name
    that was asked, so what the judge says is learned under that name's own ledger key."""
    asked = M.dotted(key)
    for name, target in ALIAS.items():
        if M.canon(name) == key:
            p = M.lookup(target)
            return M.Prop(asked, p.fn, p.fmt, p.confirmed)
    for name, (fn, fmt) in NEW.items():
        if M.canon(name) == key:
            return M.Prop(asked, fn, fmt, False)
    return None


def _key(q, name=None):
    """(canonical property, file named in the text), read the way properties_strict reads
    them: the id's item pattern, else the text, else a suffix after the file's stem."""
    key, named, source, _ = M.resolve(q)
    if source != "id":
        art = q.get("artifact")
        member = q.get("member") or (art.split("->")[-1].strip() if isinstance(art, str) and "->" in art else None)
        key = M.stem_guard(key, q, name or member or named)
    return key, named


def handles(q) -> bool:
    """True when answer() will be plain for this question: the property is in a table, its
    class fits the answer format, and its format is judged (an ALIAS of a plain name) or has
    been accepted on the base (a NEW one, after its probe)."""
    key, _ = _key(q)
    p = _prop(key) if key else None
    return p is not None and M.format_problem(p, q) is None


def answer(q, files, ctx):
    """The answer for a property in the tables (plain, or unsure through labels.pick), or
    None for every other question, which leaves properties_strict's own answer in place."""
    key, named = _key(q)
    if not key:
        return None
    name, data = M.target_file(q, files, ctx, named, key)
    if data is None:
        return None
    key, _ = _key(q, name)
    p = _prop(key) if key else None
    return M.present(p, q, name, data) if p else None


WITHDRAW = "<<withdraw>>"   # what override() returns to take an answer back (properties_strict.PATCH_WITHDRAW)

# Uncomment and fill in ONLY to replace or withdraw an answer the shipped solver gives plain and
# the judge rejected. `answer` is what would be returned without this function.
# Write it exactly as `def override(` at the start of a line (column 0): the Metadata load check looks
# for that text in day_patch.py before it loads the patch, and a patch without it is never asked.
#
# def override(q, answer, files, ctx):
#     key, named = _key(q)
#     if key != M.canon("pe.some_property"):        # the property (or q["answer_id"]) this fix is for
#         return None                               # every other question: leave it
#     name, data = M.target_file(q, files, ctx, named, key)
#     if data is None:
#         return WITHDRAW                           # no file: better no answer than the wrong one
#     value = ...                                   # read it from data: a text
#     return value                                  # plain; or M.labels.pick("metadata.format/pe.some_property", [("form", value)])
#
# Rows 320 and 344: covers() (the runner's contract check, which under "preread": "status" decides whether a Time
# Trial starts at all) is asked before the clock, with no files, so it cannot see an override's answer. If the
# override above answers its question PLAIN, say so in handles() as well, or every start of that mode is refused:
#
# def handles(q) -> bool:
#     key, _ = _key(q)
#     if key == M.canon("pe.some_property"):        # the property the override above answers plain
#         return True
#     p = _prop(key) if key else None               # the rest of handles() as it stands above
#     return p is not None and M.format_problem(p, q) is None
