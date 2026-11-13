#!/usr/bin/env python3
"""Offline test of the Unity IL2CPP global-metadata.dat reader (solvers/toolkits/il2cpp.py).

Proves the never-wrong boundary on a hand-built fixture metadata blob of a known version (24):
  - a planted string LITERAL is read byte-exact and is PLAIN-eligible (returned plain);
  - the metadata VERSION and the string-LITERAL count are byte-exact integer reads (plain);
  - a method/type/field definition COUNT is UNSURE when the table has an entry whose name does not
    validate (empty/non-ASCII name), so table_entries != names_read: never a wrong plain undercount;
  - a planted METHOD / TYPE / FIELD name is returned as an UNSURE labels.candidates pick (never plain);
  - an unknown header version yields None for every id;
  - a truncated heap / literal blob yields None for the affected id, never a guess;
  - a behaviour question and a flag are None (text-is-data).

  .venv/bin/python tests/test_unity_il2cpp_metadata.py
"""
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Isolate the labels ledger so a stray real row can never make a key answer plain, and turn the
# family prior off so a candidate key stays unsure.
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_il2cpp_")
os.environ["CTF_FAMILY_PRIOR"] = "off"
os.environ.pop("CTF_TOKEN", None)
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import labels      # noqa: E402
import il2cpp       # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# ---------------------------------------------------------------------------- fixture builder

LITERAL = "HuntressSecretLiteral/v1"      # the planted, byte-exact string literal (UTF-8 clean)
METHOD = "DecryptPayload"                 # the planted method name (author label -> unsure)
TYPE = "LicenseManager"                   # the planted type name
FIELD = "encryptionKey"                   # the planted field name
NAMESPACE = "Huntress.Core"


NONASCII_TYPE = "Résumé"        # a valid C# identifier, non-ASCII -> dropped by _IDENT


def build_metadata(version=24, truncate=None, bad_literal_index=False,
                   drop_methods=0, nonascii_type=False, empty_name_field=False):
    """A minimal but structurally valid global-metadata.dat for the classic (24/27) layout.

    Header is 64 int32 words (256 bytes). Regions follow, each referenced by (offset, size-bytes)
    word pairs. `truncate` ('heap'|'literal') cuts a region's backing bytes so the reader must
    fail closed. `bad_literal_index` points the literal past its data blob (inconsistent offsets).

    The AMBIGUOUS-count knobs (so the byte-exact table-entry count diverges from the count of
    entries whose name validates, which is the never-wrong hole this fixture exercises):
      drop_methods      append N extra method entries whose nameIndex is 0 (empty name -> dropped);
      nonascii_type     append one type entry named with a non-ASCII C# identifier (dropped by _IDENT);
      empty_name_field  append one field entry whose nameIndex is 0 (empty name -> dropped).
    Each knob adds a real table entry (so `*_entries` grows) that `_read_names` drops (so `*_names`
    does not), making table_entries != names_read.
    """
    HEADER_WORDS = 64
    header_size = HEADER_WORDS * 4

    # --- identifier string heap (null-terminated UTF-8) -------------------------------------------
    heap = bytearray(b"\x00")             # index 0 is the empty string, as IL2CPP uses it
    def intern(s):
        idx = len(heap)
        heap.extend(s.encode("utf-8") + b"\x00")
        return idx
    ns_idx = intern(NAMESPACE)
    method_name_idx = intern(METHOD)
    type_name_idx = intern(TYPE)
    field_name_idx = intern(FIELD)
    nonascii_type_idx = intern(NONASCII_TYPE) if nonascii_type else 0
    heap = bytes(heap)

    # --- string literal data blob + table ----------------------------------------------------------
    lit_bytes = LITERAL.encode("utf-8")
    lit_data = lit_bytes                  # one literal at dataIndex 0
    data_index = 0 if not bad_literal_index else len(lit_data) + 1000   # past the blob -> inconsistent
    lit_table = struct.pack("<Ii", len(lit_bytes), data_index)

    # --- definition tables (classic strides from il2cpp._DEF) --------------------------------------
    type_stride = il2cpp._DEF["type_definitions"]["stride"]
    method_stride = il2cpp._DEF["methods"]["stride"]
    field_stride = il2cpp._DEF["fields"]["stride"]

    def def_entry(stride, name_index, namespace_index=None):
        d = bytearray(stride)
        struct.pack_into("<i", d, 0, name_index)
        if namespace_index is not None:
            struct.pack_into("<i", d, 4, namespace_index)
        return bytes(d)

    # one valid method, then `drop_methods` entries with an empty (index-0) name
    method_table = def_entry(method_stride, method_name_idx)
    method_table += def_entry(method_stride, 0) * drop_methods
    # one valid type, then (optionally) one with a non-ASCII (dropped) name
    type_table = def_entry(type_stride, type_name_idx, ns_idx)
    if nonascii_type:
        type_table += def_entry(type_stride, nonascii_type_idx)
    # one valid field, then (optionally) one with an empty (index-0, dropped) name
    field_table = def_entry(field_stride, field_name_idx)
    if empty_name_field:
        field_table += def_entry(field_stride, 0)

    # --- lay the regions out after the header ------------------------------------------------------
    blob = bytearray()
    def place(chunk):
        off = header_size + len(blob)
        blob.extend(chunk)
        return off, len(chunk)

    sl_off, sl_size = place(lit_table)
    sld_off, sld_size = place(lit_data)
    str_off, str_size = place(heap)
    methods_off, methods_size = place(method_table)
    fields_off, fields_size = place(field_table)
    types_off, types_size = place(type_table)

    words = [0] * HEADER_WORDS
    words[0] = il2cpp.MAGIC
    words[1] = version
    pairs = {2: (sl_off, sl_size), 4: (sld_off, sld_size), 6: (str_off, str_size),
             12: (methods_off, methods_size), 24: (fields_off, fields_size), 40: (types_off, types_size)}
    for w, (off, size) in pairs.items():
        words[w] = off
        words[w + 1] = size
    header = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)
    out = bytearray(header + bytes(blob))

    if truncate == "heap":
        # Cut the file so the string heap region is incomplete (and its terminators are lost).
        out = out[:str_off + 2]
    elif truncate == "literal":
        # Cut the file so the literal data blob is incomplete.
        out = out[:sld_off + 1]
    return bytes(out)


def q(answer_id, question, kind="exact_text"):
    return {"qid": answer_id, "id": answer_id, "answer_id": answer_id, "member": "global-metadata.dat",
            "artifact": "delivery -> global-metadata.dat", "question": question,
            "answer_format": {"kind": kind}}


# ---------------------------------------------------------------------------- tests

def test_parse():
    data = build_metadata(24)
    rep = il2cpp.parse_metadata(data)
    check("the fixture parses as IL2CPP metadata", rep is not None and rep.get("version") == 24)
    check("the version is supported", rep.get("supported") is True)
    check("exactly one string literal is read", (rep["counts"]["string_literals"] == 1
          and rep["counts"]["string_literals_read"] == 1), rep["counts"])
    lits = rep["literals"]["literals"]
    check("the literal is read byte-exact and clean", len(lits) == 1 and lits[0]["clean"]
          and lits[0]["text"] == LITERAL, lits)
    check("the method/type/field names are recovered from the heap",
          [m["name"] for m in rep["methods"]] == [METHOD]
          and [t["name"] for t in rep["types"]] == [TYPE]
          and [t["namespace"] for t in rep["types"]] == [NAMESPACE]
          and [f["name"] for f in rep["fields"]] == [FIELD],
          {"m": rep["methods"], "t": rep["types"], "f": rep["fields"]})


def test_never_wrong_literal_and_version_plain():
    data = build_metadata(24)
    files = {"global-metadata.dat": data}
    ans = il2cpp.solve_set([q("lit", "What is the embedded string literal?")], files, {})
    check("the literal answer is PLAIN (not unsure) and byte-exact",
          ans["lit"] == LITERAL and not labels.is_unsure(ans["lit"]), ans)

    ans = il2cpp.solve_set([q("ver", "What is the metadata version?", kind="integer")], files, {})
    check("the version answer is PLAIN and correct", ans["ver"] == 24 and not labels.is_unsure(ans["ver"]), ans)

    ans = il2cpp.solve_set([q("cnt", "How many string literals are present?", kind="integer")], files, {})
    check("the literal count is PLAIN and correct", ans["cnt"] == 1 and not labels.is_unsure(ans["cnt"]), ans)


def test_never_wrong_ambiguous_count_unsure():
    """The hole: a definition-table COUNT must never be answered PLAIN, because the count of entries
    whose name validated (`*_names`) undercounts whenever an entry's name is empty/out-of-bounds/
    non-ASCII, and the byte-exact table-entry count (`*_entries`) depends on the version-inferred
    stride. Exercise the AMBIGUOUS case (table_entries != names_read) that the single-value fixtures
    above never did, and prove the count is an UNSURE candidate, never a wrong plain integer."""
    # methods: 2 table entries (one valid name, one nameIndex=0 -> dropped).  Proof 1 of the finding.
    data = build_metadata(24, drop_methods=1)
    rep = il2cpp.parse_metadata(data)
    check("method table has 2 entries but only 1 validated name (undercount)",
          rep["counts"]["method_entries"] == 2 and rep["counts"]["method_names"] == 1, rep["counts"])
    files = {"global-metadata.dat": data}
    ans = il2cpp.solve_set([q("mc", "How many methods are defined in the binary?", kind="integer")], files, {})
    check("the method count is UNSURE (never the plain undercount 1)",
          labels.is_unsure(ans["mc"]) and ans["mc"] != 1, ans)
    parsed = labels.parse(ans["mc"])
    check("the method-count candidate key is version-scoped and a candidate key",
          parsed is not None and parsed.key.startswith("binary.il2cpp_method_count/v24")
          and labels.is_candidate(parsed.key), parsed and parsed.key)
    check("the method-count candidates offer the byte-exact table_entries (2) first, names_read (1) second",
          parsed is not None and parsed.options[0] == ("table_entries", 2)
          and ("names_read", 1) in parsed.options, parsed and parsed.options)

    # types: 2 table entries (one ASCII name, one non-ASCII name -> dropped).  Proof 2 of the finding.
    data = build_metadata(27, nonascii_type=True)
    rep = il2cpp.parse_metadata(data)
    check("type table has 2 entries but only 1 ASCII-validated name (undercount)",
          rep["counts"]["type_entries"] == 2 and rep["counts"]["type_names"] == 1, rep["counts"])
    ans = il2cpp.solve_set([q("tc", "Number of types defined?", kind="integer")],
                           {"global-metadata.dat": data}, {})
    check("the type count is UNSURE (never the plain undercount 1)",
          labels.is_unsure(ans["tc"]) and ans["tc"] != 1, ans)
    parsed = labels.parse(ans["tc"])
    check("the type-count candidates offer table_entries (2) first, names_read (1) second",
          parsed is not None and parsed.options[0] == ("table_entries", 2)
          and ("names_read", 1) in parsed.options, parsed and parsed.options)

    # fields: 2 table entries (one valid name, one empty-name -> dropped).
    data = build_metadata(24, empty_name_field=True)
    ans = il2cpp.solve_set([q("fc", "How many fields are defined in the binary?", kind="integer")],
                           {"global-metadata.dat": data}, {})
    check("the field count is UNSURE (never the plain undercount 1)",
          labels.is_unsure(ans["fc"]) and ans["fc"] != 1, ans)

    # The string-literal count stays BYTE-EXACT and PLAIN (literal struct size is fixed v24-27).
    ans = il2cpp.solve_set([q("lc", "How many string literals are present?", kind="integer")],
                           {"global-metadata.dat": build_metadata(24, drop_methods=3)}, {})
    check("the string-literal count is still PLAIN and byte-exact", ans["lc"] == 1
          and not labels.is_unsure(ans["lc"]), ans)


def test_never_wrong_name_unsure():
    files = {"global-metadata.dat": build_metadata(24)}
    ans = il2cpp.solve_set([q("m", "What is the name of the method?")], files, {})
    parsed = labels.parse(ans["m"])
    check("the method name is an UNSURE candidate (never plain)",
          labels.is_unsure(ans["m"]) and parsed is not None, ans)
    check("the candidate key is a binary.il2cpp_method candidate key, scoped to the version",
          parsed is not None and parsed.key.startswith("binary.il2cpp_method/v24")
          and labels.is_candidate(parsed.key), parsed and parsed.key)
    check("the method name's first candidate rendering is the exact heap identifier",
          parsed is not None and parsed.options and parsed.options[0][1] == METHOD, parsed and parsed.options)

    ans = il2cpp.solve_set([q("t", "What is the name of the type/class?")], files, {})
    parsed = labels.parse(ans["t"])
    check("the type name is an UNSURE candidate offering bare and namespace-qualified renderings",
          labels.is_unsure(ans["t"]) and parsed is not None
          and dict(parsed.options).get("bare") == TYPE
          and dict(parsed.options).get("namespace_dot") == f"{NAMESPACE}.{TYPE}", parsed and parsed.options)

    ans = il2cpp.solve_set([q("f", "What is the field name?")], files, {})
    parsed = labels.parse(ans["f"])
    check("the field name is an UNSURE candidate", labels.is_unsure(ans["f"])
          and parsed is not None and parsed.options[0][1] == FIELD, ans)


def test_unknown_version_is_none():
    for v in (23, 40, 99):
        data = build_metadata(24)
        # Rewrite only the version word; the rest of the header stays valid.
        data = data[:4] + struct.pack("<I", v) + data[8:]
        rep = il2cpp.parse_metadata(data)
        check(f"version {v}: parsed as metadata but marked unsupported", rep is not None
              and rep.get("supported") is False and rep.get("version") == v, rep)
        files = {"global-metadata.dat": data}
        ans = il2cpp.solve_set([q("lit", "What is the embedded string literal?"),
                                q("m", "What is the method name?"),
                                q("ver", "What is the metadata version?", kind="integer")], files, {})
        check(f"version {v}: every id is None (unsupported -> never guess)",
              all(ans[k] is None for k in ("lit", "m", "ver")), ans)


def test_truncated_is_none():
    files = {"global-metadata.dat": build_metadata(24, truncate="literal")}
    ans = il2cpp.solve_set([q("lit", "What is the embedded string literal?")], files, {})
    check("a truncated literal blob yields None for the literal (never a guess)", ans["lit"] is None, ans)

    files = {"global-metadata.dat": build_metadata(24, truncate="heap")}
    ans = il2cpp.solve_set([q("m", "What is the method name?")], files, {})
    check("a truncated string heap yields None for the name (never a guess)", ans["m"] is None, ans)


def test_inconsistent_offsets_is_none():
    files = {"global-metadata.dat": build_metadata(24, bad_literal_index=True)}
    rep = il2cpp.parse_metadata(files["global-metadata.dat"])
    check("an inconsistent literal dataIndex is dropped (no literal read)",
          rep is not None and rep["counts"]["string_literals"] == 1
          and rep["counts"]["string_literals_read"] == 0, rep and rep.get("counts"))
    ans = il2cpp.solve_set([q("lit", "What is the embedded string literal?")], files, {})
    check("inconsistent offsets yield None for the literal", ans["lit"] is None, ans)


def test_behaviour_and_flag_are_none():
    files = {"global-metadata.dat": build_metadata(24)}
    ans = il2cpp.solve_set([q("b", "What does the DecryptPayload method do?"),
                            q("fl", "What is the flag hidden in the string literals?")], files, {})
    check("a behaviour question is None", ans["b"] is None, ans)
    check("a flag question is None (text-is-data)", ans["fl"] is None, ans)


def test_not_metadata_is_ignored():
    check("a non-metadata blob parses to None", il2cpp.parse_metadata(b"not metadata at all" * 8) is None)
    check("report() finds nothing in an unrelated file", il2cpp.report({"a.bin": bytes(64)}) == [])
    check("signals() is 0.0 on a 64-byte blob", il2cpp.signals(
        [{"question": "What is it?", "answer_id": "q"}], {"a.bin": bytes(64)}) == 0.0)
    check("signals() is positive on real metadata with IL2CPP vocabulary",
          il2cpp.signals([q("m", "What is the IL2CPP method name?")],
                         {"global-metadata.dat": build_metadata(24)}) > 0.0)


def main() -> int:
    test_parse()
    test_never_wrong_literal_and_version_plain()
    test_never_wrong_ambiguous_count_unsure()
    test_never_wrong_name_unsure()
    test_unknown_version_is_none()
    test_truncated_is_none()
    test_inconsistent_offsets_is_none()
    test_behaviour_and_flag_are_none()
    test_not_metadata_is_ignored()
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
