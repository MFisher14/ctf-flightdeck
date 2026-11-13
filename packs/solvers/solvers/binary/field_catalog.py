#!/usr/bin/env python3
"""A catalog of the fields a later day may ask of any Binary sample, each as an unsure answer.

  .venv/bin/python solvers/binary/field_catalog.py SAMPLE FIELD [...]   what it would answer
  .venv/bin/python solvers/binary/field_catalog.py --list               every rule and its key

Backlog row 111 (and the hook of row 116). Day 8 added fourteen fields to old samples;
d02_analysis_has_cpp_typeinfo, d02_analysis_has_cpp_vtable and the two
`analysis_compression_methods` had no reader, and the lane stood from 09:01:10 until they were
answered by hand at 09:05:00. This module is the reader of that kind of field for every prefix,
before the day asks it:

  language marks     has_cpp_typeinfo, has_cpp_vtable, has_go_buildinfo, has_rust_panic,
                     has_swift_metadata, has_objc_classlist, has_kotlin_metadata, is_packed, ...
  ELF                entry_point, has_symtab, is_stripped, is_pie, is_static, nx, relro, canary,
                     interpreter, build_id, needed, section and segment counts, e_* header fields,
                     kernel-module .modinfo fields
  PE                 entry_point, image_base, subsystem, timestamp, is_dll, section names and count,
                     dll_characteristics bits (aslr, nx_compat, cfg), data directories (is_signed,
                     has_tls, has_resources, has_cli_header), overlay, pdb_path, imported DLLs
  Mach-O             magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, uuid, minimum
                     OS, sdk, platform, dylibs, segment and section names, is_pie, is_signed, and of
                     a universal binary its architectures
  WebAssembly        section, import, export, function and data-segment counts and names, the
                     producers section, memory pages, start function
  DEX, zip, jar, apk table sizes, checksum and signature; compression_methods (the reader Day 8
                     judged, zip_methods_owner.py), entry counts, has_manifest, is_signed, native ABIs
  class, jar         the rows of fields_template.py (main class, class version, Kotlin metadata)
  one function       disassembly, recover_code, exported_symbol, marker of an x86 or AArch64 ELF,
                     read as d01.py reads them
  dynamic trace      family, effects, network and schema of the embedded trace template
                     (trace_template.py, row 116)

Round 2 (2026-10-08, tests/test_binary_b.py):

  packers            packer / protector: one packer by a section name of the PE section table or by its
                     signature (PACKERS: UPX, MPRESS, ASPack, PECompact, Petite, FSG, NsPack, Themida,
                     WinLicense, VMProtect, Enigma, Obsidium, kkrunchy, Upack, PKLITE, ConfuserEx,
                     Dotfuscator, SmartAssembly, PyArmor; an APK's protector library). Nothing is
                     unpacked. Two packers are two candidates (None); is_packed is true where one is seen
  language           the source language where exactly ONE runtime left its mark (LANGUAGE_MARKS), Java
                     for a class or a jar, .NET for a CLI assembly; a sample with no mark is not C (None)
  runtime            row 292: runtime, runtime_name, language_runtime from that one mark, under the one key
                     binary.runtime/<container>; `toolchain` falls back to the mark when the file has no
                     version string at all (compiler and every *_version stay None without one)
  more runtimes      has_kotlin_native, has_free_pascal, has_nativeaot, has_graalvm, has_vlang, has_odin
  wasm component     is_component, core_module_count, component_version, layer (binfmt.wasm_component)

Row 177 (2026-10-09, tests/test_binary_hcfg_offset.py):

  hcfg_offset        the file offset where the prefix's one CRC-valid HCFG container begins as the
                     sample stores it (r_hcfg): base64 text, the raw bytes, hex digits, base64 as
                     UTF-16LE (and since package B4 as UTF-32LE, name utf32_file_offset, unsure).
                     Key binary.hcfg_offset/<stored form>, one option. Day 9 judged the
                     base64 form (name b64_file_offset, in the seed), so that answers plain
                     for d09; another day's prefix is unsure under binary.hcfg_offset/base64+dNN
                     until its base is judged once (row 188), and the other forms are unsure. No container, two places that hold one
                     of the day, or one in a form not read here: None. Package B2 (2026-10-11, the
                     player's yes; tests/test_day12_binary_hcfg_offset.py): another day answers under
                     the judged key too, in the one shape Days 9 and 11 were judged in
                     (_hcfg_judged_shape: an ELF, an integer question, the day's one place in the
                     sample, standard base64 with its padding, not joined; since the B2 review also
                     the text exactly the container's, and no section named for the container that
                     begins anywhere but at the text); any other shape as before. Row 267
                     (2026-10-12, the player's yes; tests/test_day13_binary_hcfg_raw.py): Day 12
                     judged the raw form (name file_offset, key binary.hcfg_offset/raw+d12), and
                     another day answers under that key in the judged raw shape
                     (_hcfg_judged_raw_shape: an ELF, an integer question, the day's one place in
                     the sample, the header and exactly its payload, no section named for the
                     container elsewhere). Plain where the ledger or the seed holds that key's
                     accepted row; a PE build and every other shape keep the day's own key
  hcfg_size, hcfg_payload_length   of the same container, unsure (generic.py has hcfg_length)

The Day 12 look-ahead, package B1 (2026-10-11, tests/test_day12_binary_fields.py):

  composed names     a fact of that one container under a name made of an object (hcfg, config,
                     container), the words of a property and a number form (r_hcfg_words):
                     hcfg_file_offset, hcfg_offset_hex, hcfg_end_offset, hcfg_key_hex, config_crc32,
                     hcfg_total_size, hcfg_encoded_length, hcfg_header_size, hcfg_encoding,
                     config_keys; the stored form as a yes/no (is_hcfg_base64, has_raw_hcfg:
                     r_hcfg_state); xor_key as a number (r_xor_key). A length only under a word
                     that names one reading; no container, two places or a joined text: None
  hcfg_virtual_address, hcfg_vaddr, hcfg_address, hcfg_rva
                     the container's own address, through the PT_LOAD segment or the PE section
                     that maps its file offset; the section's address is hcfg_section_vaddr
  artifact_size, artifact_md5, artifact_sha1   of a delivered file (r_artifact), numbered as
                     generic.py numbers artifact_sha256_<n>

Day 17's fold (backlog rows 328 and 340, 2026-10-17, tests/test_day18_binary_fold.py):

  hcfg_storage       the organiser's ordered rule (base64, raw_hcfg_section, wasm_data_segment,
                     raw_const_array, raw) read from the one CRC-valid container and the evidence around it
  mangled_<m>_symbol, typeinfo_symbol   from the container's own symbol table (ELF SHT_SYMTAB in order,
                     PE COFF in raw order with section-definition symbols), keyed by the container
  has_go_runtime, has_rust_mangled_symbol, has_coroutine_runtime   true only, from the marks the judge took
  methods, access_flags, method_count   of a jar's Main-Class or a loose class file
  section_names (PE) compact JSON text; hcfg_offset of a PE's raw container under binary.hcfg_offset/pe+dNN

The comment above r_hcfg_storage has the details. Three keys the judge took in a plain bank, which wrote
no ledger row, are CARRIED: their judged name answers plain until the ledger says otherwise.

The Day 18 look-ahead (B2 and B3, 2026-10-17, tests/test_day18_binary_lookahead.py):

  vtable_symbol, typeinfo_name_symbol   the class's _ZTV and _ZTS objects, read as typeinfo_symbol is
                     (_class_object), picks under binary.<field>/<container>
  `false` marks      has_go_runtime, has_rust_mangled_symbol, has_cpp_typeinfo, has_cpp_vtable and
                     has_coroutine_runtime, where the container's own tables prove the mark absent (_absent,
                     _jar_no_coroutines), picks under binary.<field>/<container>+absent

How sure. Every answer is labels.pick(key, options): a fact read from the bytes by a method named in
the option, under the key binary.<field as asked>/<container>, with the question's answer kind in the key when
the kind is integer or hexadecimal (answer_kinds.py, row 106). Nothing here is ever plain until the
judge has accepted the method for the key; then every sample answers by that method. Options are one
fact in the forms the question's kind allows, best first, three at most.

Absence. A yes/no field is answered `false` only where a table of the container itself says so (no
SHT_SYMTAB in the section header table, an empty data directory, no such entry in the archive's
central directory; since the Day 18 look-ahead, an unstripped ELF's whole symbol tables, section names
and bytes without a runtime's mark, ABSENT_MARKS). A mark that a search over the bytes does not find is
not proof of absence (a stripped or packed build): the answer is None.

Who asks. generic.py offers it the questions that are still None after everything else
(generic.catalog_answers), and evidence.py never offers it a field a day module decides on. On every
saved attempt of Days 1 to 8 nothing is left None, so nothing here changes a saved replay.
"""
import base64
import hashlib
import io
import json
import re
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import answer_kinds  # noqa: E402
import binfmt  # noqa: E402
import field_grammar  # noqa: E402
import facts  # noqa: E402
import hcfg  # noqa: E402
import labels  # noqa: E402
import needles  # noqa: E402

MAX_OPTIONS = 3            # options one catalog answer carries: a probe budget is 40 for the whole run
LIST_MAX = 512             # items of a list answer; a longer list is not offered
SEARCH_MAX = 256 << 20     # a file larger than this is not searched for a mark
BOOL_PAIRS = (("true", "false"), ("yes", "no"), ("1", "0"), ("present", "absent"), ("enabled", "disabled"),
              ("on", "off"))

# Marks a toolchain or a language runtime leaves in a build (found: true; not found: None).
TYPEINFO = re.compile(rb"_ZT[IS][0-9N][0-9A-Za-z_]*|\.\?A[VU][A-Za-z_][A-Za-z0-9_@]*@@")
VTABLE = re.compile(rb"_ZTV[0-9N][0-9A-Za-z_]*|\?\?_7[A-Za-z_][A-Za-z0-9_@]*@@")
MARKS = (
    (r"has_cpp_typeinfo|has_typeinfo|has_rtti|has_cpp_rtti", "has_cpp_typeinfo", TYPEINFO),
    (r"has_cpp_vtable|has_vtable|has_vtables", "has_cpp_vtable", VTABLE),
    (r"has_go_build_?info|has_buildinfo|has_go_buildinf", "has_go_buildinfo", (facts.GO_BUILDINFO,)),
    (r"has_go_pclntab|has_gopclntab|has_pclntab", "has_go_pclntab", (b".gopclntab", b"\xf1\xff\xff\xff\x00\x00",
                                                                     b"\xf0\xff\xff\xff\x00\x00")),
    (r"has_rust_panic(?:_handler|_strings|_info)?|has_rust_metadata|has_rust_runtime", "has_rust_panic",
     (b"rust_panic", b"rust_begin_unwind", b"core::panicking", b"panicked at ")),
    (r"has_swift_metadata|has_swift5?_metadata|has_swift_runtime|has_swift5_types|has_swift_types",
     "has_swift_metadata", (b"swift5_typeref", b"swift5_fieldmd", b"swift5_types", b"__swift5_")),
    (r"has_objc_classlist|has_objc_metadata|has_objc_runtime|has_objc", "has_objc_classlist",
     (b"__objc_classlist", b"__objc_methname", b"_objc_msgSend")),
    (r"has_kotlin_metadata|has_kotlin", "has_kotlin_metadata", (b"kotlin/Metadata",)),
    (r"has_nim_main|has_nim_runtime|has_nim", "has_nim_main", (b"NimMain",)),
    (r"has_zig_(?:panic|runtime|std)|has_zig", "has_zig_runtime", (b"zig_probe_stack", b"start.zig",
                                                                   b"reached unreachable code")),
    (r"has_crystal_main|has_crystal_runtime|has_crystal", "has_crystal_main", (b"__crystal_main", b"Crystal::")),
    (r"has_d_runtime|has_dmain|has_d_main|has_druntime", "has_d_runtime", (b"_Dmain", b"_d_run_main", b"druntime")),
    (r"has_ghc_rts|has_haskell_rts|has_haskell_runtime|has_ghc", "has_ghc_rts", (b"GHC RTS", b"hs_main",
                                                                                b"base_GHCziBase")),
    (r"has_ocaml_runtime|has_ocaml|has_caml_startup", "has_ocaml_runtime", (b"caml_startup", b"caml_main",
                                                                           b"caml_program")),
    (r"has_dart_snapshot|has_dart_aot|has_dart|has_flutter", "has_dart_snapshot",
     (b"_kDartVmSnapshotData", b"_kDartIsolateSnapshotData", b"kDartVmSnapshotInstructions")),
    (r"has_node_sea|has_sea_blob|is_node_sea|has_node", "has_node_sea",
     (b"NODE_SEA_BLOB", b"NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2")),
    (r"has_pyinstaller(?:_cookie)?|is_pyinstaller", "has_pyinstaller", (facts.PYI_COOKIE,)),
    (r"has_nuitka|is_nuitka", "has_nuitka", (b"NUITKA_ONEFILE_PARENT", b"__nuitka_binary_dir", b"nuitka_version")),
    (r"has_python(?:_runtime)?|embeds_python|has_cpython", "has_python", (b"Py_Initialize", b"PyRun_SimpleString",
                                                                          b"Py_BytesMain")),
    (r"has_cli_metadata|has_bsjb|has_dotnet_metadata", "has_cli_metadata", (b"BSJB",)),
    (r"has_delphi(?:_rtti|_runtime)?|is_delphi", "has_delphi", (b"Embarcadero Delphi", b"Borland Delphi",
                                                                      b"@System@@", b"SOFTWARE\\Borland\\Delphi")),
    (r"has_beam_atoms|has_erlang", "has_beam_atoms", (b"AtU8",)),
    # Round 2 of the Day 9 preparation (2026-10-08): the runtimes the planner's list names and round 1 left out.
    (r"has_konan(?:_runtime)?|has_kotlin_native|is_kotlin_native", "has_kotlin_native",
     (b"Konan_", b"kfun:", b"kotlin.native.", b"konan::")),
    (r"has_fpc(?:_runtime)?|has_free_pascal|has_pascal(?:_runtime)?|is_free_pascal", "has_free_pascal",
     (b"FPC ", b"fpc_initializeunits", b"FPC_SHARED_LIB_START", b"Free Pascal")),
    (r"has_native_?aot|is_native_?aot|has_nativeaot_runtime", "has_nativeaot",
     (b"__managedcode", b"RhpNewFast", b"S_P_CoreLib_", b"__modules_a")),
    (r"has_graalvm|is_native_image|has_native_image|has_svm_heap|has_substrate_?vm|is_graalvm_native_image",
     "has_graalvm", (b"com.oracle.svm", b".svm_heap", b"graal_isolate", b"SubstrateVM")),
    (r"has_v_runtime|has_vlang|is_vlang", "has_vlang", (b"V_COMMIT_HASH", b"v_panic", b"builtin__panic")),
    (r"has_odin_runtime|has_odin", "has_odin", (b"runtime.default_assertion_failure_proc", b"odin_")),
    (r"has_upx|is_upx|upx_packed|is_upx_packed", "has_upx", (b"UPX!",)),
)


class Sample:
    """One sample and every reading of it the rules share, each made once and only when asked."""

    def __init__(self, name, data: bytes, members=None):
        self.name, self.data, self.members = name or "", data, list(members or [])
        self.day = _day_of(self.name)     # fields() sets it from the question's prefix
        self._cache = {}

    def _once(self, key, make):
        if key not in self._cache:
            try:
                self._cache[key] = make()
            except Exception as e:      # a reader that fails states nothing; the rule answers None
                print(f"[catalog] {key}: {type(e).__name__}: {e}", file=sys.stderr)
                self._cache[key] = None
        return self._cache[key]

    @property
    def elf(self):
        return self._once("elf", lambda: binfmt.elf(self.data))

    @property
    def pe(self):
        return self._once("pe", lambda: binfmt.pe(self.data))

    @property
    def fat(self):
        return self._once("fat", lambda: binfmt.macho_fat(self.data))

    @property
    def macho(self):
        """A thin Mach-O's image; of a fat file the first architecture's (None: no thin image)."""
        def make():
            if self.fat:
                return binfmt.macho(self.data, self.fat[0][2])
            return binfmt.macho(self.data)
        return self._once("macho", make)

    @property
    def wasm(self):
        return self._once("wasm", lambda: binfmt.wasm(self.data))

    @property
    def component(self):
        return self._once("component", lambda: binfmt.wasm_component(self.data))

    @property
    def zip(self):
        """{names (files, archive order), entries (directories too), infos} of a zip, a jar, an APK."""
        def make():
            if not (self.data[:4] == b"PK\x03\x04" or (self.data[:2] == b"#!" and b"PK\x03\x04" in self.data[:1 << 16])):
                return None
            zf = zipfile.ZipFile(io.BytesIO(self.data))
            infos = zf.infolist()
            return {"zf": zf, "infos": infos, "names": [i.filename for i in infos if not i.is_dir()],
                    "entries": len(infos)}
        return self._once("zip", make)

    @property
    def dex(self):
        """The DEX header of the sample, or of the classes.dex of an APK."""
        def make():
            got = binfmt.dex(self.data)
            if got is None and self.zip and "classes.dex" in self.zip["names"]:
                with self.zip["zf"].open("classes.dex") as fh:
                    got = binfmt.dex(fh.read(0x70))
            return got
        return self._once("dex", make)

    @property
    def jvm(self):
        """facts.py's class, jar, DEX, wasm and Mach-O facts (the readers that read headers only)."""
        def make():
            found = {}
            for reader in (facts._jvm, facts._dex, facts._wasm, facts._macho):
                try:
                    reader(self.data, found)
                except Exception:
                    continue
            return found
        return self._once("jvm", make)

    @property
    def hcfg_places(self):
        """[(member index, stored form or None, file offset, container)] of the sample's container (r_hcfg)."""
        return self._once(f"hcfg:{self.day}", lambda: _hcfg_places(self))

    @property
    def kind(self) -> str:
        """The container the rules key on: elf, pe, macho, fat, wasm, dex, zip, class or bytes."""
        if self.elf:
            return "elf"
        if self.pe:
            return "pe"
        if self.fat:
            return "fat"
        if self.macho:
            return "macho"
        if self.wasm:
            return "wasm"
        if binfmt.dex(self.data):
            return "dex"
        if self.zip:
            return "zip"
        if facts.is_class(self.data):
            return "class"
        return "bytes"

    @property
    def hits(self):
        """B4 (the Day 19 look-ahead): {needle: [places]} of every literal the language, runtime, compiler and
        toolchain readers look for (all_needles()), from one pass over a sample of needles.BIG bytes or more
        (needles.index: exact, about 0.25 s on the 67 MB d08 where the readers' own searches took 0.7 to
        5.1 s, and kept for the process); None for a smaller sample, which is searched as before."""
        def make():
            if len(self.data) < needles.BIG or len(self.data) > SEARCH_MAX:
                return None
            return needles.index(self.data, all_needles())
        return self._once("hits", make)

    def found(self, slug: str, marks) -> bool:
        """Whether a mark stands in the sample's bytes (a compiled pattern, or any of some literals).
        For an archive the classes and native libraries inside it are searched, at most 64 MB of them."""
        def make():
            if len(self.data) > SEARCH_MAX:
                return None
            blobs = [self.data]
            if self.zip:
                read = 0
                for info in self.zip["infos"]:
                    if info.is_dir() or info.file_size > 16 << 20 or read > 64 << 20:
                        continue
                    blobs.append(self.zip["zf"].read(info))
                    read += info.file_size
            for n, blob in enumerate(blobs):
                if hasattr(marks, "search"):
                    if marks.search(blob):
                        return True
                elif n == 0 and self.hits is not None and all(m in self.hits for m in marks):
                    if any(self.hits[m] for m in marks):     # B4: the one-pass index of a large sample
                        return True
                elif any(m in blob for m in marks):
                    return True
            return False
        return self._once("mark:" + slug, make)


# ---------------------------------------------------------------------------- option builders

def _bool(method: str, flag, fmt) -> list:
    """A yes/no fact as the question's kind spells it: true/false, or the pair its enum lists
    (yes/no, 1/0, present/absent), or 1/0 for an integer."""
    if flag is None:
        return []
    pair = BOOL_PAIRS[0]
    if answer_kinds.kind_of(fmt) == "integer":
        pair = ("1", "0")
    else:
        accepted = [answer_kinds._loose(a) for a in (fmt or {}).get("accepted_values") or [] if isinstance(a, str)]
        for a, b in BOOL_PAIRS:
            if a in accepted and b in accepted:
                pair = (a, b)
                break
    return [(method, pair[0] if flag else pair[1])]


def _num(method: str, n, hex_first: bool = False, width: int = 0) -> list:
    if n is None:
        return []
    dec, hx = (method, str(n)), (method + ":hex", f"0x{n:0{width}x}" if n >= 0 else None)
    return [hx, dec] if hex_first else [dec, hx]


def _text(method: str, value) -> list:
    return [(method, value)] if isinstance(value, str) and value else []


def _list(method: str, items) -> list:
    if items is None or len(items) > LIST_MAX:
        return []
    return [(method, list(items))]


# ---------------------------------------------------------------------------- rules
# Each rule: fn(S, fmt, m) -> (container the key names, [(method, value), ...]) or None.

def r_mark(slug, marks):
    def rule(S, fmt, m):
        box = S.kind
        # A table of the container that states the same fact stands before the search of the bytes.
        if slug == "has_objc_classlist" and S.macho:
            names = [s for _, s in S.macho["sections"]]
            return "macho", _bool("section", "__objc_classlist" in names, fmt)
        if slug == "has_swift_metadata" and S.macho:
            return "macho", _bool("section", any(s.startswith("__swift5_") for _, s in S.macho["sections"]), fmt)
        if slug == "has_swift_metadata" and S.elf and S.elf["sections"]:
            return "elf", _bool("section", any((s["name"] or "").startswith("swift5_") for s in S.elf["sections"]),
                                fmt)
        if slug == "has_go_pclntab" and S.elf and S.elf["sections"]:
            return "elf", _bool("section", any(s["name"] == ".gopclntab" for s in S.elf["sections"]), fmt)
        if slug == "has_cli_metadata" and S.pe:
            return "pe", _bool("com_descriptor", bool(S.pe["dirs"].get("com_descriptor", (0, 0))[0]), fmt)
        if S.found(slug, marks):
            return box, _bool("mark", True, fmt)
        if slug in ABSENT_MARKS:
            return _absent(S, slug, fmt)        # the Day 18 look-ahead, B3: false where the tables prove it
        return None        # not found is not proof of absence
    return rule


def r_entry(S, fmt, m):
    if S.elf:
        return "elf", _num("e_entry", S.elf["e_entry"], hex_first=True)
    if S.pe:
        rva, base = S.pe["entry_rva"], S.pe["image_base"]
        return "pe", [("va:hex", f"0x{base + rva:x}"), ("rva:hex", f"0x{rva:x}"), ("va", str(base + rva)),
                      ("rva", str(rva))]
    if S.macho and S.macho["entryoff"] is not None and not S.fat:
        return "macho", _num("lc_main_entryoff", S.macho["entryoff"], hex_first=True)
    if S.wasm and S.wasm["start"] is not None:
        return "wasm", _num("start_function", S.wasm["start"])
    return None


def _elf_sections(S):
    return S.elf["sections"] if S.elf and S.elf["sections"] else None


def r_has_symtab(S, fmt, m):
    secs = _elf_sections(S)
    return ("elf", _bool("sht_symtab", any(s["type"] == 2 for s in secs), fmt)) if secs else None


def r_stripped(S, fmt, m):
    secs = _elf_sections(S)
    return ("elf", _bool("no_sht_symtab", not any(s["type"] == 2 for s in secs), fmt)) if secs else None


def r_has_dynsym(S, fmt, m):
    secs = _elf_sections(S)
    return ("elf", _bool("sht_dynsym", any(s["type"] == 11 for s in secs), fmt)) if secs else None


def r_debug(S, fmt, m):
    secs = _elf_sections(S)
    if secs:
        return "elf", _bool("debug_sections", any((s["name"] or "").startswith((".debug_", ".zdebug_")) for s in secs),
                            fmt)
    if S.pe:
        return "pe", _bool("debug_directory", bool(S.pe["dirs"].get("debug", (0, 0))[1]), fmt)
    if S.macho and not S.fat:
        return "macho", _bool("dwarf_segment", "__DWARF" in S.macho["segments"], fmt)
    if S.wasm:
        return "wasm", _bool("debug_custom_sections", any(c.startswith(".debug_") for c in S.wasm["custom"]), fmt)
    return None


def r_pie(S, fmt, m):
    if S.elf and S.elf["e_type"] in (2, 3):
        return "elf", _bool("e_type_dyn", S.elf["e_type"] == 3, fmt)
    if S.macho and not S.fat:
        return "macho", _bool("mh_pie", bool(S.macho["flags"] & 0x200000), fmt)
    if S.pe:
        return "pe", _bool("dynamic_base", bool(S.pe["dll_characteristics"] & 0x40), fmt)
    return None


def r_static(S, fmt, m):
    if S.elf and S.elf["segments"] is not None:
        static = not any(seg["type"] == 3 for seg in S.elf["segments"])
        return "elf", _bool("no_pt_interp", static if "static" in m.group(0) else not static, fmt)
    return None


def r_linkage(S, fmt, m):
    """static or dynamic, by the reading r_static makes: an ELF whose program header table was read
    and holds no PT_INTERP is static (row 5 of the Day 13 look-ahead)."""
    if S.elf and S.elf["segments"]:
        static = not any(seg["type"] == 3 for seg in S.elf["segments"])
        return "elf", [("pt_interp", "static" if static else "dynamic"),
                       ("pt_interp:linked", "statically linked" if static else "dynamically linked")]
    return None


def r_text_size(S, fmt, m):
    """The size of the ELF's one .text section, from the section table (a PE has SizeOfCode beside its
    .text section: two readings, not answered)."""
    secs = [s for s in (_elf_sections(S) or []) if s.get("name") == ".text"]
    return ("elf", _num("sh_size", secs[0].get("size"))) if len(secs) == 1 and secs[0].get("size") is not None else None


def r_nx(S, fmt, m):
    inverse = "exec" in m.group(0)
    if S.elf and S.elf["segments"] is not None:
        stack = next((seg for seg in S.elf["segments"] if seg["type"] == 0x6474E551), None)
        if stack is None:
            return None       # no PT_GNU_STACK: the loader's default decides, the file does not say
        nx = not stack["flags"] & 1
        return "elf", _bool("pt_gnu_stack", nx != inverse, fmt)
    if S.pe:
        nx = bool(S.pe["dll_characteristics"] & 0x100)
        return "pe", _bool("nx_compat", nx != inverse, fmt)
    return None


def _relro(S):
    if not (S.elf and S.elf["segments"] is not None):
        return None
    if not any(seg["type"] == 0x6474E552 for seg in S.elf["segments"]):
        return "none"
    return "full" if S.elf["bind_now"] else "partial"


def r_relro(S, fmt, m):
    level = _relro(S)
    if level is None:
        return None
    word = m.group(0)
    if word.startswith(("has_full", "full", "is_full")):
        return "elf", _bool("gnu_relro_bind_now", level == "full", fmt)
    if word.startswith(("has_", "is_")):
        return "elf", _bool("pt_gnu_relro", level != "none", fmt)
    return "elf", [("checksec", level), ("checksec:title", {"none": "No RELRO", "partial": "Partial RELRO",
                                                           "full": "Full RELRO"}[level])]


def r_canary(S, fmt, m):
    if S.elf and S.found("canary", (b"__stack_chk_fail", b"__stack_chk_guard")):
        return "elf", _bool("stack_chk_symbol", True, fmt)
    if S.pe and S.found("canary", (b"__security_cookie", b"__security_check_cookie")):
        return "pe", _bool("security_cookie_symbol", True, fmt)
    return None


def r_interp(S, fmt, m):
    if S.elf and S.elf["interp"]:
        return "elf", _text("pt_interp", S.elf["interp"])
    if S.macho and S.macho["dylinker"] and not S.fat:
        return "macho", _text("lc_load_dylinker", S.macho["dylinker"])
    return None


def r_build_id(S, fmt, m):
    if S.elf and S.elf["build_id"]:
        return "elf", [("hex", S.elf["build_id"]), ("hex:0x", "0x" + S.elf["build_id"])]
    return None


def r_soname(S, fmt, m):
    if S.elf and S.elf["soname"]:
        return "elf", _text("dt_soname", S.elf["soname"])
    if S.macho and S.macho["id_dylib"] and not S.fat:
        return "macho", _text("lc_id_dylib", S.macho["id_dylib"])
    return None


def r_needed(S, fmt, m):
    if S.elf and S.elf["needed"] is not None and None not in S.elf["needed"]:
        return "elf", _list("dt_needed", S.elf["needed"])
    if S.pe:
        names = binfmt.pe_imports(S.data, S.pe)
        if names is not None:
            return "pe", _list("import_directory", names) + _list("import_directory:lower", [n.lower() for n in names])
    if S.macho and not S.fat:
        return "macho", _list("lc_load_dylib", S.macho["dylibs"])
    if S.wasm and S.wasm["imports"] is not None:
        modules = []
        for module, _, _ in S.wasm["imports"]:
            if module not in modules:
                modules.append(module)
        return "wasm", _list("import_modules", modules) + _list("module.field", [f"{a}.{b}" for a, b, _ in
                                                                                 S.wasm["imports"]])
    return None


def r_rpath(S, fmt, m):
    if S.elf:
        value = S.elf["runpath"] if "run" in m.group(0) else (S.elf["rpath"] or S.elf["runpath"])
        return ("elf", _text("dt_runpath" if value == S.elf["runpath"] else "dt_rpath", value)) if value else None
    if S.macho and S.macho["rpaths"] and not S.fat:
        return "macho", _list("lc_rpath", S.macho["rpaths"]) if answer_kinds.kind_of(fmt) == "json" else \
            _text("lc_rpath_first", S.macho["rpaths"][0])
    return None


def r_elf_raw(S, fmt, m):
    name = m.group(1)
    if S.elf and name in S.elf and isinstance(S.elf[name], int):
        return "elf", _num(name, S.elf[name], hex_first=name in ("e_entry", "e_flags"))
    return None


def r_osabi(S, fmt, m):
    return ("elf", _num("ei_osabi", S.elf["ei_osabi"])) if S.elf else None


def r_section_count(S, fmt, m):
    if S.elf:
        return "elf", _num("e_shnum", S.elf["e_shnum"])[:1] + [("e_shnum_without_null", str(S.elf["e_shnum"] - 1))
                                                               ] * bool(S.elf["e_shnum"])
    if S.pe:
        return "pe", _num("number_of_sections", S.pe["number_of_sections"])[:1]
    if S.macho and not S.fat:
        return "macho", _num("nsects", len(S.macho["sections"]))[:1]
    if S.wasm:
        return "wasm", _num("sections", len(S.wasm["sections"]))[:1]
    return None


def r_segment_count(S, fmt, m):
    if S.elf:
        return "elf", _num("e_phnum", S.elf["e_phnum"])[:1]
    if S.macho and not S.fat:
        return "macho", _num("lc_segment", len(S.macho["segments"]))[:1]
    return None


def _pe_long_section_names(data: bytes, names: list):
    """The section names with every `/<n>` resolved through the COFF string table, or None."""
    try:
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        ptr, count = struct.unpack_from("<II", data, nt + 12)
        if not ptr:
            return None
        strtab = ptr + 18 * count
        size = struct.unpack_from("<I", data, strtab)[0]
        out = []
        for n in names:
            if re.fullmatch(r"/\d+", n):
                off = int(n[1:])
                end = data.find(b"\0", strtab + off, strtab + size)
                if off < 4 or end < 0:
                    return None
                n = data[strtab + off:end].decode("utf-8", "replace")
            out.append(n)
        return out
    except (struct.error, ValueError):
        return None


def r_section_names(S, fmt, m):
    if S.pe:
        # Day 17 (row 340): the judge took a PE build's COFF section names in table order, no leading
        # empty name, as compact JSON text under the name `names`; a list sent as the value itself was
        # answered http 400 invalid_answers, so the option is the text.
        # A header name `/<n>` is a long name kept at offset n of the COFF string table (MinGW's debug
        # sections): which of the two the judge means is not judged, so such a table is unsure under
        # options of their own names.
        names = [s["name"] for s in S.pe["sections"]]
        if len(names) > LIST_MAX:
            return None
        if not any(re.fullmatch(r"/\d+", n) for n in names):
            return "pe", [("names", json.dumps(names, separators=(",", ":")))]
        long = _pe_long_section_names(S.data, names)
        return "pe", (([("long_names", json.dumps(long, separators=(",", ":")))] if long else [])
                      + [("header_names", json.dumps(names, separators=(",", ":")))])
    if S.macho and not S.fat:
        return "macho", (_list("sectname", [s for _, s in S.macho["sections"]])
                         + _list("segname,sectname", [f"{g},{s}" for g, s in S.macho["sections"]]))
    if S.wasm:
        names = [binfmt.WASM_SECTION.get(sid, str(sid)) for sid, _, _ in S.wasm["sections"]]
        return "wasm", _list("section_names", names) + _list("section_ids", [sid for sid, _, _ in S.wasm["sections"]])
    return None           # an ELF's are generic.py's (Day 1's judged form)


def r_segment_names(S, fmt, m):
    if S.macho and not S.fat:
        return "macho", _list("segname", S.macho["segments"])
    if S.elf and S.elf["segments"] is not None:
        return "elf", _list("p_type_names", [binfmt.PT.get(seg["type"], f"0x{seg['type']:x}")
                                             for seg in S.elf["segments"]])
    return None


def r_symbol_count(S, fmt, m):
    counts = binfmt.elf_symbol_counts(S.data, S.elf) if S.elf else None
    if counts is None:
        return None
    return "elf", [("symtab_named", str(counts[1])), ("symtab_entries", str(counts[0]))]


# ---------------------------------------------------------------------------- the Day 16 look-ahead
# Day 15 was "assembly and symbol loss": the day re-asked the first C ELF for its symbols, section
# names and disassembly, and the new component shipped two builds of one program (stripped and
# symbolized, dNN_analysis_<build>_<field>). Those are read by generic.py and dispatched by
# generic.role_answers. The fields below are the symbol-table-adjacent counts and marks a Day 16 that
# deepens the same theme would most likely ask next, and which the catalog returned None for before:
# the dynamic symbol table, the relocation tables, the .dynamic entries, the GNU hash, the notes, the
# build-id as a boolean, and the .comment compiler string. Every one is an unsure pick under
# binary.<field>/elf (no judged row), so one base probe settles each; nothing here is ever plain, and
# a fact the file does not carry (no such section, an unreadable entsize) is None, never a guess.
# A stripped build drops .symtab/.strtab but keeps .dynsym, so these are exactly the kind of field
# whose answer differs between the two builds of one program.

def _sec_count(sec):
    """Entries of an ELF section with a fixed-width entsize (.dynsym, .rela*, .dynamic), or None."""
    if sec is None or not sec.get("entsize"):
        return None
    n = sec["size"] // sec["entsize"]
    return n if n >= 0 else None


def r_dynsym_count(S, fmt, m):
    """Entries of the ELF .dynsym (SHT_DYNSYM = 11). Unchanged between a stripped and a symbolized
    build of one program (symbol_count / .symtab is what differs)."""
    secs = _elf_sections(S)
    if not secs:
        return None
    n = _sec_count(next((s for s in secs if s["type"] == 11), None))
    if n is None or n == 0:
        return None
    return "elf", [("dynsym_entries", str(n)), ("dynsym_without_null", str(n - 1))]


def r_reloc_count(S, fmt, m):
    """Relocation entries across every SHT_RELA (4) and SHT_REL (9) section of the ELF. The total is
    offered first, then the two tables apart when both are present (so a question that means only the
    dynamic relocations still has its reading)."""
    secs = _elf_sections(S)
    if not secs:
        return None
    rela = sum(_sec_count(s) or 0 for s in secs if s["type"] == 4)
    rel = sum(_sec_count(s) or 0 for s in secs if s["type"] == 9)
    if rela == 0 and rel == 0 and not any(s["type"] in (4, 9) for s in secs):
        return None
    opts = [("rela_and_rel", str(rela + rel))]
    if rela and rel:
        opts.append(("rela_only", str(rela)))
    plt = _sec_count(next((s for s in secs if s["type"] in (4, 9)
                           and (s.get("name") or "").endswith(".plt")), None))
    if plt:
        opts.append(("rela_plt_only", str(plt)))
    return "elf", opts


def r_dynamic_count(S, fmt, m):
    """Entries of the ELF .dynamic. binfmt stops at the DT_NULL terminator, so its list holds the real
    tags only; readelf -d and pyelftools count the terminator too. Both readings are offered, the
    with-terminator count first (what readelf prints) and the real-tag count second."""
    if not (S.elf and S.elf.get("dynamic") is not None):
        return None
    n = len(S.elf["dynamic"])         # real tags, DT_NULL excluded (binfmt breaks on it)
    if n == 0:
        return None
    return "elf", [("dt_with_null", str(n + 1)), ("dt_without_null", str(n))]


def r_has_gnu_hash(S, fmt, m):
    """Whether the ELF carries a .gnu.hash (SHT_GNU_HASH = 0x6ffffff6); a plain .hash (SHT_HASH = 5)
    is read where the field names the SysV hash."""
    secs = _elf_sections(S)
    if not secs:
        return None
    word = m.group(0)
    if "gnu" in word:
        present = any(s["type"] == 0x6FFFFFF6 or (s.get("name") == ".gnu.hash") for s in secs)
        return "elf", _bool("sht_gnu_hash", present, fmt)
    present = any(s["type"] == 5 or (s.get("name") == ".hash") for s in secs)
    return "elf", _bool("sht_hash", present, fmt)


def r_has_build_id(S, fmt, m):
    """Whether the ELF carries a GNU build-id note (the id itself is r_build_id's)."""
    if not S.elf:
        return None
    return "elf", _bool("note_gnu_build_id", bool(S.elf.get("build_id")), fmt)


def r_note_names(S, fmt, m):
    """The names of the ELF's SHT_NOTE (7) sections (.note.gnu.property, .note.ABI-tag, ...). A
    stripped build keeps its notes, so this does not differ between the two builds."""
    secs = _elf_sections(S)
    if not secs:
        return None
    names = [s.get("name") or "" for s in secs if s["type"] == 7]
    if not names:
        return None
    return "elf", _list("sht_note", names)


def r_comment(S, fmt, m):
    """The compiler tag in the ELF .comment section (`GCC: (...) 13.2.0`, `clang version ...`). The
    section is the one the author left in; when it is absent, or holds no printable run, the answer is
    None (never guessed). The whole text and each NUL-separated line are offered."""
    secs = _elf_sections(S)
    if not secs:
        return None
    sec = next((s for s in secs if (s.get("name") == ".comment") and s["type"] == 1), None)
    if sec is None or not sec.get("size") or sec["offset"] + sec["size"] > len(S.data):
        return None
    raw = S.data[sec["offset"]:sec["offset"] + sec["size"]]
    lines = [p.decode("latin-1") for p in raw.split(b"\x00") if p.strip()]
    lines = [t for t in lines if t.isprintable()]
    if not lines:
        return None
    opts = []
    if len(lines) == 1:
        opts.append(("comment", lines[0]))
    else:
        opts.append(("comment_joined", "\n".join(lines)))
        opts.append(("comment_first", lines[0]))
    return "elf", opts


def r_flags(S, fmt, m):
    if S.elf:
        return "elf", _num("e_flags", S.elf["e_flags"], hex_first=True)
    if S.macho and not S.fat:
        return "macho", _num("flags", S.macho["flags"], hex_first=True, width=8) + \
            [("flags:hex_short", f"0x{S.macho['flags']:x}")]
    if S.pe:
        return "pe", _num("characteristics", S.pe["characteristics"], hex_first=True, width=4)
    return None


def r_bits(S, fmt, m):
    for box, info in (("elf", S.elf), ("pe", S.pe), ("macho", None if S.fat else S.macho)):
        if info:
            bits = 64 if (info.get("plus") if box == "pe" else info["bits"] == 64) else 32
            if m.group(0).startswith("is_"):
                return box, _bool("header", bits == 64, fmt)
            return box, [("bits", str(bits))]
    return None


def r_modinfo(S, fmt, m):
    secs = _elf_sections(S)
    sec = next((s for s in secs or [] if s["name"] == ".modinfo"), None)
    if sec is None:
        return None
    pairs = {}
    for item in S.data[sec["offset"]:sec["offset"] + min(sec["size"], 1 << 16)].split(b"\0"):
        key, eq, value = item.partition(b"=")
        if eq and key:
            pairs.setdefault(key.decode("utf-8", "replace"), value.decode("utf-8", "replace"))
    return "elf", _text("modinfo", pairs.get(m.group(1)))


# ---- PE

def _pe_num(field, hex_first=False, width=0):
    def rule(S, fmt, m):
        return ("pe", _num(field, S.pe[field], hex_first, width)) if S.pe else None
    return rule


def _pe_bit(field, bit, method):
    def rule(S, fmt, m):
        return ("pe", _bool(method, bool(S.pe[field] & bit), fmt)) if S.pe else None
    return rule


def _pe_dir(name):
    def rule(S, fmt, m):
        return ("pe", _bool(name + "_directory", bool(S.pe["dirs"].get(name, (0, 0))[1]), fmt)) if S.pe else None
    return rule


def r_subsystem(S, fmt, m):
    if not S.pe:
        return None
    n = S.pe["subsystem"]
    name = binfmt.PE_SUBSYSTEM.get(n)
    out = [("decimal", str(n))]
    if name:
        out += [("name", "IMAGE_SUBSYSTEM_" + name), ("lower", name.lower())]
    return "pe", out


def r_timestamp(S, fmt, m):
    if not S.pe:
        return None
    n = S.pe["timestamp"]
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(n))
    return "pe", [("decimal", str(n)), ("hex", f"0x{n:08x}"), ("iso", iso)]


def r_pe_magic(S, fmt, m):
    if S.pe:
        return "pe", [("hex", f"0x{S.pe['magic']:x}"), ("name", "PE32+" if S.pe["plus"] else "PE32"),
                      ("decimal", str(S.pe["magic"]))]
    if S.macho and not S.fat:
        return "macho", [("hex", f"0x{S.macho['magic']:08x}"), ("decimal", str(S.macho["magic"])),
                         ("file_bytes", S.data[S.macho["offset"]:S.macho["offset"] + 4].hex())]
    if S.fat:
        return "fat", [("hex", "0x" + S.data[:4].hex()), ("file_bytes", S.data[:4].hex())]
    return None


def r_signed(S, fmt, m):
    if S.pe:
        return "pe", _bool("security_directory", bool(S.pe["dirs"].get("security", (0, 0))[1]), fmt)
    if S.macho and not S.fat:
        return "macho", _bool("lc_code_signature", S.macho["code_signature"], fmt)
    if S.zip:
        signed = any(re.fullmatch(r"META-INF/[^/]+\.(?:RSA|DSA|EC)", n, re.I) for n in S.zip["names"])
        return "zip", _bool("meta_inf_signature", signed, fmt)
    return None


def r_overlay(S, fmt, m):
    if not S.pe:
        return None
    if m.group(0).startswith("has_"):
        return "pe", _bool("past_last_section", S.pe["overlay"] > 0, fmt)
    return "pe", _num("past_last_section", S.pe["overlay"])


def r_pdb(S, fmt, m):
    if not (S.pe and S.pe["pdb"]):
        return None
    path = S.pe["pdb"]
    return "pe", [("rsds_path", path), ("rsds_basename", re.split(r"[\\/]", path)[-1])]


def r_linker(S, fmt, m):
    return ("pe", [("major.minor", "%d.%d" % S.pe["linker"]), ("major.minor:02", "%d.%02d" % S.pe["linker"])]) \
        if S.pe else None


def r_is_dll(S, fmt, m):
    if S.pe:
        return "pe", _bool("image_file_dll", bool(S.pe["characteristics"] & 0x2000), fmt)
    return None


def r_checksum(S, fmt, m):
    if S.pe and "dex" not in m.group(0):
        return "pe", _num("optional_header_checksum", S.pe["checksum"], hex_first=True, width=8)
    if S.dex:
        return "dex", _num("adler32", S.dex["checksum"], hex_first=True, width=8)
    return None


# ---- Mach-O

def _thin(S):
    return S.macho if S.macho and not S.fat else None


def r_cputype(S, fmt, m):
    mo = _thin(S)
    if not mo:
        return None
    cpu = mo["cputype"]
    out = [("decimal", str(cpu)), ("hex", f"0x{cpu:08x}"), ("hex_short", f"0x{cpu:x}")]
    if cpu in binfmt.MACHO_CPU:
        out.insert(1, ("name", binfmt.MACHO_CPU[cpu]))
    return "macho", out


def r_cpusubtype(S, fmt, m):
    mo = _thin(S)
    if not mo:
        return None
    return "macho", [("low24", str(mo["cpusubtype"] & 0x00FFFFFF)), ("raw", str(mo["cpusubtype"])),
                     ("raw:hex", f"0x{mo['cpusubtype']:08x}")]


def r_filetype(S, fmt, m):
    mo = _thin(S)
    if not mo:
        return None
    n = mo["filetype"]
    name = binfmt.MACHO_FILETYPE.get(n)
    out = [("decimal", str(n))]
    if name:
        out = [("name", name), ("decimal", str(n)), ("lower", name.lower()), ("bare", name[3:].lower())]
    return "macho", out


def _macho_num(field, hex_first=False):
    def rule(S, fmt, m):
        mo = _thin(S)
        return ("macho", _num(field, mo[field], hex_first)) if mo else None
    return rule


def r_uuid(S, fmt, m):
    mo = _thin(S)
    if not (mo and mo["uuid"]):
        return None
    h = mo["uuid"]
    dashed = "-".join((h[:8], h[8:12], h[12:16], h[16:20], h[20:]))
    return "macho", [("upper_dashed", dashed.upper()), ("lower_dashed", dashed), ("hex", h)]


def _dotted(version):
    if not version:
        return []
    short = version[:-2] if version.endswith(".0") else None
    return ([("x.y", short)] if short else []) + [("x.y.z", version)]


def r_minos(S, fmt, m):
    mo = _thin(S)
    return ("macho", _dotted(mo["minos"])) if mo and mo["minos"] else None


def r_sdk(S, fmt, m):
    mo = _thin(S)
    return ("macho", _dotted(mo["sdk"])) if mo and mo["sdk"] else None


def r_platform(S, fmt, m):
    mo = _thin(S)
    if not (mo and mo["platform"] is not None):
        return None
    name = binfmt.MACHO_PLATFORM.get(mo["platform"])
    return "macho", ([("name", name)] if name else []) + [("decimal", str(mo["platform"]))] + \
        ([("upper", "PLATFORM_" + name.upper())] if name else [])


def _archs(S):
    """[(cputype, cpusubtype)] of a fat file's architectures, or of a thin image alone."""
    if S.fat:
        return [(cpu, sub) for cpu, sub, _, _ in S.fat]
    if S.macho:
        return [(S.macho["cputype"], S.macho["cpusubtype"])]
    return None


def r_archs(S, fmt, m):
    archs = _archs(S)
    if not archs:
        return None
    box = "fat" if S.fat else "macho"
    out = []
    if all(cpu in binfmt.MACHO_CPU for cpu, _ in archs):
        names = [binfmt.MACHO_CPU[cpu] for cpu, _ in archs]
        gnu = [{"x86_64": "x86-64", "arm64": "aarch64"}.get(n, n) for n in names]
        out += _list("lipo_names", names) + (_list("gnu_names", gnu) if gnu != names else [])
    out += _list("cputypes", [cpu for cpu, _ in archs])
    if answer_kinds.kind_of(fmt) not in ("json",) and out and isinstance(out[0][1], list) and len(out[0][1]) >= 1 \
            and all(cpu in binfmt.MACHO_CPU for cpu, _ in archs):
        # A text question: the names as lipo prints them, then joined with commas.
        names = [binfmt.MACHO_CPU[cpu] for cpu, _ in archs]
        out = [("lipo_text", " ".join(names)), ("comma_text", ",".join(names))] + out
    return box, out


def r_arch_count(S, fmt, m):
    if S.fat:
        return "fat", [("nfat_arch", str(len(S.fat)))]
    if S.macho:
        return "macho", [("thin", "1")]
    return None


def r_is_fat(S, fmt, m):
    if S.fat:
        return "fat", _bool("fat_magic", True, fmt)
    if S.macho:
        return "macho", _bool("fat_magic", False, fmt)
    return None


def r_encrypted(S, fmt, m):
    mo = _thin(S)
    if not mo or mo["cryptid"] is None:
        return None
    if m.group(0) == "cryptid":
        return "macho", _num("cryptid", mo["cryptid"])[:1]
    return "macho", _bool("cryptid", mo["cryptid"] != 0, fmt)


def r_source_version(S, fmt, m):
    mo = _thin(S)
    return ("macho", _text("lc_source_version", mo["source_version"])) if mo and mo["source_version"] else None


# ---- WebAssembly, DEX, archives

def _wasm_count(field, method):
    def rule(S, fmt, m):
        if not S.wasm:
            return None
        value = S.wasm[field]
        if isinstance(value, list):
            value = len(value)
        return ("wasm", _num(method, value)[:1]) if value is not None else None
    return rule


def r_wasm_exports(S, fmt, m):
    if not (S.wasm and S.wasm["exports"] is not None):
        return None
    funcs = [n for n, k in S.wasm["exports"] if k == "func"]
    every = [n for n, _ in S.wasm["exports"]]
    if "function" in m.group(0):
        return "wasm", _list("exported_functions", funcs)
    return "wasm", _list("export_names", every) + (_list("exported_functions", funcs) if funcs != every else [])


def r_wasm_custom(S, fmt, m):
    return ("wasm", _list("custom_section_names", S.wasm["custom"])) if S.wasm else None


def r_wasm_producers(S, fmt, m):
    prod = S.wasm["producers"] if S.wasm else None
    if not prod:
        return None
    word = m.group(0)
    field = "language" if "language" in word else ("sdk" if "sdk" in word else "processed-by")
    values = prod.get(field)
    if not values:
        return None
    name, version = values[0]
    out = [("first_name", name)]
    if version:
        out += [("first_name_version", f"{name} {version}"), ("first_version", version)]
    return "wasm", out


def r_wasm_start(S, fmt, m):
    if not S.wasm:
        return None
    if m.group(0).startswith("has_"):
        return "wasm", _bool("start_section", S.wasm["start"] is not None, fmt)
    return ("wasm", _num("start_section", S.wasm["start"])[:1]) if S.wasm["start"] is not None else None


def _dex_num(field, hex_first=False, width=0):
    def rule(S, fmt, m):
        return ("dex", _num(field, S.dex[field], hex_first, width)) if S.dex else None
    return rule


def r_dex_signature(S, fmt, m):
    return ("dex", [("sha1_hex", S.dex["signature"])]) if S.dex else None


def r_class_count(S, fmt, m):
    if S.dex:
        return "dex", _num("class_defs_size", S.dex["classes"])[:1]
    if S.zip:
        return "zip", [("class_entries", str(sum(1 for n in S.zip["names"] if n.endswith(".class"))))]
    return None


def r_compression(S, fmt, m):
    """The reader Day 8 judged (key binary.compression_methods/zip, method `int` accepted)."""
    if not S.zip:
        return None
    import zip_methods_owner
    methods = zip_methods_owner.methods(S.data)
    if not methods or any(x not in zip_methods_owner.NAMES for x in methods):
        return None
    if sorted(methods) != methods:
        # First appearance and ascending order differ: Day 8's archives do not say which the judge
        # means, so this is a key of its own (zip_methods_owner.py), never the accepted reading.
        return "zip+order", [("ascending", sorted(methods)), ("first_appearance", list(methods))]
    return "zip", [("int", list(methods)), ("names", [zip_methods_owner.NAMES[x] for x in methods]),
                   ("names_ed", [zip_methods_owner.NAMES_ED[x] for x in methods])]


def r_entry_count(S, fmt, m):
    if not S.zip:
        return None
    files, entries = len(S.zip["names"]), S.zip["entries"]
    return "zip", [("files", str(files))] + ([("entries_with_directories", str(entries))] if entries != files else [])


def r_entry_names(S, fmt, m):
    return ("zip", _list("central_directory_files", S.zip["names"])) if S.zip else None


def r_has_manifest(S, fmt, m):
    return ("zip", _bool("manifest_entry", "META-INF/MANIFEST.MF" in S.zip["names"], fmt)) if S.zip else None


def r_dex_count(S, fmt, m):
    if not S.zip:
        return None
    return "zip", [("classes_dex_entries", str(sum(1 for n in S.zip["names"] if re.fullmatch(r"classes\d*\.dex", n))))]


def r_abis(S, fmt, m):
    if not S.zip:
        return None
    abis = []
    for n in S.zip["names"]:
        got = re.fullmatch(r"lib/([^/]+)/[^/]+\.so", n)
        if got and got.group(1) not in abis:
            abis.append(got.group(1))
    if not abis:
        return None
    return "zip", _list("lib_dirs", abis) + (_list("lib_dirs_sorted", sorted(abis)) if sorted(abis) != abis else [])


# Packers and protectors, each by a mark it leaves where the loader or a reader can see it: a section
# name (read from the PE section table, exact), a signature string, a library an APK ships. Nothing is
# unpacked. One packer is a fact (unsure under binary.packer/<container>: lower case first, then as the
# tool writes its own name); two of them in one sample are two candidates, and the answer is None.
PACKERS = (
    ("upx", "UPX", (b"UPX0", b"UPX1"), (b"UPX!", b"$Info: This file is packed with the UPX executable packer")),
    ("mpress", "MPRESS", (b".MPRESS1", b".MPRESS2"), ()),
    ("aspack", "ASPack", (b".aspack", b".adata"), (b"ASPack",)),
    ("pecompact", "PECompact", (b"PEC2", b"PECompact2"), (b"PECompact2",)),
    ("petite", "Petite", (b".petite",), ()),
    ("fsg", "FSG", (), (b"FSG!",)),
    ("nspack", "NsPack", (b".nsp0", b".nsp1", b"nsp0", b"nsp1"), ()),
    ("themida", "Themida", (b".themida",), (b"Themida",)),
    ("winlicense", "WinLicense", (b".winlice",), (b"WinLicense",)),
    ("vmprotect", "VMProtect", (b".vmp0", b".vmp1", b".vmp2"), (b"VMProtect",)),
    ("enigma", "Enigma", (b".enigma1", b".enigma2"), (b"Enigma protector",)),
    ("obsidium", "Obsidium", (), (b"Obsidium",)),
    ("kkrunchy", "kkrunchy", (b"kkrunchy",), ()),
    ("upack", "Upack", (b".Upack",), ()),
    ("pklite", "PKLITE", (), (b"PKLITE Copr.",)),
    ("confuserex", "ConfuserEx", (), (b"ConfusedByAttribute", b"ConfuserEx v")),
    ("dotfuscator", "Dotfuscator", (), (b"DotfuscatorAttribute",)),
    ("smartassembly", "SmartAssembly", (), (b"SmartAssembly.Attributes", b"Powered by SmartAssembly")),
    ("pyarmor", "PyArmor", (), (b"__pyarmor__", b"pyarmor_runtime")),
)
# A protector's native library inside an APK (the entry's file name).
APK_PACKERS = (("jiagu", "libjiagu.so"), ("bangcle", "libsecexe.so"), ("secneo", "libDexHelper.so"),
               ("tencent_legu", "libshella"), ("baidu", "libbaiduprotect.so"), ("ijiami", "libexec.so"))


def packers_of(S) -> list:
    """[(name, as the tool writes it, how it was seen)] of every packer of PACKERS whose mark the sample
    carries. A section-name mark counts only as a name in the PE section table (or, for another container,
    as bytes); a signature string counts anywhere."""
    def make():
        if len(S.data) > SEARCH_MAX:
            return None
        names = {sec["name"].encode("latin-1", "replace") for sec in S.pe["sections"]} if S.pe else set()
        found = []
        for name, written, sections, strings in PACKERS:
            if S.pe and any(sec in names for sec in sections):
                found.append((name, written, "section_name"))
            elif any(mark in S.data for mark in strings) or (not S.pe and any(sec in S.data for sec in sections
                                                                               if len(sec) >= 5)):
                found.append((name, written, "signature"))
        if S.zip:
            for name, lib in APK_PACKERS:
                if any(n.rsplit("/", 1)[-1].startswith(lib) for n in S.zip["names"]):
                    found.append((name, name, "native_library"))
        return found
    return S._once("packers", make) or []


def r_packer(S, fmt, m):
    found = packers_of(S)
    if len(found) != 1:
        return None                    # none seen is not proof of none; two are two candidates
    name, written, how = found[0]
    return S.kind, [(how, name)] + ([(how + ":written", written)] if written != name else [])


def r_is_packed(S, fmt, m):
    """true when a packer's own mark is seen; a sample without one is not shown to be unpacked (None)."""
    return (S.kind, _bool("packer_mark", True, fmt)) if packers_of(S) else None


# ---- the language a sample was built from, where its runtime says so and only one does
LANGUAGE_MARKS = (
    ("go", ("go", "golang"), "has_go_buildinfo"),
    ("rust", ("rust",), "has_rust_panic"),
    ("swift", ("swift",), "has_swift_metadata"),
    ("kotlin", ("kotlin", "kotlin_native"), "has_kotlin_native"),
    ("nim", ("nim",), "has_nim_main"),
    ("zig", ("zig",), "has_zig_runtime"),
    ("crystal", ("crystal",), "has_crystal_main"),
    ("d", ("d", "dlang"), "has_d_runtime"),
    ("haskell", ("haskell", "ghc"), "has_ghc_rts"),
    ("ocaml", ("ocaml",), "has_ocaml_runtime"),
    ("pascal", ("pascal", "free_pascal", "fpc"), "has_free_pascal"),
    ("delphi", ("delphi", "pascal", "object_pascal"), "has_delphi"),
    ("dart", ("dart",), "has_dart_snapshot"),
    ("v", ("v", "vlang"), "has_vlang"),
    ("odin", ("odin",), "has_odin"),
    # Row 360 and the Day 19 look-ahead, B2: the GCC front ends and the runtimes no rule read (Day 17 was Ada,
    # Day 18 Fortran, Day 14 Objective-C; COBOL and SBCL are the offline image's next ones; OCaml and Haskell
    # are above). Their marks are in LANGUAGE_ONLY_MARKS: no has_* field is read from them.
    ("fortran", ("fortran",), "lang_fortran"),
    ("ada", ("ada",), "lang_ada"),
    ("objective_c", ("objective_c", "objective-c", "objc"), "lang_objc"),
    ("cobol", ("cobol",), "lang_cobol"),
    ("common_lisp", ("common_lisp", "lisp", "sbcl"), "lang_sbcl"),
)
# A runtime library's own names, each written as the dynamic linker or the runtime itself spells it (a NUL
# after a symbol name): the language marks of the B2 runtimes, read for `language` and `runtime` only.
LANGUAGE_ONLY_MARKS = {
    "lang_fortran": (b"libgfortran.so", b"_gfortran_"),
    "lang_ada": (b"__gnat_", b"GNAT Version: "),
    "lang_objc": (b"libobjc.so", b"objc_msg_lookup\x00", b"objc_msgSend\x00"),
    "lang_cobol": (b"libcob.so", b"cob_init\x00"),
    "lang_sbcl": (b"sbcl_runtime", b"SB-IMPL"),
}
# Runtimes that are built WITH another language's runtime inside, whose mark therefore says nothing against
# them: Swift, Kotlin/Native, Crystal and D binaries carry C++ type info; a Haskell program links C.
_MARKS_BY_SLUG = {slug: marks for _, slug, marks in MARKS}
_MARKS_BY_SLUG.update(LANGUAGE_ONLY_MARKS)


def r_language(S, fmt, m):
    """The source language, when exactly one runtime of LANGUAGE_MARKS left its mark (two are two
    candidates: a Go program that embeds a Rust library, a polyglot build). A sample with none of them is
    not shown to be C: nothing is answered. A class or a jar is Java bytecode whatever compiled it (Kotlin
    metadata names Kotlin); a CLI assembly is .NET."""
    if S.kind == "class" or (S.zip and any(n.endswith(".class") for n in S.zip["names"])):
        kotlin = S.found("has_kotlin_metadata", _MARKS_BY_SLUG["has_kotlin_metadata"])
        return S.kind, [("kotlin_metadata", "kotlin"), ("class_file", "java")] if kotlin else [("class_file", "java")]
    if S.pe and S.pe["dirs"].get("com_descriptor", (0, 0))[0]:
        return "pe", [("cli_header", "dotnet"), ("cli_header:csharp", "csharp"), ("cli_header:net", ".net")]
    seen = _runtime_marks(S)
    if not seen and S.kind == "elf":
        c = _c_language(S)
        return ("elf", c) if c else None
    if _go_not_d(S, seen):
        return S.kind, [("go_buildinfo", "go"), ("go_buildinfo:golang", "golang")]
    if len(seen) != 1:
        return None
    name, spellings = seen[0]
    return S.kind, [("runtime_mark" if i == 0 else f"runtime_mark:{s}", s) for i, s in enumerate(spellings)]


def _runtime_marks(S) -> list:
    """[(name, spellings)] of every runtime of LANGUAGE_MARKS that left its mark in the sample."""
    return S._once("runtime_marks", lambda: [(name, spellings) for name, spellings, slug in LANGUAGE_MARKS
                                             if S.found(slug, _MARKS_BY_SLUG[slug])]) or []


D_ENTRY = (b"_Dmain", b"_d_run_main")     # the D program's main and druntime's entry: every D program links them


def _go_not_d(S, seen) -> bool:
    """The Day 20 build (item 4 of the Day 19 look-ahead's leftovers): every Go build of the look-ahead (go_raw,
    x_go_strip, b_go_arm64) shows TWO runtime marks, Go's build info and D's `druntime`, so `language` was None.
    The `druntime` there is no D runtime: Go packs its runtime messages back to back (`netpoll failedruntime:
    ...`). Go is answered only where exactly those two marks stand, Go's `\\xff Go buildinf:` header (its linker's
    own record, kept by -s -w) is in the file, and neither of D's entry points (`_Dmain`, `_d_run_main`) is: a D
    program, or a Go program with a D library linked in, keeps the old None. Under its own option name,
    `go_buildinfo`, so a name the judge accepts for one runtime mark (`runtime_mark`) never answers this plain."""
    if sorted(name for name, _ in seen) != ["d", "go"]:
        return False
    return S.found("go_buildinfo_header", (facts.GO_BUILDINFO,)) and not S.found("d_entry", D_ENTRY)


def _one_runtime_mark(S):
    """(name, spellings) of the ONE runtime of LANGUAGE_MARKS that left its mark in the sample, or None
    (none, or two: two candidates)."""
    seen = _runtime_marks(S)
    return seen[0] if len(seen) == 1 else None


# The files a C toolchain links in of its own: their STT_FILE names say nothing of the program's language.
CRT_FILES = re.compile(r"crt[\w.]*\.o|crtstuff\.c|abi-note\.c|static-reloc\.c|[\w.+-]+\.S")
SOURCE_C = re.compile(r"[\w.+-]+\.c")


def _c_language(S):
    """B2: `c` for an ELF that carries no runtime mark of LANGUAGE_MARKS at all, by one of two pieces of
    evidence, each its own option name: every source file its symbol table names (STT_FILE, the C runtime's
    own files left out) is a `.c` file (`source_file_c`); or, with no STT_FILE name at all, it needs exactly
    libc.so.6 and no C++ name stands in its dynamic symbols (`only_libc`). A file of another language among
    the names (`.asm`, `.cpp`, `.f90`), anything needed beside libc, or no section header table: None."""
    info = S.elf
    if not info or not info.get("sections"):
        return None
    entries = binfmt.elf_symtab_entries(S.data, info) or []
    files = [n for n, kind, _ in entries if kind == 4 and n]
    own = [f for f in files if not CRT_FILES.fullmatch(f.rsplit("/", 1)[-1])]
    if own:
        return [("source_file_c", "c")] if all(SOURCE_C.fullmatch(f.rsplit("/", 1)[-1]) for f in own) else None
    if files:
        return None                     # only the runtime's own files: nothing of the program is named
    if info.get("needed") != ["libc.so.6"]:
        return None
    dyn = binfmt.elf_symbol_names(S.data, info, ".dynsym") if any(x["type"] == 11 for x in info["sections"]) else []
    if dyn is None or any(n.startswith("_Z") for n in dyn if n):
        return None
    return [("only_libc", "c")]


def r_runtime(S, fmt, m):
    """Backlog row 292 (Day 13's prompt: 'Fingerprint the runtime'): `runtime`, `runtime_name` and
    `language_runtime`, from the single-runtime mark `language` uses and under one key,
    binary.runtime/<container>. A mark is a weaker fact than a version string, and the option's name
    says so. No mark or two marks: None. A class, a jar and a CLI assembly are not read here (their
    `language` comes from the container, not from a runtime's mark)."""
    if S.kind == "class" or (S.zip and any(n.endswith(".class") for n in S.zip["names"])):
        return None
    if S.pe and S.pe["dirs"].get("com_descriptor", (0, 0))[0]:
        return None
    one = _one_runtime_mark(S)
    if one is None:
        return None
    name, spellings = one
    return f"=binary.runtime/{S.kind}", [("runtime_mark" if i == 0 else f"runtime_mark:{s}", s)
                                         for i, s in enumerate(spellings)]


# ---- a WebAssembly component (the component-model layer)

def r_component(S, fmt, m):
    c = S.component
    if not c:
        return None
    word = m.group(0)
    if word in ("is_component", "is_wasm_component", "is_component_model"):
        return "wasm+component", _bool("layer", True, fmt)
    if word in ("core_module_count", "module_count", "num_core_modules", "embedded_module_count"):
        return "wasm+component", _num("core_module_sections", c["core_modules"])[:1]
    if word in ("component_version", "wasm_version", "binary_version"):
        return "wasm+component", _num("header_version", c["version"], hex_first=False)
    if word in ("layer", "wasm_layer", "component_layer"):
        return "wasm+component", _num("header_layer", c["layer"])[:1]
    return None


# ---- one function of an ELF, read as d01.py reads it

D01_MAX = 16 << 20        # an ELF larger than this is not handed to d01.py's reader (pyelftools, capstone)


def _has_recover_code(S) -> bool:
    """Whether the ELF has a symbol table and the name the Day 1 questions are about stands in it:
    d01.py falls back to "the sample's own function other than main", which says nothing about a
    sample that was not built from that source."""
    return bool(S.elf and S.elf["sections"] and len(S.data) <= D01_MAX
                and any(s["type"] == 2 for s in S.elf["sections"]) and b"\0recover_code\0" in S.data)


def _d01(S):
    def make():
        if not (S.elf["e_machine"] in (3, 62) and _has_recover_code(S)):
            return None
        import d01
        return d01.analyze(S.data)
    return S._once("d01", make) if S.elf else None


def r_d01(S, fmt, m):
    """disassembly, recover_code, exported_symbol and marker of an ELF that has a `recover_code`
    symbol, read as d01.py reads them (the form judged for the d01 sample: Intel syntax, decimal
    immediates); an AArch64 build's function as capstone prints it. The key names the CPU."""
    got = _d01(S)
    field = "analysis_" + m.group(0)
    if got and got.get(field) not in (None, "none"):
        return {3: "i386", 62: "x86-64"}[S.elf["e_machine"]], [("d01_reader", got[field])]
    if m.group(0) == "disassembly" and S.elf and S.elf["e_machine"] == 183 and _has_recover_code(S):
        return "aarch64", _list("capstone", _arm64_function(S))
    return None


def _arm64_function(S):
    """The designated function of an AArch64 ELF (d01.designated), one string per instruction as
    capstone prints it. None without a symbol table or the function."""
    def make():
        import d01
        from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(io.BytesIO(S.data))
        sym = d01.designated(elf)
        if sym is None or not sym["st_size"]:
            return None
        sec = elf.get_section(sym["st_shndx"])
        start = sym["st_value"] - sec["sh_addr"]
        code = sec.data()[start:start + sym["st_size"]]
        return [f"{i.mnemonic} {i.op_str}".strip() for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, sym["st_value"])]
    return S._once("arm64", make)


# ---- the rows of fields_template.py, on the header readers only

def r_template(S, fmt, m):
    import fields_template
    got = None
    for pattern, fact, key, options in fields_template.RULES:
        if re.search(pattern, "analysis_" + m.group(0)) or re.search(pattern, m.group(0)):
            if S.jvm.get(fact) is None or (S.fat and fact.startswith("macho_")):
                return None        # (facts.py reads a universal file's first image: one image's fact, not the file's)
            got = (key, options(S.jvm[fact]))
            break
    if not got:
        return None
    return ("=" + got[0]), got[1]      # the template's own key, as written there


def r_go(S, fmt, m):
    def make():
        found = {}
        facts._go(S.data, found)
        return found
    found = S._once("go", make) or {}
    word = m.group(0)
    if word in ("go_version", "go_build_version", "goversion"):
        v = found.get("go_version")
        return ("bytes", [("buildinfo", v), ("buildinfo:bare", v[2:])]) if v and v.startswith("go") else None
    settings = found.get("go_settings") or {}
    key = {"goos": "GOOS", "goarch": "GOARCH", "os": "GOOS"}.get(word)
    if key and isinstance(settings, dict) and settings.get(key):
        return "bytes", _text("buildinfo_" + key.lower(), settings[key])
    fact = {"go_module": "go_module", "go_path": "go_path", "module": "go_module", "go_main_path": "go_path"}.get(word)
    return ("bytes", _text("buildinfo", found.get(fact))) if fact and found.get(fact) else None


def r_rustc(S, fmt, m):
    def make():
        found = {}
        facts._rust(S.data, found)
        return found
    found = S._once("rust", make) or {}
    fact = {"rustc_version": "rustc_version", "rust_version": "rustc_version", "rustc_commit": "rustc_commit",
            "rustc_commit_hash": "rustc_commit"}.get(m.group(0))
    return ("bytes", _text("rustc_string", found.get(fact))) if fact and found.get(fact) else None


def r_trace(S, fmt, m):
    import trace_template
    found = S._once("trace", lambda: trace_template.collect([S.data] + [b for _, b in S.members if b is not S.data]))
    got = trace_template.options(m.group(0), found=found or [])
    return ("=" + got[0], got[1]) if got else None


# ---- backlog row 177: where the day's HCFG container stands in the file, as it is stored
#
# Day 9 asked d09_analysis_hcfg_offset of a Nim ELF that keeps its container as base64 text in a
# string literal, and the judge took the file offset of that text's first character (30696 on all
# seven samples; the bare magic at another offset is the word the sample's decoder compares with,
# and no container). The rule is that reading for any prefix and five stored forms. A place counts
# when the text or the bytes that begin there decode to a container whose CRC-32 checks. One place
# in the prefix's files is the sample's container whatever day it names, as generic.choose_config
# reads a lone container; of several, the one whose campaign names the prefix's day
# (BR<day>-<variant>). Without exactly one, or with it in a file that is not the sample, there is
# no answer. A text that continues another run (the container somewhere inside
# a longer base64 or hex text) is a place whose own start is not established: it counts, and answers
# nothing. Not read: any other form (a compressed stream, base32, a number list, an archive entry);
# a second container of the day stored that way is not seen, as generic.member_layers says of its own.
HCFG_CAMPAIGN = re.compile(r"BR(\d{2})-(\d{3})")
# The base's campaign is BR<day>-000; a Time Trial / Mastery variant's is BR<day>-<8 hex> (Day 23: BR14-EFF84CEB).
# r_hcfg_storage names the day only, so it takes either suffix; every other reader keeps the strict form above.
HCFG_CAMPAIGN_ANY = re.compile(r"BR(\d{2})-[0-9A-Za-z]{3,16}")
HCFG_FORMS = (      # (stored form, the text a container begins with there, what a run before it ends with, bytes per character)
    ("base64", re.compile(rb"SENGR[A-Za-z0-9+/_-]{11,87400}"), re.compile(rb"[A-Za-z0-9+/_-]\Z"), 1),
    ("hex", re.compile(rb"48434647(?:[0-9a-f]{16,131100}|[0-9A-F]{16,131100})"), re.compile(rb"[0-9A-Fa-f]\Z"), 1),
    ("utf16", re.compile(rb"S\0E\0N\0G\0R\0(?:[A-Za-z0-9+/_-]\0){11,87400}"), re.compile(rb"[A-Za-z0-9+/_-]\0\Z"), 2),
    # the Day 12 look-ahead, package B4: the base64 text as a UTF-32LE literal (generic.U32_SEED reads its config)
    ("utf32", re.compile(rb"S\0\0\0E\0\0\0N\0\0\0G\0\0\0R\0\0\0(?:[A-Za-z0-9+/_-]\0\0\0){11,87400}"),
     re.compile(rb"[A-Za-z0-9+/_-]\0\0\0\Z"), 4),
)
HCFG_OFFSET_NAMES = {"base64": "b64_file_offset", "raw": "file_offset", "hex": "hex_file_offset",
                     "utf16": "utf16_file_offset", "utf32": "utf32_file_offset",
                     # the Day 13 look-ahead, row 7 (_hcfg_more_places): never judged, never plain
                     "base64_joined": "b64_seed_file_offset", "base64_wrapped": "b64_wrapped_file_offset",
                     "base64_reversed": "b64_reversed_file_offset", "base64x2": "b64x2_file_offset",
                     "base32": "b32_file_offset", "base32hex": "b32hex_file_offset", "zlib": "zlib_file_offset", "gzip": "gzip_file_offset",
                     "xor": "xor_file_offset",
                     # the Day 14 look-ahead, proposal 3 (_hcfg_listed_places): never judged, never plain
                     "hex_list": "hex_list_file_offset", "hex_escapes": "hex_escapes_file_offset",
                     "hex_dollar_list": "hex_dollar_list_file_offset", "decimal_list": "decimal_list_file_offset",
                     "base85": "b85_file_offset", "ascii85": "a85_file_offset", "xz": "xz_file_offset",
                     "bzip2": "bzip2_file_offset", "zstd": "zstd_file_offset", "lz4": "lz4_file_offset",
                     "raw_utf16": "widened_file_offset", "base64_chunks": "b64_chunks_file_offset",
                     "base64_pieces": "b64_pieces_file_offset"}
HCFG_JUDGED_FORMS = ("base64", "raw", "hex", "utf16", "utf32")      # the forms HCFG_FORMS and the raw search read


def _day_of(name: str):
    """The day a file name or a question prefix states (d09--variant-000.elf, d09, day09-x), or None."""
    m = re.match(r"(?:set\d+\.)?d(?:ay)?0*(\d+)(?![0-9a-z])", str(name).rsplit("/", 1)[-1].rsplit(" -> ", 1)[-1], re.I)
    return int(m.group(1)) if m else None


def _hcfg_decoded(form: str, text: bytes):
    """The bytes a stored text decodes to (what cannot be decoded: None)."""
    try:
        if form == "hex":
            return bytes.fromhex(text[:len(text) & ~1].decode())
        text = text[::{"utf16": 2, "utf32": 4}.get(form, 1)].translate(bytes.maketrans(b"-_", b"+/"))
        text = text[:-1] if len(text) % 4 == 1 else text + b"=" * (-len(text) % 4)   # the padding is not in the run
        return base64.b64decode(text, validate=True)
    except (ValueError, UnicodeError):
        return None


def _hcfg_places(S) -> list:
    """The places in the prefix's files where the sample's CRC-valid container begins: (member index
    with the sample as 0, stored form, file offset, the container as hcfg reads it). The form is None
    where a text continues another run. One place: the answer; any other count: none."""
    def mine(c):
        campaign = c["json"].get("campaign")
        named = HCFG_CAMPAIGN.fullmatch(campaign) if isinstance(campaign, str) else None
        return named is not None and int(named.group(1)) == S.day

    places = []
    blobs = [S.data] + [b for _, b in S.members if b is not S.data]
    for i, blob in enumerate(blobs):
        if len(blob) > SEARCH_MAX:
            raise ValueError(f"a file of {len(blob)} bytes is not searched")
        if hcfg.MAGIC in blob:
            places += [(i, "raw", c["offset"], c) for c in hcfg.containers(blob, others=True) if c["crc_ok"]]
        for form, opening, before, width in HCFG_FORMS:
            for m in opening.finditer(blob):
                dec = _hcfg_decoded(form, m.group())
                first = next((c for c in hcfg.containers(dec, others=True) if c["offset"] == 0), None) if dec else None
                if first is not None and first["crc_ok"]:
                    joined = before.search(blob, max(0, m.start() - width), m.start())
                    places.append((i, None if joined else form, m.start(), first))
                    if joined:
                        # (r_hcfg, row 7 of the Day 13 look-ahead: the 8-bit base64 text's own first character)
                        S._cache.setdefault(f"hcfg_joined:{S.day}", {})[(i, m.start())] = form
    beside = 0
    if not places:
        # Row 7 of the Day 13 look-ahead: the forms generic.py reads the config through and the search
        # above does not. Only when it found no place at all, so no sample it reads answers differently.
        for i, blob in enumerate(blobs):
            # (listed=True: proposal 3's forms are looked for only here, where nothing else was found, so a
            # sample whose container stands in a form read above pays nothing for them)
            places += [(i, form, at, c) for form, at, c in _hcfg_more_places(blob, listed=True)]
        beside = sum(_hcfg_hidden_copies(blob, True) for blob in blobs)
    else:
        # The review of 2026-10-12: a second copy in a form the search above does not read (a zlib
        # stream, base32, a text in pieces, a deflated archive entry, a decoy stored so) stood beside
        # the one place unseen, and the judged shapes answered the offset plain as if it were alone.
        # Such a copy is counted (never listed: the place found above is still the one the day's own
        # unsure key offers), so `hcfg_seen` is no longer 1 and neither judged shape holds.
        main = {(i, at) for i, _, at, _ in places}
        for i, blob in enumerate(blobs):
            beside += sum(1 for _, at, _ in _hcfg_more_places(blob) if (i, at) not in main)
            beside += _hcfg_hidden_copies(blob, False)
    # every place, whatever day it names, before the day decides between several
    # (_hcfg_judged_shape; r_hcfg_words: count)
    S._cache[f"hcfg_seen:{S.day}"] = len(places) + beside
    if beside:
        print(f"[catalog] {S.name}: {beside} more CRC-valid HCFG container(s) stand in a form whose place is not read "
              "(pieces, base85, a byte list, a deflated archive entry, or a second stored form): no judged shape",
              file=sys.stderr)
    if len(places) > 1:
        places = [p for p in places if mine(p[3])]
    if len(places) != 1:
        print(f"[catalog] {S.name}: {len(places)} place(s) hold a CRC-valid HCFG container"
              + ("" if S.day is None else f" of day {S.day}")
              + "".join(f" ({form or 'inside a longer text'} at {at} of file {i + 1})" for i, form, at, _ in places[:4])
              + "; its offset, size and length are not answered", file=sys.stderr)
    return places


# ---- the Day 13 look-ahead, row 7 (2026-10-12): where a container stands that is stored another way
#
# generic.py reads the config through more layers than HCFG_FORMS names, and for eight of them the
# offset was None although every other id of the sample was answered: base64 text wrapped over lines,
# written backwards, encoded twice, base32, a zlib or gzip stream, the container under one more XOR
# byte, and base64 text that follows other text without a gap. Each is read here from the place its
# own mark stands at, and counts only when what begins THERE decodes to a container whose CRC-32
# checks. The answer is the file offset of the first byte of the container's own stored text or
# stream, under binary.hcfg_offset/<form>+dNN with one option: never judged, never plain. Two places
# (two forms, or one form twice) answer nothing, as before. Not read: a deflated archive entry, a
# stream with no header, a text in pieces.
HCFG_MORE_MAX = 32 << 20            # a file larger than this is not searched for these forms
HCFG_MORE_HITS = 64                 # places of one mark tried in one file
HCFG_MORE_STREAMS = 1 << 16         # places that look like a zlib or gzip header tried in one file
_B64_LINES = re.compile(rb"[A-Za-z0-9+/_-]+(?:(?:\r\n|\n|\r)[A-Za-z0-9+/_-]+)+")
_B64_BACKWARDS = re.compile(rb"SENGR[A-Za-z0-9+/_-]{11,87400}")
_B64_TWICE = re.compile(rb"U0VOR1[A-Za-z0-9+/]{14,116600}")        # base64 of a text that begins SENGR
_B32_TEXT = re.compile(rb"JBBUMR[A-Z2-7]{14,104900}")               # base32 of bytes that begin HCFG
_B32HEX_TEXT = re.compile(rb"911KCH[0-9A-V]{14,104900}")             # base32hex of bytes that begin HCFG (KB-6, Day 27)
_ZHEADS = re.compile(rb"\x78[\x01\x5e\x9c\xda]|\x1f\x8b\x08")
_XOR_SIG = bytes(a ^ b for a, b in zip(hcfg.MAGIC, hcfg.MAGIC[1:]))


def _crc_first(dec):
    """The container that begins at the first byte of `dec` when its CRC-32 checks, else None."""
    if not dec or dec[:4] != hcfg.MAGIC:
        return None
    first = next((c for c in hcfg.containers(dec, others=True) if c["offset"] == 0), None)
    return first if first is not None and first["crc_ok"] else None


def _hcfg_more_places(blob: bytes, listed: bool = False) -> list:
    """[(stored form, file offset, container)] of the forms above in one file."""
    if len(blob) > HCFG_MORE_MAX:
        return []
    out = []
    # base64 text wrapped over lines (76 or 64 columns, LF or CRLF), from the container's first character
    for n, m in enumerate(HCFG_FORMS[0][1].finditer(blob)):
        if n >= HCFG_MORE_HITS:
            break
        lines = _B64_LINES.match(blob, m.start())
        c = _crc_first(_hcfg_decoded("base64", re.sub(rb"[\r\n]+", b"", lines.group()))) if lines else None
        if c is not None:
            out.append(("base64_wrapped", m.start(), c))
    # base64 text written backwards: it ends with the seed reversed; it begins where the container's
    # last character (or its padding) stands
    at, n = blob.find(b"RGNES"), 0
    while at >= 0 and n < HCFG_MORE_HITS:
        n += 1
        end = at + 5
        run = _B64_BACKWARDS.match(blob[max(0, end - 87500):end][::-1])
        c = _crc_first(_hcfg_decoded("base64", run.group())) if run else None
        if c is not None:
            size = 12 + struct.unpack_from("<H", _hcfg_decoded("base64", run.group()), 6)[0]
            chars, pad = -(-size * 4 // 3), -size % 3
            start = end - chars
            if chars <= len(run.group()) and start >= 0:
                if pad and blob[max(0, start - pad):start] == b"=" * pad:
                    start -= pad
                out.append(("base64_reversed", start, c))
        at = blob.find(b"RGNES", at + 1)
    # base64 of the base64 text
    for n, m in enumerate(_B64_TWICE.finditer(blob)):
        if n >= HCFG_MORE_HITS:
            break
        inner = _hcfg_decoded("base64", m.group())
        text = HCFG_FORMS[0][1].match(inner) if inner else None
        c = _crc_first(_hcfg_decoded("base64", text.group())) if text else None
        if c is not None:
            out.append(("base64x2", m.start(), c))
    # base32
    for n, m in enumerate(_B32_TEXT.finditer(blob)):
        if n >= HCFG_MORE_HITS:
            break
        body, dec = m.group(), None
        for cut in range(8):                # a run that goes on past the container ends inside a group
            part = body[:len(body) - cut]
            try:
                dec = base64.b32decode(part + b"=" * (-len(part) % 8))
                break
            except ValueError:
                continue
        c = _crc_first(dec)
        if c is not None:
            out.append(("base32", m.start(), c))
    # base32hex (RFC 4648 extended-hex alphabet), the same way (the pattern's literal prefix is the pre-check: a regular
    # expression finds it in 33 MB in 6 ms, a `b"911KCH" in blob` takes 16)
    for n, m in enumerate(_B32HEX_TEXT.finditer(blob)):
        if n >= HCFG_MORE_HITS:
            break
        body, dec = m.group(), None
        for cut in range(8):
            part = body[:len(body) - cut]
            try:
                dec = base64.b32hexdecode(part + b"=" * (-len(part) % 8))
                break
            except ValueError:
                continue
        c = _crc_first(dec)
        if c is not None:
            out.append(("base32hex", m.start(), c))
    # a zlib or gzip stream that inflates to the container
    view = memoryview(blob)
    for n, m in enumerate(_ZHEADS.finditer(blob)):
        if n >= HCFG_MORE_STREAMS:
            break
        at = m.start()
        if blob[at] == 0x78 and ((blob[at] << 8) | blob[at + 1]) % 31:
            continue
        try:
            # (512 bytes of input: the code tables of a dynamic block alone can take a hundred)
            head = zlib.decompressobj(47).decompress(view[at:at + 512], 4)
            if head != hcfg.MAGIC:
                continue
            dec = zlib.decompressobj(47).decompress(view[at:at + (1 << 17)], 12 + 0xFFFF)
        except zlib.error:
            continue
        c = _crc_first(dec)
        if c is not None:
            out.append(("zlib" if blob[at] == 0x78 else "gzip", at, c))
    # the whole container under one more XOR byte: a one-byte key keeps the differences of
    # neighbouring bytes, so one search over the difference stream does for all 255 keys
    if len(blob) >= 16:
        size = len(blob)
        diff = (int.from_bytes(blob, "big") ^ int.from_bytes(blob[1:] + b"\0", "big")).to_bytes(size, "big")
        at, n = diff.find(_XOR_SIG), 0
        while at >= 0 and n < HCFG_MORE_HITS:
            n += 1
            k = blob[at] ^ hcfg.MAGIC[0]
            if k and at + 12 <= size:
                head = bytes(b ^ k for b in blob[at:at + 12])
                c = _crc_first(bytes(b ^ k for b in blob[at:at + 12 + struct.unpack_from("<H", head, 6)[0]]))
                if c is not None:
                    out.append(("xor", at, c))
            at = diff.find(_XOR_SIG, at + 1)
    return out + (_hcfg_listed_places(blob) if listed else [])


# ---- the Day 14 look-ahead, proposal 3 (2026-10-13): thirteen more stored forms generic.py reads the config
# through, for which the offset was None with every other id answered. Each is found from a literal mark
# (bytes.find, no pattern is run over the file), counts only when what begins THERE decodes to a container
# whose CRC-32 checks, and is answered under binary.hcfg_offset/<form>+dNN: never judged, never plain.
_NUM_LISTS = (      # (form, literal marks of the magic, one item, what may stand between items, base)
    ("hex_list", (b"0x48,", b"0x48 ,", b"0X48,"), rb"0[xX]([0-9A-Fa-f]{2})", rb"\s*,\s*", 16),
    ("hex_escapes", (b"\\x48\\x43\\x46\\x47",), rb"\\x([0-9A-Fa-f]{2})", rb"", 16),
    ("hex_dollar_list", (b"$48,", b"$48 ,"), rb"\$([0-9A-Fa-f]{2})", rb"\s*,\s*", 16),
    ("decimal_list", (b"72,67,70,71,", b"72, 67, 70, 71,"), rb"([0-9]{1,3})", rb"\s*,\s*", 10),
)
_LISTED = {}


def _listed_patterns() -> dict:
    """The patterns of _hcfg_listed_places, compiled at the first use (the review of 2026-10-13: at import
    they cost every Binary clock process 12 ms, and the search runs only where no other place was found)."""
    if not _LISTED:
        _LISTED.update(
            num={form: (re.compile(rb"(?:" + item.replace(b"(", b"(?:") + sep + rb"){3,131100}" + item.replace(b"(", b"(?:")),
                        re.compile(item)) for form, _, item, sep, _ in _NUM_LISTS},
            b85=re.compile(rb"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{20,164000}"), a85=re.compile(rb"[!-uz]{20,164000}"),
            chunks=re.compile(rb"(?:[A-Za-z0-9+/]{8,}\0)+[A-Za-z0-9+/]*={0,2}"), chars=re.compile(rb"[A-Za-z0-9+/=]+\Z"))
    return _LISTED


def _marks(blob: bytes, mark: bytes):
    at, n = blob.find(mark), 0
    while at >= 0 and n < HCFG_MORE_HITS:
        yield at
        n += 1
        at = blob.find(mark, at + 1)


def _hcfg_listed_places(blob: bytes) -> list:
    out = []
    try:
        import bz2
        import lzma
        pats = _listed_patterns()
        _B64_CHUNKS, _B64_CHARS = pats["chunks"], pats["chars"]
        for form, marks, _, _, base in _NUM_LISTS:
            run_re, item_re = pats["num"][form]
            for at in sorted({a for mark in marks for a in _marks(blob, mark)}):
                if form == "decimal_list" and at and blob[at - 1:at].isdigit():
                    continue
                m = run_re.match(blob, at)
                try:
                    c = _crc_first(bytes(int(x, base) for x in item_re.findall(m.group()))) if m else None
                except ValueError:
                    c = None
                if c is not None:
                    out.append((form, at, c))
        for form, seed, run_re, dec in (("base85", base64.b85encode(hcfg.MAGIC), pats["b85"], base64.b85decode),
                                        ("ascii85", base64.a85encode(hcfg.MAGIC), pats["a85"], base64.a85decode)):
            for at in _marks(blob, seed):
                m = run_re.match(blob, at)
                for cut in range(5 if m else 0):
                    try:
                        c = _crc_first(dec(m.group()[:len(m.group()) - cut]))
                    except ValueError:
                        continue
                    if c is not None:
                        out.append((form, at, c))
                    break
        for form, mark in (("xz", b"\xfd7zXZ\x00"), ("bzip2", b"1AY&SY"), ("zstd", b"\x28\xb5\x2f\xfd"), ("lz4", b"\x04\x22\x4d\x18")):
            for at in _marks(blob, mark):
                at = at - 4 if form == "bzip2" else at
                if at < 0 or (form == "bzip2" and blob[at:at + 3] != b"BZh"):
                    continue
                piece, dec = blob[at:at + (1 << 17)], None
                try:
                    if form == "xz":
                        dec = lzma.LZMADecompressor().decompress(piece, 12 + 0xFFFF)
                    elif form == "bzip2":
                        dec = bz2.BZ2Decompressor().decompress(piece, 12 + 0xFFFF)
                    elif form == "zstd":
                        import zstandard
                        dec = zstandard.ZstdDecompressor().decompressobj().decompress(piece)
                    else:
                        import lz4.frame
                        dec = lz4.frame.LZ4FrameDecompressor().decompress(piece, 12 + 0xFFFF)
                except Exception:
                    continue
                c = _crc_first(dec)
                if c is not None:
                    out.append((form, at, c))
        for at in _marks(blob, b"H\0C\0F\0G\0"):        # the container's bytes each widened to 16 bits
            c = _crc_first(blob[at:at + 2 * (12 + 0xFFFF):2])
            if c is not None:
                out.append(("raw_utf16", at, c))
        for at in _marks(blob, b"SENGR"):
            m = _B64_CHUNKS.match(blob, at)             # C strings of the text, a NUL after each
            if m and m.group().count(b"\0") >= 2:
                c = _crc_first(_hcfg_decoded("base64", m.group().replace(b"\0", b"").rstrip(b"=")))
                if c is not None and _crc_first(_hcfg_decoded("base64", m.group().split(b"\0", 1)[0].rstrip(b"="))) is None:
                    out.append(("base64_chunks", at, c))
            if at and blob[at - 1] >= 16:               # length-prefixed pieces: a length byte before each
                text, pos = b"", at - 1
                while pos < len(blob) and len(text) < 175000:
                    piece = blob[pos + 1:pos + 1 + blob[pos]]
                    if not piece or len(piece) != blob[pos] or not _B64_CHARS.match(piece):
                        break
                    text, pos = text + piece, pos + 1 + blob[pos]
                if len(text) > blob[at - 1]:
                    c = _crc_first(_hcfg_decoded("base64", text.rstrip(b"=")))
                    if c is not None:
                        out.append(("base64_pieces", at, c))
    except Exception as e:
        print(f"[catalog] the listed forms could not be read ({type(e).__name__}: {e})", file=sys.stderr)
    return out


def _generic():
    """solvers/binary/generic.py as the process already holds it (under `generic`, or under the name
    evidence.py loads it by), else loaded by path. Never `import generic`: Script Analysis has one too."""
    path = HERE / "generic.py"
    for name in ("generic", "binary_generic"):
        mod = sys.modules.get(name)
        try:
            if mod is not None and Path(getattr(mod, "__file__", "") or "").resolve() == path:
                return mod
        except (OSError, TypeError, ValueError):
            continue
    import importlib.util
    spec = importlib.util.spec_from_file_location("binary_generic", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["binary_generic"] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop("binary_generic", None)
        raise
    return mod


HIDDEN_ENTRIES, HIDDEN_BYTES = 256, 16 << 20      # compressed archive entries read, and their bytes


def _hcfg_hidden_copies(blob: bytes, alone: bool) -> int:
    """How many CRC-valid containers stand in `blob` in a form that has no place this module reads:
    the pieced forms generic._piece_children joins (length-prefixed pieces, two halves, a `$XX,` list,
    base85) and a compressed entry of a zip the file holds. `alone`: no place was found in the file, so
    the container generic reads through such a form is the sample's own and only a SECOND distinct one
    is counted. A file over HCFG_MORE_MAX is not read (the size rule of the other forms). Any error
    counts nothing: the search states what it read."""
    if len(blob) > HCFG_MORE_MAX:
        return 0
    seen = []

    def note(data, first: bool = False):
        # `first`: only the container the joined bytes BEGIN with. A join that starts at a bare magic
        # word runs on for the length its false header states and can take in the sample's own raw
        # container, which is no second copy.
        if not data or hcfg.MAGIC not in data:
            return
        for c in hcfg.containers(data, others=True):
            ident = (c["key"], c["crc32"], bytes(c["plain"]))
            if c["crc_ok"] and ident not in seen and (c["offset"] == 0 or not first):
                seen.append(ident)

    try:
        gen = _generic()
        for _, data in gen._piece_children(blob):
            note(data, first=True)
        for n, m in enumerate(gen.U16_MAGIC.finditer(blob)):      # the raw bytes as UTF-16LE text
            if n >= HCFG_MORE_HITS:
                break
            note(m.group()[::2], first=True)
    except Exception as e:
        print(f"[catalog] the pieced forms could not be read ({type(e).__name__}: {e})", file=sys.stderr)
    if b"PK\x03\x04" in blob:
        try:
            zf, read = zipfile.ZipFile(io.BytesIO(blob)), 0
            for n, info in enumerate(zf.infolist()):
                if n >= HIDDEN_ENTRIES or read > HIDDEN_BYTES:
                    break
                if info.is_dir() or info.compress_type == zipfile.ZIP_STORED or info.file_size > (4 << 20):
                    continue            # a stored entry's bytes stand in the file and were read there
                data = zf.read(info)
                read += len(data)
                note(data)
                for form, opening, _, _ in HCFG_FORMS:
                    for m in opening.finditer(data):
                        note(_hcfg_decoded(form, m.group()))
        except Exception:
            pass                        # no zip that zipfile reads: nothing of it is counted
    return max(0, len(seen) - 1) if alone else len(seen)


JUDGED_HCFG_DAY = 9                 # the day whose question the key binary.hcfg_offset/base64 was judged on (row 188)
HCFG_B64_TEXT_BYTE = re.compile(rb"[A-Za-z0-9+/=_-]")    # what a base64 text can hold: both alphabets and the padding


def _hcfg_judged_shape(S, fmt, place) -> bool:
    """Whether the one place is the shape the judge has accepted the base64 text's file offset for
    (the Day 12 look-ahead, package B2; the player's yes of 2026-10-11, which reverses row 188 for
    this shape only). Day 9 (a Nim ELF) and Day 11 (a D ELF) both asked hcfg_offset as an integer
    and both took the offset of the text's first character under the name b64_file_offset: 29 saved
    keys, none rejected, on two languages' layouts. Both stored the container the same way, and only
    that way answers under the judged key on another day. ALL of this holds:

      the sample is an ELF (its magic, and a header binfmt reads);
      the question is an integer question (the kind both judged questions had; no kind is not one);
      the place is the only CRC-valid one in the prefix's files, whatever day the others name, it
        is in the sample itself, and its campaign names the asked day (a lone container of another
        day is the sample's, not the day's; the day's beside an older day's is a second place);
      the text is the standard alphabet only (no '-' or '_') and its padding is there, exactly the
        '=' its length needs (one or two: a text that needs none shows no padding, and one without
        it cannot be told from an unpadded url-safe text);
      the padded text is the container and nothing more: it decodes to the 12 header bytes and the
        payload the header's length states, and encodes back to itself (both judged texts did: 508
        characters for 380 bytes);
      no section of the ELF is named for the container (a name that holds "hcfg"), unless it begins
        exactly at the text: the section's start would be a second reading of the offset;
      the byte before the text is no base64 character and no '=' (the text is not joined to a run).

    Anything else keeps the day's own key and its one probe on that day's base."""
    i, form, at, c = place
    if i != 0 or form != "base64" or answer_kinds.kind_of(fmt) != "integer":
        return False
    if S.data[:4] != b"\x7fELF" or not S.elf:
        return False
    campaign = c["json"].get("campaign") if isinstance(c.get("json"), dict) else None
    named = HCFG_CAMPAIGN.fullmatch(campaign) if isinstance(campaign, str) else None
    if S.day is None or named is None or int(named.group(1)) != S.day or S._cache.get(f"hcfg_seen:{S.day}") != 1:
        return False
    run = HCFG_FORMS[0][1].match(S.data, at)        # the text as _hcfg_places read it
    if run is None or b"-" in run.group() or b"_" in run.group():
        return False
    end, pad = run.end(), -len(run.group()) % 4
    if pad not in (1, 2) or S.data[end:end + pad] != b"=" * pad or S.data[end + pad:end + pad + 1] == b"=":
        return False
    # The literal is the container's text and nothing more (the B2 review): the padded text decodes
    # to the header and exactly the payload its length field states, and the standard encoding of
    # those bytes is the text as it stands. A run that goes on past the container (other text, or a
    # second container behind one that needs no padding, which the search above never sees as a
    # place) is a longer literal than the judge was asked about, however its end is padded.
    text = S.data[at:end + pad]
    try:
        whole = base64.b64decode(text, validate=True)
    except ValueError:
        return False
    if len(whole) < 12 or len(whole) != 12 + struct.unpack_from("<H", whole, 6)[0] or base64.b64encode(whole) != text:
        return False
    # A section named for the container begins at the text, or there is none (the B2 review): neither
    # judged ELF has one (both keep the text in .rodata), and where one begins anywhere else "the hcfg
    # offset" has two readings, the section's start and the text's. Which one the judge means is for
    # that day's probe to say.
    for sec in S.elf.get("sections") or ():
        if "hcfg" in str(sec.get("name") or "").lower() and sec.get("offset") != at:
            return False
    # The Day 14 look-ahead, proposal 8 (the narrowing): the text lies in the file bytes of a PT_LOAD
    # segment, as the raw shape asks. Every judged text does (.rodata of d09, d11 and d13); a text after
    # the end of the image is a layout the judge has not seen.
    if not any(g.get("type") == 1 and g["offset"] <= at < g["offset"] + g["filesz"]
               for g in S.elf.get("segments") or ()):
        return False
    return at > 0 and not HCFG_B64_TEXT_BYTE.match(S.data, at - 1)


OWN_KEY_FORMS = {12: "raw"}       # the day whose own raw hcfg_offset key was judged (in one shape, on an ELF)
JUDGED_RAW_HCFG_DAY = 12            # the day whose question the key binary.hcfg_offset/raw+d12 was judged on (row 267)


def _hcfg_judged_raw_shape(S, fmt, place) -> bool:
    """Whether the one place is the shape the judge has accepted the raw container's file offset for
    (backlog row 267; the player's yes of 2026-10-12, "Yes, plain"). Day 12 (a Free Pascal ELF) asked
    hcfg_offset as an integer and took the offset of the magic's first byte under the name
    file_offset, key binary.hcfg_offset/raw+d12: judged once, on one layout. Only that shape answers
    under that key on another day, and the key is the judged one as it stands (+d12): it is plain
    where the runtime ledger or the seed holds its accepted row, and unsure with its one option
    where neither does, so a tree without the row probes once as before. ALL of this holds:

      the sample is an ELF (its magic, and a header binfmt reads);
      the question is an integer question (no kind is not one);
      the place is the only CRC-valid one in the prefix's files, in any stored form and whatever day
        the others name (a second raw copy, or an encoded copy beside it, is a second place), it is
        in the sample itself, and its campaign names the asked day; its 12 header bytes stand once
        in the sample (an identical second copy is listed as one place, and is still a second copy);
      it is stored raw in the lane's layout: the magic at the offset, the 12 header bytes, then
        exactly the payload the header's length states, inside the file, single-byte XOR, its CRC-32
        the header's (a payload read another way is not the judged container);
      no section of the ELF is named for the container (a name that holds "hcfg"), unless it begins
        exactly at the magic: the section's start would be a second reading of the offset;
      the offset lies in the file bytes of a PT_LOAD segment (the review of 2026-10-12: all
        five real raw layouts do, d02, d04, d05, d10 and d12; an overlay does not, and an ELF with no
        program headers is not the judged shape);
      the sample holds no archive signature (a zip's local header, an ar's magic, a tar's ustar): a
        container inside a stored member has a second reading, its offset in the member.

    A PE build, any other form and any other count keep the day's own key and its one probe."""
    i, form, at, c = place
    if i != 0 or form != "raw" or answer_kinds.kind_of(fmt) != "integer":
        return False
    if S.data[:4] != b"\x7fELF" or not S.elf:
        return False
    campaign = c["json"].get("campaign") if isinstance(c.get("json"), dict) else None
    named = HCFG_CAMPAIGN.fullmatch(campaign) if isinstance(campaign, str) else None
    if S.day is None or named is None or int(named.group(1)) != S.day or S._cache.get(f"hcfg_seen:{S.day}") != 1:
        return False
    if c.get("version") is None or c.get("how", "xor") != "xor" or not c.get("crc_ok") or c.get("offset") != at:
        return False
    plain = c.get("plain")
    if not isinstance(plain, (bytes, bytearray)) or at < 0 or at + 12 + len(plain) > len(S.data):
        return False
    # hcfg.containers lists two identical copies once, at the first (_hcfg_one): the header standing
    # a second time in the sample is a second raw copy, and which one a question means is not judged.
    if S.data[at:at + 4] != hcfg.MAGIC or S.data.count(S.data[at:at + 12]) != 1:
        return False
    length, crc = struct.unpack_from("<HI", S.data, at + 6)
    key = S.data[at + 5]
    stored = S.data[at + 12:at + 12 + length]
    if length != len(plain) or len(stored) != length or bytes(b ^ key for b in stored) != bytes(plain):
        return False
    if zlib.crc32(bytes(plain)) & 0xFFFFFFFF != crc:
        return False
    for sec in S.elf.get("sections") or ():
        if "hcfg" in str(sec.get("name") or "").lower() and sec.get("offset") != at:
            return False
    if not any(g.get("type") == 1 and g["offset"] <= at < g["offset"] + g["filesz"]
               for g in S.elf.get("segments") or ()):
        return False
    return not _archive_marks(S.data)


TAR_MAGIC = re.compile(rb"ustar(?:\x0000|  \x00)")


def _archive_marks(data: bytes) -> bool:
    """Whether a file holds the signature of an archive whose members stand in it as they are: a zip
    local header, an ar magic, or a tar header's magic (POSIX `ustar\\0` + `00`, or GNU `ustar  \\0`)."""
    return b"PK\x03\x04" in data or b"!<arch>\n" in data or bool(TAR_MAGIC.search(data))


def _va_option(S, at: int) -> list:
    """W37 of the Day 19 look-ahead (built for Day 20): an hcfg_offset asked as another kind than an integer (a hex
    pattern) may mean the record's virtual address, not its file offset (d18: 0x2140 in the file, 0x402140 loaded).
    The address of _hcfg_address is offered LAST, as `virtual_address_hex`, under the same unsure key: the judged
    meaning of the id (file_offset) stays first. Nothing where no one segment or section maps the record, or where the
    address equals the offset (a PIE's first segment): one value is not two hypotheses."""
    got = _hcfg_address(S)
    hx = [v for name, v in (got[1] if got else []) if name.endswith(":hex") and v]
    if not hx or hx[0] == f"0x{at:x}":
        return []
    return [("virtual_address_hex", hx[0])]


def r_hcfg(S, fmt, m):
    places = S.hcfg_places
    if not places or len(places) != 1 or places[0][0] != 0:
        return None
    _, form, at, c = places[0]
    bare = m.group(0)
    if form is None:
        # A text that follows other text without a gap: its container's size and place in a longer
        # literal are not this rule's to state. The one thing established is where the container's
        # own base64 text begins (it decodes from there, behind the CRC-32): row 7 of the Day 13
        # look-ahead offers that offset under a key of its own, for the 8-bit text only.
        if bare != "hcfg_offset" or (S._cache.get(f"hcfg_joined:{S.day}") or {}).get((0, at)) != "base64":
            return None
        form = "base64_joined"
    if bare == "hcfg_offset":
        name, kind = HCFG_OFFSET_NAMES[form], answer_kinds.kind_of(fmt)
        # Row 496 (never-wrong): a second CRC-valid copy of the container stands beside the one place
        # (_hcfg_places counted it, so hcfg_seen > 1 while a single place is answered). The offset is
        # then ambiguous and never plain, even under a key later days promoted into the seed: "?=" forces
        # the answer unsure (see answer()/_unsure_only). The judged shapes already require hcfg_seen == 1.
        seen = S._cache.get(f"hcfg_seen:{S.day}")
        copies = isinstance(seen, int) and seen > 1
        if form not in HCFG_JUDGED_FORMS:
            # Row 7 of the Day 13 look-ahead: a form no day has judged, always under the day's own key.
            day = f"+d{S.day:02d}" if S.day else "+day"
            if kind in ("", "integer"):
                more = [(name + "_length_byte", str(at - 1))] if form == "base64_pieces" else []
                return f"==binary.hcfg_offset/{form}{day}", [(name, str(at))] + more
            return f"==binary.hcfg_offset/{form}{day}+{kind}", [(name, str(at)), (name + "_hex", f"0x{at:x}")] + _va_option(S, at)
        if kind in ("", "integer"):
            # The key Day 9 judged, as it was judged (an integer question): no kind suffix. On Day 9's
            # own prefix as before; on another day only in the judged shape (_hcfg_judged_shape,
            # package B2). Any other shape of another day goes under a key of its own and is probed
            # once on that day's base (row 188).
            # Row 267: the raw form was judged on Day 12 under binary.hcfg_offset/raw+d12, and the
            # judged raw shape of another day answers under that key (_hcfg_judged_raw_shape).
            judged = S.day == JUDGED_HCFG_DAY or _hcfg_judged_shape(S, fmt, places[0])
            day = "" if judged else f"+d{S.day:02d}" if S.day else "+day"
            if not judged and _hcfg_judged_raw_shape(S, fmt, places[0]):
                day = f"+d{JUDGED_RAW_HCFG_DAY:02d}"
            # Row 496 (never-wrong): a plain offset is only a byte-proven SINGLE-copy value. When a
            # second CRC-valid copy stands beside the one place (copies = hcfg_seen > 1) the offset is
            # ambiguous, so the answer must stay UNSURE even under a key later days promoted into the
            # seed (base64+d13); "?=" forces that (see answer()/_unsure_only). The judged day's own
            # container is never demoted (judged, e.g. Day 9 base64): its other, older-day place is
            # removed by the `mine` filter and the day's own offset is the judged, accepted one. A
            # single copy in a judged or seeded layout also keeps "==" (labels.pick, plain where the key
            # has an accepted name): both judged shapes require hcfg_seen == 1, and a non-judged single
            # copy the judge already answered (Day 23's d08/d11/d13/d14/d17/d18 own keys) stays plain.
            own = "?=" if (copies and not judged) else "=="
            # The Day 14 look-ahead (the variants sweep of 2026-10-13): on a day whose own question the
            # judge answered raw (d12) the key was judged in one shape too. An ELF of that day with the
            # container anywhere else (after the image, in an appended zip, beside a second copy) is
            # not that shape: it answers under a key of its own, unsure. Every saved d12 sample is in
            # the shape, so no saved answer moves. A PE build keeps the day's key, as row 267 left it
            # (the ladder would have to probe it inside a window), and so do Day 9's and Day 11's
            # base64 texts, which the tests of rows 188 and 215 pin on their own prefixes.
            shaped = {"raw": _hcfg_judged_raw_shape}
            if form == "utf16" and at % 2 == 1 and S.data[at - 1] == 0 and S.data[:4] == b"\x7fELF" and _even_section(S, at):
                # proposal 9: big-endian text reads as little-endian text one byte on; both are offered
                return own + "binary.hcfg_offset/" + form + day, [(name, str(at)), ("utf16be_file_offset", str(at - 1))]
            if (OWN_KEY_FORMS.get(S.day) == form and S.data[:4] == b"\x7fELF"
                    and not shaped[form](S, {"kind": "integer"}, places[0])):
                # Row 496 (never-wrong): the raw container is keyed "elsewhere" for any failure of the
                # judged shape, but its file offset is only one of two readings (and so UNSURE) when it
                # genuinely stands elsewhere: a second copy, OUTSIDE the mapped image (no PT_LOAD segment
                # covers it), or an archive signature in the sample (its offset within a stored member).
                # In the mapped image, a single copy whose offset the judge already answered plain
                # (raw_elsewhere+d12 is in the seed; Day 23's in-segment d12) stays plain, as before.
                in_image = any(g.get("type") == 1 and g["offset"] <= at < g["offset"] + g["filesz"]
                               for g in (S.elf.get("segments") or ()))
                elsewhere = copies or not in_image or _archive_marks(S.data)
                return f"{'?=' if elsewhere else '=='}binary.hcfg_offset/{form}_elsewhere+d{S.day:02d}", [(name, str(at))]
            if (form == "raw" and not judged and S.day and S.day not in OWN_KEY_FORMS and S.pe
                    and S.data[:2] == b"MZ"):
                # Day 17 (rows 328 and 340): a PE build's raw container offset is keyed by its container,
                # binary.hcfg_offset/pe+dNN, the key the judge took d10's under (file_offset, Mastery sets 1,
                # 3 and 5). Day 12's own prefix keeps its judged key, as row 267 left it. A second copy
                # makes even that offset ambiguous (row 496): unsure, never plain.
                return f"{'?=' if copies else '=='}binary.hcfg_offset/pe+d{S.day:02d}", [(name, str(at))]
            return own + "binary.hcfg_offset/" + form + day, [(name, str(at))]
        # Asked as another kind of answer: the same offset under that kind's own key, unsure.
        return f"{'?=' if copies else '=='}binary.hcfg_offset/{form}+{kind}", [(name, str(at)), (name + "_hex", f"0x{at:x}")] + _va_option(S, at)
    if c.get("version") is None or c.get("how", "xor") != "xor":
        return None                     # the header's length is the payload's only in the lane's layout
    if bare == "hcfg_payload_length":
        return form, [("header_length_field", str(len(c["plain"])))]
    return form, [("header_and_payload", str(12 + len(c["plain"])))]


# ---- backlog row 196: has_<token>_section, read from the sample's own section table
#
# Day 10 asked d10_analysis_has_hcfg_section (an enum true/false: is there a section named for the
# HCFG config) and the armed catalog had no rule, so the lane STOPped for a live fields_d10.py. This
# rule answers any `has_<token>_section` field from the container's own section table (ELF section
# headers, PE section table, a thin Mach-O's sections), as has_go_pclntab/has_swift_metadata do:
# `true` when a section's name (lowercased, leading dots/underscores stripped) is the token, `false`
# only when the whole table was read and no such name is in it, None when no table can be read (never
# false from a search of the bytes). The method name is `section`; once the judge accepts it for a key
# (binary.has_<token>_section/<container>) every sample answers plain, as the d10 seed does for
# binary.has_hcfg_section/elf.

def _norm_section(name) -> str:
    return str(name or "").lower().rstrip("\x00 ").lstrip("._")


def _section_names(S):
    """(container the key names, [normalized section names]) of the sample's own section table, or
    (None, None) when none of ELF, PE or Mach-O states one that can be read."""
    if S.elf and S.elf.get("sections"):
        return "elf", [_norm_section(s.get("name")) for s in S.elf["sections"]]
    if S.pe is not None and S.pe.get("sections") is not None:
        return "pe", [_norm_section(s.get("name")) for s in S.pe["sections"]]
    if S.macho and not S.fat and S.macho.get("sections") is not None:
        return "macho", [_norm_section(sectname) for _, sectname in S.macho["sections"]]
    return None, None


def r_has_section(S, fmt, m):
    # The section name as field_grammar reads it (B-216: one parser for the lane's ids). The rule's pattern stays
    # has_<x>_section alone: its answers are picks, and the grammar's other spellings of the fact are answered
    # plain by speed_solver when the question fixes the pair, which a pick here would pre-empt.
    fam, token, _ = field_grammar.family(m.group(0))
    if fam != "has_section" or not token:
        return None
    box, names = _section_names(S)
    if names is None:
        return None            # no readable section table: not proof of absence
    # One method for both values (the player's decision of 2026-10-12, after the Day 13 sweep tried a
    # method of its own for `false`): whether the table holds the name is a boolean fact the table
    # itself proves, not a name the author chose, so the method the judge accepted for `true` (the
    # d10 ELF, 15 saved keys) answers `false` plain too. The known risk of row 196's rule.
    return box, _bool("section", token in names, fmt)


# ---- row 211: the HCFG container's placement (the section that holds it) and its magic
#
# Days 9 and 10 each stopped Layer 1 on one new field about the HCFG container (hcfg_offset, then
# has_hcfg_section), each worth ~60 s on the lane's last mark. This rule answers the rest of that
# family from the one CRC-valid container's file offset matched into the sample's own section table:
# hcfg_section_name/offset/size/virtual_address/flags, and the container magic. Every answer is unsure
# (labels.pick), one fact per key under binary.<field>/<container>, so a wrong mapping costs one base
# probe, never a wrong batch. None when the sample has no single CRC-valid container, or no section
# table (Mach-O sections carry no file offset here), or the container is not inside a section.

def _hcfg_section(S):
    """(container, that section's dict) for the section of the sample that holds its one CRC-valid
    HCFG container, or (None, None)."""
    places = S.hcfg_places
    if not places or len(places) != 1 or places[0][0] != 0:
        return None, None
    at = places[0][2]
    # Padding and the config section can share file offsets, so among the sections whose file range
    # holds the container, prefer the one that starts exactly at it (the container sits at the section
    # start in the named-section layout); otherwise the latest-starting (innermost) one.
    if S.elf and S.elf.get("sections"):
        cands = [s for s in S.elf["sections"] if s.get("offset") and s.get("size") and s.get("type") != 8
                 and s["offset"] <= at < s["offset"] + s["size"]]
        if cands:
            exact = [s for s in cands if s["offset"] == at]
            return "elf", (exact[0] if len(exact) == 1 else max(cands, key=lambda s: s["offset"]))
    if S.pe is not None and S.pe.get("sections") is not None:
        cands = [s for s in S.pe["sections"] if s.get("raw") and s.get("rsize") and s["raw"] <= at < s["raw"] + s["rsize"]]
        if cands:
            exact = [s for s in cands if s["raw"] == at]
            return "pe", (exact[0] if len(exact) == 1 else max(cands, key=lambda s: s["raw"]))
    return None, None


def _hcfg_no_section(S):
    """(container, [("no_section", "none")]) when the sample's section table was read, holds a section
    with bytes in the file, and no section's file range holds the one container (an overlay, a
    segment's bytes no section names); else None. Row 5 of the Day 13 look-ahead: `none` only where
    the table itself proves it, and unsure like every name of this family."""
    one = _hcfg_one(S)
    if one is None:
        return None
    at = one[1]
    if S.elf and S.elf.get("sections"):
        spans = [(s["offset"], s["size"]) for s in S.elf["sections"] if s.get("offset") and s.get("size") and s.get("type") != 8]
        box = "elf"
    elif S.pe is not None and S.pe.get("sections"):
        spans = [(s["raw"], s["rsize"]) for s in S.pe["sections"] if s.get("raw") and s.get("rsize")]
        box = "pe"
    else:
        return None
    if not spans or any(start <= at < start + size for start, size in spans):
        return None
    return box, [("no_section", "none")]


def _hcfg_one(S):
    """(stored form, file offset, container) of the sample's one CRC-valid container whose own start
    is established, as r_hcfg takes it. None with no place, several, one in another file of the
    prefix, or one inside a longer text. None too for raw bytes whose 12 header bytes stand a second
    time in the sample: hcfg.containers lists two identical copies once, at the first, and which of
    the two a question means is not established."""
    def make():
        places = S.hcfg_places
        if not places or len(places) != 1 or places[0][0] != 0 or places[0][1] is None:
            return None
        _, form, at, _ = places[0]
        if form == "raw" and S.data.count(S.data[at:at + 12]) != 1:
            return None
        return places[0][1:]
    return S._once(f"hcfg_one:{S.day}", make)


def _hcfg_address(S, rva: bool = False):
    """(container, options) for the address the sample's one container itself is loaded at: its file
    offset through the one PT_LOAD segment (ELF) or the one section (PE) whose file bytes hold it.
    Of a PE that is the image base plus the RVA, or the RVA alone where the name says rva. None when
    no segment or section maps the offset, or two do."""
    one = _hcfg_one(S)
    if one is None:
        return None
    at = one[1]
    if S.elf and S.elf.get("segments"):
        loads = [g for g in S.elf["segments"] if g["type"] == 1 and g["offset"] <= at < g["offset"] + g["filesz"]]
        if len(loads) != 1:
            return None
        return "elf", _num("container_vaddr", loads[0]["vaddr"] + at - loads[0]["offset"], hex_first=True)
    if S.pe is not None and S.pe.get("sections"):
        secs = [s for s in S.pe["sections"]
                if s.get("raw") and s.get("rsize") and s["raw"] <= at < s["raw"] + s["rsize"]]
        if len(secs) != 1 or at - secs[0]["raw"] >= (secs[0].get("vsize") or secs[0]["rsize"]):
            return None           # in the section's file padding: not in the image
        at_rva = secs[0]["va"] + at - secs[0]["raw"]
        if rva:
            return "pe", _num("container_rva", at_rva, hex_first=True)
        return "pe", _num("container_va", S.pe["image_base"] + at_rva, hex_first=True)
    return None


def r_hcfg_place(S, fmt, m):
    word = m.group(0)
    if word in ("hcfg_magic", "config_magic", "hcfg_signature", "container_magic"):
        mg = hcfg.MAGIC
        opts = [("hex", mg.hex())]
        if mg.isascii() and mg.isalpha():
            opts.append(("ascii", mg.decode("latin-1")))
        if answer_kinds.wants_hex(fmt) and _hcfg_one(S):
            opts.append(("hex_0x", "0x" + mg.hex()))        # B1: the form a 0x question asks; its key ends +hex
        return "bytes", opts
    if word in ("hcfg_virtual_address", "hcfg_vaddr", "hcfg_rva", "hcfg_address"):
        # B1: the container's own address. On Day 11's layout the base64 text stands 0x1680 into
        # .rodata, and the section's address (what these four names answered before) is another fact;
        # that one stays under the hcfg_section_* names below.
        return _hcfg_address(S, rva=word == "hcfg_rva")
    if word in ("hcfg_segment", "hcfg_segment_index"):
        # Row 5 of the Day 13 look-ahead: the program header that maps the container's file offset. An
        # ELF segment has no name of its own: its type's name, or its index in the table. `none` only
        # where the table was read and no PT_LOAD holds the offset.
        one = _hcfg_one(S)
        if one is None or not (S.elf and S.elf.get("segments")):
            return None
        segs = S.elf["segments"]
        loads = [n for n, g in enumerate(segs) if g["type"] == 1 and g["offset"] <= one[1] < g["offset"] + g["filesz"]]
        if len(loads) > 1:
            return None
        if word == "hcfg_segment_index":
            return ("elf", [("program_header_index", str(loads[0]))]) if loads else None
        if not loads:
            return "elf", [("no_load_segment", "none")]
        return "elf", [("p_type_name", "PT_LOAD"), ("p_type_short", "LOAD")]
    box, sec = _hcfg_section(S)
    if sec is None:
        if word in ("hcfg_section_name", "config_section_name", "hcfg_section", "section_of_hcfg"):
            return _hcfg_no_section(S)
        return None
    if word in ("hcfg_section_name", "config_section_name", "hcfg_section", "section_of_hcfg"):
        name = sec.get("name")
        return (box, _text("section_name", name)) if name else None
    if word in ("hcfg_section_offset", "hcfg_section_file_offset", "config_section_offset"):
        off = sec.get("offset") if box == "elf" else sec.get("raw")
        return (box, _num("section_file_offset", off)) if off is not None else None
    if word in ("hcfg_section_size", "config_section_size", "hcfg_section_length"):
        size = sec.get("size") if box == "elf" else sec.get("rsize")
        return (box, _num("section_size", size)) if size is not None else None
    if word in ("hcfg_section_virtual_address", "hcfg_section_vaddr", "hcfg_section_rva"):
        va = sec.get("addr") if box == "elf" else sec.get("va")
        return (box, _num("section_vaddr", va, hex_first=True)) if va is not None else None
    if word in ("hcfg_section_flags", "config_section_flags"):
        flags = sec.get("flags")
        return (box, _num("section_flags", flags, hex_first=True)) if flags is not None else None
    return None


# ---- the Day 12 look-ahead (B1): a container fact under a name composed from the id's words
#
# Days 9, 10 and 11 each asked one new thing about the HCFG container under a name of its own, and a
# fixed alias list read about a quarter of the names a next one may take. A name is read here as it
# is composed: an object (hcfg, config, container), the words of one property (HCFG_PROPERTIES) and,
# for a number, the form the name states (_hex, _int, _decimal). The fact is that of the sample's one
# CRC-valid container (_hcfg_one): no container, two places or a text inside a longer one answer
# nothing, and everything of the header (key, CRC-32, version, lengths) only in the lane's layout.
# Every answer is unsure under binary.<name as asked>/<stored form>, one fact per key: a number in the
# one form its name or its question states, both spellings only where neither says. A length is read
# only under a word that names one reading (payload or json: the header's length field; total, or the
# object container: the header and the payload; encoded, text, b64: the stored text, nothing for a
# raw container); config_length and config_size name none and stay None, and the bare hcfg_length
# (generic.py) and hcfg_size (r_hcfg) keep the one option they had. A name another rule reads stays
# that rule's. Under the object config alone a word that may as well be a member of the JSON (key,
# address, count, version, form, header) is not read.
HCFG_OBJECT = r"(?:hcfg|config|container)"
HCFG_NUMBER_FORM = {"hex": "hex", "int": "integer", "integer": "integer", "decimal": "integer", "dec": "integer"}
HCFG_PROPERTIES = (     # (the words after the object, the fact, read under the object config alone)
    (r"(?:file_|start_)?offset", "offset", True),
    (r"(?:file_)?position", "offset", False),
    (r"(?:b64|base64)_offset", "offset:base64", True),
    (r"magic_offset", "offset:raw", True),
    (r"end_offset", "end", True),
    (r"end", "end", False),
    (r"xor_key", "key", True),
    (r"key", "key", False),
    (r"crc(?:32)?|checksum", "crc32", True),
    (r"version", "version", False),
    (r"magic|signature", "magic", False),
    (r"header_(?:size|length)", "header_size", True),
    (r"header(?:_bytes)?", "header", False),
    (r"encoding|stored_form", "encoding", True),
    (r"storage|form", "encoding", False),
    (r"count", "count", False),
    (r"magic_count", "magic_count", True),
    (r"(?:payload|json)_(?:length|size)", "payload", True),
    (r"total_(?:length|size)", "total", True),
    (r"length|size", "container", False),
    (r"(?:encoded|text)_(?:length|size)", "text", True),
    (r"(?:b64|base64)_(?:length|size)", "text:base64", True),
    (r"member_count", "member_count", True),
    (r"keys|members|member_names", "members", True),
    (r"section_index", "section_index", True),
    # Row 5 of the Day 13 look-ahead: where the payload begins, the decoded JSON, the segment.
    (r"(?:payload|data|json|body)_(?:file_)?offset", "payload_offset", True),
    (r"json|json_text|plaintext|plain_text|decoded", "json", True),
    (r"segment(?:_name|_type)?", "=hcfg_segment", True),
    (r"segment_index", "=hcfg_segment_index", True),
    # The placement words r_hcfg_place reads, under the other objects and spellings.
    (r"section(?:_name)?", "=hcfg_section_name", True),
    (r"section_(?:file_)?offset", "=hcfg_section_offset", True),
    (r"section_(?:size|length)", "=hcfg_section_size", True),
    (r"section_(?:virtual_address|vaddr|rva|address)", "=hcfg_section_vaddr", True),
    (r"section_flags", "=hcfg_section_flags", True),
    (r"virtual_address|vaddr", "=hcfg_virtual_address", True),
    (r"address", "=hcfg_virtual_address", False),
    (r"rva", "=hcfg_rva", True),
)
HCFG_WORDS = (rf"(?P<objects>(?:{HCFG_OBJECT}_)+)(?P<words>" + "|".join(p for p, _, _ in HCFG_PROPERTIES)
              + r")(?:_(?P<form>" + "|".join(HCFG_NUMBER_FORM) + r"))?")
# The stored form asked as a yes/no (is_hcfg_base64, has_raw_hcfg, hcfg_is_base64), and has_hcfg_magic.
HCFG_STATE = (rf"(?:is|has)_{HCFG_OBJECT}_(?:b64|base64|raw)|(?:is|has)_(?:b64|base64|raw)_{HCFG_OBJECT}|"
              rf"{HCFG_OBJECT}_is_(?:b64|base64|raw)|has_{HCFG_OBJECT}_magic")
HCFG_FORM_NAMES = {"base64": ("base64", "b64"), "raw": ("raw", "binary"), "hex": ("hex",)}


def _shown(method: str, n, fmt, form, hex_first: bool = False, width: int = 0, both: bool = True) -> list:
    """A number in the one form its name (`form`) or its question states: hexadecimal for a _hex name
    or a 0x question, decimal for an _int or _decimal name or an integer question. Where neither says:
    both spellings, the usual one first, or the decimal alone (`both` False: a length, a count)."""
    if form is None:
        form = "hex" if answer_kinds.wants_hex(fmt) else "integer" if answer_kinds.kind_of(fmt) == "integer" else None
    pair = [o for o in _num(method, n, hex_first, width) if o[1] is not None]
    if form is None:
        return pair if both else [o for o in pair if not o[0].endswith(":hex")]
    return [o for o in pair if o[0].endswith(":hex") == (form == "hex")]


def _hex_bytes(digits: str, fmt) -> list:
    """Some bytes as hex digits: with the 0x prefix alone where the question asks for it, else bare first."""
    if answer_kinds.wants_hex(fmt):
        return [("hex_0x", "0x" + digits)]
    return [("hex", digits), ("hex_0x", "0x" + digits)]


def _hcfg_stored(S, store: str, at: int, c: dict):
    """How many bytes of the file the container takes as it is stored: the 12 header bytes and the
    payload, or of a text form its characters with the padding that follows them. None where the text
    does not end with the container (more text follows, or the padding is neither whole nor absent)."""
    n = 12 + len(c["plain"])
    if store == "raw":
        return n
    if store == "base64":
        run = HCFG_FORMS[0][1].match(S.data, at)
        chars, pad = -(-n * 4 // 3), -n % 3
        if run is None or run.end() - at != chars:
            return None
        tail = S.data[at + chars:at + chars + 3]
        stood = len(tail) - len(tail.lstrip(b"="))
        return chars + pad if stood == pad else chars if not stood else None
    if store == "hex":
        run = HCFG_FORMS[1][1].match(S.data, at)
        return 2 * n if run is not None and run.end() - at == 2 * n else None
    return None


def r_hcfg_words(S, fmt, m):
    bare = m.group(0)
    if any(pattern.fullmatch(bare) for pattern, _, fn in RULES
           if fn not in (r_hcfg_words, r_derived, r_payload_text, r_absent)):     # (the Day 14 rules come after this one)
        return None                 # a name another rule reads (hcfg_offset, hcfg_size, hcfg_magic) stays its alone
    objects, words = set(m.group("objects").rstrip("_").split("_")), m.group("words")
    form = HCFG_NUMBER_FORM.get(m.group("form"))
    fact, loose = next((f, ok) for pattern, f, ok in HCFG_PROPERTIES if re.fullmatch(pattern, words))
    if objects == {"config"} and not loose:
        return None
    if form is not None and fact in ("encoding", "members", "=hcfg_section_name", "json", "=hcfg_segment"):
        return None                 # a text or a list has no number form
    if fact.startswith("="):
        if fact == "=hcfg_virtual_address" or fact == "=hcfg_rva":
            got = _hcfg_address(S, rva=fact == "=hcfg_rva")
        else:
            got = r_hcfg_place(S, fmt, re.fullmatch(r".+", fact[1:]))
        if not got or form is None:
            return got
        return got[0], [o for o in got[1] if o[0].endswith(":hex") == (form == "hex")]
    one = _hcfg_one(S)
    if one is None:
        return None
    store, at, c = one
    want = fact.partition(":")[2]
    if want and want != store:
        return None                 # hcfg_b64_offset of a raw container, hcfg_magic_offset of a text
    fact = fact.partition(":")[0]
    if fact == "offset":
        return store, _shown(HCFG_OFFSET_NAMES[store], at, fmt, form)
    if fact == "magic_count":
        return store, _shown("magic_occurrences", S.data.count(hcfg.MAGIC), fmt, form, both=False)
    if fact == "count":
        if S._cache.get(f"hcfg_seen:{S.day}") != 1:
            return None             # another day's container stands in the files too: two are there
        return store, _shown("crc_valid_containers", 1, fmt, form, both=False)
    if fact == "encoding":              # the form's name is the author's: its spellings, the catalog's own first
        return store, [(name, name) for name in HCFG_FORM_NAMES.get(store, ())]
    if fact == "magic":
        if form == "hex":
            return "bytes", _hex_bytes(hcfg.MAGIC.hex(), fmt)
        return None if form else r_hcfg_place(S, fmt, re.fullmatch(r".+", "hcfg_magic"))
    if fact == "section_index":
        box, sec = _hcfg_section(S)
        if box != "elf":
            return None             # a PE section is numbered from one or from zero: two readings
        return box, _shown("section_index", S.elf["sections"].index(sec), fmt, form, both=False)
    if fact in ("member_count", "members"):
        if not isinstance(c.get("json"), dict):
            return None
        if fact == "members":
            return store, _list("json_member_names", list(c["json"]))
        return store, _shown("json_members", len(c["json"]), fmt, form, both=False)
    if c.get("version") is None or c.get("how", "xor") != "xor":
        return None                 # the header's bytes are the key, the length and the CRC only in the lane's layout
    plain = c["plain"]
    if fact == "payload_offset":
        # the byte after the 12 header bytes: one reading for a raw container only (of a text it is
        # a character inside the text, or nothing at all)
        return (store, _shown("payload_file_offset", at + 12, fmt, form)) if store == "raw" else None
    if fact == "json":
        try:
            text = bytes(plain).decode("utf-8")
        except UnicodeError:
            return None
        return (store, [("decoded_json", text)]) if len(text) <= 4096 and c["crc_ok"] else None
    if fact == "key":
        return store, _shown("header_byte", c["key"], fmt, form, hex_first=True, width=2)
    if fact == "crc32":
        return (store, _shown("header_crc32", c["crc32"], fmt, form, hex_first=True, width=8)) if c["crc_ok"] else None
    if fact == "version":
        v = c["version"]
        return store, [o for o in (("decimal", str(v)), ("hex", f"0x{v:02x}"), ("hex_short", f"0x{v:x}"))
                       if form is None or (form == "hex") == o[0].startswith("hex")]
    if fact == "header_size":
        return store, _shown("header_bytes", 12, fmt, form, both=False)
    if fact == "header":
        if form == "integer" or len(plain) > 0xFFFF:
            return None
        head = hcfg.MAGIC + bytes([c["version"], c["key"]]) + struct.pack("<HI", len(plain), c["crc32"])
        return store, _hex_bytes(head.hex(), fmt)
    if fact == "payload":
        return store, _shown("header_length_field", len(plain), fmt, form, both=False)
    if fact == "total" or (fact == "container" and "container" in objects):
        return store, _shown("header_and_payload", 12 + len(plain), fmt, form, both=False)
    stored = _hcfg_stored(S, store, at, c)
    if stored is None:
        return None
    if fact == "end":
        return store, _shown("end_offset", at + stored, fmt, form)
    if fact == "text" and store != "raw":
        return store, _shown("stored_text_length", stored, fmt, form, both=False)
    return None


def r_hcfg_state(S, fmt, m):
    one = _hcfg_one(S)
    if one is None:
        return None
    store, words = one[0], m.group(0).split("_")
    if "magic" in words:            # the whole file is read: no magic in it is proof
        return store, _bool("magic_bytes", hcfg.MAGIC in S.data, fmt)
    if store not in ("base64", "raw", "hex"):
        return None                 # base64 text as UTF-16: whether that is "base64" is not one reading
    return store, _bool("stored_form", store == ("raw" if "raw" in words else "base64"), fmt)


def r_xor_key(S, fmt, m):
    one = _hcfg_one(S)
    if one is None or one[2].get("version") is None or one[2].get("how", "xor") != "xor":
        return None
    form = HCFG_NUMBER_FORM.get(m.group(1))
    return one[0], _shown("header_byte", one[2]["key"], fmt, form, hex_first=True, width=2)


def container_field(field: str) -> bool:
    """Whether a rule reads `field` as a fact of the HCFG container itself (its place, its header, its
    stored form). generic.py asks it of an analysis_config_* name that is no member of the decoded
    config: only such a name is the catalog's there, never one a template or a table rule reads."""
    bare = _bare(str(field))
    fns = [fn for pattern, _, fn in RULES if pattern.fullmatch(bare)]
    if any(fn in (r_hcfg, r_hcfg_place, r_hcfg_words, r_hcfg_state, r_derived, r_payload_text) for fn in fns):
        return True
    # the Day 14 look-ahead, proposal 5: a config_* name nothing else reads (no rule, no template rule) is asked
    # as a member the config may lack (r_absent)
    return bool(fns) and all(fn is r_absent for fn in fns) and not _template_reads(field)


def _template_reads(field: str) -> bool:
    import fields_template
    return any(re.search(pattern, str(field)) for pattern, _, _, _ in fields_template.RULES)


# ---- B1: the size and the MD5 or SHA-1 of a delivered file (artifact_sha256_<n> is generic.py's)

def r_artifact(S, fmt, m):
    """The file the name numbers, in the order generic.py numbers the prefix's files for
    artifact_sha256_<n>; a name with no number is about the prefix's one file and of several, none."""
    files = S.members or [(S.name, S.data)]
    what, n = m.group(1) or m.group(3), m.group(2)
    if (n is None and len(files) != 1) or (n is not None and not 0 < int(n) <= len(files)):
        return None
    blob = files[int(n or 1) - 1][1]
    if what.startswith("size"):
        return "file", [("byte_length", str(len(blob)))]
    return "file", [(what + "_hex", hashlib.new(what, blob, usedforsecurity=False).hexdigest())]


# ---- row 211: the compiler / toolchain / linker strings (facts.py reads them; this exposes them unsure)

# Row 5 of the Day 13 look-ahead: the version string a toolchain writes into its builds, in the forms
# seen in the saved samples (FPC in d12, rustc and GCC in d05, clang in d10, ldc in d11, Go's build
# info in d04) and the documented ones of the toolchains a next sample may come from. (family, the
# text with its version in group 1). The GNU front ends are one family: their strings state the one
# GCC version. A form not listed here is not read; nothing is inferred from a runtime's marks.
_V = rb"(\d+\.\d+(?:\.\d+)?)"
TOOLCHAIN_STRINGS = (
    ("fpc", re.compile(rb"FPC " + _V + rb" \[\d{4}/\d\d/\d\d\] for [\w-]{1,24} - \w{1,24}")),
    ("gcc", re.compile(rb"GCC: \([^)\x00]{0,80}\) " + _V + rb"[\x20-\x7e]{0,40}")),
    ("gcc", re.compile(rb"GNU (?:C|C\+\+|Fortran|Ada|D|Go|Objective-C|GIMPLE)\w* " + _V + rb"(?= |\x00)")),
    ("gcc", re.compile(rb"GNAT Version: " + _V + rb"[\x20-\x7e]{0,40}")),
    ("clang", re.compile(rb"(?:[A-Za-z]+ )?clang version " + _V + rb"[\x20-\x7e]{0,120}")),
    ("rustc", re.compile(rb"rustc version " + _V + rb"(?:-[a-z]+)? \([0-9a-f]{7,40} \d{4}-\d\d-\d\d\)")),
    ("ghc", re.compile(rb"\bghc-" + _V + rb"(?![\w.])")),
    ("ldc", re.compile(rb"\bldc-" + _V + rb"(?![\w.])")),
    ("ldc", re.compile(rb"LDC - the LLVM D compiler \(" + _V + rb"[^)\x00]{0,24}\)")),
    ("dmd", re.compile(rb"DMD(?:64)? D Compiler v" + _V + rb"[\x20-\x7e]{0,24}")),
    ("zig", re.compile(rb"\bzig " + _V + rb"(?:-dev\.[\w+.]{1,32})?(?=[ \x00])")),
    ("crystal", re.compile(rb"Crystal " + _V + rb" \[[0-9a-f]{6,12}\][\x20-\x7e]{0,24}")),
    ("nim", re.compile(rb"Nim Compiler Version " + _V + rb"[\x20-\x7e]{0,40}")),
    ("ocaml", re.compile(rb"OCaml (?:version|runtime, version) " + _V + rb"(?![\w.])")),
    ("swift", re.compile(rb"Swift version " + _V + rb"[\x20-\x7e]{0,60}")),
)
TOOLCHAIN_LABEL = {"fpc": "FPC", "gcc": "GCC", "clang": "clang", "rustc": "rustc", "ghc": "GHC", "ldc": "LDC",
                   "dmd": "DMD", "zig": "zig", "crystal": "Crystal", "nim": "Nim", "ocaml": "OCaml", "swift": "Swift",
                   "go": "go"}


# B4: the literal every match of each TOOLCHAIN_STRINGS pattern contains, at most 64 bytes after the match's
# start (the clang pattern's optional word before it), in the same order. A large sample is read at these
# places only (needles.windows), the same matches finditer over the whole file gives.
TOOLCHAIN_ANCHORS = ((b"FPC ",), (b"GCC: (",), (b"GNU ",), (b"GNAT Version: ",), (b"clang version ",),
                     (b"rustc version ",), (b"ghc-",), (b"ldc-",), (b"LDC - the LLVM D compiler (",), (b"DMD",),
                     (b"zig ",), (b"Crystal ",), (b"Nim Compiler Version ",), (b"OCaml ",), (b"Swift version ",))
COMPILER_NEEDLES = (b"GCC: (", b"clang version ", b"Linker: ")
_NEEDLES = []


def all_needles() -> tuple:
    """Every literal Sample.hits indexes: the literal marks of MARKS and LANGUAGE_ONLY_MARKS, facts.py's
    toolchain markers and Go build-info magic, the compiler needles and the toolchain anchors."""
    if not _NEEDLES:
        got = []
        for marks in list(_MARKS_BY_SLUG.values()):
            if isinstance(marks, tuple):
                got += [m for m in marks if isinstance(m, bytes)]
        for _, marks in facts.TOOLCHAINS:
            got += list(marks)
        got += [facts.GO_BUILDINFO, *COMPILER_NEEDLES, *(a for anchors in TOOLCHAIN_ANCHORS for a in anchors),
                b"HUNTRESS_"]
        _NEEDLES.append(tuple(dict.fromkeys(m for m in got if m)))
    return _NEEDLES[0]


def _matches(S, pattern, anchors):
    """finditer of `pattern` over the sample, or, for an indexed sample, its matches at the anchors' places."""
    if S.hits is None or not all(a in S.hits for a in anchors):
        return pattern.finditer(S.data)
    return needles.windows(S.data, pattern, [p for a in anchors for p in S.hits[a]])


def _toolchain_strings(S):
    """[(family, version, the text as it stands)] of every recognised toolchain string of the sample,
    each distinct text once; None for a file too large to search."""
    def make():
        if len(S.data) > SEARCH_MAX:
            return None
        out = []
        for (family, pattern), anchors in zip(TOOLCHAIN_STRINGS, TOOLCHAIN_ANCHORS):
            for n, hit in enumerate(_matches(S, pattern, anchors)):
                if n >= 64:
                    break
                row = (family, hit.group(1).decode(), hit.group(0).decode("latin-1").rstrip())
                if row not in out:
                    out.append(row)
        found = {}
        if S.hits is None or S.hits.get(facts.GO_BUILDINFO):
            facts._go(S.data, found)
        v = found.get("go_version")
        if isinstance(v, str) and re.fullmatch(r"go\d+\.\d+(?:\.\d+)?", v):
            out.append(("go", v[2:], v))
        return out
    return S._once("toolchain_strings", make)


def _one_toolchain(S, texts: bool):
    """The sample's one toolchain string as (family, version, text), or None. `texts`: the text itself
    is asked, so two different texts are two candidates even where they state one version; else two
    different (family, version) pairs are. A Rust build carries rustc's string and the GCC that built
    its C objects: two candidates, no answer."""
    rows = _toolchain_strings(S) or []
    if len({(f, v) for f, v, _ in rows}) != 1 or (texts and len({t for _, _, t in rows}) != 1):
        return None
    return rows[0]


_COMPILER_PATTERNS = tuple(re.compile(p) for p in (
    rb"GCC: \([^)\x00]{0,80}\) " + facts.TEXT + rb"{1,60}",
    rb"(?:[A-Za-z]+ )?clang version " + facts.TEXT + rb"{1,120}",
    rb"Linker: " + facts.TEXT + rb"{1,60}"))


def _compiler_facts(S) -> dict:
    """facts._compiler and facts._toolchain of the sample; for an indexed one (Sample.hits) read at the
    places of their needles only, with the same result (B4)."""
    found = {}
    if S.hits is None:
        facts._compiler(S.data, found)
        facts._toolchain(S.data, found)
        return found
    rows = []
    for needle, pattern in zip(COMPILER_NEEDLES, _COMPILER_PATTERNS):
        if S.hits.get(needle):
            rows += [(m.start(), m.group(0)) for m in needles.windows(S.data, pattern, S.hits[needle],
                                                                      limit=1 << 30)]
    names = facts._distinct(text for _, text in sorted(rows))
    if names:
        found["compiler"] = names
    data = S.data
    if data[:4] in facts.EXEC_HEADS or data[:2] == b"MZ" or data[:8] == facts.AR_MAGIC:
        marks = {lang: [mk.decode() for mk in ms if S.hits.get(mk)] for lang, ms in facts.TOOLCHAINS}
        marks = {k: v for k, v in marks.items() if v}
        if marks:
            found["toolchain_markers"] = marks
    return found


# B2: the compiler a runtime library names, for a build that needs it (`compiler` of the Day 18 Fortran sample:
# libgfortran.so.5 in DT_NEEDED; the .comment it would carry was stripped).
RUNTIME_LIBRARY_COMPILER = ((re.compile(r"libgfortran\.so(?:\.\d+)*"), "gfortran", "GNU Fortran"),)


def _library_compiler(S) -> list:
    """[(name, value)] of the one compiler a needed runtime library names, as `runtime_library` options."""
    needed = (S.elf or {}).get("needed") or []
    got = [(short, label) for pattern, short, label in RUNTIME_LIBRARY_COMPILER
           if any(isinstance(n, str) and pattern.fullmatch(n) for n in needed)]
    if len(got) != 1:
        return []
    return [("runtime_library", got[0][0]), ("runtime_library:label", got[0][1])]


def r_compiler(S, fmt, m):
    def make():
        return _compiler_facts(S)
    found = S._once("compiler", make) or {}
    word = m.group(0)
    if word in ("compiler_version", "toolchain_version"):
        one = _one_toolchain(S, texts=False)
        if one is None:
            return None
        return "bytes", [("version", one[1]), ("label_version", f"{TOOLCHAIN_LABEL[one[0]]} {one[1]}")]
    lib = _library_compiler(S) if word in ("compiler", "compiler_name", "producer") else []
    if word in ("compiler", "compiler_name", "compiler_string", "producer"):
        c = found.get("compiler")
        c = c[0] if isinstance(c, list) and c else (c if isinstance(c, str) else None)
        if c:
            return "bytes", _text("comment", c) + lib
    if word in ("compiler", "compiler_name", "compiler_string", "producer", "toolchain", "toolchain_marker",
                "toolchain_string", "runtime_toolchain"):
        t = found.get("toolchain_markers")
        t = t[0] if isinstance(t, list) and t else (t if isinstance(t, str) else None)
        if t and word.startswith(("toolchain", "runtime")):
            return "bytes", _text("runtime_string", t)
        one = _one_toolchain(S, texts=True)     # row 5: the one version string the file itself carries
        if one is None:
            # Row 292: `toolchain` alone falls back to the one runtime mark's label when the file has
            # NO recognised version string at all (two strings are two candidates and stay None).
            # Unsure, and named for what it is. `compiler` and every *_version stay None without one.
            mark = _one_runtime_mark(S) if word == "toolchain" and _toolchain_strings(S) == [] else None
            if mark is None:
                return ("bytes", lib) if lib else None
            label = next((v for v in TOOLCHAIN_LABEL.values() if v.lower() == mark[0]), mark[0])
            return "bytes", [("runtime_mark", mark[0]), ("runtime_mark:label", label)]
        return "bytes", [("version_string", one[2]), ("label_version", f"{TOOLCHAIN_LABEL[one[0]]} {one[1]}")] + lib
    if word in ("linker", "linker_name", "linker_version", "linker_string"):
        c = found.get("compiler")
        items = c if isinstance(c, list) else ([c] if isinstance(c, str) else [])
        lk = next((s for s in items if isinstance(s, str) and re.search(r"ld|lld|link|gold|mold", s, re.I)), None)
        return ("bytes", _text("comment", lk)) if lk else None
    return None


# ---- the Day 19 look-ahead, B3: the dispatch facts of a d18-like sample (Day 18's prompt: "Reconstruct the call
# graph ...": an environment-selected `_gfortran_select_string` dispatch over `event_*` handlers and a jump table;
# nothing asked them). Every one is a labels.pick under binary.<field as asked>/elf, read from the ELF's own
# tables, and None unless exactly one candidate stands. What the judge would call the handlers (with or without
# the `.N` a local symbol carries) is open: both spellings are options, the table's own first.
ENV_READER = re.compile(r"(?:secure_)?getenv|_gfortran_get_environment_variable\w*|GetEnvironmentVariable[AW]?|"
                        r"_wgetenv|__gnat_getenv|caml_sys_getenv|os\.Getenv|syscall\.Getenv")
ENV_TOKEN = re.compile(rb"HUNTRESS_[A-Z0-9_]{2,64}(?![A-Za-z0-9_])")
# A runtime's select or dispatch routine (`_gfortran_select_string`), never libc's select(2) or `__select`.
SELECT_IMPORT = re.compile(r"\w*[A-Za-z0-9]\w*_(?:select|dispatch)(?:_\w+)?|(?:select|dispatch)_\w+")
HANDLER = re.compile(r"(event|handler|handle|on)_[A-Za-z0-9_]+?(\.\d+)?")
JUMP_TABLE = re.compile(r"(?:jump_?table|switch\.table|dispatch_?table)[\w.$]*", re.I)


def _elf_names(S, table: str) -> list:
    """The names of one ELF symbol table (`.symtab` or `.dynsym`), version suffixes (`@GFORTRAN_8`) left out;
    [] without one."""
    def make():
        names = binfmt.elf_symbol_names(S.data, S.elf, table) if S.elf else None
        return [n.split("@", 1)[0] for n in names or () if n]
    return S._once("names:" + table, make) or []


def _symtab_typed(S, kind: int) -> list:
    """The SHT_SYMTAB names of one st_info type (1 object, 2 function), table order, versions left out."""
    def make():
        entries = binfmt.elf_symtab_entries(S.data, S.elf) if S.elf else None
        return [(n.split("@", 1)[0], k) for n, k, _ in entries or () if n]
    return [n for n, k in S._once("symtab_typed", make) or () if k == kind]


def r_dispatch_variable(S, fmt, m):
    """The one HUNTRESS_* environment name the sample holds, when it imports a reader of the environment."""
    if not S.elf or len(S.data) > SEARCH_MAX:
        return None
    dynamic = any(x["type"] == 11 for x in S.elf.get("sections") or ())
    imports = _elf_names(S, ".dynsym") if dynamic else _elf_names(S, ".symtab")   # a static build: its own table
    if not any(ENV_READER.fullmatch(n) for n in imports):
        return None
    if S.hits is not None and not S.hits.get(b"HUNTRESS_"):
        return None
    places = S.hits[b"HUNTRESS_"] if S.hits is not None else [x.start() for x in re.finditer(rb"HUNTRESS_", S.data)]
    tokens = {t.group(0).decode() for p in places for t in [ENV_TOKEN.match(S.data, p)] if t}
    tokens = {t for t in tokens if not t.startswith("HUNTRESS_ANALYSIS")}
    return ("elf", [("env_string", tokens.pop())]) if len(tokens) == 1 else None


def r_dispatch_symbol(S, fmt, m):
    """The one imported routine whose name says it selects or dispatches (`_gfortran_select_string`)."""
    if not S.elf:
        return None
    got = sorted({n for n in _elf_names(S, ".dynsym") if SELECT_IMPORT.fullmatch(n)})
    return ("elf", [("select_import", got[0])]) if len(got) == 1 else None


def _handlers(S):
    """[the FUNC symbols of the one family of handlers (`event_*`, `handler_*`, `on_*`), table order], or None
    (no family of two or more, or two such families)."""
    groups = {}
    for n in _symtab_typed(S, 2):
        h = HANDLER.fullmatch(n)
        if h:
            groups.setdefault(h.group(1), []).append(n)
    groups = {k: v for k, v in groups.items() if len(v) >= 2}
    return next(iter(groups.values())) if len(groups) == 1 else None


def r_handler_symbols(S, fmt, m):
    names = _handlers(S) if S.elf else None
    if not names:
        return None
    bare = [re.sub(r"\.\d+$", "", n) for n in names]
    return "elf", _list("symtab_order", names) + (_list("symtab_order_bare", bare) if bare != names else [])


def r_handler_count(S, fmt, m):
    names = _handlers(S) if S.elf else None
    return ("elf", [("func_symbols", str(len(names)))]) if names else None


def r_jumptable_symbol(S, fmt, m):
    if not S.elf:
        return None
    got = sorted({n for n in _symtab_typed(S, 1) if JUMP_TABLE.fullmatch(n)})
    return ("elf", [("object_symbol", got[0])]) if len(got) == 1 else None


# ---- the Day 20 build (A105 of the Day 19 look-ahead): branch_labels, the case labels of a string select.
#
# gfortran compiles `select case (string)` to a call of _gfortran_select_string over a static table (the OBJECT symbol
# `jumptable.N.M` on Day 18's d18), one 40-byte select_struct per case on a 64-bit target: low, low_len, high,
# high_len (pointers and lengths of the case's bounds), the case's index (int32) and padding; `case default` is the
# entry whose four bounds are 0. d18's table: default, analysis, sandbox, workstation. The labels are read from the
# one such table, in table order (gfortran sorts it; one case is a list of one), as a labels.pick under binary.branch_labels/elf: the strings
# alone first, then with `default` after them where the table has a default entry. None unless the ELF is 64-bit
# little-endian with exactly one jump-table OBJECT symbol whose size is a whole number of entries (2 to 256), every
# entry is either the default (at most one) or one single-string case (low == high, 1 to 64 printable bytes mapped
# by a PT_LOAD segment), the labels are distinct, and the indexes are exactly 0..n-1: a range case (`"a":"c"`), a C
# switch table or anything else is no reading. A PIE build's table holds its pointers as relocations (zeros in the
# file), so it is no reading either.
SELECT_ENTRY = 40
BRANCH_MAX = 256


def _symtab_objects(S) -> list:
    """[(name, st_value, st_size)] of the OBJECT symbols of an ELF64 little-endian SHT_SYMTAB; [] otherwise."""
    def make():
        info = S.elf
        if not info or info.get("bits") != 64 or info.get("ei_data") != 1 or not info.get("sections"):
            return []
        out = []
        for sec in info["sections"]:
            if sec["type"] != 2 or sec["link"] >= len(info["sections"]):
                continue
            strs, count = info["sections"][sec["link"]]["offset"], min(sec["size"] // 24, 1 << 18)
            for k in range(count):
                at = sec["offset"] + k * 24
                if at + 24 > len(S.data):
                    break
                name, st_info, _, _, value, size = struct.unpack_from("<IBBHQQ", S.data, at)
                if st_info & 0xF == 1 and name:
                    end = S.data.find(b"\0", strs + name, strs + name + 4096)
                    if end > 0:
                        out.append((S.data[strs + name:end].decode("latin-1"), value, size))
        return out
    return S._once("symtab_objects", make) or []


def _va_bytes(S, va: int, n: int):
    """The n file bytes a PT_LOAD segment maps at virtual address va, or None."""
    for g in S.elf.get("segments") or ():
        if g["type"] == 1 and g["vaddr"] <= va and va + n <= g["vaddr"] + g["filesz"]:
            at = g["offset"] + va - g["vaddr"]
            return S.data[at:at + n] if at + n <= len(S.data) else None
    return None


def r_branch_labels(S, fmt, m):
    if not S.elf:
        return None
    tables = [(v, z) for name, v, z in _symtab_objects(S) if JUMP_TABLE.fullmatch(name)]
    if len(tables) != 1:
        return None
    va, size = tables[0]
    if not size or size % SELECT_ENTRY or not 2 <= size // SELECT_ENTRY <= BRANCH_MAX:
        return None
    raw = _va_bytes(S, va, size)
    if raw is None:
        return None
    labels, indexes, default = [], [], 0
    for i in range(0, size, SELECT_ENTRY):
        lo, lo_len, hi, hi_len, index = struct.unpack_from("<QqQqi", raw, i)
        indexes.append(index)
        if lo == hi == lo_len == hi_len == 0:
            default += 1
            continue
        if lo != hi or lo_len != hi_len or not 1 <= lo_len <= 64:
            return None
        text = _va_bytes(S, lo, lo_len)
        if text is None or not all(0x20 <= c < 0x7f for c in text):
            return None
        labels.append(text.decode("ascii"))
    if default > 1 or not labels or len(set(labels)) != len(labels) or sorted(indexes) != list(range(len(indexes))):
        return None
    return "elf", _list("select_cases", labels) + (_list("select_cases_default", labels + ["default"]) if default else [])


# ---- backlog row 187: the host model the sample chooses among, by the HUNTRESS_HOST_MODEL marker
#
# The Day 9 Nim build writes HUNTRESS_HOST_MODEL with the branch words (sandbox, decoy, workstation)
# beside it. No day has asked a host_model field yet, so this is inert unless one does; then it offers
# the words that stand by the marker, as written, under binary.host_model/<container>, labels.pick
# (unsure, probed on the base only; run.py never sends an unsure answer inside a window).
HOST_MODEL_MARK = b"HUNTRESS_HOST_MODEL"
HOST_MODEL_WORD = re.compile(rb"[A-Za-z][A-Za-z0-9_]{2,31}")


def r_host_model(S, fmt, m):
    # Row 211 (review S2): the marker is followed by the BRANCH words a sample chooses among
    # (sandbox, decoy, workstation), which are different facts, not spellings of one. Offering them
    # as options of one key would be brute-force probing and, once one is accepted, a carried plain
    # label that is wrong for the next variant. The bytes do not prove which branch a sample is, so
    # the only honest answer is None (the branch words are shown in the triage map for the agent);
    # a single distinct word after the marker (a stated value, not a branch list) is one fact.
    at = S.data.find(HOST_MODEL_MARK)
    if at < 0:
        return None            # inert: the marker is not in the sample
    window = S.data[at + len(HOST_MODEL_MARK): at + 288]
    words = []
    for raw in HOST_MODEL_WORD.findall(window):
        word = raw.decode("latin-1")
        if word not in words:
            words.append(word)
    return (S.kind, [(words[0], words[0])]) if len(words) == 1 else None


def _rule(pattern, slug, fn):
    return re.compile(pattern), slug, fn


RULES = [_rule(pattern, slug, r_mark(slug, marks)) for pattern, slug, marks in MARKS] + [
    _rule(r"entry_?point|entry_address|entry_point_address|e_entry", "entry_point", r_entry),
    _rule(r"has_symtab|has_symbol_table", "has_symtab", r_has_symtab),
    _rule(r"is_stripped|stripped", "is_stripped", r_stripped),
    _rule(r"has_dynsym|has_dynamic_symbols", "has_dynsym", r_has_dynsym),
    _rule(r"has_debug_info|has_debug_symbols|has_dwarf|has_debug|has_debug_sections|has_debug_directory",
          "has_debug_info", r_debug),
    _rule(r"is_pie|pie|is_position_independent|position_independent|has_pie", "is_pie", r_pie),
    _rule(r"is_static|is_statically_linked|statically_linked|is_dynamic|is_dynamically_linked|dynamically_linked",
          "is_static", r_static),
    _rule(r"nx|has_nx|nx_enabled|is_nx|has_nx_stack|has_executable_stack|executable_stack|exec_stack|has_nx_compat|"
          r"nx_compat|has_dep|dep", "nx", r_nx),
    _rule(r"relro|relro_level|has_relro|is_relro|has_full_relro|full_relro|is_full_relro", "relro", r_relro),
    _rule(r"canary|has_canary|has_stack_canary|stack_canary|has_stack_protector|stack_protector", "canary", r_canary),
    _rule(r"interpreter|interp|program_interpreter|elf_interpreter|dynamic_linker|dylinker", "interpreter", r_interp),
    _rule(r"build_id|gnu_build_id", "build_id", r_build_id),
    _rule(r"soname|install_name|dylib_id|id_dylib", "soname", r_soname),
    _rule(r"needed|needed_libraries|dt_needed|libraries|shared_libraries|imported_libraries|imported_dlls|"
          r"imports|import_names|dylibs|linked_libraries|import_modules", "needed", r_needed),
    _rule(r"rpath|runpath|rpaths", "rpath", r_rpath),
    _rule(r"os_abi|osabi|elf_osabi|ei_osabi", "os_abi", r_osabi),
    _rule(r"(?:elf_)?(e_(?:type|machine|version|entry|phoff|shoff|flags|ehsize|phentsize|phnum|shentsize|shnum|"
          r"shstrndx))", None, r_elf_raw),
    _rule(r"section_count|num_sections|number_of_sections|sections_count|shnum|nsects", "section_count",
          r_section_count),
    _rule(r"segment_count|program_header_count|num_program_headers|num_segments|phnum", "segment_count",
          r_segment_count),
    _rule(r"section_names|sections", "section_names", r_section_names),
    _rule(r"segment_names|segments|program_headers", "segment_names", r_segment_names),
    _rule(r"symbol_count|num_symbols|symbols_count|symtab_count", "symbol_count", r_symbol_count),
    # the Day 16 look-ahead: symbol-table-adjacent counts and marks, all unsure (binary.<field>/elf)
    _rule(r"dynsym_count|dynamic_symbol_count|dynamic_symbols_count|num_dynamic_symbols|dynsym_entries|"
          r"dynamic_symtab_count", "dynsym_count", r_dynsym_count),
    _rule(r"relocation_count|relocations_count|reloc_count|num_relocations|num_relocs|relocation_entries|"
          r"num_relocation_entries", "relocation_count", r_reloc_count),
    _rule(r"dynamic_entry_count|dynamic_count|num_dynamic_entries|dynamic_entries_count|dt_entry_count",
          "dynamic_count", r_dynamic_count),
    _rule(r"has_gnu_hash|gnu_hash|has_gnu_hash_section|has_hash|hash_section|has_sysv_hash", "has_gnu_hash",
          r_has_gnu_hash),
    _rule(r"has_build_id|has_gnu_build_id|build_id_present", "has_build_id", r_has_build_id),
    _rule(r"note_names|note_sections|notes|note_section_names", "note_names", r_note_names),
    _rule(r"comment|comment_section|comment_string|compiler_comment|dot_comment", "comment", r_comment),
    _rule(r"flags|header_flags|elf_flags|macho_flags|mach_o_flags|characteristics|file_characteristics", "flags",
          r_flags),
    _rule(r"bits|bitness|is_64_?bit|is_pe32_plus|address_size_bits|word_size", "bits", r_bits),
    _rule(r"modinfo_(\w+)|module_(license|author|description|version|name|srcversion)|(vermagic)", "modinfo",
          lambda S, fmt, m: r_modinfo(S, fmt, re.match(r"(?:modinfo_|module_)?(\w+)", m.group(0)))),
    _rule(r"image_base", "image_base", _pe_num("image_base", True)),
    _rule(r"subsystem|pe_subsystem", "subsystem", r_subsystem),
    _rule(r"timestamp|time_date_stamp|timedatestamp|compile_time|compile_timestamp|build_timestamp|pe_timestamp",
          "timestamp", r_timestamp),
    _rule(r"is_dll", "is_dll", r_is_dll),
    _rule(r"magic|pe_magic|optional_header_magic|macho_magic|mach_o_magic|header_magic", "magic", r_pe_magic),
    _rule(r"checksum|pe_checksum|dex_checksum|adler32", "checksum", r_checksum),
    _rule(r"dll_characteristics", "dll_characteristics", _pe_num("dll_characteristics", True, 4)),
    _rule(r"aslr|has_aslr|dynamic_base|has_dynamic_base", "aslr", _pe_bit("dll_characteristics", 0x40, "dynamic_base")),
    _rule(r"high_entropy_va|has_high_entropy_va", "high_entropy_va",
          _pe_bit("dll_characteristics", 0x20, "high_entropy_va")),
    _rule(r"guard_cf|cfg|has_cfg|has_guard_cf|control_flow_guard|has_control_flow_guard", "guard_cf",
          _pe_bit("dll_characteristics", 0x4000, "guard_cf")),
    _rule(r"is_signed|signed|has_signature|has_certificate|has_authenticode|has_code_signature", "is_signed", r_signed),
    _rule(r"has_tls|has_tls_directory|has_tls_callbacks", "has_tls", _pe_dir("tls")),
    _rule(r"has_resources|has_rsrc|has_resource_directory", "has_resources", _pe_dir("resource")),
    _rule(r"has_relocations|has_relocs|has_reloc|has_base_relocations", "has_relocations", _pe_dir("basereloc")),
    _rule(r"has_imports|has_import_directory", "has_imports", _pe_dir("import")),
    _rule(r"has_exports|has_export_directory", "has_exports", _pe_dir("export")),
    _rule(r"has_cli_header|has_clr_header|has_com_descriptor|is_dotnet|is_managed", "has_cli_header",
          _pe_dir("com_descriptor")),
    _rule(r"has_overlay|overlay_size", "overlay", r_overlay),
    _rule(r"pdb_path|pdb|pdb_name|debug_path", "pdb_path", r_pdb),
    _rule(r"linker_version", "linker_version", r_linker),
    _rule(r"size_of_image|image_size", "size_of_image", _pe_num("size_of_image")),
    _rule(r"cpu_?type|macho_cpu_?type|mach_o_cpu_?type", "cputype", r_cputype),
    _rule(r"cpu_?subtype|macho_cpu_?subtype", "cpusubtype", r_cpusubtype),
    _rule(r"file_?type|macho_file_?type|mach_o_file_?type", "filetype", r_filetype),
    _rule(r"ncmds|load_command_count|num_load_commands|number_of_load_commands|command_count", "ncmds",
          _macho_num("ncmds")),
    _rule(r"sizeofcmds|size_of_cmds|load_commands_size|size_of_load_commands", "sizeofcmds", _macho_num("sizeofcmds")),
    _rule(r"uuid|lc_uuid|macho_uuid|mach_o_uuid|image_uuid|binary_uuid", "uuid", r_uuid),
    _rule(r"min(?:imum)?_?os(?:_version)?|minos|deployment_target|min(?:imum)?_macos(?:_version)?|min_version|"
          r"minimum_version", "minos", r_minos),
    _rule(r"sdk|sdk_version", "sdk", r_sdk),
    _rule(r"platform|build_platform", "platform", r_platform),
    _rule(r"archs|arches|arch_list|architectures|architecture_list|fat_archs|fat_arches|slices|fat_architectures",
          "architectures", r_archs),
    _rule(r"arch_count|nfat_arch|fat_arch_count|slice_count|num_archs|num_architectures|architecture_count",
          "arch_count", r_arch_count),
    _rule(r"is_fat|is_universal|universal|is_fat_binary|is_universal_binary", "is_fat", r_is_fat),
    _rule(r"is_encrypted|encrypted|cryptid", "encrypted", r_encrypted),
    _rule(r"source_version", "source_version", r_source_version),
    _rule(r"import_count|num_imports|imports_count", "import_count", _wasm_count("imports", "import_section")),
    _rule(r"export_count|num_exports|exports_count", "export_count", _wasm_count("exports", "export_section")),
    _rule(r"function_count|num_functions|functions_count", "function_count",
          _wasm_count("functions", "function_section")),
    _rule(r"type_count|num_types", "type_count", _wasm_count("types", "type_section")),
    _rule(r"data_segment_count|data_count|num_data_segments|data_segments", "data_segment_count",
          _wasm_count("data_segments", "data_section")),
    _rule(r"memory_pages|memory_min|initial_memory_pages|memory_min_pages|initial_memory", "memory_pages",
          _wasm_count("memory_min", "memory_section_min")),
    _rule(r"global_count|num_globals", "global_count", _wasm_count("globals", "global_section")),
    _rule(r"exports|export_names|exported_functions|exported_names", "exports", r_wasm_exports),
    _rule(r"custom_sections|custom_section_names", "custom_sections", r_wasm_custom),
    _rule(r"producers?_language|source_language|language|producers?_processed_by|processed_by|producers?_sdk|"
          r"wasm_producer|producers?", "producers", r_wasm_producers),
    _rule(r"start_function|start_function_index|has_start|has_start_function", "start_function", r_wasm_start),
    _rule(r"string_count|num_strings|string_ids_size|dex_string_count", "string_count", _dex_num("strings")),
    _rule(r"method_count|num_methods|method_ids_size|dex_method_count", "method_count", _dex_num("methods")),
    _rule(r"class_count|num_classes|class_defs_size|dex_class_count", "class_count", r_class_count),
    _rule(r"dex_type_count|type_ids_size", "dex_type_count", _dex_num("types")),
    _rule(r"field_count|field_ids_size|dex_field_count", "field_count", _dex_num("fields")),
    _rule(r"dex_signature|sha1_signature|dex_sha1", "dex_signature", r_dex_signature),
    _rule(r"dex_file_size|file_size_header", "dex_file_size", _dex_num("file_size")),
    _rule(r"compression_methods?|zip_compression_methods?", "compression_methods", r_compression),
    _rule(r"entry_count|file_count|num_entries|member_count|num_files|zip_entry_count|jar_entry_count", "entry_count",
          r_entry_count),
    _rule(r"entry_names|file_names|member_names|zip_entries|jar_entries", "entry_names", r_entry_names),
    _rule(r"has_manifest|has_jar_manifest", "has_manifest", r_has_manifest),
    _rule(r"dex_count|num_dex|dex_file_count", "dex_count", r_dex_count),
    _rule(r"native_abis|abis|native_libs_abis|supported_abis|lib_abis", "native_abis", r_abis),
    _rule(r"packer|packer_name|protector|packer_family", "packer", r_packer),
    _rule(r"is_packed|packed|has_packer|is_protected", "is_packed", r_is_packed),
    _rule(r"language|source_language|programming_language|implementation_language|compiled_language|lang",
          "language", r_language),
    _rule(r"runtime|runtime_name|language_runtime", "runtime", r_runtime),
    _rule(r"is_component|is_wasm_component|is_component_model|core_module_count|module_count|num_core_modules|"
          r"embedded_module_count|component_version|wasm_version|binary_version|layer|wasm_layer|component_layer",
          "component", r_component),
    _rule(r"disassembly|recover_code|exported_symbol|marker", None, r_d01),
    _rule(r"go_version|go_build_version|goversion|goos|goarch|go_module|go_path|go_main_path", "go", r_go),
    _rule(r"rustc_version|rust_version|rustc_commit|rustc_commit_hash", "rustc", r_rustc),
    _rule(r"hcfg_offset|hcfg_size|hcfg_payload_length", "hcfg_place", r_hcfg),
    _rule(r"hcfg_section_name|config_section_name|hcfg_section|section_of_hcfg|hcfg_magic|config_magic|hcfg_signature|"
          r"container_magic|hcfg_section_offset|hcfg_section_file_offset|config_section_offset|hcfg_section_size|"
          r"config_section_size|hcfg_section_length|hcfg_virtual_address|hcfg_vaddr|hcfg_rva|hcfg_section_virtual_address|"
          r"hcfg_section_vaddr|hcfg_section_rva|hcfg_address|hcfg_section_flags|config_section_flags", "hcfg_placement",
          r_hcfg_place),
    _rule(r"compiler|compiler_name|compiler_string|toolchain|toolchain_marker|toolchain_string|runtime_toolchain|"
          r"linker|linker_name|linker_version|linker_string|compiler_version|toolchain_version", "compiler", r_compiler),
    # The Day 19 look-ahead, B3: the dispatch facts, picks only.
    _rule(r"dispatch_variable|dispatch_env(?:_var|_variable)?|env_variable|environment_variable|env_var|"
          r"selector_variable|dispatch_selector(?:_variable)?", "dispatch_variable", r_dispatch_variable),
    _rule(r"dispatch_symbol|dispatch_function|dispatch_routine|dispatch_import|select_symbol|select_routine|"
          r"select_function", "dispatch_symbol", r_dispatch_symbol),
    _rule(r"handler_count|handlers_count|event_handler_count|num_handlers|handler_symbol_count", "handler_count",
          r_handler_count),
    _rule(r"handler_symbols|handler_names|event_handlers|event_handler_symbols|handler_functions", "handler_symbols",
          r_handler_symbols),
    _rule(r"jumptable_symbol|jump_table_symbol|jumptable|jump_table|dispatch_table_symbol|jumptable_name",
          "jumptable_symbol", r_jumptable_symbol),
    _rule(r"branch_labels|case_labels|select_labels|select_cases|branch_names|case_strings", "branch_labels",
          r_branch_labels),
    # Row 5 of the Day 13 look-ahead: names no rule read.
    _rule(r"payload_offset|payload_file_offset", "payload_offset",
          lambda S, fmt, m: r_hcfg_words(S, fmt, re.fullmatch(HCFG_WORDS, "hcfg_" + m.group(0)))),
    _rule(r"linkage|link_type|linking", "linkage", r_linkage),
    _rule(r"text_size|text_section_size", "text_size", r_text_size),
    _rule(r"host_model|hostmodel", "host_model", r_host_model),
    # The Day 12 look-ahead (B1): after every rule above, so a name one of them reads is never read twice.
    _rule(HCFG_WORDS, "hcfg_words", r_hcfg_words),
    _rule(HCFG_STATE, "hcfg_state", r_hcfg_state),
    _rule(r"xor_key(?:_(int|integer|decimal|dec))?", "xor_key", r_xor_key),
    _rule(r"(?:artifact|file|sample)_(size(?:_bytes)?|md5|sha1)(?:_(\d+))?|(size_bytes|md5|sha1)", "artifact",
          r_artifact),
    # Appended late (row 196): a specific has_<x> rule above wins; this catches the rest from the table.
    _rule(r"has_(\w+)_section", "has_section", r_has_section),
]
# ---- the Day 14 look-ahead, proposal 5 (2026-10-13): facts derived from the one container, picks only
#
# Names the look-ahead asked and no rule read: the parts of the config's url and domain, the digest and
# the length of the decoded JSON, the payload's place in a base64 text, the literal's length, the
# collector a runtime links, and a config member the config does not have (the syntax text of every
# exact_text question names the literal `none` for an absent field). All of them need exactly one
# CRC-valid place (S.hcfg_places), as every container rule does; none is ever plain.
DERIVED = (r"config_url_(host|hostname|domain|path|scheme|protocol|port)|config_domain_(tld|label_count|labels)|"
           r"(?:dns|domain)_(labels|label_count)|config_(sha256|md5|sha1|length|size|json_length)|"
           r"hcfg_(literal_length|string_length)")


def _even_section(S, at: int) -> bool:
    """Whether the ELF section that holds file offset `at` begins at an even offset: a 16-bit literal is
    aligned there, so text read from an odd offset is big-endian text that begins one byte earlier."""
    for sec in (S.elf or {}).get("sections") or ():
        off, size = sec.get("offset"), sec.get("size")
        if isinstance(off, int) and isinstance(size, int) and off <= at < off + size and sec.get("type") != 8:
            return off % 2 == 0
    return False


def _one_config(S):
    """(0, form, offset, container) of the sample's one established container (_hcfg_one) when no other
    CRC-valid container stands in the prefix's files in any form, else None."""
    one = _hcfg_one(S)
    if one is None or S._cache.get(f"hcfg_seen:{S.day}") != 1 or not isinstance(one[2].get("json"), dict):
        return None
    return (0,) + tuple(one)


def r_derived(S, fmt, m):
    place = _one_config(S)
    if place is None:
        return None
    _, form, at, c = place
    cfg, plain, bare = c["json"], bytes(c["plain"]), m.group(0)
    url, domain = cfg.get("url"), cfg.get("domain")
    if bare.startswith("config_url_") and isinstance(url, str):
        from urllib.parse import urlsplit
        try:
            u = urlsplit(url)
            port = u.port
        except ValueError:
            return None
        part = bare[len("config_url_"):]
        value = {"host": u.hostname, "hostname": u.hostname, "domain": u.hostname, "path": u.path or None,
                 "scheme": u.scheme or None, "protocol": u.scheme or None, "port": None if port is None else str(port)}[part]
        return ("=binary.config_url/" + part, [("url_part", value)]) if value else None
    if bare in ("config_domain_tld", "config_domain_label_count", "config_domain_labels", "dns_labels", "dns_label_count",
                "domain_labels", "domain_label_count") and isinstance(domain, str) and domain.strip("."):
        labels_ = domain.strip(".").split(".")
        if bare.endswith("_tld"):
            return "=binary.config_domain/tld", [("last_label", labels_[-1])]
        if bare.endswith("_count"):
            return "=binary.config_domain/label_count", [("labels", str(len(labels_)))]
        return "=binary.config_domain/labels", [("json", labels_), ("dotted", domain)]
    if bare in ("config_sha256", "config_md5", "config_sha1"):
        return "=binary." + bare + "/json", [("decoded_json", hashlib.new(bare[len("config_"):], plain).hexdigest())]
    if bare in ("config_length", "config_size", "config_json_length"):
        return "=binary." + bare + "/json", [("json_bytes", str(len(plain))), ("with_header", str(12 + len(plain)))]
    if bare.startswith("hcfg_") and form in ("base64", "utf16", "utf32"):
        width = {"base64": 1, "utf16": 2, "utf32": 4}[form]
        chars = -(-(12 + len(plain)) // 3) * 4
        run = HCFG_FORMS[0][1].match(S.data, at) if form == "base64" else None
        if run is None or len(run.group().rstrip(b"=")) + (-len(run.group().rstrip(b"=")) % 4) != chars:
            return None             # a text that goes on, or a wide one: where the literal ends is not established
        return "=binary." + bare + "/" + form, [("text_chars", str(chars)), ("text_bytes", str(chars * width))]
    return None


def r_gc(S, fmt, m):
    if not S.elf or S.data.count(b"GC_init") == 0 or b"GC_malloc" not in S.data:
        return None
    return f"=binary.gc/{S.kind}", [("boehm", "boehm"), ("bdwgc", "bdwgc"), ("boehm_gc", "boehm_gc")]


def r_payload_text(S, fmt, m):
    """hcfg_payload_offset of a base64 text: the character the payload's first byte begins in (12 header
    bytes are 16 characters), or the text's offset plus twelve."""
    place = _one_config(S)
    if place is None or place[0] != 0 or place[1] != "base64":
        return None
    at = place[2]
    return "=binary.hcfg_payload_offset/base64", [("payload_char", str(at + 16)), ("offset_plus_header", str(at + 12))]


def r_absent(S, fmt, m):
    place = _one_config(S)
    if place is None or m.group(1) in place[3]["json"] or not place[3].get("crc_ok"):
        return None
    if b'"' + m.group(1).encode() + b'"' in bytes(place[3]["plain"]):
        return None                 # the name stands in the JSON as a key one level down: not absent
    if any(pattern.fullmatch(m.group(0)) for pattern, _, fn in RULES if fn is not r_absent) \
            or _template_reads("analysis_" + m.group(0)):
        return None                 # a word a container rule reads (config_key, config_encoding) is no member's name
    if answer_kinds.kind_of(fmt) not in ("exact_text", ""):
        return None
    # one key a name (the review of 2026-10-13): under a shared key one accepted `none` would answer every
    # unknown config_* name plain on every later day
    return "=binary.config_member/absent+" + m.group(1), [("none", "none")]


RULES += [
    _rule(DERIVED, "derived", r_derived),
    _rule(r"gc|garbage_collector|gc_name|collector", "gc", r_gc),
    _rule(r"(?:hcfg|config|container)_payload_(?:file_)?offset|payload_offset|payload_file_offset", "payload_text", r_payload_text),
    _rule(r"config_(\w+)", "absent", r_absent),         # last: only a config_* name no rule above answers
]


# ---- Day 17 (backlog rows 328 and 340, 2026-10-17): the fields Day 17 asked of old samples
#
# Day 17 asked eight fields of old samples for the first time, hcfg_storage on six of them, and a PE build's
# section names and container offset in the Mastery. Its untracked live fix (solvers/binary/day_patch.py)
# answered them; what it proved is folded in here, scoped to the shape the judge took, and where the patch
# answered beyond that (hcfg_storage `base64` for samples with no carrier, `raw` for a PE `.hcfg` section,
# `raw_const_array` for any section, symbols read as printable strings) the reading below says less.
#
#   hcfg_storage        the token the organiser's ordered rule gives (the Time Trial's enum: raw, base64,
#                       raw_const_array, raw_hcfg_section, wasm_data_segment), read from the sample's one
#                       CRC-valid container: base64 for a printable base64 carrier (the judged key
#                       binary.hcfg_storage/base64, unchanged); raw_hcfg_section for a literal record in an
#                       ELF section named exactly .hcfg (judged on d14) and raw_const_array for a literal
#                       record in another mapped ELF section that an x86-64 `movabs r64, imm64` in an
#                       executable section loads by its exact start address (judged on d12), both plain;
#                       every other shape a pick under binary.hcfg_storage/<container>+<evidence>, the
#                       evidence class read from the bytes (a PE .hcfg section, a wasm data segment, another
#                       code or relocation reference, a .NET field RVA, none). No container, two, or one of
#                       another day: None. Asked under a kind that is neither exact_text nor enum: None; under an
#                       enum only the tokens it lists are offered (so a vocabulary without the judged token is
#                       unsure, never plain). A jar whose main class holds the day's container as a base64 String
#                       constant is a pick (jar+base64): the d06 and d07 jars do, and nobody has judged a jar.
#   mangled_<m>_symbol  the first symbol of the container's own table (ELF: every SHT_SYMTAB in section order;
#   typeinfo_symbol     PE: the COFF table in raw order, long names resolved, section-definition symbols kept)
#                       that the question's selection matches (<Class>.*<m>, ZTI.*<Class>), when that entry is the
#                       one method <m> of one class, or the typeinfo of the class that owns `score`, as it stands;
#                       judged on Day 17 as `mangled` and `typeinfo_of_class` (ELF, the bare name) and `comdat`
#                       (PE, the section-qualified name the table lists first). Another first match: None
#   has_go_runtime      true where the Go linker's buildinfo header and runtime.main stand in the file
#   has_rust_mangled_symbol  true where a symbol table holds a legacy (_ZN..17h<hash>E) or v0 (_R..C..) Rust name
#   has_coroutine_runtime    true where a jar holds entries under kotlin/coroutines/ or kotlinx/coroutines/ and its
#                       main class (or a nested class of it) refers to them; the entries alone are a pick
#   methods, access_flags, method_count   the main class's (the manifest's Main-Class, or a loose class
#                       file): its method table in declared order as compact JSON text, its access flags in
#                       decimal, the number of its methods (not its nested classes')
#
# "true" only: a mark not found is no proof of absence (the catalog's rule), so false is not answered here;
# since the Day 18 look-ahead (B3) it is offered, unsure, where the container's own tables prove it (_absent).
# Keys are binary.<field>/<container read from the magic>; the names Day 17 accepted are in the ledger and,
# after labels.py promote, in the seed. Where the judge took a name on a CORRECT attempt that wrote no ledger
# row (a plain bank), CARRIED below holds it, with the attempt it was judged on.

# The kinds hcfg_storage was asked under: exact_text on the Day 17 base as saved at 09:00 (its key.json holds
# the enum's tokens: the base closed after the organiser's rewording), the enum on its Time Trial and Mastery.
HCFG_STORAGE_KINDS = ("enum", "exact_text")
SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS, SHT_RELA = 0x2, 0x4, 8, 4
PE_EXEC = 0x20000000 | 0x20          # IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_CNT_CODE
CODE_SCAN_MAX = 64 << 20              # executable bytes the reference scan reads at most
_MOVABS = re.compile(rb"[\x48\x49][\xb8-\xbf]")


def _numpy():
    """numpy, imported on the first scan that needs it (about 30 ms), or None."""
    try:
        import numpy
        return numpy
    except Exception:
        return None


RIP_STEP = 1 << 20          # disp32 positions one vectorized step reads (about 4 MB of arrays a step)


def _rip_hits(code: bytes, base: int, target: int) -> bool:
    """Whether some disp32 in `code` (loaded at `base`) is a RIP-relative reference to `target`: the
    displacement plus the address after it (no immediate behind it, or a 1- or 4-byte one) is the target.

    Read as four aligned 32-bit views (the positions k, k+4, ... for k in 0..3), RIP_STEP positions at a
    time, in 32-bit arithmetic: a position whose sum matches modulo 2**32 is then checked exactly. A 64 MB
    code section so costs one step's memory, not the 2 GB of 64-bit temporaries a whole-file reading took."""
    np = _numpy()
    if np is None or len(code) < 4:
        return False
    for k in range(4):
        count = (len(code) - k) // 4
        if count <= 0:
            continue
        view = np.frombuffer(code, dtype="<u4", count=count, offset=k)
        for lo in range(0, count, RIP_STEP):
            part = view[lo:lo + RIP_STEP]
            # the disp32 at p = k + 4*(lo+i) resolves to target when disp + 4*(lo+i) == target - base - 4 - k - extra
            total = part + np.arange(lo, lo + len(part), dtype=np.uint32) * np.uint32(4)    # wraps mod 2**32
            for extra in (0, 1, 4):
                want = np.uint32((target - base - 4 - k - extra) & 0xFFFFFFFF)
                for i in np.flatnonzero(total == want)[:64]:
                    p = k + 4 * (lo + int(i))
                    if base + p + 4 + int.from_bytes(code[p:p + 4], "little", signed=True) + extra == target:
                        return True
    return False


def _code_refs(code_spans, va: int, x86_64: bool) -> str:
    """The class of instruction evidence for an address in executable bytes [(bytes, address)]: `movabs_imm64`
    (REX.W B8+r with the address as its imm64, the judged d12 shape), `code_ref` (the address as another
    4- or 8-byte immediate, or a RIP-relative displacement that resolves to it), or ''."""
    seen, read = "", 0
    for code, base in code_spans:
        read += len(code)
        if read > CODE_SCAN_MAX:
            return seen
        needle, at = struct.pack("<Q", va), 0
        while True:
            at = code.find(needle, at)
            if at < 0:
                break
            if x86_64 and at >= 2 and _MOVABS.fullmatch(code[at - 2:at]):
                return "movabs_imm64"
            seen, at = "code_ref", at + 1
        if va < 1 << 32 and struct.pack("<I", va) in code:
            seen = "code_ref"
    if not seen and x86_64:
        if any(_rip_hits(code, base, va) for code, base in code_spans):
            seen = "code_ref"
    return seen


def _elf_relocated(S, va: int) -> bool:
    """Whether an SHT_RELA entry of the ELF names `va` as its addend (a pointer the loader writes)."""
    wide, end = S.elf["bits"] == 64, "<" if S.elf["ei_data"] == 1 else ">"
    size, fmt = (24, end + "QQQ") if wide else (12, end + "III")
    np = _numpy()
    want = va & (0xFFFFFFFFFFFFFFFF if wide else 0xFFFFFFFF)       # the addend's bits, unsigned
    for sec in S.elf.get("sections") or ():
        if sec["type"] != SHT_RELA or not sec["size"] or sec["offset"] + sec["size"] > len(S.data):
            continue
        n = min(sec["size"] // size, 1 << 20)
        if np is not None:
            words = np.frombuffer(S.data, dtype=end + ("u8" if wide else "u4"), count=3 * n, offset=sec["offset"])
            if bool(np.any(words[2::3] == want)):
                return True
            continue
        for k in range(n):
            if struct.unpack_from(fmt, S.data, sec["offset"] + k * size)[2] == want:
                return True
    return False


def _pe_relocated(S, va: int) -> bool:
    """Whether a base relocation of the PE points at a location that holds `va` (a pointer the loader
    rebases)."""
    rva, size = S.pe["dirs"].get("basereloc", (0, 0))
    at = binfmt.pe_offset(S.pe["sections"], rva) if rva else None
    if at is None or not size:
        return False
    end, wide = min(len(S.data), at + size), S.pe["plus"]
    try:
        while at + 8 <= end:
            page, block = struct.unpack_from("<II", S.data, at)
            if block < 8:
                return False
            for k in range((block - 8) // 2):
                entry = struct.unpack_from("<H", S.data, at + 8 + 2 * k)[0]
                kind, where = entry >> 12, page + (entry & 0xFFF)
                if kind not in (3, 10):
                    continue
                off = binfmt.pe_offset(S.pe["sections"], where)
                if off is not None and struct.unpack_from("<Q" if kind == 10 else "<I", S.data, off)[0] == va:
                    return True
            at += block
    except struct.error:
        return False
    return False


def _hcfg_jar_storage(S):
    """(box, options) for a jar whose main class (and its nested classes) holds the day's one CRC-valid
    container as a base64 String constant and no literal one: the first rule of the organiser's order
    (a printable base64 carrier), never judged for a jar."""
    main = _main_class(S)
    if main is None or main[0] != "jar":
        return None
    stem, found = main[1], []
    for info in S.zip["infos"]:
        name = info.filename
        if info.is_dir() or not name.endswith(".class") or info.file_size > 1 << 20:
            continue
        if name != stem + ".class" and not name.startswith(stem + "$"):
            continue
        blob = S.zip["zf"].read(info)
        if hcfg.MAGIC in blob and any(c.get("crc_ok") for c in hcfg.containers(blob, others=True)):
            return None             # a literal record beside the text: not "only after decoding" (the bare
            #                         magic as a constant of the decoder is no record)
        for m in HCFG_FORMS[0][1].finditer(blob):
            c = _crc_first(_hcfg_decoded("base64", m.group()))
            if c is not None:
                found.append(c)
    keys = {(c["key"], c["crc32"], bytes(c["plain"])) for c in found}
    if len(keys) != 1:
        return None
    campaign = found[0]["json"].get("campaign") if isinstance(found[0].get("json"), dict) else None
    named = HCFG_CAMPAIGN.fullmatch(campaign) if isinstance(campaign, str) else None
    if named is None or S.day is None or int(named.group(1)) != S.day:
        return None
    return "==binary.hcfg_storage/jar+base64", [("base64", "base64")]


def r_hcfg_storage(S, fmt, m):
    if answer_kinds.kind_of(fmt) not in HCFG_STORAGE_KINDS:
        return None
    one = _hcfg_one(S)
    if one is None:
        return _hcfg_jar_storage(S) if S.zip else None
    form, at, c = one
    if S._cache.get(f"hcfg_seen:{S.day}") != 1:
        return None                 # the rule begins with the unique CRC-valid record: a second copy stands
    campaign = c["json"].get("campaign") if isinstance(c.get("json"), dict) else None
    named = HCFG_CAMPAIGN_ANY.fullmatch(campaign) if isinstance(campaign, str) else None
    if named is None or S.day is None or int(named.group(1)) != S.day:
        return None                 # a lone container of another day is not the day's record
    if form == "base64":            # the judged key, as r_hcfg_words offered it since Day 12 (d08, d09, d11, d13)
        return "base64", [("base64", "base64"), ("b64", "b64")]
    if form != "raw" or c.get("version") is None or c.get("how", "xor") != "xor" or not c.get("crc_ok"):
        return None                 # a wide text, hex, a payload read another way: not one of the five
    end = at + 12 + len(c["plain"])
    if S.wasm:
        segs = binfmt.wasm_data_segments(S.data, S.wasm) or ()
        if any(o <= at and end <= o + n for o, n in segs):
            return "==binary.hcfg_storage/wasm+data_segment", [("wasm_data_segment", "wasm_data_segment")]
        return "==binary.hcfg_storage/wasm+outside_data", [("raw", "raw")]
    if S.elf and S.elf.get("sections"):
        box, spans = "elf", [s for s in S.elf["sections"] if s["type"] != SHT_NOBITS and s["size"]
                             and s["offset"] <= at and end <= s["offset"] + s["size"]]
        sec = max(spans, key=lambda s: s["offset"]) if spans else None
        name = sec["name"] if sec else None
        load = next((g for g in S.elf.get("segments") or () if g["type"] == 1
                     and g["offset"] <= at and end <= g["offset"] + g["filesz"]), None)
        mapped = sec is not None and bool(sec["flags"] & SHF_ALLOC) and load is not None
        va = load["vaddr"] + at - load["offset"] if load else None
        x86_64 = S.elf["e_machine"] == 62
        code = [(S.data[s["offset"]:s["offset"] + s["size"]], s["addr"]) for s in S.elf["sections"]
                if s["flags"] & SHF_EXECINSTR and s["type"] != SHT_NOBITS and s["size"]]
    elif S.pe:
        box = "pe"
        spans = [s for s in S.pe["sections"] if s["rsize"] and s["raw"] <= at and end <= s["raw"] + s["rsize"]]
        sec = spans[0] if len(spans) == 1 else None
        name = sec["name"] if sec else None
        mapped = sec is not None and at - sec["raw"] < (sec["vsize"] or sec["rsize"])
        va = S.pe["image_base"] + sec["va"] + at - sec["raw"] if mapped else None
        x86_64 = S.pe["machine"] == 0x8664
        code = [(S.data[s["raw"]:s["raw"] + s["rsize"]], S.pe["image_base"] + s["va"]) for s in S.pe["sections"]
                if s["flags"] & PE_EXEC and s["rsize"]]
    else:
        return None                 # a Mach-O or another container: no section rule read here
    # The record's section, for judged_forms' open-rule key (review of 2026-10-18): a reworded rule may name
    # a section (`raw_rodata when ... a section named exactly .rodata`), and this key's shape does not carry it.
    S._cache["storage_section"] = name if isinstance(name, str) else ""
    if name == ".hcfg":
        return f"==binary.hcfg_storage/{box}+hcfg_section", [("raw_hcfg_section", "raw_hcfg_section")]
    if not mapped or va is None:
        return f"==binary.hcfg_storage/{box}+unmapped", [("raw", "raw")]
    evidence = _code_refs(code, va, x86_64)
    if evidence == "movabs_imm64" and box != "elf":
        evidence = "code_ref"
    if not evidence:
        if box == "elf" and _elf_relocated(S, va) or box == "pe" and _pe_relocated(S, va):
            evidence = "reloc_ref"
        elif box == "pe" and S.pe["dirs"].get("com_descriptor", (0, 0))[0] and \
                struct.pack("<I", va - S.pe["image_base"]) in S.data[:at] + S.data[end:]:
            evidence = "cli_field_rva"      # a .NET field whose initial value is the record (FieldRVA)
    if not evidence:
        return f"==binary.hcfg_storage/{box}+no_ref", [("raw", "raw"), ("raw_const_array", "raw_const_array")]
    return f"==binary.hcfg_storage/{box}+{evidence}", [("raw_const_array", "raw_const_array"), ("raw", "raw")]


ITANIUM_CV = re.compile(r"_ZN[rVK]*")


def _itanium_nested(name: str):
    """The components of an Itanium <nested-name> function or object name (`_ZNK15DiscoveryEngine5scoreEPKc`
    is ['DiscoveryEngine', 'score']), or None: substitutions, templates and operators are not read."""
    m = ITANIUM_CV.match(name)
    if not m:
        return None
    at, parts = m.end(), []
    while at < len(name) and name[at].isdigit():
        digits = re.match(r"\d+", name[at:]).group(0)
        n, at = int(digits), at + len(digits)
        if not n or at + n > len(name):
            return None
        parts.append(name[at:at + n])
        at += n
    return parts if len(parts) >= 2 and name[at:at + 1] == "E" else None


def _symbol_table(S):
    """(container, [names in the traversal the Day 17 question states, the empty ones left out]) or None:
    an ELF's SHT_SYMTAB tables in section-header order, a PE's COFF table in raw order."""
    def make():
        if S.elf:
            got = binfmt.elf_symtab_entries(S.data, S.elf)
            return ("elf", [n for n, _, _ in got if n]) if got else None
        if S.pe:
            got = binfmt.pe_coff_symbols(S.data)
            return ("pe", [n for _, n, _, _ in got if n]) if got else None
        return None
    return S._once("symbol_table", make)


def _bare_symbol(name: str) -> str:
    """A COFF section-definition name without its section (`.text$_ZN..` is `_ZN..`); others as they are."""
    m = re.fullmatch(r"\.[A-Za-z0-9_.]+\$(.+)", name)
    return m.group(1) if m else name


def _first_named(box: str, names: list, bare: str, pattern: str):
    """(option name, value) for the first entry of the table that the question's own selection matches
    (Day 17: the first name matching /DiscoveryEngine.*score/, /ZTI.*DiscoveryEngine/), when that entry is
    `bare` or a section-qualified form of it: `comdat` for a COFF section-definition name (judged on Day 17's
    PE builds), the judged ELF name otherwise (None as the option name). None when the first entry the
    selection matches is another symbol (a `.cold` part, a static of the method, a pointer typeinfo, a
    `.refptr`): then the first match is not the symbol this rule proves."""
    rx = re.compile(pattern)
    name = next((n for n in names if rx.search(n)), None)
    if name is None or _bare_symbol(name) != bare:
        return None
    if box == "pe":
        return ("comdat" if name != bare else "coff_symbol"), name
    return None, name


def _method_symbol(S, method: str):
    """(box, the one bare mangled name of a method called `method`, the components of its class, the
    table's names) or None."""
    table = _symbol_table(S)
    if not table:
        return None
    box, names = table
    found = {}
    for name in names:
        bare = _bare_symbol(name)
        parts = _itanium_nested(bare)
        if parts and parts[-1] == method:
            found.setdefault(bare, parts[:-1])
    if len(found) != 1:
        return None                 # no such method, or two (two classes, or overloads)
    bare, owner = next(iter(found.items()))
    return box, bare, owner, names


def r_mangled_symbol(S, fmt, m):
    got = _method_symbol(S, m.group(1))
    if got is None:
        return None
    box, bare, owner, names = got
    first = _first_named(box, names, bare, re.escape(owner[-1]) + ".*" + re.escape(m.group(1)))
    if first is None:
        return None
    return f"==binary.{m.group(0)}/{box}", [(first[0] or "mangled", first[1])]


def _class_object(S, kind: str, slug: str, option: str):
    """(key, options) for the Itanium object `_Z<kind><class>` of the class that owns `score` (TI: the
    typeinfo, TS: the typeinfo name, TV: the vtable), as the first entry of the table the selection
    /Z<kind>.*<Class>/ matches: the reading the judge took for typeinfo_symbol on Day 17."""
    got = _method_symbol(S, "score")
    if got is None:
        return None
    box, _, owner, names = got
    name = f"_Z{kind}" + ("".join(f"{len(p)}{p}" for p in owner) if len(owner) == 1
                          else "N" + "".join(f"{len(p)}{p}" for p in owner) + "E")
    first = _first_named(box, names, name, f"Z{kind}.*" + re.escape(owner[-1]))
    if first is None:
        return None
    return f"==binary.{slug}/{box}", [(first[0] or option, first[1])]


def r_typeinfo_symbol(S, fmt, m):
    return _class_object(S, "TI", "typeinfo_symbol", "typeinfo_of_class")


# The Day 18 look-ahead, B2: Day 2 asked vtable_symbol of the C++ sample, and Day 17 re-asked its two
# siblings (mangled_score_symbol, typeinfo_symbol) under the dNN_ scheme; the vtable and the typeinfo name
# (_ZTS) are the same table read for the class's other two objects. The ELF gives the bare name, a MinGW PE
# the COMDAT section-definition name (`.rdata$_ZTV15DiscoveryEngine`) where the table lists it first. Neither
# key has been judged: picks under binary.vtable_symbol/<container> and binary.typeinfo_name_symbol/<container>.
def r_vtable_symbol(S, fmt, m):
    return _class_object(S, "TV", "vtable_symbol", "vtable_of_class")


def r_typeinfo_name_symbol(S, fmt, m):
    return _class_object(S, "TS", "typeinfo_name_symbol", "typeinfo_name_of_class")


GO_BUILDINFO = b"\xff Go buildinf:"
# legacy: a nested name whose last component is the 17h<16 hex> hash; v0: _R, a path, and somewhere in it a
# crate root (C, a disambiguator s<base62>_ or none, then an identifier). `_RC4_set_key` is no Rust name.
RUST_SYMBOL = re.compile(r"_ZN.*17h[0-9a-f]{16}E|_R[0-9]*[NCMXYIB][0-9A-Za-z_]*C(?:s[0-9A-Za-z]*_)?\d+[A-Za-z_]")
COROUTINE_ENTRY = ("kotlin/coroutines/", "kotlinx/coroutines/")


def _true_only(fmt):
    """The option of a true answer when the question can take the word `true`, else []."""
    accepted = (fmt or {}).get("accepted_values")
    if isinstance(accepted, list) and accepted and "true" not in accepted:
        return []
    return [("lower", "true")]


def r_has_go_runtime(S, fmt, m):
    if len(S.data) > SEARCH_MAX or S.kind not in ("elf", "pe", "macho"):
        return None
    if GO_BUILDINFO in S.data and b"runtime.main" in S.data:
        return f"==binary.has_go_runtime/{S.kind}", _true_only(fmt)
    return _absent(S, "has_go_runtime", fmt)


def r_has_rust_mangled(S, fmt, m):
    names = []
    if S.elf:
        names = [n for n, _, _ in binfmt.elf_symtab_entries(S.data, S.elf) or ()]
        names += [n for n in binfmt.elf_symbol_names(S.data, S.elf, ".dynsym") or ()]
    elif S.pe:
        names = [n for _, n, _, _ in binfmt.pe_coff_symbols(S.data) or ()]
    if any(RUST_SYMBOL.match(_bare_symbol(n)) for n in names if n):
        return f"==binary.has_rust_mangled_symbol/{S.kind}", _true_only(fmt)
    return _absent(S, "has_rust_mangled_symbol", fmt)


# ---- the Day 18 look-ahead, B3: `false` for a mark, only where the container's own tables prove it
#
# Day 17 asked has_go_runtime, has_rust_mangled_symbol and has_coroutine_runtime only where they are true, and
# the catalog answers a mark only when it is found (a search that finds nothing proves nothing: a stripped or
# packed build). The pairs' other halves (has_go_runtime of the Rust or Ada sample, has_cpp_vtable of the Ada
# one, has_coroutine_runtime of the Java jar) were None, a STOP of about 83 s each. Here `false` is offered,
# unsure, under binary.<field>/<container>+absent, and only where absence is complete:
#   an ELF whose SHT_SYMTAB is read whole and holds named entries (not stripped), whose .dynsym (if any) is read
#   whole, where no name of either table is the mark's, no section is the runtime's own (.gopclntab, ...), and
#   no byte of the file holds the mark (the strings: GO_BUILDINFO, runtime.main, _ZTI/_ZTS/_ZTV names, a Rust
#   legacy or v0 name, the runtimes' panic strings): `symtab_absent`;
#   a jar with class entries whose central directory lists no entry with `coroutines` in its name and no
#   archive inside it: `entries_absent`.
# Anything else stays None. `true` is unchanged.
GO_SECTIONS = {".go.buildinfo", ".gopclntab", ".gosymtab", ".typelink", ".itablink", ".noptrdata", ".noptrbss",
               ".go.fipsinfo"}
RUST_BYTES = re.compile(rb"_ZN[0-9A-Za-z_$.]{1,512}?17h[0-9a-f]{16}E|"
                        rb"_R[0-9]*[NCMXYIB][0-9A-Za-z_]{0,256}?C(?:s[0-9A-Za-z]*_)?\d+[A-Za-z_]")
TYPEINFO_NAME = re.compile(r"_ZT[IS][0-9N]|\.\?A[VU]")
VTABLE_NAME = re.compile(r"_ZTV[0-9N]|\?\?_7")
# slug: (a symbol name that is the mark, sections that are the runtime's own, byte marks: literals or patterns)
ABSENT_MARKS = {
    "has_go_runtime": (lambda n: n.startswith(("runtime.", "go.", "go:", "type:", "type..")), GO_SECTIONS,
                       (GO_BUILDINFO, b"runtime.main", b"go.buildid", b"Go build ID", b"go:buildid")),
    "has_rust_mangled_symbol": (lambda n: bool(RUST_SYMBOL.match(_bare_symbol(n))), set(),
                                (RUST_BYTES, b"rust_panic", b"rust_begin_unwind", b"core::panicking", b"/rustc/")),
    "has_cpp_typeinfo": (lambda n: bool(TYPEINFO_NAME.match(_bare_symbol(n))), set(),
                         (TYPEINFO, b"St9type_info", b"__cxxabiv1", b"type_info")),
    "has_cpp_vtable": (lambda n: bool(VTABLE_NAME.match(_bare_symbol(n))), set(),
                       (VTABLE, b"__cxxabiv1", b"__cxa_pure_virtual")),
}


def _elf_all_symbols(S):
    """[every name of the ELF's SHT_SYMTAB tables and of its .dynsym], or None when that cannot be read whole:
    no section header table, no SHT_SYMTAB or one with no named entry (stripped), a table too long or cut.
    STT_FILE and STT_SECTION entries are left out: a source file's name (`runtime.c` in the Swift runtime)
    is no symbol of the program."""
    def make():
        info = S.elf
        if not info or not info.get("sections"):
            return None
        entries = binfmt.elf_symtab_entries(S.data, info)
        names = [n for n, kind, _ in entries or () if n and kind not in (3, 4)]
        if not names:
            return None
        size = 24 if info["bits"] == 64 else 16
        dyn = [s for s in info["sections"] if s["type"] == 11]
        if len(dyn) > 1 or any(s["size"] // size > 1 << 16 or s["offset"] + s["size"] > len(S.data) for s in dyn):
            return None
        if dyn:
            more = binfmt.elf_symbol_names(S.data, info, ".dynsym")
            if more is None:
                return None
            names += [n for n in more if n]
        return names
    return S._once("elf_all_symbols", make)


def _bytes_hold(S, slug: str, marks) -> bool:
    def make():
        return any(m.search(S.data) if hasattr(m, "search") else m in S.data for m in marks)
    return bool(S._once("absent_bytes:" + slug, make))


def _absent(S, slug: str, fmt):
    """(key, [the false option]) where the ELF's tables and bytes prove `slug`'s mark absent, else None."""
    if not S.elf or len(S.data) > SEARCH_MAX or slug not in ABSENT_MARKS:
        return None
    named, sections, marks = ABSENT_MARKS[slug]
    names = _elf_all_symbols(S)
    if names is None or any(named(n) for n in names):
        return None
    if any((s.get("name") or "") in sections for s in S.elf["sections"]):
        return None
    if _bytes_hold(S, slug, marks):
        return None
    return f"==binary.{slug}/elf+absent", _bool("symtab_absent", False, fmt)


def _jar_no_coroutines(S, fmt):
    """(key, [the false option]) for a jar of classes whose central directory lists nothing of the coroutine
    runtime and no archive inside it, else None."""
    if not S.zip or not any(n.endswith(".class") for n in S.zip["names"]):
        return None
    entries = [i.filename.lower() for i in S.zip["infos"]]
    if any("coroutines" in n for n in entries) or any(n.endswith((".jar", ".zip", ".war", ".aar", ".apk")) for n in entries):
        return None
    return "==binary.has_coroutine_runtime/jar+absent", _bool("entries_absent", False, fmt)


def r_has_coroutines(S, fmt, m):
    """`true` (judged on the d07 jar: 59 entries under kotlin/coroutines/, and its main class and the nested
    classes of its suspend functions refer to kotlin/coroutines/) where the jar holds the runtime's entries
    and the main class's family uses them. Entries alone (the Kotlin standard library bundled into a jar whose
    own code calls no coroutine) are the runtime present but not used: unsure under a key of their own."""
    if not S.zip or not any(n.endswith(".class") for n in S.zip["names"]):
        return None
    if not any(n.startswith(COROUTINE_ENTRY) for n in S.zip["names"]):
        return _jar_no_coroutines(S, fmt)
    main = _main_class(S)
    if main is None or main[0] != "jar":
        return None
    stem, used = main[1], False
    for info in S.zip["infos"]:
        name = info.filename
        if (name == stem + ".class" or name.startswith(stem + "$")) and name.endswith(".class") \
                and info.file_size <= 1 << 20:
            blob = S.zip["zf"].read(info)
            if any(entry.encode() in blob for entry in COROUTINE_ENTRY):
                used = True
                break
    return ("==binary.has_coroutine_runtime/jar" if used else "==binary.has_coroutine_runtime/jar+entries_only",
            _true_only(fmt))


def _main_class(S):
    """(where, the class's name without .class, its class-file table) of the sample's main class: a loose
    class file, or the class a jar's manifest names as Main-Class. None without one."""
    def make():
        if facts.is_class(S.data):
            table = binfmt.java_class_table(S.data)
            return ("class", table[1], table) if table else None
        if not S.zip or "META-INF/MANIFEST.MF" not in S.zip["names"]:
            return None
        zf = S.zip["zf"]
        main = facts.manifest(zf.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")).get("Main-Class")
        entry = main.strip().replace(".", "/") + ".class" if main else None
        if entry not in S.zip["names"]:
            return None
        table = binfmt.java_class_table(zf.read(entry))
        return ("jar", entry[:-len(".class")], table) if table else None
    return S._once("main_class", make)


def r_class_table(S, fmt, m):
    main = _main_class(S)
    if main is None:
        return None
    access, _, methods = main[2]
    word = m.group(0)
    if word == "methods":
        return "==binary.methods/class", [("declared_order", json.dumps(methods, separators=(",", ":")))]
    if word == "access_flags":
        return "==binary.access_flags/class", [("decimal", str(access))]
    return "==binary.method_count/class", [("main_class", str(len(methods)))]


RULES += [
    _rule(r"hcfg_storage", "hcfg_storage", r_hcfg_storage),
    _rule(r"mangled_([a-z][a-z0-9]*)_symbol", "mangled_symbol", r_mangled_symbol),
    _rule(r"typeinfo_symbol", "typeinfo_symbol", r_typeinfo_symbol),
    _rule(r"vtable_symbol", "vtable_symbol", r_vtable_symbol),
    _rule(r"typeinfo_name_symbol", "typeinfo_name_symbol", r_typeinfo_name_symbol),
    _rule(r"has_go_runtime", "has_go_runtime", r_has_go_runtime),
    _rule(r"has_rust_mangled_symbols?", "has_rust_mangled_symbol", r_has_rust_mangled),
    _rule(r"has_coroutine_runtime", "has_coroutine_runtime", r_has_coroutines),
    _rule(r"methods|access_flags|method_count", "class_table", r_class_table),
]


# ---- the Day 21 build, round 2 (the look-ahead's L3): a PE image's resource directory (pe_resources.walk), asked
# by type, id, name, language, size, place or count. Unsure only, under binary.pe_resource/<field>: no day has
# judged a resource answer. The leaf asked about is the one whose bytes hold a CRC-valid HCFG record when exactly
# one does, else the image's only leaf; anything else is None. A non-PE sample, or a directory that does not
# read whole, is None.
def _pe_res(S):
    if not S.pe:
        return None
    import pe_resources
    return S._once("pe_resources", lambda: pe_resources.walk(S.data, S.pe))


def _res_leaf(S):
    res = _pe_res(S)
    if not res or not res["leaves"]:
        return None
    marked = [lf for lf in res["leaves"] if lf["hcfg"]]
    if len(marked) == 1:
        return marked[0]
    return res["leaves"][0] if len(res["leaves"]) == 1 and not marked else None


def r_res_count(S, fmt, m):
    res = _pe_res(S)
    if res is None:
        return None
    return "=binary.pe_resource/" + _bare_m(m), _num("leaves", len(res["leaves"])) + _num("types", len(res["types"]))


def r_res_type_count(S, fmt, m):
    res = _pe_res(S)
    return None if res is None else ("=binary.pe_resource/" + _bare_m(m), _num("types", len(res["types"])))


def r_res_type(S, fmt, m):
    lf = _res_leaf(S)
    if lf is None:
        return None
    key = "=binary.pe_resource/" + _bare_m(m)
    if lf["type_id"] is None:
        return key, _text("type_name", lf["type"])
    if m.group(0).endswith("_id"):
        return key, _num("type_id", lf["type_id"])
    out = _num("type_id", lf["type_id"])
    if lf["type"].startswith("RT_"):
        out = [("rt_name", lf["type"]), ("rt_short", lf["type"][3:])] + out
    return key, out


def r_res_name(S, fmt, m):
    lf = _res_leaf(S)
    if lf is None:
        return None
    key = "=binary.pe_resource/" + _bare_m(m)
    if lf["name"] is not None:
        return key, _text("entry_name", lf["name"])
    return key, _num("entry_id", lf["id"])[:1] + [("entry_id:hash", f"#{lf['id']}")]


def r_res_lang(S, fmt, m):
    lf = _res_leaf(S)
    if lf is None or lf["lang"] is None:
        return None
    return "=binary.pe_resource/" + _bare_m(m), _num("lang_id", lf["lang"], width=4)


def r_res_size(S, fmt, m):
    lf = _res_leaf(S)
    return None if lf is None else ("=binary.pe_resource/" + _bare_m(m), _num("data_size", lf["size"]))


def r_res_place(S, fmt, m):
    lf = _res_leaf(S)
    if lf is None:
        return None
    off = _num("file_offset", lf["offset"]) if lf["offset"] is not None else []
    rva = _num("rva", lf["rva"])
    return "=binary.pe_resource/" + _bare_m(m), (rva + off if "rva" in m.group(0) else off + rva)


def _bare_m(m):
    return m.group(0)


_RES = r"(?:pe_)?(?:resource|rsrc)"
RULES += [
    _rule(rf"{_RES}_(?:count|entries|entry_count|leaf_count|data_count)|number_of_resources|resources_count",
          "pe_resource_count", r_res_count),
    _rule(rf"{_RES}_type_count|resource_types_count|number_of_resource_types", "pe_resource_type_count",
          r_res_type_count),
    _rule(rf"(?:config_|hcfg_)?{_RES}_type(?:_name|_id)?", "pe_resource_type", r_res_type),
    _rule(rf"(?:config_|hcfg_)?{_RES}_(?:name|id|name_or_id|identifier)", "pe_resource_name", r_res_name),
    _rule(rf"(?:config_|hcfg_)?{_RES}_(?:lang|language|language_id|langid)", "pe_resource_lang", r_res_lang),
    _rule(rf"(?:config_|hcfg_)?{_RES}_(?:data_size|data_length)|(?:config_)?{_RES}_size", "pe_resource_size",
          r_res_size),
    _rule(rf"(?:config_|hcfg_)?{_RES}_(?:offset|file_offset|rva|data_rva)", "pe_resource_place", r_res_place),
]

# Names the judge took on a CORRECT attempt that wrote no ledger row (a plain bank, or a plain answer under
# another key that the judge accepted): {key: (name, where it was judged)}. answer() gives such a key's
# option of that name plain while the ledger and the seed hold nothing for the key; a rejection of the name
# for the key, a split, or another accepted name hands the key back to labels.pick. A key a rehearsal masks
# (CTF_LEDGER_MASK) is not carried.
CARRIED = {
    "binary.hcfg_storage/elf+hcfg_section": (
        "raw_hcfg_section", "Day 17 d14 (an Objective-C ELF, the record in .hcfg): base key.json, Time Trial "
        "1cab213d and every Mastery set (5bff0b52), all CORRECT"),
    "binary.hcfg_storage/elf+movabs_imm64": (
        "raw_const_array", "Day 17 d12 (a Free Pascal ELF, the record in .data, `movabs rax, <record>` in .text): "
        "base key.json, Time Trial 1cab213d and every Mastery set (5bff0b52), all CORRECT"),
    "binary.has_go_runtime/pe": (
        "lower", "Day 17 Mastery 5bff0b52 sets 1, 3 and 5 (d04 Go PE32+ builds): `true`, CORRECT, sent plain "
        "under binary.has_go_runtime/elf"),
}


def _unsure_only(key: str, options: list):
    """An UNSURE answer under `key`, never the plain value of an accepted name (row 496, the player's
    decision on the adaptable-solver upgrade). labels.pick(key, ...) would return the plain value once
    the key has an accepted name, and later days promoted the "day's own" hcfg_offset keys into the seed
    (binary.hcfg_offset/base64+d13, binary.hcfg_offset/raw_elsewhere+d12). Those keys are used only when
    the offset is NOT a byte-proven single-copy value in a judged shape: a second CRC-valid copy stands
    beside the one place, or the layout is not the shape the judge accepted. There the offset is
    ambiguous or unjudged, so the name the judge accepted for a single judged container must not answer
    plain: the answer stays unsure (one probe on the untimed base, never a confident batch). Options
    already rejected for the key are still dropped, as labels.pick's unsure branch drops them; nothing
    left is None. This only restricts plain: it can introduce no new wrong answer and no false None."""
    rejected = set(labels.state(key).get("rejected") or ())
    left = [(n, v) for n, v in options if n not in rejected]
    return labels.unsure(key, left) if left else None


def _carried(key: str, options: list):
    """labels.pick(key, options), or the plain value of CARRIED's name for the key (see CARRIED)."""
    name = CARRIED.get(key, (None,))[0]
    value = dict(options).get(name) if name else None
    if value is None or labels._masked(key, labels._mask()):
        return labels.pick(key, options)
    st = labels.state(key)
    if st["accepted_names"] or st["split"] or name in st["rejected"]:
        return labels.pick(key, options)
    return value


TEMPLATE_RULE = _rule(r".+", "template", r_template)
TRACE_RULE = _rule(r".+", "trace", r_trace)


def _bare(field: str) -> str:
    return field[len("analysis_"):] if field.startswith("analysis_") else field


def _trace_field(bare: str) -> bool:
    import trace_template
    return trace_template.asks(bare)


def knows(field: str) -> bool:
    """Whether a rule reads `field` (a question id without its prefix). The sample decides the rest."""
    bare = _bare(str(field))
    if any(pattern.fullmatch(bare) for pattern, _, _ in RULES) or _trace_field(bare):
        return True
    import fields_template
    return any(re.search(pattern, str(field)) for pattern, _, _, _ in fields_template.RULES)


def answer(field: str, S: Sample, fmt=None):
    """labels.pick(...) for one field of one sample, or None: no rule, no such fact, or no option in
    the form the question asks for."""
    bare = _bare(str(field))
    kind = answer_kinds.kind_of(fmt)
    form = "+integer" if kind == "integer" else ("+hex" if answer_kinds.wants_hex(fmt) else "")
    rules = [(TRACE_RULE[0], "trace", r_trace)] if _trace_field(bare) else []
    rules += [r for r in RULES if r[0].fullmatch(bare)] + [TEMPLATE_RULE]
    for pattern, slug, fn in rules:
        m = pattern.fullmatch(bare)
        try:
            got = fn(S, fmt, m)
        except Exception as e:
            print(f"[catalog] {field}: the {slug or bare} rule raised {type(e).__name__}: {e}", file=sys.stderr)
            got = None
        if not got or not got[1]:
            continue
        box, options = got
        seen, kept = set(), []
        for name, value in answer_kinds.options_for(options, fmt):
            ident = repr(value)
            if ident not in seen:       # two methods that give one value are one option
                seen.add(ident)
                kept.append((name, value))
        if not kept:
            continue
        # One key per field name and container: two spellings of a field (nx, executable_stack) can
        # mean opposite things, and every id that shares a key shares the name the judge accepts.
        # `=key` is a rule's own key, `==key` one that takes no kind suffix either (a judged key),
        # `?=key` one that must stay UNSURE whatever the ledger holds (row 496; see _unsure_only).
        if box.startswith("?="):
            return _unsure_only(box[2:], kept[:MAX_OPTIONS])
        if box.startswith("=="):
            return _carried(box[2:], kept[:MAX_OPTIONS])
        key = box[1:] if box.startswith("=") else f"binary.{bare}/{box}"
        return _carried(key + form, kept[:MAX_OPTIONS])
    return None


def _qid(q):
    return q.get("qid") or q.get("id") or q.get("answer_id")


STORAGE_SECTIONS = {}     # (qid, the pick r_hcfg_storage gave) -> the name of the record's section ("" none)


def storage_section(qid, value):
    """The name of the section the hcfg_storage pick `value` of `qid` was read in ("" for a record in no
    named section), or None when this process's catalog gave no such pick for that id. judged_forms puts it
    into the key of the tokens a reworded rule lists (review of 2026-10-18)."""
    return STORAGE_SECTIONS.get((qid, value))


def fields(sample_name, data, questions, members=None) -> dict:
    """{qid: unsure answer} for the questions a rule and the sample's own tables answer."""
    S = Sample(sample_name, data, members)
    out = {}
    for q in questions:
        qid = _qid(q)
        if not isinstance(qid, str):
            continue
        field = re.sub(r"^set\d+\.", "", qid)
        field = field.split("_", 1)[1] if "_" in field else field
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else None
        asked_day = _day_of(qid)
        S.day = S.day if asked_day is None else asked_day      # the day a question asks about is its prefix's
        S._cache.pop("storage_section", None)
        got = answer(field, S, fmt)
        section = S._cache.pop("storage_section", None)
        if got is not None:
            out[qid] = got
            if section is not None:
                if len(STORAGE_SECTIONS) > 512:
                    STORAGE_SECTIONS.clear()
                STORAGE_SECTIONS[(qid, got)] = section
    return out


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--list":
        for pattern, slug, _ in RULES:
            print(f"{slug or '(as asked)':22s} {pattern.pattern}")
        sys.exit(0)
    if len(sys.argv) < 3 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    sample = Sample(sys.argv[1], Path(sys.argv[1]).read_bytes())
    print(f"{sys.argv[1]}: {sample.kind}")
    for name in sys.argv[2:]:
        got = answer(name, sample)
        parsed = labels.parse(got) if got is not None else None
        shown = got if parsed is None else f"unsure {parsed.key} {parsed.options}"
        print(f"  {name} = {shown!r}" if parsed is None else f"  {name} = {shown}")
