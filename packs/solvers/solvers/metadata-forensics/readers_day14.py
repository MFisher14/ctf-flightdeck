#!/usr/bin/env python3
"""Metadata Forensics reader pack of the Day 14 look-ahead (docs/retro/day-14-predictions-metadata.md).

properties_strict.py loads this file by name after every other pack and calls register(M). The
look-ahead staged 466 (format, property) pairs under the spelling the author would most likely use
and found, in this order of likelihood:

  1. names     a structure's own name in front of a field (lnk.link_info_local_base_path,
               ole.summary_information_author, cab.cfheader_file_count) or another spelling of it made
               a registered reader unknown. WHERE gets the words that only say which structure of the
               file a field lives in, and ALIASES the spellings no rule reaches. (The trailing `guid`
               word is properties_strict._guid_reader.)
  2. signers   who signed: the signer of the PKCS#7 a PE's certificate table, an MSI's
               \\x05DigitalSignature stream, an MSIX's AppxSignature.p7x, a NuGet package's
               .signature.p7s or a .p7b/.p7s file carries: subject and issuer by their parts, serial,
               thumbprints, validity, the certificates carried, whether a signature is there.
  3. widths    a hex name with no width word offered the minimal form only outside PE, ELF and Mach-O
               headers. The readers of fixed-width fields get their specification's width (Prop.bits),
               so the padded form the judge took on Days 9 and 10 is the first option.
  4. cab       the folder's compression type, and the specification's names (cfheader, cffile).
  5. lnk       the link CLSID, the volume serial as the number it is.
  6. second    a reader whose name has two honest readings offers the other one as one more option
               (dotnet.typedef_names with the namespace, msi.table_names as _Tables lists them,
               pe.overlay_size with the certificate table, 7z names with the directories, the low
               byte of zip's version made by).

and after those: package manifests (nupkg, deb, wheel, ipa, jar, apk), RPM header tags, OLE's root
CLSID and document summary, the scheduled-task XML, the first record of an event log, registry root
key, minidump system info, xar/pkg, the dmg trailer, a PDB's GUID and age, NSIS and Inno Setup marks,
and a handful of single fields (ELF, Mach-O, 7z, rar, bz2, Matroska, class, cpio, PE).

Everything here is unsure: every property is registered unconfirmed and no answer of this file is
ever plain before the judge has accepted its name. An extractor returns the value read from the
bytes, None when the file is not of its type or the field is absent in a structure that was read
whole, and raises M.Unknown for anything cut, damaged or ambiguous (two rows, two signatures, two
values). A key family never says a key it does not know is absent: Unknown.

Import cost: this file registers names and families and builds nothing else. Every parser is in
readers_day14_impl.py, which is loaded the first time a question needs one of them (impl()); a
registered extractor here is a thin call into it (lazy()). asn1crypto, olefile, plistlib, tarfile,
lzma and xml are imported inside the functions that need them.
"""
import functools

M = None
PACKS = {}
SECTIONS = []
_IMPL = []
NEW_FNS = []
IMPL_FILE = "readers_day14_impl.py"


def section(fn):
    SECTIONS.append(fn)
    return fn


def impl():
    """readers_day14_impl.py beside this file, loaded at the first question that needs a parser of it."""
    if not _IMPL:
        mod = M._load_beside("metadata_readers_day14_impl", IMPL_FILE)
        mod.M, mod.PACKS = M, PACKS
        _IMPL.append(mod)
    return _IMPL[0]


def lazy(name, *args):
    """An extractor that calls impl().<name>, or impl().<name>(*args) when the parser is made from arguments.
    Whatever a cut or damaged structure raises becomes Unknown: no exception leaves a reader of this pack."""
    def fn(*call):
        mod = impl()    # outside the try: a pack that cannot load raises PackMissing / PackLoadError, never Unknown (B-001b)
        try:
            f = getattr(mod, name)
            return (f(*args) if args else f)(*call)
        except (M.Unknown, M.Ambiguous):
            raise
        except Exception as e:
            raise M.Unknown(f"the bytes do not read as this structure ({type(e).__name__})")
    fn.__name__ = name
    return fn


def reg(ns, names, fmt, fn, bits=None):
    """Register fn under every name of the list that nothing else reads yet (an earlier pack's reader is kept)."""
    names = names.split() if isinstance(names, str) else list(names)
    free = [f"{ns}.{x}" for x in names if M.canon(f"{ns}.{x}") not in M.REG]
    if free:
        M.prop(*free, fmt=fmt, bits=bits)(fn)
        NEW_FNS.append(fn)


class LazyRx:
    """A family's pattern that is compiled the first time a name with one of its namespaces is looked
    up: lookup() only calls fullmatch(), and compiling these patterns at import cost 2 ms."""
    __slots__ = ("pattern", "heads", "rx")

    def __init__(self, pattern, heads):
        self.pattern, self.heads, self.rx = pattern, heads, None

    def fullmatch(self, key):
        if not key.startswith(self.heads):
            return None
        if self.rx is None:
            import re
            self.rx = re.compile(self.pattern)
        return self.rx.fullmatch(key)


def fam(pattern, fmt, fn, heads=None):
    """M.family(), with the pattern compiled late. `heads`: the namespaces the pattern can start with
    (read from the pattern itself when it starts with one literal word)."""
    if fmt not in M.FORMATS:
        raise KeyError(fmt)
    if heads is None:
        word = pattern.split("_", 1)[0]
        if not word.isalnum():
            raise ValueError(f"name the namespaces of {pattern}")
        heads = (word,)
    M.FAMILIES.append((LazyRx(pattern, tuple(h + "_" for h in heads)), fn, fmt, None))


def namespace(ns, tokens=(), test=None, archive=False):
    """A namespace no earlier pack has: its words in an id, its test for the facts page."""
    M.NAMESPACES.add(ns)
    M.PACK_NAMESPACES.add(ns)
    if archive:
        M.ARCHIVE_NAMESPACES.add(ns)
    M.CONTENT_TOKENS.update(tokens)
    if test is not None:
        M.MORE_TYPES.append((ns, test))
        M.RELATED.setdefault(ns, (ns,))


def register(module):
    global M
    M = module
    PACKS.clear()
    PACKS.update(getattr(M, "MORE_MODULES", {}))
    _IMPL.clear()
    before, families = len(M.REG), len(M.FAMILIES)
    del NEW_FNS[:]
    for s in SECTIONS:
        s()
    M.TIE_FREE.update(NEW_FNS)   # this pack's own extractors only: an alias shares its target's, which may be a judged one
    return len(M.REG) - before, len(M.FAMILIES) - families


def is_type(name):
    """A test for the facts page: impl().<name>(d) is not None."""
    def test(d):
        try:
            return getattr(impl(), name)(d) is not None
        except Exception:
            return False
    return test


# ------------------------------------------------------------------ 1. names
# Words that only say which structure of the namespace's file a field lives in. guess() drops them, on
# both sides, only where the name selects no reader with them, and only where what is left selects ONE
# extractor (properties_strict.WHERE, row 178).
WHERE = {
    "lnk": ("link", "shell", "string", "data", "linkinfo", "stringdata", "extra", "tracker"),
    "ole": ("information", "property", "set", "entry", "document"), "cfb": ("information", "property", "set", "entry", "document"),
    "msi": ("information", "property", "database"),
    "docx": ("properties", "dc", "cp", "dcterms"), "xlsx": ("properties", "dc", "cp", "dcterms"),
    "pptx": ("properties", "dc", "cp", "dcterms"), "ooxml": ("properties", "dc", "cp", "dcterms"),
    "office": ("properties", "dc", "cp", "dcterms"),
    "macho": ("mach", "load", "command", "lc"),
    "msix": ("manifest", "package"), "appx": ("manifest", "package"),
    "zoneidentifier": ("zone", "transfer", "zonetransfer"),
    "evtx": ("file",), "prefetch": ("file", "information", "scca"),
    "dotnet": ("cli", "clr", "cor20", "cor"),
    "cab": ("cfheader", "cffile", "cffolder", "cabinet"),
    "x509": ("certificate", "tbs", "validity"),
    "gzip": ("member",), "7z": ("signature", "start"), "rar": ("archive",),
    "rpm": ("tag",), "deb": ("control",), "jar": ("manifest",), "nupkg": ("nuspec", "metadata", "package"),
    "whl": ("metadata", "dist"), "ipa": ("info", "plist"), "pdb": ("pdb", "msf", "superblock"),
    "task": ("registration", "actions", "principals", "principal", "settings", "exec", "triggers"),
    "minidump": ("directory",), "regf": ("base", "hive"), "mkv": ("ebml", "segment"),
    "dmg": ("koly", "udif", "trailer"), "xar": ("toc",), "pkg": ("info",),
}
# target (a registered name) -> more spellings of the same fact, each unsure under its own key.
ALIASES = {
    "msi.package_code": ("msi.summary_revision_number", "msi.revision_number", "msi.summary_package_code"),
    "msi.product_version": ("msi.productversion", "msi.product_version_string"),
    "msi.product_name": ("msi.productname",), "msi.manufacturer": ("msi.product_manufacturer",),
    "msi.upgrade_code": ("msi.upgradecode",), "msi.product_code": ("msi.productcode",),
    "msi.product_language": ("msi.product_language_lcid", "msi.productlanguage"),
    "msi.summary_template": ("msi.summary_platform_language",),
    "msi.summary_creating_application": ("msi.summary_application_name", "msi.summary_software", "msi.summary_appname"),
    "msi.component_guid": ("msi.component_code", "msi.component_id"),
    "msi.component_guids": ("msi.component_id_guids",),
    "msi.cabinet_names": ("msi.media_cabinet_names",),
    "zip.file_names": ("zip.central_directory_file_names", "zip.central_directory_file_member_names"),
    "zip.directory_names": ("zip.directory_member_names",),
    "zip.comment": ("zip.end_of_central_directory_comment",),
    "zip.eocd_central_directory_offset": ("zip.central_directory_offset",),
    "zip.eocd_central_directory_size": ("zip.central_directory_size",),
    "cab.file_names": ("cab.cffile_names", "cab.cffile_member_names", "cab.cffile_file_names", "cab.cffile_sz_names"),
    "cab.set_id": ("cab.cfheader_setid", "cab.setid"), "cab.cabinet_size_bytes": ("cab.cfheader_cb_cabinet",),
    "cab.file_count": ("cab.cfheader_c_files", "cab.cfheader_files"), "cab.folder_count": ("cab.cfheader_c_folders", "cab.cfheader_folders"),
    "lnk.local_base_path": ("lnk.link_info_local_base_path",),
    "lnk.header_write_time": ("lnk.header_modification_time", "lnk.target_modified_time", "lnk.modification_time"),
    "lnk.tracker_machine_id": ("lnk.tracker_machine_identifier", "lnk.machine_identifier"),
    "lnk.tracker_mac_address": ("lnk.tracker_droid_mac_address",),
    "pe.authentihash_sha256": ("pe.authenticode_digest_sha256",), "pe.authentihash_sha1": ("pe.authenticode_digest_sha1",),
    "pe.authenticode_digest": ("pe.authenticode_message_digest",),
    "pe.pdb_guid": ("pe.codeview_signature", "pe.codeview_guid", "pe.codeview_signature_guid"),
    "pe.pdb_path": ("pe.rsds_pdb_file_name", "pe.codeview_pdb_file_name", "pe.rsds_pdb_path"),
    "pe.time_date_stamp": ("pe.compile_time", "pe.compilation_time", "pe.link_time"),
    "pe.authenticode_present": ("pe.authenticode_signature_present", "pe.signature_present", "pe.security_directory_present",
                                "pe.digital_signature_present"),
    "msi.digital_signature_present": ("msi.signature_present", "msi.authenticode_signature_present"),
    "msix.signature_present": ("msix.appx_signature_present",),
    "dotnet.metadata_version": ("dotnet.clr_metadata_version", "dotnet.metadata_root_version"),
    "dotnet.flags": ("dotnet.cor_flags", "dotnet.cor20_flags", "dotnet.cli_header_flags", "dotnet.clr_header_flags", "dotnet.corflags"),
    "prefetch.executable_name": ("prefetch.exe_name", "prefetch.header_file_name", "prefetch.header_executable_name"),
    "prefetch.prefetch_hash": ("prefetch.path_hash", "prefetch.header_path_hash", "prefetch.header_hash"),
    "docx.core_creator": ("docx.dc_creator",),
    "docx.core_created": ("docx.core_dcterms_created",),
    "pdf.trailer_id_first": ("pdf.trailer_id_0", "pdf.id_first", "pdf.trailer_id_permanent", "pdf.id_0"),
    "jpeg.exif_make": ("jpeg.exif_ifd0_make",), "jpeg.exif_model": ("jpeg.exif_ifd0_model",),
    "jpeg.exif_software": ("jpeg.exif_ifd0_software",),
    "jpeg.comment": ("jpeg.com_comment", "jpeg.com_segment_text", "jpeg.com_segment_comment"),
    "x509.fingerprint_sha1": ("x509.certificate_sha1", "x509.sha1"), "x509.fingerprint_sha256": ("x509.certificate_sha256", "x509.sha256"),
    "x509.subject_key_identifier": ("x509.ski", "x509.extension_subject_key_identifier"),
    "elf.interp_path": ("elf.program_interpreter", "elf.requesting_program_interpreter", "elf.program_header_interp_path",
                        "elf.program_header_interp", "elf.program_header_interpreter"),
    "elf.dt_needed": ("elf.dt_needed_names", "elf.dynamic_needed_library_names", "elf.dynamic_needed_libraries"),
    "macho.build_version_minos": ("macho.lc_build_version_min_os", "macho.build_version_min_os"),
    "evtx.next_record_id": ("evtx.header_next_record_identifier", "evtx.next_record_identifier"),
    "zstd.content_checksum_present": ("zstd.checksum_flag", "zstd.frame_header_checksum_flag", "zstd.frame_header_content_checksum_flag"),
    "ogg.vorbis_sample_rate_hz": ("ogg.vorbis_identification_sample_rate_hz", "ogg.vorbis_identification_sample_rate"),
    "png.text_software": ("png.text_chunk_software", "png.tex_t_software"), "png.text_comment": ("png.text_chunk_comment",),
    "eml.received_count": ("eml.header_received_count",),
    "regf.root_key_name": ("regf.root_cell_name", "regf.root_name"),
    "msi.summary_create_time": ("msi.summary_creation_time", "msi.summary_create_date", "msi.create_time", "msi.summary_created"),
    "msi.summary_page_count": ("msi.summary_pages", "msi.summary_schema_version", "msi.minimum_installer_version"),
    "msi.summary_word_count": ("msi.summary_words", "msi.summary_source_type"),
    "msi.summary_codepage": ("msi.summary_code_page",), "msi.stream_count": ("msi.cfb_stream_count", "msi.ole_stream_count"),
    "msi.file_name": ("msi.file_filename", "msi.file_file_name"),
    "msix.capability_names": ("msix.capabilities_names",),
    "pe.imphash": ("pe.import_hash_md5", "pe.imphash_md5", "pe.import_hash"),
    "flac.streaminfo_md5": ("flac.streaminfo_md5_signature", "flac.md5_signature"),
    "zip.eocd_offset": ("zip.end_of_central_directory_offset", "zip.eocd_file_offset"),
    "zip.eocd_total_entries": ("zip.end_of_central_directory_total_entries",),
    "evtx.chunk_count": ("evtx.file_header_number_of_chunks", "evtx.header_number_of_chunks"),
    "mp4.mvhd_timescale": ("mp4.movie_header_timescale", "mp4.mvhd_time_scale"), "mp4.mvhd_duration": ("mp4.movie_header_duration",),
    "mp4.mvhd_creation_time": ("mp4.movie_header_creation_time",),
    "dex.signature": ("dex.header_signature", "dex.signature_sha1", "dex.header_signature_sha1"),
    "dex.checksum": ("dex.header_checksum",),
    "prefetch.last_run_time": ("prefetch.last_run", "prefetch.last_execution_time"),
    "x509.public_key_bits": ("x509.subject_public_key_bits",),
    "tar.first_header_mode": ("tar.header_mode_octal",),
    "zip.version_made_by": ("zip.central_directory_first_version_made_by", "zip.first_entry_version_made_by"),
    "wav.fmt_byte_rate": ("wav.fmt_avg_bytes_per_sec",),
    "webp.canvas_dimensions_pixels": ("webp.dimensions_pixels",),
    "gzip.isize": ("gzip.trailer_uncompressed_size",), "gzip.header_os": ("gzip.header_operating_system",),
}


def _add_aliases(table):
    for target, names in table.items():
        if M.canon(target) not in M.REG:
            continue
        for n in names:
            if M.canon(n) not in M.REG:
                M.alias(target, n)


@section
def _reg_names():
    for ns, words in WHERE.items():
        M.WHERE[ns] = set(M.WHERE.get(ns, ())) | set(words)
    _add_aliases(ALIASES)


# ------------------------------------------------------------------ 2. signers
SIGNED = "pe|msi|msix|appx|nupkg|pkcs7"
HEADS_RX = r"(?:authenticode_|digital_signature_|appx_signature_|package_signature_|signed_data_|signature_)?"
CERT_RX = r"(?:signer|signing_certificate|signer_certificate)"
PARTS_RX = "organizational_unit|state_or_province|organization_name|common_name|country_name|organization|locality|country|state|org|cn|ou|st|o|c|l"


def _sfam(pattern, fmt, name):
    fam(rf"({SIGNED})_{HEADS_RX}{pattern}", fmt, lazy(name), heads=SIGNED.split("|"))


@section
def _reg_signers():
    namespace("pkcs7", tokens=("p7b", "p7s", "p7c", "p7x", "cat"), test=is_type("p7_der"))
    namespace("nupkg", tokens=("nupkg",), test=is_type("is_nupkg"), archive=True)
    M.NS_ALIAS.update({"p7b": "pkcs7", "p7s": "pkcs7", "cms": "pkcs7", "cat": "pkcs7", "catalog": "pkcs7", "nuget": "nupkg",
                       "wheel": "whl", "scheduled_task": "task", "taskxml": "task", "innosetup": "inno", "inno_setup": "inno",
                       "debian": "deb", "motw": "zoneidentifier", "zone_identifier": "zoneidentifier", "matroska": "mkv",
                       "msixbundle": "msix", "appxbundle": "msix", "flat_package": "pkg", "nuspec": "nupkg", "doc": "ole"})
    # Names are read by families (one regular expression each), so nothing is built at import; a name an
    # earlier pack registered (pe.authenticode_signer, pe.signer_thumbprint_sha1, ...) keeps its reader.
    _sfam(rf"{CERT_RX}_(?:subject_)?({PARTS_RX})", "text", "signer_part")
    _sfam(rf"(?:{CERT_RX}_)?issuer_({PARTS_RX})", "text", "issuer_part")
    _sfam(rf"{CERT_RX}(?:_subject|_name|_distinguished_name|_subject_name|_subject_dn)?", "forms", "signer_name")
    _sfam(rf"(?:{CERT_RX}_)?issuer(?:_name|_distinguished_name|_dn)?", "forms", "issuer_name")
    _sfam(rf"(?:{CERT_RX}_)?serial(?:_number)?", "serial", "signer_serial")
    _sfam(rf"{CERT_RX}_(?:certificate_)?(?:thumbprint_|fingerprint_)?(sha1|sha256|md5)", "hex", "signer_hash")
    _sfam(rf"{CERT_RX}_(?:certificate_)?(?:thumbprint|fingerprint)", "hex", "signer_hash")
    _sfam(rf"{CERT_RX}_(?:certificate_)?(not_before|not_after|valid_from|valid_to|expiry)", "timestamp", "signer_validity")
    _sfam(r"(?:pkcs7_)?certificate_count", "integer", "cert_count")
    _sfam(r"certificate_(?:subjects|common_names|subject_common_names)", "list", "cert_subjects")
    _sfam(r"(?:signer_)?digest_algorithm", "label", "digest_algorithm")
    _sfam(r"(?:signer_)?signing_time", "timestamp", "signing_time")
    _sfam(r"(?:timestamp|countersignature_time|timestamp_gen_time)", "timestamp", "timestamp")
    _sfam(r"first_certificate_(?:subject_)?(?:common_name|cn)", "text", "first_cert_cn")
    _sfam(r"(?:signature_present|signed|is_signed|has_signature|digitally_signed|present)", "bool", "signature_present")
    reg("pkcs7", "signer_count signer_info_count signer_infos_count", "integer", lazy("signer_count"))


# ------------------------------------------------------------------ 3. widths
# reader name -> the bits of its field in the format's specification. Only a reader that has no width yet
# gets one, and every spelling of that reader with it.
WIDTHS = {
    "lnk.link_flags": 32, "lnk.file_attributes": 32, "lnk.hot_key": 16, "lnk.header_show_command": 32,
    "gzip.header_flags": 8, "gzip.flags": 8, "gzip.xfl": 8, "gzip.extra_flags": 8, "gzip.header_crc32": 32, "gzip.trailer_crc32": 32,
    "gzip.crc32": 32,
    "minidump.flags": 64, "minidump.header_flags": 64, "minidump.checksum": 32, "minidump.header_checksum": 32,
    "macho.lc_main_entryoff": 64, "macho.entryoff": 64, "macho.entry_offset": 64,
    "pyc.magic": 16, "pyc.magic_number": 16, "pyc.flags": 32,
    "pe.certificate_table_offset": 32, "pe.certificate_table_size_bytes": 32, "pe.overlay_offset": 32,
    "pe.win_certificate_revision": 16, "pe.win_certificate_type": 16, "pe.rich_header_xor_key": 32, "pe.rich_xor_key": 32,
    "evtx.header_flags": 32, "evtx.flags": 32, "evtx.header_checksum": 32, "evtx.checksum": 32,
    "zip.version_made_by": 16, "zip.first_entry_crc32": 32, "zip.first_entry_flags": 16, "zip.eocd_offset": 32,
    "7z.start_header_crc": 32, "7z.start_header_crc32": 32, "7z.next_header_crc": 32, "7z.next_header_crc32": 32,
    "sqlite.application_id": 32, "sqlite.user_version": 32, "prefetch.prefetch_hash": 32, "prefetch.hash": 32,
    "cab.set_id": 16, "cab.header_flags": 16, "cab.flags": 16, "regf.checksum": 32, "regf.header_checksum": 32,
    "dex.checksum": 32, "dex.header_checksum": 32, "class.magic": 32, "rar.first_file_crc32": 32, "bz2.block_crc": 32,
    "png.ihdr_crc32": 32, "zstd.frame_header_descriptor": 8, "lz4.flg": 8, "lz4.bd": 8, "xz.stream_flags": 16,
    "wav.format_tag": 16, "wav.fmt_format_tag": 16, "wav.audio_format": 16, "id3.header_flags": 8, "ico.type": 16,
    "elf.debuglink_crc32": 32, "macho.fat_magic": 32, "tar.first_header_checksum": 32, "mkv.track_uid": 64,
    "dotnet.entry_point_token": 32, "mft.flags": 16, "ole.byte_order": 16, "cfb.byte_order": 16,
    "ole.major_version": 16, "cfb.major_version": 16, "ole.minor_version": 16, "cfb.minor_version": 16,
}


@section
def _reg_widths():
    M.LATE_WIDTHS.update({M.canon(k): b for k, b in WIDTHS.items()})


# ------------------------------------------------------------------ 4. cab, 5. lnk
@section
def _reg_cab_lnk():
    reg("cab", "compression_type folder_compression_type folder_compression cffolder_compression_type cffolder_type_compress type_compress "
               "compression compression_method first_folder_compression_type", "forms", lazy("cab_compression"))
    reg("cab", "folder_type_compress_raw cffolder_type_compress_value", "integer", lazy("cab_compression_raw"), bits=16)
    reg("lnk", "link_clsid header_link_clsid clsid header_clsid shell_link_clsid link_class_id class_id header_class_identifier", "uuid",
        lazy("lnk_clsid"))
    reg("lnk", "volume_serial_number_value drive_serial_number_value volume_id_drive_serial_number_value volume_serial_value "
               "linkinfo_volume_serial_number_value", "integer",
        lazy("lnk_serial"), bits=32)


# ------------------------------------------------------------------ 6. a second reading as one more option
def also(targets, other, fmt, tag):
    """Each registered, unconfirmed name of `targets` also offers the reading `other` (properties_strict.SECOND)."""
    for target in targets.split():
        p = M.REG.get(M.canon(target))
        if p is not None and not p.confirmed:
            M.SECOND[M.canon(target)] = (other, fmt, tag)


def _other(name):
    """The extractor registered under `name`, called when asked (the name may be registered by any pack)."""
    def fn(n, d):
        p = M.REG.get(M.canon(name))
        return None if p is None else p.fn(n, d)
    return fn


@section
def _reg_second():
    also("dotnet.typedef_names dotnet.type_def_names dotnet.type_definition_names dotnet.typedef_table_names",
         _other("dotnet.typedef_full_names"), "list", "with_namespace")
    also("msi.table_names msi.tables msi.database_table_names msi.table_list", _other("msi.declared_table_names"), "list", "as_tables_lists")
    also("msi.table_count msi.database_table_count", lazy("declared_count"), "integer", "as_tables_lists")
    also("pe.overlay_size_bytes pe.overlay_bytes pe.overlay_size", lazy("pe_overlay_with_table"), "integer", "with_certificate_table")
    also("zip.version_made_by zip.central_directory_first_version_made_by zip.first_entry_version_made_by",
         lazy("low_byte", "zip.version_made_by"), "integer", "low_byte")
    also("zip.central_directory_file_names", _other("zip.file_names"), "list", "files_only")
    also("7z.file_names", _other("7z.member_names"), "list", "with_directories")
    # elf.section_names with the null section: readers_elf_names.py's (the Day 21 build, round 2), with a class that
    # takes the null section's empty name (the class `list` refused it, so this line never offered the reading)
    also("rpm.name rpm.package_name", lazy("rpm_second", 1000), "text", "header_tag")
    also("rpm.version", lazy("rpm_second", 1001), "text", "header_tag")


# ------------------------------------------------------------------ 7. package manifests
ZIP_KINDS = "apk|msix|appx|jar|nupkg|whl|ipa|docx|xlsx|pptx|odf"


@section
def _reg_packages():
    fam(r"nupkg_(?:nuspec_)?(?:dependencies_)?target_frameworks", "list", lazy("nupkg_frameworks"))
    fam(r"nupkg_(?:nuspec_)?(?:metadata_)?([a-z0-9_]+)", "text", lazy("nupkg_field"))
    namespace("deb", tokens=("deb", "udeb"), test=is_type("deb"))
    reg("deb", "debian_binary debian_binary_version format_version debian_binary_format_version package_format_version", "text",
        lazy("deb_binary"))
    reg("deb", "ar_member_names member_names archive_member_names ar_members", "list", lazy("deb_members"))
    fam(r"deb_(?:control_)?(?:field_)?([a-z0-9_]+)", "text", lazy("deb_field"))
    namespace("whl", tokens=("whl",), test=is_type("whl"), archive=True)
    fam(r"whl_(metadata_|wheel_|dist_info_metadata_|dist_info_wheel_)?([a-z0-9_]+)", "text", lazy("whl_field"))
    namespace("ipa", tokens=("ipa",), test=is_type("ipa"), archive=True)
    fam(r"ipa_(?:info_plist_|plist_|info_)?([a-z0-9_]+)", "any", lazy("ipa_field"))
    reg("apk", "signing_block_present apk_signing_block_present apk_sig_block_present sig_block_present has_signing_block", "bool",
        lazy("apk_block_present"))
    fam(r"apk_(?:signing_block_|signature_scheme_|signature_|signing_scheme_|apk_signature_scheme_)?(v2|v3|v31)(?:_signature|_block|_scheme)?_present",
        "bool", lazy("apk_scheme_present"))
    fam(r"apk_(?:classes_)?dex_([a-z0-9_]+)", "text", lazy("delegate", "dex", "classes.dex"))
    fam(rf"(?:{ZIP_KINDS})_zip_([a-z0-9_]+)", "text", lazy("delegate", "zip"), heads=ZIP_KINDS.split("|"))
    reg("msix", "block_map_hash_method blockmap_hash_method block_map_hash_algorithm blockmap_hash_algorithm", "forms", lazy("blockmap_hash"))


# ------------------------------------------------------------------ 8. rpm
@section
def _reg_rpm():
    reg("rpm", "header_build_time build_time buildtime header_buildtime tag_buildtime", "unixtime", lazy("rpm_buildtime"), bits=32)
    fam(r"rpm_(?:signature_header_|signature_|header_)(sha1|sha256|md5|size|payload_size)", "text", lazy("rpm_sig"))
    fam(r"rpm_(?:header_|tag_)([a-z0-9_]+)", "any", lazy("rpm_tag"))
    fam(r"rpm_(release|epoch|arch|architecture|summary|license|group|url|vendor|packager|build_host|buildhost|os|source_rpm|sourcerpm|"
        r"payload_format|payload_compressor|payload_compression|payload_flags|rpm_version|rpmversion|base_names|basenames|file_names)", "any",
        lazy("rpm_tag"))


# ------------------------------------------------------------------ 10. OLE
@section
def _reg_ole():
    fam(r"(ole|cfb)_(document_)?summary_information_([a-z0-9_]+)", "text", lazy("ole_summary"), heads=("ole", "cfb"))
    for ns in ("ole", "cfb"):
        reg(ns, "root_clsid root_entry_clsid root_storage_clsid root_class_id clsid class_id", "uuid", lazy("ole_root_clsid"))


# ------------------------------------------------------------------ 11. Windows artifacts
@section
def _reg_windows():
    namespace("task", tokens=("task", "job"), test=is_type("task"))
    fam(r"task_([a-z0-9_]+)", "text", lazy("task_field"))
    fam(r"evtx_first_([a-z_]+)", "text", lazy("evtx_field"))
    reg("regf", "root_key_name root_cell_name root_name root_key root_node_name", "text", lazy("regf_root_name"))
    reg("regf", "root_subkey_names root_key_subkey_names root_subkeys root_key_subkeys", "list", lazy("regf_root_subkeys"))
    reg("regf", "root_subkey_count root_key_subkey_count root_number_of_subkeys", "integer", lazy("regf_root_subkey_count"))
    for field, names, fmt in (("arch", "processor_architecture", "code"), ("ncpu", "number_of_processors processor_count", "integer"),
                              ("major", "major_version os_major_version", "integer"), ("minor", "minor_version os_minor_version", "integer"),
                              ("build", "build_number os_build_number os_build", "integer"), ("platform", "platform_id", "integer"),
                              ("level", "processor_level", "integer"), ("revision", "processor_revision", "number"),
                              ("product_type", "product_type", "integer")):
        spell = [f"{pre}{x}" for x in names.split() for pre in ("system_info_", "")]
        reg("minidump", spell, fmt, lazy("minidump_sysinfo", field), bits=16 if field in ("arch", "revision") else None)
    reg("minidump", "module_count module_list_count module_list_number_of_modules number_of_modules", "integer", lazy("minidump_count", 4))
    reg("minidump", "thread_count thread_list_count thread_list_number_of_threads number_of_threads", "integer", lazy("minidump_count", 3))
    reg("minidump", "stream_types stream_type_ids directory_stream_types", "intlist", lazy("minidump_stream_types"))


# ------------------------------------------------------------------ 12. xar and .pkg, dmg, pdb, nsis, inno
@section
def _reg_containers():
    namespace("xar", tokens=("xar", "pkg"), test=is_type("xar"))
    M.NAMESPACES.add("pkg")
    M.PACK_NAMESPACES.add("pkg")
    for i, names in enumerate(("header_size header_size_bytes", "header_version version format_version",
                               "header_toc_length_compressed toc_length_compressed toc_compressed_size_bytes toc_compressed_length",
                               "header_toc_length_uncompressed toc_length_uncompressed toc_uncompressed_size_bytes toc_uncompressed_length",
                               "header_checksum_algorithm_id header_cksum_alg cksum_alg")):
        reg("xar", names, "integer", lazy("xar_header", i))
    reg("xar", "toc_checksum_style checksum_style checksum_algorithm header_checksum_algorithm toc_checksum_algorithm", "forms", lazy("xar_checksum"))
    for ns in ("xar", "pkg"):
        reg(ns, "toc_file_names file_names member_names toc_names entry_names", "list", lazy("xar_names"))
        reg(ns, "toc_creation_time creation_time", "text", lazy("xar_creation"))
        reg(ns, "package_info_identifier package_identifier identifier bundle_identifier", "text", lazy("pkg_info", "identifier"))
        reg(ns, "package_info_version package_version version", "text", lazy("pkg_info", "version"))
        reg(ns, "package_info_install_location install_location", "text", lazy("pkg_info", "install-location"))
    namespace("dmg", tokens=("dmg",), test=is_type("koly"))
    for names, fmt, at, bits in (("koly_version trailer_version udif_version version", ">I", 4, 32), ("koly_header_size header_size", ">I", 8, 32),
                                 ("koly_flags flags", ">I", 12, 32), ("koly_data_fork_offset data_fork_offset", ">Q", 0x18, 64),
                                 ("koly_data_fork_length data_fork_length koly_data_fork_length_bytes data_fork_size_bytes", ">Q", 0x20, 64),
                                 ("koly_segment_count segment_count", ">I", 0x3C, 32),
                                 ("koly_xml_offset xml_offset plist_offset", ">Q", 0xD8, 64),
                                 ("koly_xml_length xml_length plist_length koly_xml_length_bytes", ">Q", 0xE0, 64),
                                 ("koly_image_variant image_variant", ">I", 0x1E8, 32), ("koly_sector_count sector_count", ">Q", 0x1EC, 64)):
        reg("dmg", names, "integer", lazy("koly_field", fmt, at), bits=bits)
    reg("dmg", "koly_segment_id segment_id udif_segment_id", "uuid", lazy("koly_segment_id"))
    namespace("pdb", tokens=("pdb",), test=is_type("pdb"))
    reg("pdb", "guid pdb_stream_guid info_stream_guid signature_guid pdb_guid unique_id", "uuid", lazy("pdb_field", "guid"))
    reg("pdb", "age pdb_stream_age info_stream_age pdb_age", "integer", lazy("pdb_field", "age"))
    reg("pdb", "signature pdb_stream_signature info_stream_signature timestamp", "unixtime", lazy("pdb_field", "signature"), bits=32)
    reg("pdb", "version pdb_stream_version info_stream_version", "integer", lazy("pdb_field", "version"))
    reg("pdb", "block_size msf_block_size superblock_block_size page_size", "integer", lazy("pdb_field", "block_size"))
    reg("pdb", "block_count msf_block_count superblock_num_blocks num_blocks page_count", "integer", lazy("pdb_field", "blocks"))
    reg("pdb", "stream_count msf_stream_count num_streams", "integer", lazy("pdb_field", "streams"))
    namespace("nsis", tokens=("nsis",), test=is_type("nsis"))
    for i, names in enumerate(("firstheader_offset first_header_offset header_offset overlay_offset", "firstheader_flags first_header_flags flags",
                               "firstheader_header_size first_header_header_size header_size firstheader_length_of_header",
                               "firstheader_archive_size first_header_archive_size archive_size first_header_archive_size_bytes "
                               "firstheader_length_of_all_following_data")):
        reg("nsis", names, "integer", lazy("nsis_field", i), bits=32)
    namespace("inno", tokens=("inno",), test=is_type("inno"))
    reg("inno", "setup_data_version setup_version version data_version", "forms", lazy("inno_version"))
    reg("inno", "setup_data_signature setup_data setup_data_string setup_id", "text", lazy("inno_mark"))


def _jar_manifest_short_alternation():
    """Build B (Day 23 look-ahead): the jar manifest short-form id alternation, GENERATED from
    readers_more's MANIFEST_ATTRS so that EVERY main-section attribute -- not just a hand-picked few --
    routes to the jar_main_attribute -> _manifest_field delegate (unsure 'raw' when present, unsure
    'none' when absent, Unknown otherwise: fail-closed, never plain before the judge accepts a name).
    For each attribute two id spellings are offered -- hyphens to underscores, and camelCase split too
    ('bundle_symbolicname' and 'bundle_symbolic_name') -- and both normalize to the same MANIFEST_KNOWN
    member in the delegate, so the author's spelling is matched either way. Falls back to the Day 14 /
    row 477 explicit names when readers_more is not loaded (load order makes that unreachable in
    practice: readers_more is first in MORE_FILES, this pack later)."""
    import re as _re
    more = PACKS.get("readers_more.py")
    attrs = getattr(more, "MANIFEST_ATTRS", None) if more is not None else None
    if not attrs:
        return ("main_class|created_by|implementation_version|implementation_title|implementation_vendor|"
                "specification_version|bundle_symbolic_name|bundle_version|bundle_name|automatic_module_name|"
                "build_jdk|built_by|manifest_version|class_path|sealed|multi_release")
    forms = set()
    for attr in attrs:
        forms.add(attr.lower().replace("-", "_"))
        parts = []
        for piece in attr.split("-"):
            s = _re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", piece)
            s = _re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
            parts.append(s)
        forms.add("_".join(parts).lower())
    return "|".join(sorted(forms))


# ------------------------------------------------------------------ 13. single fields
@section
def _reg_fields():
    reg("elf", "gnu_debuglink_filename debuglink_filename gnu_debuglink debuglink section_gnu_debuglink_name gnu_debuglink_file", "text",
        lazy("elf_debuglink_name"))
    reg("elf", "gnu_debuglink_crc32 debuglink_crc32 gnu_debuglink_crc debuglink_crc", "integer", lazy("elf_debuglink_crc"), bits=32)
    reg("elf", "dynsym_symbol_count dynamic_symbol_count dynsym_count dynsym_entry_count", "integer", lazy("elf_dynsym_count"))
    reg("macho", "fat_header_magic fat_magic", "integer", lazy("macho_fat_magic"), bits=32)
    reg("7z", "start_header_crc start_header_crc32 signature_header_start_header_crc", "integer", lazy("sevenz_crc", 8), bits=32)
    reg("7z", "next_header_crc next_header_crc32 start_header_next_header_crc", "integer", lazy("sevenz_crc", 28), bits=32)
    reg("bz2", "first_block_crc32 block_header_crc first_block_crc block_crc block_crc32", "integer", lazy("bz2_block_crc"), bits=32)
    reg("class", "header_magic magic", "integer", lazy("class_magic"), bits=32)
    reg("cpio", "header_magic magic", "text", lazy("cpio_magic"))
    reg("pe", "rich_header_xor_key rich_xor_key rich_header_key rich_header_checksum rich_key", "integer", lazy("pe_rich_key"), bits=32)
    reg("pe", "manifest_assembly_identity_name manifest_identity_name", "text",
        lazy("pe_manifest_identity", "name"))
    reg("pe", "manifest_assembly_identity_version manifest_identity_version", "text",
        lazy("pe_manifest_identity", "version"))
    reg("pe", "overlay_offset overlay_file_offset overlay_start_offset overlay_start", "integer", lazy("pe_overlay_offset"), bits=32)
    reg("x509", "subject_key_identifier ski extension_subject_key_identifier subject_key_id", "hex", lazy("x509_ski"))
    # Day 23 look-ahead builds A+B (improvements row 477): the jar manifest short forms, GENERATED from
    # readers_more's MANIFEST_ATTRS (every attribute, not a hand-picked few). class_path/sealed/multi_release
    # and ~17 more short names now reach the jar_main_attribute -> _manifest_field delegate (unsure, fail
    # closed) instead of STOPping with None. Registered here, AFTER readers_more's `jar.manifest_*` family and
    # its explicit reg("jar", class_count...) -- an explicit REG always wins over a family in lookup(), and
    # this family is appended after readers_more's -- so neither is shadowed (class_path != class_count).
    fam(r"jar_(" + _jar_manifest_short_alternation() + r")", "text", lazy("jar_main_attribute"))
    # Build C (row 346; the row 477 residual, Class-Path asked as a JSON array). Class-Path as raw-vs-split
    # DIFFERENT candidates: an explicit reg wins over both the short family above and readers_more's
    # `jar.manifest_*` family, so jar.class_path and jar.manifest_class_path offer the whole space-joined
    # string AND the JSON array of its entries, unsure under a candidate key, never plain before the judge.
    reg("jar", ("class_path", "manifest_class_path"), "forms", lazy("jar_class_path_candidates"))
    reg("mkv", "track_uid tracks_track_uid track_entry_track_uid first_track_uid", "integer", lazy("mkv_track_uid"), bits=64)
