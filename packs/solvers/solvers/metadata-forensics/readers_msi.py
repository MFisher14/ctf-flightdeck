#!/usr/bin/env python3
"""Metadata Forensics reader pack after Day 13 (backlog row 283): the tables of a Windows Installer
database (.msi), its embedded cabinet, and the manifest of an MSIX/AppX package.

properties_strict.py loads this file by name after the other packs and calls register(M) with
itself. Day 13 asked msi.product_code_guid, the Value of the Property table's ProductCode row, and
no shipped reader read an MSI table: readers_formats.py knows the summary stream, the root CLSID and
the stream names. The lane's agent read that one row in a day_patch.py; that reader lives here now,
with the rest of the database.

The one judged name. msi.product_code_guid is registered under exactly that name, so its ledger key
is the one the judge's verdict stands under: metadata.format/msi.product_code_guid, name
`braces_upper` (the text as all four Day 13 installers store it; in the seed since `labels.py
promote metadata`). It is not confirmed in code: it is plain through the ledger or the seed, and
only where the stored text IS that form. A ProductCode stored in another form (lowercase, no
braces) is unsure under a key of its own with the stored text first (row 284,
properties_strict._stored_key). Everything else here is unsure: every property is registered
unconfirmed, a GUID is handed over as M.Stored(text) so that the stored text is the first option,
and a text is offered as stored (`raw`) first.

How an MSI database is stored (read here in plain Python; the compound file itself by olefile):
  stream names   coded by readers_formats.msi_name; a table's stream carries the table mark.
  _StringPool    u16 codepage, u16 flags (0x8000: string ids are 3 bytes wide, else 2), then one
                 (u16 length, u16 reference count) per string; string 0 is the null string.
  _StringData    the strings' bytes, one after another, in the pool's order.
  _Tables        one column: the name (a string id) of every table of the database.
  _Columns       four columns: Table, Number (i2), Name, Type (i2). The type's low byte is a width,
                 0x800 says string, 0x1000 nullable, 0x2000 key.
  a table        column-major: every row's first column, then every row's second, ... A string
                 column is a string id; an integer column is 2 bytes with 0x8000 added or 4 bytes
                 with 0x80000000 added, and a stored 0 is null; a stream column (Binary.Data) is 2
                 bytes. A table that _Tables names and that has no stream has no rows.

The contract of an extractor is the wrapper's: fn(name, data) returns the value read from the
bytes, None when the file is no MSI database or does not hold the table, the row or the cell, or
raises M.Unknown when it does and the bytes do not settle the fact: a pool that is not whole (the
lengths do not sum to _StringData; a string of 64 KiB or more whose two pool entries read more than
one way: _pool_readings), a string id outside the pool, a
table that is not a whole number of rows, two streams of one name, two rows of one name, a text
its codepage does not decode (codepage 0: anything beyond ASCII).

What is here (namespace msi; windows_installer and installer are read as it):
  Property       the Value of one row: product_code, upgrade_code (GUIDs, with and without `_guid`),
                 product_version, product_language, product_name, manufacturer, all_users and the
                 other standard properties, any row as msi.property_<name>; the property names and
                 their count. msi.product_name and msi.manufacturer were the summary stream's
                 Subject and Author (readers_formats.py) and are the Property rows now, the summary's
                 where the table has no such row; msi.package_code is the summary's Revision Number
                 as the GUID it is.
  tables         Component, File, Media, Feature, Directory, FeatureComponents, MsiFileHash, Upgrade,
                 CustomAction, Registry, Shortcut, ServiceInstall, LaunchCondition, Binary, Icon and
                 the sequence tables: every column as msi.<table>_<column> (the one row's value; two
                 rows are Unknown) and msi.<table>_<column>s (the list, in stored order), with the
                 usual spellings beside them (component_guid, file_names, feature_names, ...). Any
                 table's row count (msi.<table>_row_count), column names and column count; the
                 tables _Tables names; the string pool's count and codepage.
  MsiFileHash    the MD5 its four i4 columns hold (the file's 16 digest bytes, four little-endian
                 words).
  cabinet        the embedded cabinet stream (MSCF): its member names, sizes and count, its own
                 size and digests, its compression, and the digests of its members. Stored and
                 MSZIP folders are unpacked here. An LZX folder is handed to 7zz and to macOS's own
                 bsdtar, a Quantum folder to 7zz and to the decoder in this file (_quantum); the
                 folder is read only where none of them refuses it and the ones that unpack it give
                 the same bytes (_cab_decoded). A tool is a subprocess of 0.5 s at most, all of one
                 cabinet's unpacking has 0.6 s, a folder is tried once, and none of it runs for the
                 facts page; the folder is carved out under a name chosen here and written to the
                 tool's standard output (_cab_tool). Held to cabextract on 101 public test cabinets
                 (tests/real/test_real_cab.py). In a
                 cabinet of a set, a member that is whole here is read and one that continues in
                 another cabinet is Unknown. The Media table's Cabinet text is
                 `#artifact.cab` for an embedded stream: msi.cabinet_names offers it as stored and
                 without the `#`.
  msix / appx    a package's AppxManifest.xml (namespace msix; appx is read as it): the Identity
                 element's Name, Publisher, Version and ProcessorArchitecture, the Properties'
                 DisplayName, PublisherDisplayName and Logo, the capabilities, the application ids
                 and executables, the target device families, whether the signature and the block
                 map are there; the package full name, family name and publisher id Windows derives
                 from the Identity (publisher_id). A bundle (.msixbundle, .appxbundle): the bundle
                 manifest's Identity (also under the plain identity names, as the file's own
                 manifest), its Package list, and every inner package's Identity and full name.

Not read, on purpose: a patch's or transform's own tables (an .msp holds storages, an .mst only a
difference), a table with more rows than LIMIT, a member that continues in another cabinet, an LZX
or Quantum folder that does, an inner package of a bundle that is stored twice or encrypted, the
inner packages of a bundle that state more than 64 MiB to unpack, an
encrypted (.emsix) package. Each is None or M.Unknown.
"""
import functools
import hashlib
import io
import re
import struct
import zipfile
import zlib

M = None          # properties_strict, set by register()
RF = None         # readers_formats.py as loaded by properties_strict: _msi, msi_name
SECTIONS = []
LIMIT = 1 << 16            # rows of one table, columns of a schema: more is not read
MAX_STRINGS = 1 << 19      # entries of a string pool
MAX_STREAM = 64 << 20      # bytes of one stream that are read (a table, a cabinet)
MAX_UNPACKED = 64 << 20    # bytes a cabinet folder may unpack to
MAX_MANIFEST = 4 << 20     # bytes of an AppxManifest.xml
NS = "msi"
JUDGED = "msi.product_code_guid"   # Day 13's name, as the ledger keys it (see the docstring)

T_STRING, T_NULLABLE, T_KEY = 0x0800, 0x1000, 0x2000
T_BINARY = 0x0900          # a string column of width 0 with the valid bit: a stream (Binary.Data, Icon.Data)


def section(fn):
    SECTIONS.append(fn)
    return fn


def U(msg):
    raise M.Unknown(msg)


Unavailable = None   # set by register(): the M.Unknown of a decoder that was not asked or did not finish (no tool,
                     # no time, a facts page). It says nothing about the folder, where a decoder's refusal does.


def N(msg):
    raise Unavailable(msg)


def held(fn):
    """fn, with whatever a cut or damaged structure raises turned into Unknown: nothing is established."""
    @functools.wraps(fn)
    def safe(*args):
        try:
            return fn(*args)
        except (M.Unknown, M.Ambiguous):
            raise
        except Exception as e:
            U(f"the bytes do not read as this structure ({type(e).__name__})")
    return safe


WORDS = {}   # (namespace, the words of a name) -> the extractor that holds them (M.words; row 43)


def reg(names, fmt, fn, ns=NS, replace=False):
    """Register one extractor under every <ns>.<name> that no earlier reader holds (`replace`: also
    over an earlier forecast reader, never over a confirmed one). A name whose words another
    extractor already has is left out: synonym() reads an unregistered name by its words, and two
    readers with the same words would make every such name ambiguous (row 43)."""
    names = [names] if isinstance(names, str) else list(names)
    fn = held(fn)
    if fmt not in M.FORMATS:
        raise KeyError(fmt)
    registry, words = M.REG, M.words
    for x in names:
        # every name here is written in lower case with underscores, so it is its own canonical form
        # (register() checks one in passing); the registry entry is what M.prop would write
        key = f"{ns}_{x}"
        old = registry.get(key)
        if old is not None and (not replace or old.confirmed):
            continue
        held_words = words(key)
        if old is not None:
            WORDS[held_words] = fn
        elif WORDS.setdefault(held_words, fn) is not fn:
            continue
        registry[key] = M.Prop(f"{ns}.{x}", fn, fmt, False)
    return fn


def one(values, what):
    """The only value, None when there is none, Unknown when there are several."""
    values = list(values)
    if len(values) > 1:
        U(f"several {what}: the name does not say which one is asked")
    return values[0] if values else None


def squash(name: str) -> str:
    """A name compared the way an id spells it: ProductCode, product_code and PRODUCTCODE are one."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def snake(name: str) -> str:
    """ComponentId -> component_id, Directory_ -> directory, HashPart1 -> hash_part1."""
    return M.canon(re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name))


# ------------------------------------------------------------------ the compound file's streams

class _Streams:
    """The top-level streams of a compound file by their decoded MSI names, read when asked."""

    def __init__(self, d: bytes):
        try:
            import olefile
        except ImportError:
            U("the olefile library is not installed")
        try:
            self.ole = olefile.OleFileIO(io.BytesIO(d))
            self.paths = {}
            for path in self.ole.listdir(streams=True, storages=False):
                if len(path) == 1:
                    self.paths.setdefault(RF.msi_name(path[0]), []).append(path)
        except Exception as e:
            U(f"the compound file could not be read ({type(e).__name__})")

    def names(self, table: bool):
        return [n for n, t in self.paths if t == table]

    def read(self, name: str, table: bool):
        """The bytes of the one stream of this name, None when there is none."""
        paths = self.paths.get((name, table))
        if not paths:
            return None
        if len(paths) != 1:
            U(f"two streams named {M._clean(name, 40)}")
        try:
            if self.ole.get_size(paths[0]) > MAX_STREAM:
                U(f"the stream {M._clean(name, 40)} is larger than is read")
            return self.ole.openstream(paths[0]).read()
        except M.Unknown:
            raise
        except Exception as e:
            U(f"the stream {M._clean(name, 40)} could not be read ({type(e).__name__})")


def _pool_readings(pool: bytes, data: bytes):
    """Every reading of a pool's entries whose lengths sum to the string data exactly, as lists of
    the strings' bytes by id (id 0 is the null string).

    A string of 64 KiB or more takes two entries, the first with a length of 0 and a reference count
    that is not 0. The published accounts of the pair differ, and no installer on hand has one, so
    both are read: the first entry's count is the high word of the length and the second holds the
    low word and the reference count; or the first entry's count is the reference count and the
    second holds the low and the high word. They also leave open whether the empty first entry
    takes a string id of its own. A reading whose lengths do not sum to _StringData is dropped
    here; _db() keeps a reading only when the database's own stream names bear it out."""
    entries = list(struct.iter_unpack("<HH", pool[4:]))
    if not any(ln == 0 and refs for ln, refs in entries):
        ways = [(False, False)]
    else:
        ways = [(high_first, own_id) for high_first in (True, False) for own_id in (False, True)]
    out = []
    for high_first, own_id in ways:
        strings, at, i, whole = [b""], 0, 0, True
        while i < len(entries):
            ln, refs = entries[i]
            if ln == 0 and refs:
                if i + 1 >= len(entries):
                    whole = False
                    break
                low, other = entries[i + 1]
                ln = ((refs if high_first else other) << 16) | low
                if own_id:
                    strings.append(b"")
                i += 1
            strings.append(data[at:at + ln])
            at += ln
            i += 1
        if whole and at == len(data) and strings not in out:
            out.append(strings)
    return out


def _schema(streams, strings, codepage, width):
    """The database dict of one pool reading (see _db); Unknown when _Tables or _Columns is not whole."""
    db = {"streams": streams, "strings": strings, "codepage": codepage, "width": width}
    tables = streams.read("_Tables", True)
    columns = streams.read("_Columns", True)
    if tables is None or columns is None:
        U("no _Tables and _Columns: the database's schema is not there")
    if len(tables) % width:
        U("a _Tables stream that is not whole")
    db["tables"] = [_string(db, int.from_bytes(tables[i:i + width], "little")) for i in range(0, len(tables), width)]
    if len(set(db["tables"])) != len(db["tables"]) or None in db["tables"]:
        U("a _Tables stream that names a table twice or not at all")
    row = 2 * width + 4
    if len(columns) % row:
        U("a _Columns stream that is not whole")
    n = len(columns) // row
    if n > LIMIT:
        U("more columns than are read")
    by = {}
    for r in range(n):
        table = _string(db, int.from_bytes(columns[r * width:(r + 1) * width], "little"))
        number = struct.unpack_from("<H", columns, n * width + 2 * r)[0] ^ 0x8000
        name = _string(db, int.from_bytes(columns[n * (width + 2) + r * width:n * (width + 2) + (r + 1) * width], "little"))
        kind = struct.unpack_from("<H", columns, n * (2 * width + 2) + 2 * r)[0] ^ 0x8000
        if table is None or name is None:
            U("a column with no table or no name")
        by.setdefault(table, []).append((number, name, kind))
    db["columns"] = {}
    for table, cols in by.items():
        cols.sort()
        if [c[0] for c in cols] != list(range(1, len(cols) + 1)):
            U(f"the columns of {M._clean(table, 40)} are not numbered 1 to {len(cols)}")
        db["columns"][table] = [(name, kind) for _, name, kind in cols]
    return db


def _reads(db: dict, tables) -> bool:
    """Whether every one of these table streams is whole rows of its columns under this reading of
    the pool, with every string id inside the pool and no key cell null."""
    for table in tables:
        try:
            names, rows = _rows(db, table)
        except M.Unknown:
            return False
        keys = [i for i, (_, kind) in enumerate(db["columns"][table]) if kind & T_KEY]
        if any(row[i] is None for row in rows for i in keys):
            return False
    return True


SYSTEM_STREAMS = ("_StringPool", "_StringData", "_Tables", "_Columns", "_Validation")


@functools.lru_cache(maxsize=8)
def _db(d: bytes):
    """An MSI database's string pool and schema, or None when the file is not one or holds none of
    the four streams of a database:
    {"streams", "strings" (bytes, by id), "codepage", "width" (bytes of a string id), "tables"
    (the names _Tables lists), "columns" {table: [(name, type)] in column order}}."""
    if RF._msi(d) is None:
        return None
    streams = _Streams(d)
    pool, data = streams.read("_StringPool", True), streams.read("_StringData", True)
    if not any(name in ("_StringPool", "_StringData", "_Tables", "_Columns") for name in streams.names(True)):
        return None     # an installer's compound file with no database in it (a summary stream alone)
    if pool is None or data is None:
        U("no _StringPool and _StringData: the database's strings are not there")
    if len(pool) < 4 or len(pool) % 4:
        U("a string pool that is not whole")
    codepage, flags = struct.unpack_from("<HH", pool, 0)
    width = 3 if flags & 0x8000 else 2
    if len(pool) // 4 > MAX_STRINGS:
        U("a string pool larger than is read")
    readings = _pool_readings(pool, data)
    if not readings:
        U("a string pool whose lengths do not sum to the string data")
    if len(readings) == 1 and not any(ln == 0 and refs for ln, refs in struct.iter_unpack("<HH", pool[4:])):
        return _schema(streams, readings[0], codepage, width)
    # A pool with a string of 64 KiB or more: a reading stands only when the schema it gives is
    # whole, every table stream of the file is a table it names (the stream names are stored apart
    # from the pool) and every such stream is whole rows of the columns the reading gives that
    # table, with no key cell null. A reading that numbers the strings wrongly gives tables the
    # columns of other tables and does not survive this; where two readings do, nothing is read.
    stored = {name for name in streams.names(True) if name not in SYSTEM_STREAMS}
    kept = []
    for strings in readings:
        try:
            db = _schema(streams, strings, codepage, width)
        except M.Unknown:
            continue
        if stored <= set(db["tables"]) and set(db["columns"]) <= set(db["tables"]) and _reads(db, stored):
            kept.append(db)
    if len(kept) != 1:
        U("a string of 64 KiB or more whose pool entry " + ("reads more than one way" if kept else "gives no whole schema"))
    return kept[0]


def _string(db, sid: int):
    """The text of a string id, None for the null string."""
    if sid == 0:
        return None
    if sid >= len(db["strings"]):
        U("a string id outside the pool")
    raw, cp = db["strings"][sid], db["codepage"]
    try:
        return raw.decode("ascii" if cp == 0 else "utf-8" if cp == 65001 else f"cp{cp}")
    except (UnicodeDecodeError, LookupError):
        U("a string its codepage does not decode")


def _table(d: bytes, table: str):
    """(column names, rows) of one table, rows as tuples in stored order; None when the file is no
    MSI database or _Tables does not name the table. A stream column's cell is None."""
    db = _db(d)
    return None if db is None else _rows(db, table)


def _rows(db: dict, table: str):
    """_table() for a database dict."""
    if table not in db["tables"]:
        return None
    cached = db.setdefault("rows", {})
    if table in cached:
        return cached[table]
    cols = db["columns"].get(table)
    if not cols:
        U(f"the table {M._clean(table, 40)} has no columns")
    sizes = []
    for _, kind in cols:
        if kind & ~T_NULLABLE & 0xFFFF == T_BINARY:
            sizes.append(2)
        elif kind & T_STRING:
            sizes.append(db["width"])
        elif kind & 0xFF <= 2:
            sizes.append(2)
        elif kind & 0xFF == 4:
            sizes.append(4)
        else:
            U("a column of a width the format does not have")
    body = db["streams"].read(table, True) or b""
    if len(body) % sum(sizes):
        U(f"the table {M._clean(table, 40)} is not a whole number of rows")
    n = len(body) // sum(sizes)
    if n > LIMIT:
        U(f"the table {M._clean(table, 40)} has more rows than are read")
    out, at = [], 0
    for (_, kind), size in zip(cols, sizes):
        cells = []
        for r in range(n):
            v = int.from_bytes(body[at + r * size:at + (r + 1) * size], "little")
            if kind & ~T_NULLABLE & 0xFFFF == T_BINARY:
                cells.append(None)
            elif kind & T_STRING:
                cells.append(_string(db, v))
            else:
                cells.append(None if v == 0 else v - (0x8000 if size == 2 else 0x80000000))
        out.append(cells)
        at += n * size
    cached[table] = ([name for name, _ in cols], list(zip(*out)) if n else [])
    return cached[table]


def _column(d: bytes, table: str, column: str):
    """Every row's cell of one column, in stored order; None when the table or the column is not there."""
    t = _table(d, table)
    if t is None or column not in t[0]:
        return None
    i = t[0].index(column)
    return [row[i] for row in t[1]]


def _property(d: bytes, name: str):
    """The Value of the Property table's one row of this name, None when there is no such row."""
    t = _table(d, "Property")
    if t is None:
        return None
    if t[0][:2] != ["Property", "Value"]:
        U("a Property table that is not (Property, Value)")
    hits = [row[1] for row in t[1] if row[0] == name]
    if len(hits) > 1:
        U("two rows of that name")
    return hits[0] if hits else None


def guid(v):
    """A GUID read as text, handed over as stored (M.Stored: the stored form is the first option)."""
    if v is None:
        return None
    if not isinstance(v, str) or not M._GUID_STORED.fullmatch(v):
        U("a value that is no GUID")
    return M.Stored(v)


# ------------------------------------------------------------------ the Property table

# name -> (class, spellings). The class of a GUID is uuid; every other Value is the text it is.
PROPERTIES = {
    "ProductCode": ("uuid", ("product_code_guid", "product_code", "property_product_code", "product_guid", "product_code_property")),
    "UpgradeCode": ("uuid", ("upgrade_code_guid", "upgrade_code", "property_upgrade_code", "upgrade_guid", "upgrade_code_property")),
    "ProductVersion": ("text", ("product_version", "property_product_version", "version", "product_version_property")),
    "ProductLanguage": ("text", ("product_language", "property_product_language", "product_language_id", "product_lcid")),
    "ProductName": ("text", ("product_name", "property_product_name", "product_name_property")),
    "Manufacturer": ("text", ("manufacturer", "property_manufacturer", "manufacturer_property")),
    "ALLUSERS": ("text", ("all_users", "allusers", "property_all_users", "property_allusers")),
    "ARPCONTACT": ("text", ("arp_contact", "arpcontact")), "ARPHELPLINK": ("text", ("arp_help_link", "arphelplink")),
    "ARPURLINFOABOUT": ("text", ("arp_url_info_about", "arpurlinfoabout")),
    "ARPCOMMENTS": ("text", ("arp_comments", "arpcomments")), "ARPPRODUCTICON": ("text", ("arp_product_icon", "arpproducticon")),
    "ARPNOMODIFY": ("text", ("arp_no_modify", "arpnomodify")), "ARPNOREPAIR": ("text", ("arp_no_repair", "arpnorepair")),
    "ARPNOREMOVE": ("text", ("arp_no_remove", "arpnoremove")),
    "MSIINSTALLPERUSER": ("text", ("msi_install_per_user", "msiinstallperuser", "install_per_user")),
    "REINSTALLMODE": ("text", ("reinstall_mode", "reinstallmode")), "INSTALLLEVEL": ("text", ("install_level", "installlevel")),
    "SecureCustomProperties": ("text", ("secure_custom_properties",)), "MsiHiddenProperties": ("text", ("msi_hidden_properties", "hidden_properties")),
    "DefaultUIFont": ("text", ("default_ui_font",)), "LIMITUI": ("text", ("limit_ui", "limitui")),
}


STANDARD_PROPERTIES = {x.lower() for x in (
    "ProductCode ProductName ProductVersion ProductLanguage Manufacturer UpgradeCode ALLUSERS ARPCOMMENTS ARPCONTACT ARPHELPLINK "
    "ARPHELPTELEPHONE ARPINSTALLLOCATION ARPNOMODIFY ARPNOREMOVE ARPNOREPAIR ARPPRODUCTICON ARPREADME ARPSIZE ARPSYSTEMCOMPONENT "
    "ARPURLINFOABOUT ARPURLUPDATEINFO INSTALLLEVEL REINSTALLMODE SecureCustomProperties MSIFASTINSTALL MSIRMSHUTDOWN "
    "DefaultUIFont LIMITUI INSTALLDIR TARGETDIR REBOOT MSIINSTALLPERUSER DISABLEROLLBACK").split()}


@section
def _reg_property():
    for name, (fmt, spellings) in PROPERTIES.items():
        read = (lambda n, d, name=name: guid(_property(d, name))) if fmt == "uuid" else (lambda n, d, name=name: _property(d, name))
        if name in ("ProductName", "Manufacturer"):
            # readers_formats.py reads these two names from the summary stream (Subject, Author). The
            # Property row is the installer's own statement; the summary's stands where there is no
            # row, and where the file's tables do not read at all (the answer is unsure either way).
            old, rest = M.REG.get(M.canon(f"{NS}.{spellings[0]}")), read

            def read(n, d, rest=rest, old=old):
                try:
                    v = rest(n, d)
                except M.Unknown:
                    if old is None:
                        raise
                    v = None
                return v if v is not None or old is None else old.fn(n, d)
            reg(spellings[0], "any", read, replace=True)
            reg(spellings[1:], fmt, rest)
            continue
        reg(spellings, fmt, read)

    def named(n, d, field):
        """Any row by its name as an id spells it (msi.property_arp_system_component)."""
        t = _table(d, "Property")
        if t is None:
            return None
        want = squash(field)
        rows = [row[1] for row in t[1] if row[0] is not None and squash(row[0]) == want]
        if not rows and want.endswith("guid"):   # msi.property_upgrade_code_guid: the form word behind the row's name
            rows = [row[1] for row in t[1] if row[0] is not None and squash(row[0]) == want[:-4]
                    and isinstance(row[1], str) and M._GUID_STORED.fullmatch(row[1])]
        if not rows and want not in STANDARD_PROPERTIES:
            # Day 14 look-ahead: `none` only for a property of Windows Installer's own list
            U(f"the Property table has no row {field}, and it is not one of the standard properties")
        return one(rows, "rows of that name")
    M.family(r"msi_property_(?!names$|count$|name_list$|row_count$|rows$|values$|table_|column)(.+?)(?:_value)?", "text")(held(named))

    names = lambda d: (lambda c: None if c is None else [x for x in c if x])(_column(d, "Property", "Property"))   # noqa: E731
    reg(["property_names", "properties", "property_name_list", "property_table_names", "property_keys"], "list",
        lambda n, d: names(d) or None)
    reg(["property_count", "properties_count", "number_of_properties", "property_table_count"], "integer",
        lambda n, d: (lambda v: None if v is None else len(v))(names(d)))
    reg(["property_values"], "list",
        lambda n, d: (lambda c: None if c is None else [x for x in c if x] or None)(_column(d, "Property", "Value")))

    # The package code: the summary stream's Revision Number (readers_formats.py), as the GUID it is.
    old = M.REG.get(M.canon("msi.revision_number"))
    if old is not None:
        def package_code(n, d, old=old):
            v = old.fn(n, d)
            if v is None:
                return None
            if isinstance(v, str) and M._GUID_STORED.fullmatch(v):
                return M.Stored(v)
            if not isinstance(v, str) or not v.strip():
                U("a Revision Number that is no text")
            # not exactly one GUID (a patch lists several): the text as it stands, as before this pack
            raise M.Ambiguous([("raw", v)] + ([("trimmed", v.strip())] if v.strip() != v else []))
        reg(["package_code_guid", "package_code", "summary_package_code", "package_guid"], "uuid", package_code, replace=True)


# ------------------------------------------------------------------ the other tables

# table -> columns in schema order; `:i` marks an integer column. Read by name from the file's own
# _Columns, so a file whose table differs gives None for the column it does not have.
SCHEMA = {
    "Component": ("Component", "ComponentId", "Directory_", "Attributes:i", "Condition", "KeyPath"),
    "File": ("File", "Component_", "FileName", "FileSize:i", "Version", "Language", "Attributes:i", "Sequence:i"),
    "Media": ("DiskId:i", "LastSequence:i", "DiskPrompt", "Cabinet", "VolumeLabel", "Source"),
    "Feature": ("Feature", "Feature_Parent", "Title", "Description", "Display:i", "Level:i", "Directory_", "Attributes:i"),
    "Directory": ("Directory", "Directory_Parent", "DefaultDir"),
    "FeatureComponents": ("Feature_", "Component_"),
    "MsiFileHash": ("File_", "Options:i", "HashPart1:i", "HashPart2:i", "HashPart3:i", "HashPart4:i"),
    "Upgrade": ("UpgradeCode", "VersionMin", "VersionMax", "Language", "Attributes:i", "Remove", "ActionProperty"),
    "CustomAction": ("Action", "Type:i", "Source", "Target", "ExtendedType:i"),
    "Registry": ("Registry", "Root:i", "Key", "Name", "Value", "Component_"),
    "Shortcut": ("Shortcut", "Directory_", "Name", "Component_", "Target", "Arguments", "Description", "Hotkey:i", "Icon_",
                 "IconIndex:i", "ShowCmd:i", "WkDir"),
    "ServiceInstall": ("ServiceInstall", "Name", "DisplayName", "ServiceType:i", "StartType:i", "ErrorControl:i",
                       "LoadOrderGroup", "Dependencies", "StartName", "Arguments", "Component_", "Description"),
    "LaunchCondition": ("Condition", "Description"),
    "Binary": ("Name",), "Icon": ("Name",),
    "InstallExecuteSequence": ("Action", "Condition", "Sequence:i"), "InstallUISequence": ("Action", "Condition", "Sequence:i"),
    "AdminExecuteSequence": ("Action", "Condition", "Sequence:i"), "AdminUISequence": ("Action", "Condition", "Sequence:i"),
    "AdvtExecuteSequence": ("Action", "Condition", "Sequence:i"),
}


def cell(table, column):
    """The one row's cell (two rows: Unknown; no row, or a null cell: None)."""
    def fn(n, d):
        c = _column(d, table, column)
        return None if c is None else one(c, f"rows in {table}")
    return fn


def cells(table, column):
    """Every row's cell that is not null, in stored order; None when there is none."""
    def fn(n, d):
        c = _column(d, table, column)
        return None if c is None else [x for x in c if x is not None] or None
    return fn


def count(table):
    def fn(n, d):
        t = _table(d, table)
        return None if t is None else len(t[1])
    return fn


def _split_names(values, part):
    """MSI's `short|long` file names and `target:source` directories: the long (last) or short part."""
    return [v.split("|")[-1 if part == "long" else 0] for v in values]


@section
def _reg_tables():
    # the usual spellings first, so that the generated <table>_<column> names never take them
    reg(["component_guid", "component_id", "component_id_guid", "component_code", "component_guid_id", "component_component_id"],
        "uuid", lambda n, d: guid(cell("Component", "ComponentId")(n, d)))
    reg(["component_guids", "component_ids", "component_codes", "component_component_ids"], "list", cells("Component", "ComponentId"))
    reg(["component_names", "components", "component_keys", "component_list"], "list", cells("Component", "Component"))
    reg(["component_name", "component_key"], "text", cell("Component", "Component"))
    reg(["component_count", "components_count", "number_of_components"], "integer", count("Component"))
    reg(["component_key_path", "key_path"], "text", cell("Component", "KeyPath"))

    def file_names(part):
        def fn(n, d):
            v = cells("File", "FileName")(n, d)
            if v is None:
                return None
            if part is None and any("|" in x for x in v):
                U("a FileName that holds a short and a long name: ask msi.file_long_names or msi.file_short_names")
            return v if part is None else _split_names(v, part)
        return fn
    reg(["file_names", "file_table_names", "file_name_list", "installed_file_names", "payload_file_names"], "list", file_names(None))
    reg(["file_long_names", "long_file_names"], "list", file_names("long"))
    reg(["file_short_names", "short_file_names"], "list", file_names("short"))
    reg(["file_name", "installed_file_name", "payload_file_name"], "text", lambda n, d: one(file_names(None)(n, d) or [], "rows in File"))
    reg(["file_long_name"], "text", lambda n, d: one(file_names("long")(n, d) or [], "rows in File"))
    reg(["file_keys", "file_ids", "file_identifiers"], "list", cells("File", "File"))
    reg(["file_key", "file_id", "file_identifier"], "text", cell("File", "File"))
    reg(["file_count", "files_count", "number_of_files", "installed_file_count", "file_table_count"], "integer", count("File"))
    reg(["file_sizes", "file_table_sizes", "installed_file_sizes"], "intlist", cells("File", "FileSize"))
    reg(["installed_file_size", "payload_file_size", "file_table_file_size"], "integer", cell("File", "FileSize"))
    reg(["feature_names", "features", "feature_keys", "feature_list"], "list", cells("Feature", "Feature"))
    reg(["feature_name", "feature_key"], "text", cell("Feature", "Feature"))
    reg(["feature_titles"], "list", cells("Feature", "Title"))
    reg(["feature_count", "features_count", "number_of_features"], "integer", count("Feature"))
    reg(["directory_names", "directories", "directory_keys", "directory_list"], "list", cells("Directory", "Directory"))
    reg(["directory_count", "directories_count", "number_of_directories"], "integer", count("Directory"))
    reg(["default_dirs", "directory_default_dirs"], "list", cells("Directory", "DefaultDir"))
    reg(["media_count", "disk_count", "media_table_count"], "integer", count("Media"))
    reg(["custom_action_names", "custom_actions", "custom_action_list"], "list", cells("CustomAction", "Action"))
    reg(["custom_action_count", "number_of_custom_actions"], "integer", count("CustomAction"))
    reg(["binary_names", "binary_table_names", "binary_stream_names"], "list", cells("Binary", "Name"))
    reg(["icon_names", "icon_table_names"], "list", cells("Icon", "Name"))
    reg(["upgrade_table_upgrade_code", "upgrade_table_upgrade_code_guid"], "uuid",
        lambda n, d: guid(cell("Upgrade", "UpgradeCode")(n, d)))
    reg(["launch_conditions", "launch_condition_list"], "list", cells("LaunchCondition", "Condition"))

    def cabinets(n, d):
        """Media.Cabinet: one cabinet as stored and, for an embedded stream, without its `#`."""
        v = cells("Media", "Cabinet")(n, d)
        if v is None:
            return None
        if len(v) > 1:
            raise M.Ambiguous([(name, text) for name, text in (("comma", ",".join(v)), ("json_compact", M._json(v)))])
        return [("raw", v[0])] + ([("bare", v[0][1:])] if v[0].startswith("#") and len(v[0]) > 1 else [])
    reg(["cabinet_names", "cabinet_name", "media_cabinet", "media_cabinets", "media_cabinet_name", "cabinets", "cabinet",
         "embedded_cabinet_name", "cabinet_stream_name"], "forms", cabinets)

    for table, columns in SCHEMA.items():
        for spec in columns:
            column, _, integer = spec.partition(":")
            name = f"{snake(table)}_{snake(column)}"
            reg(name, "integer" if integer else "text", cell(table, column))
            plural = [f"{name}_list"] if name[-1] == "s" or name[-1].isdigit() else [f"{name}s", f"{name}_list"]
            reg(plural, "intlist" if integer else "list", cells(table, column))

    def md5(n, d):
        t = _table(d, "MsiFileHash")
        if t is None:
            return None
        if t[0] != ["File_", "Options", "HashPart1", "HashPart2", "HashPart3", "HashPart4"]:
            U("an MsiFileHash table of another shape")
        row = one(t[1], "rows in MsiFileHash")
        if row is None:
            return None
        if any(x is None for x in row[2:]):
            U("a hash part that is null")
        return struct.pack("<4i", *row[2:]).hex()
    reg(["file_hash_md5", "msi_file_hash_md5", "msi_file_hash", "file_hash", "msifilehash_md5", "msifilehash", "file_table_md5",
         "installed_file_md5", "payload_md5", "payload_file_md5"], "hex", md5)

    # the schema itself
    def declared(n, d):
        db = _db(d)
        return None if db is None else sorted(db["tables"]) or None
    reg(["declared_table_names", "all_table_names", "schema_table_names", "tables_declared"], "list", declared)
    reg(["declared_table_count", "all_table_count", "schema_table_count"], "integer",
        lambda n, d: (lambda db: None if db is None else len(db["tables"]))(_db(d)))

    def populated(n, d):
        db = _db(d)
        if db is None:
            return None
        return sorted(t for t in db["tables"] if _table(d, t)[1]) or None
    reg(["populated_table_names", "non_empty_table_names", "tables_with_rows"], "list", populated)
    reg(["populated_table_count", "non_empty_table_count"], "integer", lambda n, d: (lambda v: None if v is None else len(v))(
        (lambda db: None if db is None else [t for t in db["tables"] if _table(d, t)[1]])(_db(d))))
    reg(["string_count", "string_pool_count", "string_pool_string_count", "string_pool_entries"], "integer",
        lambda n, d: (lambda db: None if db is None else len(db["strings"]) - 1)(_db(d)))
    reg(["string_pool_codepage", "database_codepage", "string_codepage"], "integer",
        lambda n, d: (lambda db: None if db is None else db["codepage"])(_db(d)))
    reg(["string_id_width", "string_id_bytes", "string_reference_size"], "integer",
        lambda n, d: (lambda db: None if db is None else db["width"])(_db(d)))

    def the_table(d, word):
        """The one table whose name an id spells as `word`, None when the file names no such table."""
        db = _db(d)
        if db is None:
            return None
        return one([t for t in db["tables"] if squash(t) == squash(word)], "tables of that name")

    def rows_of(n, d, word):
        t = the_table(d, word)
        return None if t is None else len(_table(d, t)[1])
    M.family(r"msi_(.+?)_(?:table_)?(?:row_count|rows)", "integer")(held(rows_of))

    def columns_of(n, d, word):
        t = the_table(d, word)
        return None if t is None else _table(d, t)[0]
    M.family(r"msi_(.+?)_(?:table_)?(?:column_names|columns)", "list")(held(columns_of))

    def column_count(n, d, word):
        t = the_table(d, word)
        return None if t is None else len(_table(d, t)[0])
    M.family(r"msi_(.+?)_(?:table_)?column_count", "integer")(held(column_count))


# ------------------------------------------------------------------ the embedded cabinet

CAB_METHODS = {0: "none", 1: "mszip", 2: "quantum", 3: "lzx"}
CAB_FROM_PREV, CAB_TO_NEXT, CAB_BOTH = 0xFFFD, 0xFFFE, 0xFFFF     # CFFILE.iFolder of a member that continues elsewhere
SEVENZIP = ("/opt/homebrew/bin/7zz", "/usr/local/bin/7zz", "/usr/bin/7zz")
BSDTAR = ("/usr/bin/bsdtar",)   # libarchive, part of macOS: a second LZX decoder (it has no Quantum)
SEVENZIP_SECONDS = 0.5     # one run of a tool; the lane's solve cap inside a timed window is 1.5 s
SEVENZIP_BUDGET = 0.6      # everything one cabinet's LZX and Quantum folders may cost together: tools and the decoder here
CAB_REQUIRE_TWO = False    # True: an LZX or Quantum folder is read only where two decoders unpacked it (and agree)
CAB_REFUSAL_VETOES = (2, 3)   # the methods where one decoder's refusal of a folder leaves it unread (see _cab_decoded)


def _cab_parse(b: bytes):
    """A cabinet's header: {"folders": [(data offset, blocks, method, the type word)], "files": [(name
    or None where it does not decode, size, offset in its folder, folder)], "reserve": bytes of each block's reserve, "from_prev" and
    "to_next": whether a member continues from the previous or into the next cabinet of a set}.
    Unknown when it is not whole."""
    if b[:4] != b"MSCF" or len(b) < 36:
        U("no cabinet header")
    size, files_at, _, minor, major, nfolders, nfiles, flags = struct.unpack_from("<I4xI4sBBHHH", b, 8)
    if size != len(b):
        U("a cabinet whose stated size is not the stream's")
    if (major, minor) != (1, 3):
        U("a cabinet of another version")
    at, r_header, r_folder, r_data = 36, 0, 0, 0
    if flags & 4:
        r_header, r_folder, r_data = struct.unpack_from("<HBB", b, at)
        at += 4 + r_header
    for bit in (1, 2):                                  # the previous and the next cabinet of a set: two names each
        if flags & bit:
            for _ in range(2):
                at = b.index(b"\x00", at) + 1
    folders = []
    for _ in range(nfolders):
        start, blocks, kind = struct.unpack_from("<IHH", b, at)
        folders.append((start, blocks, kind & 0xF, kind))
        at += 8 + r_folder
    files, at = [], files_at
    for _ in range(nfiles):
        fsize, offset, folder, _, _, attribs = struct.unpack_from("<IIHHHH", b, at)
        end = b.index(b"\x00", at + 16)
        raw = b[at + 16:end]
        try:
            name = raw.decode("utf-8" if attribs & 0x80 else "ascii")
        except UnicodeDecodeError:
            name = None      # a name in a code page the cabinet does not state: its bytes are still read, its name is not
        files.append((name, fsize, offset, folder))
        at = end + 1
    return {"folders": folders, "files": files, "reserve": r_data, "unpacked": {}, "failed": {}, "spent": 0.0,
            "from_prev": any(f[3] in (CAB_FROM_PREV, CAB_BOTH) for f in files),
            "to_next": any(f[3] in (CAB_TO_NEXT, CAB_BOTH) for f in files)}


def _cab_checksum(data: bytes, seed: int) -> int:
    """The cabinet format's checksum: the XOR of the data's little-endian 32-bit words, its last one
    to three bytes taken first-byte-highest (held to the four Day 13 cabinets by the test)."""
    n = len(data) // 4
    for (word,) in struct.iter_unpack("<I", data[:n * 4]):
        seed ^= word
    tail, word = data[n * 4:], 0
    for byte in tail:
        word = word << 8 | byte
    return seed ^ word


def _cab_blocks(b: bytes, cab: dict, index: int):
    """[(packed bytes, unpacked size)] of one folder's data blocks, as the cabinet holds them. A block
    that states a checksum must have it (a stated 0 is none; with per-block reserve bytes, whose
    place in the sum no cabinet on hand shows, it is not held)."""
    at, blocks = cab["folders"][index][:2]
    out = []
    for _ in range(blocks):
        stated, packed, unpacked = struct.unpack_from("<IHH", b, at)
        head = b[at + 4:at + 8]
        at += 8 + cab["reserve"]
        body = b[at:at + packed]
        if len(body) != packed:
            U("a data block that runs past the cabinet")
        if stated and not cab["reserve"] and _cab_checksum(head, _cab_checksum(body, 0)) != stated:
            U("a data block whose checksum does not hold")
        at += packed
        out.append((body, unpacked))
    return out


def _sevenzip():
    import os
    import shutil
    return next((p for p in SEVENZIP if os.access(p, os.X_OK)), None) or shutil.which("7zz")


def _carve(b: bytes, cab: dict, index: int):
    """(a cabinet of one folder with ONE member that spans it, under a name chosen here; the folder's
    stated unpacked size). The blocks are the cabinet's own, each already held to its checksum."""
    blocks = _cab_blocks(b, cab, index)
    total = sum(u for _, u in blocks)
    if not blocks or total == 0 or total > MAX_UNPACKED:
        U("a folder with no data, or larger than is unpacked")
    name = b"folder.bin\x00"
    files_at = 36 + 8
    data_at = files_at + 16 + len(name)
    body = b"".join(struct.pack("<IHH", 0, len(packed), unpacked) + packed for packed, unpacked in blocks)
    carved = (b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, data_at + len(body), 0, files_at, 0, 3, 1, 1, 1, 0, 0, 0)
              + struct.pack("<IHH", data_at, len(blocks), cab["folders"][index][3])
              + struct.pack("<IIHHHH", total, 0, 0, 0, 0, 0x20) + name + body)
    return carved, total


def _cab_tool(b: bytes, cab: dict, index: int, tool, arguments, what: str) -> bytes:
    """One whole folder unpacked by a tool of the machine. The folder is written out as a cabinet of
    its own (_carve) into a private temporary directory, and the tool writes its one member to its
    standard output, so nothing the cabinet names is created and nothing it holds is run. A missing
    tool, an exit code other than 0, a time over SEVENZIP_SECONDS (and over SEVENZIP_BUDGET for the
    cabinet's folders together) is Unavailable: the tool said nothing about the folder. An exit code
    other than 0 or an output that is not the folder's stated size is Unknown: the tool refused the
    folder. Never run for the facts page (M.FACTS_PAGE)."""
    import os
    import shutil
    import signal
    import subprocess
    import tempfile
    import time
    if M.FACTS_PAGE[0]:
        N("an LZX or Quantum folder is not unpacked for a facts page")
    carved, total = _carve(b, cab, index)
    if tool is None:
        N(f"{what} is not installed")
    limit = min(SEVENZIP_SECONDS, SEVENZIP_BUDGET - cab["spent"])
    if limit < 0.05:
        N(f"the {SEVENZIP_BUDGET:g} s this cabinet has for unpacking are spent")
    folder = tempfile.mkdtemp(prefix="huntress-cab-")
    started = time.monotonic()
    try:
        path = os.path.join(folder, "folder.cab")
        with open(path, "wb") as fh:
            fh.write(carved)
        try:   # a session of its own, so that on a timeout the tool and anything it started end together
            proc = subprocess.Popen([tool] + arguments + [path], cwd=folder, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": folder})
        except OSError as e:
            N(f"{what} could not be run ({type(e).__name__})")
        try:
            out, _ = proc.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            try:
                proc.communicate(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
            N(f"{what} did not unpack the folder within {limit:.2g} s")
    finally:
        cab["spent"] += time.monotonic() - started
        shutil.rmtree(folder, ignore_errors=True)
    if proc.returncode != 0 or len(out) != total:
        U(f"{what} did not unpack the folder to its stated size")
    return out


def _cab_7z(b: bytes, cab: dict, index: int) -> bytes:
    """One whole folder unpacked by 7-Zip (LZX and Quantum): see _cab_tool."""
    return _cab_tool(b, cab, index, _sevenzip(), ["e", "-so", "-bd", "-y", "--"], "7zz")


def _cab_bsdtar(b: bytes, cab: dict, index: int) -> bytes:
    """One whole LZX folder unpacked by libarchive's bsdtar, which macOS ships: see _cab_tool."""
    import os
    return _cab_tool(b, cab, index, next((t for t in BSDTAR if os.access(t, os.X_OK)), None), ["-xOf"], "bsdtar")


# Quantum, decoded here: an adaptive arithmetic coder over seven models (four for the literals by their
# top two bits, three for match offsets by match length, one for long lengths, one that selects among
# them), written after the format as libmspack's qtmd.c reads it. Each data block of the cabinet is one
# frame of at most 32 KiB: the coder starts anew, the models and the window go on. Held to libmspack
# (cabextract 1.11) and to 7zz 26.03 on the one real Quantum stream of libmspack's test cabinets and
# on nine folders of 26 to 200,000 bytes in five window sizes built by a mirror encoder that gives
# that real stream back byte for byte (tests/real/test_real_cab.py rebuilds them and holds their
# digests; tests/test_day13_metadata_msi.py has the encoder). Slow, as Python is: about 1.5 s a megabyte.
_QTM_EXTRA = [0, 0, 0, 0] + [n for n in range(1, 20) for _ in (0, 1)]
_QTM_BASE = [sum(1 << e for e in _QTM_EXTRA[:i]) for i in range(42)]
_QTM_LEN_EXTRA = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
_QTM_LEN_BASE = [sum(1 << e for e in _QTM_LEN_EXTRA[:i]) for i in range(26)] + [254]


def _qtm_model(start: int, n: int) -> list:
    """[the symbols, most frequent first; their cumulative frequencies and a closing 0; updates until a re-sort]."""
    return [list(range(start, start + n)), [n - i for i in range(n + 1)], 4]


def _qtm_update(m: list):
    syms, cum = m[0], m[1]
    n = len(syms)
    m[2] -= 1
    if m[2]:
        for i in range(n - 1, -1, -1):
            cum[i] >>= 1
            if cum[i] <= cum[i + 1]:
                cum[i] = cum[i + 1] + 1
        return
    m[2] = 50
    freq = [((cum[i] - cum[i + 1]) + 1) >> 1 for i in range(n)]
    for i in range(n - 1):               # the format's own in-place selection sort: its order among equals matters
        for j in range(i + 1, n):
            if freq[i] < freq[j]:
                freq[i], freq[j] = freq[j], freq[i]
                syms[i], syms[j] = syms[j], syms[i]
    cum[n] = 0
    for i in range(n - 1, -1, -1):
        cum[i] = freq[i] + cum[i + 1]


def _quantum(blocks, window_bits: int, deadline=None) -> bytes:
    """The bytes of a Quantum folder, from its [(packed bytes, unpacked size)]. A frame ends where its
    block says: a match that runs over that end is Unknown (cabextract refuses such a folder too; it
    does unpack libmspack's test cabinet whose LAST frame decodes 129 bytes more than the folder
    states, which 7zz and this decoder refuse). Unknown also for a window the format does not have, a
    match that reaches before the folder's start, a block that needs more bits than it holds;
    Unavailable when the deadline (time.monotonic) passes."""
    import time
    if not 10 <= window_bits <= 21:
        U("a Quantum window the format does not have")
    window, slots = 1 << window_bits, window_bits * 2
    literal = (_qtm_model(0, 64), _qtm_model(64, 64), _qtm_model(128, 64), _qtm_model(192, 64))
    m4, m5, m6 = _qtm_model(0, min(24, slots)), _qtm_model(0, min(36, slots)), _qtm_model(0, slots)
    m6len, m7 = _qtm_model(0, 27), _qtm_model(0, 7)
    out = bytearray()
    for packed, unpacked in blocks:
        if deadline is not None and time.monotonic() > deadline:
            N("the Quantum decoder here ran out of its time")
        if unpacked > 32768:
            U("a Quantum block of more than one frame")
        size, pos = len(packed), 0
        limit = size * 8 + 64                # a few bits past the block read as 0, as the format's readers allow

        def bits(n):
            nonlocal pos
            v = 0
            for _ in range(n):
                byte = pos >> 3
                v = (v << 1) | ((packed[byte] >> (7 - (pos & 7))) & 1 if byte < size else 0)
                pos += 1
            if pos > limit:
                U("a Quantum block that needs more bits than it holds")
            return v
        H, L, C = 0xFFFF, 0, bits(16)

        def symbol(m):
            nonlocal H, L, C
            syms, cum = m[0], m[1]
            n = len(syms)
            spread = ((H - L) & 0xFFFF) + 1
            at = ((((C - L + 1) * cum[0]) - 1) // spread) & 0xFFFF
            i = 1
            while i < n and cum[i] > at:
                i += 1
            sym, total = syms[i - 1], cum[0]
            H = (L + (cum[i - 1] * spread) // total - 1) & 0xFFFF
            L = (L + (cum[i] * spread) // total) & 0xFFFF
            for k in range(i):
                cum[k] += 8
            if cum[0] > 3800:
                _qtm_update(m)
            while True:
                if (L & 0x8000) != (H & 0x8000):
                    if (L & 0x4000) and not (H & 0x4000):
                        C ^= 0x4000
                        L &= 0x3FFF
                        H |= 0x4000
                    else:
                        break
                L = (L << 1) & 0xFFFF
                H = ((H << 1) | 1) & 0xFFFF
                C = ((C << 1) | bits(1)) & 0xFFFF
            return sym
        end = len(out) + unpacked
        while len(out) < end:
            selector = symbol(m7)
            if selector < 4:
                out.append(symbol(literal[selector]))
                continue
            if selector == 4:
                s = symbol(m4)
                offset, length = _QTM_BASE[s] + bits(_QTM_EXTRA[s]) + 1, 3
            elif selector == 5:
                s = symbol(m5)
                offset, length = _QTM_BASE[s] + bits(_QTM_EXTRA[s]) + 1, 4
            else:
                s = symbol(m6len)
                length = _QTM_LEN_BASE[s] + bits(_QTM_LEN_EXTRA[s]) + 5
                s = symbol(m6)
                offset = _QTM_BASE[s] + bits(_QTM_EXTRA[s]) + 1
            if offset > len(out) or offset > window:
                U("a Quantum match that reaches before the folder's start")
            if offset >= length:
                start = len(out) - offset
                out += out[start:start + length]
            else:
                for _ in range(length):
                    out.append(out[-offset])
        if len(out) != end:
            U("a Quantum match that runs over its frame's end")
    return bytes(out)


def _cab_quantum(b: bytes, cab: dict, index: int) -> bytes:
    """One whole Quantum folder unpacked by the decoder here, inside what is left of the cabinet's
    budget. Not for the facts page."""
    import time
    if M.FACTS_PAGE[0]:
        N("an LZX or Quantum folder is not unpacked for a facts page")
    blocks = _cab_blocks(b, cab, index)
    if sum(u for _, u in blocks) > MAX_UNPACKED:
        U("a folder larger than is unpacked")
    left = SEVENZIP_BUDGET - cab["spent"]
    if left < 0.02:
        N(f"the {SEVENZIP_BUDGET:g} s this cabinet has for unpacking are spent")
    started = time.monotonic()
    try:
        try:
            return _quantum(blocks, (cab["folders"][index][3] >> 8) & 0x1F, started + left)
        except M.Unknown:
            raise
        except Exception as e:
            U(f"the bytes do not read as a Quantum stream ({type(e).__name__})")
    finally:
        cab["spent"] += time.monotonic() - started


CAB_DECODERS = {3: (("7zz", lambda *a: _cab_7z(*a)), ("bsdtar", lambda *a: _cab_bsdtar(*a))),
                2: (("7zz", lambda *a: _cab_7z(*a)), ("the decoder here", lambda *a: _cab_quantum(*a)))}


def _cab_decoded(b: bytes, cab: dict, index: int) -> bytes:
    """One whole LZX or Quantum folder by the chain of its decoders: every one is asked, inside the
    cabinet's one budget, and the ones that unpack it must give the same bytes: where two give
    different bytes nothing is read. A decoder that was not there or ran out of time (Unavailable)
    refused nothing, so the other's bytes stand; CAB_REQUIRE_TWO asks for two.

    A decoder that REFUSES the stream: nothing is read (CAB_REFUSAL_VETOES, both methods). libarchive's
    test cabinet with an invalid LZX history is the case: bsdtar unpacks it, 7zz and cabextract refuse
    it. On every valid folder of the 101 public test cabinets, and on nine Quantum folders built by
    the test's encoder (26 bytes to 200,000, five window sizes), 7zz, the second decoder and
    cabextract give the same bytes; on the seven built with matches over a frame's end all refuse."""
    method = cab["folders"][index][2]
    got, refused, absent = [], [], []
    for name, decode in CAB_DECODERS[method]:
        try:
            got.append((name, decode(b, cab, index)))
        except Unavailable as e:
            absent.append(str(e))
        except M.Unknown as e:
            refused.append(str(e))
    cab.setdefault("decoders", {})[index] = [name for name, _ in got]
    if refused and (method in CAB_REFUSAL_VETOES or not got):
        U("; ".join(refused))
    if not got:
        N("; ".join(absent))
    if any(out != got[0][1] for _, out in got):
        U(f"{' and '.join(name for name, _ in got)} unpack the folder to different bytes")
    if CAB_REQUIRE_TWO and len(got) < 2:
        N(f"only {got[0][0]} unpacked the folder ({'; '.join(absent)})")
    return got[0][1]


def _cab_folder(b: bytes, cab: dict, index: int) -> bytes:
    """The unpacked bytes of one folder. Stored and MSZIP are unpacked here, and where the folder goes
    on in the next cabinet of a set, as far as this cabinet's whole blocks reach. LZX and Quantum go
    to the chain of _cab_decoded, whole folders only, once for a folder. A folder that begins in the
    previous cabinet is Unknown."""
    if index >= len(cab["folders"]):
        U("a member that continues in another cabinet")
    if index in cab["unpacked"]:
        return cab["unpacked"][index]
    if index == 0 and cab["from_prev"]:
        U("a folder that begins in the previous cabinet of the set")
    method = cab["folders"][index][2]
    goes_on = cab["to_next"] and index == len(cab["folders"]) - 1
    if method in (2, 3):
        if goes_on:
            U(f"a {CAB_METHODS[method]} folder that continues in the next cabinet: not unpacked")
        if index in cab["failed"]:
            U(cab["failed"][index])          # the decoders are asked once for a folder, never again for the same file
        asked = not M.FACTS_PAGE[0]
        try:
            out = _cab_decoded(b, cab, index)
        except M.Unknown as e:
            if asked:
                cab["failed"][index] = str(e)
            raise
    elif method not in (0, 1):
        U("a folder of a compression type the format does not name")
    else:
        out = bytearray()
        for body, unpacked in _cab_blocks(b, cab, index):
            if unpacked == 0 and goes_on:
                break                                   # the block that is finished in the next cabinet
            if method == 0:
                block = body
            else:
                if body[:2] != b"CK":
                    U("an MSZIP block without its signature")
                z = zlib.decompressobj(-15, zdict=bytes(out[-32768:])) if out else zlib.decompressobj(-15)
                block = z.decompress(body[2:], unpacked + 1)
            if len(block) != unpacked:
                U("a data block that does not unpack to its stated size")
            out += block
            if len(out) > MAX_UNPACKED:
                U("a folder larger than is unpacked")
        out = bytes(out)
    cab["unpacked"][index] = out
    return out


def _cab_member(b: bytes, cab: dict, f) -> bytes:
    """The bytes of one member (a CFFILE tuple); Unknown where it is not whole in this cabinet."""
    if f[3] in (CAB_FROM_PREV, CAB_TO_NEXT, CAB_BOTH):
        U("a member that continues in another cabinet of the set")
    body = _cab_folder(b, cab, f[3])[f[2]:f[2] + f[1]]
    if len(body) != f[1]:
        U("a member that runs past what this cabinet holds of its folder")
    return body


def _cab(d: bytes):
    """(stream name, bytes, parsed header) of the installer's one embedded cabinet; None when the file
    is no MSI database or holds none; Unknown for two."""
    db = _db(d)
    if db is None:
        return None
    cached = db.setdefault("cab", [])
    if not cached:
        streams, found = db["streams"], []
        for name in streams.names(False):
            if name.startswith("\x05"):
                continue
            body = streams.read(name, False)
            if body is not None and body[:4] == b"MSCF":
                found.append((name, body))
        if len(found) > 1:
            U("several embedded cabinets: the name does not say which one is asked")
        cached.append((found[0][0], found[0][1], _cab_parse(found[0][1])) if found else None)
    return cached[0]


def cab(get):
    def fn(n, d):
        c = _cab(d)
        return None if c is None else get(c)
    return fn


@section
def _reg_cabinet():
    names = ("cabinet_file", "cabinet_member", "cab_file", "cab_member", "embedded_cabinet_file", "cabinet_entry")
    def member_names(c):
        found = [f[0] for f in c[2]["files"]]
        if None in found:
            U("a member name that does not decode: the cabinet does not state its code page")
        return found or None
    reg([f"{x}_names" for x in names] + ["cabinet_members", "cabinet_files", "cabinet_contents", "cab_contents"], "list",
        cab(member_names))
    reg([f"{x}_count" for x in names], "integer", cab(lambda c: len(c[2]["files"])))
    reg([f"{x}_sizes" for x in names], "intlist", cab(lambda c: [f[1] for f in c[2]["files"]] or None))
    reg([f"{x}_size" for x in names] + [f"{x}_size_bytes" for x in names], "integer",
        cab(lambda c: (lambda f: None if f is None else f[1])(one(c[2]["files"], "members in the cabinet"))))
    reg([f"{x}_name" for x in names], "text",
        cab(lambda c: (lambda f: None if f is None else f[0] if f[0] is not None else U("a member name that does not decode"))(
            one(c[2]["files"], "members in the cabinet"))))
    reg(["cabinet_size_bytes", "cabinet_size", "cab_size_bytes", "embedded_cabinet_size_bytes", "cabinet_stream_size_bytes"],
        "integer", cab(lambda c: len(c[1])))
    reg(["cabinet_folder_count", "cab_folder_count"], "integer", cab(lambda c: len(c[2]["folders"])))
    reg(["cabinet_compression", "cabinet_compression_type", "cabinet_compression_method", "cab_compression"], "label",
        cab(lambda c: (lambda m: None if m is None else CAB_METHODS.get(m) or U("a compression type the format does not name"))(
            one({f[2] for f in c[2]["folders"]}, "compression types in the cabinet"))))
    reg(["has_embedded_cabinet", "embedded_cabinet_present", "has_cabinet"], "bool",
        lambda n, d: None if _db(d) is None else _cab(d) is not None)
    for algo in ("md5", "sha1", "sha256"):
        reg([f"cabinet_{algo}", f"cab_{algo}", f"embedded_cabinet_{algo}", f"cabinet_stream_{algo}"], "hex",
            cab(lambda c, algo=algo: hashlib.new(algo, c[1]).hexdigest()))

        def member(c, algo=algo):
            f = one(c[2]["files"], "members in the cabinet")
            return None if f is None else hashlib.new(algo, _cab_member(c[1], c[2], f)).hexdigest()
        reg([f"{x}_{algo}" for x in names], "hex", cab(member))
        # every member's digest, in the cabinet's order: all of them whole, or no answer
        reg([f"{x}_{algo}_list" for x in names], "list",
            cab(lambda c, algo=algo: [hashlib.new(algo, _cab_member(c[1], c[2], f)).hexdigest() for f in c[2]["files"]] or None))
    reg(["cabinet_is_multi_part", "cabinet_spans_set", "cabinet_continues"], "bool",
        cab(lambda c: c[2]["from_prev"] or c[2]["to_next"]))


# ------------------------------------------------------------------ MSIX / AppX: the package manifest

MSIX = "msix"
MSIX_OTHER = ("appx", "msixbundle", "appxbundle")
MANIFEST = "AppxManifest.xml"
BUNDLE_MANIFEST = "AppxMetadata/AppxBundleManifest.xml"
MAX_BUNDLE_READ = 64 << 20   # bytes, by their stated sizes, that one bundle's inner packages may unpack to
MAX_PACKAGES = 256           # packages of a bundle that are opened
PUBLISHER_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def _manifest_xml(z, name, root_tag):
    """The root element of the one member of this name, None when there is none."""
    infos = [i for i in z.infolist() if i.filename == name]
    if not infos:
        return None
    if len(infos) != 1:
        U("two manifests in the package")
    if infos[0].flag_bits & 1 or infos[0].file_size > MAX_MANIFEST:
        U("a manifest that is encrypted or larger than is read")
    try:
        with z.open(infos[0]) as fh:
            body = fh.read(MAX_MANIFEST + 1)
    except Exception as e:
        U(f"the manifest does not unpack ({type(e).__name__})")
    if len(body) != infos[0].file_size or b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        U("a manifest that is not plain XML of its stated size")
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        U("a manifest that is not well-formed XML")
    if _local(root.tag) != root_tag:
        U(f"a manifest whose root is not {root_tag}")
    return root


def publisher_id(publisher: str) -> str:
    """The 13 characters Windows derives from a package's Publisher for its family and full names: the
    first 8 bytes of the SHA-256 of the publisher's UTF-16LE text, as 13 groups of 5 bits (the 64 bits
    and one 0 bit) in the alphabet 0-9 a-z without i, l, o and u. `CN=Microsoft Corporation,
    O=Microsoft Corporation, L=Redmond, S=Washington, C=US` gives 8wekyb3d8bbwe, the suffix of every
    Microsoft Store package name (tests/test_day13_metadata_msi.py holds it to that and to
    cw5n1h2txyewy for `CN=Microsoft Windows, ...`)."""
    bits = int.from_bytes(hashlib.sha256(publisher.encode("utf-16-le")).digest()[:8], "big") << 1
    return "".join(PUBLISHER_ALPHABET[(bits >> shift) & 31] for shift in range(60, -1, -5))


def _identity(root):
    """(Name, Version, ProcessorArchitecture or neutral, ResourceId or '', Publisher) of a Package
    manifest's one Identity element; Unknown when it lacks a name, a version or a publisher."""
    e = one(_find(root, "Identity"), "Identity elements")
    if e is None or not e.get("Name") or not e.get("Version") or not e.get("Publisher"):
        U("no Identity with a name, a version and a publisher")
    return e.get("Name"), e.get("Version"), e.get("ProcessorArchitecture") or "neutral", e.get("ResourceId") or "", e.get("Publisher")


def full_name(identity) -> str:
    name, version, arch, resource, publisher = identity
    return f"{name}_{version}_{arch}_{resource}_{publisher_id(publisher)}"


class _Window(io.RawIOBase):
    """A stored member of a zip as a file of its own, read in place: no byte of it is copied until
    it is asked for."""

    def __init__(self, data: bytes, start: int, size: int):
        self.view, self.at = memoryview(data)[start:start + size], 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.at

    def seek(self, offset, whence=0):
        self.at = max(0, offset + (0 if whence == 0 else self.at if whence == 1 else len(self.view)))
        return self.at

    def read(self, n=-1):
        end = len(self.view) if n is None or n < 0 else min(len(self.view), self.at + n)
        out = bytes(self.view[self.at:end])
        self.at = max(self.at, end)
        return out

    def readinto(self, buffer):
        out = self.read(len(buffer))
        buffer[:len(out)] = out
        return len(out)


@functools.lru_cache(maxsize=8)
def _bundle(d: bytes):
    """(the bundle manifest's root, its Package elements), or None when the file is no zip with a
    bundle manifest. No inner package is opened here: _inner_identities does that, when asked."""
    if d[:4] != b"PK\x03\x04" or BUNDLE_MANIFEST.encode() not in d:
        return None
    try:
        z = zipfile.ZipFile(io.BytesIO(d))
    except Exception:
        return None
    root = _manifest_xml(z, BUNDLE_MANIFEST, "Bundle")
    if root is None:
        return None
    packages = _find(root, "Packages", "Package")
    if len(packages) > MAX_PACKAGES:
        U("more packages in the bundle than are opened")
    return root, packages


def bundle(get):
    def fn(n, d):
        r = _bundle(d)
        return None if r is None else get(r[0], r[1], d)
    return fn


def _inner_zip(d: bytes, info):
    """One inner package opened as a zip. A stored package (what a bundle holds) is read in place,
    and only what is then asked of it is unpacked; a deflated one is unpacked whole, which
    _inner_identities has counted before it calls this."""
    if info.compress_type == zipfile.ZIP_STORED:
        at = info.header_offset
        if d[at:at + 4] != b"PK\x03\x04" or at + 30 > len(d):
            U("an inner package whose local header is not where the directory says")
        name_len, extra_len = struct.unpack_from("<HH", d, at + 26)
        start = at + 30 + name_len + extra_len
        if start + info.compress_size > len(d) or info.compress_size != info.file_size:
            U("an inner package that runs past the bundle")
        return zipfile.ZipFile(_Window(d, start, info.compress_size))
    with zipfile.ZipFile(io.BytesIO(d)) as z, z.open(info) as fh:
        body = fh.read(info.file_size + 1)
    if len(body) != info.file_size:
        U("an inner package that does not unpack to its stated size")
    return zipfile.ZipFile(io.BytesIO(body))


def _inner_identities(packages, d: bytes):
    """The Identity of every one of these inner packages, in the order given; Unknown when one is
    not read. Only each package's AppxManifest.xml is unpacked. Before anything is, the stated sizes
    of all that would be are summed (a stored package: its manifest; a deflated package: the package
    and its manifest are not known apart, so the package), and past MAX_BUNDLE_READ nothing is read."""
    cache = _bundle_cache(d)
    key = tuple(e.get("FileName") for e in packages)
    if key in cache:
        if isinstance(cache[key], str):
            U(cache[key])
        return cache[key]
    try:
        try:
            z = zipfile.ZipFile(io.BytesIO(d))
            infos = {}
            for i in z.infolist():
                infos.setdefault(i.filename, []).append(i)
        except Exception as e:
            U(f"the bundle's directory does not read ({type(e).__name__})")
        chosen = []
        for e in packages:
            hits = infos.get(e.get("FileName"), []) if e.get("FileName") else []
            if len(hits) != 1 or hits[0].flag_bits & 1:
                U(f"the inner package {M._clean(e.get('FileName'), 60)} is not in the bundle once, or is encrypted")
            chosen.append(hits[0])
        read = sum(i.file_size for i in chosen if i.compress_type != zipfile.ZIP_STORED)
        if read > MAX_BUNDLE_READ:
            U("the inner packages state more bytes to unpack than are read")
        out = []
        for info in chosen:
            try:
                inner = _inner_zip(d, info)
            except M.Unknown:
                raise
            except Exception as e:
                U(f"the inner package {M._clean(info.filename, 60)} is no zip ({type(e).__name__})")
            manifests = [i for i in inner.infolist() if i.filename == MANIFEST]
            read += sum(i.file_size for i in manifests)
            if read > MAX_BUNDLE_READ:
                U("the inner packages state more bytes to unpack than are read")
            root = _manifest_xml(inner, MANIFEST, "Package")
            if root is None:
                U(f"the inner package {M._clean(info.filename, 60)} has no manifest")
            out.append(_identity(root))
    except M.Unknown as e:
        cache[key] = str(e)
        raise
    cache[key] = out
    return out


@functools.lru_cache(maxsize=8)
def _bundle_cache(d: bytes) -> dict:
    """Per bundle: {the FileNames asked: their identities, or why they are not read}. Text, no package."""
    return {}


@functools.lru_cache(maxsize=8)
def _msix(d: bytes):
    """(the manifest's root element, the package's member names), or None when the file is no zip
    with exactly one AppxManifest.xml at its root. Unknown where it has one that does not read."""
    if d[:4] != b"PK\x03\x04" or MANIFEST.encode() not in d:
        return None
    try:
        z = zipfile.ZipFile(io.BytesIO(d))
        names = [i.filename for i in z.infolist()]
    except Exception:
        return None
    root = _manifest_xml(z, MANIFEST, "Package")
    return None if root is None else (root, names)


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _find(root, *path):
    """Every element at this path of local names under the root."""
    level = [root]
    for step in path:
        level = [c for e in level for c in e if _local(c.tag) == step]
    return level


def msix(get):
    def fn(n, d):
        r = _msix(d)
        return None if r is None else get(*r)
    return fn


def _attr(path, attr):
    """An attribute of the one element at a path (its own, never a namespaced twin's)."""
    def get(root, names):
        e = one(_find(root, *path), f"{path[-1]} elements")
        return None if e is None else (e.get(attr) or None)
    return get


def _text(path):
    def get(root, names):
        e = one(_find(root, *path), f"{path[-1]} elements")
        return None if e is None else ((e.text or "").strip() or None)
    return get


@section
def _reg_msix():
    r = lambda names, fmt, fn: reg(names, fmt, fn, ns=MSIX)   # noqa: E731

    def identity(attr):
        """The file's own manifest: a package's Identity, and for a bundle the bundle manifest's."""
        def fn(n, d):
            p = _msix(d)
            if p is not None:
                return _attr(("Identity",), attr)(*p)
            b = _bundle(d)
            return None if b is None else _attr(("Identity",), attr)(b[0], None)
        return fn
    for attr, spellings in (("Name", ("identity_name", "package_name", "name", "package_identity_name")),
                            ("Publisher", ("identity_publisher", "publisher", "package_publisher")),
                            ("Version", ("identity_version", "version", "package_version")),
                            ("ProcessorArchitecture", ("identity_processor_architecture", "processor_architecture", "architecture",
                                                       "package_architecture")),
                            ("ResourceId", ("identity_resource_id", "resource_id"))):
        r(spellings, "text", identity(attr))

    # the names Windows derives from the Identity (publisher_id's docstring has the algorithm)
    def derived(get):
        def fn(n, d):
            p = _msix(d)
            return None if p is None else get(_identity(p[0]))
        return fn
    r(["package_full_name", "full_name", "identity_full_name"], "text", derived(full_name))
    r(["package_family_name", "family_name", "identity_family_name"], "text", derived(lambda i: f"{i[0]}_{publisher_id(i[4])}"))

    def own_publisher_id(n, d):
        p = identity("Publisher")(n, d)
        return None if p is None else publisher_id(p)
    r(["publisher_id", "publisher_hash", "identity_publisher_id", "package_publisher_id"], "text", own_publisher_id)

    # a bundle (.msixbundle, .appxbundle): its own manifest, and every inner package's
    for attr, spellings in (("Name", ("bundle_identity_name", "bundle_name")),
                            ("Publisher", ("bundle_identity_publisher", "bundle_publisher")),
                            ("Version", ("bundle_identity_version", "bundle_version"))):
        r(spellings, "text", bundle(lambda root, packages, d, attr=attr: _attr(("Identity",), attr)(root, None)))
    r(["is_bundle", "bundle"], "bool", lambda n, d: True if _bundle(d) is not None else False if _msix(d) is not None else None)
    r(["bundle_package_count", "bundle_packages_count", "inner_package_count"], "integer", bundle(lambda root, packages, d: len(packages)))
    for attr, word in (("FileName", "file_names"), ("Type", "types"), ("Version", "versions"), ("Architecture", "architectures"),
                       ("ResourceId", "resource_ids")):
        r([f"bundle_package_{word}", f"inner_package_{word}"], "list",
          bundle(lambda root, packages, d, attr=attr: [e.get(attr) for e in packages if e.get(attr)] or None))
    for index, word in ((0, "names"), (1, "identity_versions"), (2, "identity_architectures"), (4, "publishers")):
        r([f"bundle_package_{word}", f"inner_package_{word}"] + (["bundle_package_identity_names"] if index == 0 else []), "list",
          bundle(lambda root, packages, d, index=index: [i[index] for i in _inner_identities(packages, d)] or None))
    r(["bundle_package_full_names", "inner_package_full_names"], "list",
      bundle(lambda root, packages, d: [full_name(i) for i in _inner_identities(packages, d)] or None))
    r(["bundle_package_family_names", "inner_package_family_names"], "list",
      bundle(lambda root, packages, d: [f"{i[0]}_{publisher_id(i[4])}" for i in _inner_identities(packages, d)] or None))

    def application(packages):
        """The bundle's one package of Type application (the others are resource packages)."""
        return one([e for e in packages if (e.get("Type") or "").lower() == "application"], "application packages in the bundle")

    def application_identity(root, packages, d):
        e = application(packages)
        return None if e is None else _inner_identities([e], d)[0]
    r(["bundle_application_package_full_name", "bundle_application_full_name"], "text",
      bundle(lambda *a: (lambda i: None if i is None else full_name(i))(application_identity(*a))))
    r(["bundle_application_package_file_name", "bundle_application_file_name"], "text",
      bundle(lambda root, packages, d: (lambda e: None if e is None else e.get("FileName"))(application(packages))))
    r(["bundle_application_package_version", "bundle_application_version"], "text",
      bundle(lambda *a: (lambda i: None if i is None else i[1])(application_identity(*a))))
    r(["bundle_application_package_architecture", "bundle_application_architecture"], "text",
      bundle(lambda *a: (lambda i: None if i is None else i[2])(application_identity(*a))))
    r(["display_name", "properties_display_name", "package_display_name"], "text", msix(_text(("Properties", "DisplayName"))))
    r(["publisher_display_name", "properties_publisher_display_name"], "text", msix(_text(("Properties", "PublisherDisplayName"))))
    r(["logo", "properties_logo", "package_logo"], "text", msix(_text(("Properties", "Logo"))))
    r(["description", "properties_description"], "text", msix(_text(("Properties", "Description"))))
    r(["phone_product_id", "phone_identity_product_id"], "text", msix(_attr(("PhoneIdentity",), "PhoneProductId")))

    def listed(path, attr):
        return msix(lambda root, names: [e.get(attr) for e in _find(root, *path) if e.get(attr)] or None)

    def capabilities(root, names):
        return [c.get("Name") for e in _find(root, "Capabilities") for c in e if c.get("Name")] or None
    r(["capabilities", "capability_names", "capability_list"], "list", msix(capabilities))
    r(["capability_count", "capabilities_count"], "integer",
      msix(lambda root, names: len([c for e in _find(root, "Capabilities") for c in e])))
    r(["application_ids", "application_id_list", "app_ids"], "list", listed(("Applications", "Application"), "Id"))
    r(["application_id", "app_id"], "text", msix(_attr(("Applications", "Application"), "Id")))
    r(["application_executables", "executables"], "list", listed(("Applications", "Application"), "Executable"))
    r(["application_executable", "executable"], "text", msix(_attr(("Applications", "Application"), "Executable")))
    r(["application_entry_point", "entry_point"], "text", msix(_attr(("Applications", "Application"), "EntryPoint")))
    r(["application_count", "applications_count"], "integer", msix(lambda root, names: len(_find(root, "Applications", "Application"))))
    r(["target_device_family_names", "target_device_families"], "list", listed(("Dependencies", "TargetDeviceFamily"), "Name"))
    r(["target_device_family_name", "target_device_family"], "text", msix(_attr(("Dependencies", "TargetDeviceFamily"), "Name")))
    r(["target_device_family_min_version", "min_version", "min_os_version"], "text",
      msix(_attr(("Dependencies", "TargetDeviceFamily"), "MinVersion")))
    r(["target_device_family_max_version_tested", "max_version_tested"], "text",
      msix(_attr(("Dependencies", "TargetDeviceFamily"), "MaxVersionTested")))
    r(["package_dependency_names", "dependency_names"], "list", listed(("Dependencies", "PackageDependency"), "Name"))
    r(["has_signature", "signature_present", "is_signed", "signed"], "bool", msix(lambda root, names: "AppxSignature.p7x" in names))
    r(["has_block_map", "block_map_present"], "bool", msix(lambda root, names: "AppxBlockMap.xml" in names))
    r(["member_names", "file_names", "package_file_names"], "list", msix(lambda root, names: names or None))
    r(["member_count", "file_count", "package_file_count"], "integer", msix(lambda root, names: len(names)))


# ------------------------------------------------------------------ registration

def register(module):
    global M, RF, Unavailable
    M = module
    Unavailable = type("Unavailable", (M.Unknown,), {})
    RF = getattr(M, "MORE_MODULES", {}).get("readers_formats.py")
    if RF is None or not hasattr(RF, "_msi"):
        raise RuntimeError("readers_formats.py is not loaded, and the test for an MSI database is its own")
    before = dict(M.REG)
    families = len(M.FAMILIES)
    WORDS.clear()
    WORDS.update({M.words(k): p.fn for k, p in M.REG.items() if k.partition("_")[0] in (NS, MSIX)})
    for s in SECTIONS:
        s()
    odd = [k for k, p in M.REG.items() if before.get(k) is not p and M.canon(p.name) != k]
    if odd:
        raise RuntimeError(f"a name that is not its own canonical form: {odd[:3]}")
    M.NAMESPACES.add(MSIX)
    M.PACK_NAMESPACES.add(MSIX)
    M.CONTENT_TOKENS.update({MSIX, *MSIX_OTHER})
    M.RELATED.setdefault(MSIX, (MSIX, "zip"))
    M.MORE_TYPES.append((MSIX, lambda d: _msix_quiet(d)))
    M.NS_ALIAS.update({a: MSIX for a in MSIX_OTHER if a not in M.NS_ALIAS and a not in M.NAMESPACES})
    M.TIE_FREE.update(p.fn for k, p in M.REG.items() if before.get(k) is not p)
    return len(M.REG) - len(before), len(M.FAMILIES) - families


def _msix_quiet(d: bytes) -> bool:
    try:
        return _msix(d) is not None or _bundle(d) is not None
    except Exception:
        return False
