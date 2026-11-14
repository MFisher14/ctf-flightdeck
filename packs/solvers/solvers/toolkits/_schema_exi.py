"""Schema-informed EXI decoding from an XSD (helper of schema_bundle, B-159).

ISO 15118 and DIN 70121 messages are EXI streams whose bits only mean something against the exact XSD
the two ends agreed on. This module turns an XSD (loaded from a path the caller names; nothing is
bundled) into EXI grammars and decodes a stream against them:

    schema = load_schema([Path("V2G_CI_MsgDef.xsd")])    # follows xs:import / xs:include on disk
    out = decode(data, schema)                           # {"header", "root", "document", ...}

Supported EXI profile (the one ISO 15118-2 and DIN 70121 use): bit-packed, schema-informed,
strict = false, no preserve options, no options document in the header. Everything outside it is a
named failure, never a guess:

    ExiSchemaMissing   an XSD named by a root or an import is not on disk
    ExiSchemaError     the XSD cannot be read or uses a construct this reader does not model
    ExiUnsupported     the stream needs a feature outside the profile (header options, a schema
                       deviation / second-level event code, a wildcard element, an EXI Date-Time or
                       restricted-character-set value)
    ExiDecodeError     the stream is malformed, truncated, or leaves bits behind

Grammar rules follow the EXI 1.0 recommendation: document grammar over the global elements sorted by
local name then namespace (8.5.1), type grammars from attribute uses and the content model (8.5.4.1),
event codes in the order AT(qname), AT(uri:*), AT(*), SE(qname) in schema order, SE(uri:*), SE(*), EE,
CH (8.5.4.3), and one extra first-part code in every state for the strict = false productions
(8.5.4.4.1). An element particle that refers to a substitution-group head stands for the head and
every member, sorted by local name then namespace.

The XSD is parsed with the standard library; an external DTD or entity is never fetched, and an
import is only followed inside the folder of the root schema.
"""
from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

XSD_NS = "http://www.w3.org/2001/XMLSchema"
MAX_XSD_BYTES = 8 << 20
MAX_SCHEMA_FILES = 64
MAX_NFA_STATES = 400_000
MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_STRING = 1 << 20
MAX_INPUT = 16 << 20

__all__ = ["ExiError", "ExiSchemaError", "ExiSchemaMissing", "ExiUnsupported", "ExiDecodeError",
           "Schema", "load_schema", "decode", "flatten"]


class ExiError(ValueError):
    """Base of every failure this module raises."""


class ExiSchemaError(ExiError):
    """The XSD cannot be read, or uses a construct this reader does not model."""


class ExiSchemaMissing(ExiSchemaError):
    """A schema file is not on disk. `.path` is the file looked for."""

    def __init__(self, path: Path, why: str):
        self.path = Path(path)
        super().__init__(f"schema file {path} is missing ({why})")


class ExiUnsupported(ExiError):
    """The stream needs an EXI feature outside the supported profile."""


class ExiDecodeError(ExiError):
    """The stream is malformed, truncated, or leaves bits behind."""


# --------------------------------------------------------------------------------------------------
# XSD model

_BUILTIN_BASE = {
    "anySimpleType": None, "anyAtomicType": "anySimpleType",
    "string": "anySimpleType", "normalizedString": "string", "token": "normalizedString",
    "language": "token", "NMTOKEN": "token", "Name": "token", "NCName": "Name", "ID": "NCName",
    "IDREF": "NCName", "ENTITY": "NCName",
    "boolean": "anySimpleType", "decimal": "anySimpleType", "float": "anySimpleType",
    "double": "anySimpleType", "duration": "anySimpleType", "dateTime": "anySimpleType",
    "time": "anySimpleType", "date": "anySimpleType", "gYearMonth": "anySimpleType",
    "gYear": "anySimpleType", "gMonthDay": "anySimpleType", "gDay": "anySimpleType",
    "gMonth": "anySimpleType", "hexBinary": "anySimpleType", "base64Binary": "anySimpleType",
    "anyURI": "anySimpleType", "QName": "anySimpleType", "NOTATION": "anySimpleType",
    "integer": "decimal", "nonPositiveInteger": "integer", "negativeInteger": "nonPositiveInteger",
    "long": "integer", "int": "long", "short": "int", "byte": "short",
    "nonNegativeInteger": "integer", "unsignedLong": "nonNegativeInteger",
    "unsignedInt": "unsignedLong", "unsignedShort": "unsignedInt", "unsignedByte": "unsignedShort",
    "positiveInteger": "nonNegativeInteger",
}
_BUILTIN_LIST = {"NMTOKENS": "NMTOKEN", "IDREFS": "IDREF", "ENTITIES": "ENTITY"}
_INT_BOUNDS = {
    "byte": (-128, 127), "unsignedByte": (0, 255), "short": (-32768, 32767),
    "unsignedShort": (0, 65535), "int": (-2 ** 31, 2 ** 31 - 1), "unsignedInt": (0, 2 ** 32 - 1),
    "long": (-2 ** 63, 2 ** 63 - 1), "unsignedLong": (0, 2 ** 64 - 1),
    "nonNegativeInteger": (0, None), "positiveInteger": (1, None),
    "nonPositiveInteger": (None, 0), "negativeInteger": (None, -1), "integer": (None, None),
}
_DATETIME = frozenset({"dateTime", "time", "date", "gYearMonth", "gYear", "gMonthDay", "gDay", "gMonth"})


@dataclass(eq=False)
class SimpleType:
    name: tuple[str, str] | None
    variety: str = "atomic"                 # atomic | list | union
    base: "SimpleType | None" = None
    builtin: str | None = None              # the XSD built-in name when this is one
    enumeration: tuple[str, ...] | None = None
    lower: int | None = None                # minInclusive (minExclusive + 1) set on this type
    upper: int | None = None
    pattern: bool = False                   # a pattern facet set on this (user-defined) type
    item: "SimpleType | None" = None
    _codec: tuple | None = None


@dataclass(eq=False)
class AttrUse:
    qname: tuple[str, str]
    type: SimpleType
    required: bool


@dataclass(eq=False)
class Particle:
    min: int
    max: int | None                         # None = unbounded
    kind: str                               # element | sequence | choice | all | any
    decl: "ElementDecl | None" = None
    children: list["Particle"] = field(default_factory=list)
    namespaces: tuple[str, ...] | None = None    # any: None = SE(*), else one SE(uri:*) per entry


@dataclass(eq=False)
class ComplexType:
    name: tuple[str, str] | None
    attributes: list[AttrUse] = field(default_factory=list)
    attr_wildcard: bool = False
    simple: SimpleType | None = None        # simple content
    particle: Particle | None = None
    mixed: bool = False
    ready: bool = False


@dataclass(eq=False)
class ElementDecl:
    qname: tuple[str, str]
    node: Any
    doc: "_Doc"
    is_global: bool
    _type: Any = None


@dataclass(eq=False)
class _Doc:
    path: Path
    root: Any
    tns: str
    eform: bool
    aform: bool
    prefixes: dict[str, str]
    chameleon: bool = False                 # included without a targetNamespace: it took the includer's


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _is_xsd(node: Any, name: str | tuple[str, ...]) -> bool:
    if not isinstance(node.tag, str) or not node.tag.startswith("{" + XSD_NS + "}"):
        return False
    names = (name,) if isinstance(name, str) else name
    return _local(node.tag) in names


def _read_xsd(path: Path) -> tuple[Any, dict[str, str]]:
    if not path.is_file():
        raise ExiSchemaMissing(path, "not a file")
    if path.stat().st_size > MAX_XSD_BYTES:
        raise ExiSchemaError(f"schema file {path} is larger than {MAX_XSD_BYTES} bytes")
    prefixes: dict[str, str] = {}
    root = None
    try:
        for event, obj in ET.iterparse(str(path), events=("start-ns", "start")):
            if event == "start-ns":
                prefix, uri = obj
                if prefixes.setdefault(prefix, uri) != uri:
                    raise ExiSchemaError(
                        f"{path}: prefix {prefix!r} is bound to two namespaces; this reader keeps one "
                        "prefix map per schema file")
            elif root is None:
                root = obj
    except ET.ParseError as exc:
        raise ExiSchemaError(f"{path}: not well-formed XML: {exc}") from None
    if root is None or not _is_xsd(root, "schema"):
        raise ExiSchemaError(f"{path}: the root element is not xs:schema")
    return root, prefixes


class Schema:
    """A set of XSD files, indexed, with EXI grammars built on demand."""

    def __init__(self, roots: Sequence[Path | str]):
        if not roots:
            raise ExiSchemaError("no schema file given")
        self.docs: list[_Doc] = []
        self.files: list[Path] = []
        self._elements: dict[tuple[str, str], tuple[Any, _Doc]] = {}
        self._types: dict[tuple[str, str], tuple[Any, _Doc]] = {}
        self._groups: dict[tuple[str, str], tuple[Any, _Doc]] = {}
        self._attr_groups: dict[tuple[str, str], tuple[Any, _Doc]] = {}
        self._attrs: dict[tuple[str, str], tuple[Any, _Doc]] = {}
        self._unlocated: set[str] = set()
        self._subst: dict[tuple[str, str], list[tuple[str, str]]] = {}
        self._type_cache: dict[tuple[str, str], Any] = {}
        self._decl_cache: dict[tuple[str, str], ElementDecl] = {}
        self._grammars: dict[int, "_TypeGrammar"] = {}
        self._keep: list[Any] = []          # anonymous types, kept alive so id() keys stay unique
        first = Path(roots[0]).resolve()
        self._fence = first.parent
        seen: set[Path] = set()
        for root in roots:
            self._load(Path(root).resolve(), seen)
        self.global_elements: list[ElementDecl] = [
            self.element(q) for q in sorted(self._elements, key=lambda q: (q[1], q[0]))]

    # ---- loading and indexing

    def _load(self, path: Path, seen: set[Path], include_tns: str = "") -> None:
        if path in seen:
            return
        if len(seen) >= MAX_SCHEMA_FILES:
            raise ExiSchemaError(f"more than {MAX_SCHEMA_FILES} schema files")
        seen.add(path)
        root, prefixes = _read_xsd(path)
        doc = _Doc(path, root, root.get("targetNamespace") or include_tns,   # an include without one takes ours
                   root.get("elementFormDefault") == "qualified",
                   root.get("attributeFormDefault") == "qualified", prefixes,
                   chameleon=bool(include_tns) and not root.get("targetNamespace"))
        self.docs.append(doc)
        self.files.append(path)
        for node in root:
            if _is_xsd(node, ("import", "include")):
                loc = node.get("schemaLocation")
                if not loc:
                    self._unlocated.add(node.get("namespace", ""))
                    continue
                self._load(self._locate(path, loc), seen, doc.tns if _is_xsd(node, "include") else "")
            elif _is_xsd(node, "redefine"):
                raise ExiSchemaError(f"{path}: xs:redefine is not modelled")
        for node in root:
            if not isinstance(node.tag, str) or not node.tag.startswith("{" + XSD_NS + "}"):
                continue
            kind, name = _local(node.tag), node.get("name")
            table = {"element": self._elements, "complexType": self._types, "simpleType": self._types,
                     "group": self._groups, "attributeGroup": self._attr_groups,
                     "attribute": self._attrs}.get(kind)
            if table is None or not name:
                continue
            key = (doc.tns, name)
            if key in table:
                raise ExiSchemaError(f"{path}: {kind} {name!r} in namespace {doc.tns!r} is defined twice")
            table[key] = (node, doc)
            if kind == "element" and node.get("substitutionGroup"):
                self._subst.setdefault(self._qn(doc, node.get("substitutionGroup")), []).append(key)

    def _locate(self, including: Path, location: str) -> Path:
        """The file an import names: beside the including file, by its relative path or its basename
        (a URL location is looked up by basename). Never fetched, never outside the root's folder."""
        tail = location.replace("\\", "/")
        cands = []
        if "://" not in tail:
            cands.append((including.parent / tail).resolve())
        cands.append((including.parent / tail.rsplit("/", 1)[-1]).resolve())
        for cand in cands:
            if cand.is_file():
                if self._fence != cand.parent and self._fence not in cand.parents:
                    raise ExiSchemaError(
                        f"{including}: schemaLocation {location!r} leaves the schema folder {self._fence}")
                return cand
        raise ExiSchemaMissing(cands[-1], f"imported by {including.name} as {location!r}")

    def _qn(self, doc: _Doc, text: str) -> tuple[str, str]:
        text = text.strip()
        if ":" in text:
            prefix, local = text.split(":", 1)
            if prefix not in doc.prefixes:
                raise ExiSchemaError(f"{doc.path}: prefix {prefix!r} in {text!r} is not declared")
            return doc.prefixes[prefix], local
        return doc.prefixes.get("", doc.tns if doc.chameleon else ""), text

    def _lookup(self, table: dict, key: tuple[str, str], what: str) -> tuple[Any, _Doc]:
        hit = table.get(key)
        if hit is None:
            hint = (" (its namespace is imported without a schemaLocation)"
                    if key[0] in self._unlocated else "")
            raise ExiSchemaError(f"{what} {key[1]!r} in namespace {key[0]!r} is not defined in "
                                 f"{', '.join(p.name for p in self.files)}{hint}")
        return hit

    # ---- components

    def element(self, qname: tuple[str, str]) -> ElementDecl:
        decl = self._decl_cache.get(qname)
        if decl is None:
            node, doc = self._lookup(self._elements, qname, "element")
            decl = self._decl_cache[qname] = ElementDecl(qname, node, doc, True)
        return decl

    def element_type(self, decl: ElementDecl) -> Any:
        if decl._type is None:
            node, doc = decl.node, decl.doc
            if node.get("type"):
                decl._type = self.type(self._qn(doc, node.get("type")))
            else:
                inline = next((k for k in node if _is_xsd(k, ("complexType", "simpleType"))), None)
                if inline is not None:
                    decl._type = (self._complex(inline, doc, None) if _is_xsd(inline, "complexType")
                                  else self._simple(inline, doc, None))
                    self._keep.append(decl._type)
                elif node.get("substitutionGroup"):
                    decl._type = self.element_type(self.element(self._qn(doc, node.get("substitutionGroup"))))
                else:
                    decl._type = self.type((XSD_NS, "anyType"))
        return decl._type

    def substitutes(self, decl: ElementDecl) -> list[ElementDecl]:
        """The head and every (transitive) member of its substitution group, by local name then namespace."""
        names, todo = {decl.qname}, [decl.qname]
        while todo:
            for member in self._subst.get(todo.pop(), ()):
                if member not in names:
                    names.add(member)
                    todo.append(member)
        return [self.element(q) for q in sorted(names, key=lambda q: (q[1], q[0]))]

    def type(self, qname: tuple[str, str]) -> Any:
        hit = self._type_cache.get(qname)
        if hit is not None:
            return hit
        ns, name = qname
        if ns == XSD_NS:
            if name == "anyType":
                typ: Any = ComplexType(qname, attr_wildcard=True, mixed=True, ready=True,
                                       particle=Particle(0, None, "any"))
            elif name in _BUILTIN_LIST:
                typ = SimpleType(qname, "list", builtin=name, item=self.type((XSD_NS, _BUILTIN_LIST[name])))
            elif name in _BUILTIN_BASE:
                parent = _BUILTIN_BASE[name]
                typ = SimpleType(qname, builtin=name, base=self.type((XSD_NS, parent)) if parent else None)
            else:
                raise ExiSchemaError(f"unknown XSD built-in type {name!r}")
            self._type_cache[qname] = typ
            return typ
        node, doc = self._lookup(self._types, qname, "type")
        if _is_xsd(node, "simpleType"):
            typ = self._type_cache[qname] = self._simple(node, doc, qname)
            return typ
        shell = self._type_cache[qname] = ComplexType(qname)    # cached first: types may recurse
        self._complex(node, doc, qname, shell)
        return shell

    def _simple_ref(self, doc: _Doc, text: str) -> SimpleType:
        typ = self.type(self._qn(doc, text))
        if isinstance(typ, ComplexType):
            if typ.simple is None:
                raise ExiSchemaError(f"{doc.path}: {text!r} is used as a simple type but has complex content")
            return typ.simple
        return typ

    def _simple(self, node: Any, doc: _Doc, name: tuple[str, str] | None) -> SimpleType:
        for kid in node:
            if _is_xsd(kid, "restriction"):
                inline = next((k for k in kid if _is_xsd(k, "simpleType")), None)
                if kid.get("base"):
                    base = self._simple_ref(doc, kid.get("base"))
                elif inline is not None:
                    base = self._simple(inline, doc, None)
                else:
                    raise ExiSchemaError(f"{doc.path}: a simpleType restriction has no base")
                return self._restrict(kid, doc, name, base)
            if _is_xsd(kid, "list"):
                inline = next((k for k in kid if _is_xsd(k, "simpleType")), None)
                if kid.get("itemType"):
                    item = self._simple_ref(doc, kid.get("itemType"))
                elif inline is not None:
                    item = self._simple(inline, doc, None)
                else:
                    raise ExiSchemaError(f"{doc.path}: a simpleType list has no item type")
                return SimpleType(name, "list", item=item)
            if _is_xsd(kid, "union"):
                return SimpleType(name, "union")
        raise ExiSchemaError(f"{doc.path}: simpleType {name} has no restriction, list or union")

    def _restrict(self, node: Any, doc: _Doc, name: tuple[str, str] | None, base: SimpleType) -> SimpleType:
        typ = SimpleType(name, base.variety, base=base, item=base.item)
        enum = []
        for facet in node:
            if not isinstance(facet.tag, str):
                continue
            kind, value = _local(facet.tag), facet.get("value", "")
            if kind == "enumeration":
                enum.append(value)
            elif kind == "pattern":
                typ.pattern = True
            elif kind in ("minInclusive", "minExclusive", "maxInclusive", "maxExclusive"):
                try:
                    number = int(value)
                except ValueError:
                    continue                    # a decimal/float/date bound: no integer range to track
                if kind.startswith("min"):
                    typ.lower = number + (1 if kind == "minExclusive" else 0)
                else:
                    typ.upper = number - (1 if kind == "maxExclusive" else 0)
        if enum:
            typ.enumeration = tuple(enum)
        return typ

    def _attributes(self, node: Any, doc: _Doc, uses: dict, state: dict) -> None:
        for kid in node:
            if _is_xsd(kid, "anyAttribute"):
                state["wildcard"] = True
            elif _is_xsd(kid, "attributeGroup") and kid.get("ref"):
                gnode, gdoc = self._lookup(self._attr_groups, self._qn(doc, kid.get("ref")), "attributeGroup")
                self._attributes(gnode, gdoc, uses, state)
            elif _is_xsd(kid, "attribute"):
                adoc, anode = doc, kid
                if kid.get("ref"):
                    qname = self._qn(doc, kid.get("ref"))
                    anode, adoc = self._lookup(self._attrs, qname, "attribute")
                else:
                    form = kid.get("form")
                    qualified = form == "qualified" or (form is None and doc.aform)
                    qname = (doc.tns if qualified else "", kid.get("name", ""))
                if kid.get("use") == "prohibited":
                    uses.pop(qname, None)
                    continue
                inline = next((k for k in anode if _is_xsd(k, "simpleType")), None)
                if anode.get("type"):
                    typ = self._simple_ref(adoc, anode.get("type"))
                elif inline is not None:
                    typ = self._simple(inline, adoc, None)
                    self._keep.append(typ)
                else:
                    typ = self.type((XSD_NS, "anySimpleType"))
                uses[qname] = AttrUse(qname, typ, kid.get("use") == "required")

    def _model(self, node: Any, doc: _Doc) -> Particle | None:
        for kid in node:
            if _is_xsd(kid, ("group", "all", "choice", "sequence")):
                return self._particle(kid, doc)
        return None

    def _particle(self, node: Any, doc: _Doc) -> Particle:
        try:
            low = int(node.get("minOccurs", "1"))
            high = None if node.get("maxOccurs") == "unbounded" else int(node.get("maxOccurs", "1"))
        except ValueError:
            raise ExiSchemaError(f"{doc.path}: bad minOccurs/maxOccurs on {_local(node.tag)}") from None
        if low < 0 or (high is not None and high < low):
            raise ExiSchemaError(f"{doc.path}: impossible occurrence range {low}..{high}")
        kind = _local(node.tag)
        if kind == "element":
            if node.get("ref"):
                decl = self.element(self._qn(doc, node.get("ref")))
            else:
                form = node.get("form")
                qualified = form == "qualified" or (form is None and doc.eform)
                decl = ElementDecl((doc.tns if qualified else "", node.get("name", "")), node, doc, False)
            return Particle(low, high, "element", decl=decl)
        if kind == "any":
            spec = node.get("namespace", "##any").split()
            if not spec or spec[0] in ("##any", "##other"):
                return Particle(low, high, "any")
            uris = sorted({doc.tns if s == "##targetNamespace" else "" if s == "##local" else s for s in spec})
            return Particle(low, high, "any", namespaces=tuple(uris))
        if kind == "group":
            if not node.get("ref"):
                raise ExiSchemaError(f"{doc.path}: a group particle has no ref")
            gnode, gdoc = self._lookup(self._groups, self._qn(doc, node.get("ref")), "group")
            inner = self._model(gnode, gdoc)
            return Particle(low, high, "sequence", children=[inner] if inner is not None else [])
        if kind in ("sequence", "choice", "all"):
            kids = [self._particle(k, doc) for k in node
                    if _is_xsd(k, ("element", "group", "choice", "sequence", "any", "all"))]
            return Particle(low, high, kind, children=kids)
        raise ExiSchemaError(f"{doc.path}: unexpected particle {kind}")

    def _complex(self, node: Any, doc: _Doc, name: tuple[str, str] | None,
                 shell: ComplexType | None = None) -> ComplexType:
        typ = shell or ComplexType(name)
        typ.mixed = node.get("mixed") == "true"
        uses: dict[tuple[str, str], AttrUse] = {}
        state = {"wildcard": False}
        simple = next((k for k in node if _is_xsd(k, "simpleContent")), None)
        complex_ = next((k for k in node if _is_xsd(k, "complexContent")), None)
        body = simple if simple is not None else complex_
        if body is None:
            typ.particle = self._model(node, doc)
            self._attributes(node, doc, uses, state)
        else:
            deriv = next((k for k in body if _is_xsd(k, ("restriction", "extension"))), None)
            if deriv is None or not deriv.get("base"):
                raise ExiSchemaError(f"{doc.path}: {name} has content without a restriction or extension base")
            base = self.type(self._qn(doc, deriv.get("base")))
            extends = _is_xsd(deriv, "extension")
            any_type = isinstance(base, ComplexType) and base.name == (XSD_NS, "anyType")
            if isinstance(base, ComplexType):
                if not base.ready:
                    raise ExiSchemaError(f"{doc.path}: {name} derives from itself through {base.name}")
                if not any_type:
                    uses.update({u.qname: u for u in base.attributes})
                    state["wildcard"] = base.attr_wildcard
            if simple is not None:
                if isinstance(base, ComplexType):
                    if base.simple is None:
                        raise ExiSchemaError(f"{doc.path}: {name} has simple content over a base without it")
                    typ.simple = base.simple
                else:
                    typ.simple = base
                if not extends:
                    inline = next((k for k in deriv if _is_xsd(k, "simpleType")), None)
                    typ.simple = self._restrict(deriv, doc, None,
                                                self._simple(inline, doc, None) if inline is not None else typ.simple)
                    self._keep.append(typ.simple)
            else:
                if not isinstance(base, ComplexType) or base.simple is not None:
                    raise ExiSchemaError(f"{doc.path}: {name} has complex content over a simple base")
                if complex_.get("mixed") is not None:
                    typ.mixed = complex_.get("mixed") == "true"
                own = self._model(deriv, doc)
                if extends and not any_type:
                    typ.mixed = typ.mixed or base.mixed
                    parts = [p for p in (base.particle, own) if p is not None]
                    typ.particle = parts[0] if len(parts) == 1 else (
                        Particle(1, 1, "sequence", children=parts) if parts else None)
                else:
                    typ.particle = own
            self._attributes(deriv, doc, uses, state)
        typ.attributes = sorted(uses.values(), key=lambda u: (u.qname[1], u.qname[0]))
        typ.attr_wildcard = state["wildcard"]
        typ.ready = True
        return typ

    # ---- grammars

    def grammar(self, typ: Any) -> "_TypeGrammar":
        hit = self._grammars.get(id(typ))
        if hit is None:
            hit = self._grammars[id(typ)] = _TypeGrammar(self, typ)
        return hit


def load_schema(roots: Sequence[Path | str]) -> Schema:
    """Load the XSD files `roots` and everything they import or include from the same folder."""
    return Schema(roots)


# --------------------------------------------------------------------------------------------------
# EXI datatype of a simple type (EXI 1.0 section 7.1)

def codec(typ: SimpleType) -> tuple:
    """('enum', values) | ('bool',) | ('nbit', bits, lower) | ('uint',) | ('int',) | ('decimal',) |
    ('float',) | ('binary', 'hex' | 'base64') | ('string',) | ('list', item codec) |
    ('unsupported', why)."""
    if typ._codec is None:
        typ._codec = _codec(typ)
    return typ._codec


def _codec(typ: SimpleType) -> tuple:
    if typ.variety == "union":
        return ("string",)
    if typ.variety == "list":
        return ("list", codec(typ.item)) if typ.item is not None else ("string",)
    chain, node = [], typ
    while node is not None:
        chain.append(node)
        node = node.base
    builtins = [t.builtin for t in chain if t.builtin]
    primitive = builtins[0] if builtins else "anySimpleType"
    enum = next((t.enumeration for t in chain if t.enumeration), None)
    if enum is not None and "QName" not in builtins and "NOTATION" not in builtins:
        return ("enum", enum)
    pattern = any(t.pattern for t in chain if not t.builtin)
    if "boolean" in builtins:
        return ("unsupported", "a boolean with pattern facets (2-bit form)") if pattern else ("bool",)
    if "integer" in builtins:
        low, high = _INT_BOUNDS[next(b for b in builtins if b in _INT_BOUNDS)]
        lower = next((t.lower for t in chain if t.lower is not None), low)
        upper = next((t.upper for t in chain if t.upper is not None), high)
        if lower is not None and upper is not None and upper >= lower and upper - lower + 1 <= 4096:
            return ("nbit", (upper - lower).bit_length(), lower)
        return ("uint",) if lower is not None and lower >= 0 else ("int",)
    if "decimal" in builtins:
        return ("decimal",)
    if primitive in ("float", "double"):
        return ("float",)
    if primitive in ("hexBinary", "base64Binary"):
        return ("binary", "hex" if primitive == "hexBinary" else "base64")
    if primitive in _DATETIME:
        return ("unsupported", f"an EXI Date-Time value (xs:{primitive})")
    if pattern:
        return ("unsupported", "a string with pattern facets (EXI restricted character set)")
    return ("string",)


# --------------------------------------------------------------------------------------------------
# Type grammar: an epsilon-NFA over the attribute uses and the content model, read as a lazy DFA

_ORDER = {"AT": 0, "ATNS": 1, "ATANY": 2, "SE": 3, "SENS": 4, "SEANY": 5, "EE": 6, "CH": 7}


class _TypeGrammar:
    """States are frozensets of NFA states. productions(state) is the event-code-ordered list of
    (kind, payload, next state); kind is one of _ORDER's keys."""

    def __init__(self, schema: Schema, typ: Any):
        self.schema = schema
        self.name = getattr(typ, "name", None)
        self._eps: list[list[int]] = []
        self._tr: list[list[tuple]] = []
        self._pos: dict[tuple, int] = {}
        self._cache: dict[frozenset, list[tuple]] = {}
        start = self._new()
        if isinstance(typ, SimpleType):
            end = self._new()
            self._tr[start].append((("CH", None), typ, end))
            self._accept = end
        else:
            cur = start
            for use in typ.attributes:
                nxt = self._new()
                self._tr[cur].append((("AT", use.qname), use, nxt))
                if not use.required:
                    self._eps[cur].append(nxt)
                cur = nxt
            if typ.attr_wildcard:
                for state in range(start, cur + 1):
                    self._tr[state].append((("ATANY", None), None, state))
            first_content = len(self._eps)
            if typ.simple is not None:
                end = self._new()
                self._tr[cur].append((("CH", None), typ.simple, end))
                self._accept = end
            else:
                self._accept = self._particle(typ.particle, cur) if typ.particle is not None else cur
                if typ.mixed:
                    for state in [cur] + list(range(first_content, len(self._eps))):
                        self._tr[state].append((("CH", None), None, state))
        self.start = self._close({start})

    def _new(self) -> int:
        if len(self._eps) >= MAX_NFA_STATES:
            raise ExiSchemaError(f"the content model of {self.name} needs more than {MAX_NFA_STATES} states")
        self._eps.append([])
        self._tr.append([])
        return len(self._eps) - 1

    def _particle(self, p: Particle, start: int) -> int:
        if p.max == 0:
            return start
        cur = start
        for _ in range(p.min):
            cur = self._term(p, cur)
        if p.max is None:
            loop = self._new()
            self._eps[cur].append(loop)
            self._eps[self._term(p, loop)].append(loop)
            return loop
        end = self._new()
        self._eps[cur].append(end)
        for _ in range(p.max - p.min):
            cur = self._term(p, cur)
            self._eps[cur].append(end)
        return end

    def _term(self, p: Particle, start: int) -> int:
        if p.kind == "element":
            end = self._new()
            members = self.schema.substitutes(p.decl) if p.decl.is_global else [p.decl]
            for decl in members:
                self._pos.setdefault(("SE", decl.qname), len(self._pos))
                self._tr[start].append((("SE", decl.qname), decl, end))
            return end
        if p.kind == "any":
            end = self._new()
            for uri in (p.namespaces if p.namespaces is not None else (None,)):
                key = ("SEANY", None) if uri is None else ("SENS", uri)
                self._pos.setdefault(key, len(self._pos))
                self._tr[start].append((key, None, end))
            return end
        if p.kind == "sequence":
            cur = start
            for kid in p.children:
                cur = self._particle(kid, cur)
            return cur
        if p.kind == "choice":
            end = self._new()
            if not p.children:
                self._eps[start].append(end)
            for kid in p.children:
                self._eps[self._particle(kid, start)].append(end)
            return end
        loop = self._new()                       # all: any member, any number of times (EXI 8.5.4.1.8)
        self._eps[start].append(loop)
        for kid in p.children:
            self._eps[self._term(kid, loop)].append(loop)
        return loop

    def _close(self, states: set[int]) -> frozenset:
        todo, seen = list(states), set(states)
        while todo:
            for nxt in self._eps[todo.pop()]:
                if nxt not in seen:
                    seen.add(nxt)
                    todo.append(nxt)
        return frozenset(seen)

    def productions(self, state: frozenset) -> list[tuple]:
        hit = self._cache.get(state)
        if hit is not None:
            return hit
        merged: dict[tuple, list] = {}
        for nfa in state:
            for key, payload, target in self._tr[nfa]:
                slot = merged.setdefault(key, [payload, set()])
                slot[1].add(target)
        rows = []
        for key, (payload, targets) in merged.items():
            kind, ident = key
            if kind == "AT":
                rank: tuple = (ident[1], ident[0])
            elif kind in ("SE", "SENS", "SEANY"):
                rank = (self._pos[key], ident[1] if kind == "SE" else "", ident[0] if kind == "SE" else ident or "")
            else:
                rank = ()
            rows.append((_ORDER[kind], rank, kind, payload if kind != "SENS" else ident, self._close(targets)))
        if self._accept in state:
            rows.append((_ORDER["EE"], (), "EE", None, None))
        rows.sort(key=lambda r: (r[0], r[1]))
        out = [(kind, payload, nxt) for _o, _r, kind, payload, nxt in rows]
        self._cache[state] = out
        return out


# --------------------------------------------------------------------------------------------------
# Decoder

class _Bits:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.limit = len(data) * 8

    def read(self, width: int, what: str = "value") -> int:
        if width == 0:
            return 0
        if self.pos + width > self.limit:
            raise ExiDecodeError(f"stream ends inside {what} (bit {self.pos} of {self.limit})")
        end = self.pos + width
        first, last = self.pos // 8, (end - 1) // 8
        chunk = int.from_bytes(self.data[first:last + 1], "big")
        value = (chunk >> ((last + 1) * 8 - end)) & ((1 << width) - 1)
        self.pos = end
        return value

    def uint(self, what: str = "unsigned integer") -> int:
        value = shift = 0
        while True:
            octet = self.read(8, what)
            value |= (octet & 0x7F) << shift
            shift += 7
            if not octet & 0x80:
                return value
            if shift > 7 * 40:
                raise ExiDecodeError(f"{what} runs past 40 octets")


class _Decoder:
    def __init__(self, schema: Schema, bits: _Bits, max_nodes: int):
        self.schema, self.bits = schema, bits
        self.budget = max_nodes
        self.global_values: list[str] = []
        self.local_values: dict[tuple[str, str], list[str]] = {}

    def element(self, decl: ElementDecl, depth: int) -> dict:
        self.budget -= 1
        if self.budget < 0:
            raise ExiDecodeError("the document holds more nodes than the decoder's limit")
        if depth > MAX_DEPTH:
            raise ExiDecodeError(f"elements nest deeper than {MAX_DEPTH}")
        grammar = self.schema.grammar(self.schema.element_type(decl))
        node: dict[str, Any] = {"name": decl.qname[1], "namespace": decl.qname[0]}
        attributes: dict[str, Any] = {}
        children: list[dict] = []
        text: list[str] = []
        state = grammar.start
        where = f"element {decl.qname[1]}"
        while True:
            prods = grammar.productions(state)
            code = self.bits.read(len(prods).bit_length(), f"an event code in {where}")
            if code == len(prods):
                raise ExiUnsupported(
                    f"{where}: the stream takes a strict=false deviation (second-level event code) at bit "
                    f"{self.bits.pos}; only schema-valid content is decoded")
            if code > len(prods):
                raise ExiDecodeError(f"{where}: event code {code} is not in the grammar ({len(prods)} productions)")
            kind, payload, nxt = prods[code]
            if kind == "EE":
                break
            if kind == "AT":
                attributes[payload.qname[1]] = self.value(payload.type, payload.qname, where)
            elif kind == "SE":
                children.append(self.element(payload, depth + 1))
            elif kind == "CH":
                if payload is None:
                    text.append(self.string(decl.qname, where))
                else:
                    node["value"] = self.value(payload, decl.qname, where)
            else:
                raise ExiUnsupported(f"{where}: a wildcard {'attribute' if kind.startswith('AT') else 'element'} "
                                     "(xs:any) is not decoded")
            state = nxt
        if attributes:
            node["attributes"] = attributes
        if children:
            node["children"] = children
        if text:
            node["text"] = text
        return node

    def string(self, qname: tuple[str, str], where: str) -> str:
        head = self.bits.uint(f"a string length in {where}")
        if head == 0:
            table = self.local_values.get(qname, [])
            if not table:
                raise ExiDecodeError(f"{where}: local string-table hit on an empty partition")
            index = self.bits.read((len(table) - 1).bit_length(), "a string-table index")
            if index >= len(table):
                raise ExiDecodeError(f"{where}: local string-table index {index} of {len(table)}")
            return table[index]
        if head == 1:
            table = self.global_values
            if not table:
                raise ExiDecodeError(f"{where}: global string-table hit on an empty table")
            index = self.bits.read((len(table) - 1).bit_length(), "a string-table index")
            if index >= len(table):
                raise ExiDecodeError(f"{where}: global string-table index {index} of {len(table)}")
            return table[index]
        length = head - 2
        if length > MAX_STRING or length * 8 > self.bits.limit - self.bits.pos:
            raise ExiDecodeError(f"{where}: string length {length} runs past the stream")
        chars = []
        for _ in range(length):
            point = self.bits.uint(f"a character in {where}")
            if point > 0x10FFFF:
                raise ExiDecodeError(f"{where}: code point {point:#x} is not a character")
            chars.append(chr(point))
        text = "".join(chars)
        if length:                               # the empty string is never added to the tables
            self.global_values.append(text)
            self.local_values.setdefault(qname, []).append(text)
        return text

    def value(self, typ: SimpleType, qname: tuple[str, str], where: str) -> Any:
        return self._value(codec(typ), qname, where)

    def _value(self, how: tuple, qname: tuple[str, str], where: str) -> Any:
        bits, kind = self.bits, how[0]
        if kind == "string":
            return self.string(qname, where)
        if kind == "enum":
            index = bits.read((len(how[1]) - 1).bit_length(), f"an enumeration index in {where}")
            if index >= len(how[1]):
                raise ExiDecodeError(f"{where}: enumeration index {index} of {len(how[1])}")
            return how[1][index]
        if kind == "bool":
            return bool(bits.read(1, f"a boolean in {where}"))
        if kind == "nbit":
            return how[2] + bits.read(how[1], f"a bounded integer in {where}")
        if kind == "uint":
            return bits.uint(f"an unsigned integer in {where}")
        if kind == "int":
            negative = bits.read(1, f"an integer sign in {where}")
            magnitude = bits.uint(f"an integer in {where}")
            return -(magnitude + 1) if negative else magnitude
        if kind == "binary":
            length = bits.uint(f"a binary length in {where}")
            if length * 8 > bits.limit - bits.pos:
                raise ExiDecodeError(f"{where}: binary length {length} runs past the stream")
            raw = bytes(bits.read(8) for _ in range(length))
            return {"hex": raw.hex()}
        if kind == "decimal":
            negative = bits.read(1, f"a decimal sign in {where}")
            whole = bits.uint(f"a decimal in {where}")
            frac = str(bits.uint(f"a decimal fraction in {where}"))[::-1]
            return ("-" if negative else "") + f"{whole}.{frac}"
        if kind == "float":
            mantissa = self._value(("int",), qname, where)
            exponent = self._value(("int",), qname, where)
            if exponent == -(1 << 14):
                return "INF" if mantissa == 1 else "-INF" if mantissa == -1 else "NaN"
            if abs(exponent) > 400:
                return f"{mantissa}E{exponent}"
            number = mantissa * math.pow(10, exponent)
            return number if math.isfinite(number) else f"{mantissa}E{exponent}"
        if kind == "list":
            count = bits.uint(f"a list length in {where}")
            if count > bits.limit - bits.pos:
                raise ExiDecodeError(f"{where}: list length {count} runs past the stream")
            return [self._value(how[1], qname, where) for _ in range(count)]
        raise ExiUnsupported(f"{where}: {how[1]} is not decoded")


def decode(data: bytes, schema: Schema, *, allow_trailing: bool = False, max_nodes: int = MAX_NODES) -> dict:
    """Decode one EXI document against `schema`.

    Returns {"header": {...}, "root": {"name", "namespace", "event_code", "event_code_bits"},
    "document": tree, "bits_consumed", "padding_bits"}; a tree node is {"name", "namespace"} plus
    "attributes" {local name: value}, "value" (typed content), "children" [nodes] and "text" (mixed
    content) when present. Binary values are {"hex": ...}. Bits left after the document other than
    zero padding to the octet are an ExiDecodeError unless allow_trailing."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ExiDecodeError("input must be bytes")
    data = bytes(data)
    if not data or len(data) > MAX_INPUT:
        raise ExiDecodeError(f"input must hold 1..{MAX_INPUT} bytes")
    cookie = data.startswith(b"$EXI")
    bits = _Bits(data)
    if cookie:
        bits.pos = 32
    if bits.read(2, "the EXI distinguishing bits") != 0b10:
        raise ExiDecodeError("not an EXI stream: the distinguishing bits are not '10'")
    if bits.read(1, "the EXI options flag"):
        raise ExiUnsupported("the EXI header carries an options document; only the default options "
                             "(bit-packed, schema-informed, strict=false) are decoded")
    if bits.read(1, "the EXI preview flag"):
        raise ExiUnsupported("the EXI header marks a preview version")
    version = bits.read(4, "the EXI version")
    if version != 0:
        raise ExiUnsupported(f"EXI format version field {version} (only final version 1 is decoded)")
    roots = schema.global_elements
    width = len(roots).bit_length()
    code = bits.read(width, "the root element event code")
    if code == len(roots):
        raise ExiUnsupported("the root element is SE(*): an element the schema does not declare globally")
    if code > len(roots):
        raise ExiDecodeError(f"root event code {code} is not in the document grammar ({len(roots)} global elements)")
    decl = roots[code]
    tree = _Decoder(schema, bits, max_nodes).element(decl, 0)
    left = bits.limit - bits.pos
    tail = bits.read(left) if left else 0
    if not allow_trailing and (left >= 8 or tail):
        raise ExiDecodeError(f"{left} bit(s) follow the document and are not zero padding to the octet")
    return {
        "header": {"cookie": cookie, "options_present": False, "version": 1},
        "root": {"name": decl.qname[1], "namespace": decl.qname[0], "event_code": code,
                 "event_code_bits": width},
        "document": tree,
        "bits_consumed": bits.limit - left,
        "padding_bits": left,
    }


def flatten(tree: dict, prefix: str = "") -> list[tuple[str, Any]]:
    """[(slash path, value)] for every attribute, typed value and text run of a decoded tree."""
    path = f"{prefix}/{tree['name']}" if prefix else tree["name"]
    out: list[tuple[str, Any]] = [(f"{path}/@{k}", v) for k, v in tree.get("attributes", {}).items()]
    if "value" in tree:
        out.append((path, tree["value"]))
    out.extend((path, t) for t in tree.get("text", ()))
    for kid in tree.get("children", ()):
        out.extend(flatten(kid, path))
    return out
