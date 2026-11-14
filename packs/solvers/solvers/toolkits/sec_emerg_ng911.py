#!/usr/bin/env python3
"""Offline NENA i3 / NG9-1-1 supplied-artifact analyzer.

The reader understands strict SIP messages and their MIME/CID relationships,
PIDF-LO, LoST ECRF queries/responses, RFC 7852 EmergencyCallData blocks,
legacy XML EIDD, and current JSON EIDO.  It never opens a socket, follows a
URI, loads an XML schema, renders embedded content, or modifies an artifact.

Structural validity is not authenticity, caller identity, freshness, routing
authorization, or operational dispatch advice.  Every public parser raises
only :class:`NG911Error` for malformed, unsupported, ambiguous, or excessive
input.
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import math
import quopri
import re
import sys
import uuid
from email import policy
from email.parser import BytesParser
from functools import wraps
from pathlib import Path
from urllib.parse import unquote_to_bytes, urlsplit


MAX_INPUT = 8 * 1024 * 1024
MAX_XML_NODES = 50_000
MAX_JSON_NODES = 50_000
MAX_DEPTH = 64
MAX_HEADERS = 512
MAX_HEADER_LINE = 8192
MAX_MIME_PARTS = 128
MAX_MAPPINGS = 1024
MAX_GEOMETRY_POINTS = 1024
MAX_TEXT = 1024 * 1024

PIDF_NS = "urn:ietf:params:xml:ns:pidf"
DM_NS = "urn:ietf:params:xml:ns:pidf:data-model"
GP_NS = "urn:ietf:params:xml:ns:pidf:geopriv10"
GBP_NS = "urn:ietf:params:xml:ns:pidf:geopriv10:basicPolicy"
CIVIC_NS = "urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr"
GML_NS = "http://www.opengis.net/gml"
SHAPE_NS = "http://www.opengis.net/pidflo/1.0"
CONF_NS = "urn:ietf:params:xml:ns:geopriv:conf"
LOST_NS = "urn:ietf:params:xml:ns:lost1"
ECD_BASE_NS = "urn:ietf:params:xml:ns:EmergencyCallData"
EIDD_NS = "http://eidd.nena.org"
NIEM_NS = "http://niem.gov/niem/niem-core/2.0"
VCARD_NS = "urn:ietf:params:xml:ns:vcard-4.0"

_ECD = {
    "ProviderInfo": "urn:ietf:params:xml:ns:EmergencyCallData:ProviderInfo",
    "ServiceInfo": "urn:ietf:params:xml:ns:EmergencyCallData:ServiceInfo",
    "DeviceInfo": "urn:ietf:params:xml:ns:EmergencyCallData:DeviceInfo",
    "SubscriberInfo": "urn:ietf:params:xml:ns:EmergencyCallData:SubscriberInfo",
    "Comment": "urn:ietf:params:xml:ns:EmergencyCallData:Comment",
}
_CIVIC_FIELDS = {
    "country", "A1", "A2", "A3", "A4", "A5", "A6", "PRM", "PRD", "RD",
    "STS", "POD", "POM", "RDSEC", "RDBR", "RDSUBBR", "HNO", "HNS", "LMK",
    "LOC", "FLR", "NAM", "PC", "BLD", "UNIT", "ROOM", "PLC", "PCN", "POBOX",
    "ADDCODE", "SEAT",
}
_CIVIC_ORDER = (
    "country", "A1", "A2", "A3", "A4", "A5", "A6", "PRM", "PRD", "RD",
    "STS", "POD", "POM", "RDSEC", "RDBR", "RDSUBBR", "HNO", "HNS", "LMK",
    "LOC", "FLR", "NAM", "PC", "BLD", "UNIT", "ROOM", "SEAT", "PLC", "PCN",
    "POBOX", "ADDCODE",
)
_GEOMETRIES = {"Point", "Polygon", "Circle", "Ellipse", "ArcBand", "Sphere", "Ellipsoid", "Prism"}
_GML_GEOMETRIES = {"Point", "Polygon"}
_SHAPE_GEOMETRIES = _GEOMETRIES - _GML_GEOMETRIES
_CRS_DIMENSIONS = {
    "urn:ogc:def:crs:EPSG::4326": 2,
    "urn:ogc:def:crs:EPSG::4979": 3,
}
_DISTANCE_UOM = "urn:ogc:def:uom:EPSG::9001"
_ANGLE_UOMS = {"urn:ogc:def:uom:EPSG::9101", "urn:ogc:def:uom:EPSG::9102"}
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
_SERVICE_URN = re.compile(r"urn:service:(?:test\.)?sos(?:\.[A-Za-z0-9][A-Za-z0-9.-]*)?", re.I)


class NG911Error(ValueError):
    """Malformed, unsupported, unsafe, ambiguous, or excessive NG9-1-1 input."""


def _guard(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except NG911Error:
            raise
        except Exception as exc:  # public parser boundary: no backend/stdlib leaks
            raise NG911Error(f"{function.__name__}: invalid input ({type(exc).__name__})") from None
    return checked


def _input_bytes(value, *, allow_empty=False):
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise NG911Error("input must be bytes or text")
    data = bytes(value)
    if (not allow_empty and not data) or len(data) > MAX_INPUT:
        raise NG911Error("input size is outside the 1..8 MiB limit")
    return data


def _qname(element):
    tag = element.tag
    if not isinstance(tag, str):
        raise NG911Error("non-element XML node is not supported")
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local
    return "", tag


def _clean_text(value, *, required=False):
    text = "" if value is None else " ".join(value.split())
    if len(text.encode("utf-8")) > MAX_TEXT:
        raise NG911Error("XML text exceeds limit")
    if required and not text:
        raise NG911Error("required XML text is empty")
    return text


def _xml_datetime(value, name, *, no_expiration=False, canonical_utc=False):
    text = _clean_text(value, required=True)
    if no_expiration and text in ("NO-CACHE", "NO-EXPIRATION"):
        return text
    if len(text) > 64 or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        text,
    ):
        raise NG911Error(f"invalid {name} dateTime")
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NG911Error(f"invalid {name} dateTime") from exc
    if parsed.utcoffset() is None:
        raise NG911Error(f"{name} dateTime lacks a timezone")
    if canonical_utc and not text.endswith("Z"):
        raise NG911Error(f"{name} dateTime must use canonical UTC Z")
    return text


def _xml(value):
    data = _input_bytes(value)
    try:
        from lxml import etree
    except ImportError as exc:
        raise NG911Error("lxml is required for safe XML parsing") from exc

    class DenyResolver(etree.Resolver):
        def resolve(self, url, pubid, context):
            raise NG911Error("external XML resources are forbidden")

    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True,
                             huge_tree=False, recover=False, remove_comments=True,
                             remove_pis=True)
    parser.resolvers.add(DenyResolver())
    root = etree.fromstring(data, parser)
    if root.getroottree().docinfo.doctype:
        raise NG911Error("DOCTYPE is forbidden")
    stack = [(root, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_XML_NODES or depth > MAX_DEPTH:
            raise NG911Error("XML tree exceeds node or depth limit")
        if isinstance(node, etree._Entity):
            raise NG911Error("XML entities are forbidden")
        namespace, local = _qname(node)
        if namespace == "http://www.w3.org/2001/XInclude" or local == "include" and namespace.endswith("XInclude"):
            raise NG911Error("XInclude is forbidden")
        for attr, attr_value in node.attrib.items():
            if len(str(attr).encode("utf-8")) + len(str(attr_value).encode("utf-8")) > MAX_TEXT:
                raise NG911Error("XML attribute exceeds limit")
        if node.text is not None and len(node.text.encode("utf-8")) > MAX_TEXT:
            raise NG911Error("XML text exceeds limit")
        stack.extend((child, depth + 1) for child in reversed(list(node)))
    return root


def _finite(text, name):
    if not isinstance(text, str) or len(text) > 128:
        raise NG911Error(f"invalid {name}")
    if not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", text.strip()):
        raise NG911Error(f"invalid {name}")
    value = float(text)
    if not math.isfinite(value):
        raise NG911Error(f"non-finite {name}")
    return value


def _coordinates(text, dimension, name="coordinate"):
    tokens = (text or "").split()
    if not tokens or len(tokens) % dimension or len(tokens) // dimension > MAX_GEOMETRY_POINTS:
        raise NG911Error(f"invalid or excessive {name} list")
    values = [_finite(token, name) for token in tokens]
    points = [values[index:index + dimension] for index in range(0, len(values), dimension)]
    for point in points:
        if not -90 <= point[0] <= 90 or not -180 <= point[1] <= 180:
            raise NG911Error("geodetic coordinate is outside WGS-84")
    return points


def _civic(element):
    namespace, local = _qname(element)
    if (namespace, local) != (CIVIC_NS, "civicAddress"):
        raise NG911Error("expected namespace-qualified civicAddress")
    fields = {}
    languages = {}
    issues = []
    positions = {name: index for index, name in enumerate(_CIVIC_ORDER)}
    last_position = -1
    foreign_seen = False
    for child in element:
        child_ns, name = _qname(child)
        if child_ns != CIVIC_NS or name not in _CIVIC_FIELDS:
            foreign_seen = True
            issues.append(f"unrecognized civic element {{{child_ns}}}{name}")
            continue
        position = positions[name]
        if foreign_seen or position < last_position:
            raise NG911Error(f"civic-address element is out of RFC 5139 sequence: {name}")
        last_position = position
        value = _clean_text(child.text, required=True)
        if name in fields:
            raise NG911Error(f"duplicate civic-address field: {name}")
        fields[name] = value
        lang = child.get("{http://www.w3.org/XML/1998/namespace}lang")
        if lang:
            languages.setdefault(name, []).append(lang)
    country = fields.get("country")
    if isinstance(country, str) and not re.fullmatch(r"[A-Z]{2}", country):
        issues.append("country is not two uppercase ISO-3166 letters")
    if "A6" in fields and "RD" not in fields:
        issues.append("A6 is present without RD; A6 is not the RFC 5139 street field")
    return {"kind": "civic", "fields": fields, "languages": languages, "issues": issues}


def _geometry(element, inherited_crs=None):
    namespace, kind = _qname(element)
    expected_namespace = GML_NS if kind in _GML_GEOMETRIES else SHAPE_NS
    if kind not in _GEOMETRIES or namespace != expected_namespace:
        raise NG911Error("unsupported geodetic geometry")
    crs = element.get("srsName") or inherited_crs
    if crs not in _CRS_DIMENSIONS:
        raise NG911Error("geometry requires supported WGS-84 srsName")
    dimension = _CRS_DIMENSIONS[crs]
    declared_dimension = element.get("srsDimension")
    if declared_dimension is not None and declared_dimension != str(dimension):
        raise NG911Error("geometry srsDimension disagrees with its CRS")
    if kind in {"Polygon", "Circle", "Ellipse", "ArcBand"} and dimension != 2:
        raise NG911Error(f"{kind} requires the two-dimensional WGS-84 CRS")
    if kind in {"Sphere", "Ellipsoid", "Prism"} and dimension != 3:
        raise NG911Error(f"{kind} requires the three-dimensional WGS-84 CRS")
    for descendant in element.iterdescendants():
        if descendant.get("srsName") is not None or descendant.get("srsDimension") is not None:
            raise NG911Error("a child geometry must not respecify its CRS")
    out = {"kind": "geodetic", "shape": kind, "crs": crs, "dimension": dimension, "issues": []}
    if kind == "Point":
        positions = element.findall(f"{{{GML_NS}}}pos")
        if len(positions) != 1:
            raise NG911Error("Point requires exactly one gml:pos")
        points = _coordinates(positions[0].text, dimension)
        if len(points) != 1:
            raise NG911Error("Point must contain exactly one coordinate")
        out["coordinates"] = points[0]
        return out
    if kind == "Polygon":
        points = _polygon_points(element, dimension)
        if len(points) > 16:
            out["issues"].append("polygon exceeds RFC 5491 real-time recommendation of 16 points including closure")
        out["coordinates"] = points
        return out

    if kind == "Prism":
        bases = element.findall(f"{{{SHAPE_NS}}}base")
        heights = element.findall(f"{{{SHAPE_NS}}}height")
        if len(bases) != 1 or len(heights) != 1 or len(bases[0]) != 1:
            raise NG911Error("Prism requires one polygon base and one height")
        polygon = bases[0][0]
        if _qname(polygon) != (GML_NS, "Polygon"):
            raise NG911Error("Prism base must contain one gml:Polygon")
        points = _polygon_points(polygon, 3)
        if any(point[2] != points[0][2] for point in points):
            raise NG911Error("Prism base points must have one altitude")
        height = _shape_scalar(heights[0], "height", "distance", positive=True)
        out["coordinates"] = points
        out["parameters"] = [height]
        return out

    positions = element.findall(f"{{{GML_NS}}}pos")
    if len(positions) != 1:
        raise NG911Error(f"{kind} requires exactly one gml:pos")
    out["coordinates"] = _coordinates(positions[0].text, dimension)[0]
    requirements = {
        "Circle": (("radius", "distance", True),),
        "Sphere": (("radius", "distance", True),),
        "Ellipse": (("semiMajorAxis", "distance", True),
                    ("semiMinorAxis", "distance", True),
                    ("orientation", "angle", False)),
        "Ellipsoid": (("semiMajorAxis", "distance", True),
                      ("semiMinorAxis", "distance", True),
                      ("verticalAxis", "distance", True),
                      ("orientation", "angle", False)),
        "ArcBand": (("innerRadius", "distance", False),
                    ("outerRadius", "distance", True),
                    ("startAngle", "angle", False),
                    ("openingAngle", "opening_angle", True)),
    }[kind]
    parameters = []
    allowed = {(GML_NS, "pos")}
    for name, scalar_kind, positive in requirements:
        nodes = element.findall(f"{{{SHAPE_NS}}}{name}")
        if len(nodes) != 1:
            raise NG911Error(f"{kind} requires exactly one {name}")
        parameters.append(_shape_scalar(nodes[0], name, scalar_kind, positive=positive))
        allowed.add((SHAPE_NS, name))
    if any(_qname(child) not in allowed for child in element):
        raise NG911Error(f"{kind} contains an unsupported child")
    values = {item["name"]: item["value"] for item in parameters}
    if "semiMajorAxis" in values and values["semiMajorAxis"] < values["semiMinorAxis"]:
        raise NG911Error("semiMajorAxis must not be shorter than semiMinorAxis")
    if kind == "ArcBand" and values["outerRadius"] <= values["innerRadius"]:
        raise NG911Error("ArcBand outerRadius must exceed innerRadius")
    out["parameters"] = parameters
    return out


def _polygon_points(element, dimension):
    exteriors = element.findall(f"{{{GML_NS}}}exterior")
    if len(exteriors) != 1 or element.findall(f"{{{GML_NS}}}interior"):
        raise NG911Error("Polygon requires one exterior ring and no interior rings")
    rings = exteriors[0].findall(f"{{{GML_NS}}}LinearRing")
    if len(rings) != 1:
        raise NG911Error("Polygon exterior requires one LinearRing")
    lists = rings[0].findall(f"{{{GML_NS}}}posList")
    positions = rings[0].findall(f"{{{GML_NS}}}pos")
    if len(lists) == 1 and not positions:
        points = _coordinates(lists[0].text, dimension, "polygon coordinate")
    elif not lists and positions:
        points = []
        for position in positions:
            parsed = _coordinates(position.text, dimension, "polygon coordinate")
            if len(parsed) != 1:
                raise NG911Error("each Polygon gml:pos requires one coordinate")
            points.append(parsed[0])
    else:
        raise NG911Error("Polygon must use exactly one posList or a sequence of pos elements")
    if len(points) < 4 or points[0] != points[-1]:
        raise NG911Error("Polygon ring must have at least four points and be closed")
    return points


def _shape_scalar(element, name, scalar_kind, *, positive):
    if list(element):
        raise NG911Error(f"{name} must be scalar")
    value = _finite(_clean_text(element.text, required=True), name)
    uom = element.get("uom")
    if scalar_kind == "distance":
        if uom != _DISTANCE_UOM:
            raise NG911Error(f"{name} must use EPSG metre units")
        if value < 0 or positive and value <= 0:
            raise NG911Error(f"{name} is outside its permitted range")
    else:
        if uom not in _ANGLE_UOMS:
            raise NG911Error(f"{name} must use EPSG degree or radian units")
        full_turn = 2 * math.pi if uom.endswith("9101") else 360.0
        if scalar_kind == "opening_angle":
            if not 0 < value <= full_turn:
                raise NG911Error(f"{name} is outside one full turn")
        elif not 0 <= value < full_turn:
            raise NG911Error(f"{name} is outside one full turn")
    return {"name": name, "value": value, "uom": uom}


def _location_children(location_info):
    locations = []
    seen = set()
    for node in location_info.iterdescendants():
        namespace, local = _qname(node)
        if (namespace, local) == (CIVIC_NS, "civicAddress"):
            if any((ancestor is not location_info and _qname(ancestor) == (CIVIC_NS, "civicAddress"))
                   for ancestor in node.iterancestors()):
                continue
            locations.append(_civic(node))
        elif ((local in _GML_GEOMETRIES and namespace == GML_NS)
              or (local in _SHAPE_GEOMETRIES and namespace == SHAPE_NS)):
            # A Point used inside a Prism/Circle is a child parameter, not an
            # independent location candidate.
            if any(_qname(ancestor)[1] in _GEOMETRIES for ancestor in node.iterancestors()
                   if ancestor is not location_info):
                continue
            marker = id(node)
            if marker not in seen:
                seen.add(marker)
                locations.append(_geometry(node))
    return locations


def _provided_by(root):
    output = []
    for provided in root.iter():
        namespace, local = _qname(provided)
        if local != "provided-by" or namespace not in (ECD_BASE_NS, GP_NS):
            continue
        refs, values = [], []
        for child in provided.iterdescendants():
            child_ns, child_local = _qname(child)
            if child_ns != ECD_BASE_NS:
                continue
            if child_local == "EmergencyCallDataReference":
                purpose, reference = child.get("purpose"), child.get("ref")
                if not purpose or not reference:
                    raise NG911Error("provided-by reference lacks purpose or ref")
                refs.append({"purpose": purpose, "uri": reference, "fetched": False})
            elif child_local == "EmergencyCallDataValue":
                values.append({"embedded_children": len(child)})
        output.append({"references": refs, "values": values})
    return output


@_guard
def parse_pidf_lo(data):
    """Parse one supplied PIDF-LO XML document without dereferencing anything."""

    root = _xml(data)
    if _qname(root) != (PIDF_NS, "presence"):
        raise NG911Error("expected PIDF presence root")
    entity = root.get("entity")
    if not entity or len(entity) > 4096:
        raise NG911Error("PIDF presence requires a bounded entity URI")
    records = []
    for geopriv in root.iter(f"{{{GP_NS}}}geopriv"):
        source = next((ancestor for ancestor in geopriv.iterancestors()
                       if (_qname(ancestor) == (PIDF_NS, "tuple")
                           or _qname(ancestor) in ((DM_NS, "device"), (DM_NS, "person")))), None)
        if source is None:
            raise NG911Error("geopriv must belong to pidf:tuple or dm:device/person")
        source_ns, source_kind = _qname(source)
        if source_ns not in (PIDF_NS, DM_NS):
            raise NG911Error("geopriv has an unsupported PIDF parent")
        infos = geopriv.findall(f"{{{GP_NS}}}location-info")
        if len(infos) != 1:
            raise NG911Error("each geopriv needs exactly one location-info")
        locations = _location_children(infos[0])
        if not locations:
            raise NG911Error("location-info contains no supported location")
        usage = {}
        rule_nodes = geopriv.findall(f"{{{GP_NS}}}usage-rules")
        if len(rule_nodes) != 1:
            raise NG911Error("each geopriv needs exactly one usage-rules")
        for child in rule_nodes[0]:
            namespace, local = _qname(child)
            if namespace not in (GP_NS, GBP_NS):
                continue
            value = _clean_text(child.text)
            if local == "retransmission-allowed":
                if value not in ("true", "false", "1", "0"):
                    raise NG911Error("invalid retransmission-allowed value")
                value = "true" if value in ("true", "1") else "false"
            if local == "retention-expiry":
                value = _xml_datetime(value, "retention-expiry")
            if local in usage:
                raise NG911Error("duplicate PIDF-LO usage rule")
            usage[local] = value
        method = geopriv.findtext(f"{{{GP_NS}}}method")
        timestamp = source.findtext(f"{{{DM_NS}}}timestamp") or source.findtext(f"{{{PIDF_NS}}}timestamp")
        if timestamp:
            timestamp = _xml_datetime(timestamp, "PIDF timestamp")
        confidence = []
        # RFC 7459 places confidence alongside location-info in geopriv.  Also
        # accept it inside location-info for artifacts produced from older
        # draft/schema interpretations, without ever using local-name matching.
        for node in geopriv.iter(f"{{{CONF_NS}}}confidence"):
            value = _clean_text(node.text, required=True)
            if value == "unknown":
                parsed = value
            else:
                parsed = _finite(value, "confidence")
                if not 0 <= parsed <= 100:
                    raise NG911Error("confidence is outside 0..100 percent")
            confidence.append({"value": parsed, "pdf": node.get("pdf")})
        issues = []
        if confidence and any(location.get("shape") == "Point" for location in locations):
            issues.append("RFC 7459 confidence is not applicable to a Point geometry")
        records.append({
            "source": {"kind": source_kind, "id": source.get("id")},
            "locations": locations,
            "usage_rules": usage,
            "method": _clean_text(method) if method else None,
            "timestamp": timestamp,
            "confidence": confidence,
            "issues": issues,
        })
    if not records:
        raise NG911Error("PIDF-LO contains no geopriv location object")
    return {
        "type": "pidf-lo",
        "entity": entity,
        "location_objects": records,
        "provided_by": _provided_by(root),
        "limitations": [
            "Location content is not authenticated or proven fresh by structural parsing.",
            "External references were retained and were not fetched.",
        ],
    }


def _lost_location(element):
    location_id = element.get("id")
    profile = element.get("profile")
    if not location_id or len(location_id) > 4096:
        raise NG911Error("LoST location requires a bounded id")
    if profile is not None and profile not in ("civic", "geodetic-2d", "geodetic-3d"):
        raise NG911Error("unsupported LoST location profile")
    candidates = []
    for child in element:
        qname = _qname(child)
        if qname == (CIVIC_NS, "civicAddress"):
            candidates.append(_civic(child))
        elif ((qname[1] in _GML_GEOMETRIES and qname[0] == GML_NS)
              or (qname[1] in _SHAPE_GEOMETRIES and qname[0] == SHAPE_NS)):
            candidates.append(_geometry(child))
    if len(candidates) != 1:
        raise NG911Error("LoST location requires exactly one location value")
    value = candidates[0]
    interpreted_profile = profile
    if interpreted_profile is None:
        interpreted_profile = ("civic" if value["kind"] == "civic" else
                               f"geodetic-{value.get('dimension')}d")
    if interpreted_profile == "civic" and value["kind"] != "civic":
        raise NG911Error("LoST civic profile does not contain a civic address")
    if interpreted_profile.startswith("geodetic-"):
        expected_dimension = 2 if interpreted_profile == "geodetic-2d" else 3
        if value["kind"] != "geodetic" or value.get("dimension") != expected_dimension:
            raise NG911Error("LoST geodetic profile and geometry dimension disagree")
    return {"id": location_id, "profile": profile,
            "interpreted_profile": interpreted_profile, "value": value}


@_guard
def parse_lost(data, *, expected_location_id=None):
    """Parse a supplied RFC 5222 LoST query, response, error, or redirect."""

    root = _xml(data)
    if expected_location_id is not None and (not isinstance(expected_location_id, str)
                                             or not expected_location_id
                                             or len(expected_location_id) > 4096):
        raise NG911Error("expected_location_id must be bounded nonempty text")
    namespace, kind = _qname(root)
    if namespace != LOST_NS or kind not in ("findService", "findServiceResponse", "errors", "redirect"):
        raise NG911Error("expected a LoST findService/result document")
    if kind == "findService":
        locations = [_lost_location(node) for node in root.findall(f"{{{LOST_NS}}}location")]
        if not 1 <= len(locations) <= MAX_MAPPINGS:
            raise NG911Error("findService location count is outside limit")
        profiles = [item["interpreted_profile"] for item in locations]
        identifiers = [item["id"] for item in locations]
        if len(set(profiles)) != len(profiles) or len(set(identifiers)) != len(identifiers):
            raise NG911Error("findService location profiles and ids must be unique")
        if sum(profile in ("civic", "geodetic-2d") for profile in profiles) != 1:
            raise NG911Error("findService requires exactly one baseline location profile")
        if expected_location_id is not None and expected_location_id not in identifiers:
            raise NG911Error("LoST query location id does not match expected_location_id")
        services = [_clean_text(node.text, required=True) for node in root.findall(f"{{{LOST_NS}}}service")]
        if len(services) != 1 or not _SERVICE_URN.fullmatch(services[0]):
            raise NG911Error("findService requires one emergency service URN")
        boundary = root.get("serviceBoundary", "reference")
        if boundary not in ("value", "reference"):
            raise NG911Error("invalid serviceBoundary mode")
        for name in ("recursive", "validateLocation"):
            if root.get(name) not in (None, "true", "false", "1", "0"):
                raise NG911Error(f"invalid LoST boolean {name}")
        return {"type": "lost", "message": kind, "service": services[0],
                "location": locations[0], "locations": locations,
                "recursive": root.get("recursive") in ("true", "1"),
                "validate_location": root.get("validateLocation") in ("true", "1"),
                "service_boundary": boundary, "network_activity": False}
    if kind == "findServiceResponse":
        nodes = root.findall(f"{{{LOST_NS}}}mapping")
        if not 1 <= len(nodes) <= MAX_MAPPINGS:
            raise NG911Error("findServiceResponse mapping count is outside limit")
        mappings = []
        for node in nodes:
            uris = [_clean_text(item.text, required=True) for item in node.findall(f"{{{LOST_NS}}}uri")]
            if not uris:
                raise NG911Error("LoST mapping has no routing URI")
            if any(not urlsplit(uri).scheme for uri in uris):
                raise NG911Error("LoST mapping contains a URI without a scheme")
            schemes = [urlsplit(uri).scheme.lower() for uri in uris]
            if len(set(schemes)) != len(schemes):
                raise NG911Error("LoST mapping repeats a URI scheme")
            required_attributes = {name: node.get(name) for name in
                                   ("expires", "lastUpdated", "source", "sourceId")}
            if any(not value or len(value) > 4096 for value in required_attributes.values()):
                raise NG911Error("LoST mapping lacks a bounded required attribute")
            display_names = []
            for item in node.findall(f"{{{LOST_NS}}}displayName"):
                language = item.get("{http://www.w3.org/XML/1998/namespace}lang")
                if not language or not re.fullmatch(r"[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*", language):
                    raise NG911Error("LoST displayName requires a valid xml:lang")
                display_names.append({"text": _clean_text(item.text, required=True),
                                      "language": language})
            service_number = node.findtext(f"{{{LOST_NS}}}serviceNumber")
            if service_number is not None:
                service_number = _clean_text(service_number, required=True)
                if not re.fullmatch(r"[0-9*#]+", service_number):
                    raise NG911Error("LoST serviceNumber contains a non-dialpad character")
            mapping = {
                "expires": _xml_datetime(required_attributes["expires"], "LoST expires",
                                          no_expiration=True, canonical_utc=True),
                "last_updated": _xml_datetime(required_attributes["lastUpdated"],
                                               "LoST lastUpdated", canonical_utc=True),
                "source": required_attributes["source"],
                "source_id": required_attributes["sourceId"],
                "display_names": display_names,
                "service": _clean_text(node.findtext(f"{{{LOST_NS}}}service"), required=True),
                "uris": uris, "service_number": service_number,
            }
            if not _SERVICE_URN.fullmatch(mapping["service"]):
                raise NG911Error("LoST mapping service is not an emergency service URN")
            boundary_value = node.find(f"{{{LOST_NS}}}serviceBoundary")
            boundary_ref = node.find(f"{{{LOST_NS}}}serviceBoundaryReference")
            if boundary_value is not None and boundary_ref is not None:
                raise NG911Error("mapping has both boundary value and reference")
            if (boundary_ref is not None
                    and (not boundary_ref.get("source") or not boundary_ref.get("key"))):
                raise NG911Error("serviceBoundaryReference requires source and key")
            mapping["boundary"] = ({"mode": "value", "xml_children": len(boundary_value)}
                                   if boundary_value is not None else
                                   {"mode": "reference", "source": boundary_ref.get("source"),
                                    "key": boundary_ref.get("key"), "fetched": False}
                                   if boundary_ref is not None else None)
            mappings.append(mapping)
        used = [node.get("id") for node in root.findall(f"{{{LOST_NS}}}locationUsed")]
        if any(not value for value in used):
            raise NG911Error("locationUsed lacks id")
        if expected_location_id is not None and expected_location_id not in used:
            raise NG911Error("LoST locationUsed does not reference the supplied location id")
        validation = None
        validation_node = root.find(f"{{{LOST_NS}}}locationValidation")
        if validation_node is not None:
            validation = {}
            for child in validation_node:
                child_ns, child_local = _qname(child)
                if child_ns == LOST_NS and child_local in ("valid", "invalid", "unchecked"):
                    validation[child_local] = _clean_text(child.text).split()
        warnings = []
        warning_node = root.find(f"{{{LOST_NS}}}warnings")
        if warning_node is not None:
            for child in warning_node:
                child_ns, child_local = _qname(child)
                if child_ns == LOST_NS:
                    warnings.append({"code": child_local, "attributes": dict(child.attrib),
                                     "text": _clean_text(child.text)})
        path = [node.get("source") for node in root.findall(f"{{{LOST_NS}}}path/{{{LOST_NS}}}via")]
        if any(not source for source in path):
            raise NG911Error("LoST path via lacks source")
        return {"type": "lost", "message": kind, "mappings": mappings,
                "location_used": used,
                "expected_location_id_matched": (expected_location_id in used
                                                 if expected_location_id is not None else None),
                "location_validation": validation, "warnings": warnings, "path": path,
                "network_activity": False,
                "note": "mapping URIs are routing next hops, not replacements for the service URN"}
    if kind == "errors":
        errors = []
        for child in root:
            child_ns, local = _qname(child)
            if child_ns == LOST_NS:
                errors.append({"code": local, "attributes": dict(child.attrib),
                               "text": _clean_text(child.text)})
        if not errors:
            raise NG911Error("LoST errors document contains no error")
        return {"type": "lost", "message": kind, "source": root.get("source"), "errors": errors}
    allowed_attributes = {"target", "source", "message",
                          "{http://www.w3.org/XML/1998/namespace}lang"}
    if any(name not in allowed_attributes for name in root.attrib):
        raise NG911Error("LoST redirect has an unsupported attribute")
    target, source = root.get("target"), root.get("source")
    app_unique = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9]+")
    if not target or not source or not app_unique.fullmatch(target) or not app_unique.fullmatch(source):
        raise NG911Error("LoST redirect requires valid target and source application identifiers")
    message = root.get("message")
    language = root.get("{http://www.w3.org/XML/1998/namespace}lang")
    if (message is None) != (language is None):
        raise NG911Error("LoST redirect message and xml:lang must occur together")
    if language is not None and not re.fullmatch(r"[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*", language):
        raise NG911Error("LoST redirect xml:lang is invalid")
    return {"type": "lost", "message": kind, "target": target,
            "source": source, "reason": message, "language": language, "fetched": False}


def _media_type(value):
    if not isinstance(value, str) or "\r" in value or "\n" in value or len(value) > 4096:
        raise NG911Error("invalid Content-Type")
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise NG911Error("invalid Content-Type") from exc
    # The email package deliberately repairs malformed MIME fields (including
    # treating a bare token as text/plain), which is useful for mail clients
    # but unsafe for a wire analyzer.  Validate the RFC 2045 token/parameter
    # grammar first, including quoted-pairs, and only then let BytesParser
    # handle multipart framing.
    token = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
    length = len(value)
    position = 0

    def ows():
        nonlocal position
        while position < length and value[position] in " \t":
            position += 1

    ows()
    match = token.match(value, position)
    if match is None:
        raise NG911Error("invalid Content-Type media type")
    major = match.group(0)
    position = match.end()
    if position >= length or value[position] != "/":
        raise NG911Error("invalid Content-Type media type")
    position += 1
    match = token.match(value, position)
    if match is None:
        raise NG911Error("invalid Content-Type media subtype")
    minor = match.group(0)
    position = match.end()
    params = {}
    while True:
        ows()
        if position == length:
            break
        if value[position] != ";":
            raise NG911Error("invalid Content-Type parameter separator")
        position += 1
        ows()
        match = token.match(value, position)
        if match is None:
            raise NG911Error("invalid Content-Type parameter name")
        name = match.group(0).lower()
        position = match.end()
        ows()
        if position >= length or value[position] != "=":
            raise NG911Error("invalid Content-Type parameter")
        position += 1
        ows()
        if position < length and value[position] == '"':
            position += 1
            decoded = []
            while position < length and value[position] != '"':
                character = value[position]
                code = ord(character)
                if character == "\\":
                    position += 1
                    if position >= length or not (value[position] in " \t" or 0x21 <= ord(value[position]) <= 0x7e):
                        raise NG911Error("invalid Content-Type quoted-pair")
                    decoded.append(value[position])
                    position += 1
                elif character == "\t" or character == " " or code == 0x21 or 0x23 <= code <= 0x5b or 0x5d <= code <= 0x7e:
                    decoded.append(character)
                    position += 1
                else:
                    raise NG911Error("invalid Content-Type quoted value")
            if position >= length:
                raise NG911Error("unterminated Content-Type quoted value")
            position += 1
            parameter_value = "".join(decoded)
        else:
            match = token.match(value, position)
            if match is None:
                raise NG911Error("invalid Content-Type parameter value")
            parameter_value = match.group(0)
            position = match.end()
        if name in params:
            raise NG911Error("duplicate Content-Type parameter")
        params[name] = parameter_value
    return f"{major.lower()}/{minor.lower()}", params


def _validate_ecd_children(root, namespace, token):
    specifications = {
        "ProviderInfo": (
            ("DataProviderReference", 1, 1), ("DataProviderString", 1, 1),
            ("ProviderID", 0, 1), ("ProviderIDSeries", 0, 1),
            ("TypeOfProvider", 1, 1), ("ContactURI", 1, 1),
            ("Language", 1, None), ("DataProviderContact", 0, 1),
            ("SubcontractorPrincipal", 0, 1), ("SubcontractorPriority", 0, 1),
        ),
        "ServiceInfo": (
            ("DataProviderReference", 1, 1), ("ServiceEnvironment", 0, 1),
            ("ServiceType", 1, None), ("ServiceMobility", 1, 1),
        ),
        "DeviceInfo": (
            ("DataProviderReference", 1, 1), ("DeviceClassification", 0, 1),
            ("DeviceMfgr", 0, 1), ("DeviceModelNr", 0, 1),
            ("UniqueDeviceID", 0, None), ("DeviceSpecificData", 0, 1),
            ("DeviceSpecificType", 0, 1),
        ),
        "SubscriberInfo": (
            ("DataProviderReference", 1, 1), ("SubscriberData", 1, 1),
        ),
        "Comment": (
            ("DataProviderReference", 1, 1), ("Comment", 0, None),
        ),
    }[token]
    positions = {name: index for index, (name, _minimum, _maximum) in enumerate(specifications)}
    counts = {name: 0 for name, _minimum, _maximum in specifications}
    last_position = -1
    foreign_seen = False
    for child in root:
        child_ns, name = _qname(child)
        if child_ns != namespace:
            foreign_seen = True
            continue
        if foreign_seen or name not in positions or positions[name] < last_position:
            raise NG911Error(f"invalid {token} child or sequence: {name}")
        last_position = positions[name]
        counts[name] += 1
        maximum = specifications[last_position][2]
        if maximum is not None and counts[name] > maximum:
            raise NG911Error(f"too many {token}/{name} elements")
    for name, minimum, _maximum in specifications:
        if counts[name] < minimum:
            raise NG911Error(f"{token} lacks required {name}")

    if token == "ProviderInfo":
        contact = root.findtext(f"{{{namespace}}}ContactURI")
        if not contact or not urlsplit(_clean_text(contact)).scheme:
            raise NG911Error("ProviderInfo ContactURI is not an absolute URI")
        provider_id = root.findtext(f"{{{namespace}}}ProviderID")
        provider_series = root.findtext(f"{{{namespace}}}ProviderIDSeries")
        if (provider_id is None) != (provider_series is None):
            raise NG911Error("ProviderInfo ProviderID and ProviderIDSeries must occur together")
        provider_type = _clean_text(root.findtext(f"{{{namespace}}}TypeOfProvider"), required=True)
        if provider_type != "Client" and provider_id is None:
            raise NG911Error("non-Client ProviderInfo requires ProviderID and ProviderIDSeries")
        for language in root.findall(f"{{{namespace}}}Language"):
            if not re.fullmatch(r"[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*",
                                _clean_text(language.text, required=True)):
                raise NG911Error("ProviderInfo Language is not a language tag")
        priority = root.findtext(f"{{{namespace}}}SubcontractorPriority")
        if priority is not None and _clean_text(priority) not in ("sub", "main"):
            raise NG911Error("invalid ProviderInfo SubcontractorPriority")
    elif token == "DeviceInfo":
        for identifier in root.findall(f"{{{namespace}}}UniqueDeviceID"):
            if not identifier.get("TypeOfDeviceID") or not _clean_text(identifier.text):
                raise NG911Error("UniqueDeviceID lacks type or value")
        specific = root.findtext(f"{{{namespace}}}DeviceSpecificData")
        if specific is not None and not urlsplit(_clean_text(specific)).scheme:
            raise NG911Error("DeviceSpecificData is not an absolute URI")
        specific_type = root.findtext(f"{{{namespace}}}DeviceSpecificType")
        if (specific is None) != (specific_type is None):
            raise NG911Error("DeviceSpecificData and DeviceSpecificType must occur together")
    elif token == "ServiceInfo":
        service_types = [_clean_text(node.text, required=True).lower()
                         for node in root.findall(f"{{{namespace}}}ServiceType")]
        environment = root.findtext(f"{{{namespace}}}ServiceEnvironment")
        if any(value != "wireless" for value in service_types) and not _clean_text(environment):
            raise NG911Error("non-wireless ServiceInfo requires ServiceEnvironment")
    elif token == "SubscriberInfo":
        if root.get("privacyRequested") not in ("true", "false", "1", "0"):
            raise NG911Error("SubscriberInfo requires boolean privacyRequested")
        data = root.find(f"{{{namespace}}}SubscriberData")
        cards = [] if data is None else data.findall(f"{{{VCARD_NS}}}vcard")
        if not cards:
            raise NG911Error("SubscriberData requires at least one xCard vcard")
    return counts


@_guard
def parse_emergency_call_data(data, *, content_type=None, purpose=None):
    """Parse one RFC 7852 XML block and cross-check optional MIME/purpose facts."""

    root = _xml(data)
    namespace, local = _qname(root)
    tokens = [token for token, expected_ns in _ECD.items()
              if namespace == expected_ns and local == "EmergencyCallData." + token]
    if len(tokens) != 1:
        raise NG911Error("unknown or namespace-mismatched EmergencyCallData block")
    token = tokens[0]
    expected_purpose = "EmergencyCallData." + token
    expected_media = "application/emergencycalldata." + token.lower() + "+xml"
    if content_type is not None and _media_type(content_type)[0] != expected_media:
        raise NG911Error("EmergencyCallData MIME/root mismatch")
    if purpose is not None and purpose.lower() != expected_purpose.lower():
        raise NG911Error("EmergencyCallData purpose/root mismatch")
    _validate_ecd_children(root, namespace, token)
    references = []
    fields = []
    for node in root.iter():
        node_ns, name = _qname(node)
        text = _clean_text(node.text)
        if name == "DataProviderReference" and node_ns != namespace:
            raise NG911Error("foreign namespace shadows DataProviderReference")
        if node.getparent() is root and node_ns == namespace and name == "DataProviderReference" and text:
            if "<" in text or ">" in text or len(text) > 998 or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+", text):
                raise NG911Error("invalid DataProviderReference msg-id")
            references.append(text)
        if node is not root and text:
            if len(fields) >= 1024:
                raise NG911Error("EmergencyCallData field limit exceeded")
            fields.append({"namespace": node_ns, "name": name, "value": text})
    if not references:
        raise NG911Error("EmergencyCallData block lacks DataProviderReference")
    return {"type": "emergency-call-data", "block": token,
            "purpose": expected_purpose,
            "content_type": f"application/EmergencyCallData.{token}+xml",
            "data_provider_references": list(dict.fromkeys(references)),
            "fields": fields,
            "limitations": ["XML structure does not authenticate its provider or assertions."]}


def _first_text(root, namespaces, local):
    for node in root.iter():
        namespace, name = _qname(node)
        if namespace in namespaces and name == local:
            text = _clean_text(" ".join(node.itertext()))
            if text:
                return text
    return None


@_guard
def parse_eidd(data):
    """Recognize and inventory one legacy APCO/NENA XML EIDD document."""

    root = _xml(data)
    if _qname(root) != (EIDD_NS, "EmergencyIncidentDataDocument"):
        raise NG911Error("expected legacy EIDD root and namespace")
    reasons = [_clean_text(node.text, required=True)
               for node in root.iter(f"{{{EIDD_NS}}}ReasonForIssueRegistryText")]
    creation = _first_text(root, {NIEM_NS, EIDD_NS}, "DocumentCreationDate")
    issuer = _first_text(root, {EIDD_NS}, "IssuingElementIdentification")
    document_id = _first_text(root, {NIEM_NS, EIDD_NS}, "DocumentIdentification")
    missing = [name for name, value in (("ReasonForIssueRegistryText", reasons),
                                        ("DocumentCreationDate", creation),
                                        ("IssuingElementIdentification", issuer),
                                        ("DocumentIdentification", document_id)) if not value]
    if missing:
        raise NG911Error("legacy EIDD lacks required field(s): " + ", ".join(missing))
    creation = _xml_datetime(creation, "EIDD DocumentCreationDate")
    issuer_msg_id = re.fullmatch(r"[^\s@<>]+@[^\s@<>]+", issuer) is not None
    issuer_domain = (len(issuer) <= 253 and "." in issuer and
                     all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                         for label in issuer.split(".")))
    if len(issuer) > 998 or not (issuer_msg_id or issuer_domain):
        raise NG911Error("EIDD IssuingElementIdentification is invalid")
    issues = []
    if issuer_domain and not issuer_msg_id:
        issues.append(
            "IssuingElementIdentification uses the domain-only form present in the official IEPD sample; "
            "the standard prose specifies name@owning_agency"
        )
    try:
        parsed_document_id = uuid.UUID(document_id)
    except (ValueError, AttributeError) as exc:
        raise NG911Error("EIDD DocumentIdentification is not an RFC 4122 UUID") from exc
    if str(parsed_document_id) != document_id.lower():
        raise NG911Error("EIDD DocumentIdentification is not canonical")
    agents = root.findall(f"{{{EIDD_NS}}}Agent")
    if len(agents) != 1:
        raise NG911Error("legacy EIDD requires exactly one Agent")
    if (_first_text(agents[0], {EIDD_NS}, "AgentIdentification") is None
            or _first_text(agents[0], {EIDD_NS}, "AgentDeviceRoleRegistryText") is None):
        raise NG911Error("legacy EIDD Agent lacks identity or role")
    inventory = {}
    for node in root.iter():
        namespace, local = _qname(node)
        if namespace in (EIDD_NS, NIEM_NS):
            inventory[local] = inventory.get(local, 0) + 1
    return {"type": "eidd", "status": "legacy-withdrawn",
            "namespace": EIDD_NS, "reasons": reasons,
            "creation_date": creation, "issuing_element": issuer,
            "document_id": document_id, "element_inventory": inventory,
            "issues": issues,
            "replacement": "NENA JSON EIDO (NENA-STA-021)",
            "limitations": ["schemaLocation and all external references were ignored"]}


def _json_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise NG911Error(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _json_constant(_):
    raise NG911Error("non-finite JSON number")


def _json_document(data):
    if isinstance(data, (bytes, bytearray, memoryview, str)):
        raw = _input_bytes(data)
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_json_constant)
    else:
        value = data
    if not isinstance(value, dict):
        raise NG911Error("EIDO must be a JSON object")
    stack = [(value, 0)]
    count, text_size, seen = 0, 0, set()
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_DEPTH:
            raise NG911Error("JSON tree exceeds node or depth limit")
        if isinstance(node, (dict, list)):
            marker = id(node)
            if marker in seen:
                raise NG911Error("cyclic JSON object")
            seen.add(marker)
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str):
                    raise NG911Error("JSON keys must be strings")
                text_size += len(key.encode("utf-8"))
                stack.append((item, depth + 1))
        elif isinstance(node, list):
            stack.extend((item, depth + 1) for item in node)
        elif isinstance(node, str):
            text_size += len(node.encode("utf-8"))
        elif node is not None and type(node) not in (bool, int, float):
            raise NG911Error("non-JSON object")
        elif type(node) in (int, float) and not math.isfinite(float(node)):
            raise NG911Error("non-finite JSON number")
        if text_size > MAX_INPUT:
            raise NG911Error("JSON text exceeds limit")
    return value


@_guard
def parse_eido(data):
    """Validate the required NENA EIDO envelope and inventory its components."""

    document = _json_document(data)
    identifier = document.get("$id")
    version = document.get("eidoVersion")
    if not isinstance(identifier, str) or not identifier.startswith("urn:emergency:uid:") or len(identifier) > 4096:
        raise NG911Error("EIDO requires a bounded emergency URN $id")
    if version != "1.0":
        raise NG911Error("this engine requires the current EIDO version 1.0")
    _xml_datetime(document.get("lastUpdateTimeStamp"), "EIDO lastUpdateTimeStamp")
    issuing = document.get("issuingElementIdentification")
    if not isinstance(issuing, str) or not issuing or len(issuing) > 4096:
        raise NG911Error("EIDO requires issuingElementIdentification")

    def reference(value, name):
        if not isinstance(value, dict) or set(value) != {"$ref"}:
            raise NG911Error(f"{name} must be one JSON reference object")
        target = value.get("$ref")
        if not isinstance(target, str) or not target or len(target) > 4096:
            raise NG911Error(f"{name} has an invalid $ref")
        return target

    reference(document.get("updatedByAgencyReference"), "updatedByAgencyReference")
    agencies = document.get("agencyComponent")
    if not isinstance(agencies, list) or not agencies:
        raise NG911Error("EIDO requires at least one agencyComponent")
    for agency in agencies:
        if not isinstance(agency, dict):
            raise NG911Error("agencyComponent entries must be objects")
        agency_id = agency.get("$id")
        if not isinstance(agency_id, str) or not agency_id or len(agency_id) > 4096:
            raise NG911Error("agencyComponent requires a bounded $id")
        _xml_datetime(agency.get("lastUpdateTimeStamp"), "agency lastUpdateTimeStamp")
        reference(agency.get("updatedByAgencyReference"), "agency updatedByAgencyReference")
        for key in ("agencyRoleDescriptionRegistryText", "agencyType"):
            value = agency.get(key)
            if (not isinstance(value, list) or not value
                    or any(not isinstance(item, str) or not item for item in value)):
                raise NG911Error(f"agencyComponent requires nonempty {key}")
    components = []
    stack = [(document, "$")]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            if node is not document and ("$id" in node or any(key.lower().endswith("type") for key in node)):
                component_type = next((value for key, value in node.items()
                                       if key.lower().endswith("type") and isinstance(value, str)), None)
                components.append({"path": path, "id": node.get("$id"), "component_type": component_type})
                if len(components) > 4096:
                    raise NG911Error("EIDO component limit exceeded")
            for key, value in reversed(list(node.items())):
                stack.append((value, path + "/" + key))
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((node[index], f"{path}/{index}"))
    return {"type": "eido", "format": "JSON", "id": identifier,
            "version": version, "top_level_keys": sorted(document),
            "issuing_element_identification": issuing,
            "components": components, "issues": [],
            "limitations": ["References and embedded HTML/media were not fetched or rendered."]}


def _split_header_values(value):
    values, start, angle, quote, escape = [], 0, 0, None, False
    for index, char in enumerate(value):
        if escape:
            escape = False
        elif quote:
            if char == "\\":
                escape = True
            elif char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == "<":
            angle += 1
            if angle > 1:
                raise NG911Error("nested angle brackets in SIP header")
        elif char == ">":
            angle -= 1
            if angle < 0:
                raise NG911Error("unbalanced SIP angle brackets")
        elif char == "," and angle == 0:
            values.append(value[start:index].strip())
            start = index + 1
    if quote or angle or escape:
        raise NG911Error("unterminated SIP header quoting")
    values.append(value[start:].strip())
    if any(not item for item in values):
        raise NG911Error("empty SIP header value")
    return values


def _parameterized_uri(value):
    match = re.fullmatch(r"\s*<([^<>\s]+)>\s*((?:;.*)?)\s*", value)
    if not match:
        raise NG911Error("SIP location/Call-Info value must contain one bracketed URI")
    uri, tail = match.groups()
    parameters = {}
    if tail:
        raw_parameters, start, quote, escape = [], 1, None, False
        for index, char in enumerate(tail[1:], 1):
            if escape:
                escape = False
            elif quote:
                if char == "\\":
                    escape = True
                elif char == quote:
                    quote = None
            elif char == '"':
                quote = char
            elif char == ";":
                raw_parameters.append(tail[start:index])
                start = index + 1
        if quote or escape:
            raise NG911Error("unterminated SIP parameter quoting")
        raw_parameters.append(tail[start:])
        for raw in raw_parameters:
            if not raw:
                raise NG911Error("empty SIP header parameter")
            if "=" in raw:
                name, parameter = raw.split("=", 1)
                parameter = parameter.strip()
                if len(parameter) >= 2 and parameter[0] == parameter[-1] == '"':
                    parameter = parameter[1:-1]
            else:
                name, parameter = raw, None
            name = name.strip().lower()
            if not _HEADER_NAME.fullmatch(name) or name in parameters:
                raise NG911Error("invalid or duplicate SIP header parameter")
            parameters[name] = parameter
    return {"uri": uri, "parameters": parameters}


def _sip(data):
    raw = _input_bytes(data)
    marker = raw.find(b"\r\n\r\n")
    separator = 4
    if marker < 0:
        marker = raw.find(b"\n\n")
        separator = 2
    if marker < 0:
        raise NG911Error("SIP header terminator is missing")
    header_bytes, body = raw[:marker], raw[marker + separator:]
    if b"\r" in header_bytes.replace(b"\r\n", b"") or any(
            byte < 0x20 and byte not in (0x09, 0x0a, 0x0d) for byte in header_bytes):
        raise NG911Error("SIP headers contain a bare CR or control character")
    try:
        header_text = header_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NG911Error("SIP headers are not UTF-8/ASCII") from exc
    lines = header_text.replace("\r\n", "\n").split("\n")
    if not lines or len(lines[0]) > MAX_HEADER_LINE:
        raise NG911Error("invalid SIP start line")
    request = re.fullmatch(r"([A-Z]+)\s+(\S+)\s+SIP/2\.0", lines[0])
    response = re.fullmatch(r"SIP/2\.0\s+([0-9]{3})(?:\s+(.*))?", lines[0])
    if not request and not response:
        raise NG911Error("invalid SIP request/status line")
    unfolded = []
    for line in lines[1:]:
        if len(line) > MAX_HEADER_LINE:
            raise NG911Error("SIP header line exceeds limit")
        if line[:1] in (" ", "\t"):
            if not unfolded:
                raise NG911Error("orphan SIP folded header")
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)
    compact = {"f": "from", "t": "to", "m": "contact", "i": "call-id",
               "v": "via", "c": "content-type", "l": "content-length"}
    headers = {}
    for line in unfolded:
        if not line:
            continue
        if len(headers) > MAX_HEADERS or ":" not in line:
            raise NG911Error("malformed or excessive SIP headers")
        name, value = line.split(":", 1)
        name = compact.get(name.strip().lower(), name.strip().lower())
        if not _HEADER_NAME.fullmatch(name):
            raise NG911Error("invalid SIP header name")
        headers.setdefault(name, []).append(value.strip())
        if sum(len(values) for values in headers.values()) > MAX_HEADERS:
            raise NG911Error("SIP header count exceeds limit")
    lengths = headers.get("content-length", [])
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            raise NG911Error("invalid or duplicate SIP Content-Length")
        if int(lengths[0]) != len(body):
            raise NG911Error("SIP Content-Length does not match body")
    elif body:
        raise NG911Error("SIP body requires Content-Length")
    return {"kind": "request" if request else "response", "method": request.group(1) if request else None,
            "request_uri": request.group(2) if request else None,
            "status": int(response.group(1)) if response else None,
            "reason": response.group(2) if response else None,
            "start_line": lines[0], "headers": headers, "body": body}


def _cid(value):
    if not value:
        return None
    value = value.strip()
    if not re.fullmatch(r"<[^<>\s]+>", value):
        raise NG911Error("invalid MIME Content-ID")
    return value[1:-1]


def _cid_key(value, *, url=False):
    if url:
        if not isinstance(value, str) or not value.lower().startswith("cid:"):
            raise NG911Error("expected a cid URI")
        encoded = value[4:]
        if re.search(r"%(?![0-9A-Fa-f]{2})", encoded):
            raise NG911Error("cid URI has malformed percent encoding")
        try:
            value = unquote_to_bytes(encoded).decode("ascii")
        except UnicodeDecodeError as exc:
            raise NG911Error("cid URI target is not ASCII") from exc
    if not isinstance(value, str) or not re.fullmatch(r"[^<>\s\x00-\x1f\x7f]+", value):
        raise NG911Error("invalid Content-ID value")
    if "@" not in value:
        return value, ""
    local, domain = value.rsplit("@", 1)
    return local, domain.lower()


def _strict_transfer_payload(part, cte):
    if cte not in ("base64", "quoted-printable"):
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise NG911Error("invalid MIME payload")
        return payload
    raw = part.get_payload(decode=False)
    if isinstance(raw, str):
        try:
            raw = raw.encode("ascii")
        except UnicodeEncodeError as exc:
            raise NG911Error("encoded MIME payload is not ASCII") from exc
    if not isinstance(raw, bytes):
        raise NG911Error("invalid encoded MIME payload")
    if cte == "base64":
        compact = re.sub(br"[\t\r\n ]", b"", raw)
        if len(compact) % 4:
            raise NG911Error("malformed base64 MIME payload")
        try:
            payload = base64.b64decode(compact, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise NG911Error("malformed base64 MIME payload") from exc
        if base64.b64encode(payload) != compact:
            raise NG911Error("non-canonical base64 MIME payload")
        return payload
    index = 0
    while index < len(raw):
        if raw[index:index + 1] != b"=":
            index += 1
            continue
        if raw[index + 1:index + 3] == b"\r\n":
            index += 3
        elif index + 2 < len(raw) and re.fullmatch(br"[0-9A-Fa-f]{2}", raw[index + 1:index + 3]):
            index += 3
        else:
            raise NG911Error("malformed quoted-printable MIME payload")
    return quopri.decodestring(raw)


def _mime_parts(content_type, body):
    media, _ = _media_type(content_type)
    if not media.startswith("multipart/"):
        return [{"content_type": media, "content_id": None, "body": body, "headers": {}}]
    synthetic = ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode("ascii") + body
    # compat32 preserves the original field value.  EmailPolicy's header
    # registry silently appends a missing closing quote, defeating the strict
    # Content-Type validation above.
    message = BytesParser(policy=policy.compat32).parsebytes(synthetic)
    if message.defects or not message.is_multipart():
        raise NG911Error("defective MIME multipart body")
    if (message.preamble and message.preamble.strip()) or (message.epilogue and message.epilogue.strip()):
        raise NG911Error("non-whitespace MIME preamble/epilogue")
    output = []

    def walk(part, depth):
        if depth > 8:
            raise NG911Error("MIME nesting exceeds limit")
        if part.defects:
            raise NG911Error("defective MIME body part")
        if part.is_multipart():
            if (part.preamble and part.preamble.strip()) or (part.epilogue and part.epilogue.strip()):
                raise NG911Error("non-whitespace nested MIME preamble/epilogue")
            children = part.get_payload()
            if not isinstance(children, list):
                raise NG911Error("invalid MIME multipart payload")
            for child in children:
                walk(child, depth + 1)
            return
        if len(output) >= MAX_MIME_PARTS:
            raise NG911Error("MIME part count exceeds limit")
        cte_values = part.get_all("Content-Transfer-Encoding", [])
        if len(cte_values) > 1:
            raise NG911Error("duplicate MIME transfer encoding")
        cte = cte_values[0].lower() if cte_values else "7bit"
        if cte not in ("7bit", "8bit", "binary", "base64", "quoted-printable"):
            raise NG911Error("unsupported MIME transfer encoding")
        payload = _strict_transfer_payload(part, cte)
        if not isinstance(payload, bytes) or len(payload) > MAX_INPUT:
            raise NG911Error("invalid or oversized MIME payload")
        content_types = part.get_all("Content-Type", [])
        ids = part.get_all("Content-ID", [])
        if len(content_types) > 1 or len(ids) > 1:
            raise NG911Error("duplicate MIME Content-Type/Content-ID")
        part_media = "text/plain"
        if content_types:
            raw_content_type = re.sub(r"\r?\n[ \t]+", " ", str(content_types[0]))
            part_media, _part_params = _media_type(raw_content_type)
        output.append({"content_type": part_media,
                       "content_id": _cid(ids[0]) if ids else None,
                       "body": payload,
                       "headers": {key.lower(): value for key, value in part.items()}})
    walk(message, 0)
    if not output:
        raise NG911Error("empty MIME multipart body")
    return output


@_guard
def parse_ng911_sip(data):
    """Parse one supplied i3 SIP message and resolve only in-message CID data."""

    message = _sip(data)
    headers, body = message.pop("headers"), message.pop("body")
    content_types = headers.get("content-type", [])
    if len(content_types) > 1:
        raise NG911Error("duplicate SIP Content-Type")
    if body and len(content_types) != 1:
        raise NG911Error("SIP body requires exactly one Content-Type")
    parts = _mime_parts(content_types[0], body) if body else []
    by_cid = {}
    part_inventory = []
    for index, part in enumerate(parts):
        content_id = part["content_id"]
        if content_id:
            key = _cid_key(content_id)
            if key in by_cid:
                raise NG911Error("duplicate MIME Content-ID")
            by_cid[key] = part
        part_inventory.append({"index": index, "content_type": part["content_type"],
                               "content_id": content_id, "bytes": len(part["body"]),
                               "sha256": hashlib.sha256(part["body"]).hexdigest()})
    geolocations = []
    for header in headers.get("geolocation", []):
        for value in _split_header_values(header):
            geolocations.append(_parameterized_uri(value))
    route_values = headers.get("geolocation-routing", [])
    if len(route_values) > 1 or any("," in value for value in route_values):
        raise NG911Error("duplicate Geolocation-Routing")
    route_raw = route_values[0].strip().lower() if route_values else None
    if route_raw == "yes":
        route_effective = "yes"
    else:
        route_effective = "no"
    issues = []
    if route_raw not in (None, "yes", "no"):
        issues.append("unknown Geolocation-Routing value treated as no")
    location_objects = []
    for value in geolocations:
        uri = value["uri"]
        if uri.lower().startswith("cid:"):
            key = _cid_key(uri, url=True)
            part = by_cid.get(key)
            if part is None:
                raise NG911Error("Geolocation cid does not resolve exactly once")
            if part["content_type"] != "application/pidf+xml":
                raise NG911Error("Geolocation cid does not reference PIDF-LO")
            location_objects.append({"uri": uri, "by_value": True,
                                     "pidf_lo": parse_pidf_lo(part["body"])})
        else:
            scheme = urlsplit(uri).scheme.lower()
            if scheme not in ("sip", "sips", "pres", "http", "https"):
                raise NG911Error("unsupported Geolocation URI scheme")
            location_objects.append({"uri": uri, "by_value": False, "fetched": False})
    call_info = []
    for header in headers.get("call-info", []):
        for value in _split_header_values(header):
            call_info.append(_parameterized_uri(value))
    additional = []
    provider_refs = set()
    non_provider_refs = set()
    for info in call_info:
        purpose = info["parameters"].get("purpose")
        uri = info["uri"]
        record = {"uri": uri, "purpose": purpose, "by_value": uri.lower().startswith("cid:"),
                  "fetched": False}
        if purpose and purpose.lower().startswith("emergencycalldata."):
            token = next((name for name in _ECD if purpose.lower() == ("emergencycalldata." + name).lower()), None)
            if uri.lower().startswith("cid:"):
                part = by_cid.get(_cid_key(uri, url=True))
                if part is None:
                    raise NG911Error("Call-Info cid does not resolve exactly once")
                if token is None:
                    record["recognized"] = False
                    record["content_type"] = part["content_type"]
                else:
                    parsed = parse_emergency_call_data(part["body"], content_type=part["content_type"], purpose=purpose)
                    record["recognized"] = True
                    record["data"] = parsed
                    references = set(parsed["data_provider_references"])
                    (provider_refs if token == "ProviderInfo" else non_provider_refs).update(references)
            else:
                if urlsplit(uri).scheme.lower() != "https":
                    issues.append(f"RFC 7852 by-reference URI is not HTTPS: {uri}")
                record["recognized"] = token is not None
            additional.append(record)
    missing_providers = sorted(non_provider_refs - provider_refs)
    if missing_providers:
        issues.append("EmergencyCallData blocks lack matching in-message ProviderInfo: " + ", ".join(missing_providers))
    embedded = []
    referenced_cids = {_cid_key(item["uri"], url=True) for item in geolocations + call_info
                       if item["uri"].lower().startswith("cid:")}
    for part in parts:
        content_type = part["content_type"]
        if content_type == "application/lost+xml":
            embedded.append(parse_lost(part["body"]))
        elif content_type in ("application/emergency.eido+json", "application/eido+json"):
            embedded.append(parse_eido(part["body"]))
        elif content_type in ("xml+nena/eidd", "application/xml+nena/eidd", "application/nena-eidd+xml"):
            embedded.append(parse_eidd(part["body"]))
        elif part["content_id"] and _cid_key(part["content_id"]) not in referenced_cids:
            issues.append(f"unreferenced MIME Content-ID: {part['content_id']}")
    request_uri = message.get("request_uri")
    service_urn = request_uri if isinstance(request_uri, str) and _SERVICE_URN.fullmatch(request_uri) else None
    if message["kind"] == "request" and message.get("method") in ("INVITE", "MESSAGE") and service_urn is None:
        issues.append("request URI is not a recognized emergency service URN")
    routes = [value for header in headers.get("route", []) for value in _split_header_values(header)]
    selected_headers = {name.replace("-", "_"): list(headers.get(name, []))
                        for name in ("via", "from", "to", "call-id", "cseq", "contact")
                        if name in headers}
    return {
        "type": "ng911-sip", **message, "service_urn": service_urn,
        "sip_headers": selected_headers,
        "routes": routes, "geolocation_routing": {"raw": route_raw, "effective": route_effective},
        "geolocations": location_objects, "call_info": call_info,
        "additional_data": additional, "embedded_documents": embedded,
        "mime_parts": part_inventory, "issues": issues,
        "network_activity": False,
        "limitations": [
            "No URI was dereferenced and no traffic was generated.",
            "SIP/XML/JSON structure does not authenticate a caller, provider, location, or route.",
        ],
    }


@_guard
def analyze(data, *, kind="auto", content_type=None, purpose=None):
    """Dispatch a supplied artifact by explicit kind or a strict root signature."""

    choices = {"auto", "sip", "pidf", "lost", "additional", "eidd", "eido"}
    if kind not in choices:
        raise NG911Error("unsupported analysis kind")
    if kind == "sip":
        return parse_ng911_sip(data)
    if kind == "pidf":
        return parse_pidf_lo(data)
    if kind == "lost":
        return parse_lost(data)
    if kind == "additional":
        return parse_emergency_call_data(data, content_type=content_type, purpose=purpose)
    if kind == "eidd":
        return parse_eidd(data)
    if kind == "eido":
        return parse_eido(data)
    raw = _input_bytes(data)
    stripped = raw.lstrip()
    if re.match(rb"(?:[A-Z]+\s+\S+\s+SIP/2\.0|SIP/2\.0\s+[0-9]{3})", stripped[:8192]):
        return parse_ng911_sip(raw)
    if stripped.startswith((b"{", b"[")):
        return parse_eido(raw)
    if not stripped.startswith(b"<"):
        raise NG911Error("unrecognized NG9-1-1 artifact")
    root = _xml(raw)
    namespace, local = _qname(root)
    if (namespace, local) == (PIDF_NS, "presence"):
        return parse_pidf_lo(raw)
    if namespace == LOST_NS:
        return parse_lost(raw)
    if (namespace, local) == (EIDD_NS, "EmergencyIncidentDataDocument"):
        return parse_eidd(raw)
    if any(namespace == expected and local == "EmergencyCallData." + token
           for token, expected in _ECD.items()):
        return parse_emergency_call_data(raw, content_type=content_type, purpose=purpose)
    raise NG911Error("unrecognized namespace-qualified XML artifact")


def _read(path):
    try:
        with Path(path).open("rb") as stream:
            value = stream.read(MAX_INPUT + 1)
    except (OSError, UnicodeError, ValueError) as exc:
        raise NG911Error("cannot read the supplied file") from exc
    if len(value) > MAX_INPUT:
        raise NG911Error("file exceeds 8 MiB input limit")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("auto", "sip", "pidf", "lost", "eidd", "eido"):
        command = sub.add_parser(name)
        command.add_argument("file")
    sub.choices["lost"].add_argument("--expected-location-id")
    additional = sub.add_parser("additional")
    additional.add_argument("file")
    additional.add_argument("--content-type")
    additional.add_argument("--purpose")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception:
        return 2
    try:
        if args.command == "lost":
            result = parse_lost(_read(args.file),
                                expected_location_id=getattr(args, "expected_location_id", None))
        else:
            result = analyze(_read(args.file), kind=args.command,
                             content_type=getattr(args, "content_type", None),
                             purpose=getattr(args, "purpose", None))
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
        return 0
    except NG911Error as exc:
        print(f"sec_emerg_ng911: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
