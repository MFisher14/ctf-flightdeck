#!/usr/bin/env python3
"""Never-wrong readers for application protocols network.py does not read (Day-26 coverage build):
MQTT, Redis (RESP), MySQL, PostgreSQL, LDAP simple bind and syslog.

Same contract as net_auth.py and net_voip.py: `field(Q, cap, Found, choose)` is consulted by
network.py ONLY for a question its own readers (and net_auth, net_voip) returned no answer for.
Every value is offered through `choose`, which builds an option list (an UNSURE `labels.pick`
under `network.<field>/<shape>`), never a plain answer. Nothing here executes artifact content,
sends a request or imports anything outside the standard library. Parse failure, truncation,
ambiguity (several distinct values and no selector in the question) and absence are None.

Boundaries (declined on purpose):
  - A password read from the wire is a fact of the capture, but its rendering is the author's, so it
    is only ever a pick. A cracked or derived secret is never offered (md5 PostgreSQL logins are
    offered as the `md5<hex>` string the wire carries, never reversed).
  - A flag is never offered: a value of the form word{...} is withheld from every field.
"""
import re
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent

_FLAG = flagfmt.TEXT
MAX_STREAM = 8 * 1024 * 1024


def _text(b):
    """Strict UTF-8 printable text, else None (binary is never offered as a string)."""
    try:
        s = bytes(b).decode("utf-8")
    except Exception:
        return None
    if not s or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in s):
        return None
    if _FLAG.search(s):
        return None
    return s


def _cstr(d, o):
    e = d.find(b"\x00", o)
    if e < 0:
        return None, o
    return d[o:e], e + 1


# ---- MQTT ------------------------------------------------------------------------------------------

def _varint(d, o):
    mult, val = 1, 0
    for i in range(4):
        if o + i >= len(d):
            return None, o
        b = d[o + i]
        val += (b & 0x7F) * mult
        if not b & 0x80:
            return val, o + i + 1
        mult *= 128
    return None, o


def _mqtt_packets(d):
    """[(type, flags, body)] while the framing is exact; stops (never guesses) at the first bad frame."""
    out, o = [], 0
    while o + 2 <= len(d):
        t, fl = d[o] >> 4, d[o] & 15
        n, p = _varint(d, o + 1)
        if n is None or p + n > len(d) or t == 0 or t == 15:
            break
        out.append((t, fl, d[p:p + n]))
        o = p + n
    return out, o == len(d)


def _u16s(d, o):
    if o + 2 > len(d):
        return None, o
    n = (d[o] << 8) | d[o + 1]
    if o + 2 + n > len(d):
        return None, o
    return d[o + 2:o + 2 + n], o + 2 + n


def _mqtt_connect(body):
    name, o = _u16s(body, 0)
    if name not in (b"MQTT", b"MQIsdp") or o >= len(body):
        return None
    level = body[o]
    if o + 4 > len(body):
        return None
    flags = body[o + 1]
    o += 4
    if level == 5:
        n, o = _varint(body, o)
        if n is None or o + n > len(body):
            return None
        o += n
    cid, o = _u16s(body, o)
    if cid is None:
        return None
    rec = {"level": level, "client_id": cid, "username": None, "password": None}
    if flags & 4:                               # will
        if level == 5:
            n, o = _varint(body, o)
            if n is None:
                return rec
            o += n
        wt, o = _u16s(body, o)
        wm, o = _u16s(body, o)
        if wt is None or wm is None:
            return rec
    if flags & 0x80:
        rec["username"], o = _u16s(body, o)
    if flags & 0x40:
        rec["password"], o = _u16s(body, o)
    return rec


def mqtt_facts(cap):
    facts = {"connect": [], "publish": [], "subscribe": []}
    for st in _streams(cap).values():
        d = st.data or b""
        if len(d) < 14 or len(d) > MAX_STREAM:
            continue
        pk, exact = _mqtt_packets(d)
        if not pk or pk[0][0] != 1:             # a client stream starts with CONNECT
            continue
        c = _mqtt_connect(pk[0][2])
        if c is None:
            continue
        level = c["level"]
        facts["connect"].append(c)
        for t, fl, body in pk[1:]:
            try:
                if t == 3:
                    topic, o = _u16s(body, 0)
                    if topic is None:
                        continue
                    if (fl >> 1) & 3:
                        o += 2
                    if level == 5:
                        n, o = _varint(body, o)
                        if n is None:
                            continue
                        o += n
                    facts["publish"].append({"topic": topic, "payload": body[o:]})
                elif t == 8:
                    o = 2
                    if level == 5:
                        n, o = _varint(body, o)
                        if n is None:
                            continue
                        o += n
                    while o < len(body):
                        tp, o = _u16s(body, o)
                        if tp is None:
                            break
                        o += 1
                        facts["subscribe"].append({"topic": tp})
            except Exception:
                continue
    return facts


# ---- Redis (RESP) ----------------------------------------------------------------------------------

def _resp_commands(d):
    """Client commands as arrays of byte strings; stops at the first frame that is not exact RESP."""
    out, o = [], 0
    while o < len(d):
        if d[o:o + 1] != b"*":
            break
        e = d.find(b"\r\n", o)
        if e < 0 or not d[o + 1:e].isdigit() or e - o > 8:
            break
        n = int(d[o + 1:e])
        o = e + 2
        if n < 1 or n > 64:
            break
        args, ok = [], True
        for _ in range(n):
            if d[o:o + 1] != b"$":
                ok = False
                break
            e = d.find(b"\r\n", o)
            if e < 0 or not d[o + 1:e].isdigit() or e - o > 10:
                ok = False
                break
            ln = int(d[o + 1:e])
            s = e + 2
            if s + ln + 2 > len(d) or d[s + ln:s + ln + 2] != b"\r\n":
                ok = False
                break
            args.append(d[s:s + ln])
            o = s + ln + 2
        if not ok:
            break
        out.append(args)
    return out


def redis_facts(cap):
    facts = {"auth_user": [], "auth_pass": [], "set_key": [], "set_value": [], "get_key": [], "commands": []}
    for st in _streams(cap).values():
        d = st.data or b""
        if not d.startswith(b"*") or len(d) > MAX_STREAM:
            continue
        for args in _resp_commands(d):
            cmd = args[0].upper().decode("latin-1")
            if not re.fullmatch(r"[A-Z][A-Z.]{1,20}", cmd):
                continue
            facts["commands"].append(cmd)
            if cmd == "AUTH" and len(args) == 2:
                facts["auth_pass"].append(args[1])
            elif cmd == "AUTH" and len(args) == 3:
                facts["auth_user"].append(args[1])
                facts["auth_pass"].append(args[2])
            elif cmd == "SET" and len(args) >= 3:
                facts["set_key"].append(args[1])
                facts["set_value"].append(args[2])
            elif cmd == "GET" and len(args) == 2:
                facts["get_key"].append(args[1])
    return facts


# ---- MySQL -----------------------------------------------------------------------------------------

def _mysql_packets(d):
    out, o = [], 0
    while o + 4 <= len(d):
        n = d[o] | (d[o + 1] << 8) | (d[o + 2] << 16)
        if o + 4 + n > len(d) or n == 0:
            break
        out.append((d[o + 3], d[o + 4:o + 4 + n]))
        o += 4 + n
    return out


def mysql_facts(cap):
    facts = {"version": [], "user": [], "database": [], "query": []}
    for st in _streams(cap).values():
        d = st.data or b""
        if len(d) < 8 or len(d) > MAX_STREAM:
            continue
        pk = _mysql_packets(d)
        if not pk:
            continue
        seq0, body = pk[0]
        if seq0 == 0 and body[:1] == b"\x0a":                       # server greeting
            v, _ = _cstr(body, 1)
            if v is not None and re.fullmatch(rb"[0-9][ -~]{0,60}", v):
                facts["version"].append(v)
            continue
        if seq0 == 1 and len(body) > 33:                           # client login (protocol 41)
            cap_fl = int.from_bytes(body[:4], "little")
            if not cap_fl & 0x200 or any(body[9:32]):
                continue
            user, o = _cstr(body, 32)
            if user is None or not re.fullmatch(rb"[ -~]{1,64}", user):
                continue
            facts["user"].append(user)
            if cap_fl & (0x200000 | 0x8000):
                if o >= len(body):
                    continue
                n = body[o]
                o += 1
                # LENENC takes precedence over SECURE_CONNECTION's one-byte length.
                if cap_fl & 0x200000 and n >= 0xFB:
                    width = {0xFC: 2, 0xFD: 3, 0xFE: 8}.get(n)
                    if width is None or o + width > len(body):
                        continue
                    n = int.from_bytes(body[o:o + width], "little")
                    o += width
                if n > len(body) - o:
                    continue
                o += n
            else:
                auth, o = _cstr(body, o)
                if auth is None:
                    continue
            if cap_fl & 0x8 and o <= len(body):
                db, _ = _cstr(body, o)
                if db and re.fullmatch(rb"[ -~]{1,64}", db):
                    facts["database"].append(db)
            for sq, b in pk[1:]:
                if sq == 0 and b[:1] == b"\x03" and len(b) > 1:
                    facts["query"].append(b[1:])
    return facts


# ---- PostgreSQL ------------------------------------------------------------------------------------

def _pg_startup(d):
    if len(d) < 12:
        return None
    n = int.from_bytes(d[:4], "big")
    if n > len(d) or n < 12 or int.from_bytes(d[4:8], "big") != 196608:
        return None
    params, o, end = {}, 8, n
    while o < end - 1:
        k, o = _cstr(d[:end], o)
        if k is None:
            return None
        if not k:
            break
        v, o = _cstr(d[:end], o)
        if v is None:
            return None
        params[k.decode("latin-1")] = v
    return params, d[n:]


def _pg_messages(d):
    out, o = [], 0
    while o + 5 <= len(d):
        n = int.from_bytes(d[o + 1:o + 5], "big")
        if n < 4 or o + 1 + n > len(d):
            break
        out.append((d[o:o + 1], d[o + 5:o + 1 + n]))
        o += 1 + n
    return out


def pg_facts(cap):
    facts = {"user": [], "database": [], "app": [], "password": [], "md5": [], "query": []}
    sts = _streams(cap)
    for k, st in sts.items():
        d = st.data or b""
        if len(d) > MAX_STREAM:
            continue
        sp = _pg_startup(d)
        if sp is None:
            continue
        params, rest = sp
        if b"user" not in [x.encode("latin-1") for x in params]:
            continue
        for fld, key in (("user", "user"), ("database", "database"), ("app", "application_name")):
            if key in params:
                facts[fld].append(params[key])
        srv = sts.get((k[2], k[3], k[0], k[1], k[4]))
        auth = None
        if srv is not None:
            for t, b in _pg_messages(srv.data or b""):
                if t == b"R" and len(b) >= 4:
                    auth = int.from_bytes(b[:4], "big")
                    break
        for t, b in _pg_messages(rest):
            if t == b"p" and b.endswith(b"\x00"):
                pw = b[:-1]
                if auth == 3 and b"\x00" not in pw:
                    facts["password"].append(pw)
                elif auth == 5 and re.fullmatch(rb"md5[0-9a-f]{32}", pw):
                    facts["md5"].append(pw)
            elif t == b"Q" and b.endswith(b"\x00") and len(b) > 1:
                facts["query"].append(b[:-1])
    return facts


# ---- LDAP simple bind ------------------------------------------------------------------------------

def _ber(d, o):
    """(tag, content start, content end) or None; definite lengths only."""
    if o + 2 > len(d):
        return None
    tag, ln = d[o], d[o + 1]
    p = o + 2
    if ln & 0x80:
        k = ln & 0x7F
        if k == 0 or k > 3 or p + k > len(d):
            return None
        ln = int.from_bytes(d[p:p + k], "big")
        p += k
    if p + ln > len(d):
        return None
    return tag, p, p + ln


def _ldap_messages(d):
    out, o = [], 0
    while o < len(d):
        e = _ber(d, o)
        if e is None or e[0] != 0x30:
            break
        tag, s, end = e
        m = _ber(d, s)
        if m is None or m[0] != 2:
            break
        op = _ber(d, m[2])
        if op is None:
            break
        out.append((int.from_bytes(d[m[1]:m[2]], "big"), op[0], d[op[1]:op[2]]))
        o = end
    return out


def ldap_facts(cap):
    facts = {"bind_dn": [], "bind_pw": [], "bound_ok_dn": [], "search_base": []}
    sts = _streams(cap)
    for k, st in sts.items():
        d = st.data or b""
        if len(d) < 12 or len(d) > MAX_STREAM or d[0] != 0x30:
            continue
        msgs = _ldap_messages(d)
        if not msgs:
            continue
        srv = sts.get((k[2], k[3], k[0], k[1], k[4]))
        results = {}
        if srv is not None and srv.data:
            for mid, optag, body in _ldap_messages(srv.data):
                if optag == 0x61:                       # BindResponse: LDAPResult starts with ENUMERATED
                    r = _ber(body, 0)
                    if r is not None and r[0] == 10 and r[2] - r[1] == 1:
                        results[mid] = body[r[1]]
        for mid, optag, body in msgs:
            try:
                if optag == 0x60:                       # BindRequest
                    v = _ber(body, 0)
                    n = _ber(body, v[2]) if v else None
                    pw = _ber(body, n[2]) if n else None
                    if not (v and n and pw) or v[0] != 2 or n[0] != 4 or pw[0] != 0x80:
                        continue            # sasl (0xA3) or malformed: not a simple bind
                    dn, pwd = body[n[1]:n[2]], body[pw[1]:pw[2]]
                    facts["bind_dn"].append(dn)
                    if pwd:
                        facts["bind_pw"].append(pwd)
                        if results.get(mid) == 0:
                            facts["bound_ok_dn"].append(dn)
                elif optag == 0x63:                     # SearchRequest
                    b = _ber(body, 0)
                    if b and b[0] == 4:
                        facts["search_base"].append(body[b[1]:b[2]])
            except Exception:
                continue
    return facts


# ---- syslog ----------------------------------------------------------------------------------------

_SYS5424 = re.compile(rb"<(\d{1,3})>(\d) (\S+) (\S{1,255}) (\S{1,48}) (\S+) (\S+) ")
_SYS3164 = re.compile(rb"<(\d{1,3})>([A-Z][a-z]{2}) [ 0-3]\d \d\d:\d\d:\d\d ([A-Za-z0-9_.-]{1,255}) ([A-Za-z0-9_./-]{1,48})(?:\[\d+\])?: ")


def syslog_facts(cap):
    facts = {"host": [], "app": [], "facility": [], "severity": []}
    blobs = []
    for p in cap.packets:
        if p.proto == 17 and p.payload and 514 in (p.sport, p.dport) and p.frag != 2:
            blobs.append(bytes(p.payload))
    for st in _streams(cap).values():
        if 514 in (st.sport, st.dport) and st.data and len(st.data) <= MAX_STREAM:
            blobs.extend(x for x in st.data.split(b"\n") if x)
    for b in blobs:
        for rx, hi, ai in ((_SYS5424, 4, 5), (_SYS3164, 3, 4)):
            m = rx.match(b)
            if m and int(m.group(1)) <= 191:
                pri = int(m.group(1))
                if rx is _SYS5424 and m.group(2) != b"1":
                    continue
                facts["host"].append(m.group(hi))
                if m.group(ai) != b"-":
                    facts["app"].append(m.group(ai))
                facts["facility"].append(str(pri // 8).encode())
                facts["severity"].append(str(pri % 8).encode())
                break
    return facts


# ---- plumbing --------------------------------------------------------------------------------------

def _streams(cap):
    try:
        return cap.streams() or {}
    except Exception:
        return {}


_CACHE = {}


def _facts(cap, name, fn):
    key = (id(cap), getattr(cap, "sha256", None), getattr(cap, "size", None), name)
    if key not in _CACHE:
        if len(_CACHE) > 32:
            _CACHE.clear()
        _CACHE[key] = fn(cap)
    return _CACHE[key]


def _strs(values):
    out = []
    for v in values:
        t = _text(v)
        if t is not None:
            out.append(t)
    return out


def field(Q, cap, Found, choose):
    """A Found for a question about one of these protocols, else None. Options only, never plain."""
    try:
        return _field(Q, cap, Found, choose)
    except Exception:
        return None


def _field(Q, cap, Found, choose):
    if Q.has(r"\bmqtt\b|\bmosquitto\b"):
        f = _facts(cap, "mqtt", mqtt_facts)
        c = f["connect"]
        if Q.asks(r"\bpassword\b|\bpasswd\b|\bsecret\b|\bcredential"):
            return choose(Q, _strs([x["password"] for x in c if x["password"]]), "mqtt_password", "mqtt")
        if Q.asks(r"\buser ?name\b|\blogin\b|\bwho (?:logged|authenticated)\b"):
            return choose(Q, _strs([x["username"] for x in c if x["username"]]), "mqtt_username", "mqtt")
        if Q.asks(r"\bclient[- ]?id\b|\bclient identifier\b"):
            return choose(Q, _strs([x["client_id"] for x in c if x["client_id"]]), "mqtt_client_id", "mqtt")
        if Q.asks(r"\bsubscri\w+\b"):
            return choose(Q, _strs([x["topic"] for x in f["subscribe"]]), "mqtt_subscribe_topic", "mqtt")
        if Q.asks(r"\btopic\b"):
            return choose(Q, _strs([x["topic"] for x in f["publish"]]), "mqtt_topic", "mqtt")
        if Q.asks(r"\bpayload\b|\bmessage\b|\bpublished\b"):
            return choose(Q, _strs([x["payload"] for x in f["publish"]]), "mqtt_payload", "mqtt")
        if Q.asks(r"\bprotocol (?:version|level)\b|\bversion\b"):
            return choose(Q, [str(x["level"]) for x in c], "mqtt_protocol_level", "mqtt")
        return None

    if Q.has(r"\bredis\b"):
        f = _facts(cap, "redis", redis_facts)
        if Q.asks(r"\bpassword\b|\bauth\w*\b|\bsecret\b") and not Q.asks(r"\buser ?name\b"):
            return choose(Q, _strs(f["auth_pass"]), "redis_auth_password", "redis")
        if Q.asks(r"\buser ?name\b|\bacl user\b"):
            return choose(Q, _strs(f["auth_user"]), "redis_auth_username", "redis")
        if Q.asks(r"\bvalue\b") and Q.asks(r"\bset\b|\bstored\b|\bwritten\b"):
            return choose(Q, _strs(f["set_value"]), "redis_set_value", "redis")
        if Q.asks(r"\bkey\b") and Q.asks(r"\bset\b|\bstored\b|\bwritten\b|\bcreated\b"):
            return choose(Q, _strs(f["set_key"]), "redis_set_key", "redis")
        if Q.asks(r"\bkey\b") and Q.asks(r"\bget\b|\bread\b|\bfetched\b|\bretrieved\b"):
            return choose(Q, _strs(f["get_key"]), "redis_get_key", "redis")
        return None

    if Q.has(r"\bmysql\b|\bmariadb\b"):
        f = _facts(cap, "mysql", mysql_facts)
        if Q.asks(r"\bversion\b|\bbanner\b"):
            return choose(Q, _strs(f["version"]), "mysql_server_version", "mysql")
        if Q.asks(r"\buser ?name\b|\blogin\b|\blogged in\b|\buser\b|\baccount\b"):
            return choose(Q, _strs(f["user"]), "mysql_username", "mysql")
        if Q.asks(r"\bdatabase\b|\bschema\b"):
            return choose(Q, _strs(f["database"]), "mysql_database", "mysql")
        if Q.asks(r"\bquery\b|\bstatement\b|\bsql\b|\bcommand\b"):
            return choose(Q, _strs(f["query"]), "mysql_query", "mysql")
        return None

    if Q.has(r"\bpostgres\w*\b|\bpgsql\b|\bpsql\b"):
        f = _facts(cap, "pg", pg_facts)
        if Q.asks(r"\bmd5\b|\bhash\b"):
            return choose(Q, _strs(f["md5"]), "pg_password_md5", "postgres")
        if Q.asks(r"\bpassword\b|\bsecret\b"):
            return choose(Q, _strs(f["password"]), "pg_password", "postgres")
        if Q.asks(r"\bapplication\b|\bclient name\b"):
            return choose(Q, _strs(f["app"]), "pg_application_name", "postgres")
        if Q.asks(r"\bdatabase\b"):
            return choose(Q, _strs(f["database"]), "pg_database", "postgres")
        if Q.asks(r"\buser ?name\b|\blogin\b|\blogged in\b|\brole\b|\buser\b"):
            return choose(Q, _strs(f["user"]), "pg_user", "postgres")
        if Q.asks(r"\bquery\b|\bstatement\b|\bsql\b"):
            return choose(Q, _strs(f["query"]), "pg_query", "postgres")
        return None

    if Q.has(r"\bldap\b|\bactive directory\b|\bdirectory bind\b"):
        f = _facts(cap, "ldap", ldap_facts)
        if Q.asks(r"\bpassword\b|\bcredential\b|\bsecret\b"):
            return choose(Q, _strs(f["bind_pw"]), "ldap_bind_password", "ldap")
        if Q.asks(r"\bsearch base\b|\bbase (?:dn|object)\b"):
            return choose(Q, _strs(f["search_base"]), "ldap_search_base", "ldap")
        if Q.asks(r"\bbind\b|\bdn\b|\bdistinguished name\b|\bauthenticated\b|\bsuccess"):
            src = f["bound_ok_dn"] if Q.success and f["bound_ok_dn"] else f["bind_dn"]
            return choose(Q, _strs(src), "ldap_bind_dn", "ldap")
        return None

    if Q.has(r"\bsyslog\b"):
        f = _facts(cap, "syslog", syslog_facts)
        if Q.asks(r"\bfacility\b"):
            return choose(Q, _strs(f["facility"]), "syslog_facility", "syslog")
        if Q.asks(r"\bseverity\b|\bpriority level\b"):
            return choose(Q, _strs(f["severity"]), "syslog_severity", "syslog")
        if Q.asks(r"\bhost ?name\b|\bhost\b|\bsender\b|\bdevice\b|\bmachine\b"):
            return choose(Q, _strs(f["host"]), "syslog_hostname", "syslog")
        if Q.asks(r"\bapp(?:lication)?\b|\bprogram\b|\bprocess\b|\btag\b|\bdaemon\b"):
            return choose(Q, _strs(f["app"]), "syslog_app", "syslog")
        return None
    return None
