#!/usr/bin/env python3
"""Toolkit `malconfig`: malware config extraction beyond HCFG, key recovery, ransomware sets.

  .venv/bin/python solvers/toolkits/malconfig.py <file or folder> [...] [--json]

prints a triage of the files: every validated config reading (how it was wrapped, the cipher and
key, the fields), the family readers (Cobalt Strike, .NET literals, NetSupport, AutoIt, Lua,
quarantine wrappers, an embedded XOR-ed PE), a ransom note's checked addresses, and an encrypted
set decrypted. Offline: no Game Master request, no token. Docs: docs/toolkits/malconfig.md.

The readers are solvers/common/malconfig.py (imported here as `lib`; an agent calls them by hand:
lib.scan, lib.config, lib.cobalt_strike, lib.us_strings, lib.netsupport, lib.note, lib.decrypt_set,
lib.xor_key_from_pair, lib.keystream_from_magic, lib.footer_diff, lib.proof ...).

signals(questions, files) -> 0..1   how strongly a delivery and its questions look like this category
solve_set(questions, files, ctx)    the runner contract (tools/run.py, tools/verify.py)

Never-guess (AGENTS.md, "Uncertain answers"). Nothing of this category has been judged, so:

  - plain: only the SHA-256, SHA-1 or MD5 of a decrypted file the question names, when its words
    say decrypted (decrypted, recovered, restored, extracted ...) and nothing in them says the
    file as delivered (encrypted, before, ciphertext ...: then None, or unsure under a key of its
    own), and the decrypt is proven exactly (lib.proof: a clean magic, a parse, and the file ends
    where its structure says), in lowercase hex (uppercase when the question says so);
  - unsure, labels.pick('malconfig.<field>/<shape>', [(format name, value), ...]): a config field,
    a key, a cipher or family name, an address from a note. The fact is read from a reading that
    validated, and exactly one value may fit; the format names carry to the next variant once the
    judge accepts one on the untimed base;
  - None: everything else, and every question of a set that belongs to one of the five known
    lanes (dNN_ ids, -role/-attack ids, 'message', the ANS- answer, 'Determine <property> for').

A plain JSON object lying in a file is a config only for a question that speaks of one (config,
C2, beacon, implant, malware, sample, payload ...); an encrypted or HCFG reading always is.
"""
import hashlib
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
sys.path.insert(0, str(COMMON))
import labels       # noqa: E402
import triage       # noqa: E402


def _load_lib():
    """solvers/common/malconfig.py under its own name: this file has the same base name."""
    name = "malconfig_readers"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, COMMON / "malconfig.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


lib = _load_lib()

KEY = "malconfig"
BUDGET = 0.6                # seconds of scanning one set's files in solve_set
ARROW = " -> "
ARCHIVES = (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")


# ---- the label keys ------------------------------------------------------------------------------------

def pick(field: str, shape: str, options):
    """labels.pick under 'malconfig.<field>/<shape>'. Where solvers/common/labels.py does not know
    the lane prefix `malconfig` (its LANE_DIRS has the five lanes), the key is filed in the Binary
    lane's ledger as 'binary.malconfig_<field>/<shape>': the same facts, the same fate."""
    shape = re.sub(r"[^a-z0-9_.+:-]+", "_", str(shape).lower()).strip("_") or "any"
    for key in (f"{KEY}.{field}/{shape}", f"binary.{KEY}_{field}/{shape}"):
        try:
            return labels.pick(key, options)
        except ValueError:
            continue
    return None


# ---- what a question asks ---------------------------------------------------------------------------------

# field -> (pattern a config key's name or an answer id's tail matches in full, pattern a question's words match)
FIELDS = (
    ("c2_port", r"(?:c2|cnc|c_c|server|callback|gateway|beacon|listener|remote|c2_server)_?port|port",
     r"\bport\b"),
    ("c2_host", r"(?:c2|cnc|c_c|server|callback|gateway|beacon|remote|control)_?(?:host|hostname|domain|ip|addr|ip_?address)|host|hostname|domain|ip",
     r"\b(?:host ?name|host|domain|ip address)\b"),
    ("c2_url", r"(?:c2|cnc|callback|beacon|gate|panel|server|download|payload|stage|exfil)?_?(?:url|uri)|gate|panel",
     r"\b(?:url|uri)\b"),
    ("c2", r"c2|cnc|c_c|c2_?(?:server|address|addr|endpoint)|callback|endpoint|gateway_?address|server_?address|server|gateway",
     r"\b(?:c2|c&c|cnc|command[- ]and[- ]control|callback|gateway)\b"),
    ("mutex", r"mutex|mutant|mutex_?name", r"\bmut(?:ex|ant)\b"),
    ("campaign", r"campaign|campaign_?(?:id|name|tag)", r"\bcampaign\b"),
    ("build_id", r"build|build_?(?:id|tag|name|number)", r"\bbuild\b"),
    ("version", r"version|ver|bot_?version|config_?version", r"\bversion\b"),
    ("botnet", r"botnet|botnet_?id|group|group_?id|affiliate|affiliate_?id", r"\b(?:botnet|affiliate|group id)\b"),
    ("iv", r"iv|nonce|init(?:ialization)?_?vector|(?:aes|cbc)_?iv|iv_?hex", r"\b(?:iv|nonce|initiali[sz]ation vector)\b"),
    ("key", r"(?:xor|rc4|aes|enc(?:ryption)?|dec(?:ryption)?|crypto|cipher|config|session|comm)?_?key(?:_?hex|_?bytes)?",
     r"\b(?:xor|rc4|aes|encryption|decryption|cipher|config(?:uration)?) key\b|\bkey\b[^?]{0,40}\b(?:decrypt|encrypt|xor|rc4|aes)"),
    ("jitter", r"jitter", r"\bjitter\b"),
    ("sleep", r"sleep|sleep_?(?:time|ms|seconds|sec|interval)|sleeptime|interval|(?:beacon|callback|poll|check_?in)_?interval|delay|heartbeat",
     r"\b(?:sleep|beacon interval|callback interval|check-?in interval)\b"),
    ("user_agent", r"user_?agent|ua|useragent", r"\buser[- ]?agent\b"),
    ("chat_id", r"chat_?id|(?:telegram|tg)_?chat(?:_?id)?", r"\bchat id\b"),
    ("bot_token", r"(?:bot|telegram|tg|api)_?token|token", r"\b(?:bot|telegram|api) token\b"),
    ("onion", r"onion|tor|(?:onion|tor|leak)_?(?:url|address|host|domain|site)", r"\b(?:onion|tor (?:site|address|url))\b"),
    ("tox_id", r"tox|tox_?id", r"\btox\b"),
    ("wallet", r"wallet|btc|bitcoin|xmr|monero|eth|ethereum|(?:btc|bitcoin|xmr|monero|eth|payment|ransom)_?(?:address|addr|wallet)|wallet_?address",
     r"\b(?:wallet|bitcoin|btc|monero|xmr|ethereum|payment address)\b"),
    ("victim_id", r"(?:victim|personal|client|unique|decryption)_?id|victim", r"\b(?:victim|personal|unique|decryption) (?:id|identifier|key)\b"),
    ("extension", r"ext|extension|(?:file|appended|encrypted|ransom)_?ext(?:ension)?|suffix", r"\bextension\b"),
    ("email", r"e_?mail|contact|contact_?e_?mail", r"\be-?mail\b"),
    ("pipe", r"pipe|pipe_?name|named_?pipe|pipename", r"\bpipe\b"),
    ("watermark", r"watermark|license_?id", r"\bwatermark\b"),
    ("spawnto", r"spawn_?to(?:_?x(?:86|64))?", r"\bspawn ?to\b"),
    ("password", r"password|passwd|pass", r"\bpassword\b"),
    ("crc32", r"(?:config_?)?crc(?:32)?(?:_?hex)?|checksum", r"\bcrc-?32\b"),
    ("cipher", r"cipher|algorithm|algo|encryption|encoding|scheme|encryption_?(?:algorithm|method|scheme)|cipher_?(?:name|mode)",
     r"\b(?:cipher|algorithm|encryption scheme|encryption method|how is the config(?:uration)? (?:encrypted|encoded|protected))\b"),
    ("family", r"family|(?:malware|threat)_?(?:family|name)?|malware|threat", r"\b(?:malware )?family\b"),
)
_NAME = {f: re.compile(n) for f, n, _ in FIELDS}
_TEXT = {f: re.compile(t, re.I) for f, _, t in FIELDS}
_CONTEXT = re.compile(r"(?i)\b(?:config(?:uration)?|settings|c2|c&c|cnc|command[- ]and[- ]control|beacon|implant|malware|sample|"
                      r"payload|stealer|loader|dropper|backdoor|rat|bot|botnet|ransom\w*|trojan|agent)\b")
_HASH = {"sha256": r"sha-?256", "sha1": r"sha-?1", "md5": r"md5"}
# Words that say the hash wanted is the decrypted file's (a plain answer needs one of them) ...
_DECRYPTED = re.compile(r"(?i)\b(?:decrypt\w*|decod\w*|recover\w*|restor\w*|plaintext|unlock\w*|unwrapp\w*|unquarantin\w*|extract\w*)\b")
# ... words that say it is the file as it was delivered (no answer: that hash is not this toolkit's) ...
_AS_DELIVERED = re.compile(r"(?i)\b(?:before|prior to|as (?:it was )?(?:delivered|received|found|given)|cipher ?text|undecrypted|"
                           r"still (?:encrypted|locked|wrapped|quarantined)|without decrypt\w*)\b")
# ... and words that leave it open which of the two is meant.
_STILL_WRAPPED = re.compile(r"(?i)\b(?:encrypted|encoded|quarantined|wrapped|locked|obfuscated|protected|packed)\b")
_DECRYPT = re.compile(r"(?i)\b(?:decrypt\w*|decod\w*|recover\w*|restor\w*|original|plaintext|unlock\w*|unwrapp\w*|unquarantin\w*|"
                      r"extract\w*|embedded|payload)\b")


def norm(name) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")


def _aid(q) -> str:
    return re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))


def known_lane(questions) -> bool:
    """True when the questions are those of one of the five known lanes: this toolkit then says nothing."""
    aids = [_aid(q) for q in questions]
    if any(re.match(r"d\d\d[_-]", a) for a in aids):
        return True                                     # Binary dNN_ ids, Metadata's dNN-<type>-NNN- ids
    if any(re.search(r"-(?:role|attack|adapter|steps)$", a) for a in aids):
        return True                                     # Script Analysis
    if aids in (["message"], ["answer"]):
        return True                                     # Warmups, Mobile
    for q in questions:
        f = triage._fmt(q)
        text = " ".join(str(x or "") for x in (q.get("question"), f.get("syntax"), f.get("pattern")))
        if "ANS-" in text or re.search(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+", str(q.get("question") or "")):
            return True
        if re.search(r"\bvalue for field \S+ in the delivered evidence set\b", str(q.get("question") or "")):
            return True                                 # the Binary lane's own sentence (its Day 2 ids had no dNN_ prefix)
        if f.get("kind") == "mitre_attack_id":
            return True
    return False


def asked(q) -> list:
    """The fields a question may be asking, most likely first: by the tail of its answer id
    (the longest tail that is a field's name), else by its words."""
    tokens = norm(_aid(q)).split("_")
    for start in range(len(tokens)):
        tail = "_".join(tokens[start:])
        got = [f for f, _, _ in FIELDS if _NAME[f].fullmatch(tail)]
        if got:
            return got
    text = str(q.get("question") or "")
    got = [f for f, _, _ in FIELDS if _TEXT[f].search(text)]
    if "c2_host" in got and "c2_port" in got:
        got = ["c2"] + [f for f in got if f not in ("c2_host", "c2_port", "c2")]
    return got


# ---- the facts of a set of files ------------------------------------------------------------------------------

_HOSTPORT = re.compile(r"((?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+|\[[0-9a-fA-F:]+\]):(\d{1,5})")
_URL = re.compile(r"(?i)([a-z][a-z0-9+.-]*)://([^/\s:@]+)(?::(\d{1,5}))?(/[^\s]*)?")
_TG_TOKEN = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")


def _text_of(data: bytes):
    if len(data) > 256 * 1024 or b"\x00\x00\x00" in data[:4096]:
        return None
    return lib.decode_text(data)


def gather(files: dict, budget: float = BUDGET) -> dict:
    """Everything the readers find in a set's files:

      {"sources": [{"shape", "file", "values": {key: value}, "plain": bool, "hit": scan hit or None}],
       "decrypted": [{"file", "plain", "sha256", "proof", "strong", "how", "names": [...]}],
       "families": {name: file}, "notes": {file: lib.note()}, "partial": the scan ran out of budget,
       "files": the base names of the files read (archives that were opened are not among them)}"""
    t0 = time.monotonic()
    out = {"sources": [], "decrypted": [], "families": {}, "notes": {}, "partial": False, "extension": None, "files": set()}
    unique = [(n, d) for n, d in triage.unique_files(files)]
    has_members = {part for k in files if ARROW in k for part in k.split(ARROW)[:-1]}     # archives that were opened
    todo = [(n, d) for n, d in unique if not (d[:4] in ARCHIVES or d[:6] in ARCHIVES) or n.split(ARROW)[-1] not in has_members]
    todo.sort(key=lambda nd: len(nd[1]))
    out["files"] = {Path(n.split(ARROW)[-1]).name for n, _ in todo}
    notes_text = []
    for i, (name, data) in enumerate(todo):
        short = name.split(ARROW)[-1]
        left = budget - (time.monotonic() - t0)
        if left <= 0.02:
            out["partial"] = True
            break
        for hit in lib.scan(data, budget=max(0.05, left / max(1, min(3, len(todo) - i)))):
            shape = "hcfg" if hit.get("container") == "hcfg" else hit["kind"] + ("." + hit["cipher"] if hit["cipher"] else "")
            out["sources"].append({"shape": shape, "file": short, "values": lib.flatten(hit["config"]) if hit["kind"] == "json" else dict(hit["config"]),
                                   "plain": hit["cipher"] is None, "hit": hit})
        out["partial"] = out["partial"] or lib.scan.partial
        for cs in lib.cobalt_strike(data):
            named = cs["named"]
            values = {k: v for k, v in named.items() if not isinstance(v, bytes)}
            hosts = named.get("c2_hosts") or []
            if len(hosts) == 1:
                values["c2_host"] = hosts[0]
                if len(named.get("c2_uris") or []) == 1:
                    values["uri"] = named["c2_uris"][0]
            values.pop("c2_server", None)
            values.pop("c2_hosts", None)
            values.pop("c2_uris", None)
            if "sleeptime" in values:
                values["sleep"] = values.pop("sleeptime")
            out["sources"].append({"shape": "cobalt_strike", "file": short, "values": values, "plain": False, "hit": None,
                                   "xor_key": cs["key"]})
            out["families"]["cobalt_strike"] = short
        text = _text_of(data)
        if text is not None:
            ns = lib.netsupport(text)
            if ns:
                values = {"gateway_address": ns.get("gateway_address"), "c2_host": ns.get("gateway_host"),
                          "c2_port": ns.get("gateway_port"), "gsk": ns.get("gsk"), "licensee": ns.get("licensee"),
                          "serial_no": ns.get("serial_no"), "secondary_gateway": ns.get("secondary_gateway")}
                out["sources"].append({"shape": "netsupport", "file": short, "values": {k: v for k, v in values.items() if v is not None},
                                       "plain": False, "hit": None})
                out["families"]["netsupport"] = short
            if lib.NOTE_WORDS.search(text):
                out["notes"][short] = lib.note(text)
                notes_text.append(text)
        if lib.autoit(data[:lib.FULL]):
            out["families"]["autoit"] = short
        if data[:4] == b"\x1bLua":
            out["families"]["lua"] = short
        if b"BSJB" in data[:lib.FULL]:
            pairs = lib.xor_b64_pairs(lib.us_strings(data), limit=20000)
            values = {}
            texts = list(dict.fromkeys(p["text"] for p in pairs))
            for t in texts:
                m = _HOSTPORT.fullmatch(t)
                if m:
                    values.setdefault("c2", []).append(t)
            if len(values.get("c2", [])) == 1:
                values["c2"] = values["c2"][0]
            elif "c2" in values:
                del values["c2"]
            keys = list(dict.fromkeys(p["key"] for p in pairs))
            if len(keys) == 1:
                values["key"] = keys[0]
            if values:
                out["sources"].append({"shape": "dotnet_pair", "file": short, "values": values, "plain": False, "hit": None})
        unknown = text is None and len(data) <= lib.FULL and time.monotonic() - t0 < budget and \
            (data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or lib.proof(data) is None)
        for q in lib.quarantine(data) if unknown else []:
            out["decrypted"].append({"file": short, "plain": q["plain"], "sha256": q["sha256"], "proof": q["kind"],
                                     "strong": q["exact"], "how": "quarantine:" + q["wrapper"], "names": [short]})
        if unknown and data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            for pe in lib.xor_pe(data):
                out["decrypted"].append({"file": short, "plain": pe["plain"], "sha256": pe["sha256"], "proof": "pe",
                                         "strong": pe["to_end"], "how": "xor_pe", "names": [short], "key": pe["key"]})
    # the note as a source, and the encrypted set
    merged = {}
    for name, n in out["notes"].items():
        for k in ("onion", "tox", "emails", "victim_id", "extension"):
            for v in n[k]:
                merged.setdefault(k, [])
                if v not in merged[k]:
                    merged[k].append(v)
        for w in n["wallets"]:
            merged.setdefault("wallets", [])
            if w not in merged["wallets"]:
                merged["wallets"].append(w)
        for w in n["wallets_unchecked"]:
            if w["coin"] == "eth" and w["check"] == "none":
                merged.setdefault("wallets_eth_onecase", []).append(w)
    names = [n for n, _ in todo]
    ext = lib.appended_extension(names)
    out["extension"] = ext
    if merged or ext:
        values = {}
        for src, dst in (("onion", "onion"), ("tox", "tox_id"), ("emails", "email"), ("victim_id", "victim_id")):
            if len(merged.get(src, [])) == 1:
                values[dst] = merged[src][0]
        wallets = merged.get("wallets", [])
        if len(wallets) == 1:
            values["wallet"] = wallets[0]["address"]
            values["_coin"] = wallets[0]["coin"]
        elif not wallets and len(merged.get("wallets_eth_onecase", [])) == 1:
            values["wallet"] = merged["wallets_eth_onecase"][0]["address"]
            values["_coin"] = "eth_one_case"
        for w in wallets:
            coin = re.sub(r"_.*", "", w["coin"])
            same = [x for x in wallets if re.sub(r"_.*", "", x["coin"]) == coin]
            if len(same) == 1:
                values[coin + "_wallet"] = w["address"]
        exts = set(merged.get("extension", [])) | ({ext} if ext else set())
        if len(exts) == 1:
            values["extension"] = next(iter(exts))
        if values:
            out["sources"].append({"shape": "note", "file": next(iter(out["notes"]), "-"), "values": values, "plain": False, "hit": None})
    enc = {n.split(ARROW)[-1]: d for n, d in todo if ext and n.split(ARROW)[-1].endswith(ext)}
    if not enc and out["notes"]:
        enc = {n.split(ARROW)[-1]: d for n, d in todo if n.split(ARROW)[-1] not in out["notes"] and lib.proof(d[:lib.FULL]) is None
               and len(d) >= 16}
    left = budget - (time.monotonic() - t0)
    if enc and 1 <= len(enc) <= 64 and left > 0.05:
        extra = []
        for n, d in todo:
            short = n.split(ARROW)[-1]
            if short in enc or len(d) > 4096:
                continue
            if short not in out["notes"]:
                extra += [d, d.strip()]
            for k, _, kind in lib.key_candidates(d, limit=64):
                if kind in lib.NEAR or short not in out["notes"]:
                    extra.append(k)
        got = lib.decrypt_set(enc, extra_keys=list(dict.fromkeys(e for e in extra if e)), budget=min(2.0, max(0.1, left)))
        for name, r in got.items():
            orig = name[:-len(ext)] if ext and name.endswith(ext) else name
            out["decrypted"].append({"file": name, "plain": r["plain"], "sha256": r["sha256"], "proof": r["proof"],
                                     "strong": r["strong"], "how": "set:" + r["cipher"], "names": [name, orig],
                                     "key": r["key"], "iv": r["iv"], "footer_len": r["footer_len"]})
        keys = {r["key"] for r in got.values()}
        ciphers = {r["cipher"] for r in got.values()}
        if got and len(keys) == 1 and len(ciphers) == 1:
            out["sources"].append({"shape": "set", "file": "-", "values": {}, "plain": False, "hit": None,
                                   "set_key": next(iter(keys)), "set_cipher": next(iter(ciphers)),
                                   "set_iv": {r["iv"] for r in got.values()}})
    return out


# ---- one question ------------------------------------------------------------------------------------------------

def _hex_options(raw: bytes, words: str) -> list:
    low = raw.hex()
    opts = [("0x_lower", "0x" + low), ("lower", low), ("upper", low.upper()), ("0x_upper", "0x" + low.upper())]
    if re.search(r"\bupper-?case\b", words, re.I):
        opts = [opts[2], opts[3], opts[0], opts[1]]
    elif not re.search(r"\b0x", words):
        opts = [opts[1], opts[0], opts[2], opts[3]]
    try:
        text = raw.decode("ascii")
        if text.isprintable() and len(text) >= 2 and not re.search(r"\bhex", words, re.I):
            opts.insert(0, ("text", text))
        elif text.isprintable() and len(text) >= 2:
            opts.append(("text", text))
    except UnicodeDecodeError:
        pass
    return opts


def _scalar_options(value) -> list:
    if isinstance(value, bool):
        return [("lower", "true" if value else "false")]
    if isinstance(value, (int, float)):
        return [("decimal", str(value))]
    if isinstance(value, str):
        return [("raw", value)] if value != "" else []
    if isinstance(value, list) and value and all(isinstance(x, (str, int, float)) and not isinstance(x, bool) for x in value):
        return [("json", json.dumps(value, separators=(",", ":"), ensure_ascii=False)), ("csv", ",".join(str(x) for x in value))]
    if isinstance(value, (list, dict)) and value:
        return [("json", json.dumps(value, separators=(",", ":"), ensure_ascii=False))]
    return []


def _endpoint(value):
    """(host, port, url) read from a 'host:port' or URL value; (None, None, None) for anything else."""
    if not isinstance(value, str):
        return None, None, None
    m = _URL.fullmatch(value.strip())
    if m:
        return m.group(2), m.group(3), value.strip()
    m = _HOSTPORT.fullmatch(value.strip())
    if m:
        return m.group(1), m.group(2), None
    return None, None, None


def _from_source(field: str, src: dict, direct: str):
    """[(format name, value)] for `field` from one source, or [] when the source does not hold it
    or holds more than one value for it."""
    values = src["values"]
    if direct is not None:
        keys = [k for k in values if norm(k.rsplit(".", 1)[-1]) == direct or norm(k) == direct]
    else:
        keys = [k for k in values if not k.startswith("_") and _NAME[field].fullmatch(norm(k.rsplit(".", 1)[-1]))]
    exact = [k for k in keys if norm(k.rsplit(".", 1)[-1]) == field or norm(k) == field]
    keys = exact or keys
    found = {json.dumps(values[k], sort_keys=True, default=str): values[k] for k in keys if values[k] not in (None, "", [], {})}
    if len(found) != 1:
        derived = []
        if not found and direct is None and field in ("c2_host", "c2_port"):
            # an endpoint kept as one 'host:port' or URL value answers its parts
            ends = {k: _endpoint(values[k]) for k in values if _NAME["c2"].fullmatch(norm(k.rsplit(".", 1)[-1]))
                    or _NAME["c2_url"].fullmatch(norm(k.rsplit(".", 1)[-1]))}
            parts = {(e[0] if field == "c2_host" else e[1]) for e in ends.values() if e[0]}
            parts.discard(None)
            if len(parts) == 1:
                derived = [("host" if field == "c2_host" else "port", next(iter(parts)))]
        return derived
    value = next(iter(found.values()))
    if field == "c2_host":
        host, _, _ = _endpoint(value)
        return [("host", host), ("raw", value)] if host and host != value else _scalar_options(value)
    if field == "c2_port":
        _, port, _ = _endpoint(value)
        if port:
            return [("port", port)]
        return [("decimal", str(value))] if re.fullmatch(r"\d{1,5}", str(value)) else []
    if field == "c2" and isinstance(value, str) and direct is None:
        host, port, url = _endpoint(value)
        if host is None:
            ports = {str(values[k]) for k in values if _NAME["c2_port"].fullmatch(norm(k.rsplit(".", 1)[-1]))
                     and re.fullmatch(r"\d{1,5}", str(values[k]))}
            if len(ports) == 1:
                return [("host_port", f"{value}:{next(iter(ports))}"), ("raw", value)]
        return [("raw", value)] + ([("host_port", f"{host}:{port}")] if url and port else [])
    if field == "extension" and isinstance(value, str):
        return [("dotted", "." + value.lstrip(".")), ("bare", value.lstrip("."))]
    return _scalar_options(value)


def _scoped(q, facts: dict, text: str) -> list:
    """The sources a question is about: all of them, or, when its artifact or its words name
    files of the delivery (not an archive that was opened), only what was read from those files
    (and the encrypted set as a whole)."""
    named = set()
    for part in (str(q.get("member") or ""), str(q.get("artifact") or "").split("->")[-1].strip()):
        if part:
            named.add(Path(part).name)
    for name in facts["files"]:
        if len(name) > 2 and re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-])", text):
            named.add(name)
    named &= facts["files"]
    if not named:
        return facts["sources"]
    return [s for s in facts["sources"] if Path(s["file"]).name in named or s["shape"] == "set"]


# An unsure offer on such a question would get the field's names rejected for its key (labels: one key, one fate).
_NEGATED = re.compile(r"\bnot\b|n't\b|\bexcept\b|\bexcluding\b|\bother than\b|\bneither\b|\bnever\b|\binstead\b"
                      r"|\b(?:second(?:ary)?|third|backup|fallback|alternate|alternative)\b|\bhow many\b|\bnumber of\b|\bcount of\b", re.I)


def answer(q, facts: dict):
    """One question's answer under the never-guess contract (module text)."""
    text = " ".join(str(q.get("question") or "").split())
    if _NEGATED.search(text):
        return None             # what the config does NOT hold, or its second or fallback value, is not the one value read
    f = triage._fmt(q)
    words = f"{f.get('syntax') or ''} {text}"
    aid = _aid(q)
    context = bool(_CONTEXT.search(text) or _CONTEXT.search(aid.replace("-", " ").replace("_", " ")))

    # 1. a hash of a decrypted file
    algos = {a for a, rx in _HASH.items() if re.search(r"\b" + rx + r"\b", text + " " + aid.replace("_", " ").replace("-", " "), re.I)}
    if algos:
        if len(algos) != 1 or not facts["decrypted"] or not _DECRYPT.search(text + " " + aid.replace("_", " ").replace("-", " ")):
            return None
        algo = next(iter(algos))
        name_rx = {n: re.compile(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])") for d in facts["decrypted"] for n in d["names"]}
        named = [d for d in facts["decrypted"] if any(name_rx[n].search(text) for n in d["names"])]
        # what the words say about WHICH bytes are hashed, read with the file names taken out
        # ('photo.png.locked' is a name, not the word 'locked')
        said = text
        for n in sorted(name_rx, key=len, reverse=True):
            said = name_rx[n].sub(" ", said)
        said += " " + aid.replace("_", " ").replace("-", " ")
        if _AS_DELIVERED.search(said):
            return None                                 # the hash of the file as delivered is asked
        sure, open_ = bool(_DECRYPTED.search(said)), bool(_STILL_WRAPPED.search(said))
        if open_ and not sure:
            return None                                 # 'the encrypted payload X': the delivered file, as far as the words go
        pool = named or facts["decrypted"]
        digests = {hashlib.new(algo, d["plain"]).hexdigest() for d in pool}
        if len(digests) != 1:
            return None
        value = next(iter(digests))
        value = value.upper() if re.search(r"\bupper-?case\b", words, re.I) else value
        if not triage._fits(q, value):
            return None
        if named and sure and not open_ and all(d["strong"] for d in pool):
            return value                                # the file is named, the words say decrypted, the decrypt is proven exactly
        # a reading of the words that is not certain has a key of its own: a name accepted for
        # 'the decrypted X' must not answer 'the encrypted X once decrypted' or 'the embedded X' plain
        reading = "" if sure and not open_ else ".mixed" if sure else ".implied"
        return pick(algo, pool[0]["how"].split(":")[0] + "." + pool[0]["proof"] + reading, [("lower_hex", value)])

    fields = asked(q)
    sources = [s for s in _scoped(q, facts, text) if not s["plain"] or context]
    # 2. a member of the config named by the tail of the answer id itself
    tokens = norm(aid).split("_")
    direct = None
    leafs = {norm(k.rsplit(".", 1)[-1]) for s in sources if s["shape"] not in ("note", "set") for k in s["values"]}
    for start in range(len(tokens)):
        tail = "_".join(tokens[start:])
        if tail in leafs and len(tail) >= 2:
            direct = tail
            break
    field = fields[0] if fields else None
    if direct is None and field is None:
        return None

    # 3. facts that are not members: the key and cipher of the reading, a family, a checksum
    spoken = re.search(r"(?i)\b(?:xor|rc4|aes|decrypt\w*|encrypt\w*)\b", words + " " + " ".join(tokens))
    if field in ("key", "iv", "cipher", "crc32", "family") and (direct is None or (spoken and field in ("key", "iv"))):
        opts, shape = _meta(field, facts, sources, words, q)
        if opts:
            opts = [(n, v) for n, v in opts if triage._fits(q, v)]
            return pick(field, shape, opts)
        if field in ("cipher", "family", "crc32"):
            return None

    got = []
    for src in sources:
        opts = _from_source(field or direct, src, direct) if (direct is not None or field in _NAME) else []
        opts = [(n, v) for n, v in opts if v not in (None, "")]
        if opts:
            got.append((src, opts))
    if not got:
        return None
    firsts = {json.dumps(opts[0][1], default=str) for _, opts in got}
    if len(firsts) != 1:
        return None                                     # two sources, two values: not one fact
    src, opts = got[0]
    opts = [(n, v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))) for n, v in opts]
    opts = [(n, v) for n, v in opts if triage._fits(q, v)]
    shape = src["shape"]
    if src["shape"] == "note" and (field or direct) == "wallet":
        shape = "note." + str(src["values"].get("_coin", "any"))
    return pick(field or direct, shape, opts)


_CIPHER_NAMES = {
    "xor1": ["xor", "single_byte_xor", "xor_single_byte", "xor_1"],
    "xorn": ["xor", "repeating_xor", "multi_byte_xor", "repeating_key_xor", "rolling_xor", "xor_repeating"],
    "rc4": ["rc4", "arc4"],
}
_FAMILY_NAMES = {
    "cobalt_strike": ["cobalt_strike", "cobaltstrike", "cobalt_strike_beacon", "beacon"],
    "netsupport": ["netsupport", "netsupport_rat", "netsupport_manager", "netsupport_client"],
    "autoit": ["autoit", "autoit_compiled", "autoit3", "compiled_autoit"],
    "lua": ["lua", "lua_bytecode", "luac"],
}


def _listed(q, names: list) -> list:
    """`names` cut down to what the question itself lists, when it lists names (an enum)."""
    listed = [norm(o) for o in triage.enum_options(q)] or [norm(o) for o in labels.enum_from_question(str(q.get("question") or ""))]
    if not listed:
        return names
    keep = [n for n in names if n in listed]
    if keep:
        return keep
    words = {t for n in names for t in n.split("_") if len(t) >= 3}
    return [o for o in listed if words & set(o.split("_"))]


def _meta(field: str, facts: dict, sources: list, words: str, q):
    """([(name, value)], shape) for a fact about the reading itself; ([], '') when it is not one fact."""
    hits = [s["hit"] for s in sources if s["hit"] is not None and s["hit"]["cipher"] is not None]
    sets = [s for s in sources if s["shape"] == "set"]
    cs = [s for s in sources if s["shape"] == "cobalt_strike"]
    if field == "family":
        fams = list(facts["families"])
        member = [s for s in sources if any(_NAME["family"].fullmatch(norm(k.rsplit(".", 1)[-1])) for k in s["values"])]
        if member or len(fams) != 1:
            return [], ""
        # The shape carries the family itself (as the cipher field carries the cipher below), so the
        # key is 'malconfig.family/<family>', not a literal 'detected' shared by every family: a
        # spelling the judge accepts for one family then answers only that family's own variants, and
        # a different family stays unsure instead of being answered plain with the stale name.
        return [(n, n) for n in _listed(q, _FAMILY_NAMES[fams[0]])], fams[0]
    if field == "crc32":
        crcs = {h["crc32"] for h in hits if h.get("container") == "hcfg" and h["valid"] == "crc32"}
        if len(crcs) != 1:
            return [], ""
        v = next(iter(crcs))
        return [("0x_lower", f"0x{v:08x}"), ("lower", f"{v:08x}"), ("upper", f"{v:08X}"), ("decimal", str(v))], "hcfg"
    ways = {(h["cipher"], h["key"], h["iv"]) for h in hits}
    ambiguous = any(h["also"] for h in hits)
    if field == "cipher":
        if len(ways) == 1 and not ambiguous and not sets:
            cipher, key, _ = next(iter(ways))
            if cipher == "xor":
                names = _CIPHER_NAMES["xor1" if len(key) == 1 else "xorn"]
            elif cipher == "rc4":
                names = _CIPHER_NAMES["rc4"]
            else:
                bits, mode = len(key) * 8, cipher.split("_")[1]
                names = [f"aes_{bits}_{mode}", f"aes_{mode}", f"aes-{bits}-{mode}", f"aes{bits}_{mode}", "aes"]
            return [(n, n) for n in _listed(q, names)], cipher
        if not hits and len(sets) == 1:
            c = sets[0]["set_cipher"]
            names = _CIPHER_NAMES["rc4"] if c == "rc4" else _CIPHER_NAMES["xorn"] if c == "xor" else \
                [c, f"aes_{len(sets[0]['set_key']) * 8}_{c.split('_')[1]}", "aes"]
            return [(n, n) for n in _listed(q, names)], "set." + c
        return [], ""
    # key and iv: of the one reading, or of the set; a config member named like a key goes the member way
    member = [s for s in sources if s["shape"] not in ("set",) and
              any(_NAME[field].fullmatch(norm(k.rsplit(".", 1)[-1])) for k in s["values"])]
    if member and not re.search(r"(?i)\b(?:xor|rc4|aes|decrypt\w*|encrypt\w*|decod\w*|obfuscat\w*|protect\w*)\b", words + " " + norm(_aid(q)).replace("_", " ")):
        return [], ""                   # the config has a member named like a key, and the words do not say which is meant
    raws = set()
    shape = ""
    if len(ways) == 1 and not ambiguous:
        cipher, key, iv = next(iter(ways))
        raw = key if field == "key" else iv
        if raw:
            raws.add(bytes(raw))
            shape = cipher
    for s in sets:
        raw = s["set_key"] if field == "key" else (next(iter(s["set_iv"])) if len(s["set_iv"]) == 1 else None)
        if raw:
            raws.add(bytes(raw))
            shape = shape or "set." + s["set_cipher"]
    if field == "key" and not raws and len(cs) == 1 and not hits:
        raws.add(bytes([cs[0]["xor_key"]]))
        shape = "cobalt_strike"
    if len(raws) != 1 or len(ways) > 1:
        return [], ""
    return _hex_options(next(iter(raws)), words), shape


# ---- the runner contract ----------------------------------------------------------------------------------------------

_Q_WORDS = re.compile(r"(?i)\b(?:config(?:uration)?|c2|c&c|cnc|command[- ]and[- ]control|mutex|beacon|campaign|ransom\w*|wallet|"
                      r"onion|decrypt\w*|xor|rc4|aes|bot token|user[- ]agent|victim|implant|stealer|malware|payload|watermark|"
                      r"quarantin\w*|key)\b")
_MARKS = (b"HCFG", b"GatewayAddress=", lib.AU3_MARK, b"\x1bLua", b"client32", b"AU3!EA0")


def signals(questions, files) -> float:
    """0..1: how strongly these questions and files look like malware config extraction or a
    ransomware set. 0 for the questions of one of the five known lanes. Cheap: words of the
    questions (up to 0.6) and marks in the first and last megabyte of each file (up to 0.4): an
    HCFG magic (also base64, hex or UTF-16), a Cobalt Strike settings block, NetSupport, AutoIt
    and Lua markers, a ransom note's words, an extension appended to several names."""
    questions = list(questions or [])
    if questions and known_lane(questions):
        return 0.0
    hits = 0
    for q in questions:
        blob = f"{q.get('question') or ''} {_aid(q).replace('-', ' ').replace('_', ' ')}"
        if _Q_WORDS.search(blob):
            hits += 1
    qscore = min(1.0, 2.0 * hits / len(questions)) if questions else 0.0
    mark = 0.0
    names = []
    for name, data in triage.unique_files(files or {}):
        names.append(name)
        if mark >= 1.0:
            continue
        parts = [data[:1 << 20]] + ([data[-(1 << 20):]] if len(data) > 1 << 20 else [])
        for part in parts:
            if any(m in part for m in _MARKS) or any(s in part for s in lib._B64_SEEDS[:lib._HCFG_ONLY[id(lib._B64_SEEDS)]]) \
                    or b"48434647" in part or lib._WIDE_SEEDS[0] in part:
                mark = 1.0
            elif lib._CS_DELTA in lib.delta(part[:1 << 20]):
                mark = max(mark, 1.0 if lib.cobalt_strike(part[:1 << 20]) else 0.0)
            elif len(part) <= 65536:
                text = lib.decode_text(part) if b"\x00\x00" not in part[:512] else None
                if text and lib.NOTE_WORDS.search(text):
                    mark = max(mark, 1.0)
    if mark < 1.0 and lib.appended_extension(names):
        mark = max(mark, 0.75)
    return round(min(1.0, 0.6 * qscore + 0.4 * mark), 3)


def solve_set(questions, files, ctx) -> dict:
    """The runner contract. ctx["malconfig_any"] = True answers the questions of a known lane as
    well (for a lane agent who has decided that this toolkit is the reader; see the doc)."""
    out = {q.get("qid") or q.get("id"): None for q in questions}
    if known_lane(questions) and not (ctx or {}).get("malconfig_any"):
        return out
    if not questions:
        return out
    try:
        facts = gather(files, budget=float((ctx or {}).get("malconfig_budget") or BUDGET))
    except Exception:
        return out
    partial = (ctx or {}).get("partial")
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            out[qid] = answer(q, facts)
        except Exception:               # a fact that cannot be read is no answer
            out[qid] = None
        if isinstance(partial, dict) and out[qid] is not None:
            partial[qid] = out[qid]
    return out


# ---- the command -------------------------------------------------------------------------------------------------------

def _show(v, n=96):
    if isinstance(v, (bytes, bytearray)):
        v = bytes(v)
        return "0x" + v.hex() if len(v) <= 48 else f"0x{v[:24].hex()}... ({len(v)} bytes)"
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n] + "..."


def report(files: dict, budget: float = 20.0) -> dict:
    """The triage of a set of files as one JSON-ready map (what the command prints)."""
    facts = gather(files, budget=budget)
    rep = {"files": [], "configs": [], "families": facts["families"], "notes": facts["notes"], "decrypted": [],
           "appended_extension": facts["extension"], "partial": facts["partial"], "lua": {}, "autoit": {}, "dotnet": {}}
    for name, data in triage.unique_files(files):
        short = name.split(ARROW)[-1]
        rep["files"].append({"file": name, "size": len(data), "type": triage.identify(data, short), "sha256": lib.sha256(data),
                             "proof": lib.proof(data[:lib.FULL])})
        if data[:4] == b"\x1bLua":
            got = lib.lua_constants(data)
            rep["lua"][short] = got if got else "not parsed (another version, LuaJIT, or stripped)"
        au = lib.autoit(data[:lib.FULL])
        if au:
            rep["autoit"][short] = au
        if b"BSJB" in data[:lib.FULL]:
            us = lib.us_strings(data)
            rep["dotnet"][short] = {"user_strings": len(us), "sample": us[:40], "pairs": lib.xor_b64_pairs(us, limit=20000)}
    for s in facts["sources"]:
        h = s["hit"]
        row = {"file": s["file"], "shape": s["shape"], "values": {k: v for k, v in s["values"].items()}}
        if h is not None:
            row.update(how=h["how"], offset=h["offset"], cipher=h["cipher"], key=_show(h["key"]) if h["key"] else None,
                       iv=_show(h["iv"]) if h["iv"] else None, valid=h["valid"], also=len(h["also"]),
                       plain_sha256=lib.sha256(h["plain"]), plain_bytes=len(h["plain"]))
            if h.get("container") == "hcfg":
                row.update(version=h["version"], crc32=f"0x{h['crc32']:08x}")
        for k in ("set_key", "set_cipher", "xor_key"):
            if k in s:
                row[k] = _show(s[k]) if isinstance(s[k], (bytes, bytearray)) else s[k]
        rep["configs"].append(row)
    for d in facts["decrypted"]:
        rep["decrypted"].append({k: (_show(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in d.items() if k != "plain"}
                                | {"bytes": len(d["plain"])})
    return rep


def read_paths(paths) -> dict:
    """{name: bytes} of files and of every file under a folder; archives opened as tools/run.py opens them."""
    files = {}
    for p in paths:
        p = Path(p)
        for f in ([p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file())):
            files[f.name if f.name not in files else str(f)] = f.read_bytes()
    try:
        sys.path.insert(0, str(HERE.parent.parent / "tools"))
        import run
        expanded = dict(files)
        for name, data in list(files.items()):
            if data[:4] == b"PK\x03\x04" or data[:6] == b"7z\xbc\xaf\x27\x1c":
                try:
                    run.expand(name, data, expanded)
                except BaseException:
                    pass
        files = expanded
    except Exception:
        pass
    return files


def main(argv) -> int:
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__.strip().split("\n\n")[0] + "\n\n  .venv/bin/python solvers/toolkits/malconfig.py <file or folder> [...] [--json]", file=sys.stderr)
        return 2
    missing = [p for p in paths if not Path(p).exists()]
    if missing:
        print(f"malconfig.py: not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    files = read_paths(paths)
    rep = report(files)
    if "--json" in argv:
        print(json.dumps(rep, indent=1, ensure_ascii=False, default=str))
        return 0
    print(f"MALCONFIG files={len(rep['files'])} configs={len(rep['configs'])} decrypted={len(rep['decrypted'])} "
          f"families={','.join(rep['families']) or '-'} signals={signals([], files)} seconds={time.monotonic() - t0:.2f}"
          + (" PARTIAL (the keyed search ran out of time)" if rep["partial"] else ""))
    for f in rep["files"]:
        print(f"FILE {f['file']}  {f['type']}  {f['size']} bytes  sha256={f['sha256']}" + (f"  proof={f['proof']}" if f["proof"] else ""))
    for c in rep["configs"]:
        head = f"CONFIG {c['file']} shape={c['shape']}"
        if "how" in c:
            head += f" how={c['how']} offset=0x{c['offset']:x} valid={c['valid']}"
            head += f" key={c['key']}" if c.get("key") else ""
            head += f" iv={c['iv']}" if c.get("iv") else ""
            head += f" crc32={c['crc32']} version={c['version']}" if "crc32" in c else ""
            head += f" also={c['also']} (the same config reads another way: key and cipher are not one fact)" if c.get("also") else ""
        for k in ("set_key", "set_cipher", "xor_key"):
            head += f" {k}={c[k]}" if k in c else ""
        print(head)
        for k, v in c["values"].items():
            if not k.startswith("_"):
                print(f"  {k} = {_show(v)}")
    if len({json.dumps(c["values"], sort_keys=True, default=str) for c in rep["configs"] if "how" in c}) > 1:
        print("NOTE more than one config validated: a field is answered only when exactly one value fits it")
    for name, n in rep["notes"].items():
        print(f"NOTE-FILE {name}")
        for k, v in n.items():
            if v:
                print(f"  {k}: " + ", ".join(_show(x) for x in v))
    if rep["appended_extension"]:
        print(f"SET appended extension {rep['appended_extension']}")
    for d in rep["decrypted"]:
        print(f"DECRYPTED {d['file']} how={d['how']} proof={d['proof']}{'' if d['strong'] else ' (weak: not answered plain)'} "
              f"bytes={d['bytes']} sha256={d['sha256']}" + (f" key={d['key']}" if d.get("key") else "")
              + (f" footer_len={d['footer_len']}" if d.get("footer_len") else ""))
    for name, got in rep["lua"].items():
        print(f"LUA {name}: " + (f"version {got['version']} source={got['source']} strings={got['strings'][:40]}" if isinstance(got, dict) else got))
    for name, au in rep["autoit"].items():
        print(f"AUTOIT {name}: compiled script marker at 0x{au['offset']:x} subtype={au['subtype']} standalone={au['standalone']} "
              f"after_pe={au['after_pe']} (not extracted: sandbox or the agent)")
    for name, dn in rep["dotnet"].items():
        print(f"DOTNET {name}: {dn['user_strings']} user strings; pairs={dn['pairs']}")
        for s in dn["sample"][:20]:
            print(f"  us: {_show(s, 120)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
