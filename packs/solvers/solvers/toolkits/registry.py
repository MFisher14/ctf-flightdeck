#!/usr/bin/env python3
"""The registry of category toolkits (built 2026-10-08 for Day 9 and later).

A toolkit is one file solvers/toolkits/<key>.py for a category no lane solver plays. Each has reader
functions, `signals(questions, files) -> float` (0..1: how much the delivery and the questions look
like its category), `solve_set(questions, files, ctx)` under the runner contract and never-guess
(AGENTS.md, "Uncertain answers"), a triage command, and a one-page reference docs/toolkits/<key>.md.

Who reads this file:
  - tools/lane_match.py: for a lane tools/lanes.py does not know, every toolkit with `match` set is
    run beside the five lane solvers, one process each. A toolkit can win only when no lane solver
    does and no known lane's signal shows (see lane_match.decide_toolkit).
  - solvers/common/triage.py: the triage map names the best-matching toolkits, their reference
    page and the first command to run.
  - docs/toolkits/README.md is the same table for a reader; tests/test_toolkit_registry.py keeps
    the two and the files on disk in step.

A known lane never reaches any of this: only the opener's NO_SOLVER path calls lane_match.py and
triage.py. Nothing here makes a request or reads a token.

The bundle router (solvers/toolkits/evidence_core.py route()) also reads this file: a question the
evidence layer leaves None is handed to the toolkits whose signal reaches its ROUTE_SIGNAL. In the
csctf and Pink forks this file was treated as dead code and left out, and the router quietly said
"registry not loaded"; B-001b restored it and made every miss loud (ctf/packs.py): a missing
registry raises RegistryLoadError, a registered toolkit whose file is gone raises PackMissing, one
that does not import raises PackLoadError. A toolkit whose own signals() raises scores 0.0 and says
so on stderr, naming it.

  .venv/bin/python solvers/toolkits/registry.py                 the table
  .venv/bin/python solvers/toolkits/registry.py <attempt dir>   the toolkits ranked for a saved attempt
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))          # appended, never first: the repo root must not shadow a lane module
from ctf.packs import PackMissing, load_module  # noqa: E402
DOCS = ROOT / "docs" / "toolkits"
PREFIX = "toolkit:"             # a toolkit's name among lane_match.py's candidates: toolkit:<key>
SHOWN = 0.25                    # a toolkit is named in the triage map from this signal on
RANK_SECONDS = 8.0              # the whole ranking stops after this long (the map says so)

# key: the file's stem and the label prefix (solvers/common/labels.py LANE_DIRS) unless `labels` says
#      otherwise.  threshold: the signal from which the toolkit may be a match candidate's winner.
# match: tried by tools/lane_match.py.  generic: wins only when no specific toolkit is eligible.
# row: its backlog row in docs/improvements.md.  reads: what it reads, for the table.  args: what follows the file name in the first command.
TOOLKITS = [
    {"key": "evidence_core", "threshold": 0.5, "match": True, "generic": True, "row": "122",
     "reads": "any mix of csv, JSON, JSON lines, logs (also IIS/Zeek #Fields and Apache error logs), XML, sqlite: "
              "tables, queries, times, a cross-artifact indicator index, the exactly-one question router, the bundle "
              "router across toolkits",
     "args": "<attempt dir>"},
    {"key": "memory", "threshold": 0.5, "match": True, "row": "82",
     "reads": "Volatility tables (text, CSV, JSON), minidump, ELF core, LiME, crash dump; symbol-free carving; "
              "a Windows image off the clock with `--vol windows --symbols fetch` (sandbox)",
     "args": "<members>..."},
    {"key": "network", "threshold": 0.7, "match": True, "row": "83",
     "reads": "pcap and pcapng in plain Python: DNS, HTTP, TLS SNI/JA3/JA4, credentials, carved files, covert "
              "channels, beacons, USB keys",
     "args": "--attempt <attempt dir>"},
    {"key": "email", "threshold": 0.7, "match": True, "row": "84",
     "reads": ".eml, .msg, mbox: Received chain, SPF/DKIM/DMARC, attachments, URLs, QR codes, HTML smuggling",
     "args": "<file>..."},
    {"key": "cloudlogs", "threshold": 0.5, "match": True, "row": "85",
     "reads": "M365 Unified Audit Log, Entra sign-ins and audit, CloudTrail, Azure Activity, GCP audit, Okta, "
              "Kubernetes audit (JSON, JSON lines, CSV)",
     "args": "<attempt dir>/members"},
    {"key": "windows", "threshold": 0.5, "match": True, "row": "86",
     "reads": ".evtx (pyevtx-rs, python-evtx as the fallback) and event exports, registry hives and .reg, "
              "prefetch, LNK, task XML, $I, $MFT, USN; a persistence summary",
     "args": "<attempt dir>/members"},
    {"key": "maldoc", "threshold": 0.5, "match": True, "row": "87",
     "reads": "OLE/VBA/XLM, OOXML, RTF, PDF, OneNote, LNK, ISO/FAT/VHD, HTA/WSF (static only)",
     "args": "--attempt <attempt dir>"},
    {"key": "rf", "threshold": 0.5, "match": True, "row": "89",
     "reads": "Flipper .sub/.nfc/.rfid/.ir, MIFARE Classic dumps, NDEF, PWM/Manchester, IQ envelope, magstripe, "
              "EM4100/Wiegand, Intel HEX/SREC, candump, UART/I2C/SPI CSV",
     "args": "<members>..."},
    {"key": "web", "threshold": 0.5, "match": False, "row": "90", "labels": "web",
     "reads": "live-target readiness (WebClient with scope lock and VPN stop) and offline HAR/log/JWT/cookie "
              "readers; never on a clock",
     "args": "<file>..."},
    {"key": "web_evidence", "threshold": 0.6, "match": True, "row": "123", "labels": "web",
     "reads": "the Web lane as files: access logs (Apache/nginx, IIS W3C, JSON lines, CSV), HAR, JWT and session "
              "cookies, source review",
     "args": "<attempt dir>/members"},
    {"key": "edr_persistence", "threshold": 0.6, "match": True, "row": "124",
     "reads": "exported Sysmon/Security/PowerShell events and EDR process JSON, process tree, -EncodedCommand, "
              "persistence table with ATT&CK ids",
     "args": "<attempt dir>/members"},
    {"key": "nix_host", "threshold": 0.5, "match": True, "row": "125",
     "reads": "Linux and macOS host: auth logs, auditd, journald, utmp/wtmp, cron, systemd, plists, TCC, quarantine",
     "args": "<attempt dir>/members"},
    {"key": "cloud_container", "threshold": 0.7, "match": False, "row": "126",
     "reads": "cloud and Kubernetes audit logs, docker save and OCI images (layers, deleted files), Dockerfile, "
              "Compose, manifests, Terraform state",
     "args": "<attempt dir>/members"},
    {"key": "ai_model_files", "threshold": 0.5, "match": True, "row": "127",
     "reads": "pickle (symbolic walk, never unpickled), PyTorch zip, joblib, numpy, safetensors, GGUF, ONNX, Keras",
     "args": "<file>..."},
    {"key": "agent_trace", "threshold": 0.3, "match": True, "row": "128",
     "reads": "agent transcripts, MCP configs, tool manifests and Python MCP server sources, RAG corpora, hidden "
              "text (tag characters, zero-width, display:none, PDF render mode 3, same-colour ANSI terminal text)",
     "args": "<members dir>"},
    {"key": "malconfig", "threshold": 0.5, "match": True, "row": "129",
     "reads": "malware configs beyond HCFG (XOR, RC4, AES under a key in the file), family readers, ransomware "
              "sets and notes",
     "args": "<attempt dir>/artifact"},
    {"key": "modern_crypto", "threshold": 0.5, "match": True, "row": "130",
     "reads": "RSA from parameters, XOR and stream reuse, stated-key ciphers, JWT, ECDSA nonce reuse, ECB and "
              "generator checks",
     "args": "<members>... --budget 20"},
    {"key": "carve_stego", "threshold": 0.45, "match": True, "row": "131",
     "reads": "carving, PNG/JPEG/GIF/WAV side channels, LSB, DTMF, zero-width text, QR and barcodes, small disk "
              "images, minidump and ELF core",
     "args": "<files>... --extract <attempt dir>/carved"},
    {"key": "sqlite_artifacts", "threshold": 0.5, "match": True, "row": "132",
     "reads": "browser and app SQLite by schema, deleted rows (WAL, journal, freelist), Chrome extensions, LevelDB",
     "args": "<members folder>"},
    {"key": "repo_supply_chain", "threshold": 0.6, "match": True, "row": "133",
     "reads": "git/hg/darcs/svn/fossil from bytes (no VCS binary is run), npm/wheel/sdist/vsix/crx/jar/nupkg/gem, "
              "JSON hash manifests, workflows, secrets",
     "args": "<artifact or members folder>"},
    {"key": "osint", "threshold": 0.45, "match": True, "row": "158",
     "reads": "leads from a delivery and the questions (usernames, handles, e-mails, domains, URLs, phones, "
              "coordinates, EXIF device/GPS, hashes, dates, names, QR, language), ranked, with a search plan "
              "(leads.md); solve_set answers only what the bytes prove",
     "args": "<attempt dir>"},
    {"key": "pwn", "threshold": 0.6, "match": True, "row": "T-a",
     "reads": "userland exploitation RECON: ELF arch, mitigations (NX/PIE/RELRO/canary/FORTIFY via a "
              "checksec-style header read), symbols, GOT/PLT, dangerous imports, ROP-gadget ENUMERATION "
              "(report, never executed), format-string/overflow surface; facts unsure, win-addr candidates, "
              "the flag always None; a live target is the hand tool pwn_target.py",
     "args": "<file>..."},
    {"key": "forensics", "threshold": 0.6, "match": True, "row": "T-b",
     "reads": "container/structure facts for disk/memory/capture forensics (a NARROW complement to network, "
              "memory and carve_stego): pcap/pcapng format, byte order and datalink; memory-dump format and OS; "
              "disk partition scheme (MBR/GPT), filesystem and boot signature; all unsure, payloads left to the "
              "specialists",
     "args": "<file>..."},
    {"key": "asn1_reader", "threshold": 0.5, "match": True, "row": "C2",
     "reads": "ASN.1/DER + X.509/PKCS/PEM/SSH/PGP: certificate subject/issuer/serial/validity, SHA-1/SHA-256 "
              "fingerprints, key algorithm and size, SSH and PGP key fingerprints; deterministic facts "
              "plain-eligible, interpretive unsure, private secrets and flags None",
     "args": "<file>..."},
    {"key": "wire_decode", "threshold": 0.5, "match": True, "row": "C3",
     "reads": "schema-less protobuf/CBOR/MessagePack/BSON wire decode: field numbers, wire types, lengths and "
              "scalar values (structural facts plain-eligible); semantic field names unsure; malformed None",
     "args": "<file>..."},
    {"key": "pcap_creds", "threshold": 0.6, "match": True, "row": "GAP-PCAP-CREDS", "labels": "network",
     "reads": "pcap/pcapng credential MATERIAL in plain Python (specialist ownership over network.py only for an "
              "equivalent byte-proven answer): WPA* EAPOL handshakes "
              "(hashcat 22000), NTLMSSP type2/type3 over SMB/HTTP/LDAP (netntlmv1/v2), Kerberos AS-REQ/AS-REP/TGS-REP "
              "etype 23 (krb5pa/krb5asrep/krb5tgs); the assembled hashcat line unsure, the cracked password always None",
     "args": "<capture>..."},
    {"key": "pdf_revisions", "threshold": 0.5, "match": True, "row": "GAP-PDF-REVISIONS", "labels": "carve_stego",
     "reads": "PDF incremental-revision splitter: each prior revision carved as a standalone document through the "
              "startxref/%%EOF boundaries and the /Prev xref chain (classic tables and xref streams), an object's "
              "value at revision k; the revision count plain, an author-named selection unsure, nothing rendered or run",
     "args": "<file.pdf>..."},
    {"key": "fs_walk", "threshold": 0.5, "match": True, "row": "GAP-FS-WALK", "labels": "forensics",
     "reads": "directory-walk facts of a complete, checksum-validated filesystem image that carve_stego_fs, forensics "
              "and windows do not walk: squashfs, NTFS $MFT ($DATA incl. named :ADS, in-use flag), exFAT entry sets, "
              "JFFS2 (CRC-checked); paths/sizes/stream-names plain-eligible, path spellings unsure, a flag always None",
     "args": "<image>..."},
    {"key": "firmware_walk", "threshold": 0.5, "match": True, "row": "firmware-image-walker", "labels": "firmware",
     "reads": "firmware/flash container walker (distinct from carve_stego_fs and fs_walk): SquashFS 4.0, JFFS2 "
              "(CRC-checked), UBI/UBIFS volume map and nodes, DTB/FDT node paths and properties, U-Boot env (leading "
              "CRC32 validated first); names/sizes plain-eligible, path spellings unsure, no non-stdlib codec is run",
     "args": "<members>..."},
    {"key": "il2cpp", "threshold": 0.5, "match": True, "row": "il2cpp",
     "reads": "Unity IL2CPP global-metadata.dat reader (magic 0xFAB11BAF): embedded string literals read byte-exact at "
              "(dataIndex, length), identifier names of the type/method/field tables from the string heap; the version "
              "and literal-table count plain, names and definition counts unsure under binary.il2cpp_*, the flag None",
     "args": "<global-metadata.dat>..."},
    {"key": "jumplist", "threshold": 0.55, "match": True, "row": "wave121/forensics-next", "labels": "windows",
     "reads": "Windows Jump Lists: a bounded CFB walk of an automaticDestinations-ms (DestList MRU order, per-entry "
              "hostname/access-time/pin) with every numbered stream and a customDestinations-ms carve fed to the armed "
              "windows.lnk() (target, times, volume serial, drive type, machine id, MAC); nothing judged, so every "
              "answer is an unsure pick (format) or candidate (hypothesis, re-derived per variant) or None, the flag None",
     "args": "<file>..."},
    {"key": "deser_chain", "threshold": 0.6, "match": True, "row": "wave121",
     "reads": "passive serialized-object reader: Java serialization (magic AC ED 00 05) class-descriptor names, "
              "serialVersionUIDs, object graph; PHP serialize() objects/properties (and phar manifest metadata); .NET "
              "BinaryFormatter/NRBF type and assembly names; structural counts plain-eligible, class/type names and the "
              "gadget-chain family unsure candidates, a command/url/flag a lead; nothing is deserialized or run",
     "args": "<file>..."},
    {"key": "serial_decode", "threshold": 0.5, "match": True, "row": "serial-native-blobs",
     "reads": "language-native serialization blobs with NO instantiation (beyond deser_detect and wire_decode): Java "
              "serialization stream (AC ED), PHP serialize(), Ruby Marshal 4.8 (04 08) -> class names, field/property/"
              "ivar names, counts and primitive values read as structural facts (plain-eligible via labels.pick); a "
              "malformed or not-fully-consumed blob, a container value and the flag are None",
     "args": "<file>..."},
    {"key": "ese_reader", "threshold": 0.6, "match": False, "row": "ese_reader", "labels": "forensics",
     "reads": "bounded pure-Python ESE/EDB table-ROW reader (SRUM SRUDB.dat, WebCacheV01.dat, NTDS.dit; signature "
              "0x89abcdef): the header, the MSysObjects catalog (tables + columns) and leaf-record row values (fixed "
              "and variable columns); every fact unsure under forensics.ese_* (deterministic-reader picks; row values "
              "delivery-scoped candidates), malformed/truncated => None, flag None; agent's/triage's, never a match",
     "args": "<SRUDB.dat|WebCacheV01.dat|NTDS.dit|*.edb>..."},
    {"key": "blockchain", "threshold": 0.6, "match": True, "row": "blockchain",
     "reads": "READ-ONLY, artifact-only EVM and Bitcoin facts (nothing executed, no RPC): raw EVM tx (RLP; sender by "
              "ecrecover, to/value/nonce/gas/chain id/selector/hash), 4-byte selectors and ABI calldata/event decode, "
              "EVM bytecode dispatch table + constructor/runtime split + solc version + PUSH strings, EIP-55 checksum, "
              "address from a provided public key, base58check and bech32/bech32m addresses, Bitcoin raw tx; every "
              "answer an unsure pick under blockchain.*, a private key, seed or flag always None",
     "args": "<file>..."},
]
BY_KEY = {t["key"]: t for t in TOOLKITS}


def entries(match_only: bool = False) -> list:
    """The registry rows (only those with `match` set when match_only). A row whose file is not there
    raises PackMissing naming it: a registered toolkit is never skipped without a word."""
    rows = [t for t in TOOLKITS if t.get("match") or not match_only]
    for t in rows:
        if not path(t["key"]).is_file():
            raise PackMissing(PREFIX + t["key"], path(t["key"]), "registered in solvers/toolkits/registry.py "
                              "but the file is not there")
    return rows


def path(key: str) -> Path:
    return HERE / f"{key}.py"


def doc(key: str) -> Path:
    return DOCS / f"{key}.md"


def label_prefix(key: str) -> str:
    return BY_KEY[key].get("labels") or key


def first_command(key: str) -> str:
    return f".venv/bin/python solvers/toolkits/{key}.py {BY_KEY[key]['args']}"


def key_of(name) -> str:
    """'network' from 'toolkit:network'; '' for anything that is not a registered toolkit's name."""
    name = str(name or "")
    key = name[len(PREFIX):] if name.startswith(PREFIX) else ""
    return key if key in BY_KEY else ""


MODULE_PREFIX = "ctf_toolkit_"  # a toolkit's module name: ctf_toolkit_<key>


def load(key: str):
    """The toolkit's module, loaded by path under a name of its own (never as `<key>`: two toolkits
    share a stem with a reader in solvers/common, and one is named like the standard `email`).
    PackMissing for a key that is not registered or whose file is not there, PackLoadError for a file
    that raises while importing (ctf/packs.py); a runner's BaseException stop passes through."""
    if key not in BY_KEY:
        raise PackMissing(PREFIX + str(key), path(str(key)), "not a key of solvers/toolkits/registry.py")
    return load_module(MODULE_PREFIX + key, path(key), pack=PREFIX + key)


def signal(key: str, questions, files) -> float:
    """The toolkit's own signals() as a float in 0..1. A toolkit that cannot be loaded raises (PackMissing,
    PackLoadError). One whose signals() raises or answers something that is not a number scores 0.0, and
    a NOTE line on stderr names the toolkit and the error: a toolkit that cannot say does not match, but
    never silently."""
    mod = load(key)
    try:
        v = float(mod.signals(questions, files))
    except (Exception, SystemExit) as e:  # noqa: BLE001 - not BaseException: a runner's stop must pass through
        print(f"[registry] NOTE toolkit:{key} signals() raised {type(e).__name__}: {str(e)[:160]}; scored 0.0",
              file=sys.stderr)
        return 0.0
    if v != v:
        print(f"[registry] NOTE toolkit:{key} signals() answered NaN; scored 0.0", file=sys.stderr)
        return 0.0
    return max(0.0, min(1.0, v))


def rank(questions, files, budget: float = RANK_SECONDS) -> dict:
    """{"rows": [{key, signal, threshold, match, doc, command, reads}], "skipped": [key]} with the
    rows of every toolkit whose signal is SHOWN or more, best first. Toolkits not reached within
    `budget` seconds are listed as skipped. For the triage map only: never on a clock."""
    t0, rows, skipped = time.monotonic(), [], []
    for t in entries():
        if time.monotonic() - t0 > budget:
            skipped.append(t["key"])
            continue
        s = signal(t["key"], questions, files)
        if s >= SHOWN:
            rows.append({"key": t["key"], "signal": round(s, 3), "threshold": t["threshold"], "match": bool(t.get("match")),
                         "generic": bool(t.get("generic")), "doc": f"docs/toolkits/{t['key']}.md",
                         "command": first_command(t["key"]), "reads": t["reads"]})
    rows.sort(key=lambda r: (r["generic"], -r["signal"], r["key"]))
    return {"rows": rows, "skipped": skipped}


def table() -> str:
    lines = ["| toolkit | row | reads | first command |", "| --- | --- | --- | --- |"]
    for t in TOOLKITS:
        lines.append(f"| [`{t['key']}`]({t['key']}.md) | {t['row']} | {t['reads']} | `{first_command(t['key'])}` |")
    return "\n".join(lines)


def main(argv) -> int:
    if not argv:
        print(table())
        return 0
    sys.path.insert(0, str(ROOT / "solvers" / "common"))
    import triage      # noqa: E402
    folder = Path(argv[0]).resolve()
    if not ((folder / "attempt.json").is_file() or (folder / "status.json").is_file()):
        print(f"registry.py: no attempt.json or status.json under {folder}", file=sys.stderr)
        return 2
    _, sets, _ = triage.load(folder)
    questions = [q for qs, _, _ in sets for q in qs]
    files = {}
    for _, f, _ in sets:
        for k, v in f.items():
            files.setdefault(k, v)
    got = rank(questions, files)
    for r in got["rows"]:
        print(f"TOOLKIT {r['key']} signal={r['signal']:.2f} threshold={r['threshold']:.2f} doc={r['doc']} first={r['command']}")
    if got["skipped"]:
        print("NOTE not asked (time): " + ", ".join(got["skipped"]))
    if not got["rows"]:
        print("TOOLKIT - no toolkit's signal reaches %.2f" % SHOWN)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
