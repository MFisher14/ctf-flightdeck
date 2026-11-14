#!/usr/bin/env python3
"""Metadata Forensics graph readers: the execution chain through a zip of artifacts (Day 31 fold).

Day 31 ("No Artifact Left Behind") asked `graph.execution_chain_artifact_ids` of a zip of 22 extensionless
members (`case-001.zip`) as a compact JSON array. No reader had the name, Layer 1 STOPped, and the standby's
`day_patch_live.py` answered it as a candidate pick (row 346); the judge accepted `stems_chain` under
`metadata.graph.execution_chain_artifact_ids/zip+chain#candidates` on the first probe (rejected: the basenames,
the full paths, the chain without its terminal and without its start). This fold replaces that mutable live file.

properties_strict.py loads this file by name and hands it a question whose property (after the file's stem)
starts with `graph_`, AFTER the target file is chosen by the lane's own target_file(), before any property
lookup, and only for a name `route()` claims and no reader registers. It registers nothing. Anything `route()`
does not know returns None and takes the normal path exactly as before.

What the fact is: each member of the zip names the next member it runs or delivers -- a PowerShell line
(`Invoke-Item`, `Start-Process`, `&` of `.\\<name>`), a PNG tEXt/zTXt/iTXt `next=<name>`, an inner zip's
`run.txt` (`execute <name>`), a mail attachment (`open: <name>`, `forwarded to: <name>`), an SQLite row
(`launch_queue.target`). The reader reads every member's bytes (raw, plus the inner zip's members, decoded MIME
parts and inflated PNG text chunks) and records an edge to every OTHER member whose name/stem occurs there as a
whole token. The chain is the walk from the one member nobody names to a member that names nobody; a member
naming two others, a walk that loops, or not exactly one such chain is None. The 18-node ring nobody enters is
the decoy. The answer is NEVER plain: it is a `labels.candidates` pick under the key above, the ordered stems
first. On the base the seed's accepted `stems_chain` makes that pick replay as the frozen value; on a variant
whose byte-derived chain differs, that variant's own stems answer, still as the accepted candidate hypothesis.
"""
import email
import email.policy
import io
import json
import re
import zipfile
import zlib

import labels

FIELD = "graph_execution_chain_artifact_ids"
KEY = "metadata.graph.execution_chain_artifact_ids/zip+chain"
MAX_MEMBERS = 512
MAX_BYTES = 8 << 20

# Names of the fact we will read when asked (canon form: lowercase, underscores). The judged field plus a few
# obvious author synonyms; every one answers unsure under the same candidate key -- only the hypothesis names
# differ, and only `stems_chain` is judge-accepted.
_ROUTED = {
    "graph_execution_chain_artifact_ids",
    "graph_execution_chain_artifacts",
    "graph_execution_chain_ids",
    "graph_execution_chain",
    "graph_execution_order_artifact_ids",
    "graph_execution_order",
}


def route(key):
    """A truthy sentinel for a graph property this module reads, else None."""
    k = str(key or "").strip().lower().replace(".", "_").replace("-", "_")
    return "chain" if k in _ROUTED else None


def _png_text(b):
    out = []
    i = 8
    while i + 12 <= len(b):
        n = int.from_bytes(b[i:i + 4], "big")
        t = b[i + 4:i + 8]
        body = b[i + 8:i + 8 + n]
        if t == b"zTXt":
            k = body.find(b"\x00")
            if k >= 0:
                try:
                    out.append(zlib.decompress(body[k + 2:]))
                except Exception:
                    pass
        elif t == b"iTXt":
            k = body.find(b"\x00")
            if k >= 0 and k + 2 < len(body) and body[k + 1] == 1:
                rest = body[k + 3:]
                parts = rest.split(b"\x00", 2)
                if len(parts) == 3:
                    try:
                        out.append(zlib.decompress(parts[2]))
                    except Exception:
                        pass
        if t == b"IEND":
            break
        i += 12 + n
    return out


def _texts(b):
    """Every byte string a member's name could appear in: the raw bytes, plus the readable payloads of the
    containers Day 31 used to hide the pointer (inner zip members, SQLite cells, PNG text chunks, MIME parts)."""
    out = [b]
    if b[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(b))
            for inf in z.infolist()[:64]:
                if not inf.is_dir() and inf.file_size <= MAX_BYTES:
                    out.append(z.read(inf))
        except Exception:
            pass
    elif b[:16] == b"SQLite format 3\x00":
        try:
            import sqlite3
            con = sqlite3.connect(":memory:")
            con.deserialize(b)
            cells = []
            for (tname,) in con.execute(
                    "select name from sqlite_master where type='table'").fetchall()[:32]:
                for row in con.execute('select * from "%s" limit 1000' % tname.replace('"', '""')):
                    cells.extend(str(c) for c in row if c is not None)
            con.close()
            out.append("\n".join(cells).encode("utf-8", "replace"))
        except Exception:
            pass
    elif b[:8] == b"\x89PNG\r\n\x1a\n":
        out.extend(_png_text(b))
    elif re.match(rb"(?i)(from|to|subject|message-id|mime-version|received|return-path|date):", b[:40]):
        try:
            msg = email.message_from_bytes(b, policy=email.policy.compat32)
            for part in msg.walk():
                if part.is_multipart():
                    continue
                pl = part.get_payload(decode=True)
                if pl:
                    out.append(pl)
        except Exception:
            pass
    return out


def _stem(base):
    return base.rsplit(".", 1)[0] if "." in base[1:] else base


def chain(data):
    """[(full member path, basename, stem)] of the one execution chain, or None."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = [i for i in z.infolist() if not i.is_dir()]
    except Exception:
        return None
    if not 2 <= len(infos) <= MAX_MEMBERS:
        return None
    names = [i.filename for i in infos]
    if len(set(names)) != len(names):
        return None
    bases = [n.rsplit("/", 1)[-1] for n in names]
    stems = [_stem(b) for b in bases]
    if len(set(stems)) != len(stems) or any(len(s) < 3 for s in stems):
        return None
    pats = []
    for b, s in zip(bases, stems):
        alts = sorted({re.escape(b), re.escape(s)}, key=len, reverse=True)
        pats.append(re.compile(rb"(?<![A-Za-z0-9_-])(?:" + "|".join(alts).encode() + rb")(?![A-Za-z0-9_-])"))
    out = {}
    for idx, inf in enumerate(infos):
        if inf.file_size > MAX_BYTES:
            return None
        try:
            b = z.read(inf)
        except Exception:
            return None
        texts = _texts(b)
        hits = set()
        for j, p in enumerate(pats):
            if j != idx and any(p.search(t) for t in texts):
                hits.add(j)
        out[idx] = hits
    indeg = {i: 0 for i in range(len(infos))}
    for i, hs in out.items():
        for j in hs:
            indeg[j] += 1
    chains = []
    for s in (i for i in indeg if indeg[i] == 0):
        walk, cur, ok = [s], s, True
        while out[cur]:
            if len(out[cur]) != 1:
                ok = False
                break
            nxt = next(iter(out[cur]))
            if nxt in walk:
                ok = False
                break
            walk.append(nxt)
            cur = nxt
        if ok and len(walk) >= 2:
            chains.append(walk)
    if len(chains) != 1:
        return None
    return [(names[i], bases[i], stems[i]) for i in chains[0]]


def _dump(xs):
    return json.dumps(xs, separators=(",", ":"))


def answer(key, q, name, data, labels):
    """(value, why): an unsure candidates pick (never plain), or (None, why)."""
    if route(key) is None:
        return None, "not a graph property this module reads"
    fmt = q.get("answer_format") or {}
    kind = fmt.get("kind") if isinstance(fmt, dict) else None
    if kind not in (None, "json", "exact_text", "text"):
        return None, f"a graph chain asked as {kind}"
    if data is None or bytes(data[:2]) != b"PK":
        return None, "the target is not a zip"
    c = chain(data)
    if not c:
        return None, "no single execution chain (a fork, a cycle, or none)"
    opts = []
    seen = set()
    for hyp, xs in (("stems_chain", [s for _, _, s in c]),
                    ("basenames_chain", [b for _, b, _ in c]),
                    ("paths_chain", [n for n, _, _ in c]),
                    ("stems_chain_without_terminal", [s for _, _, s in c[:-1]]),
                    ("stems_chain_without_start", [s for _, _, s in c[1:]])):
        v = _dump(xs)
        if v not in seen:
            seen.add(v)
            opts.append((hyp, v))
    return labels.candidates(KEY, opts), "unsure: an execution-chain rendering is a candidate until judged"


def covered(key=None, q=None):
    """A graph chain is never plain (a candidate pick), so this always reports why not."""
    return "an execution-chain artifact-id list is a candidate pick, never plain"
