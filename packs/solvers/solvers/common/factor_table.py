#!/usr/bin/env python3
"""Offline FactorDB-style factor table: known factorisations looked up locally, never fetched (B-244).

The table is one SQLite file outside the repo: $CTF_FACTOR_TABLE, else
<realdata>/factor-table/factors.sqlite when it exists (ctf.paths.factor_table_path). It is built
from text dumps the player collected (past challenges, FactorDB exports, known weak keys):

    factor_table.py build OUT.sqlite SRC [SRC ...]   lines "n = p * q", "n: p, q", "n p q", "n,p,q",
                                                     factors may be "p^2", integers decimal or 0x-hex;
                                                     or JSONL {"n": ..., "factors": [...]}; '#' comments
    factor_table.py lookup N [--table T]             the stored factorisation of N, verified
    factor_table.py lookup --pem KEY.pem             the modulus of an RSA public key
    factor_table.py status [--table T]               row counts and the build record

Rules: every row is checked at build time (the factors multiply to n, each above 1) and a row that
fails is rejected and counted, never stored. A lookup re-checks the product before it returns
anything; a stored row whose product is wrong is a corrupt table and raises TableCorrupt (never a
silent miss). Status "FF" means every factor passed a primality test, "CF" that a composite factor
remains. ``shared_factor(n)`` also tries gcd(n, p) against every stored prime: two keys generated
with a shared prime factor through the table even when n itself was never stored.

No network: there is no FactorDB client here, by design (rule: no event infrastructure, and the
public FactorDB is a third-party host). A missing table fails loudly naming CTF_FACTOR_TABLE.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

try:
    from ctf import paths as _paths
except ModuleNotFoundError:                 # a script run: put the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import paths as _paths

MAX_BITS = 1 << 16
MAX_LINE = 1 << 16
SCHEMA_VERSION = 1


class TableMissing(FileNotFoundError):
    """No factor table is configured or the named one does not exist."""


class TableCorrupt(RuntimeError):
    """A stored row does not multiply out to its n."""


@dataclass(frozen=True)
class Entry:
    n: int
    factors: tuple[int, ...]            # with multiplicity, ascending
    status: str                         # "FF" fully factored (all prime) | "CF" composite factor left
    source: str
    how: str = "table"                  # "table" (n stored) | "shared-prime" (gcd with a stored prime)


def _int(text: str) -> int:
    t = text.strip().replace("_", "")
    if not t:
        raise ValueError("empty integer")
    v = int(t, 16) if t.lower().startswith("0x") else int(t, 10)
    if v.bit_length() > MAX_BITS:
        raise ValueError(f"integer over {MAX_BITS} bits")
    return v


def _is_prime(v: int) -> bool:
    import sympy
    return bool(sympy.isprime(v))


_TOKEN = re.compile(r"(0[xX][0-9a-fA-F_]+|\d[\d_]*)(?:\s*\^\s*(\d+))?")


def parse_line(line: str) -> tuple[int, tuple[int, ...]] | None:
    """(n, factors with multiplicity) from one text line, or None for a blank / comment line.
    Raises ValueError for a line that names fewer than two numbers or a malformed one."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if len(line) > MAX_LINE:
        raise ValueError("line too long")
    if line.startswith("{"):
        obj = json.loads(line)
        if not isinstance(obj, dict) or "n" not in obj or not isinstance(obj.get("factors"), list):
            raise ValueError("JSON row needs n and a factors list")
        n = _int(str(obj["n"]))
        factors = tuple(_int(str(f)) for f in obj["factors"])
    else:
        if re.search(r"[^\s=:,*;]", _TOKEN.sub("", line)):
            raise ValueError("unexpected characters")
        toks = list(_TOKEN.finditer(line))
        if len(toks) < 2 or toks[0].group(2):
            raise ValueError("a row needs n and at least one factor")
        n = _int(toks[0].group(1))
        factors = []
        for tok in toks[1:]:
            base, exp = _int(tok.group(1)), int(tok.group(2) or 1)
            if not 1 <= exp <= 4096:
                raise ValueError("exponent out of range")
            factors += [base] * exp
        factors = tuple(factors)
    return n, factors


def _check(n: int, factors: tuple[int, ...]) -> str | None:
    """None when the factorisation is sound, else why not."""
    if n < 4:
        return "n below 4"
    if not factors or any(f <= 1 for f in factors):
        return "a factor at or below 1"
    if len(factors) == 1:
        return "a single factor is not a factorisation"
    if math.prod(factors) != n:
        return "factors do not multiply to n"
    return None


def _key(v: int) -> str:
    return format(v, "x")


def build(out: Path, sources: list[Path], *, source_name: str | None = None) -> dict:
    """Create or extend the table at `out` from text/JSONL dumps. Returns counts. Rejected rows are
    counted with their line numbers (first 20), never stored."""
    out = Path(out)
    db = sqlite3.connect(out)
    try:
        db.executescript(
            "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);"
            "CREATE TABLE IF NOT EXISTS factors(n TEXT PRIMARY KEY, bits INTEGER, factors TEXT,"
            " status TEXT, source TEXT);"
            "CREATE TABLE IF NOT EXISTS primes(p TEXT PRIMARY KEY, bits INTEGER);")
        db.execute("INSERT OR REPLACE INTO meta VALUES('schema', ?)", (str(SCHEMA_VERSION),))
        added = dup = 0
        rejected: list[str] = []
        rejected_count = 0
        for src in sources:
            src = Path(src)
            label = source_name or src.name
            with src.open("r", encoding="utf-8", errors="strict") as fh:
                for lineno, line in enumerate(fh, 1):
                    try:
                        row = parse_line(line)
                    except (ValueError, json.JSONDecodeError) as exc:
                        rejected_count += 1
                        if len(rejected) < 20:
                            rejected.append(f"{src.name}:{lineno}: {exc}")
                        continue
                    if row is None:
                        continue
                    n, factors = row
                    why = _check(n, factors)
                    if why:
                        rejected_count += 1
                        if len(rejected) < 20:
                            rejected.append(f"{src.name}:{lineno}: {why}")
                        continue
                    factors = tuple(sorted(factors))
                    primes = [f for f in set(factors) if _is_prime(f)]
                    status = "FF" if len(primes) == len(set(factors)) else "CF"
                    cur = db.execute("INSERT OR IGNORE INTO factors VALUES(?,?,?,?,?)",
                                     (_key(n), n.bit_length(), ",".join(_key(f) for f in factors),
                                      status, label))
                    if cur.rowcount:
                        added += 1
                    else:
                        dup += 1
                    db.executemany("INSERT OR IGNORE INTO primes VALUES(?,?)",
                                   [(_key(p), p.bit_length()) for p in primes])
        db.commit()
        total = db.execute("SELECT COUNT(*) FROM factors").fetchone()[0]
        nprimes = db.execute("SELECT COUNT(*) FROM primes").fetchone()[0]
    finally:
        db.close()
    return {"added": added, "duplicates": dup, "rejected": rejected_count, "rejected_first": rejected,
            "rows": total, "primes": nprimes, "table": str(out)}


def resolve_table(table: str | Path | None = None) -> Path:
    """The table to read: `table` when given, else ctf.paths.factor_table_path(). Raises TableMissing
    naming CTF_FACTOR_TABLE when there is none."""
    if table is not None:
        p = Path(table)
        if not p.is_file():
            raise TableMissing(f"factor table not found at {p}")
        return p
    try:
        p = _paths.factor_table_path()
    except FileNotFoundError as exc:
        raise TableMissing(str(exc)) from exc
    if p is None:
        raise TableMissing("no offline factor table configured: set CTF_FACTOR_TABLE to a table built "
                           "with `factor_table.py build` (or put one at <realdata>/factor-table/"
                           "factors.sqlite); it lives outside the repo")
    return p


class FactorTable:
    """Read-only access to a built table."""

    def __init__(self, table: str | Path | None = None):
        self.path = resolve_table(table)
        # read-only URI; the path is percent-quoted so a "?" or "#" in a folder name is not a URI part
        self._db = sqlite3.connect(f"file:{urllib.parse.quote(str(self.path))}?mode=ro", uri=True)
        try:
            row = self._db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        except sqlite3.DatabaseError as exc:
            self._db.close()
            raise TableCorrupt(f"{self.path} is not a factor table ({exc})") from exc
        if row is None or row[0] != str(SCHEMA_VERSION):
            self._db.close()
            raise TableCorrupt(f"{self.path}: schema {row[0] if row else None!r}, expected {SCHEMA_VERSION}")

    def close(self) -> None:
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def lookup(self, n: int) -> Entry | None:
        """The stored factorisation of n, re-verified, or None when n is not stored."""
        if not isinstance(n, int) or n < 4:
            raise ValueError("n must be an integer of at least 4")
        row = self._db.execute("SELECT factors, status, source FROM factors WHERE n=?", (_key(n),)).fetchone()
        if row is None:
            return None
        try:
            factors = tuple(int(f, 16) for f in row[0].split(","))
        except (AttributeError, ValueError):
            raise TableCorrupt(f"{self.path}: stored row for n={_key(n)[:24]}... is not hex factors") from None
        why = _check(n, factors)
        if why:
            raise TableCorrupt(f"{self.path}: stored row for n={_key(n)[:24]}... is wrong ({why})")
        return Entry(n, factors, row[1], row[2])

    def shared_factor(self, n: int, *, max_primes: int = 5_000_000) -> Entry | None:
        """A stored prime p with 1 < gcd(n, p) i.e. p | n: (p, n/p), verified. Scans at most
        `max_primes` stored primes of at most n's size."""
        if not isinstance(n, int) or n < 4:
            raise ValueError("n must be an integer of at least 4")
        cur = self._db.execute("SELECT p FROM primes WHERE bits < ? LIMIT ?", (n.bit_length(), max_primes))
        for (hx,) in cur:
            p = int(hx, 16)
            if p > 1 and n % p == 0 and p < n:
                q = n // p
                status = "FF" if _is_prime(q) else "CF"
                return Entry(n, tuple(sorted((p, q))), status, "shared prime", how="shared-prime")
        return None

    def find(self, n: int) -> Entry | None:
        """lookup, then shared_factor."""
        return self.lookup(n) or self.shared_factor(n)

    def status(self) -> dict:
        rows = self._db.execute("SELECT COUNT(*), SUM(status='FF') FROM factors").fetchone()
        nprimes = self._db.execute("SELECT COUNT(*) FROM primes").fetchone()[0]
        return {"table": str(self.path), "rows": rows[0], "fully_factored": rows[1] or 0, "primes": nprimes}


def modulus_from_pem(path: Path) -> int:
    from Crypto.PublicKey import RSA
    data = Path(path).read_bytes()
    if len(data) > 1 << 20:
        raise ValueError("key file over 1 MiB")
    return int(RSA.import_key(data).n)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="factor_table.py", description="offline FactorDB-style factor table")
    sub = parser.add_subparsers(dest="op", required=True)
    b = sub.add_parser("build")
    b.add_argument("out")
    b.add_argument("sources", nargs="+")
    b.add_argument("--source-name")
    lk = sub.add_parser("lookup")
    lk.add_argument("n", nargs="?")
    lk.add_argument("--pem")
    lk.add_argument("--table")
    st = sub.add_parser("status")
    st.add_argument("--table")
    try:
        args = parser.parse_args(argv)
        if args.op == "build":
            print(json.dumps(build(Path(args.out), [Path(s) for s in args.sources],
                                   source_name=args.source_name), sort_keys=True))
            return 0
        with FactorTable(args.table) as table:
            if args.op == "status":
                print(json.dumps(table.status(), sort_keys=True))
                return 0
            if (args.n is None) == (args.pem is None):
                raise ValueError("lookup takes N or --pem, exactly one")
            n = modulus_from_pem(Path(args.pem)) if args.pem else _int(args.n)
            entry = table.find(n)
            if entry is None:
                print(json.dumps({"found": False, "bits": n.bit_length()}))
                return 1
            print(json.dumps({"found": True, "how": entry.how, "status": entry.status, "source": entry.source,
                              "factors": [str(f) for f in entry.factors], "verified": True}, sort_keys=True))
            return 0
    except TableMissing as exc:
        print(f"factor_table: {exc}", file=sys.stderr)
        return 3
    except TableCorrupt as exc:
        print(f"factor_table: corrupt table: {exc}", file=sys.stderr)
        return 4
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"factor_table: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
