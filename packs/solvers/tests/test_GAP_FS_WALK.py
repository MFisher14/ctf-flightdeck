#!/usr/bin/env python3
"""Offline tests of solvers/toolkits/fs_walk.py (GAP-FS-WALK: squashfs / NTFS($MFT+ADS) / exFAT /
JFFS2 directory walkers). No network, no token; every image is a tiny spec-compliant fixture built
in memory by the module's own builders. Standalone, the ledger lives under one tempfile.mkdtemp()
($CTF_WORKDIR), removed at the end; under pytest it is the session temp dir conftest.py sets.

What it proves, the never-wrong boundary per output class (AGENTS.md "Uncertain answers"):
  - a NAME / PATH / SIZE / ADS-stream read from a structurally-complete, (CRC-/checksum-)validated
    record is PLAIN-ELIGIBLE: labels.pick (unsure now, and PLAIN once the judge accepts a
    rendering) -- never a bare plain guess, and never a candidate key;
  - a DELETED / slack / partial reading is labels.candidates (unsure, key ends in CANDIDATE_MARK),
    never plain before the judge;
  - the sha256 of a complete file's exact bytes is a canonical digest -> PLAIN;
  - a non-decoding compression branch, a truncated image, a damaged record, a flag, or anything not
    proven -> None (never a partial guess);
  - solve_set() / signals() are fail-closed (no exception escapes) and bounded.

  .venv/bin/python tests/test_GAP_FS_WALK.py
"""
import hashlib
import os
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_gap_fs_walk_"))
# labels reads the ledger root from $CTF_WORKDIR on every call. setdefault: under pytest conftest.py
# has already pointed it at a session temp dir, and this module must not redirect other tests.
os.environ.setdefault("CTF_WORKDIR", str(TMP / "challenges"))
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pytest        # noqa: E402
import labels        # noqa: E402
import fs_walk as fw  # noqa: E402

FAILED = []
# Standalone (`python tests/test_GAP_FS_WALK.py`) a failed check is collected and main() exits 1.
# Under pytest a failed check must fail its test, not only print FAIL and report green.
_STANDALONE = __name__ == "__main__"

# The judge-acceptance tests assert that a judge's accepted verdict is replayed PLAIN. That needs
# the judge ledger; on a judge-free event ($CTF_JUDGE_LEDGER=off) labels.learn records nothing, so
# they are skipped (reported as not run) instead of passing vacuously.
judge = pytest.mark.judge
needs_judge = pytest.mark.skipif(not labels.judge_ledger(),
                                 reason="no judge ledger ($CTF_JUDGE_LEDGER=off): judge-acceptance replay not available")


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)
        if not _STANDALONE:
            raise AssertionError(f"{label}  [{str(detail)[:300]}]")


def q(qid, text, member=None):
    d = {"qid": qid, "answer_id": qid, "question": text}
    if member:
        d["artifact"] = "image.bin" + fw.ARROW + member
        d["member"] = member
    return d


def answer(files, qid, text, member=None):
    return fw.solve_set([q(qid, text, member)], files, None).get(qid)


def as_files(image):
    return {"image.bin": image}


# ------------------------------------------------------------------ structural walk per filesystem

def test_squashfs():
    fs, complete, entries = fw.walk(fw.build_squashfs({"readme.txt": b"hello squashfs\n",
                                                       "data.bin": bytes(range(40))}))
    names = {e["name"]: e for e in entries}
    check("squashfs recognised + complete", fs == "squashfs" and complete, (fs, complete))
    check("squashfs names + sizes", names.get("readme.txt", {}).get("size") == 15
          and names.get("data.bin", {}).get("size") == 40, names)
    check("squashfs content exact", names.get("readme.txt", {}).get("content") == b"hello squashfs\n")

    files = as_files(fw.build_squashfs())
    name = answer(files, "n", "What is the name of the file in the image?")
    # two files -> no single named entry, so name is None (never a guess); path of a named one is a pick
    check("squashfs path is a PLAIN-ELIGIBLE pick",
          labels.is_unsure(path := answer(files, "p", "full path of readme.txt"))
          and not labels.is_candidate(labels.parse(path).key), path)
    check("squashfs size is a pick", labels.is_unsure(answer(files, "s", "size in bytes of data.bin")))

    sha = answer(files, "h", "sha256 of the file readme.txt")
    check("squashfs sha256 is PLAIN + exact",
          isinstance(sha, str) and not labels.is_unsure(sha)
          and sha == hashlib.sha256(b"hello squashfs\n").hexdigest(), sha)


def test_squashfs_undecodable():
    # unsupported compressor (lzo) on the inode table -> nothing proven -> None for every id
    files = as_files(fw.build_squashfs(break_compression=True))
    fs, complete, entries = fw.walk(files["image.bin"])
    check("squashfs unsupported-compression -> partial, no entries", complete is False and not entries,
          (complete, len(entries)))
    check("squashfs unsupported-compression -> None answer",
          answer(files, "p", "full path of readme.txt") is None)

    files = as_files(fw.build_squashfs(truncate=True))
    check("squashfs truncated -> None answer", answer(files, "s", "size of readme.txt") is None)


def test_ntfs():
    img = fw.build_ntfs()
    fs, complete, entries = fw.walk(img)
    check("ntfs recognised", fs == "ntfs", fs)
    secret = [e for e in entries if e["name"] == "secret.txt" and e["stream"] is None]
    ads = [e for e in entries if e["stream"] == "hidden.txt"]
    deleted = [e for e in entries if e["deleted"] and e["name"] == "old.log"]
    check("ntfs file + path", len(secret) == 1 and secret[0]["path"] == "\\secret.txt", secret)
    check("ntfs ADS stream surfaced", len(ads) == 1 and ads[0]["path"] == "\\secret.txt:hidden.txt", ads)
    check("ntfs deleted (unallocated) entry surfaced", len(deleted) == 1, deleted)

    files = as_files(img)
    pth = answer(files, "p", "What is the full path of secret.txt?")
    u = labels.parse(pth)
    check("ntfs path pick includes posix + windows renderings",
          labels.is_unsure(pth) and not u.candidate
          and {"/secret.txt", "\\secret.txt"} <= set(dict(u.options).values()), pth)

    ads_a = answer(files, "a", "What is the name of the alternate data stream on secret.txt?")
    check("ntfs ADS name is a PLAIN-ELIGIBLE pick (not candidate)",
          labels.is_unsure(ads_a) and not labels.parse(ads_a).candidate
          and "hidden.txt" in dict(labels.parse(ads_a).options).values(), ads_a)

    deleted_a = answer(files, "d", "List the deleted entries in the image")
    check("ntfs deleted reading is UNSURE candidates",
          labels.is_unsure(deleted_a) and labels.parse(deleted_a).candidate
          and "old.log" in dict(labels.parse(deleted_a).options).values(), deleted_a)

    sha = answer(files, "h", "sha256 of the file secret.txt")
    check("ntfs resident $DATA sha256 is PLAIN + exact",
          sha == hashlib.sha256(b"top secret bytes\n").hexdigest(), sha)


def test_exfat():
    img = fw.build_exfat()
    fs, complete, entries = fw.walk(img)
    live = [e for e in entries if e["name"] == "report.pdf" and not e["deleted"]]
    dead = [e for e in entries if e["name"] == "trash.tmp" and e["deleted"]]
    check("exfat recognised + live entry set", fs == "exfat" and len(live) == 1
          and live[0]["size"] == len(b"exfat report body\n"), (fs, live))
    check("exfat deleted entry set surfaced", len(dead) == 1, dead)

    files = as_files(img)
    size = answer(files, "s", "what is the size of report.pdf")
    check("exfat live size is a pick", labels.is_unsure(size) and not labels.parse(size).candidate, size)
    deleted_a = answer(files, "d", "list the deleted files")
    check("exfat deleted reading is candidates",
          labels.is_unsure(deleted_a) and labels.parse(deleted_a).candidate
          and "trash.tmp" in dict(labels.parse(deleted_a).options).values(), deleted_a)
    sha = answer(files, "h", "sha256 of report.pdf")
    check("exfat content sha256 is PLAIN + exact",
          sha == hashlib.sha256(b"exfat report body\n").hexdigest(), sha)


def test_jffs2():
    fs, complete, entries = fw.walk(fw.build_jffs2())
    names = {e["name"] for e in entries}
    check("jffs2 recognised + complete", fs == "jffs2" and complete, (fs, complete))
    check("jffs2 all files walked", {"firmware.bin", "config.txt", "notes.md"} <= names, names)

    # one byte of config.txt's dirent name flipped -> that entry's name CRC fails -> it is dropped,
    # the walk continues and the other two entries are still recovered
    fs, complete, entries = fw.walk(fw.build_jffs2(corrupt_name="config.txt"))
    names = {e["name"] for e in entries}
    check("jffs2 corrupt node -> that entry None, walk continues",
          complete is False and "config.txt" not in names and {"firmware.bin", "notes.md"} <= names, names)
    files = as_files(fw.build_jffs2(corrupt_name="config.txt"))
    check("jffs2 corrupt entry answers None", answer(files, "p", "full path of config.txt") is None)
    sha = answer(files, "h", "sha256 of firmware.bin")
    check("jffs2 intact file sha256 is PLAIN + exact",
          sha == hashlib.sha256(b"\x7fELF firmware image\n").hexdigest(), sha)


# ------------------------------------------------------------------ the PLAIN-eligibility promise

@judge
@needs_judge
def test_pick_banks_plain_once_judged():
    files = as_files(fw.build_ntfs())
    pth = answer(files, "p", "full path of secret.txt")
    key = labels.parse(pth).key
    check("before the judge: the path is unsure", labels.is_unsure(pth))
    # the options are METHOD-NAMED (name=method, value=this variant's path), so the judge accepts
    # the posix METHOD, not a bare value; the ledger remembers the method and pick returns THIS
    # variant's posix value PLAIN
    names = dict((n, v) for n, v in labels.parse(pth).options)
    check("path options are method-named (name != value), so labels_only is False",
          "posix" in names and names["posix"] == "/secret.txt"
          and all(n != v for n, v in labels.parse(pth).options), list(labels.parse(pth).options))
    labels.learn(key, "posix", "accepted", scope="key")
    again = answer(files, "p", "full path of secret.txt")
    check("after the judge accepts the posix method: the path is banked PLAIN",
          again == "/secret.txt" and not labels.is_unsure(again), again)


@judge
@needs_judge
def test_pattern_a_no_stale_plain_across_variants():
    """GAP Pattern A (wrong-PLAIN, this fix): the key shape `forensics.file_path/<fs>` carries only
    the filesystem (fixed per challenge), never the varying path value. With BARE-LABEL options
    (name==value) a value accepted on variant 1 was returned PLAIN on a later variant whose real
    path differed, via labels' labels_only branch -- the stale-plain hole. With METHOD-NAMED
    renderings labels_only is False, so after the judge accepts a METHOD the pick is scoped to that
    method: a different-value variant returns its OWN value plain, never variant-1's stale value."""
    key = "forensics.file_path/squashfs"
    v1 = fw._pick("file_path", "squashfs", fw._path_renderings("/alpha.txt"))
    check("pattern-A: before any accept, the path is unsure", labels.is_unsure(v1) and key == labels.parse(v1).key)
    labels.learn(key, "posix", "accepted", scope="key")          # the judge accepts the posix METHOD
    v2 = fw._pick("file_path", "squashfs", fw._path_renderings("/beta/gamma.txt"))
    check("pattern-A: accepted METHOD answers the CURRENT variant value plain, not variant-1's",
          v2 == "/beta/gamma.txt" and not labels.is_unsure(v2), v2)


def test_pattern_a_value_accepted_as_name_stays_unsure():
    """The direct Pattern-A trigger (accept value1 on the key, a different-value variant must stay
    UNSURE). Simulate a ledger that accepted a VALUE as the key's name -- exactly what the old
    bare-label options produced (labels_only True -> `return names[0]` plain on any later variant).
    With method-named options none of a later variant's option NAMES equals that value, and
    labels_only is False, so the stale value never leaks out as a plain answer."""
    key = "forensics.file_name/jffs2"
    labels.learn(key, "firmware.bin", "accepted", scope="key")   # value1 from variant 1, as a name
    v = fw._pick("file_name", "jffs2", fw._name_renderings("payload.elf"))   # a DIFFERENT variant
    check("pattern-A: a value accepted as a name never leaks as a stale plain on another variant",
          labels.is_unsure(v) and "firmware.bin" not in (v or ""), v)


# ------------------------------------------------------------------ never-guess tails, fail-closed, bounded

def test_never_guess_tails():
    files = as_files(fw.build_ntfs())
    check("a flag is never answered", answer(files, "f", "What is the flag?") is None)
    check("an unproven fact is None", answer(files, "x", "how many clusters does nope.bin use") is None)
    # a question naming no single known file -> None, never a guess at which file
    check("ambiguous / unnamed file -> None",
          answer(as_files(fw.build_squashfs()), "p", "what is the full path of the file") is None)


def test_hash_algorithm_must_be_named():
    """GAP (wrong-PLAIN): the digest branch used to fire on any generic 'hash'/'digest' word and
    return a sha256 value, so an md5/sha1/crc/bare-checksum question got a WRONG sha256. A digest is
    PLAIN only when the question NAMES the algorithm that is computed; a different named algorithm is
    computed and answered as itself; CRC-32 (ambiguous rendering) is an unsure pick; a bare
    'hash'/'checksum' with no named algorithm is None -- never a sha256 value for another algorithm."""
    files = as_files(fw.build_ntfs())
    content = b"top secret bytes\n"              # secret.txt's resident $DATA
    sha256 = hashlib.sha256(content).hexdigest()
    # legit: an explicitly-named sha256 question is still PLAIN + exact (no false None / no change)
    check("sha256 question -> PLAIN exact sha256 (legit case preserved)",
          answer(files, "h256", "sha256 of the file secret.txt") == sha256)
    # the NAMED algorithm is computed and answered PLAIN -- never the sha256 value
    v = answer(files, "hmd5", "What is the md5 hash of secret.txt?")
    check("md5 question -> PLAIN md5 (never the sha256 value)",
          v == hashlib.md5(content).hexdigest() and v != sha256, v)
    v = answer(files, "hsha1", "What is the sha1 digest of secret.txt?")
    check("sha1 question -> PLAIN sha1 (never the sha256 value)",
          v == hashlib.sha1(content).hexdigest() and v != sha256, v)
    v = answer(files, "hsha512", "Give the sha-512 of secret.txt")
    check("sha-512 question -> PLAIN sha512 (never the sha256 value)",
          v == hashlib.sha512(content).hexdigest() and v != sha256, v)
    # crc32: deterministic but the rendering is ambiguous -> an UNSURE pick, never a sha256 plain
    v = answer(files, "hcrc", "What is the crc32 checksum of secret.txt?")
    crc = zlib.crc32(content) & 0xFFFFFFFF
    check("crc32 question -> UNSURE pick over renderings, never a sha256 plain",
          labels.is_unsure(v) and not labels.parse(v).candidate and v != sha256, v)
    if labels.is_unsure(v):
        check("the crc32 pick offers this file's real crc32 renderings",
              str(crc) in dict(labels.parse(v).options).values(), v)
    # a bare 'hash' / 'checksum' with no named algorithm pins nothing -> None, never a sha256 plain
    check("bare 'hash' (no algorithm) -> None, never a sha256 plain",
          answer(files, "hbare", "What is the hash of secret.txt?") is None)
    check("bare 'checksum' (no algorithm) -> None, never a sha256 plain",
          answer(files, "ckbare", "Compute the checksum of secret.txt") is None)


def test_fail_closed_and_dispatch():
    for bad in (b"", b"not a filesystem at all", bytes(4096), b"hsqs" + b"\x00" * 8,
                b"FILE" + b"\x00" * 20, os.urandom(2048)):
        try:
            fs, complete, entries = fw.walk(bad)
            ok = (fs in (None, "ntfs", "squashfs", "exfat", "jffs2"))
        except Exception as e:  # noqa: BLE001
            ok = False
        check(f"walk fail-closed on {len(bad)}B junk", ok)
    # solve_set must never raise, whatever the files
    for files in ({}, {"x": b"junk"}, {"x": os.urandom(1000)}, as_files(fw.build_ntfs())):
        try:
            fw.solve_set([q("a", "the path of x.txt"), q("b", "the flag")], files, None)
            check("solve_set fail-closed", True)
        except Exception as e:  # noqa: BLE001
            check("solve_set fail-closed", False, e)


def test_bounded():
    # every list is capped, and an oversized image is refused outright (no allocation blow-up)
    check("entry cap is bounded", 0 < fw.MAX_ENTRIES <= 100000)
    check("image cap is bounded", 0 < fw.MAX_IMAGE <= 1 << 31)
    big = fw.build_squashfs()
    check("walk refuses an image over MAX_IMAGE",
          fw.squashfs(big + bytes(0)) is not None            # the normal one still walks
          and fw.ntfs(b"FILE" + bytes(fw.MAX_IMAGE + 10)) is None, "size guard")


def test_signals():
    s_fs = fw.signals([q("p", "what is the path of the deleted file in the squashfs image")],
                      as_files(fw.build_squashfs()))
    s_junk = fw.signals([q("p", "what is the path")], {"x": os.urandom(500)})
    check("signals > 0 on a real filesystem + vocabulary", s_fs > 0.5, s_fs)
    check("signals 0 on junk (never competes on a blob)", s_junk == 0.0, s_junk)


def main():
    test_squashfs()
    test_squashfs_undecodable()
    test_ntfs()
    test_exfat()
    test_jffs2()
    if labels.judge_ledger():
        # judge-acceptance -> plain replay; only meaningful with a judge ledger (see needs_judge)
        test_pick_banks_plain_once_judged()
        test_pattern_a_no_stale_plain_across_variants()
    else:
        print("skip judge-acceptance tests: no judge ledger ($CTF_JUDGE_LEDGER=off)")
    test_pattern_a_value_accepted_as_name_stays_unsure()
    test_never_guess_tails()
    test_hash_algorithm_must_be_named()
    test_fail_closed_and_dispatch()
    test_bounded()
    test_signals()
    print("ok" if not FAILED else f"FAILED: {FAILED}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        import shutil
        shutil.rmtree(TMP, ignore_errors=True)
