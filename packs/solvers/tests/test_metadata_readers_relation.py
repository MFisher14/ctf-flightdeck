"""B-240 carry: solvers/metadata-forensics/readers_relation.py (the Day 30 identical-content groups reader).

Zips are built here with zipfile; the expected groups are computed by hand from the bytes written.
"""
import io
import json
import struct
import zipfile

import labels
import readers_relation as R

JUDGED = "Determine relation.identical_sha256_groups for cluster-001.zip."
Q_JSON = {"question": JUDGED, "answer_format": {"kind": "json"}}


def _zip(entries, *, encrypted=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    out = bytearray(buf.getvalue())
    for name in encrypted:              # set the encrypted bit in the entry's central-directory header (offset 8)
        at = out.find(b"PK\x01\x02")
        while at >= 0:
            n = struct.unpack_from("<H", out, at + 28)[0]
            if out[at + 46:at + 46 + n] == name.encode():
                out[at + 8] |= 0x1
                break
            at = out.find(b"PK\x01\x02", at + 4)
    return bytes(out)


# shuffled on purpose: first-seen order differs from the sorted rendering
ENTRIES = [("artifacts/zeta.txt", b"two"), ("artifacts/beta.txt", b"one"), ("artifacts/solo.ps1", b"alone"),
           ("artifacts/alpha.txt", b"one"), ("artifacts/delta.json", b"two")]


def _opts(v):
    assert labels.is_unsure(v), v
    return [o for _n, o in labels.parse(v).options]


def test_route_knows_its_properties_and_nothing_else():
    assert R.route("relation_identical_sha256_groups") == ("groups", "sha256")
    assert R.route("relation.identical-md5-groups") == ("forecast", "relation_identical_md5_groups")
    assert R.route("relation_duplicate_member_count") == ("count", "sha256", "member")
    assert R.route("relation_identical_crc32_clusters") == ("groups", "crc32")
    assert R.route("file_size") is None and R.route("") is None


def test_groups_are_shared_digests_of_two_or_more_in_first_seen_order():
    members, why = R.read_members(_zip(ENTRIES))
    assert why is None and [n for n, _ in members] == [n for n, _ in ENTRIES]
    gs = R.groups_of(members)
    assert [names for _h, names, _d in gs] == [["artifacts/zeta.txt", "artifacts/delta.json"],
                                               ["artifacts/beta.txt", "artifacts/alpha.txt"]]
    assert json.loads(R.canonical(gs)) == [["alpha", "beta"], ["delta", "zeta"]]


def test_judged_question_gets_the_canonical_rendering_plain():
    value, why = R.answer("relation_identical_sha256_groups", Q_JSON, "cluster-001.zip", _zip(ENTRIES), labels)
    assert why is None
    assert value == R.canonical(R.groups_of(R.read_members(_zip(ENTRIES))[0]))
    assert json.loads(value) == [["alpha", "beta"], ["delta", "zeta"]]


def test_reworded_question_or_other_file_is_unsure_with_canonical_first():
    data = _zip(ENTRIES)
    q = {"question": "List groups of identical files in cluster-001.zip.", "answer_format": {"kind": "json"}}
    v, why = R.answer("relation_identical_sha256_groups", q, "cluster-001.zip", data, labels)
    assert why == "the question is not the judged wording"
    assert json.loads(_opts(v)[0]) == [["alpha", "beta"], ["delta", "zeta"]]
    v, why = R.answer("relation_identical_sha256_groups", Q_JSON, "cluster-002.zip", data, labels)
    assert "the target is 'cluster-002.zip'" in why and labels.is_unsure(v)


def test_member_outside_the_judged_parent_is_never_plain():
    data = _zip([("other/a.txt", b"x"), ("other/b.txt", b"x")])
    v, why = R.answer("relation_identical_sha256_groups", Q_JSON, "cluster-001.zip", data, labels)
    assert "not directly under artifacts/" in why
    assert json.loads(_opts(v)[0]) == [["a", "b"]]


def test_no_shared_content_is_an_unsure_empty_array():
    data = _zip([("artifacts/a.txt", b"1"), ("artifacts/b.txt", b"2")])
    v, why = R.answer("relation_identical_sha256_groups", Q_JSON, "cluster-001.zip", data, labels)
    assert why == "no two members share content" and _opts(v) == ["[]"]


def test_counts_are_unsure_candidates_led_by_the_noun_asked():
    data = _zip(ENTRIES)
    v, _ = R.answer("relation_duplicate_member_count", {"question": "?"}, "cluster-001.zip", data, labels)
    assert _opts(v) == ["4", "2", "2", "3"]          # grouped members first, then groups, copies, distinct
    v, _ = R.answer("relation_duplicate_group_count", {"question": "?"}, "cluster-001.zip", data, labels)
    assert _opts(v)[0] == "2"


def test_unreadable_containers_decline_with_a_reason():
    assert R.read_members(b"not a zip") == (None, "the target is not a zip")
    enc = _zip([("artifacts/a.txt", b"1"), ("artifacts/b.txt", b"1")], encrypted={"artifacts/b.txt"})
    assert R.read_members(enc) == (None, "entry 'artifacts/b.txt' is encrypted")
    v, why = R.answer("relation_identical_sha256_groups", Q_JSON, "cluster-001.zip", enc, labels)
    assert v is None and "encrypted" in why
    v, why = R.answer("relation_identical_sha256_groups", {"question": JUDGED, "answer_format": {"kind": "integer"}},
                      "cluster-001.zip", _zip(ENTRIES), labels)
    assert v is None and why == "groups asked as integer"
