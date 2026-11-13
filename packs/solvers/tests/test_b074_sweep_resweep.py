"""B-074: the sweep's harvest + recursive re-sweep (ctf/sweep.py).

A pulled challenge ships an encrypted archive whose password is written in a sibling note. The first
unpack leaves the member locked; the sweep then harvests the password from the corpus, adds it to the
store, and unpacks again so the flag inside the archive is found. Built synthetically; nothing runs.
"""
import json

import pytest

from ctf import event, sweep

CSCTF = event.load("csctf")


@pytest.fixture(autouse=True)
def _workdir(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    yield


def _aes_zip_bytes(password, member="flag.txt", content=b"CSCTF{harvested_from_the_note}"):
    pyzipper = pytest.importorskip("pyzipper")
    import io
    bio = io.BytesIO()
    with pyzipper.AESZipFile(bio, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr(member, content)
    return bio.getvalue()


def _pulled(tmp_path, files, description="Find the flag. Flag format: CSCTF{...}", cid=9082):
    ch = tmp_path / "wd" / f"{cid}-x"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps(
        {"id": cid, "name": "x", "category": "Forensics", "description": description}))
    for name, data in files.items():
        (ch / "files" / name).write_bytes(data)
    return ch


def test_sibling_password_is_harvested_and_the_locked_flag_is_swept(tmp_path):
    ch = _pulled(tmp_path, {
        "secret.zip": _aes_zip_bytes("Octopus2024"),
        "note.txt": b"The curator left a note: the archive password is Octopus2024.\n",
    })
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "solved"
    assert rep.result.flags == ("CSCTF{harvested_from_the_note}",)
    assert any("harvested" in n and "re-swept" in n for n in rep.notes)


def test_overlay_password_on_the_archive_itself_is_harvested(tmp_path):
    # the password is appended after the zip's own end, not in a sibling
    ch = _pulled(tmp_path, {
        "handout.zip": _aes_zip_bytes("Trailing_Pw_9") + b"\npassword: Trailing_Pw_9\n",
    })
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "solved"
    assert rep.result.flags == ("CSCTF{harvested_from_the_note}",)


def test_no_locked_archive_means_no_harvest_and_no_resweep(tmp_path):
    # a plain handout: the harvest/re-sweep branch must stay out of the way entirely
    ch = _pulled(tmp_path, {"a.txt": b"nothing secret here, pid 4242"})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "none"
    assert not any("harvested" in n for n in rep.notes)


def test_locked_but_no_harvestable_password_stays_unsolved(tmp_path):
    # the password appears nowhere in the corpus: the sweep must not invent it
    ch = _pulled(tmp_path, {
        "secret.zip": _aes_zip_bytes("UnguessablePasswordNotWrittenAnywhere"),
        "readme.txt": b"good luck cracking this one\n",
    })
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "none"
    assert any("no known archive password opens" in n for n in rep.notes)
