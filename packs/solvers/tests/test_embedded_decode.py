"""embedded_decode: find+decode encoded blobs embedded inside mixed text."""
from __future__ import annotations

import base64

import pytest

import embedded_decode as ed


def test_base64_flag_in_html_comment():
    flag = b"CSCTF{base64_in_a_comment}"
    blob = base64.b64encode(flag).decode()
    page = f"<html><body><!-- note: {blob} --><p>hello world nothing to see</p></body></html>"
    res = ed.find_blobs(page)
    assert any(r["decoded"] == flag and r["encoding"] == "base64" and r["flag"] for r in res)
    assert res[0]["flag"]  # flag-shaped hit ranks first


def test_hex_blob_in_log():
    flag = b"FLAG{hex_embedded_here}"
    log = f"2023-06-01 INFO token={flag.hex()} user=admin done"
    assert flag in ed.flags_in(log)


def test_base32_blob():
    flag = b"CSCTF{base32_works_too}"
    blob = base64.b32encode(flag).decode()
    text = f"config value = {blob} ; end"
    assert flag in ed.flags_in(text)



def test_printable_filter_drops_random_noise():
    # a base64-looking run that decodes to binary noise is dropped (not printable, not a flag)
    noise = base64.b64encode(bytes(range(40))).decode()
    text = f"xx {noise} yy"
    res = ed.find_blobs(text, min_printable=0.9)
    assert all(not r["flag"] for r in res)  # no flag; binary blob filtered by printability


def test_fail_closed():
    assert ed.find_blobs("") == []
    assert ed.find_blobs(12345) == []
    assert ed.flags_in("no encoded blobs here just words") == []


def test_cli(tmp_path, capsys):
    flag = b"CSCTF{cli_embedded}"
    blob = base64.b64encode(flag).decode()
    f = tmp_path / "page.html"
    f.write_text(f"<div data-x='{blob}'>content</div>")
    rc = ed.main([str(f), "--flags-only", "--json"])
    assert rc == 0
    import json
    assert flag.decode() in json.loads(capsys.readouterr().out)
    assert ed.main([str(tmp_path / "nope")]) == 1
    assert ed.main(["--help"]) == 0
