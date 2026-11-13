"""linefilter: the Extraction 1/2 "find the odd line out" helper."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solvers" / "toolkits"))
import linefilter  # noqa: E402


def test_not_matching_extraction1(tmp_path):
    # Extraction 1: every normal line fits ^[A-Z]{4}[a-z]{6}\d[A-Z]\d{2}[a-zA-Z]{6}$ ; the flag line
    # does not.
    pat = r"^[A-Z]{4}[a-z]{6}\d[A-Z]\d{2}[a-zA-Z]{6}$"
    good = ["ABCDabcdef1A23abcDEF", "WXYZqwerty9Z88mnoPQR"]
    bad = "CSCTF{extraction_one}"
    lines = [good[0], bad, good[1]]
    odd = linefilter.not_matching(lines, pat)
    assert odd == [bad]


def test_odd_one_out_non_md5(tmp_path):
    # Extraction 2: 32-hex-char md5 lines, one odd line that is not an md5.
    md5s = ["d41d8cd98f00b204e9800998ecf8427e",
            "0cc175b9c0f1b6a831c399e269772661",
            "900150983cd24fb0d6963f7d28e17f72",
            "f96b697d7cb7938d525a2f31aaf161d0"]
    odd_line = "CSCTF{n0t_an_md5_here}"
    lines = md5s[:2] + [odd_line] + md5s[2:]
    odd, common = linefilter.odd_one_out(lines)
    assert odd == [odd_line]


def test_shape_signature():
    assert linefilter.shape("ABCD") == "U{4}"
    assert linefilter.shape("abc123") == "L{3}d{3}"
    assert linefilter.shape("d41d8cd9") == "L{1}d{2}L{1}d{1}L{2}d{1}"  # hex folds into L/d runs


def test_flags_extracted():
    lines = ["nothing here", "prefix CSCTF{abc_123} suffix", "more"]
    assert linefilter.flags(lines) == ["CSCTF{abc_123}"]


def test_matching_grep_mode():
    lines = ["AAAA", "bbbb", "CCCC"]
    assert linefilter.matching(lines, r"^[A-Z]+$") == ["AAAA", "CCCC"]


def test_odd_one_out_by_length_fallback():
    # shapes all distinct but lengths cluster -> length-based outlier
    lines = ["aaaaa", "bbbbb", "ccccc", "dd"]
    odd, common = linefilter.odd_one_out(lines)
    assert odd == ["dd"]


def test_report_auto(tmp_path):
    f = tmp_path / "ex.txt"
    f.write_text("d41d8cd98f00b204e9800998ecf8427e\n"
                 "0cc175b9c0f1b6a831c399e269772661\n"
                 "CSCTF{report_flag}\n"
                 "900150983cd24fb0d6963f7d28e17f72\n")
    out = linefilter.report(str(f))
    assert "CSCTF{report_flag}" in out
    assert "odd-one-out" in out


def test_report_invert_pattern(tmp_path):
    f = tmp_path / "ex.txt"
    f.write_text("abc123\nCSCTF{keep_me}\ndef456\n")
    out = linefilter.report(str(f), inv_pattern=r"^[a-z]{3}\d{3}$")
    assert "CSCTF{keep_me}" in out
