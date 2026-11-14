"""Published bank record samples plus independently totaled complete fixtures."""
import random

import pytest

from fin2_bai2 import BAI2Error, main, parse_bai2


def fixture():
    # Westpac published 03/88, 16/88 examples. Trailers manually totaled:
    # 300000 -100000 +765000 +9760000 +503333 +631500 +90000 =11949833.
    return "\n".join([
        "01,WPACAU2DK,WIBSCUST,060302,1301,01,080,,2/",
        "02,WIBSCUST,WPACAU2DK,1,060302,,AUD,2/",
        "03,032000000007,AUD,010,300000,,,015,-100000,,,045,765000,,,/",
        "88,100,9760000,1,,400,503333,2,/",
        "16,175,631500,Z,0003930045232,0013256202/",
        "88,YOUR REF=0013256202",
        "16,698,90000,Z,0000050000,/",
        "88,CSCTF{bai_narrative}, customer / reference",
        "49,11949833,7/",
        "98,11949833,1,9/",
        "99,11949833,1,11/",
    ])


def test_published_records_and_manual_control_oracle():
    result = parse_bai2(fixture().encode())
    assert result["valid"]
    assert result["computed_total"] == 11949833
    account = result["groups"][0]["accounts"][0]
    assert account["account"] == "032000000007"
    assert [s["amount"] for s in account["summaries"]] == [300000, -100000, 765000, 9760000, 503333]
    assert account["transactions"][0]["text"] == "YOUR REF=0013256202"
    assert account["transactions"][1]["text"] == "CSCTF{bai_narrative}, customer / reference"
    assert result["flags"] == ["CSCTF{bai_narrative}"]


def test_funds_s_v_d_not_double_counted():
    text = "\n".join([
        "01,BANK,CLIENT,261106,1300,1,,,2/",
        "02,CLIENT,BANK,1,261106,,USD,2/",
        "03,123,,010,1000,,S,100,200,700,015,500,,V,261106,1200/",
        "16,195,200,D,2,0,100,1,100,bank,cust,memo/",
        "49,1700,3/", "98,1700,1,5/", "99,1700,1,7/",
    ])
    result = parse_bai2(text)
    assert result["valid"]
    account = result["groups"][0]["accounts"][0]
    assert account["currency"] == "USD"
    assert account["summaries"][0]["funds"]["availability"] == [100, 200, 700]
    assert account["summaries"][1]["funds"]["value_date"] == "261106"
    assert account["transactions"][0]["funds"]["distributions"] == [{"days": 0, "amount": 100}, {"days": 1, "amount": 100}]
    assert result["computed_total"] == 1700


def test_continuation_in_middle_of_numeric_fields():
    source = fixture().replace("03,032000000007,AUD,010,300000,,,015,-100000,,,045,765000,,,/",
                               "03,032000000007,AUD,010,300000/\n88,,,015,-100000,,,045,765000,,,/")
    # One additional physical record changes all enclosing record counts.
    source = source.replace("49,11949833,7/", "49,11949833,8/").replace("98,11949833,1,9/", "98,11949833,1,10/").replace("99,11949833,1,11/", "99,11949833,1,12/")
    assert parse_bai2(source)["valid"]


def test_gs_published_sample_reports_bad_trailers():
    # https://developer.gs.com/docs/services/transaction-banking/bai-file/
    # Published sample is illustrative, not an internally consistent whole file.
    text = "\n".join([
        "01,GSBI,ABC,200331,2300,1,,,2/",
        "02,test,026015079,1,230906,2000,,/",
        "03,123456,USD,010,10000,,,/",
        "16,495,1000,,I1220012,endtoendID,To: Payee account, Account: XXXXX-4454/",
        "88,CREF: 9f4396bd-8c47-4893-8682-bd8ff006d140",
        "49,11000,2/", "98,12000,2,5/", "99,22000,2,10/",
    ])
    result = parse_bai2(text)
    assert not result["valid"]
    assert result["computed_total"] == 11000
    assert any(i["check"] == "account record count" and i["expected"] == 4 for i in result["issues"])


def test_flag_split_across_text_continuation():
    text = fixture().replace("88,CSCTF{bai_narrative}, customer / reference", "88,CSCTF{bai_\n88,narrative}, customer / reference")
    text = text.replace("49,11949833,7/", "49,11949833,8/").replace("98,11949833,1,9/", "98,11949833,1,10/").replace("99,11949833,1,11/", "99,11949833,1,12/")
    result = parse_bai2(text)
    assert result["valid"]
    assert result["flags"] == ["CSCTF{bai_narrative}"]


@pytest.mark.parametrize("before,after,issue", [
    ("175,631500", "175,631501", "account total"),
    ("49,11949833,7", "49,11949833,6", "account record count"),
    ("98,11949833,1", "98,11949833,2", "group account count"),
    ("99,11949833,1", "99,11949833,2", "file group count"),
])
def test_tamper_evidence(before, after, issue):
    result = parse_bai2(fixture().replace(before, after))
    assert not result["valid"]
    assert any(i["check"] == issue for i in result["issues"])


@pytest.mark.parametrize("data", [None, 1, {}, b"", "", b"\xff", "88,orphan/", "01,BANK,CLIENT,261132,1200,1,,,2/", "01,BANK,CLIENT,261106,1200,1,,,2/"])
def test_malformed_declared_error(data):
    with pytest.raises(BAI2Error):
        parse_bai2(data)


def test_bad_funds_and_boundaries():
    for replacement in ["16,175,631500,Q,b,c/", "16,175,631500,V,261106/", "16,175,631500,D,99999,b,c/"]:
        text = fixture().replace("16,175,631500,Z,0003930045232,0013256202/", replacement)
        with pytest.raises(BAI2Error):
            parse_bai2(text)
    for text in [fixture() + "\n99,0,0,0/", fixture().replace("49,11949833,7/\n", ""), fixture().replace("88,YOUR REF=0013256202", "01,BANK,CLIENT,261106,1200,1,,,2/")]:
        with pytest.raises(BAI2Error):
            parse_bai2(text)


def test_mutation_contract():
    rng = random.Random(613)
    source = fixture()
    for _ in range(200):
        pos = rng.randrange(len(source))
        data = source[:pos] + rng.choice("09 x,/\xff\x00") + source[pos + 1:]
        try:
            result = parse_bai2(data)
            assert isinstance(result["valid"], bool)
        except BAI2Error:
            pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "bank.bai"
    path.write_text(fixture())
    assert main([str(path)]) == 0
    assert main(["--help"]) == 0
    assert main([]) == 2
    assert main([str(path) + ".missing"]) == 2
