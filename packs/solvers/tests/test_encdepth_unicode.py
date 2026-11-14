"""Independent-library and primary-source vectors for Unicode codec hardening."""
import io
import random

import base2048  # PyPI 0.1.3: Rust variant, NOT qntm.
import base65536
import ecoji
import pytest

import encdepth_unicode as subject


def _ecoji_v1(data):
    output = io.StringIO()
    ecoji.encode(io.BytesIO(data), output, wrap=0)
    return output.getvalue()


@pytest.mark.parametrize("size", list(range(34)) + [255, 256, 257, 1024])
def test_roundtrip_against_independent_libraries(size):
    data = random.Random(size + 0xECA).randbytes(size)
    for codec, encoder in (("base2048-rust", base2048.encode),
                           ("base65536", base65536.encode),
                           ("ecoji-v1", _ecoji_v1)):
        encoded = encoder(data)
        assert subject.decode(encoded, codec) == data
        assert subject.decode(encoded.encode(), codec) == data


def test_all_byte_values_and_leading_zeroes_against_libraries():
    data = b"\x00\x00" + bytes(range(256)) * 2 + b"\x00"
    assert subject.decode(base2048.encode(data), "base2048-rust") == data
    assert subject.decode(base65536.encode(data), "base65536") == data
    assert subject.decode(_ecoji_v1(data), "ecoji") == data


def test_qntm_published_readme_vectors():
    # github.com/qntm/base2048 and github.com/qntm/base65536 README vectors.
    assert subject.decode("GƸOʜeҩ", "base2048-qntm") == bytes([1, 2, 4, 8, 16, 32, 64, 128])
    assert subject.decode("驨ꍬ啯𒁷ꍲᕤ", "base65536") == b"hello world"


# The following inclusive Unicode range pairs are primary-spec data, transcribed
# from qntm's src/index.js files, not imported from any local engine/table module:
# https://github.com/qntm/base2048/blob/main/src/index.js
# https://github.com/qntm/base32768/blob/main/src/index.js
_REFERENCE_RANGES = {
    11: (
        '89AZazÆÆÐÐØØÞßææððøøþþĐđĦħııĸĸŁłŊŋŒœŦŧƀƟƢƮƱǃǝǝǤǥǶǷȜȝȠȥȴʯͰͳͶͷͻͽͿͿΑΡΣΩαωϏϏϗϯϳϳϷϸϺϿЂЂЄІЈЋЏИКикяђђєіјћџѵѸҁҊӀӃӏӔӕӘәӠӡӨөӶӷӺԯԱՖաֆאתװײؠءاؿفي٠٩ٮٯٱٴٹڿہہۃےەەۮۼۿۿܐܐܒܯݍޥޱޱ߀ߪࠀࠕࡀࡘࡠࡪࢠࢴࢶࢽऄनपरलळवहऽऽॐॐॠॡ०९ॲঀঅঌএঐওনপরললশহঽঽৎৎৠৡ০ৱ৴৹ৼৼਅਊਏਐਓਨਪਰਲਲਵਵਸਹੜੜ੦੯ੲੴઅઍએઑઓનપરલળવહઽઽૐૐૠૡ૦૯ૹૹଅଌଏଐଓନପରଲଳଵହଽଽୟୡ୦୯ୱ୷ஃஃஅஊஎஐஒஓககஙசஜஜஞடணதநபமஹௐௐ௦௲అఌఎఐఒనపహఽఽౘౚౠౡ౦౯౸౾ಀಀಅಌಎಐಒನಪಳವಹಽಽೞೞೠೡ೦೯ೱೲഅഌഎഐഒഺഽഽൎൎൔൖ൘ൡ൦൸ൺൿඅඖකනඳරලලවෆ෦෯กะาาเๅ๐๙ກຂຄຄງຈຊຊຍຍດທນຟມຣລລວວສຫອະາາຽຽເໄ໐໙ໞໟༀༀ༠༳ཀགངཇཉཌཎདནབམཛཝཨཪཬྈྌကဥဧဪဿ၉ၐၕ',
        '07',
    ),
    15: (
        'ҠҿԀԟڀڿݠޟ߀ߟကဟႠႿᄀᅟᆀᆟᇠሿበቿዠዿጠጿᎠᏟᐠᙟᚠᛟកសᠠᡟᣀᣟᦀᦟ᧠᧿ᨠᨿᯀᯟᰀᰟᴀᴟ⇠⇿⋀⋟⍀⏟␀␟─❟➀➿⠀⥿⦠⦿⨠⩟⪀⪿⫠⭟ⰀⰟⲀⳟⴀⴟⵀⵟ⺠⻟㇀㇟㐀䶟䷀龿ꀀꑿ꒠꒿ꔀꗿꙀꙟꚠꛟ꜀ꝟꞀꞟꡀꡟ',
        'ƀƟɀʟ',
    ),
}


def _reference_qntm_encode(data, width):
    """Independent, deliberately simple bit-string encoder and range lookup."""
    stream = ''.join(format(byte, '08b') for byte in data)
    result = ''
    for offset in range(0, len(stream), width):
        chunk = stream[offset:offset + width]
        is_short = len(chunk) <= width - 8
        ordinal = int(chunk.ljust(width - 8 if is_short else width, '1'), 2)
        pairs = _REFERENCE_RANGES[width][int(is_short)]
        for start, stop in zip(pairs[::2], pairs[1::2]):
            size = ord(stop) - ord(start) + 1
            if ordinal < size:
                result += chr(ord(start) + ordinal)
                break
            ordinal -= size
        else:
            raise AssertionError('reference range table incomplete')
    return result


@pytest.mark.parametrize("codec,width", [("base2048-qntm", 11), ("base32768", 15)])
def test_independent_primary_spec_qntm_encoder(codec, width):
    for size in list(range(46)) + [256, 1024]:
        data = random.Random(size + width).randbytes(size)
        encoded = _reference_qntm_encode(data, width)
        assert subject.decode(encoded, codec) == data
    data = b'\x00\x00' + bytes(range(256))
    assert subject.decode(_reference_qntm_encode(data, width), codec) == data


def test_hand_encoder_matches_published_qntm_vector():
    assert _reference_qntm_encode(bytes([1, 2, 4, 8, 16, 32, 64, 128]), 11) == 'GƸOʜeҩ'


@pytest.mark.parametrize("text,expected", [
    ("👖📸🎈☕", b"abc"),
    ("🎥🤠📠🛼", b"6789"),
    ("🐲👡🪚☕", b"XY\n"),
    ("👖📸🎈☕🎥🤠📠🛼🐲👡🪚☕", b"abc6789XY\n"),
    ("👕☕", b"a"),
    ("👖📲☕", b"ab"),
    ("🎥🤠📠🥷", b"6788"),
    ("🎥🤠📠🛼", b"6789"),
    ("🎥🤠📠📑", b"678:"),
    ("🎥🤠📠🙋", b"678;"),
])
def test_ecoji_v2_published_and_hand_derived_padding_vectors(text, expected):
    # README's abc/6789/XY examples and docs/encoding.md's a/ab examples;
    # 6788..678; differ only in their final two bits, selecting paddingLastV2.
    assert subject.decode(text, "ecoji-v2") == expected
    assert subject.decode(text, "ecoji") == expected


@pytest.mark.parametrize("version", ["ecoji-v1", "ecoji"])
def test_v1_concatenated_records_against_library(version):
    chunks = [b"a", b"bc", b"def", b"ghij", b"klmno", bytes(range(256))]
    encoded = "\r\n".join(_ecoji_v1(chunk) for chunk in chunks)
    assert subject.decode(encoded, version) == b"".join(chunks)


def test_v2_concatenated_short_records():
    assert subject.decode("👕☕👖📲☕👖📸🎈☕🎥🤠📠🥷", "ecoji-v2") == b"aababc6788"


@pytest.mark.parametrize("codec,text", [
    ("base2048-qntm", "7"),  # zero-byte terminal alias of empty input
    ("base2048-qntm", "GƸOʜeҩ7"),
    ("base2048-qntm", "7GƸOʜeҩ"),
    ("base65536", "ᕤ驨"),  # terminal in interior
    ("base65536", "hello"),
    ("ecoji-v1", "👕☕"),
    ("ecoji-v1", "👖📲☕"),
    ("ecoji-v2", "👕☕☕"),  # one pad or a full group, not two pads
    ("ecoji-v2", "👕☕☕👕☕"),
    ("ecoji-v2", "☕☕☕☕"),
    ("ecoji", "👖📸🎦⚜👖📸🎦🥷"),  # mixed v1/v2-only pads
    ("ecoji", "👖📸🎈"),
    ("ecoji", "👖☕"),  # nonzero unused low bits
])
def test_noncanonical_rejected(codec, text):
    with pytest.raises(subject.EncodingError):
        subject.decode(text, codec)


@pytest.mark.parametrize("bad", [None, 123, [], {}, b"\xff", "\ud800"])
def test_bad_types_and_unicode_contract(bad):
    for codec in subject.CODECS:
        with pytest.raises(subject.EncodingError):
            subject.decode(bad, codec)
    assert subject.steps(bad) == []


@pytest.mark.parametrize("insert", [" ", "\t", "\u00a0", "\u200b", "\ufe0f"])
def test_only_crlf_is_transport_wrapping(insert):
    encoded = "GƸOʜeҩ"
    with pytest.raises(subject.EncodingError):
        subject.decode(encoded[:2] + insert + encoded[2:], "base2048-qntm")
    assert subject.decode(encoded[:2] + "\r\n" + encoded[2:], "base2048-qntm") == bytes([1, 2, 4, 8, 16, 32, 64, 128])
    for codec in ("ecoji", "ecoji-v1", "ecoji-v2"):
        with pytest.raises(subject.EncodingError):
            subject.decode("👕" + insert + "☕☕☕", codec)


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "10", None, subject.MAX_OUTPUT + 1])
def test_limit_contract(bad):
    with pytest.raises(subject.EncodingError):
        subject.decode("驨", "base65536", max_bytes=bad)


def test_output_limit_and_registry():
    with pytest.raises(subject.EncodingError):
        subject.decode("驨ꍬ啯𒁷ꍲᕤ", "base65536", max_bytes=10)
    assert ("base65536", b"hello world") in subject.steps("驨ꍬ啯𒁷ꍲᕤ")
    assert subject.steps("ordinary plain words") == []
    assert subject.steps(b"CSCTF{test}") == []
    for codec in subject.CODECS:
        assert subject.decode("", codec) == b""


def test_cli_guard_and_file_errors(tmp_path):
    assert subject.main(["--help"]) == 0
    assert subject.main(["unknown"]) == 2
    assert subject.main(["base65536", str(tmp_path / "missing")]) == 1


def test_fuzz_malformed_contract():
    rng = random.Random(446)
    alphabet = list("ABCxyz01237!?\t\u00a0\ud800☕👖📸⚜🥷ᕤ驨")
    for _ in range(300):
        text = "".join(rng.choices(alphabet, k=rng.randrange(1, 20)))
        for codec in subject.CODECS:
            try:
                value = subject.decode(text, codec)
                assert isinstance(value, bytes)
            except subject.EncodingError:
                pass
