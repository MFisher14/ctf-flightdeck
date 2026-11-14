"""B-223: the media-container reader pack (solvers/metadata-forensics/readers_media.py) through the metadata lane.

Every file here is built in the test from invented values (WAV) or by the synthetic corpus (MP4, MKV:
ctf/formats/corpus.py). Each question is asked exactly as the lane is asked one ('Determine <property> for
<file>.') through properties_strict.answer_question, with the judge ledger either off or on over an empty
event workdir (tmp_path), so the tracked seed (conventions.json) is the only judged evidence.

  1. Day 17's row: media.primary_audio_codec_name of a 16-bit integer PCM WAV is pcm_s16le, plain with the
     seed (the one judged shape), unsure without it; every other WAV shape stays unsure under its own key.
  2. The compressed-in-PCM guard: a chain of MPEG audio frames behind a 16-bit PCM header is never plain.
  3. MP4 and Matroska: codec and stream facts in ffprobe's vocabulary; plain only where the seed has the
     exact container+codec key (mp4+mp4a_40), never across containers (ogg+opus does not make mkv opus plain).
  4. media.<rest> that the media grammar does not read is read in the file's own container namespace by that
     namespace's registered reader, unsure, the reader named in every option; nothing for an unseen name, a
     name the container has no reader for, or a file that is no media container.
"""
import json
import struct

import pytest

from ctf import formats
from ctf.formats import corpus as C
from ctf.formats import matrix as X

LANE = X.lane_module()
import labels  # noqa: E402  (solvers/common, on sys.path once the lane is loaded)

MEDIA = LANE.MORE_MODULES["readers_media.py"]
DAY17_ID = "d17-audio-001-media-primary-audio-codec-name"
CODEC = "media.primary_audio_codec_name"


@pytest.fixture
def judged(monkeypatch, tmp_path):
    """The judge ledger on, over an empty event workdir: the tracked seed is the only judged evidence."""
    monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    assert labels.judge_ledger()


@pytest.fixture
def no_judge(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")


def wav(tag=1, bits=16, channels=1, rate=44100, payload=None, frames=4410, extensible=None):
    """A RIFF/WAVE file: fmt (16 bytes, or 40 for WAVE_FORMAT_EXTENSIBLE with `extensible` the subformat tag)
    and a data chunk (`payload`, else a ramp of `frames` frames)."""
    align = channels * bits // 8
    fmt = struct.pack("<HHIIHH", 0xFFFE if extensible else tag, channels, rate, rate * align, align, bits)
    if extensible:
        guid = struct.pack("<H", extensible) + bytes.fromhex("0000" "000010008000" "00aa00389b71")
        fmt += struct.pack("<HHI", 22, bits, 0x4 if channels == 1 else 0x3) + guid
    data = payload if payload is not None else bytes((i * 13) & 0xFF for i in range(frames * align))
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body


MP3_FRAME = b"\xff\xfb\x90\x00" + b"\x00" * 413     # MPEG-1 layer III, 128 kbit/s, 44.1 kHz: 417 bytes


def ask(prop, name, data, aid=None):
    q = {"answer_id": aid or "t-" + prop.replace(".", "-"), "question": f"Determine {prop} for {name}."}
    return LANE.answer_question(q, {name: data}, {})


def unsure(answer):
    """(key, [(option name, value)]) of an unsure answer; fails on a plain or empty one."""
    parsed = labels.parse(answer) if answer is not None else None
    assert parsed is not None, f"expected an unsure answer, got {answer!r}"
    return parsed.key, list(parsed.options)


# ------------------------------------------------------------------ 1. Day 17's codec row

def test_day17_pcm_s16le_is_plain_with_the_seed(judged):
    data = wav()
    assert ask(CODEC, "hear-me-out.wav", data, DAY17_ID) == "pcm_s16le"
    assert ask("media.primary_audio_codec_name", "hear-me-out.wav", data) == "pcm_s16le"   # any id: the key is the name's


def test_day17_codec_is_unsure_with_ffprobe_first_without_the_judge(no_judge):
    key, options = unsure(ask(CODEC, "hear-me-out.wav", wav(), DAY17_ID))
    assert key == "metadata.media.primary_audio_codec_name/wav"
    assert options[0] == ("ffprobe_codec_name", "pcm_s16le")
    assert ("pcm", "pcm") in options


@pytest.mark.parametrize("kw, codec, shape", [
    ({"bits": 24}, "pcm_s24le", "wav+pcm_s24le"),
    ({"bits": 8}, "pcm_u8", "wav+pcm_u8"),
    ({"tag": 3, "bits": 32}, "pcm_f32le", "wav+pcm_f32le"),
    ({"tag": 6, "bits": 8}, "pcm_alaw", "wav+pcm_alaw"),
    ({"tag": 7, "bits": 8}, "pcm_mulaw", "wav+pcm_mulaw"),
    ({"extensible": 1, "bits": 16, "channels": 2}, "pcm_s16le", "wav+extensible+pcm_s16le"),
])
def test_every_other_wav_shape_stays_unsure_under_its_own_key(judged, kw, codec, shape):
    key, options = unsure(ask(CODEC, "tone.wav", wav(**kw)))
    assert key == f"metadata.media.primary_audio_codec_name/{shape}"
    assert options[0] == ("ffprobe_codec_name", codec)


def test_a_wav_the_fmt_chunk_does_not_settle_has_no_codec(judged):
    assert ask(CODEC, "odd.wav", wav(tag=0x1234, bits=16)) is None
    assert ask(CODEC, "nodata.wav", wav()[:12 + 8 + 16]) is None


# ------------------------------------------------------------------ 2. compressed frames behind a PCM header

def test_a_probed_mp3_stream_in_a_pcm_wav_is_never_plain(judged):
    key, options = unsure(ask(CODEC, "hidden.wav", wav(payload=MP3_FRAME * 8)))
    assert key == "metadata.media.primary_audio_codec_name/wav+probed+mp3"
    assert options == [("ffprobe_codec_name", "mp3"), ("fmt_header", "pcm_s16le")]


def test_a_short_chain_is_embedded_pcm_first_and_never_plain(judged):
    key, options = unsure(ask(CODEC, "hidden.wav", wav(payload=MP3_FRAME * 3 + b"\x01" * 1000)))
    assert key == "metadata.media.primary_audio_codec_name/wav+embedded+mp3"
    assert options == [("ffprobe_codec_name", "pcm_s16le"), ("embedded_stream", "mp3")]


def test_one_frame_alone_changes_nothing(judged):
    assert ask(CODEC, "hidden.wav", wav(payload=MP3_FRAME + b"\x01" * 2000)) == "pcm_s16le"


# ------------------------------------------------------------------ 3. MP4 and Matroska

def test_mp4_aac_is_plain_through_its_judged_container_codec_key(judged):
    s = C.build("media_mp4")
    assert ask(CODEC, s.name, s.data) == "aac"
    key, options = unsure(ask("media.primary_video_codec_name", s.name, s.data))
    assert key == "metadata.media.primary_video_codec_name/mp4+avc1" and options[0][1] == "h264"


def test_mkv_opus_is_not_plain_because_ogg_opus_was_judged(judged):
    s = C.build("media_mkv")
    key, options = unsure(ask(CODEC, s.name, s.data))
    assert key == "metadata.media.primary_audio_codec_name/mkv+a_opus"
    assert options[0] == ("ffprobe_codec_name", "opus")


@pytest.mark.parametrize("sample, prop, first", [
    ("media_mp4", "media.format_name", "mov,mp4,m4a,3gp,3g2,mj2"),
    ("media_mp4", "media.duration_seconds", "2.000000"),
    ("media_mp4", "media.primary_video_frame_rate", "25/1"),
    ("media_mp4", "media.primary_audio_sample_rate_hz", "44100"),
    ("media_mp4", "media.audio_codec_names", '["aac"]'),
    ("media_mkv", "media.format_name", "matroska,webm"),
    ("media_mkv", "media.duration_seconds", "1.500000"),
    ("media_mkv", "media.primary_video_width_pixels", "640"),
    ("media_mkv", "media.primary_video_frame_rate", "25/1"),
    ("media_mkv", "media.title_tag", "Corpus Clip"),
])
def test_container_facts_in_ffprobes_vocabulary_first(no_judge, sample, prop, first):
    s = C.build(sample)
    key, options = unsure(ask(prop, s.name, s.data))
    assert key.startswith(f"metadata.{prop}/")
    assert options[0][1] == first


def test_a_stream_the_file_does_not_have_is_absent(no_judge):
    s = C.build("media_mp4")
    _, options = unsure(ask("media.primary_subtitle_codec_name", s.name, s.data))
    assert options == [("absent", "none")]


# ------------------------------------------------------------------ 4. media.<rest> in the container namespace

@pytest.mark.parametrize("sample, asked, reader, value", [
    ("riff_wav", "media.block_align", "wav.block_align", "4"),
    ("riff_wav", "audio.data_size_bytes", "wav.data_size_bytes", "8820"),
    ("riff_wav", "media.wav_byte_rate", "wav.byte_rate", "88200"),
    ("riff_wav", "media.chunk_ids", "riff.chunk_ids", '["fmt ","LIST","data"]'),
    ("media_mp4", "video.ftyp_major_brand", "mp4.ftyp_major_brand", "isom"),
    ("media_mp4", "media.ftyp_minor_version", "mp4.ftyp_minor_version", "512"),
    ("media_mkv", "media.doc_type", "mkv.doc_type", "webm"),
    ("media_mkv", "audio.muxing_app", "mkv.muxing_app", "corpus-mux"),
])
def test_an_unread_media_name_is_read_by_the_containers_reader_unsure(judged, sample, asked, reader, value):
    s = C.build(sample)
    key, options = unsure(ask(asked, s.name, s.data))
    assert key == f"metadata.format/{asked}"
    assert options and all(n.endswith("~" + reader) for n, _ in options), options
    assert value in [v for _, v in options]


def test_an_exact_reader_of_any_container_namespace_wins_over_a_nearest_one(no_judge):
    """wav.chunk_ids is no reader (the wav namespace's nearest reading is its INFO list); riff.chunk_ids is."""
    s = C.build("riff_wav")
    assert LANE.lookup("wav_chunk_ids") is None and LANE.lookup("riff_chunk_ids") is not None
    _, options = unsure(ask("media.chunk_ids", s.name, s.data))
    assert {n.split("~")[1] for n, _ in options} == {"riff.chunk_ids"}


@pytest.mark.parametrize("sample, asked, reader", [
    ("riff_wav", "media.chunk_count", "wav.chunk_count"),
    ("media_mp4", "media.atom_count", "mp4.atom_count"),
])
def test_an_exact_container_reader_beats_guess_by_shared_words(no_judge, sample, asked, reader):
    """guess() alone reads both names as media.stream_count (they share 'count'); the file's container has a
    reader registered under exactly that field, and it is the one taken (resolve_name step 4a, before guess)."""
    s = C.build(sample)
    assert LANE.guess(LANE.canon(asked))[1] == "media.stream_count"   # what guess-first would have answered
    assert reader.replace(".", "_") in LANE.REG
    got = LANE.resolve_name(asked, None, s.name, s.data)
    assert (got.reader, got.kind, got.way) == (reader, "guess", "container " + reader.split(".")[0])
    assert got.prop.name == asked and not got.prop.confirmed
    key, options = unsure(ask(asked, s.name, s.data))
    assert key == f"metadata.format/{asked}"
    assert options and all(n.endswith("~" + reader) for n, _ in options), options


def test_a_family_pattern_is_not_taken_for_an_exact_reader(no_judge):
    """riff.<anything> of a WAVE is a family (readers_riff.py); only registered names count as exact, so the
    wav namespace's own reader of the field is the one named."""
    s = C.build("riff_wav")
    assert LANE.lookup("riff_fmt_chunk_size") is not None and "riff_fmt_chunk_size" not in LANE.REG
    key, options = unsure(ask("media.fmt_chunk_size", s.name, s.data))
    assert key == "metadata.format/media.fmt_chunk_size"           # the asked name's key, never wav.*
    assert {n.split("~")[1] for n, _ in options} == {"wav.fmt_chunk_size_bytes"}
    assert [v for _, v in options] == ["16"]


def test_a_typed_media_name_reads_as_the_container_name_with_the_padded_form_first(no_judge):
    """media.format_tag_hex is wav.format_tag_hex: the field's own width (u16) padded first, at most three options."""
    s = C.build("riff_wav")
    got = LANE.resolve_name("media.format_tag_hex", None, s.name, s.data)
    assert (got.reader, got.way) == ("wav.format_tag", LANE.FIELD_WIDTH)
    assert got.prop.name == "media.format_tag_hex" and not got.prop.confirmed
    key, media = unsure(ask("media.format_tag_hex", s.name, s.data))
    assert key == "metadata.format/media.format_tag_hex"           # the asked name's key, never wav.*
    _, own = unsure(ask("wav.format_tag_hex", s.name, s.data))
    assert media == own and media[0] == ("0x_u16_4digits~wav.format_tag", "0x0001") and len(media) <= 3


def test_the_container_is_the_files_own_never_another_media_namespace(no_judge):
    mp4, mkv = C.build("media_mp4"), C.build("media_mkv")
    assert ask("media.block_align", mp4.name, mp4.data) is None        # wav.block_align exists; an mp4 has none
    assert ask("media.doc_type", mp4.name, mp4.data) is None           # mkv.doc_type exists; an mp4 has none
    assert ask("media.ftyp_minor_version", mkv.name, mkv.data) is None   # mp4's reader, a webm file
    assert ask("media.ftyp_minor_version", mp4.name, mp4.data) is not None


def test_an_unseen_name_and_a_file_that_is_no_media_container_get_nothing(no_judge):
    s = C.build("riff_wav")
    assert ask("media.zzz_unheard_of", s.name, s.data) is None
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0) + b"\0" * 4
    assert ask("media.block_align", "x.png", png) is None


def test_a_name_the_media_grammar_reads_is_never_sent_to_the_container(no_judge):
    s = C.build("riff_wav")
    _, options = unsure(ask("media.duration_seconds", s.name, s.data))
    assert not any("~" in n for n, _ in options)
    assert options[0] == ("ffprobe", "0.100000")      # 2205 frames at 22050 Hz


def test_resolve_name_reads_the_container_only_with_the_files_bytes():
    data = C.build("riff_wav").data
    got = LANE.resolve_name("media.block_align", None, "voice-note.wav", data)
    assert (got.kind, got.reader, got.way) == ("guess", "wav.block_align", "container wav")
    assert not got.prop.confirmed and got.prop.name == "media.block_align"
    assert LANE.resolve_name("media.block_align").prop is None


def test_container_namespaces_follow_the_detected_container():
    assert MEDIA.container_namespaces(C.build("riff_wav").data) == ("wav", "riff")
    assert MEDIA.container_namespaces(C.build("riff_avi").data) == ("avi", "riff")
    assert MEDIA.container_namespaces(C.build("media_mp4").data) == ("mp4",)
    assert MEDIA.container_namespaces(C.build("media_mkv").data) == ("mkv",)
    assert MEDIA.container_namespaces(b"fLaC" + b"\0" * 64) == ("flac",)
    assert MEDIA.container_namespaces(b"%PDF-1.4\n" + b"\0" * 64) == ()
    assert MEDIA.container_namespaces(b"") == ()
    assert set(LANE.CONTAINER_HEADS) >= {"media", "audio", "video"}
    assert all(ns in LANE.NAMESPACES for v in MEDIA.CONTAINER_NAMESPACES.values() for ns in v)


# ------------------------------------------------------------------ the media matrix sample (ctf/formats)

def test_the_media_samples_are_identified_as_media_and_a_wav_stays_riff():
    cat = formats.load()
    assert [m.format for m in formats.identify("c.mp4", C.build("media_mp4").data, cat)][:1] == ["media"]
    assert [m.format for m in formats.identify("c.webm", C.build("media_mkv").data, cat)][:1] == ["media"]
    assert formats.identify("v.wav", C.build("riff_wav").data, cat)[0].format == "riff"


@pytest.mark.parametrize("data, want", [
    (b"\0\0\0\x18ftypisom\0\0\x02\0isomiso2", True),
    (b"\0\0\0\x18ftypheic\0\0\0\0mif1heic", False),          # a HEIF still image, not a movie
    (b"\0\0\0\x18ftypavif\0\0\0\0mif1avif", False),
    (b"\x1a\x45\xdf\xa3\x9f", True),
    (b"fLaC\0\0\0\x22", True),
    (b"OggS\0\x02", True),
    (b"FORM\0\0\0\x20AIFFCOMM", True),
    (b"FORM\0\0\0\x20AIFCFVER", True),                       # AIFF-C
    (b"\0\0\0\x18ftypcrx \0\0\0\x01crx isom", False),        # a Canon CR3 raw still image
    (b"\0\0\0\x18ftypjpeg\0\0\0\0mif1jpeg", False),          # JPEG in HEIF
    (b"\0\0\0\x18ftypmiaf\0\0\0\0mif1miaf", False),
    (b"\0\0\0\x18ftypM4A \0\0\0\0M4A isom", True),           # an audio-only MP4 is media
    (b"\0\0\0\x18ftypxyzi\0\0\0\0mif1xyzi", False),          # an unlisted still brand, by its image compat brand
    (b"\0\0\0\x1cftypisom\0\0\0\0isommif1mp42", True),       # an image brand beside a movie brand: a movie
    (b"\0\0\0\x18ftypmp42\0\0\0\0isommif1", True),           # a movie major brand
    (b"\0\0\0\x14ftypxyzi\0\0\0\0isommif1", True),           # mif1 lies past the ftyp box's own size
    (b"FORM\0\0\0\x20ILBMBMHD", False),
    (b"RIFF\0\0\0\0WAVEfmt ", False),                          # the riff format's
    (b"", False),
])
def test_the_media_detector(data, want):
    assert formats.DETECTORS["media"](data) is want


def test_the_media_format_in_the_shipped_matrix_has_no_problem():
    cat = tuple(f for f in formats.load() if f.id in ("media", "riff"))
    m = X.compute(cat)
    assert not m.problems(), m.problems()
    media = next(f for f in m.formats if f.id == "media")
    assert len([c for c in media.checks if c.matched]) == len(media.checks) >= 30
    assert {n.reader_seen for n in media.nearest} == {"mp4.ftyp_minor_version", "mp4.ftyp_major_brand",
                                                       "mkv.doc_type", "mkv.muxing_app"}
    riff = next(f for f in m.formats if f.id == "riff")
    near = {n.asked: n for n in riff.nearest}
    assert near["media.block_align"].status == "unsure" and near["media.block_align"].reader_seen == "wav.block_align"
    assert json.loads(m.to_json())["problems"] == []
