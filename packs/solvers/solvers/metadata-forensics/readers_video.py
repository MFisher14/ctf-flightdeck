#!/usr/bin/env python3
"""Metadata Forensics video geometry pack (backlog rows 361 and 362; the Day 19 look-ahead's build items 1 and 2).

properties_strict.py loads this file by name (MORE_FILES, right after readers_media.py) and calls register(M). It
registers no name of its own: readers_media.py's grammar asks it, at answer time, through M.MORE_MODULES, for

1. The stream's own size, read from the codec's sequence parameter set (an exp-Golomb parse; no decoding):
     H.264  the first SPS of `avcC` (an mp4 sample entry's child box, a Matroska CodecPrivate): pic_width_in_mbs,
            pic_height_in_map_units and frame_mbs_only (the coded size, padded to 16, as ffprobe's coded_width and
            coded_height), the frame crop offsets in the chroma format's crop unit (the cropped size, ffprobe's
            width and height), the VUI's aspect_ratio_idc / sar (ffprobe's codec sample aspect ratio), the video
            full range flag, profile_idc with the constraint flags (ffprobe's profile name), level_idc, chroma
            format and bit depth (ffprobe's pix_fmt).
     HEVC   the first SPS of `hvcC`: profile_tier_level (general profile and level), chroma format, the luma size
            (coded) and the conformance window (cropped), the bit depth. The VUI (its SAR) is not read: an HEVC
            stream's SAR comes from `pasp` or is Unknown.
   A stream that is not parsed whole (an emulation byte past the end, a seq_scaling_matrix, a value out of its
   range, a second SPS that disagrees) is Unknown: nothing below reads a size from a part of an SPS.

2. The container's geometry (mp4 / mov): the `tkhd` display matrix (ffmpeg's av_display_rotation_get, the
   rotation ffprobe prints as the Display Matrix side data), `pasp` (the container sample aspect ratio, which
   ffprobe prefers to the codec's), `clap` (clean aperture), and the `tkhd` width and height.

3. The guard on the one judged dimensions key (row 361). `metadata.media.primary_video_dimensions/mp4` has `wxh`
   accepted (Day 18, one file: H.264, 320x180, `pasp` 1:1, no `clap`, identity matrix, tkhd 320x180). Its answer
   stays under that key only in that shape: the SPS's cropped size equals the sample entry's (stsd) size, the
   matrix is the identity, `pasp` is absent or 1:1 (and the SPS states no other SAR), there is no `clap`, and the
   tkhd size equals stsd. The SPS is the one ffprobe's decoder takes: an SPS the track's first sample sends in the
   stream replaces the record's when it differs (`sps_differs`), and one that does not parse, or a first sample that
   is not located, leaves the SPS unread. A codec whose header this pack does not parse (AV1, VP9, MPEG-4 part 2,
   MJPEG, ProRes in an mp4) has no size of its own to hold stsd against and is never plain (`sps_unread`; review of
   the build: a lying stsd of an mp4v file was answered plain). Anything else is keyed `<key>+<shape>`
   (`mp4+sps_differs`, `mp4+rotated`, `mp4+anamorphic`, `mp4+clap`, `mp4+tkhd_differs`, `mp4+sps_unread`, joined
   in that order), unsure, the stream's own size first (ffprobe's width x height, as on Day 18), then the
   displayed size, then stsd, then tkhd. The same shape key holds `width` and `height`.

4. New fields of the media grammar (all `labels.pick` under `metadata.<asked>/<container>[+shape]`): coded_width,
   coded_height, coded_dimensions, display_dimensions, rotation (ffprobe's sign first, then its negation, then
   0-359), sample_aspect_ratio, display_aspect_ratio, profile, level, pixel_format, and the bit depth of a video
   stream (bits_per_raw_sample). ffprobe's form first in each.

5. Tags of an mp4/mov (row 362's tag half, readers_media.py's TAG_FIELDS): creation_time (the mvhd creation time
   in ffprobe's form, then the QuickTime `creationdate` key as stored), major_brand, minor_version and
   compatible_brands (ftyp, as ffprobe prints them), and location from the 3GPP `loci` box (ffmpeg's text,
   `%+08.4f%+09.4f/` of the single-precision coordinates) where no `©xyz` or ISO 6709 key holds it.

Cost: nothing at import but the tables. The SPS parse runs once per probed file (readers_media.py caches the probe)
and takes a few tens of microseconds.
"""
import fractions
import math
import struct
import datetime

M = None      # properties_strict, set by register()
MED = None    # readers_media.py as loaded


def U(msg):
    raise M.Unknown(msg)


# ====================================================================== 1. the exp-Golomb reader

class _Bits:
    """An RBSP bit reader (emulation prevention bytes removed first). Reading past the end raises IndexError."""

    def __init__(self, nal: bytes):
        out, zeros = bytearray(), 0
        for b in nal:
            if zeros >= 2 and b == 3:
                zeros = 0
                continue
            out.append(b)
            zeros = zeros + 1 if b == 0 else 0
        self.b, self.n, self.i = bytes(out), len(out) * 8, 0

    def u(self, k: int) -> int:
        if self.i + k > self.n:
            raise IndexError("the SPS ends early")
        v = 0
        for _ in range(k):
            v = (v << 1) | ((self.b[self.i >> 3] >> (7 - (self.i & 7))) & 1)
            self.i += 1
        return v

    def ue(self) -> int:
        z = 0
        while self.u(1) == 0:
            z += 1
            if z > 31:
                raise ValueError("an exp-Golomb code longer than 32 bits")
        return (1 << z) - 1 + (self.u(z) if z else 0)

    def se(self) -> int:
        k = self.ue()
        return (k + 1) // 2 if k & 1 else -(k // 2)


SAR_IDC = {1: (1, 1), 2: (12, 11), 3: (10, 11), 4: (16, 11), 5: (40, 33), 6: (24, 11), 7: (20, 11), 8: (32, 11),
           9: (80, 33), 10: (18, 11), 11: (15, 11), 12: (64, 33), 13: (160, 99), 14: (4, 3), 15: (3, 2), 16: (2, 1)}
H264_PROFILES = {66: "Baseline", 77: "Main", 88: "Extended", 100: "High", 110: "High 10", 122: "High 4:2:2",
                 244: "High 4:4:4 Predictive", 44: "CAVLC 4:4:4"}
HIGH_PROFILES = {100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135}
HEVC_PROFILES = {1: "Main", 2: "Main 10", 3: "Main Still Picture", 4: "Rext", 9: "SCC"}
CHROMA = {0: "gray", 1: "420", 2: "422", 3: "444"}


def h264_profile(idc: int, flags: int):
    """ffprobe's profile name (libavcodec/profiles.c, ff_h264_profiles) from profile_idc and the constraint flags."""
    if idc == 66 and flags & 0x40:
        return "Constrained Baseline"
    if idc == 110 and flags & 0x10:
        return "High 10 Intra"
    if idc == 122 and flags & 0x10:
        return "High 4:2:2 Intra"
    if idc == 244 and flags & 0x10:
        return "High 4:4:4 Intra"
    return H264_PROFILES.get(idc)


def pix_fmt(chroma: int, depth: int, full_range: bool):
    """ffmpeg's pixel format of a decoded H.264 or HEVC stream."""
    if chroma == 0:
        return "gray" if depth == 8 else f"gray{depth}le" if depth in (9, 10, 12, 14) else None
    sub = CHROMA.get(chroma)
    if sub is None:
        return None
    if depth == 8:
        return f"yuv{'j' if full_range else ''}{sub}p"
    return f"yuv{sub}p{depth}le" if depth in (9, 10, 12, 14) else None


def h264_sps(nal: bytes):
    """The facts of one H.264 SPS NAL unit (with its one-byte NAL header), or Unknown."""
    if not nal or nal[0] & 0x1F != 7:
        U("not an H.264 SPS")
    r = _Bits(nal[1:])
    try:
        profile, flags, level = r.u(8), r.u(8), r.u(8)
        r.ue()                                   # seq_parameter_set_id
        chroma, depth_l, depth_c = 1, 8, 8
        if profile in HIGH_PROFILES:
            chroma = r.ue()
            if chroma > 3:
                U("a chroma_format_idc out of range")
            if chroma == 3:
                r.u(1)                           # separate_colour_plane_flag
            depth_l, depth_c = r.ue() + 8, r.ue() + 8
            r.u(1)                               # qpprime_y_zero_transform_bypass_flag
            if r.u(1):                           # seq_scaling_matrix_present_flag
                U("an SPS with a scaling matrix (not read)")
        r.ue()                                   # log2_max_frame_num_minus4
        poc = r.ue()
        if poc == 0:
            r.ue()
        elif poc == 1:
            r.u(1)
            r.se()
            r.se()
            n = r.ue()
            if n > 255:
                U("an SPS with too many reference frames in the POC cycle")
            for _ in range(n):
                r.se()
        elif poc != 2:
            U("a pic_order_cnt_type out of range")
        r.ue()                                   # max_num_ref_frames
        r.u(1)                                   # gaps_in_frame_num_value_allowed_flag
        mbs_w, map_h = r.ue() + 1, r.ue() + 1
        frame_mbs_only = r.u(1)
        if not frame_mbs_only:
            r.u(1)                               # mb_adaptive_frame_field_flag
        r.u(1)                                   # direct_8x8_inference_flag
        crop = (0, 0, 0, 0)
        if r.u(1):
            crop = (r.ue(), r.ue(), r.ue(), r.ue())
        sar, full, vui_rest = None, False, {"vui": False}
        if r.u(1):                               # vui_parameters_present_flag
            if r.u(1):                           # aspect_ratio_info_present_flag
                idc = r.u(8)
                if idc == 255:
                    sar = (r.u(16), r.u(16))
                elif idc in SAR_IDC:
                    sar = SAR_IDC[idc]
                elif idc != 0:
                    U("an aspect_ratio_idc out of the table")
            if r.u(1):                           # overscan_info_present_flag
                r.u(1)
            signal = None
            if r.u(1):                           # video_signal_type_present_flag
                r.u(3)
                full = signal = bool(r.u(1))
            vui_rest = _vui_rest(r, h264=True, signal=signal)   # the Day 20 build: colour, chroma location, timing
    except (IndexError, ValueError) as e:
        U(f"the H.264 SPS does not parse ({e})")
    coded_w, coded_h = mbs_w * 16, (2 - frame_mbs_only) * map_h * 16
    if chroma == 0 or chroma == 3:
        cx, cy = 1, 2 - frame_mbs_only
    else:
        cx, cy = (2, 2 * (2 - frame_mbs_only)) if chroma == 1 else (2, 2 - frame_mbs_only)
    w = coded_w - cx * (crop[0] + crop[1])
    h = coded_h - cy * (crop[2] + crop[3])
    if w <= 0 or h <= 0 or coded_w > 16384 or coded_h > 16384:
        U("an SPS size out of range")
    if sar is not None and (not sar[0] or not sar[1]):
        sar = None
    out = {"codec": "h264", "width": w, "height": h, "coded_width": coded_w, "coded_height": coded_h,
           "cropped": any(crop), "sar": sar, "profile": h264_profile(profile, flags), "level": level,
           "pix_fmt": pix_fmt(chroma, depth_l, full) if depth_l == depth_c else None, "depth": depth_l,
           "chroma": chroma, "frame_mbs_only": bool(frame_mbs_only)}
    out.update(vui_rest)
    return out


def _hevc_ptl(r: _Bits, max_sub: int):
    r.u(2)
    r.u(1)                                       # general_profile_space, general_tier_flag
    profile = r.u(5)
    compat = r.u(32)
    r.u(32)
    r.u(16)                                      # progressive, interlaced, ..., 43 reserved bits, 1 bit
    level = r.u(8)
    present = [(r.u(1), r.u(1)) for _ in range(max_sub)]
    if max_sub:
        for _ in range(max_sub, 8):
            r.u(2)
    for p, lv in present:
        if p:
            r.u(32)
            r.u(32)
            r.u(24)
        if lv:
            r.u(8)
    if profile == 0:                             # a stream that states only the compatibility flags
        profile = next((i for i in range(1, 32) if compat & (1 << (31 - i))), 0)
    return profile, level


def hevc_sps(nal: bytes):
    """The facts of one HEVC SPS NAL unit (with its two-byte NAL header), or Unknown. The VUI is read when the SPS
    parses to it (Day 20 build); otherwise the SAR stays unread ('sar_unread'), as before."""
    if len(nal) < 3 or (nal[0] >> 1) & 0x3F != 33:
        U("not an HEVC SPS")
    r = _Bits(nal[2:])
    try:
        r.u(4)
        max_sub = r.u(3)
        r.u(1)
        profile, level = _hevc_ptl(r, max_sub)
        r.ue()                                   # sps_seq_parameter_set_id
        chroma = r.ue()
        if chroma > 3:
            U("a chroma_format_idc out of range")
        if chroma == 3:
            r.u(1)
        cw, ch = r.ue(), r.ue()
        win = (0, 0, 0, 0)
        if r.u(1):
            win = (r.ue(), r.ue(), r.ue(), r.ue())
        depth_l, depth_c = r.ue() + 8, r.ue() + 8
    except (IndexError, ValueError) as e:
        U(f"the HEVC SPS does not parse ({e})")
    sx, sy = (2, 2) if chroma == 1 else (2, 1) if chroma == 2 else (1, 1)
    w, h = cw - sx * (win[0] + win[1]), ch - sy * (win[2] + win[3])
    if w <= 0 or h <= 0 or cw > 16888 or ch > 16888:
        U("an SPS size out of range")
    out = {"codec": "hevc", "width": w, "height": h, "coded_width": cw, "coded_height": ch,
           "cropped": any(win), "sar": None, "sar_unread": True, "profile": HEVC_PROFILES.get(profile),
           "level": level, "pix_fmt": pix_fmt(chroma, depth_l, False) if depth_l == depth_c else None,
           "pix_fmt_range_unread": True, "depth": depth_l, "chroma": chroma}
    vui = _hevc_vui(r, max_sub)    # the Day 20 build: {} where the rest of the SPS does not parse to its VUI
    if vui:
        out.pop("sar_unread")
        out.pop("pix_fmt_range_unread")
        out.update(vui)
        # ffmpeg's hevc/ps.c (decode_vui and the SPS's pixel format): full range turns YUV420P (8-bit 4:2:0) alone into
        # YUVJ420P, never 4:2:2 or 4:4:4 (ffprobe: yuv422p, yuv444p with color_range pc; review of the Day 20 build);
        # an RGB matrix turns YUV444P, YUV444P10 and YUV444P12 into GBRP, GBRP10 and GBRP12
        if depth_l == depth_c:
            if vui.get("matrix") == "gbr" and chroma == 3 and depth_l in (8, 10, 12):
                out["pix_fmt"] = "gbrp" if depth_l == 8 else f"gbrp{depth_l}le"
            elif vui.get("range") == "pc" and chroma == 1 and depth_l == 8:
                out["pix_fmt"] = "yuvj420p"
    return out


# ---------------------------------------------------------------- the VUI past the sample aspect ratio (Day 20 build)
#
# The colour description (ffprobe's color_primaries, color_transfer, color_space), the video range (color_range), the
# chroma sample location (chroma_location) and the timing (num_units_in_tick, time_scale) of an H.264 VUI, and the
# HEVC VUI itself (its SAR, which an HEVC SPS states only there; the rows 361 and 362 build read no HEVC VUI). Only what
# the stream states is kept: a VUI cut after its SAR keeps the SAR and leaves the rest out ('vui_cut'), and an HEVC
# SPS that does not parse to its VUI flag (a value out of range, a cut) is read as before, its SAR unread. The names
# are ffmpeg's (libavutil/pixdesc.c: av_color_primaries_name, av_color_transfer_name, av_color_space_name,
# av_chroma_location_name).

COLOR_PRIMARIES = {1: "bt709", 4: "bt470m", 5: "bt470bg", 6: "smpte170m", 7: "smpte240m", 8: "film", 9: "bt2020",
                   10: "smpte428", 11: "smpte431", 12: "smpte432", 22: "ebu3213"}
COLOR_TRANSFER = {1: "bt709", 4: "gamma22", 5: "gamma28", 6: "smpte170m", 7: "smpte240m", 8: "linear", 9: "log100",
                  10: "log316", 11: "iec61966-2-4", 12: "bt1361e", 13: "iec61966-2-1", 14: "bt2020-10", 15: "bt2020-12",
                  16: "smpte2084", 17: "smpte428", 18: "arib-std-b67"}
COLOR_SPACE = {0: "gbr", 1: "bt709", 4: "fcc", 5: "bt470bg", 6: "smpte170m", 7: "smpte240m", 8: "ycgco", 9: "bt2020nc",
               10: "bt2020c", 11: "smpte2085", 12: "chroma-derived-nc", 13: "chroma-derived-c", 14: "ictcp"}
CHROMA_LOC = {0: "left", 1: "center", 2: "topleft", 3: "top", 4: "bottomleft", 5: "bottom"}   # ffmpeg: type + 1


def _vui_rest(r, h264: bool, signal):
    """{vui, range, primaries, transfer, matrix, chroma_loc, timing} of a VUI read from just after the video signal
    type (`signal` is its full range flag, None when the VUI states no video signal type). A VUI that ends early keeps
    what was read before the cut and says so ('vui_cut')."""
    out = {"vui": True}
    if signal is not None:
        out["range"] = "pc" if signal else "tv"
    try:
        if signal is not None and r.u(1):        # colour_description_present_flag
            pri, trc, mat = r.u(8), r.u(8), r.u(8)
            out.update(primaries=COLOR_PRIMARIES.get(pri), transfer=COLOR_TRANSFER.get(trc), matrix=COLOR_SPACE.get(mat))
        if r.u(1):                               # chroma_loc_info_present_flag
            top = r.ue()
            r.ue()
            out["chroma_loc"] = CHROMA_LOC.get(top)
            out["chroma_loc_stated"] = True
        if h264 and r.u(1):                      # timing_info_present_flag
            units, scale = r.u(32), r.u(32)
            fixed = r.u(1)                       # fixed_frame_rate_flag
            if units and scale:
                out["timing"] = (units, scale)
                out["timing_fixed"] = bool(fixed)
    except (IndexError, ValueError):
        out["vui_cut"] = True
    return out


def _scaling_list_data(r):
    for size_id in range(4):
        for _ in range(0, 6, 3 if size_id == 3 else 1):
            if not r.u(1):                       # scaling_list_pred_mode_flag
                r.ue()
                continue
            if size_id > 1:
                r.se()
            for _ in range(min(64, 1 << (4 + (size_id << 1)))):
                r.se()


def _st_ref_pic_sets(r, count: int):
    """Read `count` st_ref_pic_set() of an HEVC SPS (H.265 7.3.7 and 7.4.8), keeping the delta POCs that the inter
    prediction of a later set needs. A value out of its range raises ValueError."""
    sets = []
    for idx in range(count):
        if idx and r.u(1):                       # inter_ref_pic_set_prediction_flag (delta_idx is 1 in an SPS)
            sign, absd = r.u(1), r.ue()
            if absd > 32767:
                raise ValueError("abs_delta_rps out of range")
            delta = (1 - 2 * sign) * (absd + 1)
            s0r, s1r = sets[idx - 1]
            nd = len(s0r) + len(s1r)
            use = []
            for _ in range(nd + 1):
                used = r.u(1)
                use.append(1 if used else r.u(1))
            s0, s1 = [], []
            for j in range(len(s1r) - 1, -1, -1):
                dp = s1r[j] + delta
                if dp < 0 and use[len(s0r) + j]:
                    s0.append(dp)
            if delta < 0 and use[nd]:
                s0.append(delta)
            for j in range(len(s0r)):
                dp = s0r[j] + delta
                if dp < 0 and use[j]:
                    s0.append(dp)
            for j in range(len(s0r) - 1, -1, -1):
                dp = s0r[j] + delta
                if dp > 0 and use[j]:
                    s1.append(dp)
            if delta > 0 and use[nd]:
                s1.append(delta)
            for j in range(len(s1r)):
                dp = s1r[j] + delta
                if dp > 0 and use[len(s0r) + j]:
                    s1.append(dp)
            if len(s0) > 16 or len(s1) > 16:
                raise ValueError("a short-term RPS with too many pictures")
            sets.append((s0, s1))
            continue
        neg, pos = r.ue(), r.ue()
        if neg > 16 or pos > 16:
            raise ValueError("a short-term RPS with too many pictures")
        s0, s1, poc = [], [], 0
        for _ in range(neg):
            poc -= r.ue() + 1
            r.u(1)
            s0.append(poc)
        poc = 0
        for _ in range(pos):
            poc += r.ue() + 1
            r.u(1)
            s1.append(poc)
        sets.append((s0, s1))


def _hevc_vui(r, max_sub: int):
    """The VUI of an HEVC SPS read from just after its bit depths: {} when the SPS does not parse to its VUI flag (the
    SAR stays unread); {'vui': False, 'sar': None, 'range': 'tv'} for an SPS with no VUI; otherwise sar (None where no
    aspect ratio is stated), range (ffmpeg's hevc decoder exports tv where no video signal type is stated) and
    _vui_rest's fields."""
    try:
        poc_bits = r.ue() + 4
        if poc_bits > 16:
            return {}
        start = 0 if r.u(1) else max_sub         # sps_sub_layer_ordering_info_present_flag
        for _ in range(start, max_sub + 1):
            r.ue()
            r.ue()
            r.ue()
        for _ in range(6):                       # coding and transform block sizes, transform hierarchy depths
            r.ue()
        if r.u(1) and r.u(1):                    # scaling_list_enabled_flag, sps_scaling_list_data_present_flag
            _scaling_list_data(r)
        r.u(1)                                   # amp_enabled_flag
        r.u(1)                                   # sample_adaptive_offset_enabled_flag
        if r.u(1):                               # pcm_enabled_flag
            r.u(4)
            r.u(4)
            r.ue()
            r.ue()
            r.u(1)
        n = r.ue()
        if n > 64:
            return {}
        _st_ref_pic_sets(r, n)
        if r.u(1):                               # long_term_ref_pics_present_flag
            k = r.ue()
            if k > 32:
                return {}
            for _ in range(k):
                r.u(poc_bits)
                r.u(1)
        r.u(1)                                   # sps_temporal_mvp_enabled_flag
        r.u(1)                                   # strong_intra_smoothing_enabled_flag
        if not r.u(1):                           # vui_parameters_present_flag
            return {"vui": False, "sar": None, "range": "tv"}
        sar = None
        if r.u(1):                               # aspect_ratio_info_present_flag
            idc = r.u(8)
            if idc == 255:
                sar = (r.u(16), r.u(16))
            elif idc in SAR_IDC:
                sar = SAR_IDC[idc]
            elif idc != 0:
                return {}
            if sar is not None and (not sar[0] or not sar[1]):
                sar = None
        if r.u(1):                               # overscan_info_present_flag
            r.u(1)
        signal = None
        if r.u(1):                               # video_signal_type_present_flag
            r.u(3)
            signal = bool(r.u(1))
    except (IndexError, ValueError):
        return {}
    out = _vui_rest(r, h264=False, signal=signal)
    out["sar"] = sar
    out.setdefault("range", "tv")
    return out


def avcc_sps(body: bytes):
    """The parsed SPS of an avcC body (AVCDecoderConfigurationRecord), or Unknown. Two SPS that differ in a fact
    read here are Unknown."""
    if len(body) < 7 or body[0] != 1:
        U("not an AVCDecoderConfigurationRecord")
    n, i, got = body[5] & 0x1F, 6, []
    if n == 0:
        U("an avcC without an SPS")
    for _ in range(n):
        ln = struct.unpack_from(">H", body, i)[0]
        nal = body[i + 2:i + 2 + ln]
        if len(nal) != ln:
            U("an avcC that is cut")
        got.append(h264_sps(nal))
        i += 2 + ln
    if any(g != got[0] for g in got[1:]):
        U("an avcC with SPS that disagree")
    return got[0]


def hvcc_sps(body: bytes):
    """The parsed SPS of an hvcC body (HEVCDecoderConfigurationRecord), or Unknown."""
    if len(body) < 23 or body[0] != 1:
        U("not an HEVCDecoderConfigurationRecord")
    arrays, i, got = body[22], 23, []
    for _ in range(arrays):
        kind = body[i] & 0x3F
        cnt = struct.unpack_from(">H", body, i + 1)[0]
        i += 3
        for _ in range(cnt):
            ln = struct.unpack_from(">H", body, i)[0]
            nal = body[i + 2:i + 2 + ln]
            if len(nal) != ln:
                U("an hvcC that is cut")
            if kind == 33:
                got.append(hevc_sps(nal))
            i += 2 + ln
    if not got:
        U("an hvcC without an SPS")
    if any(g != got[0] for g in got[1:]):
        U("an hvcC with SPS that disagree")
    return got[0]


def config_sps(kind: str, body: bytes):
    """(parsed SPS or None, why) of a codec configuration record: kind 'avcC' or 'hvcC'."""
    try:
        return (avcc_sps(body) if kind == "avcC" else hvcc_sps(body)), None
    except M.Unknown as e:
        return None, str(e)
    except (struct.error, IndexError, ValueError) as e:
        return None, f"the {kind} record does not parse ({type(e).__name__})"


# ---------------------------------------------------------------- AV1 and VP9 headers (Day 20 build)
#
# The facts ffprobe prints of an AV1 or VP9 stream that its own headers state: the profile (ffmpeg's names), the AV1
# level (seq_level_idx[0], as ffprobe prints it; a VP9 stream's level is -99 to ffprobe and is not offered), the pixel
# format (the chroma subsampling and bit depth: libdav1d's and the vp9 decoder's table), the video range and, for AV1,
# the colour description and the chroma sample position. AV1: the av1C record (ISO/IEC 23091 AV1-ISOBMFF 2.3), whose
# sequence header OBU is parsed whole and must agree with the record's own fields. VP9: the vpcC record of an mp4 (VP
# Codec ISO Media File Format 2.2) and the uncompressed header of the track's first frame (VP9 6.2), which must agree;
# a WebM track's first frame (its first SimpleBlock or Block, unlaced) alone. These headers are kept apart from an
# H.264/HEVC SPS (s['header'], never s['sps']): the size a sequence header states is a maximum (AV1) or one frame's
# (VP9), so nothing here moves the dimensions key or its guard (an AV1 or VP9 mp4 stays `+sps_unread`).

HEADER_CODECS = {"av1", "vp9"}
HEADER_FIELDS = {"profile", "level", "pix_fmt", "color_range", "color_space", "color_transfer", "color_primaries",
                 "chroma_location"}
AV1_PROFILES = {0: "Main", 1: "High", 2: "Professional"}
VP9_PROFILES = {0: "Profile 0", 1: "Profile 1", 2: "Profile 2", 3: "Profile 3"}
VP9_SPACE = {1: "bt470bg", 2: "bt709", 3: "smpte170m", 4: "smpte240m", 5: "bt2020nc", 7: "gbr"}


def _fmt_of(sub, depth: int, mono=False):
    """libdav1d's / the vp9 decoder's pixel format: sub (x, y) subsampling, the bit depth."""
    if depth not in (8, 10, 12):
        return None
    if mono:
        return "gray" if depth == 8 else f"gray{depth}le"
    name = {(1, 1): "420", (1, 0): "422", (0, 0): "444", (0, 1): "440"}.get(sub)
    if name is None:
        return None
    return f"yuv{name}p" if depth == 8 else f"yuv{name}p{depth}le"


def _leb128(b: bytes, i: int):
    v = 0
    for k in range(8):
        if i + k >= len(b):
            raise IndexError("a leb128 that is cut")
        v |= (b[i + k] & 0x7F) << (7 * k)
        if not b[i + k] & 0x80:
            return v, i + k + 1
    raise ValueError("a leb128 longer than 8 bytes")


class _Plain(_Bits):
    """A plain MSB-first bit reader (AV1 and VP9 headers have no emulation prevention bytes)."""

    def __init__(self, b: bytes):
        self.b, self.n, self.i = bytes(b), len(b) * 8, 0


def av1_sequence(obu_payload: bytes):
    """The facts of an AV1 sequence header OBU payload (AV1 5.5), or Unknown."""
    r = _Plain(obu_payload)
    try:
        profile, _still, reduced = r.u(3), r.u(1), r.u(1)
        if profile > 2:
            U("an AV1 seq_profile out of range")
        if reduced:
            level = r.u(5)
        else:
            dm_info, n = False, 0
            if r.u(1):                           # timing_info_present_flag
                r.u(32)
                r.u(32)
                if r.u(1):                       # equal_picture_interval: num_ticks_per_picture_minus_1, uvlc()
                    z = 0
                    while not r.u(1):
                        z += 1
                        if z > 31:
                            raise ValueError("a uvlc longer than 32 bits")
                    r.u(z)
                dm_info = bool(r.u(1))           # decoder_model_info_present_flag
                if dm_info:
                    n = r.u(5) + 1
                    r.u(32)
                    r.u(5)
                    r.u(5)
            idd = r.u(1)                         # initial_display_delay_present_flag
            level = None
            for k in range(r.u(5) + 1):          # operating points
                r.u(12)
                lv = r.u(5)
                if k == 0:
                    level = lv
                if lv > 7:
                    r.u(1)
                if dm_info and r.u(1):
                    r.u(n)
                    r.u(n)
                    r.u(1)
                if idd and r.u(1):
                    r.u(4)
        wb, hb = r.u(4) + 1, r.u(4) + 1
        width, height = r.u(wb) + 1, r.u(hb) + 1
        if not reduced and r.u(1):               # frame_id_numbers_present_flag
            r.u(4)
            r.u(3)
        r.u(3)                                   # 128x128 superblock, filter intra, intra edge filter
        if not reduced:
            r.u(4)                               # interintra, masked compound, warped motion, dual filter
            order_hint = r.u(1)
            if order_hint:
                r.u(2)                           # jnt_comp, ref_frame_mvs
            force_sct = 2 if r.u(1) else r.u(1)  # seq_choose_screen_content_tools, else seq_force_screen_content_tools
            if force_sct > 0 and not r.u(1):     # seq_choose_integer_mv, else seq_force_integer_mv
                r.u(1)
            if order_hint:
                r.u(3)
        r.u(3)                                   # superres, cdef, restoration
        high = r.u(1)
        depth = (12 if r.u(1) else 10) if profile == 2 and high else (10 if high else 8)
        mono = 0 if profile == 1 else r.u(1)
        pri = trc = mat = 2
        if r.u(1):                               # color_description_present_flag
            pri, trc, mat = r.u(8), r.u(8), r.u(8)
        csp = 0
        if mono:
            full, sub = r.u(1), (1, 1)
        elif pri == 1 and trc == 13 and mat == 0:
            full, sub = 1, (0, 0)
        else:
            full = r.u(1)
            if profile == 0:
                sub = (1, 1)
            elif profile == 1:
                sub = (0, 0)
            elif depth == 12:
                sx = r.u(1)
                sub = (sx, r.u(1) if sx else 0)
            else:
                sub = (1, 0)
            if sub == (1, 1):
                csp = r.u(2)
        if not mono:
            r.u(1)                               # separate_uv_delta_q
        r.u(1)                                   # film_grain_params_present: the last bit of the header
    except (IndexError, ValueError) as e:
        U(f"the AV1 sequence header does not parse ({e})")
    return {"codec": "av1", "profile": AV1_PROFILES[profile], "level": level, "depth": depth, "mono": bool(mono),
            "sub": sub, "pix_fmt": _fmt_of(sub, depth, bool(mono)), "range": "pc" if full else "tv",
            "primaries": COLOR_PRIMARIES.get(pri), "transfer": COLOR_TRANSFER.get(trc), "matrix": COLOR_SPACE.get(mat),
            "chroma_loc": {1: "left", 2: "topleft"}.get(csp), "chroma_loc_stated": bool(csp),
            "max_width": width, "max_height": height}


def av1c_header(body: bytes):
    """The parsed sequence header of an av1C record, or Unknown. The record's own profile, level, bit depth, mono
    and subsampling fields must agree with the sequence header OBU it carries (one OBU of that type, parsed whole)."""
    if len(body) < 4 or body[0] != 0x81:
        U("not an AV1CodecConfigurationRecord (marker 1, version 1)")
    profile, level = body[1] >> 5, body[1] & 0x1F
    high, twelve, mono = (body[2] >> 6) & 1, (body[2] >> 5) & 1, (body[2] >> 4) & 1
    sub = ((body[2] >> 3) & 1, (body[2] >> 2) & 1)
    i, seqs = 4, []
    while i < len(body):
        h = body[i]
        kind, ext, has_size = (h >> 3) & 0x0F, (h >> 2) & 1, (h >> 1) & 1
        i += 1 + ext
        if not has_size:
            U("a config OBU without a size field")
        size, i = _leb128(body, i)
        if i + size > len(body):
            U("a config OBU that is cut")
        if kind == 1:
            seqs.append(av1_sequence(body[i:i + size]))
        i += size
    if len(seqs) != 1:
        U(f"an av1C with {len(seqs)} sequence header OBUs")
    q = seqs[0]
    depth = 12 if twelve else 10 if high else 8
    if (AV1_PROFILES.get(profile), level, depth, bool(mono), sub) != (q["profile"], q["level"], q["depth"], q["mono"],
                                                                      q["sub"] if not mono else (1, 1)):
        U("the av1C record and its sequence header OBU disagree")
    return q


def vp9_frame_header(frame: bytes):
    """The facts of the uncompressed header of a VP9 key frame (VP9 6.2), or Unknown (an inter frame states no colour
    config, and a superframe index or a frame that does not start a key frame is not read)."""
    r = _Plain(frame[:64])
    try:
        if r.u(2) != 2:
            U("not a VP9 frame (frame_marker)")
        lo, hi = r.u(1), r.u(1)
        profile = (hi << 1) | lo
        if profile == 3 and r.u(1):
            U("a VP9 reserved bit set")
        if r.u(1):                               # show_existing_frame
            U("a VP9 frame that shows an earlier one")
        if r.u(1) != 0:                          # frame_type: 0 is a key frame
            U("the first VP9 frame is not a key frame")
        r.u(1)                                   # show_frame
        r.u(1)                                   # error_resilient_mode
        if (r.u(8), r.u(8), r.u(8)) != (0x49, 0x83, 0x42):
            U("a VP9 key frame without its sync code")
        depth = (12 if r.u(1) else 10) if profile >= 2 else 8
        space = r.u(3)
        if space != 7:
            full = r.u(1)
            if profile in (1, 3):
                sub = (r.u(1), r.u(1))
                if r.u(1):
                    U("a VP9 reserved bit set")
            else:
                sub = (1, 1)
        else:
            full, sub = 1, (0, 0)
            if profile in (1, 3) and r.u(1):
                U("a VP9 reserved bit set")
        width, height = r.u(16) + 1, r.u(16) + 1
    except IndexError as e:
        U(f"the VP9 frame header does not parse ({e})")
    return {"codec": "vp9", "profile": VP9_PROFILES[profile], "level": None, "depth": depth, "mono": False, "sub": sub,
            "pix_fmt": "gbrp" if space == 7 and depth == 8 else (f"gbrp{depth}le" if space == 7 else _fmt_of(sub, depth)),
            "range": "pc" if full else "tv", "matrix": VP9_SPACE.get(space), "frame_width": width,
            "frame_height": height}


def vpcc_record(body: bytes):
    """(profile, bit depth, subsampling, full range) of an mp4 vpcC box (version 1), or Unknown."""
    if len(body) < 12 or body[0] != 1:
        U("not a vpcC version 1 record")
    profile, depth, chroma, full = body[4], body[6] >> 4, (body[6] >> 1) & 7, body[6] & 1
    sub = {0: (1, 1), 1: (1, 1), 2: (1, 0), 3: (0, 0)}.get(chroma)
    if sub is None or profile > 3:
        U("a vpcC chroma subsampling or profile out of range")
    return profile, depth, sub, full


def header_of(codec: str, record: bytes = None, frame: bytes = None):
    """(parsed header or None, why) of an AV1 or VP9 stream: AV1 from its av1C record; VP9 from its first frame,
    held against the vpcC record when there is one."""
    try:
        if codec == "av1":
            if not record:
                return None, "no av1C record"
            return av1c_header(record), None
        if frame is None:
            return None, "the first VP9 frame is not located"
        h = vp9_frame_header(frame)
        if record is not None:
            profile, depth, sub, full = vpcc_record(record)
            if (VP9_PROFILES[profile], depth, sub, "pc" if full else "tv") != (h["profile"], h["depth"], h["sub"], h["range"]):
                return None, "the vpcC record and the first frame's header disagree"
        return h, None
    except M.Unknown as e:
        return None, str(e)
    except (struct.error, IndexError, ValueError) as e:
        return None, f"the {codec} header does not parse ({type(e).__name__})"


def header_forms(h, field):
    """[(name, text)] of a field an AV1 or VP9 header states, or Unknown."""
    if field == "profile":
        return [("ffprobe", h["profile"]), ("lower", h["profile"].lower())]
    if field == "level":
        if h["level"] is None:
            U(f"ffprobe prints no level of a {h['codec']} stream (-99)")
        return [("ffprobe", str(h["level"]))]
    if field == "pix_fmt":
        if not h.get("pix_fmt"):
            U("a subsampling or bit depth the decoder's table does not name")
        return [("ffprobe", h["pix_fmt"])]
    if field == "color_range":
        return [("ffprobe", h["range"])]
    if field in COLOUR_KEYS:
        v = h.get(COLOUR_KEYS[field])
        if not v:
            U(f"the {h['codec']} stream states no {field.replace('_', ' ')} ffmpeg names")
        return [("ffprobe", v)]
    if field == "chroma_location" and h.get("chroma_loc_stated") and h.get("chroma_loc"):
        return [("ffprobe", h["chroma_loc"])]
    U(f"{field} of a {h['codec']} stream is not read from its header")


MPEG_RATES = {1: fractions.Fraction(24000, 1001), 2: fractions.Fraction(24), 3: fractions.Fraction(25),
              4: fractions.Fraction(30000, 1001), 5: fractions.Fraction(30), 6: fractions.Fraction(50),
              7: fractions.Fraction(60000, 1001), 8: fractions.Fraction(60)}
MPEG2_PROFILES = {1: "High", 2: "Spatially Scalable", 3: "SNR Scalable", 4: "Main", 5: "Simple"}
MPEG2_CHROMA = {1: "yuv420p", 2: "yuv422p", 3: "yuv444p"}


def mpeg2_sequence(es: bytes):
    """{codec, width, height, fps, sps} of the first MPEG-1/2 sequence header (00 00 01 B3) in an elementary stream
    and its sequence extension (00 00 01 B5, id 1) when there is one (the Day 19 look-ahead's item 4), or None.
    The frame rate is the code's, times (n + 1) / (d + 1) of the extension (ffmpeg's mpeg12dec)."""
    i = es.find(b"\x00\x00\x01\xb3")
    if i < 0 or i + 12 > len(es):
        return None
    b = es[i + 4:i + 12]
    w, h, code = (b[0] << 4) | (b[1] >> 4), ((b[1] & 0x0F) << 8) | b[2], b[3] & 0x0F
    if not w or not h or code not in MPEG_RATES:
        return None
    out = {"codec": "mpeg1video", "width": w, "height": h}
    fps = MPEG_RATES[code]
    j = es.find(b"\x00\x00\x01\xb5", i + 12, i + 4096)
    if j >= 0 and j + 10 <= len(es) and es[j + 4] >> 4 == 1:
        e = es[j + 4:j + 10]
        pl = ((e[0] & 0x0F) << 4) | (e[1] >> 4)
        chroma = (e[1] >> 1) & 3
        hx, vx = ((e[1] & 1) << 1) | (e[2] >> 7), (e[2] >> 5) & 3
        n, dd = (e[5] >> 5) & 3, e[5] & 0x1F
        fps = fps * (n + 1) / (dd + 1)
        out.update(codec="mpeg2video", width=w | (hx << 12), height=h | (vx << 12))
        out["sps"] = {"codec": "mpeg2video", "width": out["width"], "height": out["height"], "coded_width": None,
                      "coded_height": None, "sar": None, "profile": None if pl & 0x80 else MPEG2_PROFILES.get((pl >> 4) & 7),
                      "level": None if pl & 0x80 else pl & 0x0F, "pix_fmt": MPEG2_CHROMA.get(chroma), "depth": 8}
    out["avg_fps"] = fps
    if out["codec"] == "mpeg2video":   # ffprobe's r_frame_rate of an MPEG-1 stream is its own guess (50/1 for 25 fps)
        out["fps"] = fps
    return out


# ====================================================================== 2. the container's geometry (mp4 / mov)

IDENTITY = (0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)
SPS_BOX = {"avc1": "avcC", "avc3": "avcC", "hvc1": "hvcC", "hev1": "hvcC"}
SPS_CODECS = {"h264", "hevc"}


def rotation_of(m) -> int:
    """ffmpeg's av_display_rotation_get of an mp4 display matrix (a, b, u, c, d, v, x, y, w), as ffprobe prints it
    (an int, truncated toward zero; -0 is 0)."""
    a, b, c, d = (x / 65536.0 for x in (m[0], m[1], m[3], m[4]))
    s0, s1 = math.hypot(a, c), math.hypot(b, d)
    if not s0 or not s1:
        U("a display matrix that scales to nothing")
    r = -math.degrees(math.atan2(b / s1, a / s0))
    return int(r) + 0


# Review of the Day 19 build (second round): ffmpeg's mov_read_tkhd multiplies the track's matrix by the movie's (mvhd)
# before it reads the rotation, so an mvhd matrix turned by 90 degrees over an identity tkhd is ffprobe's rotation -90.
# The composed matrix is what the identity check and rotation_of read; a file with no single mvhd in the moov that
# holds the track is not read (identity False, rotation None: the shape word 'rotated', the rotation Unknown).

def movie_matrix(d: bytes, trak, boxes):
    """The mvhd display matrix of the moov that holds `trak`, or None when there is not exactly one readable mvhd."""
    moov = [(s, e) for k, s, e in boxes(d, 0, len(d)) if k == "moov" and s <= trak[0] < e]
    if len(moov) != 1:
        return None
    mvhd = [(s, e) for k, s, e in boxes(d, moov[0][0], moov[0][1]) if k == "mvhd"]
    if len(mvhd) != 1:
        return None
    s, e = mvhd[0]
    at = s + (48 if d[s] == 1 else 36)
    if at + 36 > e:
        return None
    return struct.unpack_from(">9i", d, at)


def compose(tk, mv):
    """ffmpeg's res_display_matrix of mov_read_tkhd: the track matrix times the movie matrix, row-major 3x3 tuples,
    each product shifted right by 16, 16 and 30 by its inner index (an arithmetic shift, as on int64)."""
    sh = (16, 16, 30)
    out = []
    for i in range(3):
        for j in range(3):
            out.append(sum((tk[3 * i + k] * mv[3 * k + j]) >> sh[k] for k in range(3)))
    return tuple(out)


def mp4_geometry(d: bytes, trak, entry, fourcc: str, boxes):
    """{matrix, rotation, pasp, clap, sps, sps_why} of an mp4 video track; `trak` and `entry` are (start, end) of the
    trak body and of the sample entry body, `boxes` readers_media's box lister."""
    g = {}
    tkhd = [(s, e) for k, s, e in boxes(d, trak[0], trak[1]) if k == "tkhd"]
    if len(tkhd) == 1 and tkhd[0][1] - tkhd[0][0] >= 84:
        e = tkhd[0][1]
        tk = struct.unpack_from(">9i", d, e - 44)
        mv = movie_matrix(d, trak, boxes)
        g["tkhd_matrix"], g["mvhd_matrix"] = tk, mv
        if mv is None:
            # no single mvhd: ffmpeg would compose the track matrix with a movie matrix this reader cannot see
            g["matrix"], g["identity"], g["rotation"] = tk, False, None
        else:
            m = compose(tk, mv)
            g["matrix"] = m
            g["identity"] = m == IDENTITY
            try:
                g["rotation"] = rotation_of(m)
            except M.Unknown:
                g["rotation"] = None
    kids = boxes(d, entry[0] + 78, entry[1]) if entry[1] - entry[0] >= 78 else []
    for kind in ("pasp", "clap"):
        hits = [(s, e) for k, s, e in kids if k == kind]
        if len(hits) > 1:
            g[f"{kind}_many"] = True
        elif hits:
            s, e = hits[0]
            if kind == "pasp" and e - s >= 8:
                g["pasp"] = struct.unpack_from(">II", d, s)
            elif kind == "clap" and e - s >= 32:
                v = struct.unpack_from(">8I", d, s)
                g["clap"] = (fractions.Fraction(v[0], v[1] or 1), fractions.Fraction(v[2], v[3] or 1))
            else:
                g[f"{kind}_cut"] = True
    want = SPS_BOX.get(fourcc)
    if want:
        hits = [(s, e) for k, s, e in kids if k == want]
        if len(hits) == 1:
            g["sps"], g["sps_why"] = config_sps(want, d[hits[0][0]:hits[0][1]])
        else:
            g["sps"], g["sps_why"] = None, f"{len(hits)} {want} boxes in the sample entry"
        if g["sps"]:
            _inband(g, d, trak, want, d[hits[0][0]:hits[0][1]], boxes)
    codec = {"av01": "av1", "vp09": "vp9"}.get(fourcc)
    if codec:                                    # the Day 20 build: the AV1 or VP9 header (s['header'], not the SPS)
        rec = [(s, e) for k, s, e in kids if k == ("av1C" if codec == "av1" else "vpcC")]
        if len(rec) > 1:
            g["header"], g["header_why"] = None, "two configuration records"
        else:
            frame = None
            if codec == "vp9":
                try:
                    where = _first_sample(d, trak, boxes)
                except (struct.error, IndexError):
                    where = None
                frame = d[where[0]:where[1]] if where else None
            g["header"], g["header_why"] = header_of(codec, d[rec[0][0]:rec[0][1]] if rec else None, frame)
    return g


# Review of the Day 19 build: ffprobe decodes the first frames, and an SPS sent in the stream itself (repeated headers,
# avc3/hev1) is the one its decoder takes, whatever avcC or hvcC states. The first sample of the track is read (the
# sample table's first chunk offset and first size, or a fragmented file's first trun) and every SPS NAL unit in it is
# parsed; one that differs from the configuration record's replaces it as the stream's SPS (g['sps_inband'] True),
# one that does not parse, or a first sample that cannot be located, leaves the SPS unread. Only the first sample is
# read (a key frame, where an encoder repeats its headers); a different SPS first sent later in the stream is not seen.

def _first_sample(d: bytes, trak, boxes):
    """(start, end) of the first sample of a track, or None when it cannot be located."""
    def child(a, b, kind):
        hits = [(s, e) for k, s, e in boxes(d, a, b) if k == kind]
        return hits[0] if len(hits) == 1 else None
    mdia = child(trak[0], trak[1], "mdia")
    minf = mdia and child(mdia[0], mdia[1], "minf")
    stbl = minf and child(minf[0], minf[1], "stbl")
    if not stbl:
        return None
    stsz = child(stbl[0], stbl[1], "stsz")
    if not stsz or stsz[1] - stsz[0] < 12:
        return None
    size1, count = struct.unpack_from(">II", d, stsz[0] + 4)
    if count:
        size = size1 or (struct.unpack_from(">I", d, stsz[0] + 12)[0] if stsz[1] - stsz[0] >= 16 else 0)
        co = child(stbl[0], stbl[1], "stco")
        c64 = child(stbl[0], stbl[1], "co64")
        if co and not c64 and co[1] - co[0] >= 12 and struct.unpack_from(">I", d, co[0] + 4)[0]:
            off = struct.unpack_from(">I", d, co[0] + 8)[0]
        elif c64 and not co and c64[1] - c64[0] >= 16 and struct.unpack_from(">I", d, c64[0] + 4)[0]:
            off = struct.unpack_from(">Q", d, c64[0] + 8)[0]
        else:
            return None
        return (off, off + size) if size and off + size <= len(d) else None
    # a fragmented file: the first trun of this track in the first moof that holds one
    tkhd = child(trak[0], trak[1], "tkhd")
    if not tkhd:
        return None
    tid = struct.unpack_from(">I", d, tkhd[0] + (20 if d[tkhd[0]] == 1 else 12))[0]
    trex = {}
    for k, a, b in boxes(d, 0, len(d)):
        if k == "moov":
            mvex = child(a, b, "mvex")
            for k2, a2, b2 in (boxes(d, mvex[0], mvex[1]) if mvex else []):
                if k2 == "trex" and b2 - a2 >= 24 and struct.unpack_from(">I", d, a2 + 4)[0] == tid:
                    trex["size"] = struct.unpack_from(">I", d, a2 + 16)[0]
        if k != "moof":
            continue
        moof = a - 8 if d[a - 4:a] == b"moof" else None
        if moof is None:
            return None                          # a 64-bit moof header: not read
        for k2, a2, b2 in boxes(d, a, b):
            if k2 != "traf":
                continue
            tfhd = child(a2, b2, "tfhd")
            if not tfhd or struct.unpack_from(">I", d, tfhd[0] + 4)[0] != tid:
                continue
            flags = int.from_bytes(d[tfhd[0] + 1:tfhd[0] + 4], "big")
            i, base, dsize = tfhd[0] + 8, moof, trex.get("size", 0)
            if flags & 0x1:
                base = struct.unpack_from(">Q", d, i)[0]
                i += 8
            i += 4 if flags & 0x2 else 0
            i += 4 if flags & 0x8 else 0
            if flags & 0x10:
                dsize = struct.unpack_from(">I", d, i)[0]
            truns = [(s, e) for k3, s, e in boxes(d, a2, b2) if k3 == "trun"]
            if not truns:
                continue
            t = truns[0][0]
            tflags = int.from_bytes(d[t + 1:t + 4], "big")
            if not struct.unpack_from(">I", d, t + 4)[0] or not tflags & 0x1:
                return None
            off = base + struct.unpack_from(">i", d, t + 8)[0]
            j = t + 12 + (4 if tflags & 0x4 else 0) + (4 if tflags & 0x100 else 0)
            size = struct.unpack_from(">I", d, j)[0] if tflags & 0x200 else dsize
            return (off, off + size) if size and 0 <= off and off + size <= len(d) else None
    return None


def _inband(g, d: bytes, trak, kind: str, record: bytes, boxes):
    try:
        where = _first_sample(d, trak, boxes)
    except (struct.error, IndexError):
        where = None
    if where is None:
        g["sps"], g["sps_why"] = None, "the track's first sample is not located, so an SPS sent in the stream is not read"
        return
    n = (record[4] & 3) + 1 if kind == "avcC" else (record[21] & 3) + 1 if len(record) > 21 else 4
    sample, i, found = d[where[0]:where[1]], 0, []
    while i + n <= len(sample):
        ln = int.from_bytes(sample[i:i + n], "big")
        nal = sample[i + n:i + n + ln]
        if not ln or len(nal) != ln:
            g["sps"], g["sps_why"] = None, "the track's first sample does not split into NAL units"
            return
        if (kind == "avcC" and nal[0] & 0x1F == 7) or (kind == "hvcC" and (nal[0] >> 1) & 0x3F == 33):
            found.append(nal)
        i += n + ln
    if i != len(sample):
        g["sps"], g["sps_why"] = None, "the track's first sample does not split into NAL units"
        return
    parsed = []
    for nal in found:
        try:
            parsed.append(h264_sps(nal) if kind == "avcC" else hevc_sps(nal))
        except M.Unknown as e:
            g["sps"], g["sps_why"] = None, f"an SPS sent in the stream does not parse ({e})"
            return
    if any(p != parsed[0] for p in parsed[1:]):
        g["sps"], g["sps_why"] = None, "the SPS sent in the stream's first sample disagree"
        return
    if parsed and parsed[0] != g["sps"]:
        g["sps"], g["sps_inband"] = parsed[0], True


def mkv_geometry(codec: str, private: bytes):
    if codec not in SPS_CODECS or not private:
        return {}
    sps, why = config_sps("avcC" if codec == "h264" else "hvcC", private)
    return {"sps": sps, "sps_why": why}


MKV_FIRST_WINDOW = 1 << 22    # bytes of a Matroska file walked for a track's first block (the first clusters)
MKV_FIRST_STEPS = 4096        # elements looked at on that walk


def _vint(d: bytes, i: int, size: bool):
    if i >= len(d) or d[i] == 0:
        raise ValueError("an EBML number that is not read")
    n = 8 - d[i].bit_length() + 1
    v = int.from_bytes(d[i:i + n], "big")
    if size:
        v &= (1 << (7 * n)) - 1
    return v, i + n, n


def mkv_first_frame(d: bytes, track: int):
    """The first frame of track `track` in the first clusters of a Matroska file (a SimpleBlock, or a BlockGroup's
    Block, without lacing), or None. Bounded: MKV_FIRST_WINDOW bytes, MKV_FIRST_STEPS elements."""
    end_all = min(len(d), MKV_FIRST_WINDOW)
    steps = 0

    def walk(a, b, depth):
        nonlocal steps
        i = a
        while i < b:
            steps += 1
            if steps > MKV_FIRST_STEPS:
                return None
            eid, j, _ = _vint(d, i, False)
            sz, j, n = _vint(d, j, True)
            unknown = sz == (1 << (7 * n)) - 1
            e = b if unknown else min(j + sz, b)
            if eid in (0x18538067, 0x1F43B675, 0xA0) and depth < 3:   # Segment, Cluster, BlockGroup
                got = walk(j, e, depth + 1)
                if got is not None:
                    return got
            elif eid in (0xA3, 0xA1):                                  # SimpleBlock, Block
                tn, k, _ = _vint(d, j, True)
                if tn == track and k + 3 <= e:
                    if (d[k + 2] >> 1) & 3:
                        return b""                                    # laced: not read
                    return d[k + 3:e]
            if unknown and eid not in (0x18538067, 0x1F43B675):
                return None
            i = e
        return None
    try:
        if d[:4] != b"\x1a\x45\xdf\xa3":
            return None
        _, j, _ = _vint(d, 0, False)
        sz, j, _ = _vint(d, j, True)
        got = walk(j + sz, end_all, 0)
    except (ValueError, IndexError):
        return None
    return got or None


def mkv_header(codec: str, private, d: bytes, track):
    """{header, header_why} of an AV1 or VP9 Matroska track (the Day 20 build), or {}."""
    if codec not in HEADER_CODECS:
        return {}
    if codec == "av1":
        h, why = header_of("av1", private or None)
    else:
        frame = mkv_first_frame(d, track) if track else None
        h, why = header_of("vp9", None, frame)
    return {"header": h, "header_why": why}


# ====================================================================== 3. the guard and the stream size

def _sar(s):
    """The sample aspect ratio ffprobe prints for a stream (av_guess_sample_aspect_ratio: the container's pasp when
    it is valid, else the codec's), as (num, den), or Unknown."""
    p = s.get("pasp")
    if p and p[0] and p[1]:
        return p
    sps = s.get("sps")
    if sps and sps.get("sar"):
        return sps["sar"]
    if sps and sps.get("sar_unread"):
        U("the HEVC SPS's VUI (its SAR) is not read, and the track has no pasp")
    U("neither the container nor the codec states a sample aspect ratio")


def guard(info, s):
    """(shape words, stream size) of a video stream of an mp4: an empty list is the judged shape (Day 18)."""
    words, stsd = [], (s.get("width"), s.get("height"))
    sps = s.get("sps")
    size = (sps["width"], sps["height"]) if sps else stsd
    if not sps:
        # Review of the Day 19 build: a codec whose header this pack does not parse (MPEG-4 part 2, AV1, VP9, MJPEG,
        # ProRes) has no size of its own to hold stsd against, and a sample entry that lies was answered plain.
        words.append("sps_unread")
    elif s.get("sps_inband") or size != stsd:
        words.append("sps_differs")
    if "identity" not in s or not s["identity"]:
        words.append("rotated")
    p = s.get("pasp")
    vui = sps.get("sar") if sps else None
    if s.get("pasp_many") or s.get("pasp_cut") or (p and p[0] != p[1]) or (vui and vui[0] != vui[1]) or \
            (sps and sps.get("sar_unread") and not p):
        words.append("anamorphic")
    if s.get("clap") or s.get("clap_many") or s.get("clap_cut"):
        words.append("clap")
    td = s.get("tkhd_dims")
    if not td or td != stsd:
        words.append("tkhd_differs")
    # Review of the Day 19 build (second round): Day 18's judged shape had one video track. With two, 'primary' is
    # read as the first stream (index 0) while ffprobe's default disposition may name another, so the size of a file
    # with more than one video stream is never the judged key's.
    # Review round 3: readers_media types a track by its hdlr, ffmpeg by its sample entry, so a visual sample entry
    # under another handler ('text' over avc1) is a video stream to ffprobe; it is counted here whatever the hdlr.
    if sum(1 for x in (info.get("streams") or []) if _visual_track(x)) > 1:
        words.append("tracks")
    return words, size


# Visual sample entries (ISO 14496-12 VisualSampleEntry codes ffmpeg's mov demuxer reads as video).
VISUAL_ENTRIES = frozenset(("avc1", "avc2", "avc3", "avc4", "hvc1", "hev1", "dvh1", "dvhe", "dvav", "dva1", "av01", "vp08",
                            "vp09", "mp4v", "s263", "h263", "H263", "jpeg", "mjpa", "mjpb", "mjp2", "png ", "raw ", "rle ",
                            "cvid", "smc ", "8BPS", "SVQ1", "SVQ3", "mp1v", "mp2v", "encv", "resv", "vvc1", "vvi1", "apco",
                            "apcs", "apcn", "apch", "ap4h", "ap4x", "dvc ", "dvcp", "dv5n", "dv5p", "xd5b", "AVdn", "AVdh"))
_NOT_VISUAL = frozenset(("audio", "subtitle"))


def _visual_track(x):
    """A stream ffprobe shows as video: the hdlr says so, the sample entry is a visual one, or (any other entry) the
    track has a tkhd size and is neither audio nor a subtitle by its hdlr."""
    if x.get("type") == "video" or x.get("sample_entry") in VISUAL_ENTRIES:
        return True
    td = x.get("tkhd_dims")
    return bool(td and td[0] and td[1]) and x.get("type") not in _NOT_VISUAL and "sample_entry" in x


def _display(s, size):
    """The displayed size: the stream size stretched by its SAR, turned by a quarter rotation; None when unsettled."""
    try:
        a, b = _sar(s)
    except M.Unknown:
        a, b = 1, 1
        if s.get("pasp") is None and s.get("sps") and s["sps"].get("sar_unread"):
            return None
    w, h = size
    dw = (fractions.Fraction(w * a, b) + fractions.Fraction(1, 2)).__floor__()
    rot = s.get("rotation")
    if rot is None:
        return None
    return (h, dw) if abs(rot) % 180 == 90 else (dw, h)


def dimension_forms(info, s, field):
    """[(name, text)] and the key's shape of dimensions, width or height of a video stream (row 361)."""
    c = info["container"]
    w0, h0 = s.get("width"), s.get("height")
    if c != "mp4":
        sps = s.get("sps")
        if not sps or (sps["width"], sps["height"]) == (w0, h0):
            return None                          # readers_media.py's own reading, as before
        size, shape = (sps["width"], sps["height"]), f"{c}+sps_differs"
        stsd_name = "container"
    else:
        if w0 is None or h0 is None:
            U(f"the size of this {c} stream is not read")
        words, size = guard(info, s)
        shape = "+".join([c] + words)
        stsd_name = "sample_entry"
    if field in ("width", "height"):
        i = 0 if field == "width" else 1
        forms = [("integer", str(size[i])), (stsd_name, str((w0, h0)[i]))]
        return forms, shape
    forms = [("wxh", f"{size[0]}x{size[1]}")]
    if c == "mp4" and shape != c:
        disp = _display(s, size)
        if disp:
            forms.append(("display", f"{disp[0]}x{disp[1]}"))
        forms.append((stsd_name, f"{w0}x{h0}"))
        td = s.get("tkhd_dims")
        if td and all(td):
            forms.append(("track_header", f"{td[0]}x{td[1]}"))
    elif c != "mp4":
        forms.append((stsd_name, f"{w0}x{h0}"))
    return forms, shape


# ====================================================================== 4. the new stream fields

GEOMETRY = {"coded_width", "coded_height", "coded_dimensions", "display_dimensions", "rotation", "sar", "dar",
            "profile", "level", "pix_fmt", "video_bits",
            "color_range", "color_space", "color_transfer", "color_primaries", "chroma_location"}   # Day 20
COLOUR_KEYS = {"color_space": "matrix", "color_transfer": "transfer", "color_primaries": "primaries"}


def colour_forms(sps, field):
    """[(name, text)] of a colour field of a parsed H.264 or HEVC SPS (its VUI) or an AV1 or VP9 header, or Unknown.
    Only a value the stream states, in ffmpeg's name, and the two defaults ffmpeg's decoders export where nothing is
    stated: the video range of HEVC, AV1 and VP9 ('tv'), and the chroma location of H.264 and HEVC ('left' for a
    chroma format other than 4:0:0). Everything else ffprobe prints as unknown (or leaves out), which is None here."""
    codec = sps.get("codec")
    if field == "color_range":
        v = sps.get("range")
        if not v:
            U(f"the {codec} stream states no video range (ffprobe: unknown)")
        return [("ffprobe", v)]
    if field in COLOUR_KEYS:
        v = sps.get(COLOUR_KEYS[field])
        if not v:
            U(f"the {codec} stream states no {field.replace('_', ' ')} ffmpeg names")
        return [("ffprobe", v)]
    if sps.get("chroma_loc_stated"):
        if not sps.get("chroma_loc"):
            U("a chroma sample location out of the table")
        return [("ffprobe", sps["chroma_loc"])]
    # ffmpeg's defaults where a VUI that is read whole states no chroma location: H.264 left for any chroma format
    # (ffprobe: 4:2:0 and 4:4:4 seen), HEVC left for 4:2:0 only (a 4:4:4 HEVC stream is unspecified to ffprobe). An SPS
    # with no VUI at all ({'vui': False}) is not given the default: ffmpeg sets it only while it parses a VUI, and an
    # H.264 stream with none is unspecified to ffprobe (review of the Day 20 build: VideoToolbox's output)
    if sps.get("vui") and not sps.get("vui_cut") and (sps.get("chroma") == 1 or (codec == "h264" and sps.get("chroma") in (2, 3))):
        return [("ffprobe", "left")]
    U(f"the chroma location of this {codec} stream is not stated (or its VUI is not read whole)")


def _unique2(forms):
    out, seen = [], set()
    for n, v in forms:
        if v not in seen:
            seen.add(v)
            out.append((n, v))
    return out


def _ratio(a: int, b: int):
    g = math.gcd(a, b) or 1
    return a // g, b // g


def stream_forms(info, s, field, shape):
    """[(name, text)] and the key's shape of a field this pack reads (GEOMETRY), or Unknown."""
    c = info["container"]
    sps = s.get("sps")
    if field == "profile" and s["type"] == "audio":
        p = s.get("aac_profile")
        if not p:
            U(f"the profile of this {c} audio stream is not read")
        return [("ffprobe", p), ("lower", p.lower())], shape
    if s["type"] != "video":
        U(f"{field} is read for a video stream only")
    if field == "rotation":
        if c != "mp4":
            U(f"the rotation of a {c} stream is not read")
        rot = s.get("rotation")
        if rot is None:
            U("the track's display matrix is not read")
        forms = [("ffprobe", str(rot)), ("negated", str(-rot + 0)), ("degrees_0_359", str(rot % 360)),
                 ("clockwise_0_359", str(-rot % 360))]
        return forms, shape
    if field in ("sar", "dar"):
        a, b = _sar(s)
        if field == "sar":
            a, b = _ratio(a, b)
            return [("ffprobe", f"{a}:{b}"), ("ratio", f"{a}/{b}")], shape
        if not sps and c == "mp4" and s.get("codec") in SPS_CODECS:
            U("the stream size is not read")
        w, h = (sps["width"], sps["height"]) if sps else (s.get("width"), s.get("height"))
        if not w or not h:
            U("the stream size is not read")
        q = MED.av_reduce(w * a, h * b, 1024 * 1024)
        return [("ffprobe", f"{q.numerator}:{q.denominator}"), ("ratio", f"{q.numerator}/{q.denominator}")], shape
    if field == "display_dimensions":
        if c != "mp4":
            U(f"the display size of a {c} stream is not read")
        size = (sps["width"], sps["height"]) if sps else (s.get("width"), s.get("height"))
        if s.get("codec") in SPS_CODECS and not sps:
            U(f"the {s['codec']} stream's own size is not read ({s.get('sps_why')})")
        disp = _display(s, size)
        if not disp:
            U("the displayed size is not settled (no SAR or no display matrix read)")
        forms = [("wxh", f"{disp[0]}x{disp[1]}")]
        if abs(s["rotation"]) % 180 == 90:
            forms.append(("unrotated", f"{disp[1]}x{disp[0]}"))
        return forms, shape
    direct = s.get("direct") or {}
    if field in direct:      # a container or codec header that states it (a GIF decodes to bgra)
        return [("ffprobe", direct[field])], shape
    if not sps and s.get("header") and field in HEADER_FIELDS:
        return header_forms(s["header"], field), shape      # the Day 20 build: AV1 and VP9
    if not sps:
        U(f"{field} of a {s.get('codec') or 'video'} stream is read from an H.264, HEVC or MPEG-2 sequence header, or "
          f"an AV1 or VP9 header, only" + (f" ({s.get('sps_why') or s.get('header_why')})"
                                           if s.get("sps_why") or s.get("header_why") else ""))
    if field in COLOUR_KEYS or field in ("color_range", "chroma_location"):
        if sps.get("codec") not in SPS_CODECS:
            U(f"{field} of a {sps.get('codec')} stream is not read")
        return colour_forms(sps, field), shape
    if field in ("coded_width", "coded_height", "coded_dimensions"):
        cw, ch = sps.get("coded_width"), sps.get("coded_height")
        if not cw:
            U("ffprobe's coded size of an HEVC stream is not read here")
        # Review of the Day 19 build: ffprobe prints the padded size only once frames are decoded (-count_frames, as
        # the look-ahead's truth was taken); a plain -show_streams prints the cropped one. Both, padded first.
        w, h = sps["width"], sps["height"]
        if field == "coded_dimensions":
            return _unique2([("wxh", f"{cw}x{ch}"), ("cropped", f"{w}x{h}")]), shape
        i = 0 if field == "coded_width" else 1
        return _unique2([("integer", str((cw, ch)[i])), ("cropped", str((w, h)[i]))]), shape
    if field == "profile":
        if not sps.get("profile"):
            U("a profile ffprobe's table does not name")
        p = sps["profile"]
        return [("ffprobe", p), ("lower", p.lower())], shape
    if field == "level":
        lv = sps["level"]
        if lv is None:
            U("a level ffprobe's table does not name")
        if sps["codec"] not in SPS_CODECS:
            return [("ffprobe", str(lv))], shape
        dotted = f"{lv // 10}.{lv % 10}" if sps["codec"] == "h264" else (f"{lv // 30}" if lv % 30 == 0 else f"{lv / 30:.1f}")
        return [("ffprobe", str(lv)), ("dotted", dotted)], shape
    if field == "pix_fmt":
        if not sps.get("pix_fmt"):
            U("a chroma format or bit depth ffmpeg's table does not name")
        return [("ffprobe", sps["pix_fmt"])], shape
    if field == "video_bits":
        return [("integer", str(sps["depth"]))], shape
    U(f"{field} is not read")


# ====================================================================== 5. mp4 tags

MAC_EPOCH = datetime.datetime(1904, 1, 1, tzinfo=datetime.timezone.utc)


def _f32(x: float) -> float:
    return struct.unpack(">f", struct.pack(">f", x))[0]


def loci_text(body: bytes):
    """ffmpeg's text of a 3GPP `loci` box (mov_metadata_loci): '%+08.4f%+09.4f' of latitude and longitude, the
    altitude as '%+f' when it is not 0, then '/' and the place name. None when the box does not parse."""
    try:
        i = 6                                    # version and flags, language
        end = body.index(b"\x00", i)
        place = body[i:end].decode("utf-8")
        i = end + 2                              # the name's NUL, the role
        lon, lat, alt = (_f32(v / 65536.0) for v in struct.unpack_from(">iii", body, i))
    except (ValueError, struct.error, UnicodeDecodeError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    t = f"{lat:+08.4f}{lon:+09.4f}"
    if alt:
        t += f"{alt:+f}"
    return f"{t}/{place}"


def _boxes(d, a, b):
    try:
        return M._boxes(d, a, b) or []
    except M.Unknown:
        return []


def mp4_tag(d: bytes, field: str, boxes=None):
    """[(name, text)] of an mp4 tag this pack reads, None (absent), or Unknown. `boxes` readers_media's lister."""
    boxes = boxes or _boxes
    if field in ("major_brand", "minor_version", "compatible_brands"):
        if d[4:8] != b"ftyp":
            return None
        size = struct.unpack_from(">I", d, 0)[0]
        if size < 16 or size > len(d) or (size - 16) % 4:
            U("an ftyp box that is cut")
        if field == "major_brand":
            return [("ffprobe", d[8:12].decode("latin-1"))]
        if field == "minor_version":
            return [("integer", str(struct.unpack_from(">I", d, 12)[0]))]
        brands = d[16:size].decode("latin-1")
        out = [("ffprobe", brands)]
        listed = [brands[i:i + 4] for i in range(0, len(brands), 4)]
        out.append(("json_compact", "[" + ",".join(f'"{b}"' for b in listed) + "]"))
        out.append(("comma", ",".join(b.strip() for b in listed)))
        return out
    moov = [(s, e) for k, s, e in boxes(d, 0, len(d)) if k == "moov"]
    if len(moov) != 1:
        U(f"{len(moov)} moov boxes")
    a, b = moov[0]
    if field == "creation_time":
        out = []
        mvhd = [(s, e) for k, s, e in boxes(d, a, b) if k == "mvhd"]
        if len(mvhd) == 1:
            s = mvhd[0][0]
            secs = struct.unpack_from(">Q", d, s + 4)[0] if d[s] == 1 else struct.unpack_from(">I", d, s + 4)[0]
            if secs:
                t = MAC_EPOCH + datetime.timedelta(seconds=secs)
                out += [("ffprobe", t.strftime("%Y-%m-%dT%H:%M:%S.000000Z")), ("iso_z", t.strftime("%Y-%m-%dT%H:%M:%SZ")),
                        ("iso_space", t.strftime("%Y-%m-%d %H:%M:%S"))]
        rm = getattr(M, "MORE_MODULES", {}).get("readers_more.py")
        if rm is not None:
            meta = rm._mp4_meta(d) or {}
            keyed = set(meta.get(b"creationdate", []))
            if len(keyed) > 1:
                U("the file states several creation dates")
            if keyed:
                out.append(("raw", keyed.pop()))
        return out or None
    if field == "location":
        hits = []
        for k, s, e in boxes(d, a, b):
            if k == "udta":
                hits += [(s2, e2) for k2, s2, e2 in boxes(d, s, e) if k2 == "loci"]
        if not hits:
            return None
        texts = {loci_text(d[s:e]) for s, e in hits}
        if None in texts or len(texts) != 1:
            U("a loci box that does not parse, or two that differ")
        return [("raw", texts.pop())]
    U(f"{field} is not read here")


# ====================================================================== registration

def register(module):
    """properties_strict calls this with its own module object. Registers nothing (readers_media.py's grammar asks
    this pack at answer time); returns (0, 0)."""
    global M, MED
    M = module
    MED = getattr(M, "MORE_MODULES", {}).get("readers_media.py")
    for n in ("display", "negated", "degrees_0_359", "clockwise_0_359", "unrotated", "sample_entry", "track_header", "cropped"):
        if n not in M.FORM_NAMES:
            raise RuntimeError(f"the form name {n} is not in properties_strict.FORM_NAMES")
    return (0, 0)
