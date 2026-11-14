# Metadata format fixtures

Real encoder output, built on 2026-10-08 for `tests/test_metadata_formats.py`. None of it is
challenge data and nothing here is ever run: the tests only read the bytes. The values the test
asks for are the ones the generating command set, or the ones a second tool printed for the
file (named in the last column).

The source picture is a 64x48 RGB gradient (Pillow). The archive tree is `docs/readme.txt`
(`read me first\n`), `docs/notes.txt`, `data/a.bin` (300 zero bytes) and an empty folder `empty/`,
with the three files' times set to 2026-01-02 03:04:05 US Eastern (08:04:05 UTC).

| File | Built with | Checked against |
| --- | --- | --- |
| `sample.7z` | `7zz a` (7-Zip 25, LZMA2, solid, packed header) | `7zz l -slt` |
| `plain_header.7z` | `7zz a -mhc=off` (the header as it is) | `7zz l -slt` |
| `enc_data.7z` | `7zz a -pinfected` (data encrypted, names readable) | `7zz l -slt` |
| `enc_header.7z` | `7zz a -mhe=on -pinfected` (names encrypted) | nothing may be read |
| `sample.heic` | `heif-enc -q 60` (libheif: 64x64 coded, clean aperture 64x48) | `exiftool` |
| `sample.avif` | `avifenc -q 50` (libavif) | `exiftool` |
| `lossy.webp`, `lossless.webp`, `exif.webp` | `cwebp` (libwebp), `-lossless`, `-metadata exif` | `exiftool` |
| `anim.webp` | Pillow, three frames of 120 ms, loop 2 | the call's arguments |
| `sample.tif` | Pillow, with tags 270, 271, 272, 305, 306, 315 and the DNG tags 50706 (1.4.0.0) and 50708 | `exiftool` |
| `sample.mp4`, `sample.mov` | `ffmpeg` testsrc 64x48 at 5 fps, 0.6 s, `mpeg4` (+ `aac` 8 kHz mono in the mp4), `-movflags +faststart` for the mov | `ffprobe` |
| `sample.mkv`, `sample.webm` | `ffmpeg`, `mpeg4` + `flac` and `libvpx`, title and creation time set | `exiftool` |
| `sample.flac`, `sample.wav` | `ffmpeg` sine 440 Hz at 8 kHz, title and artist set | `ffprobe` |
| `sample.ico` | Pillow, sizes 16, 32, 48 | the call's arguments |
| `sample.pdf` | `pypdf`: one 612x792 page, an Info dictionary with two keys of its own, one URI link | the call's arguments |
| `sample.sqlite` | the `sqlite3` module, page size 512: two tables, an index, a view, a trigger | the schema's own SQL |

Formats with no encoder on the build machine (RAR 4 and 5, LNK, MSI, pcap and pcapng, an MFT
record, OOXML and ODF packages, a cursor, a broadcast WAV, a signed PE, a signed Mach-O) are
built inside the test from their specifications; where a second reader exists the test asks it
(`7zz l` lists the RAR archives; `otool` and `codesign` read a slice of `/bin/ls`; a
Microsoft-signed DLL in the venv is read when it is there).
