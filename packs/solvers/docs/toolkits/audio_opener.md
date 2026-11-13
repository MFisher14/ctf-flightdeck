# Toolkit `audio_opener`: the audio drop opener (Morse, DTMF, tones, tags)

File: `solvers/toolkits/audio_opener.py` (engine `toolkits.audio_opener`, B-129). It sits in front of
the keyed-tone decoders carried in `solvers/toolkits/signal_stego_depth.py`. It is offline: libsndfile
decodes in-process, nothing is executed or transcoded on disk, and no network is used.
Tests: `tests/test_toolkits_audio_opener.py`.

## Run first

```
.venv/bin/python solvers/toolkits/audio_opener.py <file-or-folder>... [--event SLUG]
```

Intake runs it with no model on the handout folder whenever any file is audio. That covers members
unpacked from an archive, matched by `magic:RIFF`, `ID3`, an MPEG frame sync, `fLaC`, `OggS`, `FORM`,
or the extensions `.mp3 .wav .flac .ogg .oga .aif .aiff`. Intake runs it only under the OS network
sandbox (`spawns = true`), because soundfile loads libsndfile through ctypes and the hook-only guard
refuses ctypes. Under the hook guard, intake lists it as skipped and names the reason.

## What it prints

For each audio file (sniffed by content):

| line | what |
|---|---|
| `audio <file>: mp3, 44100 Hz, 1 ch, 165.8 s` | the decode. A note follows when only the first 600 s were read, or when the file was mean-decimated to fit the decoder's 12 M sample cap |
| `tag <frame> = <value>` | ID3v2.2/2.3/2.4 frames (text, comments, TXXX, URLs, PRIV/GEOB sizes), ID3v1, and the libsndfile strings (`sndfile.title`, RIFF INFO, Vorbis comments) |
| `APIC:<mime> exif <tag> = <value>` | the EXIF text of a cover picture embedded in the ID3 tag |
| `tones: 548.0 Hz (x... over the floor)` | up to 3 narrow spectral peaks: at least 20x the median power and -20 dB of the strongest. Peaks within 60 Hz of a stronger one count as the same tone (keying sidebands) |
| `keyed at 548.0 Hz: N tone runs, on ms p10/50/90 ..., off ms ..., unit ~25 ms` | the on/off runs of the envelope at that tone. Use it to hand-decode when the lattice refuses |
| `morse (548.0 Hz, 1/3/7 lattice, unit ~25 ms): TEXT` | `decode_morse_tone` keyed at each tone, strongest first, then broadband |
| `dtmf: 0123#` | energy-segmented key presses (30 ms or longer), every one a DTMF key, at least 3 |
| `exif <image>: <tag> = <value>` | every JPEG/PNG/TIFF/WebP in the same folder: ImageDescription, XP comments, UserComment, Artist, Copyright and DateTimeOriginal first |

The last line is a `SolverResult`:

- `candidate`: an event-format flag in a decode, a tag or EXIF.
- `unsure`: Morse or DTMF text was read. It is usually a clue for the agent, quoted in `notes`.
- `none`: nothing found.
- `blocked`: no audio could be decoded because soundfile is missing, or an MP3 met a libsndfile
  without MPEG support. The reason is named. There is no ffmpeg or Docker fallback.

## The Morse decoder (signal_stego_depth.decode_morse_tone)

It returns text only when every tone run is 1 or 3 units and every silence is 1, 3 or 7 units. A run
fits when it is within `tolerance` (default 0.36) of the lattice value. The unit is the median of the
shorter half of the tone runs. B-129 added to the decoder:

- `tone_hz`: keys on the I/Q envelope at that frequency (one value per 5 ms block). Hum, hiss and
  other tones no longer hide the keying. Broadband RMS stays the default.
- `long_gaps`: a silence longer than 7 units reads as a word gap, such as a pause between sentences.
  Tone runs are still checked.
- `"` (`.-..-.`) and `&` (`.-...`) in the table. The Nosocomephobia message quotes a word. Without
  `"` the whole decode returned nothing.
- `keyed_runs`, `tone_levels`, `dtmf_key`: the public steps the opener uses.

Timing check for Nosocomephobia: a 25 ms dot, 75 ms dash and 165 ms word gap. The word gap is 6.6
units, not 7, an error of 0.057 of the lattice value. That fits the default tolerance. It fails
below about 0.06: `test_the_nosocomephobia_timing_fits_the_lattice_only_because_of_the_tolerance`
pins both sides.
