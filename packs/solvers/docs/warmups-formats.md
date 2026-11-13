# Warmups formats and Mobile classical ciphers (Day 9 round 2, branch day9b/fmt-warmups)

What round 2 added to the Warmups lane and to Mobile's codec search, what stays unanswered by rule, and how it
was measured. The modules' own docstrings carry the detail; this page is the index.

## Warmups: `solvers/warmups/formats_more.py`, `esolangs.py`, `formats_tables.py`

`crib_decode.py` loads `formats_more.py` by name (an armed export without the file runs as before) and asks it
in three places. Nothing in it answers by itself: a reading counts only when it reproduces the Warmups sentence
in `crib_decode`'s search, behind every reading that was there before (the rival rule of rows 109, 110 and 136
is unchanged).

| Where | Readers | Answer |
| --- | --- | --- |
| strict steps, on every state of the search (chains to depth six, Mastery records) | punycode; base65536, base32768, base2048 (qntm's, and as `b2048r` the Rust crate's and PyPI's, which is another table); Ecoji 1 and 2; emoji letters (regional indicators, squared and circled letters, keycaps); base62 with three more alphabets, base58 Flickr and Ripple; character codes in mixed notations; spelling alphabets beyond ICAO; Morse as dit/dah words, swapped, in any two symbols, as timing bits; Braille by dot numbers; COW, Whitespace, Malbolge, JSFuck (bounded interpreters); since the Day 18 build Roman numerals of the bytes, Braille hex with a number sign before every digit, upside-down text | plain when the sentence is reproduced (upside-down: the digits unsure where a 6 or 9 is among them) |
| late, once per blob when nothing else answered | another keyboard layout (Dvorak, Colemak), a shift of code points, a symbol table read off the sentence, character codes whose base cycles, Befunge-93; since the Day 18 build `hexsym`, sixteen tokens over the text's hex learned from the sentence | plain; the slug's digits unsure where the code cannot prove them (`warmups.digits/<kind>`) |
| lossy | A1Z26, multi-tap, T9, a 6 x 6 Polybius square, flag semaphore as arrows or compass points, a strict reading that lost its marks | ONE unsure option (`warmups.lossy/<code>`), never plain, never sent on a clock |

Already in the lane before round 2 and not rebuilt: base45, base91, base92, base36, base62 (0-9A-Za-z), ICAO
words, Morse, Braille cells, Brainfuck/Ook, the keyed letter ciphers of `solvers/common/classical.py`
(a QWERTY neighbour shift among them).

Stays `None` by rule: T9 where a word shares its keys with another vocabulary word (74 of the 142 saved slug
words do); Bacon of letters, the tap code and a 5 x 5 Polybius square (they cannot carry the slug's two digits;
five-symbol groups of hex nibbles are another code, read as `baconhex` by `crib_decode.py`, row 331, and a 4 x 4
square or tap code over the text's hex another again, read as `hexsym`, row 333); a program
that asks for input, uses randomness, or does not end inside its step cap and the blob's deadline; a Whitespace
program as one numbered Mastery record (it holds line feeds); Piet (an image). JSFuck is read over a fixed
vocabulary only; a program wrapped for `eval` gives its source text and is never run.

Tests: `tests/test_warmups_formats.py` (21 checks, about 15 s; reference vectors in
`tests/fixtures/warmups_formats/reference.json`), with `tests/test_warmups_day9.py` and
`solvers/warmups/selftest.py` unchanged and green.

Measured on 2026-10-08 with `tools/run.py --offline --no-save` on an APFS clone of the saved attempts, before
(ed77d25) and after: all 39 saved Warmups attempts of Days 1 to 8 (332 answers) print identical answers; the
Day 8 Mastery (38 sets) solves in 0.68 s before and 0.70 s after; the synthetic 43-set Mastery of
`tests/test_warmups_day9.py` in 0.94 to 0.95 s before and 0.99 to 1.00 s after (limit 1.5 s), and the one of
`tests/test_warmups_formats.py` (record 09 in base32768) in 0.97 s. The machine was under other load during
both runs.

## Review of round 2 (branch day9b/fmt-warmups-r)

Checked again, independently: the 39 saved Warmups attempts and the 39 saved Mobile attempts of Days 1 to 8 print
the same answers before (ed77d25) and after; qntm's base2048 and base32768 against 400 random encodings each of
the npm packages, base65536 and Ecoji 1 against 600 of the PyPI packages, both Ecoji tables against upstream
`v2/mapping.go`.

Fixed, with `tests/test_warmups_formats_review.py` (12 checks, a few seconds):

- A COW program whose loop skips a long stretch on every pass ran far past its deadline (240 000 instructions
  skipped per pass: 7.9 s against 0.1 s, and up to its 400 000 steps without a print). A jump is now looked for
  once and remembered, and the looking is counted against the clock. A megabyte of Whitespace is no longer
  parsed past the deadline either.
- PyPI's `base2048` (the Rust crate) is not qntm's base2048: none of its encodings was read. It is now the
  strict step `b2048r` (table read off the package's encoder, fixture `base2048_rust.json`).

Known and left as they are:

- A lossy reading (`warmups.lossy/<code>`) is unsure until the judge accepts its method on the base, and plain
  after that. For T9 and for a slug written without breaks the method rests on the vocabulary (one dictionary
  word per key run, one split into three words): a judge's word that is not in the dictionary can then give a
  wrong plain slug on a later variant. Nothing is sent on a clock before the base's acceptance.
- A Mastery record that holds nothing but the slug's two digits in swapped Morse is read as ordinary Morse
  (94 for 49); in any two other symbols both readings compete and the answer is None. Saved records are 13
  characters and more, so the last one has always held a hyphen, which swapped Morse cannot fake.
- Text that ends in one '-' is also read without it (punycode of plain ASCII). Nothing found that this turns
  into a different slug.

## The Day 13 build (2026-10-12, backlog row 269, `tests/test_warmups_day13.py`)

Day 12's encoding is the whole text reversed, and its Mastery record is slug-only (9 or 10 bytes). Until Day
12 the record of a letters-to-letters day was always the last one; from Day 13 on it is record 12 of 13. The
armed solver vouched for the LAST record only (`consensus`, from `ctx['siblings']`): measured on the real
58-set Day 12 Mastery, 58 of 58 with the delivery-wide read and 46 of 58 (12 `None`, 0 wrong) without it, and
3 to 9 of 63 staged sets came back `None` for every thirteenth encoding staged. What `crib_decode.py` does
now, in the words of its own docstring:

- The walk by the days. Numbered records are first read one way only, each by the chain that reads both
  saved blobs of its own day. When together they are the sentence and one slug, cut where the rule of twelve
  days cuts a blob, and every record that gives slug characters is settled (the crib, a strict chain of its
  day, or the delivery's pin), that is the answer and no search is made: 63 sets of 13 records took 1.45 to
  1.8 s and take 0.2 to 0.45 s (the cap is 1.5 s).
- The delivery vouches for single records before the last one too: for every slug-only record of a
  letters-to-letters day whose day's chain reads both saved blobs, with the payload in the pin, and only in a
  blob cut as ruled. Two readings that differ stay `None`.
- One more loose step: the words in the opposite order (word-order reversal). A record its day's word order
  leaves as it stands is a record left alone, and a text two steps read alike (reverse, word order) is its
  day's.
- What the build takes away: all of it rests on the cut at floor(k * L / N). In a blob cut any other way
  (rounded, the remainder in the first or last record) no record before the last is believed on its day and a
  word, no pin holds and the walk does not answer: a Mastery whose slug-only record of a letters-to-letters
  day is not the last one is then `None` in EVERY set, where the solver before this build answered some (0 of
  63 on a rounded cut, 28 of 63 before). Never a wrong slug.
- Unchanged: a letter-cipher day leaves the slug's digits unsure until the base probe settles
  `warmups.digits/<cipher>`, and a lossy code is never answered.
- Two wall-clock limits bound the delivery-wide reads: `RECORDS_TIME` 0.6 s and `CONSENSUS_TIME` 0.25 s. Cut
  short, a read vouches for nothing: on a loaded machine sets can come back `None`, never wrong.
- `day_patch.py` may define `override(q, answer, files, ctx)` (backlog row 263): the one way a live fix
  replaces or withdraws a plain answer of the lane; `answer()` is still asked only about `None` and unsure.

## The Day 18 build (2026-10-17, the look-ahead's B1 to B5 and backlog row 333, `tests/test_day18_warmups.py`)

`docs/retro/day-18/predictions-warmups.md` staged 157 candidate Day 18 encodings on the armed tree, each as a
base, a Time Trial and an 88-set Mastery of 18 records, and found no wrong plain answer but 35 base STOPs, 22
of them the text's hex under a 16-token code, and one hole that does not depend on the code. What was built:

| Item | Where | What it reads now | Staged before, after |
| --- | --- | --- | --- |
| B1 | `crib_decode._rotation_checked` | A Mastery record with fewer than `PIN` sentence letters and some slug characters, read by its day's own proved chain when that chain is one rotation (`caesarN`, `atbash`, `rot13`) and the record gives at least two sentence letters at its place. In an 18-record cut that is record 14 for a slug of 27 characters or more, which the delivery's vouch cannot pin (0 to 2 such sets, `CONSENSUS_MIN` 5) | forced long slugs: 84 to 85 of 88 sets, then 88 of 88 |
| B3 | `formats_more.WALKING`, `crib_decode._walking`, `_apply_bytes` | Inside the walk by the days `d_emojiaz` needs one emoji letter or keycap, not four (keycap hex: about one letter in a six-character record); a chain that ends in `a85`, `b85` or `z85` drops the encoder's NUL fill, as `_strict_steps` did | keycap hex and NUL-filled Z85 Masteries: 0, then 88 of 88 |
| B5 | `formats_more.d_roman`, `d_brhex`, `d_upside` | Roman numerals of the bytes (canonical forms, one letter case, 1 to 255); Braille hex with the number sign before every digit (cells only, no white space); upside-down text by one table of the common glyphs (no glyph for two characters; at least 4 turned outside the walk) | each base, Time Trial and Mastery from None to plain (upside: see below) |
| B2 | `formats_more._late_hexsym`, `HEXSYM_WAYS`, `keyed_fn('hexsym:...')` | The text as hex, each hex digit one of 16 tokens, the table learned from the sentence's 174 hex digits (all 16 values occur): tokens by white space, by two or more spaces, per character with its marks, or at a fixed width of 1 to 8; one to one over the whole crib, every later token in the table, an even count. A late reader: asked only for a whole blob nothing else answered, so no saved day's chain moves; the Mastery record is read by the day's learned table | 22 base STOPs (4 x 4 Polybius in five forms, tap code, values, A1Z26, letters a to p three ways, fruit emoji, semaphore, dice, Roman numerals of the digits, unary dots, DNA three ways, ICAO, English spelled, x/y Bacon groups) close in every mode, 88 of 88 |
| B4 | `day_patch_template.py` (`_taken`, `_prove_today`) | A `NAME` the solver already has is refused at load; when `decode()` alone reads both saved blobs of the attempt's day, the private copy's chain for that day is `(NAME,)` | a template patch named `z85` on the tree before B3: 0 of 88 in 20.3 s; named `z85patch`: 88 of 88 in 1.2 s |

How they answer. `roman` and `brhex` are strict codes and plain. `hexsym` is a keyed step like `symsub`, not a
strict decoder (review of f8fe87e): a slug-only Mastery record needs the delivery's vouch, since a table that keeps
a few digits and shuffles the rest reads a wrong slug; every nibble of the slug is a token the crib fixed, so its
digits are plain once the record is vouched for. `upside` is the exception: the upside-down tables in use agree on the
letters, which the sentence checks, and differ on digits (6 and 9 turned or left), which it cannot. Digits read
through it are unsure under `warmups.digits/upside` with `as_is` first and `unflipped` (6 and 9 as written)
second; a slug with neither digit is plain, because both readings give it. So an upside-down base whose digits
have no 6 or 9 learns nothing, and its Mastery's sets with a 6 or 9 stay unsure until one probe (staged: 51 plain
and 37 unsure with the truth of 88; `tools/run.py` probes them inside a window that has 10 s or more, row 299).

Across all 157 candidates: base None 35 to 10, Time Trial None 36 to 11, Mastery None 3,478 to 1,071 of 13,816
sets, WRONG 0 to 0; one adversarial candidate (a keyboard shift that also moves the digit row) has its long-slug
set BAD like its other 87 sets, where it was None (its base stops after two rejected probes either way). Still
None by rule: the lossy codes (Braille digits without the number sign, 5 x 5 tap code of a to p, classic Bacon,
A1Z26 of the text, leetspeak, Pig Latin, multi-tap), Cyrillic look-alikes, and two loose steps stacked (rot47
then reversed, reversed then Caesar). Not built: B6 (a third digit option for a keyboard shift and a Vigenère
key that move the digits), yEnc records without their header, repeating-key xor records, a key per variant.

Measured: the 70 saved Warmups attempt folders of Days 1 to 17 (19 of them history) give the same answers on
an APFS clone, and Days 1 to 17's day chains are unchanged; the real Day 15, 16 and 17 Masteries replay in
0.500, 0.448 and 0.443 s (medians of 5, separate processes, load about 7.5) against 0.498, 0.447 and 0.447 s
before; staged 88-set Masteries are as fast or faster (a long-slug set no longer pays for the search: 0.50 to
0.35 s for NATO hex); one `hexsym` look at a blob takes about 0.25 ms.

## Mobile: `solvers/mobile-android/codec_classical.py` (backlog row 88)

`codec_search.py` imports it beside `codec_more.py`. It registers nine steps over
`solvers/common/classical.py`, applied only when the puzzle document names them: autokey, Gronsfeld, variant
Beaufort, QWERTY neighbours, a 6 x 6 Polybius square, ICAO spelling words, reversed blocks, swapped pairs,
Enigma I / M3. None is a search move, so a document that names no such codec is read as before. A reading
counts only when it is exactly `ANS-` plus 16 hex characters and is offered unsure
(`labels.pick` under `mobile.codec/<name>`) until the judge accepts its route; `run.py` never sends it on a
clock. A searched parameter (a one-letter autokey primer, a block size, a keyboard move) is kept only when the
code's form proves it. Reversed blocks and swapped pairs yield to `codec_search`'s own position moves wherever
those read the data, so the routes the lane already offered (`chunk-reverse:chunks4-reversed`,
`swap-pairs:chunks2-reversed`) are unchanged.

Not registered, because the cipher cannot carry the code: Bacon of letters (five-symbol groups of hex nibbles
are another code, read as `baconhex` by the Warmups solver, row 331), the tap code, a 5 x 5 Polybius square, A1Z26,
Playfair, bifid. Nothing reads Enigma settings out of free prompt text: the document's fields must give them.

Tests: `tests/test_mobile_classical.py` (6 checks, 4 s), with `tests/test_mobile_day9.py`,
`solvers/mobile-android/selftest.py` and `tests/test_classical.py` green; every saved Mobile answer of Days 1
to 8 (38) is still plain.
