# Toolkit `modern_crypto`: quick reference

RSA, supplied-key Paillier and Rabin, XOR and stream reuse, ciphers with a stated key, JWT, ECDSA nonce reuse, ECB
and generator checks. Offline, plain Python, 0.8 s per set by default. Classical ciphers (Caesar,
Vigenere, substitution, transposition, Morse, Baconian, and strict stated-key Trifid/four-square/
two-square/straddling-checkerboard), encoding chains and hash/HMAC structure
are now here too, through the hand module `solvers/toolkits/classical.py` (backlog row 88), wired
into `solve_set` as UNSURE answers only. See "Classical ciphers, encoding chains, HMAC" below.

| File | What it is |
| --- | --- |
| `solvers/toolkits/modern_crypto.py` | `signals`, `solve_set`, the command, `material()`, `solve_rsa`, `solve_sym`, `solve_xor`, `solve_reuse`, `solve_ecdsa` |
| `solvers/toolkits/classical.py` | classical ciphers, encoding chains, hash/HMAC structure, RSA detection (hand tool; no `signals`/`solve_set`); imported by `modern_crypto.py` |
| `solvers/common/modern_crypto.py` | the maths and the readers (`tk.lib`): standard-library integers, `gmpy2` only for speed |
| `tests/test_tk_modern_crypto.py` | every attack with a near-miss that must give `None`; Days 1 to 8 answer nothing |
| `tests/test_day24_toolkit_crypto.py` | the classical half: every cipher with a near-miss; the unsure-only invariant for the wiring |
| `tests/test_day30_classical_stated.py` | independent encoders for the four stated-key families; production `solve_set`, ambiguity, malformed/resource negatives, real-mode cold path |

## Run first

```bash
.venv/bin/python tools/unpack.py challenges/day-09/<id>            # members/ beside the attempt
.venv/bin/python solvers/toolkits/modern_crypto.py challenges/day-09/<id>/members/* --budget 20
```

The triage prints one line per finding: `KEY` (PEM, DER, JWK, OpenSSH, certificate; type, bits,
e), `PARAM` (labelled n, e, d, p, q, c, dp, dq, phi, r, s, z with bit lengths), `CONSISTENCY`
(relations checked and broken), `FIELD` (key, iv, nonce, tag, ciphertext and the readings of each:
hex, base64, raw), `RSA attack=<name>` with every reading of the message, `CIPHER`, `ECDSA`,
`JWT` (header, payload, and a string of the delivery whose HMAC verifies), `HASH-SHAPED` (shape
only), `INTS` (MT19937 clone, LCG), `BYTES` (repeated 16-byte blocks).

`solve_set` returns proven answers and ranked candidate values (`labels.show(...)`); reason to the flag
from its output and submit it once via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`).

By hand, in `.venv/bin/python` (run it with `-I` on files of a delivery):

```python
import importlib.util, time
spec = importlib.util.spec_from_file_location("tk", "solvers/toolkits/modern_crypto.py")
tk = importlib.util.module_from_spec(spec); spec.loader.exec_module(tk); mc = tk.lib
M = tk.material({"output.txt": open(path, "rb").read()})
for r in tk.solve_rsa(M, time.monotonic() + 60):       # a longer cap than a clock allows
    print(r.attack, r.factors, r.messages)
mc.rsa_attack(n, e, time.monotonic() + 120)             # Wiener, Fermat, p-1, rho
mc.small_e_root(c, 3, n, max_k=10**6); mc.hastad(pairs, 3); mc.common_modulus(n, e1, c1, e2, c2)
mc.repair_digit(mc.read_params(text)); mc.crib_drag(c1, c2, b"flag{"); mc.xor_crib(ct, b"flag{", anywhere=True)
mc.ecdsa_nonce_reuse(r, s1, z1, s2, z2); mc.mt_clone(outputs, 5); mc.lcg_recover(outputs)
```

## What `solve_set` answers

It reads the question's words (then the answer id's), never the file names alone.

| Asked | Needs | Answer |
| --- | --- | --- |
| the plaintext, message, flag | RSA: n with a private part (d; p and q; phi; dp), or a proven weakness: exact e-th root (also `c + k*n`, k up to 4096, e up to 17), shared prime (gcd above 1), Hastad (CRT then an exact root), common modulus, Wiener, Fermat, prime or square n, small factor, Pollard p-1 and rho inside the budget, a dp leak. Messages are read raw, without PKCS#1 v1.5 padding, and as OAEP (SHA-1, SHA-256) | plain when the `answer_format` pattern picks it out; else unsure `modern_crypto.plaintext/rsa` (`flag`, `text`, `flag_inner`) |
| the RSA plaintext as an integer | exactly one verified raw RSA message representative, with no competing ciphertext and no PKCS#1/OAEP unpadded interpretation | plain decimal for kind `integer`, key `modern_crypto.plaintext_integer/rsa`; otherwise the ordinary text/form path above |
| Paillier plaintext/message | one coherent supplied `n`, `g`, and ciphertext, plus either proven prime factors or supplied `lambda`; a supplied `mu` is cross-checked, `g = n + 1` is never assumed, and every supplied integer is bounded before private-key work | proven integer/plaintext via `modern_crypto.plaintext/paillier`; missing, duplicate, contradictory, over-2,048-bit modulus/factors, out-of-domain fields or an expired deadline give `None` |
| Rabin plaintext/root | one coherent supplied Blum modulus, both proven prime factors, and one ciphertext; every integer is bounded before primality/CRT work | a question-stated smallest/largest selector or a unique answer-format match is plain; otherwise all verified roots are instance-scoped `labels.candidates` under `modern_crypto.plaintext/rabin@inst-*`; over-2,048-bit or over-deadline material gives `None` |
| the same | a stated key: fields `key`, `aes_key`, `secret`, `password`, `passphrase` (hex, base64 or text; a passphrase also as its SHA-256 and MD5), `iv`/`nonce`, `tag`, and a ciphertext field or file: AES ECB/CBC/CTR/CFB/OFB/GCM, DES, 3DES, RC4, ChaCha20, XOR | the one plaintext that unpads (or 16 readable bytes of a stream); key `.../cipher` or `.../xor` |
| the same | XOR with no key, only when XOR is named: every single byte but 0, and repeating keys from the question's cribs (`starts with '...'`, `contains '...'`, a stated `flag{`) | only with the question's own proof: a specific pattern, a crib, the flag form |
| the same | a reused keystream (named in the question): a readable file and two byte strings | the same proof |
| `md5` / `sha1` / `sha256` of the plaintext | any of the above | the hash, plain when the plaintext has one form |
| d, p, q, smaller or larger prime, factors, phi, bit length, e | a factored or given key | plain decimal for kind `integer`; unsure over decimal and hex otherwise; d is unsure between `mod_phi` and `mod_lambda` when they differ; `p` is unsure between the two primes |
| which attack or weakness | exactly one proven attack | always unsure: `modern_crypto.attack/<attack>` |
| ECDSA private key, nonce | two signatures with one r (labels `r`, `s1`, `s2`, `z1`/`h1`, or `msg1`/`msg2`, or DER / r\|\|s `sig` fields); secp256k1 and P-256 | d plain for `integer` or a fixing pattern; k always unsure (`as_written`, `negated`) |
| next output | 624 or more integers (MT19937), or an LCG sequence (with or without m, a, c) | plain only when an output not used to build the state checks; else unsure |
| hash type | exactly one hash-shaped string | always unsure, by length or prefix |
| duplicate blocks, block mode | exactly one 16-aligned ciphertext | count plain only when it is 0; mode unsure, and only when a block repeats |
| JWT claim, algorithm, secret | exactly one token; the secret must be a string of the delivery whose HMAC verifies | unsure (`raw`), plain for an `integer` claim or a specific pattern |

`None` for everything else, and in particular: parameters that contradict each other (n is not
p times q, e times d is not 1) unless EXACTLY ONE change of one digit of one parameter makes every
relation hold; a value written with one `?`; a root that is not exact; coprime moduli; an attack
that ran out of budget; two candidates that both pass; an ATT&CK question; a set that carries
Binary, Mobile or Metadata marks.

The Paillier/Rabin production-path fixtures are in `tests/test_day30_crypto_paillier_rabin.py` and
`tests/test_tk_modern_crypto_budget.py`. They independently encrypt, enter through `solve_set`,
enforce sub-second cold paths, preserve Rabin's four-root ambiguity, and prove wrong, duplicate and
truncated inputs fail closed. The budget fixture also proves a valid 1,886-bit modulus at over 92%
of the 2,048-bit ceiling, an exhausted deadline, and 8,676-bit adversarial keys. The production
path declines those oversized keys before multiplication, primality testing or modular exponentiation;
it preserves the native 30-round prime test when installed, then uses 24 fixed bases with deadline
checks between exponentiations. Adaptive
Bleichenbacher/Manger padding-oracle attacks are not folded into this offline reader: they require a
separately scoped live oracle, query budget and target authorization, and remain an explicit open row
instead of silently sending network probes.

Also `None` (review of 2026-10-08): a number computed from a proven number (`d mod (p-1)`, the last
digits, a digit sum, `p minus 1`, the bit length of anything but the modulus, the year of an `exp`
claim); a generator question that is not the one next 32-bit output (the seed, the modulus, the
multiplier, `randrange`, `getrandbits(64)`, the Nth output unless N is the count given plus one, the
next several); an LCG with no modulus written whose candidate moduli (the divisors of the
determinants' gcd) disagree about the next output; a duplicate-block count of 0 at 16 bytes when
blocks repeat at 8.

The challenge's `answer_format` has carried no `pattern` so far (`kind` and `syntax`, and
`accepted_values` for an enum), so on a real base a text/flag plaintext is an unsure answer. An
explicit raw RSA plaintext integer is plain decimal; other plain results include proven kind
`integer` numbers, a hash of a single-form plaintext and a zero count.

## Classical ciphers, encoding chains, HMAC (`classical.py`)

Backlog row 88. `solvers/toolkits/classical.py` is a HAND TOOL (no `signals`/`solve_set`; not part of
triage routing), imported by `modern_crypto.py`, which answers classical
questions through it as UNSURE picks only: never a plain answer, only ranked candidates, and a
discovered flag or secret is reported, never used or submitted. Everything is offline and bounded
(byte caps, iteration/time caps; no network, no factoring of a real modulus, no running a found key).

```bash
.venv/bin/python solvers/toolkits/classical.py <members>/*          # a per-file triage
```

By hand (`spec = ...('cl', 'solvers/toolkits/classical.py'); cl = module_from_spec(...)`):

- `cl.identify(data)` -> ranked `(cipher_or_encoding, evidence)` hypotheses (information only).
- Substitution ciphers: `caesar_all(text)`, `rot13`, `atbash`, `affine_all(text)`,
  `vigenere_decrypt(ct, key)`, `vigenere_known_plaintext(ct, crib)` (key from a known start),
  `kasiski_lengths(ct)` (likely Vigenere key lengths by index of coincidence),
  `substitution_hillclimb(ct, deadline)` (a bigram hill-climb; a HYPOTHESIS, the caller validates).
- Transposition: `rail_fence_all(ct)`, `columnar_all(ct)` (bounded to small widths), `columnar_decrypt`.
- Other: `morse_decode(text)`, `baconian_decode(text)`.
- Strict stated-key families: `trifid_decrypt_stated`, `four_square_decrypt_stated`,
  `two_square_decrypt_stated`, `straddling_checkerboard_decrypt_stated`; or
  `stated_key_decodings([(name, text), ...], question, deadline)` for the same parser used by
  `modern_crypto.solve_set`.
- Encoding chains: `decode_chain(data)` peels nested transport encodings (base64, base64url, base32,
  base16, base85/ascii85, url). It stops at readable text; ciphers on the decoded output are a
  separate `solve_classical` step.
- Hash/HMAC: `hash_format(s)` (length -> families: md5/md4/ntlm for 32 hex, sha1 for 40, ...; `$id$`
  prefixes -> bcrypt/sha512crypt/...), `hmac_structure(s)` (the UNDERLYING family by output length).
- RSA DETECTION from public parameters only: `rsa_findings(params, moduli)` reports small-e,
  close-primes (bounded Fermat), small-modulus and shared/common-modulus as findings. It never
  decrypts, never factors past the cap, never touches a private value (the toolkit's own `solve_rsa`
  is what actually recovers a plaintext, and only from proven parameters).

What `solve_set` answers through it (every one UNSURE):

| Asked | Needs | Key |
| --- | --- | --- |
| decrypt a NAMED classical cipher (caesar, rot13, vigenere, substitution, atbash, affine, rail-fence, columnar, scytale, morse, baconian, playfair) | exactly one readable English (or flag-shaped) plaintext over all candidate texts; a crib the question states (`starts with '...'`, `contains '...'`) feeds a Vigenere known-plaintext | `modern_crypto.plaintext/classical` |
| decrypt Trifid, four-square, two-square or a straddling checkerboard | the cipher is explicitly named and the delivery/question states one unambiguous ciphertext plus the complete alphabet/table inputs described below | instance-scoped `modern_crypto.plaintext/stated_<family>@inst-<sha256>#candidates` |
| which classical cipher/encoding is this | exactly one identified family | `modern_crypto.classical_cipher/identified` |
| decode nested base64/base32/... layers | exactly one decoded chain that reads as text | `modern_crypto.decoded/chain` |
| which hash does this HMAC use | exactly one hash/HMAC-shaped string | `modern_crypto.hmac_alg/len<N>` |

`None` when nothing (or more than one distinct plaintext) reads cleanly: the never-guess rule binds
it exactly as it binds the modern side. The detector is strict (common-word density, not letter
frequency alone), so a lucky single shift of a Vigenere text is not mistaken for Caesar.

### Strict stated-key fractionating and square ciphers (Day 30 U2)

This path is deterministic decoding, not keyless cryptanalysis. It runs before the older
English-ranked classical search when one of the four family names is explicit in the question or
delivery. A generic `Recover the plaintext` question also reaches it when the delivery names the
cipher. Labels may be line fields (`Name: value` / `Name = value`) or scalar JSON fields; quoted
inline declarations are also read. Required data:

- Trifid: `Ciphertext`, an exact 27-symbol `Alphabet`/`Cube`, and integer `Period` (1..4096).
  `Coordinate order` may be `layer-row-column` or any explicit permutation. If it is omitted, the
  six axis permutations are separate candidates.
- Four-square: `Ciphertext`, an exact 25-symbol base `Alphabet`, and either `Top-right key` plus
  `Bottom-left key`, or `Key 1` plus `Key 2`. A key may be a keyword or the complete square. Generic
  key numbering leaves the two key-to-square assignments as candidates.
- Two-square: the same 25-symbol alphabet and two keywords/squares. `Left key`/`Right key` fixes a
  horizontal layout; `Top key`/`Bottom key` fixes a vertical layout. With `Key 1`/`Key 2`, an explicit
  `Orientation` fixes the layout; if it is omitted, horizontal/vertical and key order stay candidates.
- Straddling checkerboard: a 26..28-symbol `Alphabet`, ten unique `Columns` digits and two row-prefix
  digits. Ordered `Row digits` fixes their assignment; named `Row 1 digit`/`Row 2 digit` does too;
  unordered `Blank digits` keeps both row assignments as candidates. An unfilled cell or dangling
  row prefix is malformed.

Whitespace around written symbols is transport and is removed; ciphertext symbols must all occur
in the stated alphabet. Square ciphertext must contain whole digraphs. Duplicate alphabet cells,
missing halves, conflicting repeated fields, multiple named families, invalid orientation/order,
oversized ciphertext (over 64 KiB), oversized stated-key material (over 128 KiB), or any incomplete declaration returns `None` and cannot fall
through to another cipher reader. No output is plain merely because the arithmetic is deterministic:
spacing/punctuation may have been erased and conventions can vary. Every form/convention is a
`labels.candidates` option (at most 12), and its key hashes the full question, answer format, member
names and every delivered byte, so acceptance can replay only that exact instance.

## When it says `None` and you think it should not

- A sound-looking key that is slow to factor: raise the budget
  (`--budget 120`, or `CTF_TK_BUDGET=30`).
- `e` is not written: nothing is assumed (65537 is not a default).
- A key, IV or password the QUESTION states is read like one in a file (`tk.question_fields`): quoted (`under the key "YELLOW SUBMARINE"`),
  after a colon, an equals sign or `is` (`key: 42 6c 6f 77 66 69 73 68, iv: ...`), `the key and IV are both ...`, and an IV said to be all
  zeros. An unquoted key of several words must stand after `key:` and end its clause. Blowfish (ECB, CBC, CFB, OFB, CTR) is tried only
  when the delivery or the question names it.
- A list of ciphertexts, one a line (hex or base64): `which line is ECB` is the one line that repeats a 16-byte block, unsure between
  the line counted from 1, from 0, and the line itself (`modern_crypto.ecb_line/index`); the mode and duplicate-count questions read
  that one line. A list with no crib (single-byte XOR on one of 327 lines) is not searched: `mc.xor` per line is agent work.
- Key files beside as many raw ciphertext files with nothing pairing them (Hastad): every pairing is tried, and the message is
  proven only when exactly one has an exact root. A raw ciphertext saved with a line end after it is read without it.
- XOR with no crib: the question must name XOR and give a pattern, a crib or a flag form.
  `mc.xor_crib` and `mc.crib_drag` list candidates for you; reason to the answer and submit it, never guess.
- Unsure answers are ranked candidate values (`labels.show`). `labels.py` does not
  know the prefix `modern_crypto` yet (five category prefixes are registered), so the unsure string
  is carried as candidates, and nothing is remembered between variants.

## Label vocabularies likely here (lowercase snake_case, best first)

- attack: `wiener`, `wiener_attack`, `small_private_exponent` | `fermat`, `fermat_factorization`,
  `close_primes` | `small_exponent`, `low_public_exponent`, `small_e`, `cube_root` |
  `hastad_broadcast`, `hastad`, `broadcast_attack` | `common_modulus` | `common_factor`,
  `shared_prime`, `common_prime`, `gcd`, `batch_gcd` | `pollard_p_minus_1`, `smooth_prime` |
  `pollard_rho`, `small_factor`, `trial_division` | `prime_modulus` | `square_modulus`,
  `repeated_prime` | `dp_leak`, `crt_exponent_leak`, `partial_key_exposure` |
  `corrupted_parameter`
- mode and cipher: `ecb`, `aes_ecb`, `electronic_codebook`; `aes_256_cbc`, `aes_128_ctr`, `rc4`,
  `chacha20`, `xor`, `repeating_key_xor`, `single_byte_xor`, `two_time_pad`, `keystream_reuse`,
  `nonce_reuse`
- hash type: `md5`, `ntlm`, `sha1`, `sha256`, `sha512`, `bcrypt`, `sha512crypt`, `md5crypt`,
  `argon2id`
- JWT: `none_algorithm`, `alg_none`, `weak_secret`, `algorithm_confusion`, `hs256`, `rs256`
- numbers: decimal first for kind `integer`; lowercase hex without `0x` next; `0x` only when the
  question shows it. Keys: `modern_crypto.<field>/<shape>`.
- classical cipher name: `caesar`, `caesar_cipher`, `shift_cipher`, `rot`; `rot13`, `rot_13`;
  `atbash`, `atbash_cipher`; `vigenere`, `vigenere_cipher`, `polyalphabetic`; `substitution`,
  `monoalphabetic_substitution`, `substitution_cipher`; `transposition`, `columnar_transposition`,
  `rail_fence`; `morse`, `morse_code`; `baconian`, `bacon`.
- HMAC underlying hash: same vocabulary as hash type, by output length (`sha256`, `sha1`, `md5`, ...).

## Real artifacts (2026-10-08, `tests/real/test_real_modern_crypto.py`)

Run on 24 real files: the Huntress 2024 RSA challenge ("Strive Marish Leadman TypeCDR", closed by the toolkit
alone), the Huntress 2025 "Angler" Blowfish note and Entra token, sixteen RsaCtfTool example files and five
Cryptopals files. No crash and no wrong answer; the slowest set is 0.9 s (Wiener on a 4096-bit key). Before the
fixes every Cryptopals file and the Angler note answered `None`: the key stood in the question, not in a
file. Also changed: trial division up to 2^20 (a 16-bit factor was reported as Pollard p-1), Pollard rho
inside the deadline on a modulus of any size, the set's RSA result answered from its cache after the budget
is spent (the second question about a 4096-bit Wiener key was `None`).

Not broken, and `None`: RsaCtfTool's `pollard_rho.pub` (257 bits), `small_exponent` (no exact root for
k < 20000), `weak_public` (two 64-bit primes), ROCA, partial-d and masked PEM keys, SIQS-sized moduli.
The record is `docs/toolkits/real-data.md`.

Review (2026-10-08, `tests/test_tk_real_c_review.py`): "a non-zero IV" and "the IV is not zero" no longer state a zero IV, and "which line
is NOT ECB" is `None` instead of an offer of the ECB line.

## Discrete logarithms in Z_p (2026-10-26, Day 27 build KB-10; `solvers/common/dlog.py`, `tests/test_tk_day27_dlog.py`)

ElGamal and Diffie-Hellman in a weak group. `dlog.solve_dlog(p, g, h, order=None, bound=None)`: Pohlig-Hellman over
the group order (trial division by the primes under 2^16, then Brent rho on the rest, every prime Miller-Rabin
proven), BSGS per prime (at most 2^18 baby steps, so a prime up to about 2^36; Pollard rho above that), CRT; the
small-subgroup case (a `g` of small order inside an unfactorable `p-1`, or a stated subgroup order `q` with
`g^q == 1`); Pollard's kangaroo for a stated exponent interval (`x < 2^40`, `a 32-bit secret`, `bound = N`; about
2^33 inside the 0.5 s cap). `dh_shared` and `elgamal_decrypt` build the shared secret `g^(ab)` and the plaintext
`c2 * c1^(-x)`.

The one rule: a value is returned only after `pow(g, x, p) == h` is checked in code, a stated private value is used
only when `g^priv` reproduces its public value, and a shared secret or plaintext is returned only when the other
base (`B`, `c1`, `h`) lies in `<g>` (`base^ord(g) == 1`, `ord(g)` computed exactly from the factorisation). `p` not
prime, `g` or `h` outside the group, a prime factor of the group order above 2^44, an unsplit composite that `g`
needs, and the deadline all give `None`. One problem is capped at 0.5 s (`DLOG_BUDGET`); a 128-bit safe prime or a
`p-1` of two 60-bit primes declines in 1 ms and 0.25 to 0.5 s.

Router: `_dlog_answer` (called first in `answer()`, material-gated like the GCM and key-wrap hooks) claims a question
only when its words ask for a shared secret, a private exponent / discrete log, or an ElGamal plaintext, and the
material states `p`, `g` and the public values (`A`/`B`, `alice_public`/`bob_public`, `client_public`/
`server_public`, `h`/`y`/`public_key`; `c1`/`c2` or `ciphertext = (c1, c2)`; plain text or JSON; decimal or `0x`
hex; labels are read case-sensitively because `A` and `a` differ). Conflicting labels, an elliptic-curve / ECDH /
DSA / RSA / signature wording, a value derived from the secret (hash, digits, `mod`), and an unnamed party when
both `A` and `B` are stated all give `None`. Keys: `modern_crypto.dh_shared/zp` (exact, integer),
`modern_crypto.dlog_x/unique` (plain-capable: `g` a primitive root, or a stated bound no larger than `ord(g)`),
`modern_crypto.dlog_x/least_residue` (a subgroup generator or a kangaroo-only result: the exponent is a residue
class, so it is an unsure pick, never plain), `modern_crypto.plaintext/elgamal` and `modern_crypto.elgamal_m/zp`.

### Review fixes of the discrete-log hook (2026-10-26, KB-10 fix round 1; `tests/test_tk_day27_dlog.py`, section `review_tests`)

The router paragraph above is superseded where it differs from this one. What the adversarial review of `6a11f24` forced:

- Call order: `answer()` is now `_answer_core()` (every older path) and, only when that returns None, `_dlog_answer`. A question that
  names the problem itself (ElGamal, Diffie-Hellman, discrete log, `shared secret`, `g^x`) is still asked first. A delivery with
  signature pairs (`r1`/`s1`, `signature`) is never read as a DH instance unless the question names the problem. A toy DSA nonce
  reuse worded without `DSA` keeps its older plain answer.
- Plain only for the shared SECRET (`shared secret`, `g^ab`): `session / shared / common / agreed key` is an unsure pick, and so is a
  secret asked while the material hashes or runs a KDF over something (`hashlib`, `sha256`, `hkdf`, ...). A hash / KDF / `derived`
  word on the question as written (the statement's own `K = SHA256(s)` is not stripped first) declines; `mod p` is stripped only
  inside `g^x = h mod p`, so `x modulo q` and `reduced modulo the prime q` decline.
- A named party takes that party's labelled slot and nothing else (Bob's key with only `A` read is None); a question that names Eve,
  Mallory, Carol, a third or a group, or material that labels a third public value (`C`, `E`, `M`, `eve_*`, ...), declines the
  shared secret.
- An ElGamal integer plaintext is an unsure pick (nothing independent proves `c2 * c1^-x` is the number); exponential / additive /
  hashed / XOR / KEM ElGamal declines. Bytes that pass the question's specific pattern stay plain.
- A private exponent is plain only when its range is stated: a numeric bound in the QUESTION no larger than `ord(g)`, or (primitive
  root) `x < p-1` / `randrange(2, p-1)` in the question or material; a bound read from the material only steers the search. Bounds
  are whole-word phrases about the private value (`attempts under 100`, `a 64-bit value`, `max: 10 tries` read nothing) and at
  most 2^40; the kangaroo's tame walk checks the deadline (2^64 declines in 0.5 s, was a hang).
- The material is parsed once per Material (`dlog.may_state_group` is a one-pass superset test before `read_instance`), and
  `is_prime` caches large values (a 4096-bit modulus declines in about 0.4 s).

### Verifier's pass over the fixed head (2026-10-26, KB-10 round 2; `tests/test_tk_day27_dlog.py`, `round2_tests` R10 to R14)

An independent pass tried to force a WRONG plain answer out of `2cc5f27` and did, in classes the first review's probes did not try. The
paragraphs above are superseded where they differ. Every change only restricts what is plain.

- What the reader takes: a labelled number that goes on as an expression (`p = 7 * 2**26 + 1`, `2^255 - 19`, `g = 2 ** 3`), a digit
  group (`1,000,003`, `1 000 003`, `23 45`, `2.5`), an ellipsis or an indented next line (a wrapped modulus) is not read as its first
  piece (it was: p = 7, g = 2, and a logarithm of the wrong problem went out plain). A numbered sibling of the group's labels (`A2`,
  `B_2`, `p2`, `g_2`, `alice_public_2`, `c1_2`) or a text past 400000 characters makes the instance ambiguous (None).
- When a number is plain: only for a PLAIN ASK. `_dlog_plain_ask` needs (1) the head of every clause that names the target to be
  the target (`What is Bob's public key used to compute the shared secret?` is about the public key; only lead-in words such as
  `What is the value of Alice's ...` may stand before it, a party only as a possessive or coordinated), (2) the rest of the question
  to be made of a closed plain-ask vocabulary (`_DLOG_WORDS`; any other word, `parity`, `in octal`, `in base 7`, `twice`, `next prime`,
  `to 16 bits`, makes it not plain; a count of bits is notation only inside a recognised bound statement), (3) no derivation in the
  answer-format text and no integer kind asked in hex, (4) one target per sentence (`the shared secret and Alice's private key` is
  two asks: None; a means such as `with the private key` or `given the shared secret` is no ask), and for the shared secret and a
  unique exponent (5) a delivery with no program in it (a code file name, `pow(`, `def`, `import`, `print(`, `hashlib`, a hash or KDF,
  or prose saying the secret is reduced, cut or hashed): `shared = pow(B, a, p) % 2**128` is not g^(ab).
- Keys: what is not plain is an unsure pick under a key of its own kind, because `labels.pick` answers every id of a key plain once the
  judge accepts a name for it (with `decimal` accepted for `dh_shared/zp` the fixed head answered `What is the session key?` with the bare
  secret): `modern_crypto.dh_shared/zp+key` (session / shared / common / agreed key), `...+src` (a program in the delivery),
  `...+q<8 hex>` (a digest of the question's words, digits folded: the same wording the same key across variants, another wording
  another key); the same suffixes on `dlog_x/unique`, `dlog_x/least_residue`, `elgamal_m/zp` and `plaintext/elgamal`.
- Routing: `private|secret key|exponent` is a `dlog` intent (the hook is material-gated, so a non-DH question still gets None); tell me /
  show / return / state are ask verbs.
- Measured (the final tree): a wording-by-format fuzz (7 file styles, data-only and program-bearing deliveries, plain, derived, key-wording and
  unnamed-party asks, range stated or not, g a primitive root or a subgroup generator; 3 seeds x 2000 instances) and a grammar-driven question
  fuzz (lead-ins, heads that are another quantity, transform heads and tails, two asks in one sentence; 3 seeds x 8000 questions, ground truth per
  shape) give 0 wrong plain; the plain shared-secret asks stay 100 % plain (2699 of 2699) and the plain private-exponent asks with their range
  stated stay plain. A mutation check (18 of the new gates disabled one at a time in a scratch copy) fails the test file for every one.
  Not read, so declined (a recall gap, never a wrong answer): prose labels such as `Alice sends A = 8` or `prime p: 23` (the label reader takes
  the whole phrase before the `=`), and any delivery that holds a program gives an unsure pick (ranked candidates) where it used to
  give a plain number.

### Third pass (2026-10-26/27, KB-10 fix round 3; review of `95699e2`; `tests/test_tk_day27_dlog.py`, `fix1_tests` R15 to R24)

A second verifier forced seven classes of wrong PLAIN answers, a slowdown and the set-level regression it caused out of `95699e2`. The
discrete-log maths held (every answer is checked with `pow()`); the holes were in how the router matched the asked quantity to the
computed one, in label keys shared across deliveries and in a missing deadline. Every change only restricts what is plain. The paragraphs
above are superseded where they differ. On the verifier's own scripts every wrong plain is now None or unsure; on a ground-truth grammar fuzz
(15 families: preambles, two asks, imperatives, yes / no, hypotheticals, operands, numbers, bases, roles, operators, expressions, ranges,
names, decrypt, controls; `95699e2`: 1866 of 3557 and 2959 of 5618 questions wrong plain) this tree gives 0 of 3557 and 0 of 5618, and
all 72 and 108 controls stay plain and exact.

- The ask is read from the ASK, never from a mention. `_dlog_asks` finds the ask phrases (an ask verb to the end of its sentence; a sentence
  that opens with an imperative the vocabulary allows but the ask search did not know, `Get`, `Share`, `Use`, `Run` ...; a verb-less sentence
  that ends in `?`). Every ask phrase must name the SAME target or be a format instruction (`Give it in decimal.`), at least one must name
  it, and a yes / no question (`Is the shared secret the generator?`) asks none. The old fallback to the preamble's mention is gone (122 of
  128 `The shared secret is known to both parties. What is the generator?` questions went out plain). The head test also runs over the whole
  ask phrase, commas included (`Find the generator, then the shared secret.` has a clause `then the shared secret` with a lead-in head), and
  nothing after the target past a conjunction or a comma may name another quantity (`and the generator`, `, and Bob's key`).
- What the vocabulary admits but changes the question is closed: a modal or subjunctive, a negation, `without` (`would could might should shall
  may were not no never neither nor cannot unless instead without`); Greek and other non-ASCII symbols are read as letters (a symbol that is
  none of the instance's declines).
- Operands are bound (`_dlog_bind`). The question's statements are taken out first (the equation `g^x = h (mod p)`, a power assigned to a symbol
  `s = g^(ab) mod p`, the shared-secret formula itself, a bound statement about a private value, `x is a 28-bit number`, a labelled parameter
  the reader models); a bare `g^x` is NOT a statement: it is the thing asked. Then no operator may remain (`>> << & | ~ ^ % // ** + - * /`, the
  Unicode ones: the number asked is computed from the one the router has: None) and no digit or odd character may remain (not plain). A number
  the question states must be a public value of the pair (a ciphertext component and the public key for a plaintext) or a parameter restated
  outside the ask; a long (6 digits or more) number that is none of these gives None. The question's own private value (`... for a = 5`) must
  reproduce a public value or the question describes another instance (None). `the discrete log of c1 | the ciphertext | the ephemeral key |
  the nonce | C | k | r` names another operand (None; `K` and `S` may name the secret), `to base A` and `with respect to A` another base. The
  material states a group element the instance does not model (`unread_elements`: a Pedersen `C`, a second ciphertext, a value under a label
  nobody reads, at least 32 bits and three quarters of p's width) and the ask does not name its public value or party: None (the shared secret,
  the plaintext) or no default slot (the exponent).
- Roles stay apart (`dlog.read_instance`): `client_*` and `server_*` are slots of their own, never the bare `A` / `B` (a transcript may print the
  server's value first under the label `A`); a question that names a role takes that role's labelled slot or none, and so does a party word with
  no slot (`sender`, `receiver`, `peer`). A JSON key that names a role prefixes what is below it (`{"server": {"A": ...}}` is `server_A`, which no
  slot reads; `{"server": {"public": ...}}` is `server_public`). The shared secret needs one complete pair (A and B, or client and server);
  two different pairs decline.
- A range counts for the variable it is about and for no other (`dlog.range_claims`): each statement is read with its subject (a letter, a party,
  `the private key` in general, or another thing: the ephemeral key, a nonce, Eve's key, the shared secret, a session key) and the router applies
  only the claims whose subject is the asked variable (the party's letter, `x` for the one public value or when the question says it, a letter the
  question writes after the target, the party) or the private key in general, anchored at the start of its clause (`Eve's private key is below p-1`
  is Eve's). A numeric bound counts only from the question, an applicable statement of a larger or unread size (`getrandbits(p.bit_length() + 8)`)
  blocks, a call's assigned name sets its subject (`a_priv` is Alice's, `k` is another thing).
- Keys: a value that is only a guess about what is asked (a least residue, an integer plaintext, a number from a delivery with a program, a key
  derived from the secret) is a CANDIDATE pick under a key scoped to this delivery and question (`...unverified@<64 hex of p, g, the public values,
  the ciphertext, the whole material text and the question>#candidates`), so a confirmed name on one delivery gives the same delivery its
  value on replay and never answers another; `+key` carries `+src` as well when a program is present. Only the proven plain asks of a
  data-only delivery (`dh_shared/zp`, `dlog_x/unique`, and the wording-scoped `...+q<8 hex>` keys of a proven value) are shared.
- Time. The order of g is found prime by prime (`t = g^(order/q)` raised to ell until 1: at most e small raisings) with the cofactor powers of every
  prime as one product tree (`_cof_pows`: about log2(n) full-size exponentiations, not n), Pohlig-Hellman reuses those powers, the baby-step /
  giant-step loops run on gmpy2 mpz (7 to 10 times faster than a Python int at 1000 to 4000 bits), the inverse of an element of known order is a
  power, and every step checks the deadline. A stated private value more than 64 bits wider than p is never exponentiated, a number of more than
  1400 characters is never converted (a labelled megabyte of hex beside a DH instance took 22 s), and at most 64 stated values are kept. The hook
  takes at most `DLOG_SET_CAP` (0.5 s) of a set in all and never the last `DLOG_RESERVE` (0.2 s) of its budget, so the set's other questions are
  answered (a 4-kbit group beside an RSA question: the RSA answer was None after 2.0 s, now `flag{...}` after 0.5 s). Measured, library:
  p = 2247 * 2^4000 + 1 with g of order 2247 15.7 s then None, now 0.12 s solved; p of 3793 bits with p - 1 = 2 x 250 16-bit primes 2.3 s then
  None, now 0.39 s solved; 1991 bits / 128 16-bit primes 0.51 s declined, now 0.09 s solved; 992 bits / 42 24-bit primes declined, now 0.18 s
  solved. Still declined (the 0.5 s cap): 2005 bits / 85 24-bit primes, 2023 bits / 64 32-bit primes, 3986 bits / 256 16-bit primes.
- Test discipline. `fix1_tests` has one block per class, each with controls that stay plain and exact, and asserts None (not just not plain) where the
  design says None, so every layer is pinned alone. A mutation check (32 gates disabled one at a time in a scratch copy of the tree) fails the test
  file for 31 of them; the one that survives is the deadline check inside the loop that raises t to ell (at most e small steps). Not touched, base
  behaviour: a JSON text nested 3000 deep makes the older `lib.read_fields` raise RecursionError in `Material`, which `solve_set` turns into None
  for every question.

### Fix round 4: convergence by restriction (2026-10-27, KB-10; `tests/test_tk_day27_dlog.py`, `fix2_tests` R27 to R31)

Every paragraph of this section above is superseded where it differs. Five review rounds each closed the wrong plain answers they found and each
next review found more, every one from reading what the natural-language question asks (which operand, which party, which target, an expression
of it, a range of another variable, an operator symbol). So the hook stopped trying to read the question perfectly and answers NOTHING plain.

- Every value the hook derives (an exponent, a shared secret, a plaintext) is a candidate pick (`labels.candidates`, row 346: at most 12
  evidence-ranked values you read with `labels.show`, never a single plain value). The key is the instance's own: `modern_crypto.dlog_<x|shared|plaintext>/zp@inst-<64 hex>#candidates`, the hex
  a SHA-256 of the question's words (blanks folded, case kept), its whole `answer_format`, the member it names, the kind and slot the router
  read, `p`, `g`, the stated order, every public value, the ciphertext, the stated private values in the order the reader met them, and the
  whole delivery: every delivered file, archive key and bytes (a magic-header file, a key file, a binary over 1 MiB and a 65th file included),
  every member Material keeps and every text in reading order (the review of `eddb777` moved a member into the archive: the reading order
  and so the `stated` value changed under an unchanged key). Each stays a ranked candidate for that one
  question on that one delivery; another instance, wording, format, delivery or set stays unsure. The keys of rounds 1 to 3
  (`dh_shared/zp`, its `+src`, `+key` and `+q<hex>` forms, `dlog_x/unique`, `dlog_x/least_residue`, `elgamal_m/zp`, `plaintext/elgamal`,
  `...unverified@...`) are no longer written, so a name accepted for one of them changes nothing.
- The options, best first: the value the router computed and verified in code (`log`: `pow(g, x, p) == h`, the least residue modulo
  `ord(g)`, which is also the least residue modulo the subgroup order the reviews asked for; `shared_secret`; `message`), then the alternatives
  the reviews named where they are well defined and the deadline allows, each verified the same way: `stated` (a stated private value that
  reproduces the public value, not reduced), `other_party` (the other slot's exponent), the shared secret `B^x` (the other public value in
  `<g>`), and for a plaintext `swapped` (the same decryption with `c1` and `c2` read the other way round). A kangaroo find whose `ord(g)` was
  not determined in time may be another logarithm on another run, so it is `log_bounded` (`other_party_bounded`) and an accepted `log` never
  answers it.
  Names are `<hypothesis>:<form>`: an integer kind or `decimal` words give decimal only, hex words the hex forms, else decimal, hex, `0x` hex
  and upper-case hex; a plaintext that reads as text gives the flag in it, the whole text and the flag's inside first. The first hypothesis
  comes in every form, then every alternative in its first form, then their other forms; a form the answer_format's pattern refuses is left out.
- The router's reading of the question now only decides None or which values are offered; the plain-ask machinery of rounds 2 and 3 (the
  closed vocabulary, the head and conjunction tests, the program and prose detectors, the range attribution of the router) is deleted. A
  misreading yields a weaker candidate, never a wrong submission.
- Order and budget. `intent()` names a question `dlog` only when no older intent reads its words or its answer id (as the last entry of
  `_INTENTS` it was tried on the words before the older intents saw the id). `solve_set` runs every older reader first, exactly as the baseline
  runs them (a `dlog` question is not handed to them), then the discrete-log pass for the questions they left None, inside
  `min(the set's deadline, DLOG_SET_CAP 0.5 s)` in all and `DLOG_BUDGET` 0.5 s a problem, and no problem starts with less than `DLOG_MIN` 0.1 s
  left. It only fills a None, so no answer of the older readers can be lost to it: with a solve made to overrun by 0.6 s on every call, every
  older answer is in the return value and in `ctx["partial"]` before the first solve begins. A DH question an older reader already answers (an
  RSA plaintext pick in a mixed set: `secret` is a plaintext word) keeps that answer, as before. `answer()` for one question is the
  older paths, then the pass bounded by the caller's deadline. The pass reads its own material (`_DlogMaterial`: the texts, names and members
  Material reads, without its parameter and field parsing; it stops past `READ_LIMIT` or the deadline), never the older readers' Material, so
  its answer does not depend on the set's other questions and a set the baseline did not read costs no Material (the review of `eddb777`:
  a question only the `dlog` intent reads beside 500 KB of word-like text took 0.9 s a file outside every deadline; now 0.009 s, None), and a
  structured answer kind is skipped before anything is read. Its PEM strip is linear and equal to Material's regex (`_strip_pem`; the regex
  retries its lazy scan at every BEGIN with no END, 2.8 s for 100 KB of unmatched headers, now 0.02 s), and `lib.read_keys` runs only where
  its answer decides the text (no PEM header in it).
- Time in the library: every full-size exponentiation of the hook and of `group_order_of` goes through gmpy2 (`_pw`; the builtin `pow` is 11
  times slower at 4096 bits, 0.116 s against 0.010 s), a wide cofactor past the deadline is not primality-tested, rho checks the deadline every
  4096 steps, and the question's restated private values are checked at most 16, inside the deadline. Measured on this tree (gmpy2):
  p = 2247 * 2^4000 + 1, g of order 2247: 0.11 s solved (15.7 s on `95699e2`); 3952 bits with p - 1 = 2 x 250 16-bit primes: inside 0.5 s
  (declined); p = 1465 * 2^2040 + 1, g of odd order: 0.02 s solved; a labelled 390000-hex-digit value beside a 2048-bit instance: 0.41 s, None
  (22 s); a 4-kbit smooth group or a 2-kbit Proth group beside an RSA question: the RSA flag plain, as before.

KB-10's optional half, fpylll for a faster Boneh-Durfee (feasibility only, nothing installed): PyPI has `fpylll 0.6.4` as
`fpylll-0.6.4-cp312-cp312-macosx_11_0_arm64.whl` (8.1 MB, downloaded to a scratch folder with `pip download --no-deps
--only-binary=:all: --platform macosx_11_0_arm64 --python-version 3.12`, not installed). It bundles `libfplll`, `libgmp` and
`libmpfr` under `fpylll/.dylibs/`, so no Homebrew or compiler is needed, and the venv here is CPython 3.12.13 arm64. License GPL-2+
(a vendored copy in this private repo is fine; relicensing is not). Adding it to the shared `.venv` is the integrator's call.
