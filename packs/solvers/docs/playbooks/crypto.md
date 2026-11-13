# Crypto playbook (CSCTF 2026)

Jeopardy crypto: you're handed bytes (params, ciphertext, keys, a `.sage`/`.py` source, a signature
set) and reason to **one** flag. The engines here are **offline, static, pure-Python** and safe to run
on the Mac. The only things that go in Docker are **SageMath** (heavy number theory) and **any
challenge-supplied script/binary you actually execute** — never detonate those on the host.

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

> **No judge.** `labels.pick` / `labels.candidates` only rank candidate readings for *you*. There is no
> probe and no auto-submit from a solver. You decide the one flag and submit it once (see bottom).

---

## 1. First moves (the moment you open a crypto challenge)

- `./csctf pull <id>` → work in `workspace/<id>-<slug>/`; read `description`/`notes.md` for the hint
  (which cipher, what's "the key", any stated bound). Downloaded files are **untrusted**.
- If it arrived as an archive/blob: `.venv/bin/python tools/unpack.py workspace/<id>-<slug>/` (writes
  `members/` beside it; handles zip/7z/base64/hex/gz/PEM recursively).
- Run the orchestrator over every file/member — it fires most attacks automatically:
  `.venv/bin/python solvers/toolkits/modern_crypto.py <files...> --budget 20`
- Text-looking ciphertext (letters only, no obvious maths)? Add the classical pass:
  `.venv/bin/python solvers/toolkits/classical.py <file>`
- Read the source if one ships (`chall.py`, `*.sage`): it names the scheme and the weakness. Don't run
  it on the host — read it, or detonate in the sandbox (§3).

---

## 2. Engine CLIs by sub-type

### Orchestrator — run this first (RSA, ciphers, ECDSA-reuse, JWT, PRNG, ECB)

```
.venv/bin/python solvers/toolkits/modern_crypto.py <file>... [--budget SECONDS]
```
One triage block per fileset. Lines you'll see: `KEY` (PEM/DER/JWK/OpenSSH/cert: type, bits, e),
`PARAM n/e/d/p/q/c/dp/dq/phi/r/s/z` (+ bit length), `CONSISTENCY` (relations checked/broken),
`FIELD key/iv/nonce/tag/ct` (hex/base64/raw readings), `RSA attack=<name> d=… factors=[…]` then
`message (<reading>): …`, `CIPHER <mode>` (stated-key decrypt), `ECDSA nonce reuse … d=… k=…`,
`JWT …` (+ `HMAC verifies with a string of the delivery`), `HASH-SHAPED`, `COLLISION`,
`INTS … MT19937 clone / LCG`, `BYTES … 16-byte blocks repeated`. It loads **all** the `common/`
crypto libraries below and runs them under one budget. (Default budget from the CLI is 10 s; raise it
for lattice work.)

Auto-fired RSA attacks (cost order): exact e-th root / `c+k·n`, shared prime (gcd), Håstad CRT,
common modulus, Wiener, Fermat, prime/square `n`, small factor, Pollard p-1 & rho, dp leak — **plus**
the lattice attacks (Coppersmith / partial-prime / Boneh–Durfee / ROCA) within a cap. Stated-key
ciphers: AES ECB/CBC/CTR/CFB/OFB/GCM, DES/3DES, RC4, ChaCha20, XOR. Also ECDSA nonce reuse, JWT HMAC
secret from delivery strings, MT19937 clone (≥624 outputs), LCG recovery, ECB duplicate blocks.

### The `common/` crypto libraries — **import-only, no file CLI**

These have **no `__main__`** — don't try `python solvers/common/<x>.py <file>`, it does nothing. The
orchestrator above drives them; for the cases it can't infer from bare files (discrete log, weak-curve
ECC, GCM/HNP), call them by hand:

```python
# .venv/bin/python -I   (run with -I when challenge files are in the cwd)
import sys; sys.path.insert(0, "solvers/common")
import modern_crypto as mc, rsa_lattice as rsal, ecc_weak as eccw
import dlog, crypto_depth as depth, shamir_totp as sss
```

- **`modern_crypto` (mc)** — RSA maths + readers. `mc.rsa_attack(n, e, deadline)`,
  `mc.small_e_root(c, e, n, max_k=10**6)`, `mc.hastad(pairs, e)`, `mc.common_modulus(n,e1,c1,e2,c2)`,
  `mc.wiener`, `mc.fermat`, `mc.pollard_rho`, `mc.pollard_p1`, `mc.dp_leak`; XOR: `mc.xor_crib(ct, b"flag{", anywhere=True)`,
  `mc.crib_drag(c1, c2, b"flag{")`, `mc.keystream_reuse`; `mc.ecdsa_nonce_reuse(r,s1,z1,s2,z2)`,
  `mc.mt_clone(outputs, 5)`, `mc.lcg_recover(outputs)`. Every return is verified (root exact, `pq==n`,
  nonce reproduces `r`) or `None`.
- **`rsa_lattice` (rsal)** — `rsal.stereotyped_message(n, e, c, prefix=b"", suffix=b"", unknown_len=0)`,
  `rsal.partial_prime(n, known, known_bits, kind="high")`, `rsal.boneh_durfee(n, e, delta=0.27)`,
  `rsal.coppersmith_roots(coeffs, N, X, beta)`, `rsal.roca_fingerprint(n)` (detects Infineon form at
  any size), `rsal.roca_factor(n)` (**toy-sized only** — real ROCA needs Sage, §3).
- **`ecc_weak` (eccw)** — `eccw.recover_scalar(p, a, b, G, Q, order=None)` → private scalar `d` for
  **singular**, **anomalous** (Smart), or **smooth-order** (Pohlig–Hellman) curves; `G`/`Q` are `(x,y)`.
  Returned only after `[d]G == Q`.
- **`dlog`** — `dlog.solve_dlog(p, g, h, order=None, bound=None)` → `Dlog(x=…)` with `g^x≡h`
  (Pohlig–Hellman / BSGS / rho / kangaroo for a stated interval); `dlog.dh_shared(p,g,A,B,…)`,
  `dlog.elgamal_decrypt(p, g, h, c1, c2, …)`. Caps: `p ≤ 4096 bits`, largest prime factor `< 2^44`,
  kangaroo interval `< 2^40` — a bigger instance returns `None` (take it to Sage).
- **`crypto_depth` (depth)** — AES-GCM **nonce-reuse forgery**: `depth.gcm_recover_subkey(pairs)` →
  GHASH subkey `H` (needs ≥3 same-key/same-nonce pairs to be unique; check the signature for the tuple
  shape), then `depth.gcm_tag(h, mask, aad, ct)` forges a tag. ECDSA **biased-nonce / HNP**:
  `depth.ecdsa_hnp_recover(curve, pubkey, sigs, nonce_bits)` → `d` (only when `d·G == pubkey`).
- **`shamir_totp` (sss)** — Shamir SSS: `sss.recover(texts, question_text="")` (top-level parser) or
  `sss.recover_prime(points, prime, threshold=None)` / `sss.recover_gf256(points, threshold=None)`.
  OTP: `sss.totp(secret, unix_time, period=30, digits=6, algo="sha1")`, `sss.hotp(secret, counter, …)`,
  `sss.parse_otpauth(uri)`, `sss.b32_secret(s)`.

### Adaptive crypto oracles — callback only, no transport

`solvers/common/crypto_oracles.py` implements the attack state machines without opening a socket or
sending a request. Import it from the challenge-specific solve script and give it a **bounded**
`check(ciphertext) -> bool` callback connected through the existing scope-locked client:

```python
import sys; sys.path.insert(0, "solvers/common")
import crypto_oracles as oracle

# The callback is the only challenge-specific part. RSA callbacks receive fixed-width bytes by default.
plaintext = oracle.cbc_padding_oracle_decrypt(iv + ciphertext, check_padding)
forged = oracle.cbc_padding_oracle_encrypt(chosen_plaintext, check_padding)
m = oracle.rsa_parity_oracle_recover(c, n, e, check_odd)
em = oracle.bleichenbacher_pkcs1_v1_5_recover(c, n, e, check_pkcs1)
message = oracle.manger_oaep_recover(c, n, e, check_leading_zero)
```

- CBC queries carry `IV || ciphertext`; decrypt preserves the prefix and truncates at the target
  block, while encrypt builds a chosen-plaintext chain backwards. Both enforce strict PKCS#7.
- `rsa_parity_oracle_recover` uses exact rational intervals. Bleichenbacher supports initial blinding
  and merged solution intervals. Manger expects the standard predicate `RSA_dec(c) < 2^(8*(k-1))`.
- Every API has `max_queries`; the hard process cap is ten million. RSA values are returned only if
  `pow(recovered, e, n) == c`. Use `decode_pkcs1_v1_5` / `oaep_decode` to verify encoding structure.
- For an in-process integer oracle (usually a unit test), pass `oracle_input="int"`; production solve
  callbacks should use the default fixed-width bytes. The module never imports a network client.

The guarded CLI is inspection/decoder-only—it deliberately cannot load a Python callback:

```
.venv/bin/python solvers/common/crypto_oracles.py describe [--json]
.venv/bin/python solvers/common/crypto_oracles.py pkcs7-unpad <hex> [--block-size 16] [--json]
.venv/bin/python solvers/common/crypto_oracles.py pkcs1-decode <hex> [--json]
.venv/bin/python solvers/common/crypto_oracles.py oaep-decode <hex> [--hash sha1] [--label-hex HEX] [--json]
```

Do not put retry loops around a failing callback. A timeout, inconsistent answer, or exhausted query
budget is evidence to stop and fix the scoped transport/rate before continuing; it is never a reason
to fan out requests or probe another target.

### General CVP and knapsack helpers

`solvers/common/lattice_tools.py` reuses the exact-integer LLL in `rsa_lattice` and adds:

- `closest_vector(basis, target)` — exact-fraction Gram–Schmidt plus Babai nearest-plane; the result
  includes its reduced basis, coefficients, lattice vector, and squared distance for independent checks.
- `solve_subset_sum(values, target)` — bounded exact meet-in-the-middle followed by a low-density LLL
  embedding; returns a bit vector only when its weighted sum exactly equals the target.
- `merkle_hellman_decrypt(ciphertext, private_sequence, multiplier, modulus)` — verifies the
  superincreasing sequence, modular transform, greedy solution, and derived-public-key ciphertext.

For a reusable solve script, import those functions directly. The guarded CLI takes a JSON object:

```
.venv/bin/python solvers/common/lattice_tools.py cvp params.json --json
.venv/bin/python solvers/common/lattice_tools.py subset-sum params.json --json
.venv/bin/python solvers/common/lattice_tools.py merkle-hellman params.json --json
```

This helper is deliberately honest about its boundary: Babai is an approximation and high-density
subset sum can return `None`. Large multivariate Coppersmith/Howgrave–Graham instances still go to
Sage (§3); do not treat an unverified short vector as a plaintext.

### Oracle-free CBC / CTR chosen-plaintext edits

`modern_crypto.cbc_bitflip_forge(...)` and `modern_crypto.ctr_edit_forge(...)` build malleability
candidates from **known plaintext bytes at known offsets**. They transform local bytes only; no
oracle or transport is present. The convenience wrappers `cbc_bitflip(...)` and
`ctr_known_edit(...)` handle one contiguous edit.

```python
import sys; sys.path.insert(0, "solvers/common")
import modern_crypto as mc

cbc = mc.cbc_bitflip(iv, ciphertext, offset, b"user", b"root")
ctr = mc.ctr_known_edit(ciphertext, offset, b"user", b"root")
```

- CBC changes the IV for plaintext block 0 or the preceding ciphertext block for later blocks.
  The result names every plaintext block that will decrypt unpredictably. Adjacent-block requests
  whose targets overlap that collateral are rejected instead of producing a false guarantee;
  non-adjacent multi-block edits are supported.
- CTR uses `C' = C XOR known XOR desired` and has no neighbouring-byte collateral. Keep the
  original nonce/counter unchanged.
- Both enforce input/edit/allocation caps and report compact modified ranges. Their guarantee is
  conditional on the supplied known plaintext being byte-exact; they do not authenticate a forged
  token and cannot bypass a correct MAC/AEAD tag.

The guarded hex-only CLI prints payload bytes for human review:

```
.venv/bin/python solvers/common/crypto_malleability.py cbc --iv IVHEX --ciphertext CTHEX \
  --edit OFFSET:KNOWNHEX:DESIREDHEX [--edit ...] --json
.venv/bin/python solvers/common/crypto_malleability.py ctr --ciphertext CTHEX \
  --edit OFFSET:KNOWNHEX:DESIREDHEX [--edit ...] --json
```

### Classical ciphers / encodings

```
.venv/bin/python solvers/toolkits/classical.py <file>...          # triage: IDENTIFY <cipher> / CANDIDATE [label] text
.venv/bin/python solvers/common/classical.py <file> [--crib TEXT] [--pattern REGEX] [--seconds S]
.venv/bin/python solvers/common/classical.py <file> --enigma [SETTINGS-file-or-text]
```
- Toolkit `classical.py`: ranked `IDENTIFY <cipher>: <evidence>` + `CANDIDATE [<label>] <reading>`.
  Covers Caesar/ROT, Vigenère (known-start/crib), monoalphabetic hill-climb, Atbash, affine,
  rail-fence, columnar, Morse, Baconian, nested encoding chains (base64/32/16/85/url/rot13), hash/HMAC
  structure, and strict stated-key Trifid / four-square / two-square / straddling-checkerboard.
- `common/classical.py` (the only `common/` module with a CLI): prints `LOOKS` (letter stats, IoC,
  chi², Kasiski key-lengths), `PATTERN` (a reading holding exactly one `--pattern` match, default
  `flag{…}`), `SCORE` (English-ranked). **`--crib TEXT` turns a reading into a proof** (key derived from
  / checked by the known plaintext). `--enigma` deciphers with stated rotor/ring/plugboard settings.
  Also exposes `crack_caesar/affine/vigenere/railfence/columnar/substitution`, `crack()`, and
  Brainfuck/Ook!/COW interpreters.

### Blockchain artifacts (EVM / Bitcoin)

```
.venv/bin/python solvers/toolkits/blockchain.py <file>...          # read-only; needs pycryptodome for keccak
```
Prints `# <file> [<kind>] <summary>`: raw-tx decode + recovered **sender** (ecrecover, re-verified),
4-byte selector / ABI decode, bytecode dispatch table, EIP-55 checksums, base58check / bech32(m).

For Solidity/EVM security evidence, run `solvers/toolkits/evm_security.py` entirely offline:

```sh
.venv/bin/python solvers/toolkits/evm_security.py bytecode runtime.hex
.venv/bin/python solvers/toolkits/evm_security.py source Contract.sol
.venv/bin/python solvers/toolkits/evm_security.py layout proxy-layout.json implementation-layout.json
```

It identifies exact `ORIGIN`, low-level `CALL`/`DELEGATECALL`, call-before-`SSTORE`, unchecked-call,
`SELFDESTRUCT`, block-value, arithmetic and EIP-1967 slot evidence; masks comments/quoted strings in
Solidity source; and computes exact overlapping storage byte ranges. These are review leads, not
vulnerability verdicts: dynamic jump targets, stack/data flow, authorization, compiler-inserted checks,
fork semantics and exploitability require human confirmation. Every result therefore carries
`vulnerability_verified=false`; no RPC, deployment, signing or simulation occurs.
**Never emits a private key, WIF, seed, or flag** (hard guard) — reasoning value, not a submit source.

---

## 3. Docker (detonate / heavy maths only — never on the Mac)

Our engines above are offline and run on the host. Docker is for two things:

**SageMath** — when an attack exceeds the pure-Python caps (full-size ROCA, real Coppersmith/LLL,
LWE/lattice, pairings, isogenies, index calculus). Write the `.sage` yourself, then:
```
python -m ctf toolchain versions <challenge files>     # which Sage the files ask for (default ctf-sage:10.7)
docker run --rm --platform linux/amd64 --network none --pull=never -v "$PWD":/work -w /work \
  ctf-sage:10.5 sage your_script.sage
```
Results can depend on the Sage release (a past challenge's `E.gens()` differed after 10.5): use the tag the
challenge names, and cross-check with the other tag when a consistent-looking answer is rejected.

For the standard primitives you do not need a script: `python -m ctf run common.algebra_service run job.json`
runs LLL/BKZ, Groebner bases, varieties, elimination, resultants, roots and Coppersmith small roots as a
JSON job on a named backend (in-repo Python, a local `sage`, or the pinned image) and checks what comes
back (`docs/toolkits/algebra_service.md`); `common.lattice_templates` builds the usual lattices (hidden
number, truncated LCG, subset sum, bounded linear systems; `docs/toolkits/lattice_templates.md`).
`python -m ctf run common.algebra_service status` says which backends are usable here. A backend that is
missing is reported as `blocked` with its `needs_tool`; BKZ is never quietly replaced by LLL.

**Any challenge-supplied code you execute** — a provided `chall.py`/solve script, a keygen, an oracle
image, a compiled binary. This is the "install the tools, detonate only in a Docker VM so we don't
brick the Mac" rule:
```
python3 tools/sandbox.py run --in solve.py python3 {in}         # csctf-sandbox:2, --network none, caps dropped
```
`csctf-sandbox:2` ships `python3` (launched with `-I`), numpy/scipy, radare2, etc. An **x86-64** crypto
binary goes to the pwn image instead (`docker/pwn`, `csctf-pwn:1`; see the pwn playbook). The sandbox is
`--network none` / read-only root — fine for computation, not for a live oracle.

---

## 4. CSCTF techniques → which engine

| You see… | Attack | Here |
| --- | --- | --- |
| small `e` (3), short message, no pad | e-th root / Håstad | auto (orchestrator); `mc.small_e_root`, `mc.hastad` |
| `p`,`q` close; `n` prime/square | Fermat / trivial | auto |
| two `n` sharing a factor | shared-prime gcd | feed both files to orchestrator |
| same `n`, two `e`, coprime | common modulus | auto; `mc.common_modulus` |
| tiny `d` / big `e` | Wiener → Boneh–Durfee | auto + `rsal.boneh_durfee` |
| known prefix/suffix plaintext, or leaked high/low bits of `p` | Coppersmith | `rsal.stereotyped_message` / `rsal.partial_prime` (Sage if large) |
| modulus "looks Infineon" | ROCA | `rsal.roca_fingerprint`; factor in Sage |
| `dp` (CRT exponent) leaked | dp leak | auto; `mc.dp_leak` |
| ElGamal/DH, smooth `p-1`, or stated small exponent | discrete log | `dlog.solve_dlog` / `elgamal_decrypt` / `dh_shared` |
| curve with `4a³+27b²=0`, `#E=p`, or smooth order | weak-curve ECDLP | `eccw.recover_scalar` |
| two ECDSA sigs share `r` | nonce reuse | auto (`ECDSA` line) |
| many ECDSA sigs, short/biased `k` | HNP lattice | `depth.ecdsa_hnp_recover` |
| AES-GCM, nonce repeated | forbidden attack / tag forgery | `depth.gcm_recover_subkey` → `gcm_tag` |
| stated key + AES/DES/RC4/ChaCha ct | just decrypt | auto (`CIPHER` line) |
| XOR, key reuse, crib `flag{` | crib-drag / keystream reuse | `mc.crib_drag`, `mc.xor_crib` |
| `getrandbits`/MT outputs, or LCG stream | predict next | auto (`INTS` line) |
| Shamir shares / `otpauth://` | reconstruct / OTP | `sss.recover`, `sss.totp` |
| JWT, `alg:HS256`, weak secret | sign-with-delivery-string | auto (`JWT` line) |
| letters only, shifted/periodic | classical | `toolkits/classical.py`, then `common/classical.py --crib` |
| raw EVM/BTC tx, address, selector | decode/recover sender | `toolkits/blockchain.py` |

**Proof discipline:** every attack returns a value only when verified (`pq==n`, exact root,
`[d]G==Q`, `g^x≡h`, nonce reproduces `r`). A reading ranked only by "how English" it looks is a *hint*
— confirm it contains `flag{…}` or the stated plaintext before you treat it as the answer.

---

## 5. Get the flag out & submit

The flag is a decrypted plaintext / recovered secret that matches the event flag format. Reason to
**one** value, then submit **once**:

```
./csctf submit <id> 'flag{...}'          # == .venv/bin/python -m ctf submit <id> 'flag{...}'  — quote it
```
From inside a solver:
```python
ctf.submit.guarded_submit(ctfd, ch, flag, provenance="rsa wiener → decrypt")
```
The guard dedupes, paces, skips challenges the team already solved, and **blocks after 3 wrong answers
on one challenge** (then stop and ask the player). **Never loop over candidate flags** — that's flag
brute-forcing, which CSCTF bans. If several readings survive, narrow to one by proof; don't spray them.

**Live-oracle crypto** (a padding-oracle / `nc host port` service — the offline toolkit deliberately
does **not** send network probes): that's a scoped, interactive attack. Point it **only at the squad's
assigned endpoint**, pace the queries (no flooding/mass requests), and it's the player's call to run it.

Never fabricate a flag. If nothing verifies, say so and move on.

## Gotcha: case-losing ciphers vs. the CSCTF{CaMeL} flag convention

Enigma (and some classical ciphers) emit **uppercase only** — the original letter case is destroyed, so you
cannot reproduce a CaMeL-case flag like `CSCTF{mUcH_3nc0d1ng_W@S_D0N3_ch3f}` from the ciphertext alone (the
rehearsal recovered the exact *content* but as `CSCTF{MUCH_3NC0D1NG_...}` → byte-mismatch).
- Recover the content first; it's correct even if the case isn't.
- The case/styling comes from the **brief** or the CSCTF convention (leet + CaMeL). Check the brief.
- There is **no wrong-submit penalty**, so resolving a *known* case ambiguity by trying the content in the
  documented style (and a plain-lowercase variant) is acceptable — that's disambiguation, not the banned
  brute-forcing (which is exhaustive/blind search). Do NOT sweep many variants; 1–2 reasoned forms only.

## Gotcha: a shortcut can decrypt a locally-valid DECOY flag

Rehearsal (secustoring): statically extracting the AES/HMAC keys from the shipped verifier and decrypting
the bundled `.svlt` gave a flag that passed PKCS#7 + HMAC-SHA256 + JSON checks — and was still WRONG
(`CSCTF{cbc_p4dding_0r4cl3s_s7ill_bi73}` decoy vs real `CSCTF{cbc_padding_oracles_still_bite}` from the
intended padding-oracle path against the live service).
- When a challenge has an **intended live/interactive path** (padding oracle, remote service) AND an
  offline shortcut (key extraction from a packed binary), the shortcut may hit a planted decoy that
  self-verifies locally. Prefer the intended path, or treat a shortcut flag as **unconfirmed until the
  CTFd judge accepts it**.
- There's no wrong-submit penalty, so guarded_submit will catch a decoy (incorrect) and we fall back to
  the live path — but it costs a wrong attempt + time, so note "possible decoy" when submitting a
  shortcut flag and have the intended path ready.

## Fast Enigma — `--crib`
Don't IoC-rank a million rotor/start candidates. Give the known-plaintext crib and let the crib-first,
multiprocessed breaker do it in seconds: `.venv/bin/python solvers/common/classical.py <cipher.txt> --crib 'CSCTF{'`.
It decrypts only the crib region to score each (rotor-order, start) across all cores (`solvers/common/psearch.py`),
then recovers the plugboard on the survivors. The same `psearch` helper pools any brute-ish sweep (PRNG seeds,
key spaces, cipher-ID).

## Round-3 depth: lattices, weak curves, AEAD, PRNGs, and wallets

The reusable lattice API in `solvers/common/lattice_tools.py` now includes bounded multivariate
Howgrave-Graham/Coppersmith candidate recovery and approximate-common-divisor recovery, in addition
to CVP and subset sum. Its JSON CLI accepts `small-roots` and `acd`; use deliberately small bounds and
verify every returned root in the original congruence. LLL candidates are ranked evidence, never an
automatic judge probe.

`solvers/common/ecc_weak.py invalid-crt transcript.json --json` combines supplied weak-subgroup
discrete-log residues with generalized CRT, while `mov curve.json --json` performs the supersingular
embedding-degree-1/2 MOV/Frey--Rück transfer and verifies the recovered scalar on the source curve.
It does not query a curve oracle or search a live service.

For repeated-nonce/tag challenges, `solvers/common/crypto_depth.py` exposes `gcm-forge`,
`chacha-forge`, and `ghash-partition` JSON operations. The builders require already-recovered key
material (`H`, the GCM mask, or Poly1305 one-time-key constraints), recompute the authenticators, and
return payload bytes for human review. They never transmit them.

PRNG recovery APIs live in `solvers/common/modern_crypto.py`, with the guarded CLI in
`solvers/toolkits/prng_recovery.py`: Python MT floats/bounded draws and shuffle evidence, Java's 48-bit LCG, glibc
TYPE_3, and PHP MT observations are accepted only when a recovered state replays every supplied
observation exactly; otherwise prediction is `None`. Wallet helpers in `solvers/toolkits/blockchain.py`
cover BIP39 seed derivation, BIP32/BIP44 paths, WIF/brainwallets, Ethereum keystore-v3 decryption, and
mapping/storage slots. Example: `blockchain.py wallet wallet.json --json`. Secret inputs stay local.

MT19937 runs backwards too (B-063). `python -m ctf run toolkits.mt_arrays <challenge_dir>` (intake runs
it on CBOR, MessagePack, JSON and output-list text files) tests every list of numbers in the handout,
as outputs and as raw state words, and for each stretch of 624 or more consecutive MT19937 words writes
the recovered state, the outputs after it and the outputs **before** it to
`recon/mt_arrays/mt_arrays.json`, with the seed when the stream's start is in reach. It stops there: how
outputs become keys (words per record, hash, counter) is the challenge's own schedule, yours to read
from its fields. A finding with 0 verified words is marked UNVERIFIED: do not answer from it alone. From
Python: `mc.mt_rewind(outputs, n)`, `mc.mt_untwist(state)`, `mc.mt_extend(window, before=, after=)`,
`mc.mt_runs(words)`, `mc.mt_seed_search(window)`; from the CLI: `prng_recovery.py mt-rewind in.json`.

## Round-4 algebra and truncated generators

`lattice_tools.py small-roots` accepts a supplied sparse polynomial in as many as sixteen variables;
the 72-column cap still prevents combinatorial blow-ups, and every reported tuple is substituted into
the original congruence. This is a bounded CTF small-root engine, not a general ideal solver.

For pairing transfers with embedding degree above two, provide `embedding`, an irreducible monic
`extension_modulus` (low coefficient first), and an extension-field `auxiliary` point to
`ecc_weak.py mov`. The polynomial and point are checked, the Tate pairing is evaluated in the supplied
polynomial basis, and the recovered scalar is replayed on the source curve.

`crypto_depth.py gcm-recover capture.json --json` recovers ranked `(H, E_K(J0))` candidates directly
from two same-nonce ciphertext/tag pairs; a third pair normally makes the candidate unique.
`chacha-recover` and `chacha-forge` now accept `max_degree` (up to 256) and factor general Poly1305
equations over `GF(2^130-5)`. All candidates must reproduce every captured tag.

The `prng_recovery.py` CLI adds `java-truncated`, `xorshift-truncated`, `xoshiro`, `pcg-unknown`, and
`lcg-truncated`. These use modular intervals, GF(2) elimination, or exact bit-vector constraints and
return a prediction only when every compatible state agrees. The unknown-modulus LCG path is explicit
about its power-of-two modulus family and preserves ambiguous candidate widths.

## Round-5 signature faults, MAC misuse, and reduction backends

Do not reimplement attacks already present: `modern_crypto.py` covers Wiener, Håstad broadcast,
Franklin–Reiter, common-modulus RSA, and exact-checked ECDSA/DSA nonce reuse; `rsa_lattice.py` covers
univariate Coppersmith, stereotyped messages, partial primes, and bounded Boneh–Durfee; and
`crypto_depth.py` covers biased/short-nonce ECDSA HNP. Each recovered message, factor, or scalar is
checked against the original ciphertext, modulus, or public point before it is returned.

`solvers/common/crypto_faults.py` fills the distinct fault/misuse seam:

- `ecdsa_fault_pair_recover` handles a valid faulted signature that preserved the ECDSA nonce and
  returns a scalar only after both equations and the supplied public point agree.
- `ed25519_nonce_reuse_recover` performs strict canonical/subgroup signature verification, recovers
  the scalar from two signatures sharing `R`, and replays both the public point and nonce point.
- `cbc_mac_length_extension` emits a review plan for raw, zero-IV, variable-length CBC-MAC. Its
  assumptions are carried beside the bytes; it never claims that CMAC or a length-bound construction
  is vulnerable. `audit_aead_misuse` groups same-key nonces and truncated tags without guessing keys.
- `recover_masked_aes_sbox` enumerates only full-table exact explanations of
  `T[x] = SBOX[x xor k] xor mask`; a damaged or more complex white-box table returns no match.

```console
.venv/bin/python solvers/common/crypto_faults.py ed25519-reuse observations.json --json
.venv/bin/python solvers/common/crypto_faults.py aead-audit observations.json --json
.venv/bin/python solvers/common/lattice_backends.py status --json
```

`lattice_backends.py` reuses the in-repo exact-integer LLL and dispatches BKZ only when a local
`fpylll` is installed. A basis is emitted only after an independent exact Hermite-normal-form check
proves that it spans the same row lattice. There is no silent BKZ-to-LLL downgrade. The wider
multivariate front end accepts 16 variables, while a direct weak-composition generator enforces the
existing 72-column cap before allocation; this makes sparse high-variable affine cases tractable
without pretending to solve general polynomial ideals.

## Advanced algebra, stream ciphers, and side channels (dedicated engines)

Beyond the lattice/RSA/ECC depth above, these offline engines each cover a whole archetype — every
recovery verifies against the original instance and returns `None` on ambiguity:

- `solvers/common/rsa_attacks.py` — Wiener, Boneh–Durfee, Håstad broadcast, Franklin–Reiter /
  related-message, common-modulus, Fermat / close-prime, partial-key / known-bits, Bellcore CRT-fault.
- `solvers/common/lattice_nonce.py` — Hidden Number Problem, biased/low/repeated ECDSA–DSA nonce recovery.
- `solvers/common/special_curves.py` — singular (cusp/node), anomalous (Smart), quadratic-twist, BSGS /
  Pohlig–Hellman, embedding-degree analysis; `solvers/common/ecc_faults.py` adds invalid-curve & fault pairs.
- `solvers/common/stream_recovery.py` — Berlekamp–Massey / minimal-LFSR, Geffe correlation, nonlinear
  filter, shrinking/alternating generators, RC4 KSA/PRGA, WEP/FMS, reused-keystream known-plaintext.
- `solvers/common/symmetric_cryptanalysis.py` — reduced-round differential & linear, meet-in-the-middle
  (2DES), slide, related-key, Feistel/SPN recovery, ECB cut-and-paste, CBC bit-flip/IV reuse.
- `solvers/common/isogeny_pairing_attacks.py` — SIDH/SIKE/CSIDH toy transcripts, BLS, IBE.
- `solvers/common/pq_weak.py` — LWE / module-LWE / NTRU / Kyber-like / Dilithium-like weak-parameter audits.
- `solvers/common/protocol_crypto.py` — DH small-subgroup, ElGamal/Paillier/Schnorr reuse, Shamir recovery.
- `solvers/common/sidechannel_offline.py` — CPA/DPA, timing, cache, DFA, fault clustering over SUPPLIED traces.
- `solvers/common/oracle_aead.py` — padding/parity/Bleichenbacher/Manger oracles; `hash_structures.py` —
  length-extension, multicollision (Joux), polynomial-hash key recovery, GF(2) CRC forgery.

See `docs/CAPABILITIES.md` for the full crypto capability list.
