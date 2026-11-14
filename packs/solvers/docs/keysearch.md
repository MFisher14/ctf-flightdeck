# Key search (B-215)

`python -m ctf keysearch` runs a key-derivation search as a job on disk, so a long search survives a
crash, a budget stop and a handoff to another agent or harness. The contract is CONTRACTS.md
section 66; this page is the operator's view.

## When to use it

The key is derived from things the handout states (a SID, a hostname, a word in a note, a salt in a
header), but the recipe is unknown: which values, in what order, joined how, in which encoding,
through which hash or KDF. Write the candidate banks and the recipes once, give the harness one exact
check (a crib, a tag, a digest, an encrypted zip), and let any agent run and resume it.

## A spec

```toml
key_len = 16
chunk = 2048                       # candidates per ledger record
kdf = ["md5", "sha256", "md4", "sha256*1000", "pbkdf2:sha256:10000", "hmac:sha256"]
salts_hex = ["83cbc9af"]           # used by the salted derivations (hmac, pbkdf2, scrypt) only
note = "license blob key"

[[bank]]
name = "words"
values = ["flaggy", "premium"]
harvest = "files/handout.bin"      # B-074 harvest: overlay, strings, sibling notes (read now, frozen)
case = ["as-is", "lower", "upper", "title"]
encodings = ["utf8", "utf16le"]
nul = [false, true]

[[bank]]
name = "sid"
values = ["S-1-5-21-1-2-3"]

[[bank]]
name = "rock"
wordlist = true                    # hashcrack.wordlist(): CTF_WORDLIST, outside the repo
limit = 100000

[[template]]
slots = ["sid", "words"]
seps = ["", ":", "|"]
orders = "all"

[[template]]
slots = ["rock"]

[verify]
kind = "crib"
cipher = "aes-cbc"                 # aes-ecb aes-cbc aes-ctr xor rc4
ct_file = "files/blob.enc"         # or ct_hex; the IV is its first block unless iv_hex is given
crib = "PK\u0003\u0004"            # or crib_hex; offset = 0
pkcs7 = true
```

Paths are relative to the spec's folder. Other verifiers: `hash` (`target_hex`: the derived key
itself), `hmac` (`alg`, `msg_hex`, `tag_hex`), `aes-gcm` (`nonce_hex`, `ct_hex`, `tag_hex`, `aad_hex`),
`zip` (`file`: an encrypted zip; use `kdf = ["raw"]` for a password search).

## Running

```sh
python -m ctf keysearch new lic --spec lic.toml      # prints the space size and the chance-hit estimate
python -m ctf keysearch run lic --workers 4 --cpu-seconds 600
python -m ctf keysearch status lic                   # chunks done, hits (masked), the resume command
python -m ctf keysearch run lic                      # the resume: done chunks are skipped
python -m ctf keysearch show lic --reveal            # the hit's candidate and key, to stdout only
```

`new` refuses a job whose verifier is not exact over its space (more than 0.001 expected chance
hits); add a longer crib, a full tag, or shrink the space, or pass `--allow-weak` knowingly. A job is
frozen when it is made: to change it, make it again with `--replace` (the old one is moved aside as
`<id>.replaced-<time>`, ledger and all).

A zip hit found by `raw` goes into the archive-password store, so `ctf sweep` and the archive lane
open that archive from then on. With no workdir for the store (no `CTF_WORKDIR`, no single event) the
hit is still recorded (`stored: false`) and a warning says so: set `CTF_WORKDIR` or `CTF_EVENT` and
`show --reveal` it.
