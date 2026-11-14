# Toolkit `blockchain`: read-only EVM and Bitcoin artifact facts

Built for the Day-31 finale (the 25-day retrospective listed blockchain as an absent category). Offline and
artifact-only: nothing is executed, no contract is deployed or called, no RPC or network request is made, nothing is
ever signed. Libraries: only pycryptodome (Keccak-256) is used; eth-utils, web3, eth-abi, rlp, coincurve and bech32
are not in the venv, so RLP, ABI, bech32/bech32m, base58check and secp256k1 are small own implementations checked
against published vectors (`tests/test_day26_blockchain.py`). Without pycryptodome every Keccak feature declines.

## Run first

```bash
.venv/bin/python solvers/toolkits/blockchain.py <file>...
```

`solve_set` and `signals` follow the toolkit contract (`signals` is 0.0 when nothing parses as a blockchain artifact).

## What it reads

| Artifact | Facts |
| --- | --- |
| raw EVM tx (hex or JSON `rawTransaction`) | type, chain id, nonce, gas limit/price/max fee/tip, to, value, selector, tx hash, sender (ecrecover, re-verified) |
| ABI json (+ calldata or event-log json) | selector of a function/signature, function name/signature, one decoded argument named once, event name, topic0 |
| EVM bytecode | solc `PUSH4 EQ PUSH JUMPI` selector table, constructor/runtime split (CODECOPY/RETURN pattern), solc version from CBOR metadata, PUSH-literal string, instruction count |
| addresses | EIP-55 validity and checksummed form, address from a provided public key or provided private key (the key is never emitted), signer of a (hash or EIP-191 message with a claimed address, signature) |
| encodings / Bitcoin | base58check (P2PKH/P2SH; WIF recognised, withheld), bech32/bech32m segwit, Bitcoin raw tx (txid, wtxid, inputs, outputs, script types, addresses, size/weight) |

## Never-guess

Every answer is `labels.pick(blockchain.<field>/<shape>, options)` (a ranked candidate list to read with `labels.show(...)`, never plain).
Heuristic facts say so in the shape (`solc_eq_pattern`, `creation_codecopy_pattern`, `common_table`,
`mainnet_rendering`). The exactly-one router answers `None` when a question names two fields or two artifacts match.
Malformed, truncated or non-canonical input is `None`. A private key, WIF, seed phrase or flag is always `None`, and a
final guard drops any answer containing a 32-byte key found in the delivery. A bare output number ("output 1") is
ambiguous (zero- vs one-based) and is `None`; `vout N` and ordinals ("second output") are read.
