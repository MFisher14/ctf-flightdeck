"""chain_formats is blockchain, despite its assignment to compression family.

Independent eth_abi/base58 encoders and published Solidity ABI/Bitcoin BIP174
wire semantics. No network, signing, submissions, or engine encoder oracles.
https://docs.soliditylang.org/en/latest/abi-spec.html
https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""
import base64
import random

import base58
import eth_abi
from eth_utils import keccak
import pytest

import chain_formats as engine


def test_abi_scalar_dynamic_and_calldata_real_encoder():
    types = ['address', 'uint256', 'int32', 'bool', 'bytes4', 'string', 'uint256[]']
    address = '0x' + '12' * 20
    values = [address, 123456789, -55, True, b'ABCD', 'CSCTF{abi}', [1, 9, 100]]
    encoded = eth_abi.encode(types, values)
    assert engine.abi_decode(types, encoded) == [address, 123456789, -55, True, '0x41424344', 'CSCTF{abi}', [1, 9, 100]]
    raw = bytes.fromhex('a9059cbb') + eth_abi.encode(['address', 'uint256'], [address, 123])
    out = engine.decode_calldata(raw)
    assert out['signature'] == 'transfer(address,uint256)'
    assert out['arguments'] == [address, 123]
    assert engine.selector('transfer(address,uint256)') == bytes.fromhex('a9059cbb')
    assert engine.keccak256(b'abc') == keccak(b'abc')


def test_revert_and_standard_event():
    revert = bytes.fromhex('08c379a0') + eth_abi.encode(['string'], ['denied'])
    assert engine.decode_revert(revert)['reason'] == 'denied'
    signature = 'Transfer(address,address,uint256)'
    a, b = '0x' + '11' * 20, '0x' + '22' * 20
    out = engine.decode_event([keccak(text=signature), eth_abi.encode(['address'], [a]),
                               eth_abi.encode(['address'], [b])], eth_abi.encode(['uint256'], [37]))
    assert out['indexed'] == [a, b]
    assert out['data_values'] == [37]


@pytest.mark.parametrize('raw', [b'', b'\0', b'\0\0abc', b'abc', bytes(range(64))])
def test_base58_independent_package(raw):
    encoded = base58.b58encode(raw).decode()
    assert engine.base58_encode(raw) == encoded
    assert engine.base58_decode(encoded) == raw


def psbt():
    tx = (bytes.fromhex('01000000 01') + bytes(32) + bytes.fromhex('ffffffff 00 ffffffff 01')
          + (1000).to_bytes(8, 'little') + b'\x01\x51' + bytes(4))
    return b'psbt\xff\x01\x00' + bytes([len(tx)]) + tx + b'\0\0\0'


def solana():
    return (b'\x01' + bytes(64) + b'\x01\x00\x01\x02' + b'\x01' * 32 + b'\x02' * 32
            + b'\x03' * 32 + b'\x01\x01\x01\x00\x02\xab\x01')


def test_psbt_and_solana_documented_wire_fields():
    for data in [psbt(), base64.b64encode(psbt()).decode()]:
        out = engine.parse_psbt(data)
        assert (out['version'], out['inputs'], out['outputs']) == (0, 1, 1)
        assert out['global_key_types'] == [0]
        assert out['input_key_types'] == [[]]
    out = engine.parse_solana_transaction(solana())
    assert out['signature_count'] == 1
    assert out['header'] == {'required_signatures': 1, 'readonly_signed': 0, 'readonly_unsigned': 1}
    assert out['accounts'] == [base58.b58encode(b'\x01' * 32).decode(), base58.b58encode(b'\x02' * 32).decode()]
    assert out['instructions'][0]['data_base58'] == base58.b58encode(b'\xab\x01').decode()


def test_wallet_metadata_and_uri_never_returns_secret():
    out = engine.classify_wallet({'version': 3, 'address': 'abc', 'crypto': {
        'ciphertext': 'PRIVATE_SENTINEL', 'cipher': 'aes-128-ctr', 'kdf': 'scrypt'}})
    assert out['format'] == 'ethereum-keystore-v3'
    assert out['encrypted_private_material'] is True
    assert 'PRIVATE_SENTINEL' not in str(out)
    uri = 'wc:topic@2?relay-protocol=irn&symKey=PRIVATE_SENTINEL'
    assert engine.parse_walletconnect_uri(uri) == {'format': 'walletconnect-uri', 'topic': 'topic',
        'version': 2, 'relay_protocol': 'irn', 'symmetric_key_present': True}
    assert engine.analyze_chain_artifact(uri.encode())['topic'] == 'topic'


@pytest.mark.parametrize('types,values,expected', [
    (['uint256[2]', 'uint256'], [[11, 22], 33], [[11, 22], 33]),
    (['uint256[2][2]'], [[[1, 2], [3, 4]]], [[[1, 2], [3, 4]]]),
    (['string[2]'], [['a', 'b']], [['a', 'b']]),
])
def test_fixed_array_layout_matches_real_abi_encoder(types, values, expected):
    assert engine.abi_decode(types, eth_abi.encode(types, values)) == expected


def test_signed_integer_padding_rejected():
    raw = bytes(31) + b'\x80'
    with pytest.raises(eth_abi.exceptions.NonEmptyPaddingBytes):
        eth_abi.decode(['int8'], raw)
    with pytest.raises(ValueError):
        engine.abi_decode(['int8'], raw)


def test_nested_abi_type_has_bounded_depth():
    with pytest.raises(ValueError):
        engine.abi_decode(['uint256' + '[1]' * 1500], bytes(32))


@pytest.mark.parametrize('entry', [engine.decode_calldata, engine.decode_revert,
                                  engine.parse_psbt, engine.parse_solana_transaction,
                                  engine.analyze_chain_artifact])
def test_byte_parser_fuzz_and_explicit_small_cap(entry, monkeypatch):
    rng = random.Random(0xc0dec)
    data = [b'', b'\xff' * 128] + [rng.randbytes(n) for n in (1, 4, 7, 64, 256)]
    for valid in (psbt(), solana(), bytes.fromhex('a9059cbb') + bytes(64)):
        data += [valid[:n] for n in (1, 5, 8, len(valid)-1)]
        altered = bytearray(valid)
        altered[rng.randrange(len(valid))] ^= 0x80
        data.append(bytes(altered))
    for raw in data:
        try:
            entry(raw)
        except Exception as exc:
            assert type(exc) is ValueError
    monkeypatch.setattr(engine, 'MAX_INPUT', 16)
    with pytest.raises(ValueError):
        entry(b'\0' * 17)


@pytest.mark.parametrize('args', [[], ['--help'], ['--unknown']])
def test_cli_argument_guard(args):
    assert isinstance(engine.main(args), int)
