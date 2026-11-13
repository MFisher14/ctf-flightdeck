#!/usr/bin/env python3
"""Guarded offline CLI for exact-roundtrip PRNG recovery helpers in modern_crypto.

The input is bounded JSON containing observations already supplied by a challenge.  No random
endpoint is queried and no seed range larger than one million candidates is accepted.  Ambiguous
states/predictions print a null candidate rather than a guess.

`mt-rewind` (B-063) takes {"outputs": [>= 624 consecutive MT19937 words, at most 4096], "count": N
(default 624, at most 65536), "tempered": true} and prints the N outputs that came before them. A
request outside those bounds exits 2 with the reason; a null candidate means the words are not one stream.
Finding such words inside a file is solvers/toolkits/mt_arrays.py.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
MAX_JSON = 8 << 20
MT_WORDS = 624                      # one MT19937 state: the fewest outputs mt-rewind reads


def _load():
    name = "csctf_modern_crypto_prng"
    if name in sys.modules:
        return sys.modules[name]
    path = HERE.parent / "common" / "modern_crypto.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("modern_crypto reader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_seeded_keygen():
    """Load solvers/common/seeded_keygen.py (B-064), with solvers/common importable for its helpers."""
    common = HERE.parent / "common"
    if str(common) not in sys.path:
        sys.path.insert(0, str(common))
    name = "seeded_keygen"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, common / "seeded_keygen.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("seeded_keygen reader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


mc = _load()


_SCHEME_FIELDS = ("prng", "nbits", "set_top_bit", "set_odd", "num_primes", "prime_method", "e")


def _seeded_keygen(data):
    """Run the seeded-keygen (PRNG prime) RSA recovery from one bounded JSON request."""
    sk = _load_seeded_keygen()
    if "n" not in data:
        raise ValueError("seeded-keygen request needs n")
    raw_scheme = data.get("scheme", {})
    if not isinstance(raw_scheme, dict):
        raise ValueError("scheme must be a JSON object")
    unknown = set(raw_scheme) - set(_SCHEME_FIELDS)
    if unknown:
        raise ValueError(f"unknown scheme field(s): {', '.join(sorted(unknown))}")
    scheme = sk.KeygenScheme(**{k: raw_scheme[k] for k in _SCHEME_FIELDS if k in raw_scheme})
    epoch_start, epoch_stop = data.get("epoch_start"), data.get("epoch_stop")
    window = None
    sources = [key for key in ("pcap", "mtime_file") if data.get(key) is not None]
    if len(sources) > 1:
        raise ValueError("seeded-keygen: give at most one of pcap, mtime_file")
    if sources:
        clash = [k for k in ("epoch_start", "epoch_stop", "seeds", "seed_start", "seed_stop")
                 if data.get(k) is not None]
        if clash:
            raise ValueError(f"seeded-keygen: {sources[0]} derives the epoch window; "
                             f"do not also pass {', '.join(clash)}")
        slack = {k: int(data[k]) for k in ("before", "after") if data.get(k) is not None}
        if sources[0] == "pcap":
            marker = data.get("pcap_marker")
            if marker is not None and not isinstance(marker, str):
                raise ValueError("pcap_marker must be a string")
            window = sk.epoch_window_from_pcap(
                Path(data["pcap"]).read_bytes(),
                marker=None if marker is None else marker.encode("utf-8"), **slack)
        else:
            window = sk.epoch_window_from_mtime(data["mtime_file"], **slack)
        epoch_start, epoch_stop = window["epoch_start"], window["epoch_stop"]
    result = sk.recover(
        int(data["n"]),
        scheme=scheme,
        seeds=data.get("seeds"),
        seed_start=data.get("seed_start"),
        seed_stop=data.get("seed_stop"),
        epoch_start=epoch_start,
        epoch_stop=epoch_stop,
        serial=data.get("serial"),
        shift=int(data.get("shift", 16)),
        ciphertext=data.get("ciphertext"),
        workers=None if data.get("workers") is None else int(data["workers"]),
    )
    if window is not None and isinstance(result, dict):
        result = {**result, "epoch_window": window}
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # pragma: no cover
        raise ValueError(message)


def _read(path):
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise ValueError("JSON exceeds 8 MiB cap")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def main(argv=None) -> int:
    parser = _Parser(prog="prng_recovery.py")
    parser.add_argument("operation", choices=(
        "python", "python-float", "python-seed", "java", "java-truncated", "java-seed",
        "glibc", "glibc-seed", "php", "shuffle", "sample", "xorshift-truncated", "xoshiro",
        "pcg-unknown", "lcg-truncated", "mt-rewind", "seeded-keygen",
    ))
    parser.add_argument("input")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        data = _read(args.input)
        if args.operation == "python":
            result = mc.python_random_recover(data["observations"],
                                              max_rejections=int(data.get("max_rejections", 2)),
                                              timeout_ms=int(data.get("timeout_ms", 20000)))
        elif args.operation == "python-float":
            result = mc.python_random_float_recover(data["outputs"],
                                                    timeout_ms=int(data.get("timeout_ms", 30000)))
        elif args.operation == "python-seed":
            result = mc.python_seed_recover(data["observations"], int(data["seed_start"]),
                                            int(data["seed_stop"]))
        elif args.operation == "java":
            result = mc.java_random_recover(data["outputs"])
        elif args.operation == "java-truncated":
            result = mc.java_random_truncated_recover(
                data["outputs"], int(data["bits"]), timeout_ms=int(data.get("timeout_ms", 20000))
            )
        elif args.operation == "java-seed":
            result = mc.java_seed_recover(data["outputs"], int(data["seed_start"]),
                                          int(data["seed_stop"]))
        elif args.operation == "seeded-keygen":
            result = _seeded_keygen(data)
        elif args.operation == "glibc":
            result = mc.glibc_random_type3_recover(data["outputs"],
                                                   timeout_ms=int(data.get("timeout_ms", 10000)))
        elif args.operation == "glibc-seed":
            result = mc.glibc_seed_recover(data["outputs"], int(data["seed_start"]),
                                           int(data["seed_stop"]))
        elif args.operation == "php":
            result = mc.php_mt_rand_recover(data["outputs"],
                                            timeout_ms=int(data.get("timeout_ms", 20000)))
        elif args.operation == "shuffle":
            result = mc.python_shuffle_observations(data["before"], data["after"])
        elif args.operation == "sample":
            result = mc.python_sample_observations(data["population"], data["sample"])
        elif args.operation == "xorshift-truncated":
            result = mc.xorshift_truncated_recover(
                data["outputs"], int(data["width"]), data["operations"],
                int(data["output_bits"]),
            )
        elif args.operation == "xoshiro":
            result = mc.xoshiro256ss_truncated_recover(
                data["outputs"], int(data.get("output_bits", 64)),
                timeout_ms=int(data.get("timeout_ms", 30000)),
            )
        elif args.operation == "pcg-unknown":
            result = mc.pcg32_unknown_increment_recover(
                data["outputs"], mult=int(data.get("multiplier", mc.PCG32_MULT)),
                timeout_ms=int(data.get("timeout_ms", 30000)),
            )
        elif args.operation == "mt-rewind":
            # B-063: the outputs BEFORE >= 624 consecutive MT19937 words (mt_rewind bounds both the
            # words read and the count). 0 verified outputs prints verified false: not a plain answer.
            # A request outside those bounds is a usage error with its reason (exit 2), never a null
            # candidate: null means the words were read and are not one MT19937 stream.
            tempered = data.get("tempered", True)
            if not isinstance(tempered, bool):
                raise ValueError("tempered must be true (outputs) or false (raw state words)")
            outputs, count = data["outputs"], data.get("count", 624)
            if not isinstance(outputs, list) or not MT_WORDS <= len(outputs) <= mc.MAX_PRNG_WORDS:
                raise ValueError(f"outputs must be a list of {MT_WORDS} to {mc.MAX_PRNG_WORDS} words")
            if any(isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 0xFFFFFFFF for v in outputs):
                raise ValueError("outputs must be 32-bit unsigned integers")
            if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= mc.MAX_MT_REWIND:
                raise ValueError(f"count must be an integer from 1 to {mc.MAX_MT_REWIND}")
            rewound = mc.mt_rewind(outputs, count, tempered=tempered)
            result = None if rewound is None else {
                "previous": rewound[0], "verified_outputs": rewound[1], "verified": rewound[1] > 0}
        else:
            result = mc.lcg_power2_truncated_recover(
                data["outputs"], int(data["output_bits"]),
                state_bits=data.get("state_bits"),
                a=None if data.get("multiplier") is None else int(data["multiplier"]),
                c=None if data.get("increment") is None else int(data["increment"]),
                require_odd_multiplier=bool(data.get("require_odd_multiplier", False)),
                require_odd_increment=bool(data.get("require_odd_increment", False)),
                timeout_ms=int(data.get("timeout_ms", 30000)),
            )
        output = {"candidate": result, "verified": bool(isinstance(result, dict) and result.get("verified"))}
        print(json.dumps(output, sort_keys=True))
        return 0
    except (KeyError, OSError, TypeError, ValueError, OverflowError, UnicodeError,
            RecursionError, MemoryError, json.JSONDecodeError) as exc:
        print(f"prng_recovery: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
