"""Seeded-keygen (PRNG prime) RSA recovery (B-064).

Some RSA challenges generate the key from a *seeded* PRNG: a seed is drawn from something an
attacker can bound (a power-up epoch, a PID, a packet timestamp), the PRNG is reseeded with it, and
the primes are the first primes at or above successive PRNG draws.  Given the modulus ``n`` and the
reconstructed keygen *scheme* (read, as prose, from the challenge's own description — a pcap payload,
a handout, a source snippet), this module bounds the seed (by hand, or from a capture's packet
timestamps or a file's mtime), searches it in parallel until a produced prime divides ``n``, factors
fully, and (when a ciphertext is supplied) decrypts.

What is reconstructed here, not guessed
---------------------------------------
The keygen scheme is DATA the caller supplies (:class:`KeygenScheme`): which PRNG, the prime bit
width, whether the top bit / low bit are forced, how many primes are drawn in turn, and the public
exponent.  This module does not read the keygen prose; a human or a model reads the stated scheme and
fills the fields.  Everything after that is mechanical and *verified*: a result is returned ONLY when
a seed's produced primes (plus at most one prime cofactor) multiply back to ``n`` exactly and the key
gate passes — :func:`rsa_attacks.recover_seeded_private_key` for a two-prime modulus (``p*q == n``,
both independently prime, ``e*d == 1 (mod lcm)``, PyCryptodome's checker when installed), or the
equivalent multi-prime gate here for three or more distinct primes.

Outcomes of :func:`recover`:

* a verified key dict;
* ``None`` when no seed in the window produces a prime dividing ``n`` (wrong window or scheme);
* :class:`SeededKeygenGateError` when some seed DID produce a prime dividing ``n`` but no such seed
  passes the gate (composite cofactor, repeated prime, ``e`` not invertible).  That is a real partial
  result — a found factor — and is reported loudly with the seeds, primes and reason, never folded
  into ``None``.  The whole window is searched before it is raised.

Offline and bounded.  No network, no token, no challenge binary is executed.  The seed range is
capped at :data:`DEFAULT_SEED_CAP` candidates; a larger request is declined loudly.
"""

from __future__ import annotations

import functools
import importlib.util
import math
import os
import random
import sys
from dataclasses import dataclass
from pathlib import Path

try:  # Imported both as ``solvers.common...`` and as a standalone common module (see rsa_attacks).
    from . import modern_crypto as _mc
    from . import rsa_attacks as _rsa
    from . import psearch as _ps
except ImportError:  # pragma: no cover - exercised by the repository's flat CLI import style
    from _shadowed import common_module
    _mc = common_module("modern_crypto")
    _rsa = common_module("rsa_attacks")
    _ps = common_module("psearch")


# One million candidate seeds, matching python_seed_recover / java_seed_recover in modern_crypto and
# the cap documented for the prng_recovery CLI.  A request above this is refused, not truncated.
DEFAULT_SEED_CAP = 1_000_000

# PRNGs whose seed->prime replay this module reproduces exactly.  "python_mt19937" is CPython's
# ``random.Random(seed)`` (the common ``random.getrandbits`` keygen).  Unknown names decline loudly.
SUPPORTED_PRNGS = ("python_mt19937",)

# Default slack around a timestamp anchor, in seconds.  A keygen runs BEFORE the packet or file that
# reveals it (csctf 9151: the seed epoch was about 4 s before the REG packet), so the window reaches
# further back than forward.  Both are overridable; the resulting span is still capped.
DEFAULT_BEFORE = 600
DEFAULT_AFTER = 60

# Seeds handed to one parallel_search call.  The window is searched block by block, in order; after a
# dividing seed fails the gate only the rest of ITS block is searched again (a parallel search returns
# whichever match a worker finds first, so nothing earlier in the block is known to be non-dividing),
# never the window from the start.  k gate failures cost at most k extra blocks, not k windows.
SEARCH_BLOCK = 65_536

# The capture reader this module reuses (solvers/toolkits/network.py's Capture).
_NETWORK_READER = Path(__file__).resolve().parents[1] / "toolkits" / "network.py"


class SeededKeygenError(ValueError):
    """A scheme or seed-range input that cannot be honoured (no silent fallback)."""


class SeededKeygenGateError(SeededKeygenError):
    """A seed produced a prime dividing ``n`` but the factorisation/key gate refused every such seed.

    ``failures`` is a list of ``{"seed", "primes", "reason"}`` dicts, one per dividing seed."""

    def __init__(self, failures):
        self.failures = list(failures)
        detail = "; ".join(
            f"seed {f['seed']}: {f['reason']} (dividing primes {f['primes']})" for f in self.failures
        )
        super().__init__(f"seeded keygen found a factor of n but the gate refused it: {detail}")


@dataclass(frozen=True)
class KeygenScheme:
    """The reconstructed PRNG prime-keygen, as read from the challenge's own description.

    prng          PRNG reseeded per key.  Only ``"python_mt19937"`` is supported today.
    nbits         bit width of each raw PRNG draw (e.g. 512 for a 1024-bit modulus).
    set_top_bit   force bit ``nbits-1`` of each draw (the usual "full-width prime" trick).
    set_odd       force the low bit of each draw before searching upward for a prime.
    num_primes    primes drawn, in turn, from the one reseeded PRNG.  2 for textbook RSA; 1 when only
                  one factor is seeded (the cofactor must then be prime); 3+ for multi-prime RSA.
    prime_method  how a draw becomes a prime.  ``"next_prime_ge"``: the first prime at or above the
                  (adjusted) draw — the ``while not isprime: v += step`` idiom.
                  ``"strict_next_prime"``: the first prime strictly greater than the draw (sympy's
                  ``nextprime`` convention).
    e             public exponent.
    """

    prng: str = "python_mt19937"
    nbits: int = 512
    set_top_bit: bool = True
    set_odd: bool = True
    num_primes: int = 2
    prime_method: str = "next_prime_ge"
    e: int = 65537

    def validate(self) -> None:
        if self.prng not in SUPPORTED_PRNGS:
            raise SeededKeygenError(
                f"unsupported prng {self.prng!r}; known: {', '.join(SUPPORTED_PRNGS)}"
            )
        if not isinstance(self.nbits, int) or isinstance(self.nbits, bool) or not 8 <= self.nbits <= 8192:
            raise SeededKeygenError("nbits must be an int in [8, 8192]")
        if not isinstance(self.num_primes, int) or isinstance(self.num_primes, bool) \
                or not 1 <= self.num_primes <= 16:
            raise SeededKeygenError("num_primes must be an int in [1, 16]")
        if self.prime_method not in ("next_prime_ge", "strict_next_prime"):
            raise SeededKeygenError(f"unknown prime_method {self.prime_method!r}")
        if not isinstance(self.e, int) or isinstance(self.e, bool) or self.e <= 1:
            raise SeededKeygenError("e must be an int > 1")
        for flag in (self.set_top_bit, self.set_odd):
            if not isinstance(flag, bool):
                raise SeededKeygenError("set_top_bit and set_odd must be booleans")


def _next_prime(value: int, scheme: KeygenScheme) -> int:
    """The prime selected from a (bit-adjusted) draw ``value`` under ``scheme``'s prime method."""
    if scheme.prime_method == "strict_next_prime":
        value += 1
    if value <= 2:
        return 2
    # The first prime at or above an even value > 2 is at or above value + 1; from there only odd
    # numbers need testing.  This is the same answer as a step-1 scan, at half the primality tests.
    if not value & 1:
        value += 1
    while not _mc.is_prime(value):
        value += 2
    return value


def _iter_primes(seed: int, scheme: KeygenScheme):
    """Lazily yield the primes a key for ``seed`` uses, in draw order (``scheme`` already valid)."""
    rng = random.Random(seed)
    top = (1 << (scheme.nbits - 1)) if scheme.set_top_bit else 0
    low = 1 if scheme.set_odd else 0
    for _ in range(scheme.num_primes):
        yield _next_prime(rng.getrandbits(scheme.nbits) | top | low, scheme)


def _check_seed(seed) -> None:
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise SeededKeygenError("seed must be a non-negative int")


def generate_primes(seed: int, scheme: KeygenScheme):
    """The primes a key for ``seed`` would use, in draw order.  Deterministic replay, no key emitted."""
    scheme.validate()
    _check_seed(seed)
    return list(_iter_primes(seed, scheme))


def _seed_divisor(n: int, scheme: KeygenScheme, seed: int) -> int:
    """The first prime a key for ``seed`` produces that divides ``n``, else 0.

    Primes are generated lazily and the search stops at the first divisor, so a seed costs only the
    draws up to it.  ``scheme`` is validated once by the caller, not per seed.  Module-level so
    :func:`psearch.parallel_search` can pickle a ``functools.partial`` over it under the ``spawn``
    start method; it returns a truthy prime used as the ``first_match`` score."""
    for prime in _iter_primes(seed, scheme):
        if n % prime == 0:
            return prime
    return 0


def _independently_prime(value: int) -> bool:
    if not _mc.is_prime(value):
        return False
    try:
        import sympy
    except ImportError:  # pragma: no cover - sympy is pinned; this only guards a broken install
        return True
    return bool(sympy.isprime(value))


def _factor_with_seed(n: int, scheme: KeygenScheme, seed: int):
    """``(primes, None)`` — every distinct prime of ``n`` — or ``(dividing_primes, reason)``.

    ``primes`` are the seed's primes that divide ``n`` plus the cofactor when that is prime; their
    product is exactly ``n`` and each is distinct.  Any other shape is a named gate failure."""
    dividing = []
    rest = n
    for prime in _iter_primes(seed, scheme):
        if prime in dividing or rest % prime:
            continue
        dividing.append(prime)
        rest //= prime
        if rest % prime == 0:
            return sorted(dividing), f"prime {prime} divides n more than once"
    # No "cofactor repeats a seeded prime" case: right after dividing by p the check above proves
    # p no longer divides rest, and further division cannot make it divide again, so rest is never
    # one of the dividing primes here.
    if rest == 1:
        primes = dividing
    elif not _independently_prime(rest):
        return sorted(dividing), f"cofactor {rest} is not prime"
    else:
        primes = dividing + [rest]
    if len(primes) < 2:
        return sorted(dividing), "n is itself prime"
    if math.prod(primes) != n:  # defensive: cannot happen by construction, refuse rather than guess
        return sorted(dividing), "primes do not multiply back to n"
    return sorted(primes), None


def _multiprime_key(n: int, e: int, primes):
    """``d`` for a square-free multi-prime modulus (decrypt with ``pow(c, d, n)``), else ``None``.

    Mirrors rsa_attacks' two-prime gate: every prime independently checked, the product equals n,
    ``gcd(e, lambda) == 1``, ``e*d == 1 (mod lambda)``, and RSA round trips including non-units."""
    if len(set(primes)) != len(primes) or math.prod(primes) != n:
        return None
    if not all(_independently_prime(p) for p in primes):
        return None
    phi = math.prod(p - 1 for p in primes)
    lam = math.lcm(*(p - 1 for p in primes))
    if math.gcd(e, phi) != 1:
        return None
    d = pow(e, -1, phi)
    if (e * d - 1) % lam:
        return None
    probes = {0, 1, 2, 42 % n, n - 1, *primes}
    if any(pow(pow(m, e, n), d, n) != m % n for m in probes):
        return None
    return d


def _gate(n: int, scheme: KeygenScheme, seed: int):
    """``(key_dict, None)`` for a seed whose primes factor ``n`` and pass the key gate, else
    ``(None, failure_dict)``."""
    primes, reason = _factor_with_seed(n, scheme, seed)
    if reason is not None:
        return None, {"seed": seed, "primes": primes, "reason": reason}
    if len(primes) == 2:
        key = _rsa.recover_seeded_private_key(n, scheme.e, primes[0])
        if key is None:
            return None, {"seed": seed, "primes": primes,
                          "reason": "two-prime key gate refused (e not invertible or check failed)"}
        d, p, q = key
        return {"seed": seed, "primes": [p, q], "p": p, "q": q, "d": d}, None
    d = _multiprime_key(n, scheme.e, primes)
    if d is None:
        return None, {"seed": seed, "primes": primes,
                      "reason": "multi-prime key gate refused (e not invertible or check failed)"}
    return {"seed": seed, "primes": primes, "d": d}, None


def _check_window_args(**values) -> None:
    for name, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise SeededKeygenError(f"{name} must be a non-negative int")


def seeds_from_epochs(epoch_start: int, epoch_stop: int, serial: int, *, shift: int = 16):
    """Seeds ``(epoch << shift) | serial`` for ``epoch`` in ``[epoch_start, epoch_stop)``.

    Models the common ``seed = (power_up_epoch << 16) | serial`` field-provisioning scheme.  Raises
    when the span exceeds the cap or ``serial`` does not fit in ``shift`` bits, rather than silently
    clipping."""
    _check_window_args(epoch_start=epoch_start, epoch_stop=epoch_stop, serial=serial, shift=shift)
    if epoch_stop <= epoch_start:
        raise SeededKeygenError("epoch_stop must exceed epoch_start")
    if epoch_stop - epoch_start > DEFAULT_SEED_CAP:
        raise SeededKeygenError(
            f"epoch span {epoch_stop - epoch_start} exceeds seed cap {DEFAULT_SEED_CAP}"
        )
    if serial >= (1 << shift):
        raise SeededKeygenError(f"serial {serial} does not fit in {shift} bits")
    return [(epoch << shift) | serial for epoch in range(epoch_start, epoch_stop)]


def _window(anchors, before: int, after: int, source: str, **extra):
    _check_window_args(before=before, after=after)
    first, last = min(anchors), max(anchors)
    start = max(0, first - before)
    stop = last + after + 1  # half-open: the last anchor second plus `after` is included
    if stop - start > DEFAULT_SEED_CAP:
        raise SeededKeygenError(
            f"timestamp window [{start}, {stop}) spans {stop - start} s, over seed cap {DEFAULT_SEED_CAP}"
        )
    return {"epoch_start": start, "epoch_stop": stop, "first_anchor": first, "last_anchor": last,
            "anchor_count": len(anchors), "source": source, **extra}


def _load_network():
    name = "seeded_keygen_network_reader"
    if name in sys.modules:
        return sys.modules[name]
    if not _NETWORK_READER.is_file():
        raise SeededKeygenError(f"capture reader missing: {_NETWORK_READER.name} not found")
    spec = importlib.util.spec_from_file_location(name, _NETWORK_READER)
    if spec is None or spec.loader is None:
        raise SeededKeygenError("capture reader solvers/toolkits/network.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def epoch_window_from_pcap(data: bytes, *, marker: bytes | None = None,
                           before: int = DEFAULT_BEFORE, after: int = DEFAULT_AFTER):
    """The epoch window ``[t_first - before, t_last + after]`` (as a half-open ``epoch_stop``) from a
    pcap/pcapng's packet timestamps.

    ``marker``: only packets whose payload (or, undecoded, raw record) contains these bytes anchor
    the window — e.g. ``b"REG"`` for the registration packet that carries the public key.  Without it
    every timestamped packet anchors.  Returns a dict with ``epoch_start``/``epoch_stop`` (feed them
    to :func:`recover`), the anchor span and count, and ``damaged`` (why the reader stopped early, or
    ``None``).  Raises :class:`SeededKeygenError` for a non-capture, a capture with no timestamped
    packets, or a marker that matches no packet."""
    if not isinstance(data, (bytes, bytearray)):
        raise SeededKeygenError("pcap data must be bytes")
    if marker is not None and (not isinstance(marker, (bytes, bytearray)) or not marker):
        raise SeededKeygenError("marker must be non-empty bytes")
    network = _load_network()
    try:
        capture = network.Capture(bytes(data), "seeded-keygen-capture")
    except ValueError as exc:
        raise SeededKeygenError(f"not a readable capture: {exc}") from exc
    anchors = []
    for packet in capture.packets:
        if packet.ts is None:
            continue
        if marker is not None and marker not in (packet.payload or b"") and marker not in packet.raw:
            continue
        anchors.append(packet.ts // 1_000_000_000)
    if not anchors:
        what = f"no packet containing marker {bytes(marker)!r}" if marker is not None \
            else "no timestamped packet"
        raise SeededKeygenError(f"capture has {what}; cannot bound the seed epoch")
    return _window(anchors, before, after, "pcap", damaged=capture.damaged)


def epoch_window_from_mtime(path, *, before: int = DEFAULT_BEFORE, after: int = DEFAULT_AFTER):
    """The epoch window around a file's modification time (whole seconds), same shape as
    :func:`epoch_window_from_pcap`.  A missing file raises (``OSError``), never a guessed window."""
    mtime = int(os.stat(path).st_mtime)
    if mtime < 0:
        raise SeededKeygenError(f"file mtime {mtime} is before the epoch")
    return _window([mtime], before, after, "mtime", damaged=None)


def _coerce_seed_list(seeds, seed_start, seed_stop, epoch_start, epoch_stop, serial, shift):
    given = [name for name, used in (
        ("seeds", seeds is not None),
        ("seed_start/seed_stop", seed_start is not None or seed_stop is not None),
        ("epoch_start/epoch_stop/serial",
         epoch_start is not None or epoch_stop is not None or serial is not None),
    ) if used]
    if len(given) > 1:
        raise SeededKeygenError(f"give exactly one seed source, not {' and '.join(given)}")
    if seeds is not None:
        materialised = list(seeds)
        if len(materialised) > DEFAULT_SEED_CAP:
            raise SeededKeygenError(f"seed list of {len(materialised)} exceeds cap {DEFAULT_SEED_CAP}")
        for seed in materialised:
            if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
                raise SeededKeygenError("every seed must be a non-negative int")
        return materialised
    if epoch_start is not None or epoch_stop is not None or serial is not None:
        if epoch_start is None or epoch_stop is None or serial is None:
            raise SeededKeygenError("epoch search needs epoch_start, epoch_stop and serial")
        return seeds_from_epochs(epoch_start, epoch_stop, serial, shift=shift)
    if seed_start is not None or seed_stop is not None:
        if seed_start is None or seed_stop is None:
            raise SeededKeygenError("a seed range needs both seed_start and seed_stop")
        _check_window_args(seed_start=seed_start, seed_stop=seed_stop)
        if seed_stop <= seed_start:
            raise SeededKeygenError("seed_stop must exceed seed_start")
        if seed_stop - seed_start > DEFAULT_SEED_CAP:
            raise SeededKeygenError(
                f"seed span {seed_stop - seed_start} exceeds cap {DEFAULT_SEED_CAP}"
            )
        return list(range(seed_start, seed_stop))
    raise SeededKeygenError("no seed source: pass seeds, seed_start/seed_stop or epoch_*/serial")


def recover(n, *, scheme=None, seeds=None, seed_start=None, seed_stop=None,
            epoch_start=None, epoch_stop=None, serial=None, shift=16,
            ciphertext=None, workers=None):
    """Recover the seeded-keygen RSA key for modulus ``n``.

    Supply the seed source exactly one of three ways (more than one raises
    :class:`SeededKeygenError`): an explicit ``seeds`` iterable, a
    ``seed_start``/``seed_stop`` half-open range, or ``epoch_start``/``epoch_stop``/``serial`` for
    the ``(epoch << shift) | serial`` scheme (:func:`epoch_window_from_pcap` /
    :func:`epoch_window_from_mtime` derive the epoch window from timestamps).  Returns on success::

        {"seed", "primes", "e", "d", "n", "verified": True, "gate_failures": [...],
         ["p", "q" for a two-prime modulus,] ["plaintext_int", "plaintext_hex"]}

    ``None`` when no seed in range produces a prime dividing ``n``.  Raises
    :class:`SeededKeygenGateError` when seeds produced a dividing prime but none passed the gate
    (after searching the whole window), and :class:`SeededKeygenError` for a bad scheme or range."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 6:
        raise SeededKeygenError("n must be an int >= 6")
    scheme = scheme if scheme is not None else KeygenScheme()
    scheme.validate()
    if ciphertext is not None and (not isinstance(ciphertext, int) or isinstance(ciphertext, bool)
                                   or not 0 <= ciphertext < n):
        raise SeededKeygenError("ciphertext must be an int in [0, n)")
    # Order-preserving de-duplication: a repeated seed would only repeat its gate failure.
    remaining = list(dict.fromkeys(_coerce_seed_list(seeds, seed_start, seed_stop,
                                                     epoch_start, epoch_stop, serial, shift)))
    score = functools.partial(_seed_divisor, n, scheme)
    failures = []
    key = None
    for offset in range(0, len(remaining), SEARCH_BLOCK):
        block = remaining[offset:offset + SEARCH_BLOCK]
        while block:
            seed, _prime = _ps.parallel_search(block, score, workers=workers, first_match=True)
            if seed is None:
                break
            key, failure = _gate(n, scheme, seed)
            if key is not None:
                break
            # A dividing seed that fails the gate must not end the search: drop THAT seed (seeds
            # are unique, see above) and search the rest of this block again.
            failures.append(failure)
            index = block.index(seed)
            block = block[:index] + block[index + 1:]
        if key is not None:
            break
    if key is None:
        if failures:
            raise SeededKeygenGateError(failures)
        return None
    d = key["d"]
    result = {**key, "e": scheme.e, "n": n, "verified": True, "gate_failures": failures}
    if ciphertext is not None:
        message = pow(ciphertext, d, n)
        result["plaintext_int"] = message
        result["plaintext_hex"] = _mc.to_bytes(message).hex()
    return result


__all__ = [
    "DEFAULT_SEED_CAP",
    "DEFAULT_BEFORE",
    "DEFAULT_AFTER",
    "SUPPORTED_PRNGS",
    "SeededKeygenError",
    "SeededKeygenGateError",
    "KeygenScheme",
    "generate_primes",
    "seeds_from_epochs",
    "epoch_window_from_pcap",
    "epoch_window_from_mtime",
    "recover",
]
