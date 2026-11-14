"""Exact-roundtrip recovery across Python, Java, glibc, and PHP PRNG families."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import modern_crypto as mc  # noqa: E402
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import prng_recovery as cli  # noqa: E402


def test_python_full_words_and_random_float_state_recovery():
    generator = random.Random(20261104)
    words = [generator.getrandbits(32) for _ in range(625)]
    result = mc.python_random_recover([{"kind": "uint32", "value": value} for value in words[:624]],
                                      max_rejections=0)
    assert result["next_uint32"] == words[624]
    assert result["verified"] is True

    generator = random.Random(0xC5C7F)
    values = [generator.random() for _ in range(625)]
    assert mc.python_random_float_recover(values[:312], timeout_ms=5000) is None
    result = mc.python_random_float_recover(values[:624], timeout_ms=30000)
    assert result["next"] == values[624]
    assert result["numerator"] / float(1 << 53) == values[624]
    assert result["verified"] is True


def test_python_mixed_width_seed_search_and_shuffle_sample_inversion():
    generator = random.Random(777)
    observations = [
        {"kind": "random", "value": generator.random()},
        {"kind": "getrandbits", "bits": 13, "value": generator.getrandbits(13)},
        {"kind": "randrange", "stop": 100, "value": generator.randrange(100)},
    ]
    expected = generator.getrandbits(32)
    result = mc.python_seed_recover(observations, 700, 800)
    assert result == {"seed": 777, "candidate_count": 1, "next_uint32": expected, "verified": True}

    before = list("ABCDEFGHIJ")
    after = before[:]
    random.Random(9).shuffle(after)
    rows = mc.python_shuffle_observations(before, after)
    work = before[:]
    for index, row in zip(range(len(work) - 1, 0, -1), rows):
        work[index], work[row["value"]] = work[row["value"]], work[index]
    assert work == after

    population = list(range(20))
    selected = random.Random(4).sample(population, 5)
    rows = mc.python_sample_observations(population, selected)
    pool, replay = population[:], []
    for i, row in enumerate(rows):
        replay.append(pool[row["value"]])
        pool[row["value"]] = pool[len(pool) - i - 1]
    assert replay == selected


def _java(seed, count):
    state = (seed ^ mc.JAVA_RANDOM_MULTIPLIER) & mc.JAVA_RANDOM_MASK
    out = []
    for _ in range(count):
        state = (state * mc.JAVA_RANDOM_MULTIPLIER + mc.JAVA_RANDOM_ADDEND) & mc.JAVA_RANDOM_MASK
        out.append(state >> 16)
    return out


def test_java_random_low16_and_time_seed_search():
    values = _java(123456, 7)
    result = mc.java_random_recover(values[:6])
    assert result["next_uint32"] == values[6]
    assert result["state_candidates"] == 1
    assert result["verified"] is True

    result = mc.java_seed_recover(values[:3], 123000, 124000)
    assert result["seed"] == 123456
    assert result["next_uint32"] == values[3]


def test_glibc_type3_and_php_mt_partial_outputs():
    source = random.Random(123)
    states = [source.getrandbits(32) for _ in range(31)]
    for index in range(31, 101):
        states.append((states[index - 3] + states[index - 31]) & 0xFFFFFFFF)
    outputs = [value >> 1 for value in states]
    result = mc.glibc_random_type3_recover(outputs[:90])
    assert result["next"] == outputs[90]
    assert result["verified"] is True

    state = [source.getrandbits(32) for _ in range(624)]
    php = []
    for _ in range(3):
        php.extend(mc._mt_temper(value) >> 1 for value in state)
        state = mc._mt_twist(state)
    # One 31-bit state cycle remains ambiguous; two complete cycles prove the next value.
    assert mc.php_mt_rand_recover(php[:624]) is None
    result = mc.php_mt_rand_recover(php[:1248])
    assert result["next"] == php[1248]
    assert result["verified"] is True


def test_guarded_prng_cli(tmp_path, capsys):
    values = _java(55, 5)
    fixture = tmp_path / "java.json"
    fixture.write_text(json.dumps({"outputs": values[:4]}), encoding="utf-8")
    assert cli.main(["java", str(fixture), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["candidate"]["next_uint32"] == values[4]
    assert output["verified"] is True

    bad = tmp_path / "bad.json"
    bad.write_bytes(b"{\xff")
    assert cli.main(["python", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("prng_recovery: ")
    assert "Traceback" not in captured.err

