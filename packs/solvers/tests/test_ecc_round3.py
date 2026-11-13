"""Synthetic offline coverage for invalid-curve/CRT and MOV pairing recovery."""
from __future__ import annotations

import json
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import ecc_weak as ecc  # noqa: E402


def _invalid_observations(secret: int):
    # Three deliberately different b coefficients.  The supplied points have exact smooth
    # orders 11, 7 and 5 respectively while the target-style addition formula keeps a=2.
    rows = []
    for b, point, order in (
        (1, (938, 907), 11),
        (2, (688, 278), 7),
        (4, (530, 226), 5),
    ):
        rows.append({
            "p": 1019, "a": 2, "b": b, "point": point, "order": order,
            "response": ecc.ec_mul(secret, point, 1019, 2),
        })
    return rows


def test_invalid_curve_subgroups_recover_residues_and_crt_scalar():
    secret = 123
    rows = _invalid_observations(secret)
    assert [ecc.invalid_curve_residue(row["p"], row["a"], row["b"], row["point"],
                                      row["response"], row["order"])
            for row in rows] == [(2, 11), (4, 7), (3, 5)]

    # Without a verification object the CRT residue is the unique candidate under the bound, so the
    # scalar is surfaced, but it is NOT point-proven against Q — verified must stay False (a too-tight
    # scalar_bound would otherwise emit a wrong value stamped verified).
    result = ecc.recover_invalid_curve_scalar(rows, scalar_bound=300)
    assert result["residue"] == secret
    assert result["modulus"] == 11 * 7 * 5
    assert result["scalar"] == secret
    assert result["verified"] is False

    # Supplying {p,a,b,G,Q} runs the [scalar]G == Q filter and only then stamps verified=True.
    # Pick any G=(x,y) and choose b so G lies on y^2 = x^3 + 2x + b (mod p); ec_mul only uses a.
    G = (5, 17)
    bb = (G[1] * G[1] - pow(G[0], 3, 1019) - 2 * G[0]) % 1019
    Q = ecc.ec_mul(secret, G, 1019, 2)
    proven = ecc.recover_invalid_curve_scalar(
        rows, scalar_bound=300, verification={"p": 1019, "a": 2, "b": bb, "G": G, "Q": Q})
    assert proven["scalar"] == secret
    assert proven["verified"] is True

    # A too-tight bound that excludes the real key must NOT be stamped verified (it is a wrong value).
    tight = ecc.recover_invalid_curve_scalar(rows, scalar_bound=secret)  # excludes secret itself
    assert tight is None or tight["verified"] is False


def test_invalid_curve_refuses_bad_point_and_ambiguous_scalar():
    rows = _invalid_observations(123)
    bad = [dict(row) for row in rows]
    bad[0]["response"] = (0, 0)
    assert ecc.recover_invalid_curve_scalar(bad, scalar_bound=300) is None

    result = ecc.recover_invalid_curve_scalar(rows[:1], scalar_bound=300)
    assert result["residue"] == 2
    assert result["scalar"] is None
    assert result["verified"] is False


def test_supersingular_mov_transfer_recovers_and_replays_scalar():
    # E: y^2=x^3+x over F_43 has #E=44.  P has order 11 and 43 == -1 (mod 11), so k=2.
    point = (31, 18)
    secret = 7
    public = ecc.ec_mul(secret, point, 43, 1)
    assert ecc.embedding_degree(43, 11, 12) == 2
    result = ecc.mov_frey_ruck_recover(43, 1, 0, point, public, 11)
    assert result["scalar"] == secret
    assert result["embedding_degree"] == 2
    assert result["verified"] is True
    assert ecc.ec_mul(result["scalar"], point, 43, 1) == public


def test_mov_declines_unsupported_or_unproven_transfer():
    point = (31, 18)
    public = ecc.ec_mul(3, point, 43, 1)
    assert ecc.mov_frey_ruck_recover(43, 1, 1, point, public, 11) is None
    assert ecc.mov_frey_ruck_recover(43, 1, 0, point, public, 11, embedding=3) is None


def test_guarded_cli_json_and_bad_input(tmp_path, capsys):
    fixture = tmp_path / "invalid.json"
    fixture.write_text(json.dumps({"observations": _invalid_observations(123),
                                   "scalar_bound": 300}), encoding="utf-8")
    assert ecc.main(["invalid-crt", str(fixture), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["candidate"]["scalar"] == 123
    # No verification object in the fixture → CRT-unique candidate, correctly surfaced but not
    # point-proven, so the CLI labels it unproven rather than verified.
    assert output["verified"] is False

    garbage = tmp_path / "garbage"
    garbage.write_bytes(b"not json\xff")
    assert ecc.main(["mov", str(garbage)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("ecc_weak: ")
    assert "Traceback" not in captured.err

