from __future__ import annotations

import sys
from pathlib import Path


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers/toolkits"
sys.path.insert(0, str(TOOLKITS))
import jail_escape as J  # noqa: E402


def test_shell_constraints_rank_only_payloads_that_fit():
    constraints = J.constraints_from_mapping({
        "mode": "shell",
        "banned_chars": [" "],
        "banned_substrings": ["printf"],
    })
    rows = J.suggest(constraints, include_blocked=False)
    assert rows
    assert all(row["satisfies"] and " " not in row["payload"] for row in rows)
    assert rows[0]["name"] in {"shell-ifs", "shell-stdin", "shell-brace"}


def test_python_no_builtins_and_no_parens_are_annotated_not_executed():
    constraints = J.constraints_from_mapping({
        "mode": "python", "no_builtins": True, "no_parentheses": True,
    })
    rows = J.suggest(constraints)
    direct = next(row for row in rows if row["name"] == "python-import")
    assert not direct["satisfies"]
    assert any("builtins" in v for v in direct["violations"])
    assert any("parentheses" in v for v in direct["violations"])
    # The engine returns catalogue strings. It has no execution API or dynamic eval path.
    assert not hasattr(J, "execute")


def test_natural_language_parser_is_conservative():
    constraints = J.parse_constraints(
        "Python 3.12 expression only; no builtins; banned characters: '/' and ';'; audit hook enabled"
    )
    assert constraints.mode == "python"
    assert constraints.version == "3.12"
    assert constraints.expression_only and constraints.no_builtins and constraints.audit_hook
    assert "/" in constraints.banned_chars and ";" in constraints.banned_chars
    rows = J.suggest(constraints)
    assert rows[0]["score"] >= rows[-1]["score"] or rows[-1]["satisfies"] is False


def test_limits_and_cli_error_are_guarded(capsys):
    assert J.main([]) == 2
    assert "jail_escape:" in capsys.readouterr().err
    try:
        J.constraints_from_mapping({"banned_substrings": ["x"] * (J.MAX_BANS + 1)})
    except ValueError:
        pass
    else:
        raise AssertionError("constraint count cap was not enforced")

