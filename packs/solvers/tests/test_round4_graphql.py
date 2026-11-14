"""GraphQL introspection/document analysis remains entirely offline."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))

import graphql_analyzer as gql  # noqa: E402


def _ref(kind, name=None, nested=None):
    return {"kind": kind, "name": name, "ofType": nested}


def _schema():
    return {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "secretToken", "args": [], "type": _ref("SCALAR", "String"),
                 "isDeprecated": False},
                {"name": "users", "args": [], "type": _ref("LIST", nested=_ref("OBJECT", "User")),
                 "isDeprecated": False},
            ]},
            {"kind": "OBJECT", "name": "User", "fields": [
                {"name": "manager", "args": [], "type": _ref("OBJECT", "User"),
                 "isDeprecated": False},
                {"name": "passwordHash", "args": [], "type": _ref("SCALAR", "String"),
                 "isDeprecated": True, "deprecationReason": "legacy"},
            ]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                {"name": "resetPassword", "args": [{"name": "token", "type": _ref("SCALAR", "String")}],
                 "type": _ref("OBJECT", "User"), "isDeprecated": False},
            ]},
            {"kind": "SCALAR", "name": "String"},
        ],
    }}}


def test_introspection_sensitive_lists_cycles_mutations_and_plans():
    result = gql.analyze_introspection(_schema())
    assert result["roots"] == {"query": "Query", "mutation": "Mutation", "subscription": None}
    assert {row["path"] for row in result["sensitive_fields"]} == {
        "Query.secretToken", "User.passwordHash", "Mutation.resetPassword"
    }
    assert result["list_fields"] == [{"path": "Query.users", "pagination_arguments": [],
                                      "risk": "list field exposes no conventional pagination argument"}]
    assert result["recursive_paths"][0]["path"] == ["User.manager"]
    assert result["mutations"][0]["name"] == "resetPassword"
    plan = next(row for row in result["review_plans"] if row["name"] == "review_secretToken")
    assert plan["value"] == "query OfflineReview { secretToken }"
    assert plan["sent"] is False and result["requests_sent"] == 0


def test_document_depth_alias_fragments_directives_and_strings():
    aliases = " ".join(f"a{i}:user(id:{i}){{name}}" for i in range(24))
    document = f'''query Deep($skip: Boolean!) @cache(ttl: 1) {{
      {aliases}
      viewer {{ manager {{ manager {{ name bio(format: "}} not syntax") }} }} }}
      ...UserBits
    }}
    fragment UserBits on User {{ passwordHash @skip(if:$skip) }}'''
    result = gql.analyze_document(document)
    assert result["alias_count"] == 24
    assert result["max_depth"] == 4
    assert {row["kind"] for row in result["findings"]} == {"alias_amplification", "repeated_field"}
    assert result["fragments"]["UserBits"]["type"] == "User"
    assert set(result["directives"]) == {"cache", "skip"}
    assert result["requests_sent"] == 0


def test_request_batch_analysis_and_invalid_fragments():
    request = [
        {"operationName": "A", "query": "query A { viewer { name } }", "variables": {}},
        {"query": "mutation { resetPassword(token: \"x\") { manager { name } } }"},
    ]
    result = gql.analyze_request_json(request)
    assert result["findings"] == [{"kind": "http_batch", "count": 2}]
    assert result["requests"][1]["document"]["operations"][0]["kind"] == "mutation"
    undefined = gql.analyze_document("{ viewer { ...Missing } }")
    assert undefined["findings"] == [{"kind": "undefined_fragments", "names": ["Missing"]}]


def test_guarded_cli_and_caps(tmp_path, capsys):
    path = tmp_path / "schema.json"
    path.write_text(json.dumps(_schema()))
    assert gql.main([str(path), "--kind", "schema", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["offline"] is True
    assert gql.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err
    with pytest.raises(gql.GraphQLError):
        gql.analyze_document("query { broken(")


def test_seeded_document_mutations_fail_only_with_graphql_error():
    rng = random.Random(0x6A617068)
    seed = 'query Q($x:Int){ viewer { name bio(format:"long") } }'
    alphabet = "{}():@$![],.# abcXYZ012\"\\"
    for _ in range(1000):
        text = list(seed)
        for _ in range(rng.randrange(1, 8)):
            action = rng.randrange(3)
            if action == 0 and text:
                text[rng.randrange(len(text))] = rng.choice(alphabet)
            elif action == 1 and text:
                del text[rng.randrange(len(text))]
            else:
                text.insert(rng.randrange(len(text) + 1), rng.choice(alphabet))
        try:
            result = gql.analyze_document("".join(text))
            assert result["offline"] is True
        except gql.GraphQLError:
            pass
