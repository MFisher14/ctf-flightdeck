"""Tests for the schema-aware offline GraphQL execution-cost engine.

``graphql-core`` is used only as a non-circular parser/validator oracle.  The
production engine is a separate stdlib implementation.  Operation selection,
field collection, fragments and @skip/@include follow the published GraphQL
execution/validation semantics: https://spec.graphql.org/September2025/.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import random
import sys

from graphql import build_schema, get_operation_ast, parse, validate
import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import webdepth_graphql_cost as cost  # noqa: E402


SDL = """
schema { query: Root mutation: Mut }
scalar Timestamp
input Filter { active: Boolean = true }
type Root {
  viewer: User!
  users(first: Int): [User!]!
  matrix(limit: Int): [[User!]!]!
}
type Mut { updateName(id: ID!): User! }
type User {
  id: ID!
  name: String!
  friends(limit: Int = 2): [User!]!
}
"""


def _oracle_valid(document: str) -> None:
    """Independent syntax and schema-validation assertion."""

    errors = validate(build_schema(SDL), parse(document))
    assert errors == [], [error.message for error in errors]


def _operation(result: dict, index: int = 0) -> dict:
    return result["operations"][index]


def test_selected_operation_matches_graphql_core_and_ignores_unselected_cost():
    document = """
      query Expensive { users(first: 100) { id } }
      query Cheap { viewer { id } }
    """
    _oracle_valid(document)
    oracle = get_operation_ast(parse(document), "Cheap")
    assert oracle is not None and oracle.name.value == "Cheap"

    result = cost.analyze_graphql_request(
        SDL, {"query": document, "operationName": "Cheap"}, default_list_size=5
    )
    row = _operation(result)
    assert row["operation_name"] == "Cheap"
    assert row["weighted_cost"] == 2  # viewer(1) + id(1)
    assert row["field_count"] == 2 and row["root_field_count"] == 1
    assert result["transport_batch"] is False and result["network_requests"] == 0

    with pytest.raises(cost.WebDepthGraphQLError, match="operationName is required"):
        cost.analyze_graphql_request(SDL, {"query": document})


def test_fragment_expansion_directives_aliases_and_duplicate_field_collection():
    document = """
      query Q($includeFriends: Boolean!, $n: Int = 3) {
        viewer {
          id
          ...Base
          ...More @include(if: $includeFriends)
        }
      }
      fragment Base on User { id friends(limit: $n) { id } }
      fragment More on User { aliasFriends: friends(limit: 2) { id } }
    """
    _oracle_valid(document)
    hidden = cost.analyze_graphql_request(SDL, {
        "query": document,
        "operationName": "Q",
        "variables": {"includeFriends": False, "n": 4},
    })
    hidden_row = _operation(hidden)
    # Duplicate response key `id` is collected once.  friends costs
    # 4 * (field weight 1 + child id 1), and viewer adds one.
    assert hidden_row["weighted_cost"] == 10
    assert hidden_row["field_count"] == 4
    assert hidden_row["alias_count"] == 0
    assert hidden_row["max_depth"] == 3 and hidden_row["max_breadth"] == 2
    assert hidden_row["list_factors"] == [{
        "path": "viewer.friends", "list_levels": 1, "factor": 4,
        "multiplier": 4, "source": "argument:limit",
    }]

    shown = cost.analyze_graphql_request(SDL, {
        "query": document,
        "operationName": "Q",
        "variables": {"includeFriends": True, "n": 4},
    })
    shown_row = _operation(shown)
    assert shown_row["weighted_cost"] == 14
    assert shown_row["field_count"] == 6 and shown_row["alias_count"] == 1

    # A missing runtime Boolean is conservatively included rather than
    # disappearing from the estimate.  The $n schema-document default is 3.
    unknown = cost.analyze_graphql_request(
        SDL, {"query": document, "operationName": "Q", "variables": {}}
    )
    unknown_row = _operation(unknown)
    assert unknown_row["weighted_cost"] == 12
    assert unknown_row["conditional_inclusions"] == 1


def test_transitive_fragments_schema_pagination_default_and_cycle_guard():
    document = """
      query Q { viewer { ...A } }
      fragment A on User { ...B }
      fragment B on User { friends { id } }
    """
    _oracle_valid(document)
    row = _operation(cost.analyze_graphql_request(SDL, {"query": document}))
    assert row["weighted_cost"] == 5
    assert row["list_factors"][0]["source"] == "schema-default:limit"
    assert row["list_factors"][0]["factor"] == 2

    cyclic = """
      query Q { viewer { ...A } }
      fragment A on User { ...B }
      fragment B on User { ...A }
    """
    assert validate(build_schema(SDL), parse(cyclic))  # independent oracle rejects the cycle
    with pytest.raises(cost.WebDepthGraphQLError, match="fragment cycle"):
        cost.analyze_graphql_request(SDL, {"query": cyclic})


def test_schema_list_levels_weights_and_duplicate_response_keys():
    weighted = cost.analyze_graphql_request(
        SDL,
        {"query": "{ users(first: 2) { id } }"},
        field_weights={"Root.users": 3, "User.id": 2},
    )
    assert _operation(weighted)["weighted_cost"] == 10  # 2 * (3 + 2)

    matrix = cost.analyze_graphql_request(
        SDL, {"query": "{ matrix { id } }"}, default_list_size=3
    )
    matrix_row = _operation(matrix)
    assert matrix_row["weighted_cost"] == 18  # 3^2 * (matrix 1 + id 1)
    assert matrix_row["max_list_depth"] == 2
    assert matrix_row["list_factors"][0]["list_levels"] == 2

    merged_document = "{ viewer { id } viewer { id name } }"
    _oracle_valid(merged_document)
    merged = _operation(cost.analyze_graphql_request(SDL, {"query": merged_document}))
    assert merged["root_field_count"] == 1
    assert merged["field_count"] == 3
    assert merged["weighted_cost"] == 3

    conflict = "{ x: viewer { id } x: users(first: 1) { id } }"
    assert validate(build_schema(SDL), parse(conflict))
    with pytest.raises(cost.WebDepthGraphQLError, match="conflicting fields"):
        cost.analyze_graphql_request(SDL, {"query": conflict})


def test_http_array_is_aggregate_transport_batch_not_multi_operation_execution():
    query = "{ users(first: 2) { id } }"
    mutation = 'mutation Rename { updateName(id: "7") { name } }'
    _oracle_valid(query)
    _oracle_valid(mutation)
    request = [
        {"query": query},
        {"query": mutation, "operationName": "Rename"},
    ]
    result = cost.analyze_graphql_request(
        SDL, request, field_weights={"Root.users": 3, "User.id": 2}
    )
    assert result["transport_batch"] is True and result["batch_count"] == 2
    assert [row["operation_kind"] for row in result["operations"]] == ["query", "mutation"]
    assert [row["weighted_cost"] for row in result["operations"]] == [10, 2]
    assert result["aggregate_weighted_cost"] == 12


@pytest.mark.parametrize("call", [
    lambda: cost.analyze_graphql_request(None, {}),
    lambda: cost.analyze_graphql_request("type Query {", {"query": "{x}"}),
    lambda: cost.analyze_graphql_request(SDL, None),
    lambda: cost.analyze_graphql_request(SDL, {"query": "query {"}),
    lambda: cost.analyze_graphql_request(SDL, {"query": "{ viewer { missing } }"}),
    lambda: cost.analyze_graphql_request(SDL, {"query": "{ users(first: $n) { id } }",
                                               "variables": {"n": 2}}),
    lambda: cost.analyze_graphql_request(SDL, {"query": "{ users(first: $n) { id } }"}),
    lambda: cost.analyze_graphql_request(SDL, {"query": "{ viewer { id } }"},
                                         field_weights={"bad key": 1}),
    lambda: cost.analyze_graphql_json(SDL, "{not-json"),
    lambda: cost.analyze_graphql_json(SDL, '{"query":"{viewer{id}}","query":"{viewer{name}}"}'),
])
def test_every_malformed_public_input_raises_only_declared_error(call):
    with pytest.raises(Exception) as caught:
        call()
    assert type(caught.value) is cost.WebDepthGraphQLError


def test_seeded_malformed_documents_never_leak_stdlib_exceptions():
    rng = random.Random(0xC057)
    seed = 'query Q($n:Int=2){users(first:$n){id}}'
    alphabet = '{}()[]:$!@.,# abcXYZ012"\\'
    for _ in range(300):
        text = list(seed)
        for _ in range(rng.randrange(1, 7)):
            action = rng.randrange(3)
            if action == 0 and text:
                text[rng.randrange(len(text))] = rng.choice(alphabet)
            elif action == 1 and text:
                del text[rng.randrange(len(text))]
            else:
                text.insert(rng.randrange(len(text) + 1), rng.choice(alphabet))
        try:
            result = cost.analyze_graphql_request(SDL, {"query": "".join(text)})
            assert result["offline"] is True
        except Exception as exc:  # exact contract assertion
            assert type(exc) is cost.WebDepthGraphQLError


def test_strict_json_cli_guard_import_and_no_execution_surface(tmp_path, capsys, monkeypatch):
    schema_path = tmp_path / "schema.graphql"
    request_path = tmp_path / "request.json"
    weights_path = tmp_path / "weights.json"
    schema_path.write_text(SDL, encoding="utf-8")
    request_path.write_text(json.dumps({"query": "{ users(first: 2) { id } }"}), encoding="utf-8")
    weights_path.write_text(json.dumps({"Root.users": 3, "User.id": 2}), encoding="utf-8")

    assert cost.main([
        str(schema_path), str(request_path), "--weights", str(weights_path), "--compact"
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["aggregate_weighted_cost"] == 10 and output["network_requests"] == 0

    assert cost.main([]) == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert cost.main(["--help"]) == 0
    capsys.readouterr()

    class NonIntegerExitParser:
        def parse_args(self, _argv):
            raise SystemExit("non-integer")

    monkeypatch.setattr(cost, "_build_parser", lambda: NonIntegerExitParser())
    assert cost.main(["ignored"]) == 2

    tree = ast.parse((WEB / "webdepth_graphql_cost.py").read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not imports.intersection({
        "socket", "requests", "http.client", "urllib.request", "subprocess", "pickle", "marshal",
    })
    assert not calls.intersection({"eval", "exec", "compile", "__import__"})

