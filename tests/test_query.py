from hypersearch.query import parse_query, structural_signature


def test_scope_and_symbol_language():
    q = parse_query("repo:ultrabricks/skin lang:js def:restoreFocus")
    assert q.repo == "ultrabricks/skin"
    assert q.lang == "js"
    assert q.mode == "symbol"
    assert q.symbol == "restoreFocus"
    assert q.symbol_role == "definition"


def test_ast_is_inferred_from_syntax():
    q = parse_query("restoreFocus(trigger) {")
    assert q.ast_candidate is True
    assert q.symbol_candidate is False


def test_filename_is_inferred():
    q = parse_query("src/server.py")
    assert q.file_candidate is True


def test_structure_ignores_spacing_but_not_tokens():
    a = structural_signature("foo( a, b )")
    b = structural_signature("foo(a,b)")
    assert a == b
    assert a != structural_signature("foo(a,c)")


def test_natural_intents_route_without_query_syntax():
    definition = parse_query("function restoreFocus")
    assert definition.mode == "symbol"
    assert definition.symbol == "restoreFocus"
    assert definition.symbol_role == "definition"

    reference = parse_query("references restoreFocus")
    assert reference.mode == "symbol"
    assert reference.symbol == "restoreFocus"
    assert reference.symbol_role == "reference"

    file_query = parse_query("file src/focus.js")
    assert file_query.mode == "file"
    assert file_query.text == "src/focus.js"


def test_incomplete_parenthesis_stays_on_fast_path():
    assert parse_query("restoreFocus(").ast_candidate is False
    assert parse_query("restoreFocus(trigger)").ast_candidate is True
