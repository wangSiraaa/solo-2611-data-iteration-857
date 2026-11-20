"""Schema directory compilation: strictness and ambiguity rejection."""

from __future__ import annotations

import copy

import pytest

from conftest import field, make_schema
from telber.errors import SchemaError
from telber.schema import compile_product


def test_hash_tag_derives_constructed_from_mode():
    schema = make_schema(
        [
            field("e", "context", 1, "explicit", "INTEGER"),
            field("i", "context", 2, "implicit", "INTEGER"),
            field("s", "context", 3, "implicit", "SEQUENCE",
                  fields=[field("x", "context", 0, "implicit", "INTEGER")]),
            field("t", "context", 4, "explicit", "SEQUENCE",
                  fields=[field("y", "context", 0, "implicit", "INTEGER")]),
        ]
    )
    product = compile_product(schema)
    by_name = {f.name: f for f in product.fields}
    assert by_name["e"].wire_tag.constructed is True     # explicit wrapper
    assert by_name["i"].wire_tag.constructed is False
    assert by_name["s"].wire_tag.constructed is True     # implicit SEQUENCE
    assert by_name["t"].wire_tag.constructed is True     # explicit wrapper
    assert by_name["e"].inner_tag.number == 2
    assert by_name["i"].inner_tag is None


def test_unknown_keys_rejected_everywhere():
    bad = make_schema([field("a", "context", 0, "implicit", "INTEGER")])
    bad["root"]["fields"][0]["oops"] = True
    with pytest.raises(SchemaError) as exc:
        compile_product(bad)
    assert exc.value.code == "unknown_schema_key"

    bad = make_schema([field("a", "context", 0, "implicit", "INTEGER")])
    bad["root"]["tag"]["constructed"] = False
    with pytest.raises(SchemaError) as exc:
        compile_product(bad)
    assert exc.value.code == "unknown_schema_key"

    bad = make_schema([field("a", "context", 0, "implicit", "INTEGER")])
    bad["extra"] = 1
    with pytest.raises(SchemaError) as exc:
        compile_product(bad)
    assert exc.value.code == "unknown_schema_key"


@pytest.mark.parametrize("bad_type", ["BOOLEAN", "REAL", "SEQUENCE OF", "int"])
def test_unsupported_types_rejected(bad_type):
    with pytest.raises(SchemaError):
        compile_product(make_schema([field("a", "context", 0, "implicit", bad_type)]))


def test_duplicate_field_names_rejected():
    with pytest.raises(SchemaError) as exc:
        compile_product(
            make_schema(
                [
                    field("a", "context", 0, "implicit", "INTEGER"),
                    field("a", "context", 1, "implicit", "INTEGER"),
                ]
            )
        )
    assert exc.value.code == "duplicate_field_name"


def test_duplicate_wire_tag_rejected():
    with pytest.raises(SchemaError) as exc:
        compile_product(
            make_schema(
                [
                    field("a", "context", 0, "implicit", "INTEGER"),
                    field("b", "context", 0, "implicit", "INTEGER"),
                ]
            )
        )
    assert exc.value.code == "duplicate_field_tag"


def test_adjacent_optional_same_tag_rejected():
    with pytest.raises(SchemaError) as exc:
        compile_product(
            make_schema(
                [
                    field("a", "context", 1, "implicit", "INTEGER", optional=True),
                    field("b", "context", 2, "implicit", "INTEGER", optional=True),
                    field("c", "context", 1, "implicit", "INTEGER", optional=True),
                ]
            )
        )
    assert exc.value.code == "ambiguous_optionals"


def test_optional_then_required_same_tag_rejected():
    with pytest.raises(SchemaError) as exc:
        compile_product(
            make_schema(
                [
                    field("a", "context", 1, "implicit", "INTEGER", optional=True),
                    field("b", "context", 1, "implicit", "INTEGER"),
                ]
            )
        )
    assert exc.value.code == "ambiguous_optionals"


def test_explicit_and_implicit_on_same_number_are_distinct_wire_tags():
    # The constructed bit is part of the tag, so context[1] constructed
    # (explicit) and context[1] primitive (implicit) are deterministically
    # distinguishable on the wire and need not be rejected as ambiguous.
    product = compile_product(
        make_schema(
            [
                field("a", "context", 1, "explicit", "INTEGER", optional=True),
                field("b", "context", 1, "implicit", "INTEGER"),
            ]
        )
    )
    a, b = product.fields
    assert a.wire_tag != b.wire_tag
    assert a.wire_tag.constructed and not b.wire_tag.constructed


def test_adjacent_optionals_with_distinct_tags_accepted():
    product = compile_product(
        make_schema(
            [
                field("a", "context", 1, "implicit", "INTEGER", optional=True),
                field("b", "context", 2, "implicit", "OCTET STRING", optional=True),
                field("c", "context", 3, "implicit", "INTEGER"),
            ]
        )
    )
    assert [f.name for f in product.fields] == ["a", "b", "c"]


def test_required_sequence_missing_fields_rejected():
    with pytest.raises(SchemaError):
        compile_product(
            make_schema([field("s", "context", 0, "implicit", "SEQUENCE")])
        )


def test_nesting_depth_bound():
    node_fields = [field("leaf", "context", 0, "implicit", "INTEGER")]
    for i in range(70):
        node_fields = [
            field(f"n{i}", "context", 0, "implicit", "SEQUENCE", fields=node_fields)
        ]
    with pytest.raises(SchemaError) as exc:
        compile_product(make_schema(node_fields))
    assert exc.value.code == "too_deep"


def test_hundred_fields_compile():
    fields = [
        field(f"f{i}", "context", i, "implicit", "INTEGER") for i in range(100)
    ]
    product = compile_product(make_schema(fields))
    assert len(product.fields) == 100
    assert len(product.match_table()["$root"]) == 100


def test_product_id_is_content_addressed_and_revision_sensitive():
    base = make_schema([field("a", "context", 0, "implicit", "INTEGER")])
    p1 = compile_product(base)
    p2 = compile_product(copy.deepcopy(base))
    assert p1.product_id == p2.product_id

    revised = copy.deepcopy(base)
    revised["version"] = 2
    revised["root"]["fields"][0]["type"] = "OCTET STRING"
    p3 = compile_product(revised)
    assert p3.product_id != p1.product_id
    assert p3.version == 2


def test_non_minimal_tag_numbers_in_schema_are_still_compiled_correctly():
    # The directory stores numbers, not octets: 31 must be encoded long-form,
    # 30 short-form, on the wire.  Compilation pre-computes both correctly.
    product = compile_product(
        make_schema(
            [
                field("a", "context", 30, "implicit", "INTEGER"),
                field("b", "context", 31, "implicit", "INTEGER"),
            ]
        )
    )
    assert len(product.match_table()["$root"][0]["wire_tag"]) == 3


def test_tag_number_bounds():
    with pytest.raises(SchemaError) as exc:
        compile_product(make_schema([field("a", "context", -1, "implicit", "INTEGER")]))
    assert exc.value.code == "bad_tag_number"
    with pytest.raises(SchemaError):
        compile_product(make_schema([field("a", "bogus", 0, "implicit", "INTEGER")]))


def test_artifact_roundtrip_detects_tampering():
    from telber.service import CompileService

    service = CompileService()
    product = service.compile(make_schema([field("a", "context", 0, "implicit", "INTEGER")]))
    artifact = service.artifact(product)
    restored = service.load_artifact(artifact)
    assert restored.product_id == product.product_id
    tampered = artifact.replace('"implicit"', '"explicit"')
    with pytest.raises(Exception) as exc:
        service.load_artifact(tampered)
    assert getattr(exc.value, "code", None) in {
        "artifact_digest_mismatch",
        "schema_error",
    }
