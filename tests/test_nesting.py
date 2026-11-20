"""Mixed definite/indefinite nesting across explicit wrappers and SEQUENCEs."""

from __future__ import annotations

import itertools

import pytest

from conftest import field, make_schema
from telber import build as B
from telber.codec import decode_record
from telber.errors import TelberError
from telber.schema import compile_product


SCHEMA = make_schema(
    [
        field("id", "context", 0, "implicit", "INTEGER"),
        field(
            "wrap",
            "context",
            1,
            "explicit",
            "SEQUENCE",
            fields=[
                field("x", "private", 0, "implicit", "INTEGER"),
                field("blob", "private", 1, "implicit", "OCTET STRING", optional=True),
            ],
        ),
        field(
            "flat",
            "application",
            1000,
            "implicit",
            "SEQUENCE",
            fields=[
                field("y", "private", 2, "implicit", "INTEGER"),
                field(
                    "deep",
                    "private",
                    3,
                    "explicit",
                    "SEQUENCE",
                    optional=True,
                    fields=[
                        field("z", "private", 4, "implicit", "INTEGER"),
                    ],
                ),
            ],
        ),
    ]
)


def build(mode_root, mode_wrap, mode_deep, *, blob=b"\x00\x00", deep=True):
    """Assemble the record with each constructed layer independently timed."""
    inner_fields = B.integer(-1, cls="private", number=0) + B.octets(blob, cls="private", number=1)
    wrap_seq = B.seq(inner_fields, indefinite=mode_wrap == "indefinite")
    wrap = B.tlv(
        B.tag("context", True, 1),
        wrap_seq,
        indefinite=mode_wrap == "indefinite",
    )
    flat_body = B.integer(3, cls="private", number=2)
    if deep:
        deep_seq = B.seq(
            B.integer(4, cls="private", number=4),
            indefinite=mode_deep == "indefinite",
        )
        flat_body += B.tlv(
            B.tag("private", True, 3),
            deep_seq,
            indefinite=mode_deep == "indefinite",
        )
    flat = B.tlv(
        B.tag("application", True, 1000),
        flat_body,
        indefinite=mode_deep == "indefinite" and False,
    )
    body = B.integer(1, cls="context", number=0) + wrap + flat
    return B.seq(body, indefinite=mode_root == "indefinite")


@pytest.mark.parametrize(
    "mode_root, mode_wrap, mode_deep",
    list(itertools.product(["definite", "indefinite"], repeat=3)),
)
def test_all_definite_indefinite_combinations(mode_root, mode_wrap, mode_deep):
    product = compile_product(SCHEMA)
    for deep in (True, False):
        data = build(mode_root, mode_wrap, mode_deep, deep=deep)
        record = decode_record(data, product)
        values = record.value_map()
        assert values["id"].value == 1
        assert values["wrap.x"].value == -1
        assert values["wrap.blob"].value == b"\x00\x00"
        assert values["flat.y"].value == 3
        assert ("flat.deep.z" in values) is deep
        if deep:
            assert values["flat.deep.z"].value == 4
        assert record.end == len(data)


def test_mixed_nesting_source_ranges_are_ordered():
    product = compile_product(SCHEMA)
    data = build("indefinite", "definite", "indefinite")
    values = decode_record(data, product).value_map()
    # child encodings nest inside their parent's encoding range
    for parent, child in [
        ("wrap", "wrap.x"),
        ("wrap", "wrap.blob"),
        ("flat", "flat.y"),
        ("flat", "flat.deep"),
        ("flat.deep", "flat.deep.z"),
    ]:
        prow = values[parent].source_ranges[-1]
        crow = values[child].source_ranges[-1]
        assert prow[1] <= crow[1] and crow[2] <= prow[2]


def test_indefinite_layer_missing_eoc_is_error():
    product = compile_product(SCHEMA)
    # root indefinite but stripped of its EOC
    body = B.integer(1, cls="context", number=0)
    data = B.tag("universal", True, 16) + b"\x80" + body
    with pytest.raises(TelberError):
        decode_record(data, product)


def test_depth_32_default_suite():
    fields = [field("leaf", "context", 0, "implicit", "INTEGER")]
    for i in range(32):
        fields = [field(f"n{i}", "context", 0, "implicit", "SEQUENCE", fields=fields)]
    product = compile_product(make_schema(fields))
    payload = B.integer(7, cls="context", number=0)
    for i in range(32):
        payload = B.tlv(B.tag("context", True, 0), payload,
                        indefinite=(i % 2 == 0))
    data = B.raw_tlv(B.tag("universal", True, 16), payload)
    values = decode_record(data, product).value_map()
    deepest = max(values, key=lambda p: len(p.split(".")))
    assert values[deepest].value == 7
