"""Compile service: schema product artifact, check/encode, type preservation."""

from __future__ import annotations

import pytest

from conftest import field, make_schema
from telber.codec import decode_record, encode_record, encode_record_indefinite
from telber.errors import EncodeError
from telber.service import CompileService


SCHEMA = make_schema(
    [
        field("id", "context", 0, "implicit", "INTEGER"),
        field("blob", "context", 1, "implicit", "OCTET STRING", optional=True),
        field("tagged", "application", 300, "implicit", "INTEGER"),
        field("nul", "context", 2, "explicit", "NULL", optional=True),
        field("wrapped", "context", 3, "explicit", "OCTET STRING", optional=True),
        field(
            "inner",
            "application",
            1000,
            "implicit",
            "SEQUENCE",
            fields=[
                field("a", "private", 0, "implicit", "INTEGER"),
                field("b", "private", 1, "implicit", "OCTET STRING", optional=True),
                field("c", "private", 2, "explicit", "INTEGER", optional=True),
            ],
        ),
    ]
)


def test_encode_decode_preserves_presence_and_types():
    service = CompileService()
    product = service.compile(SCHEMA)
    cases = [
        {"id": 0, "tagged": 0, "inner": {"a": 0}},
        {"id": -1, "blob": b"\x00\x00", "tagged": -128, "inner": {"a": -129}},
        {
            "id": 127,
            "tagged": 128,
            "nul": None,
            "wrapped": b"\x00\x00\xff",
            "inner": {"a": 1, "b": b"\x00", "c": -1},
        },
        {
            "id": -8388608,
            "blob": b"",
            "tagged": 65535,
            "nul": None,
            "wrapped": b"",
            "inner": {"a": 2, "c": 2**31},
        },
    ]
    for values in cases:
        for encoder in (encode_record, encode_record_indefinite):
            data = encoder(values, product)
            decoded = decode_record(data, product)
            flat = decoded.value_map()

            def flat_in(src, prefix=""):
                out = {}
                for k, v in src.items():
                    key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, dict):
                        out.update(flat_in(v, key))
                    else:
                        out[key] = v
                return out

            src = flat_in(values)
            # every supplied value is present with the same type and value
            for key, expected in src.items():
                assert key in flat, (key, values)
                got = flat[key]
                if expected is None:
                    assert got.null is True and got.type in ("NULL", "SEQUENCE")
                elif isinstance(expected, bytes):
                    assert got.type == "OCTET STRING" and got.value == expected
                elif isinstance(expected, int):
                    assert got.type == "INTEGER" and got.value == expected
            # optional fields not supplied remain absent
            for opt in ("blob", "nul", "wrapped", "inner.b", "inner.c"):
                if opt not in src:
                    assert opt not in flat, (opt, values)


def test_artifact_recompiles_to_same_product():
    service = CompileService()
    product = service.compile(SCHEMA)
    artifact = service.artifact(product)
    restored = service.load_artifact(artifact)
    assert restored.product_id == product.product_id
    assert restored.match_table() == product.match_table()
    # encoding under the restored product is byte-identical
    values = {"id": -5, "tagged": 7, "inner": {"a": 9, "c": -2}}
    assert encode_record(values, restored) == encode_record(values, product)


def test_check_reports_field_presence_and_ranges():
    service = CompileService()
    product = service.compile(SCHEMA)
    data = encode_record({"id": 1, "blob": b"\x00\x00", "tagged": 2, "inner": {"a": 3}}, product)
    result = service.check(product, data)
    d = result.as_dict()
    assert d["fields"]["id"]["present"] is True
    assert d["fields"]["nul"]["present"] is False if "nul" in d["fields"] else True
    assert d["fields"]["blob"]["value"] == "0000"
    assert "inner.a" in d["fields"]


def test_encoder_rejects_wrong_value_types():
    service = CompileService()
    product = service.compile(SCHEMA)
    with pytest.raises(EncodeError):
        encode_record({"id": "not-an-int", "tagged": 2, "inner": {"a": 1}}, product)
    with pytest.raises(EncodeError):
        encode_record({"id": 1, "tagged": 2, "blob": "text", "inner": {"a": 1}}, product)
    with pytest.raises(EncodeError):
        encode_record({"id": 1, "inner": {"a": 1}}, product)  # missing required 'tagged'


def test_null_versus_absent_in_encoder():
    service = CompileService()
    product = service.compile(SCHEMA)
    absent = encode_record({"id": 1, "tagged": 2, "inner": {"a": 3}}, product)
    null = encode_record({"id": 1, "tagged": 2, "nul": None, "inner": {"a": 3}}, product)
    assert null != absent
    assert "nul" not in decode_record(absent, product).value_map()
    assert decode_record(null, product).value_map()["nul"].null is True
    # declaring a None for a non-NULL optional means absent
    same_as_absent = encode_record(
        {"id": 1, "tagged": 2, "wrapped": None, "inner": {"a": 3}}, product
    )
    assert same_as_absent == absent


def test_indefinite_encoding_roundtrips_identically():
    service = CompileService()
    product = service.compile(SCHEMA)
    values = {"id": -1, "blob": b"\x00\x00", "tagged": 3, "nul": None,
              "wrapped": b"\x00", "inner": {"a": -2, "b": b"\x00\x00", "c": 4}}
    definite = encode_record(values, product)
    indefinite = encode_record_indefinite(values, product)
    assert definite != indefinite
    a = decode_record(definite, product).value_map()
    b = decode_record(indefinite, product).value_map()
    assert {k: (v.value, v.null) for k, v in a.items()} == {
        k: (v.value, v.null) for k, v in b.items()
    }
