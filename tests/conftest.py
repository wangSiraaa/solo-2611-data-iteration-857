"""Shared fixtures: an independent byte builder and small ground-truth records.

The fixtures intentionally express expected wire bytes and field presence by
hand so the library is checked against an independent construction, not
against its own encoder.
"""

from __future__ import annotations

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telber.schema import compile_product  # noqa: E402


def make_schema(fields, *, name="test.record", version=1, root_number=16):
    return {
        "schema": name,
        "version": version,
        "root": {
            "name": "Record",
            "tag": {"class": "universal", "number": root_number},
            "type": "SEQUENCE",
            "fields": copy.deepcopy(fields),
        },
    }


def field(name, cls, number, mode, type_, optional=False, fields=None):
    out = {
        "name": name,
        "tag": {"class": cls, "number": number},
        "mode": mode,
        "type": type_,
    }
    if optional:
        out["optional"] = True
    if fields is not None:
        out["fields"] = copy.deepcopy(fields)
    return out


@pytest.fixture
def simple_schema():
    """A small record exercising every mode and base type."""
    return make_schema(
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


@pytest.fixture
def simple_product(simple_schema):
    return compile_product(simple_schema)


def minimal_record(product, id_value=1, tagged_value=2, inner_a=3):
    from telber.codec import encode_record

    return encode_record(
        {"id": id_value, "tagged": tagged_value, "inner": {"a": inner_a}},
        product,
    )
