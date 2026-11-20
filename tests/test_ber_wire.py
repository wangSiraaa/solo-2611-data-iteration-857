"""Wire-level tag/length rules: minimality, base-128 long tags, EOC semantics."""

from __future__ import annotations

import pytest

from telber import build as B
from telber.ber import (
    Reader,
    Tag,
    encode_length,
    encode_tag,
    parse_header,
)
from telber.errors import BerError


@pytest.mark.parametrize(
    "number, expected",
    [
        (0, b"\x80"),
        (30, b"\x9e"),
        (31, b"\x9f\x1f"),
        (127, b"\x9f\x7f"),
        (128, b"\x9f\x81\x00"),
        (300, b"\x9f\x82\x2c"),
        (16383, b"\x9f\xff\x7f"),
        (16384, b"\x9f\x81\x80\x00"),
    ],
)
def test_long_tag_encoding_matches_base128(number, expected):
    assert encode_tag("context", False, number) == expected
    # independent builder agrees
    assert B.tag("context", False, number) == expected


@pytest.mark.parametrize("number", [0, 1, 30, 31, 32, 127, 128, 300, 1000, 16384, 2**20])
def test_tag_roundtrip_through_parser(number):
    raw = encode_tag("application", True, number) + b"\x00"
    header = parse_header(Reader(raw))
    assert header.tag == Tag("application", True, number)


def test_non_minimal_long_tag_rejected():
    # 0x80 padding octet
    with pytest.raises(BerError) as exc:
        parse_header(Reader(b"\x9f\x80\x2c\x00"))
    assert exc.value.code == "non_minimal_tag"

    # value < 31 must use the short form (0x1e in long form encodes 30)
    with pytest.raises(BerError) as exc:
        parse_header(Reader(b"\x9f\x1e\x00"))
    assert exc.value.code == "non_minimal_tag"


def test_tag_class_and_construct_bits_decoded():
    for cls, bits in [("universal", 0), ("application", 1), ("context", 2), ("private", 3)]:
        for constructed in (False, True):
            header = parse_header(Reader(encode_tag(cls, constructed, 7) + b"\x00"))
            assert header.tag.cls == cls
            assert header.tag.constructed is constructed
            assert header.tag.number == 7


@pytest.mark.parametrize("length", [0, 1, 127, 128, 255, 256, 65535, 2**32 - 1])
def test_length_roundtrip(length):
    raw = encode_length(length)
    header = parse_header(Reader(b"\x04" + raw))
    assert header.length == length


def test_length_minimality():
    # long form used where short form fits
    with pytest.raises(BerError) as exc:
        parse_header(Reader(b"\x04\x81\x05"))
    assert exc.value.code == "non_minimal_length"

    # leading zero octet
    with pytest.raises(BerError) as exc:
        parse_header(Reader(b"\x04\x82\x00\x80"))
    assert exc.value.code == "non_minimal_length"

    # five length octets is beyond the supported subset
    with pytest.raises(BerError) as exc:
        parse_header(Reader(b"\x04\x85\x01\x00\x00\x00\x00"))
    assert exc.value.code == "length_too_long"


def test_indefinite_rejected_on_primitive():
    with pytest.raises(BerError) as exc:
        parse_header(Reader(b"\x04\x80"))
    assert exc.value.code == "indefinite_primitive"


def test_definite_constructed_allows_long_length_form():
    header = parse_header(Reader(b"\x30\x81\x80" + b"\x00" * 0))
    assert header.length == 128
    assert not header.indefinite


def test_builder_long_tag_is_minimal():
    # sanity: B.tag encodes 300 as 0x9f 0x82 0x2c for context class
    assert B.tag("context", False, 300) == b"\x9f\x82\x2c"
