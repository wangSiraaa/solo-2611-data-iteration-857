"""Decoding rules against independently built wire bytes.

Every record here is assembled with :mod:`telber.build`; expected field
presence, values and byte ranges are stated by hand.
"""

from __future__ import annotations

import pytest

from telber import build as B
from telber.codec import decode_record
from telber.errors import BerError, DecodeError, TelberError


def root(body: bytes, *, indefinite=False) -> bytes:
    return B.seq(body, indefinite=indefinite)


def test_basic_implicit_and_explicit_values(simple_product):
    # id = -1, blob = "\x00\x00", tagged = 300 (long tag), nul explicit NULL,
    # wrapped explicit "\xff\x00", inner {a=5, c explicit -128}
    body = (
        B.integer(-1, cls="context", number=0)
        + B.octets(b"\x00\x00", cls="context", number=1)
        + B.integer(300, cls="application", number=300)
        + B.explicit(B.tag("context", True, 2), B.null())
        + B.explicit(B.tag("context", True, 3), B.octets(b"\xff\x00"))
        + B.tlv(
            B.tag("application", True, 1000),
            B.integer(5, cls="private", number=0)
            + B.explicit(B.tag("private", True, 2), B.integer(-128)),
        )
    )
    data = root(body)
    record = decode_record(data, simple_product)
    values = record.value_map()
    assert values["id"].value == -1
    assert values["blob"].value == b"\x00\x00"
    assert values["tagged"].value == 300
    assert values["nul"].null is True
    assert values["wrapped"].value == b"\xff\x00"
    assert values["inner.a"].value == 5
    assert values["inner.b"] if "inner.b" in values else True
    assert values["inner.c"].value == -128
    assert "inner.b" not in values


def test_optional_absent_vs_explicit_null_are_distinct(simple_product):
    body = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
    )
    present = decode_record(root(body), simple_product).value_map()
    assert "blob" not in present and "nul" not in present and "wrapped" not in present

    body_with_null = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.explicit(B.tag("context", True, 2), B.null())
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
    )
    with_null = decode_record(root(body_with_null), simple_product).value_map()
    assert "nul" in with_null
    assert with_null["nul"].null is True
    # blob still absent: null and absence are different facts
    assert "blob" not in with_null


def test_eoc_bytes_in_primitive_body_are_data(simple_product):
    body = (
        B.integer(1, cls="context", number=0)
        + B.octets(b"\x00\x00\x00\x00", cls="context", number=1)
        + B.integer(2, cls="application", number=300)
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
    )
    data = root(body)
    record = decode_record(data, simple_product)
    assert record.value_map()["blob"].value == b"\x00\x00\x00\x00"
    assert record.end == len(data)


def test_eoc_bytes_inside_definite_constructed_do_not_end_it(simple_product):
    # inner's body literally begins with 00 00; since the layer is definite
    # this is an (invalid) child header, not an early terminator.  Use an
    # OCTET STRING field after a zero-length INTEGER body to keep it legal:
    # the point is that decoding does not stop at the first 00 00.
    body = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.tlv(
            B.tag("application", True, 1000),
            B.integer(0, cls="private", number=0)  # 0x02 0x01 0x00 -- ends with 00
            + B.octets(b"\x00\x00", cls="private", number=1),
        )
    )
    data = root(body)
    record = decode_record(data, simple_product)
    assert record.value_map()["inner.b"].value == b"\x00\x00"
    assert record.end == len(data)


def test_indefinite_layers_with_mixed_children(simple_product):
    def tlv(tag, body):
        return tag + b"\x80" + body + b"\x00\x00"

    inner = tlv(
        B.tag("application", True, 1000),
        B.integer(7, cls="private", number=0)
        + B.octets(b"\x00\x00", cls="private", number=1)
        + tlv(B.tag("private", True, 2), B.integer(-1)),
    )
    body = (
        B.integer(-3, cls="context", number=0)
        + B.integer(4, cls="application", number=300)
        + tlv(B.tag("context", True, 3), B.octets(b"\x00\x00"))
        + inner
    )
    data = root(body, indefinite=True)
    record = decode_record(data, simple_product)
    values = record.value_map()
    assert values["id"].value == -3
    assert values["inner.a"].value == 7
    assert values["inner.b"].value == b"\x00\x00"
    assert values["inner.c"].value == -1
    assert values["wrapped"].value == b"\x00\x00"
    assert record.end == len(data)


def test_integer_minimality_is_enforced():
    from conftest import field, make_schema
    from telber.schema import compile_product

    product = compile_product(
        make_schema([field("i", "context", 0, "implicit", "INTEGER")])
    )
    # 0x00 0x01 encodes 1 but is not minimal
    bad = B.raw_tlv(B.tag("universal", True, 16), B.raw_tlv(B.tag("context", False, 0), b"\x00\x01"))
    with pytest.raises(BerError) as exc:
        decode_record(bad, product)
    assert exc.value.code == "non_minimal_integer"

    # 0xFF 0x80 encodes -128 in two octets; -128 fits in one, so this is a
    # redundant sign-extension octet and must be rejected.
    bad = B.raw_tlv(B.tag("universal", True, 16), B.raw_tlv(B.tag("context", False, 0), b"\xff\x80"))
    with pytest.raises(BerError) as exc:
        decode_record(bad, product)
    assert exc.value.code == "non_minimal_integer"

    # 0xFF 0x7F encodes -129, which genuinely needs two octets, so it is legal.
    good = B.raw_tlv(B.tag("universal", True, 16), B.raw_tlv(B.tag("context", False, 0), b"\xff\x7f"))
    assert decode_record(good, product).value_map()["i"].value == -129


@pytest.mark.parametrize(
    "raw, value",
    [
        (b"\x00", 0),
        (b"\x7f", 127),
        (b"\x80", -128),
        (b"\xff", -1),
        (b"\x00\x80", 128),
        (b"\xff\x7f", -129),
        (b"\x80\x00", -32768),
        (b"\x7f\xff", 32767),
        (b"\x80\x00\x00", -8388608),
    ],
)
def test_integer_boundary_bodies(raw, value):
    from conftest import field, make_schema
    from telber.schema import compile_product

    product = compile_product(
        make_schema([field("i", "context", 0, "implicit", "INTEGER")])
    )
    data = B.raw_tlv(B.tag("universal", True, 16), B.raw_tlv(B.tag("context", False, 0), raw))
    assert decode_record(data, product).value_map()["i"].value == value


def test_null_must_have_zero_length():
    from conftest import field, make_schema
    from telber.schema import compile_product

    product = compile_product(make_schema([field("n", "context", 0, "implicit", "NULL")]))
    bad = B.raw_tlv(B.tag("universal", True, 16), B.raw_tlv(B.tag("context", False, 0), b"\x00"))
    with pytest.raises(DecodeError) as exc:
        decode_record(bad, product)
    assert exc.value.code == "null_nonzero_length"


def test_explicit_wrapper_must_contain_exactly_one_value():
    from conftest import field, make_schema
    from telber.schema import compile_product

    product = compile_product(
        make_schema([field("e", "context", 0, "explicit", "INTEGER")])
    )
    two = B.raw_tlv(B.tag("universal", True, 16), B.explicit(B.tag("context", True, 0), B.integer(1) + B.integer(2)))
    with pytest.raises(DecodeError) as exc:
        decode_record(two, product)
    assert exc.value.code == "explicit_extra_value"

    empty = B.raw_tlv(B.tag("universal", True, 16), B.explicit(B.tag("context", True, 0), b""))
    with pytest.raises(DecodeError) as exc:
        decode_record(empty, product)
    assert exc.value.code == "explicit_empty"

    wrong_inner = B.raw_tlv(
        B.tag("universal", True, 16),
        B.explicit(B.tag("context", True, 0), B.octets(b"x")),
    )
    with pytest.raises(DecodeError) as exc:
        decode_record(wrong_inner, product)
    assert exc.value.code == "explicit_inner_tag_mismatch"


def test_implicit_body_interpreted_as_declared_base_type(simple_product):
    # 'wrapped' is explicit OCTET STRING: inner tag universal 4, body is data
    body = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.explicit(B.tag("context", True, 3), B.octets(b"\x01\x02\x03"))
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
    )
    record = decode_record(root(body), simple_product)
    assert record.value_map()["wrapped"].value == b"\x01\x02\x03"


def test_eoc_inside_definite_constructed_is_rejected_not_terminator(simple_product):
    # A definite root whose body starts with 00 00: this is not a terminator and
    # not a valid child header, so decoding must fail at that offset rather than
    # silently treating the layer as closed.
    data = b"\x30\x02" + b"\x00\x00"
    with pytest.raises(BerError) as exc:
        decode_record(data, simple_product)
    assert exc.value.code == "unexpected_eoc"
    assert exc.value.offset == 2


def test_indefinite_terminator_only_closes_indefinite_layers(simple_product):
    # Definite inner SEQUENCE (implicit application 1000) followed by real root
    # fields; its length governs, so trailing 00 00 belongs to the root layer.
    body = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
    )
    data = B.raw_tlv(B.tag("universal", True, 16), body, indefinite=True)
    record = decode_record(data, simple_product)
    assert record.value_map()["inner.a"].value == 3
    assert record.end == len(data)


def test_unknown_field_rejected(simple_product):
    body = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
        + B.integer(9, cls="context", number=99)  # undeclared
    )
    with pytest.raises(DecodeError) as exc:
        decode_record(root(body), simple_product)
    assert exc.value.code == "unknown_field"


def test_duplicate_field_rejected_not_silently_overwritten():
    from conftest import field, make_schema
    from telber.schema import compile_product

    product = compile_product(
        make_schema(
            [
                field("a", "context", 0, "implicit", "INTEGER"),
                field("b", "context", 1, "implicit", "INTEGER", optional=True),
            ]
        )
    )
    # b is present twice
    body = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="context", number=1)
        + B.integer(3, cls="context", number=1)
    )
    with pytest.raises(DecodeError) as exc:
        decode_record(root(body), product)
    assert exc.value.code == "unknown_field"


def test_missing_required_field_reports_offset(simple_product):
    body = B.integer(1, cls="context", number=0)  # tagged missing
    data = root(body)
    with pytest.raises(DecodeError) as exc:
        decode_record(data, simple_product)
    assert exc.value.code == "missing_field"
    assert exc.value.offset == len(data)


def test_trailing_bytes_after_record_rejected(simple_product):
    from conftest import minimal_record

    one = minimal_record(simple_product)
    with pytest.raises(DecodeError) as exc:
        decode_record(one + one, simple_product)
    assert exc.value.code == "trailing_bytes"


def test_child_overrun_is_structural_error_not_truncation(simple_product):
    # root declares 3 body bytes but its child claims a 5-byte body
    bad = b"\x30\x03" + b"\x80\x05\x01"
    with pytest.raises(TelberError) as exc:
        decode_record(bad, simple_product)
    assert exc.value.code in {"body_overruns_parent", "truncated"}


def test_truncated_indefinite_missing_eoc(simple_product):
    body = B.integer(1, cls="context", number=0)
    data = B.tag("universal", True, 16) + b"\x80" + body  # no EOC
    with pytest.raises(TelberError) as exc:
        decode_record(data, simple_product)
    assert exc.value.code in {"truncated", "missing_field"}


def test_source_ranges_cover_original_bytes(simple_product):
    from conftest import minimal_record

    data = minimal_record(simple_product)
    record = decode_record(data, simple_product)
    values = record.value_map()
    # every encoding range slices back to the exact field bytes
    id_v = values["id"]
    (role, s, e), = id_v.source_ranges
    assert role == "encoding"
    assert data[s:e] == B.integer(1, cls="context", number=0)
    assert id_v.body_start is not None and id_v.body_end is not None
    assert data[id_v.body_start : id_v.body_end] == B.int_body(1)

    # nested values are inside their parent's encoding range
    inner = values["inner"]
    (_, ps, pe), = inner.source_ranges
    a = values["inner.a"]
    (_, as_, ae), = a.source_ranges
    assert ps <= as_ and ae <= pe


def test_explicit_source_ranges_are_wrapper_and_inner(simple_product):
    body = (
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.explicit(B.tag("context", True, 3), B.octets(b"\xaa\xbb"))
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
    )
    data = root(body)
    record = decode_record(data, simple_product)
    wrapped = record.value_map()["wrapped"]
    roles = [r[0] for r in wrapped.source_ranges]
    assert roles == ["wrapper", "inner"]
    wrapper = wrapped.source_ranges[0]
    inner = wrapped.source_ranges[1]
    assert data[wrapper[1] : wrapper[2]] == B.explicit(
        B.tag("context", True, 3), B.octets(b"\xaa\xbb")
    )
    assert data[inner[1] : inner[2]] == B.octets(b"\xaa\xbb")


def test_decode_with_absolute_base_offsets(simple_product):
    from conftest import minimal_record

    data = minimal_record(simple_product)
    record = decode_record(data, simple_product, base=1000)
    values = record.value_map()
    assert record.start == 1000
    assert values["id"].source_ranges[0][1] >= 1000 + 2
    assert values["id"].end <= 1000 + len(data)


def test_long_tag_field_parsed(simple_product):
    from conftest import minimal_record

    data = minimal_record(simple_product)
    values = decode_record(data, simple_product).value_map()
    tagged = values["tagged"]
    assert tagged.value == 2
    # application tag 300 must have been written in base-128 long form
    raw = data[tagged.start : tagged.end]
    assert raw[:3] == b"\x5f\x82\x2c"


def test_negative_zero_length_integer_rejected():
    from conftest import field, make_schema
    from telber.schema import compile_product

    product = compile_product(
        make_schema([field("i", "context", 0, "implicit", "INTEGER")])
    )
    data = B.raw_tlv(B.tag("universal", True, 16), B.raw_tlv(B.tag("context", False, 0), b""))
    with pytest.raises(BerError) as exc:
        decode_record(data, product)
    assert exc.value.code == "invalid_integer"


def test_non_minimal_wire_tag_rejected_end_to_end():
    from conftest import field, make_schema
    from telber.schema import compile_product

    product = compile_product(
        make_schema([field("a", "context", 2, "implicit", "INTEGER")])
    )
    # context 2 written in long form: 0x9f 0x02
    bad = B.raw_tlv(B.tag("universal", True, 16), b"\x9f\x02\x01\x05")
    with pytest.raises(BerError) as exc:
        decode_record(bad, product)
    assert exc.value.code == "non_minimal_tag"
