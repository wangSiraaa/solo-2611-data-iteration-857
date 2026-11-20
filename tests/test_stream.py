"""Streaming delimitation: block-size invariance, limits, truncation, EOC."""

from __future__ import annotations

import io

import pytest

from conftest import field, make_schema
from telber import build as B
from telber.codec import decode_record
from telber.errors import BerError, TelberError, TruncatedError
from telber.schema import compile_product
from telber.stream import RecordScanner, scan_records


def records(list_of_bodies, *, indefinite=False):
    return [B.seq(body, indefinite=indefinite) for body in list_of_bodies]


@pytest.fixture
def stream_product():
    return compile_product(
        make_schema(
            [
                field("id", "context", 0, "implicit", "INTEGER"),
                field("blob", "context", 1, "implicit", "OCTET STRING", optional=True),
                field("tagged", "application", 300, "implicit", "INTEGER"),
                field("inner", "application", 1000, "implicit", "SEQUENCE",
                      fields=[field("a", "private", 0, "implicit", "INTEGER")]),
            ]
        )
    )


def body(id_, tagged, a, blob=None):
    parts = [B.integer(id_, cls="context", number=0)]
    if blob is not None:
        parts.append(B.octets(blob, cls="context", number=1))
    parts.append(B.integer(tagged, cls="application", number=300))
    parts.append(
        B.tlv(B.tag("application", True, 1000), B.integer(a, cls="private", number=0))
    )
    return b"".join(parts)


def test_block_size_invariance(stream_product):
    parts = [
        B.seq(body(-1, 0, 1, b"\x00\x00")),
        B.seq(body(2, -129, 2), indefinite=True),
        B.seq(body(300, 5, 3, b"\x00\x00\x00\x00")),
        B.seq(body(-8388608, 7, 4), indefinite=True),
    ]
    stream = b"".join(parts)
    expected = parts
    for block in (1, 2, 3, 4, 5, 7, 13, 64, 4096):
        got = [r.data for r in scan_records(io.BytesIO(stream), stream_product, block_size=block)]
        assert got == expected, f"block size {block} disagreed"

    offsets = [r.start for r in scan_records(io.BytesIO(stream), stream_product, block_size=3)]
    running = 0
    expected_offsets = []
    for p in parts:
        expected_offsets.append(running)
        running += len(p)
    assert offsets == expected_offsets


def test_offsets_independent_of_block_size(stream_product):
    stream = b"".join(records([body(1, 2, 3), body(4, 5, 6)]))
    reference = None
    for block in (1, 2, 7, 1024):
        spans = [(r.start, r.end) for r in scan_records(io.BytesIO(stream), stream_product, block_size=block)]
        if reference is None:
            reference = spans
        assert spans == reference


def test_truncated_tail_reports_offset_and_keeps_prefix(stream_product):
    good = records([body(1, 2, 3), body(4, 5, 6)])
    stream = b"".join(good) + B.seq(body(7, 8, 9))[:-2]  # cut inside last primitive body
    scanner = RecordScanner(io.BytesIO(stream), stream_product, block_size=2)
    seen = []
    with pytest.raises(TruncatedError) as exc:
        for r in scanner.records():
            seen.append(r.data)
    assert seen == good
    assert exc.value.offset == len(stream)
    assert exc.value.record_start == len(good[0]) + len(good[1])


def test_truncation_prefix_matches_across_block_sizes(stream_product):
    good = records([body(1, 2, 3), body(4, 5, 6)])
    stream = b"".join(good) + B.seq(body(7, 8, 9))[:-1]
    results = {}
    for block in (1, 3, 5, 64):
        seen = []
        error = None
        try:
            for r in scan_records(io.BytesIO(stream), stream_product, block_size=block):
                seen.append(r.data)
        except TelberError as exc:
            error = (exc.code, exc.offset, exc.record_start)
        results[block] = (seen, error)
    assert all(v == results[1] for v in results.values())


def test_no_resynchronisation_after_bad_record(stream_product):
    # Structurally truncated root (declares 5 body bytes, only 2 present).
    bad = b"\x30\x05\x01\x02"
    stream = records([body(1, 2, 3)])[0] + bad + records([body(4, 5, 6)])[0]
    seen = []
    with pytest.raises(TelberError):
        for r in scan_records(io.BytesIO(stream), stream_product, block_size=1):
            seen.append(r.data)
    # the third, perfectly valid record must never be reached
    assert len(seen) == 1


def test_00_00_in_primitive_body_does_not_split_record(stream_product):
    one = records([body(1, 2, 3, b"\x00\x00\x00\x00")])[0]
    stream = one + one
    got = [r.data for r in scan_records(io.BytesIO(stream), stream_product, block_size=1)]
    assert got == [one, one]


def test_indefinite_layer_terminator_only_at_its_level(stream_product):
    # Both the outer record and the nested 'inner' SEQUENCE are indefinite and
    # contain a primitive body ending in 00 00.  Only the two real EOCs may
    # terminate layers; the primitive's trailing zeros are data.
    inner = B.tlv(
        B.tag("application", True, 1000),
        B.integer(1, cls="private", number=0),
        indefinite=True,
    )
    one = B.raw_tlv(
        B.tag("universal", True, 16),
        B.integer(1, cls="context", number=0)
        + B.octets(b"\x00\x00", cls="context", number=1)
        + B.integer(2, cls="application", number=300)
        + inner,
        indefinite=True,
    )
    stream = one + one
    got = [r.data for r in scan_records(io.BytesIO(stream), stream_product, block_size=2)]
    assert got == [one, one]
    record = decode_record(got[0], stream_product)
    assert record.value_map()["blob"].value == b"\x00\x00"


def test_max_record_limit(stream_product):
    big = body(1, 2, 3, b"\x00" * 512)
    stream = records([big])[0]
    with pytest.raises(BerError) as exc:
        list(scan_records(io.BytesIO(stream), stream_product, max_record=128, block_size=16))
    assert exc.value.code == "record_too_large"


def test_max_body_limit(stream_product):
    big = body(1, 2, 3, b"\x00" * 4096)
    stream = records([big])[0]
    with pytest.raises(BerError) as exc:
        list(scan_records(io.BytesIO(stream), stream_product, max_body=1024, block_size=16))
    assert exc.value.code == "body_too_large"


def test_root_tag_mismatch_reported_at_first_byte(stream_product):
    stream = b"\x31\x00" + records([body(1, 2, 3)])[0]
    with pytest.raises(BerError) as exc:
        list(scan_records(io.BytesIO(stream), stream_product, block_size=1))
    assert exc.value.code == "root_tag_mismatch"
    assert exc.value.offset == 0


def test_depth_limit(stream_product):
    # Deeply nested constructed values not matching the product: the scanner
    # must still bound recursion rather than crash.
    payload = B.integer(1, cls="private", number=0)
    for _ in range(200):
        payload = B.tlv(B.tag("context", True, 0), payload)
    stream = B.raw_tlv(B.tag("universal", True, 16), payload)
    with pytest.raises(BerError) as exc:
        list(scan_records(io.BytesIO(stream), stream_product, block_size=8))
    assert exc.value.code in {"too_deep", "record_too_large"}


def test_definite_parent_child_overrun_detected(stream_product):
    # root says 3 bytes, child claims 5 body bytes
    stream = b"\x30\x03\x80\x05\x01\x02"
    with pytest.raises(BerError) as exc:
        list(scan_records(io.BytesIO(stream), stream_product, block_size=1))
    assert exc.value.code in {"body_overruns_parent", "child_overruns_parent", "truncated"}


def test_empty_stream_yields_no_records(stream_product):
    assert list(scan_records(io.BytesIO(b""), stream_product)) == []


def test_large_stream_bounded_memory(stream_product, tmp_path):
    """A stream many times larger than the buffer is processed without loading
    it: the read buffer plus the current record stays small."""
    import os

    one = records([body(1, 2, 3, b"\x00" * 64)])[0]
    count = 20000  # ~1.4 MB total
    path = tmp_path / "many.bin"
    with open(path, "wb") as fh:
        for _ in range(count):
            fh.write(one)
    total = os.path.getsize(path)
    assert total == count * len(one)

    seen = 0
    max_buffered = 0
    with open(path, "rb") as fh:
        scanner = RecordScanner(fh, stream_product, block_size=4096)
        for r in scanner.records():
            seen += 1
            max_buffered = max(max_buffered, scanner.src.buffered() + len(r.data))
    assert seen == count
    assert max_buffered < 64 * 1024
    assert max_buffered < total / 10
