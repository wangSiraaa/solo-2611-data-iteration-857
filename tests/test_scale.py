"""Scale checks kept out of the default run unless TELBER_FULL_SCALE is set.

Default-run coverage of the same properties lives in test_stream.py (bounded
memory) and test_schema.py (100 fields).  These tests exercise the concrete
limits from the task statement: 100 MiB stream, ~1 MiB records, 2 MiB body
buffer, depth 32.
"""

from __future__ import annotations

import io
import os

import pytest

from conftest import field, make_schema
from telber import build as B
from telber.errors import BerError
from telber.schema import compile_product
from telber.stream import RecordScanner, scan_records

full = pytest.mark.skipif(
    not os.environ.get("TELBER_FULL_SCALE"),
    reason="set TELBER_FULL_SCALE=1 to run full-scale tests",
)


def _product(blob_max=2 * 1024 * 1024):
    return compile_product(
        make_schema(
            [
                field("id", "context", 0, "implicit", "INTEGER"),
                field("blob", "context", 1, "implicit", "OCTET STRING"),
                field("tagged", "application", 300, "implicit", "INTEGER"),
            ]
        )
    )


def _record(id_, blob):
    body = (
        B.integer(id_, cls="context", number=0)
        + B.octets(blob, cls="context", number=1)
        + B.integer(id_ * 2, cls="application", number=300)
    )
    return B.seq(body)


@full
def test_depth_32_compiles_and_decodes():
    from telber.codec import decode_record

    fields = [field("leaf", "context", 0, "implicit", "INTEGER")]
    for i in range(32):
        fields = [field(f"n{i}", "context", 0, "implicit", "SEQUENCE", fields=fields)]
    product = compile_product(make_schema(fields))
    # build the matching 32-deep value
    payload = B.integer(7, cls="context", number=0)
    for _ in range(32):
        payload = B.tlv(B.tag("context", True, 0), payload)
    record = B.raw_tlv(B.tag("universal", True, 16), payload)
    decoded = decode_record(record, product).value_map()
    deepest = max(decoded, key=lambda p: len(p.split(".")))
    assert decoded[deepest].value == 7


@full
def test_100mib_stream_with_1mib_records(tmp_path):
    import tracemalloc

    product = _product()
    record = _record(1, b"\x00\x00" * (512 * 1024))  # ~1 MiB record
    target = 100 * 1024 * 1024
    count = target // len(record) + 1

    class RepeatingSource:
        """Serves ``count`` copies of ``record`` without materialising them."""

        def __init__(self) -> None:
            self.sent = 0
            self.total = len(record) * count

        def read(self, n: int) -> bytes:
            if self.sent >= self.total:
                return b""
            n = min(n, self.total - self.sent)
            offset = self.sent % len(record)
            chunk = (record * (n // len(record) + 2))[offset : offset + n]
            self.sent += n
            return chunk

    source = RepeatingSource()
    tracemalloc.start()
    try:
        seen = 0
        peak = 0
        scanner = RecordScanner(
            source, product, block_size=1024 * 1024,
            max_record=2 * 1024 * 1024, max_body=2 * 1024 * 1024,
        )
        for r in scanner.records():
            seen += 1
            peak = max(peak, scanner.src.buffered() + len(r.data))
            del r
        _, traced_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert source.total >= target
    assert seen == count
    # bounded buffers: not the 100 MiB stream
    assert peak < 8 * 1024 * 1024
    assert traced_peak < 16 * 1024 * 1024


@full
def test_body_over_2mib_rejected(tmp_path):
    product = _product()
    big = _record(1, b"\x00" * (2 * 1024 * 1024 + 1))
    with pytest.raises(BerError) as exc:
        list(scan_records(
            io.BytesIO(big), product,
            max_record=8 * 1024 * 1024, max_body=2 * 1024 * 1024,
            block_size=64 * 1024,
        ))
    assert exc.value.code == "body_too_large"
