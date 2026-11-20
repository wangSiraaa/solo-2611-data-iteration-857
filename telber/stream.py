"""Bounded streaming extraction of top-level BER records.

The stream layer performs *structural* delimitation only.  It parses headers
and walks nested constructed values (bounded recursion depth) to find where the
current top-level record ends, copying at most ``max_record`` bytes into a
small buffer, then hands that buffer to :func:`telber.codec.decode_record`.

Consequences:

* a 100 MiB stream is never held in memory; only one record (default 1 MiB)
  plus the source's fixed-size read block is resident,
* primitive bodies larger than ``max_body`` (default 2 MiB) are rejected before
  being copied,
* a truncated tail raises :class:`TruncatedError` with the absolute offset of
  the missing/partial encoding.  Records already yielded stay valid, and no
  byte-scanning resynchronisation is attempted,
* ``00 00`` only terminates an indefinite constructed layer.  In a definite
  constructed body or a primitive body it is ordinary data (or, for a definite
  constructed body, an invalid child header which the decoder rejects).

The read block size is configurable; it never changes the offsets or decoded
values, only I/O granularity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Iterator

from .ber import (
    MAX_LENGTH_OCTETS,
    MAX_TAG_NUMBER,
    Header,
    Tag,
    CODE_CLASSES,
)
from .errors import BerError, TruncatedError
from .schema import Product

DEFAULT_BLOCK_SIZE = 64 * 1024
DEFAULT_MAX_RECORD = 1 * 1024 * 1024
DEFAULT_MAX_BODY = 2 * 1024 * 1024
MAX_DEPTH = 64


class BlockSource:
    """A forward-only buffered view of a binary stream.

    ``buf`` holds up to ``block_size`` unconsumed bytes starting at internal
    index ``off``; ``pos`` is the absolute offset of ``buf[off]``.  Consumed
    bytes are reclaimed with an amortised compaction rather than a per-read
    front deletion, so byte-at-a-time header parsing (block size 1) stays linear
    in the stream length.
    """

    __slots__ = ("fp", "block_size", "buf", "off", "pos", "eof", "read_bytes")

    def __init__(self, fp: BinaryIO, *, block_size: int = DEFAULT_BLOCK_SIZE) -> None:
        if block_size <= 0:
            raise ValueError("block_size must be positive")
        self.fp = fp
        self.block_size = block_size
        self.buf = bytearray()
        self.off = 0
        self.pos = 0
        self.eof = False
        self.read_bytes = 0

    def tell(self) -> int:
        return self.pos

    def available(self) -> int:
        return len(self.buf) - self.off

    def _compact(self) -> None:
        if self.off:
            del self.buf[: self.off]
            self.off = 0

    def _fill(self, need: int) -> bool:
        """Buffer at least ``need`` unconsumed bytes if the stream has them.

        ``block_size`` is the *minimum* read granularity: small peeks read one
        block at a time, but a large requested span is fetched in one call so a
        tiny block size does not turn large body copies into per-byte I/O.
        """
        if self.available() < need and self.off:
            self._compact()
        while self.available() < need and not self.eof:
            want = max(self.block_size, need - self.available())
            chunk = self.fp.read(want)
            if not chunk:
                self.eof = True
                break
            self.read_bytes += len(chunk)
            self.buf.extend(chunk)
        return self.available() >= need

    def peek(self, n: int) -> bytes:
        self._fill(n)
        return bytes(self.buf[self.off : self.off + n])

    def read(self, n: int, *, context: str = "value") -> bytes:
        if not self._fill(n):
            raise TruncatedError(
                f"stream ended while reading {context}: need {n} bytes, "
                f"only {self.available()} available",
                offset=self.pos,
            )
        start = self.off
        out = bytes(self.buf[start : start + n])
        self.off = start + n
        self.pos += n
        # Reclaim eagerly once the consumed prefix dominates the window.
        if self.off > self.block_size:
            self._compact()
        return out

    def at_eof(self) -> bool:
        return not self._fill(1)

    def buffered(self) -> int:
        return self.available()


class _Sink:
    __slots__ = ("chunks", "size", "limit")

    def __init__(self, limit: int) -> None:
        self.chunks: list[bytes] = []
        self.size = 0
        self.limit = limit

    def add(self, data: bytes) -> None:
        self.size += len(data)
        if self.size > self.limit:
            raise BerError(
                f"record exceeds maximum supported size {self.limit} bytes",
                code="record_too_large",
            )
        self.chunks.append(data)

    def getvalue(self) -> bytes:
        return b"".join(self.chunks)


def _parse_header_stream(src: BlockSource, sink: _Sink, record_start: int) -> Header:
    offset = src.tell()
    first = src.read(1, context="identifier octet")
    sink.add(first)
    b0 = first[0]
    cls = CODE_CLASSES[b0 >> 6]
    constructed = bool(b0 & 0x20)
    number = b0 & 0x1F
    if number == 0x1F:
        groups: list[int] = []
        while True:
            b = src.read(1, context="long-form tag number")
            sink.add(b)
            if not groups and b[0] == 0x80:
                raise BerError(
                    "long-form tag number starts with padding octet 0x80",
                    offset=src.tell() - 1,
                    code="non_minimal_tag",
                )
            groups.append(b[0] & 0x7F)
            if not b[0] & 0x80:
                break
            if len(groups) > 9:
                raise BerError("long-form tag number is unreasonably long", offset=offset, code="tag_too_large")
        number = 0
        for g in groups:
            number = (number << 7) | g
        if number < 31:
            raise BerError(
                f"tag number {number} must use the short form",
                offset=offset,
                code="non_minimal_tag",
            )
        if number > MAX_TAG_NUMBER:
            raise BerError(
                f"tag number {number} exceeds supported maximum", offset=offset, code="tag_too_large"
            )
    tag = Tag(cls, constructed, number)

    len_start = src.tell()
    lb = src.read(1, context="length octet")
    sink.add(lb)
    l0 = lb[0]
    if l0 < 0x80:
        return Header(tag, offset, src.tell(), l0, False)
    if l0 == 0x80:
        if not constructed:
            raise BerError(
                "indefinite length not allowed for a primitive value",
                offset=len_start,
                code="indefinite_primitive",
            )
        return Header(tag, offset, src.tell(), None, True)
    count = l0 & 0x7F
    if count > MAX_LENGTH_OCTETS:
        raise BerError(
            f"long-form length uses {count} octets; at most {MAX_LENGTH_OCTETS} supported",
            offset=len_start,
            code="length_too_long",
        )
    body = src.read(count, context="long-form length")
    sink.add(body)
    if body[0] == 0:
        raise BerError(
            "long-form length has a leading zero octet",
            offset=len_start,
            code="non_minimal_length",
        )
    length = int.from_bytes(body, "big")
    if length < 0x80:
        raise BerError(
            f"length {length} must use the short form",
            offset=len_start,
            code="non_minimal_length",
        )
    return Header(tag, offset, src.tell(), length, False)


def _skip_value(
    src: BlockSource,
    sink: _Sink,
    header: Header,
    *,
    depth: int,
    max_body: int,
    record_start: int,
) -> None:
    """Consume the full encoding of ``header`` (header already in ``sink``).

    ``00 00`` is treated as an end-of-contents marker only while scanning the
    children of an indefinite-length constructed value.  A definite layer is
    bounded by its declared length and never ends early; ``00 00`` inside a
    primitive body is copied as data because primitive bodies are consumed by
    length.
    """
    if depth > MAX_DEPTH:
        raise BerError(
            f"nesting depth exceeds supported maximum {MAX_DEPTH}",
            offset=header.offset,
            code="too_deep",
        )
    if not header.tag.constructed:
        if header.indefinite:  # pragma: no cover - rejected by parser
            raise BerError(
                "indefinite length on a primitive value",
                offset=header.offset,
                code="indefinite_primitive",
            )
        assert header.length is not None
        if header.length > max_body:
            raise BerError(
                f"primitive body at offset {header.offset} is {header.length} bytes, "
                f"exceeding the {max_body}-byte buffer limit",
                offset=header.offset,
                code="body_too_large",
            )
        remaining = header.length
        while remaining:
            # Copy in large spans regardless of the block size: the block size
            # governs stream read granularity, not body-copy granularity.
            want = min(remaining, max(src.block_size, 64 * 1024))
            chunk = src.read(want, context="primitive body")
            sink.add(chunk)
            remaining -= want
        return

    if header.indefinite:
        while True:
            if src.at_eof():
                raise TruncatedError(
                    "indefinite-length value is missing its end-of-contents octets",
                    offset=src.tell(),
                )
            if src.peek(2) == b"\x00\x00":
                eoc = src.read(2, context="end-of-contents")
                sink.add(eoc)
                return
            child = _parse_header_stream(src, sink, record_start)
            _skip_value(
                src,
                sink,
                child,
                depth=depth + 1,
                max_body=max_body,
                record_start=record_start,
            )
    else:
        assert header.length is not None
        body_end = src.tell() + header.length
        while src.tell() < body_end:
            if src.at_eof():
                raise TruncatedError(
                    f"definite-length value at offset {header.offset} is truncated; "
                    f"expected body to end at offset {body_end}",
                    offset=src.tell(),
                )
            # Inside a definite layer, 0x00 is never an EOC: it is an
            # (invalid) identifier octet and parsing it as a child is correct.
            child_region_start = src.tell()
            available = body_end - child_region_start
            child = _parse_header_stream(src, sink, record_start)
            header_len = src.tell() - child_region_start
            if header_len > available:
                raise BerError(
                    "child header crosses the end of its parent value",
                    offset=child.offset,
                    code="child_overruns_parent",
                )
            if not child.indefinite and child.length is not None:
                if header_len + child.length > available:
                    raise BerError(
                        "child value crosses the end of its parent value",
                        offset=child.offset,
                        code="child_overruns_parent",
                    )
            _skip_value(
                src,
                sink,
                child,
                depth=depth + 1,
                max_body=max_body,
                record_start=record_start,
            )
            if src.tell() > body_end:
                raise BerError(
                    "child value crosses the end of its parent value",
                    offset=child.offset,
                    code="child_overruns_parent",
                )
        if src.tell() != body_end:  # pragma: no cover - loop condition guarantees
            raise BerError(
                "constructed value body length mismatch",
                offset=src.tell(),
                code="child_overruns_parent",
            )


@dataclass
class StreamRecord:
    start: int
    data: bytes

    @property
    def end(self) -> int:
        return self.start + len(self.data)


class RecordScanner:
    """Iterates over complete top-level records from a binary stream."""

    def __init__(
        self,
        fp: BinaryIO,
        product: Product,
        *,
        block_size: int = DEFAULT_BLOCK_SIZE,
        max_record: int = DEFAULT_MAX_RECORD,
        max_body: int = DEFAULT_MAX_BODY,
    ) -> None:
        self.product = product
        self.src = BlockSource(fp, block_size=block_size)
        self.max_record = max_record
        self.max_body = max_body
        self._started = False
        self.error: Exception | None = None

    def __iter__(self) -> Iterator[StreamRecord]:
        return self.records()

    def records(self) -> Iterator[StreamRecord]:
        while True:
            if not self._started:
                self._started = True
            if self.src.at_eof():
                return
            start = self.src.tell()
            try:
                sink = _Sink(self.max_record)
                header = _parse_header_stream(self.src, sink, start)
                # Root tag validation happens here so a garbage stream fails with
                # its real offset instead of after a potentially long skip.
                if header.tag != self.product.root_tag:
                    raise BerError(
                        f"expected root tag {self.product.root_tag}, found {header.tag}",
                        offset=header.offset,
                        code="root_tag_mismatch",
                    )
                _skip_value(
                    self.src,
                    sink,
                    header,
                    depth=0,
                    max_body=self.max_body,
                    record_start=start,
                )
            except BerError as exc:
                exc.with_record_start(start)
                raise
            yield StreamRecord(start=start, data=sink.getvalue())


def scan_records(
    fp: BinaryIO,
    product: Product,
    **kwargs,
) -> Iterator[StreamRecord]:
    return RecordScanner(fp, product, **kwargs).records()
