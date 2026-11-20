"""Minimal BER-subset tag/length codec.

Supported on the wire:

* identifier octets: class (universal/application/context/private), constructed
  bit, tag numbers in both short form (0..30) and base-128 long form
  (31 and beyond).  Long-form tag encodings must be minimal: no leading 0x80
  padding octet and no needless extra octets.
* length octets: short form (0..127), long form with 1..4 length octets, and
  the indefinite form 0x80 for constructed values only.  Long-form lengths
  must be minimal (no leading zero octet, and a value that fits in the short
  form must use it).
* universal primitives INTEGER, OCTET STRING and NULL; SEQUENCE.  INTEGER uses
  the shortest two's-complement big-endian representation; NULL must have
  length zero.

The decoder never treats the octets 0x00 0x00 as an end-of-contents marker
except while scanning the direct children of a constructed value whose length
was encoded as indefinite.  Inside a primitive body they are ordinary data.

Nothing here depends on an ASN.1 compiler or on application-specific types.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .errors import BerError, TruncatedError

UNIVERSAL = "universal"
APPLICATION = "application"
CONTEXT = "context"
PRIVATE = "private"

CLASS_CODES = {UNIVERSAL: 0, APPLICATION: 1, CONTEXT: 2, PRIVATE: 3}
CODE_CLASSES = {code: name for name, code in CLASS_CODES.items()}

UNIVERSAL_INTEGER = 2
UNIVERSAL_OCTET_STRING = 4
UNIVERSAL_NULL = 5
UNIVERSAL_SEQUENCE = 16

MAX_TAG_NUMBER = (1 << 63) - 1
MAX_LENGTH_OCTETS = 4
MAX_DEFINITE_LENGTH = (1 << (8 * MAX_LENGTH_OCTETS)) - 1


@dataclass(frozen=True, order=True)
class Tag:
    cls: str
    constructed: bool
    number: int

    def __str__(self) -> str:
        return f"{self.cls}({self.number}){'*' if self.constructed else ''}"

    def as_dict(self) -> dict:
        return {
            "class": self.cls,
            "constructed": self.constructed,
            "number": self.number,
        }


@dataclass(frozen=True)
class Header:
    """A parsed identifier + length octets pair."""

    tag: Tag
    offset: int
    header_end: int
    length: int | None  # None means indefinite
    indefinite: bool


def encode_tag(cls: str, constructed: bool, number: int) -> bytes:
    if cls not in CLASS_CODES:
        raise BerError(f"unknown class {cls!r}", code="bad_tag_class")
    if not isinstance(number, int) or number < 0:
        raise BerError(f"tag number must be non-negative, got {number!r}", code="bad_tag_number")
    if number > MAX_TAG_NUMBER:
        raise BerError(f"tag number {number} exceeds supported maximum", code="bad_tag_number")
    first = (CLASS_CODES[cls] << 6) | (0x20 if constructed else 0)
    if number < 31:
        return bytes([first | number])
    out = bytearray([first | 0x1F])
    # base-128, most significant group first
    groups = []
    n = number
    while n:
        groups.append(n & 0x7F)
        n >>= 7
    groups.reverse()
    for i, g in enumerate(groups):
        out.append(g | (0x80 if i + 1 < len(groups) else 0))
    return bytes(out)


def encode_length(length: int, *, indefinite: bool = False) -> bytes:
    if indefinite:
        return b"\x80"
    if not isinstance(length, int) or length < 0:
        raise BerError(f"length must be non-negative, got {length!r}", code="bad_length")
    if length < 0x80:
        return bytes([length])
    if length > MAX_DEFINITE_LENGTH:
        raise BerError(
            f"length {length} exceeds 4-octet long-form maximum", code="length_too_large"
        )
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode_header(tag: Tag, length: int | None = None) -> bytes:
    """Encode identifier octets followed by length octets.

    ``length=None`` requests the indefinite form and requires a constructed tag.
    """
    if length is None:
        if not tag.constructed:
            raise BerError("indefinite length requires a constructed value", code="indefinite_primitive")
        return encode_tag(tag.cls, tag.constructed, tag.number) + b"\x80"
    return encode_tag(tag.cls, tag.constructed, tag.number) + encode_length(length)


class Reader:
    """A cursor over an immutable byte buffer with absolute-offset tracking.

    ``limit`` bounds the region the reader may consume.  When the limit is the
    buffer end, running out of bytes is a stream truncation; when it is a
    parent's body end, crossing it is a structural overrun.
    """

    __slots__ = ("data", "pos", "base", "limit")

    def __init__(
        self, data: bytes, pos: int = 0, base: int = 0, limit: int | None = None
    ) -> None:
        self.data = data
        self.pos = pos
        self.base = base
        self.limit = len(data) if limit is None else limit

    @property
    def offset(self) -> int:
        return self.base + self.pos

    @property
    def limit_offset(self) -> int:
        return self.base + self.limit

    def at_end(self) -> bool:
        return self.pos >= self.limit

    def remaining(self) -> int:
        return self.limit - self.pos

    def peek(self, count: int = 1) -> bytes:
        end = min(self.pos + count, self.limit, len(self.data))
        return self.data[self.pos : end]

    def read(self, count: int, *, context: str = "value body") -> bytes:
        end = self.pos + count
        if end > self.limit:
            if self.limit >= len(self.data):
                raise TruncatedError(
                    f"stream ended while reading {context}: need {count} bytes, "
                    f"only {max(0, len(self.data) - self.pos)} available",
                    offset=self.offset,
                )
            raise BerError(
                f"{context} at offset {self.offset} crosses the end of its "
                f"enclosing value at offset {self.limit_offset}",
                offset=self.offset,
                code="body_overruns_parent",
            )
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk


def parse_tag(reader: Reader) -> Tag:
    start = reader.offset
    first = reader.read(1, context="identifier octet")[0]
    cls = CODE_CLASSES[first >> 6]
    constructed = bool(first & 0x20)
    number = first & 0x1F
    if number != 0x1F:
        return Tag(cls, constructed, number)

    # High-tag-number form.  The first group must be non-zero (which also
    # forbids the 0x80 padding octet) and the encoding must use the fewest
    # possible groups.
    groups: list[int] = []
    while True:
        b = reader.read(1, context="long-form tag number")[0]
        if not groups and b == 0x80:
            raise BerError(
                "long-form tag number starts with padding octet 0x80",
                offset=reader.offset - 1,
                code="non_minimal_tag",
            )
        groups.append(b & 0x7F)
        if not b & 0x80:
            break
        if len(groups) > 9:
            raise BerError("long-form tag number is unreasonably long", offset=start, code="tag_too_large")
    value = 0
    for g in groups:
        value = (value << 7) | g
    if value < 31:
        raise BerError(
            f"tag number {value} must use the short form",
            offset=start,
            code="non_minimal_tag",
        )
    if value > MAX_TAG_NUMBER:
        raise BerError(f"tag number {value} exceeds supported maximum", offset=start, code="tag_too_large")
    return Tag(cls, constructed, value)


def parse_length(reader: Reader, *, constructed: bool) -> tuple[int | None, bool]:
    start = reader.offset
    first = reader.read(1, context="length octet")[0]
    if first < 0x80:
        return first, False
    if first == 0x80:
        if not constructed:
            raise BerError(
                "indefinite length not allowed for a primitive value",
                offset=start,
                code="indefinite_primitive",
            )
        return None, True
    count = first & 0x7F
    if count > MAX_LENGTH_OCTETS:
        raise BerError(
            f"long-form length uses {count} octets; at most {MAX_LENGTH_OCTETS} supported",
            offset=start,
            code="length_too_long",
        )
    body = reader.read(count, context="long-form length")
    if body[0] == 0:
        raise BerError(
            "long-form length has a leading zero octet",
            offset=start,
            code="non_minimal_length",
        )
    value = int.from_bytes(body, "big")
    if value < 0x80:
        raise BerError(
            f"length {value} must use the short form",
            offset=start,
            code="non_minimal_length",
        )
    return value, False


def parse_header(reader: Reader) -> Header:
    offset = reader.offset
    tag = parse_tag(reader)
    length, indefinite = parse_length(reader, constructed=tag.constructed)
    return Header(tag=tag, offset=offset, header_end=reader.offset, length=length, indefinite=indefinite)


def is_eoc(data: bytes, pos: int, end: int) -> bool:
    return pos + 2 <= end and data[pos] == 0x00 and data[pos + 1] == 0x00


@dataclass
class Tlv:
    """A decoded value location within the original buffer.

    ``body_start``/``body_end`` delimit the value octets; ``end`` is the offset
    just past the complete encoding (including any EOC octets for indefinite
    constructed values).  Offsets are absolute if the buffer was presented with
    a non-zero base.
    """

    tag: Tag
    header_start: int
    body_start: int
    body_end: int
    end: int
    indefinite: bool
    children: list["Tlv"] | None = None
    primitive_body_start: int | None = None
    primitive_body_end: int | None = None

    def body_bytes(self, buffer: bytes, base: int = 0) -> bytes:
        return buffer[self.body_start - base : self.body_end - base]


def iter_children(
    data: bytes,
    pos: int,
    end: int,
    base: int = 0,
) -> Iterator[tuple[Tag, int, int, int | None, bool]]:
    """Yield ``(tag, header_start, body_start, body_len, indefinite)``.

    For indefinite children the caller must recurse to find the true end; this
    iterator is used only for shallow structural scans (EOC checks, test
    helpers).
    """
    while pos < end:
        reader = Reader(data, pos - base, base)
        header = parse_header(reader)
        body_start = reader.pos
        if header.indefinite:
            yield header.tag, header.offset, body_start + base, None, True
            # caller cannot advance reliably; stop
            return
        body_end = body_start + header.length
        if body_end > len(data):
            raise TruncatedError("value body extends past end of buffer", offset=header.offset)
        yield header.tag, header.offset, body_start + base, header.length, False
        pos = body_end
