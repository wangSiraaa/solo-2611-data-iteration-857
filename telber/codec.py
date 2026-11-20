"""Decode / encode telemetry records under a compiled product.

Design notes
------------

* Every TLV header is parsed by :mod:`telber.ber`, which rejects non-minimal
  tags/lengths and indefinite primitive lengths at the byte level.
* Instantiation matches fields of a SEQUENCE strictly in declaration order.
  Optional fields are consumed in order while their wire tag matches; once a
  required field is reached, a missing required field is an error, and a
  required field whose wire tag does not match is *not* skipped in search of a
  later match (schemas with that hazard are rejected at compile time).
* A decoded value remembers the *absolute* byte range of its body so the
  ingestion repository can record field provenance.  Explicit fields also
  remember the inner value's range.
* Primitive bodies are materialised into bounded byte buffers by the streaming
  reader; the plain buffer entry points used in tests operate in memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Any, Mapping

from .ber import (
    Header,
    Reader,
    Tag,
    parse_header,
)
from .errors import BerError, DecodeError, EncodeError, TruncatedError
from .schema import Field, Product


@dataclass
class Value:
    """A decoded value plus the absolute byte ranges of its encoding."""

    field: str
    path: str
    type: str
    value: Any
    present: bool = True
    null: bool = False
    # Absolute offsets of the complete field encoding (header + body + EOC).
    start: int | None = None
    end: int | None = None
    # Absolute offsets of the primitive body (or the inner value of an
    # explicit wrapper for its inner primitive body).
    body_start: int | None = None
    body_end: int | None = None
    # (role, start, end) byte ranges in the original stream.  Roles are
    # ``encoding`` for an implicitly-tagged complete field, ``wrapper`` and
    # ``inner`` for an explicit field's outer and inner values, and ``body``
    # for the value octets themselves.
    source_ranges: list[tuple[str, int, int]] = dc_field(default_factory=list)
    children: list["Value"] = dc_field(default_factory=list)
    source: str = "wire"

    def as_dict(self, *, include_children: bool = True) -> dict:
        out = {
            "field": self.field,
            "path": self.path,
            "type": self.type,
            "present": self.present,
            "null": self.null,
            "start": self.start,
            "end": self.end,
            "body_start": self.body_start,
            "body_end": self.body_end,
            "source_ranges": [[role, s, e] for role, s, e in self.source_ranges],
            "source": self.source,
        }
        if self.type == "SEQUENCE":
            out["value"] = None
        elif self.type == "OCTET STRING":
            out["value"] = self.value.hex() if self.value is not None else None
        else:
            out["value"] = self.value
        if include_children and self.children:
            out["children"] = [c.as_dict() for c in self.children]
        return out


@dataclass
class Record:
    """A decoded top-level record."""

    start: int
    end: int
    fields: list[Value]

    def as_dict(self, *, include_children: bool = True) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "fields": [v.as_dict(include_children=include_children) for v in self.fields],
        }

    def value_map(self) -> dict[str, Value]:
        out: dict[str, Value] = {}

        def walk(values: list[Value]) -> None:
            for v in values:
                out[v.path] = v
                walk(v.children)

        walk(self.fields)
        return out


# ---------------------------------------------------------------------------
# Buffer decoder (whole record already in memory)

def decode_record(data: bytes, product: Product, *, base: int = 0) -> Record:
    """Decode exactly one complete top-level record from ``data``.

    ``base`` is the absolute stream offset of ``data[0]``; all recorded offsets
    are absolute so provenance points into the original source stream.  The
    whole buffer must be consumed: concatenated records are rejected instead of
    being silently merged.
    """
    reader = Reader(data, 0, base)
    header = parse_header(reader)
    if header.tag != product.root_tag:
        raise DecodeError(
            f"expected root tag {product.root_tag}, found {header.tag}",
            offset=header.offset,
            code="root_tag_mismatch",
        )
    value = _decode_value(reader, _RootField(product), header)
    if not reader.at_end():
        raise DecodeError(
            f"{reader.remaining()} trailing byte(s) after the top-level record",
            offset=reader.offset,
            code="trailing_bytes",
        )
    return Record(start=header.offset, end=reader.offset, fields=value.children)


class _RootField:
    """Structural stand-in for the root SEQUENCE while decoding."""

    __slots__ = ("name", "path", "base_type", "mode", "fields", "wire_tag", "inner_tag")

    def __init__(self, product: Product) -> None:
        self.name = product.root_name
        self.path = ""
        self.base_type = "SEQUENCE"
        self.mode = "implicit"
        self.fields = product.fields
        self.wire_tag = product.root_tag
        self.inner_tag = None


def _require_constructed(header: Header, what: str) -> None:
    if not header.tag.constructed:
        raise BerError(
            f"{what} must be constructed but tag {header.tag} is primitive",
            offset=header.offset,
            code="expected_construct",
        )


def _require_primitive(header: Header, path: str) -> None:
    if header.tag.constructed:
        raise BerError(
            f"field {path!r} expects a primitive value but tag {header.tag} is constructed",
            offset=header.offset,
            code="unexpected_construct",
        )


def _enter(reader: Reader, header: Header, what: str) -> tuple[int, bool]:
    """Return ``(body_end, indefinite)`` for a constructed value.

    ``body_end`` is a *buffer-relative* offset (the same coordinate space as
    ``reader.pos``/``reader.limit``); message offsets stay absolute.  For
    indefinite values it is the enclosing limit; the terminator is checked
    separately.
    """
    if header.indefinite:
        return reader.limit, True
    assert header.length is not None
    body_end = (header.header_end - reader.base) + header.length
    if body_end > reader.limit:
        if reader.limit >= len(reader.data):
            raise TruncatedError(
                f"{what} at offset {header.offset} extends past the end of data",
                offset=header.offset,
            )
        raise BerError(
            f"{what} at offset {header.offset} extends past its enclosing value "
            f"(ends at offset {reader.limit_offset})",
            offset=header.offset,
            code="body_overruns_parent",
        )
    return body_end, False


def _decode_value(
    reader: Reader,
    fld,
    header: Header,
) -> Value:
    """Decode one complete value (header consumed) under ``reader.limit``."""
    body_end, indefinite = _enter(reader, header, f"value {fld.path!r}")
    start = header.offset
    body_start = header.header_end
    value = Value(
        field=fld.name,
        path=fld.path or fld.name,
        type=fld.base_type,
        value=None,
        start=start,
        body_start=body_start,
    )

    if fld.base_type == "SEQUENCE":
        _require_constructed(header, f"SEQUENCE {fld.path!r}")
        children = _decode_children(
            reader, fld.fields, body_end=body_end, indefinite=indefinite, path=fld.path
        )
        value.children = children
        value.body_end = (body_end + reader.base) if not indefinite else reader.offset - 2
        value.end = reader.offset
    else:
        _require_primitive(header, fld.path)
        if indefinite:  # pragma: no cover - rejected by parse_length
            raise BerError(
                f"primitive field {fld.path!r} cannot be indefinite",
                offset=header.offset,
                code="indefinite_primitive",
            )
        assert header.length is not None
        body = reader.read(header.length, context=f"{fld.base_type} {fld.path!r}")
        if fld.base_type == "INTEGER":
            value.value = _decode_integer(body, offset=body_start)
        elif fld.base_type == "OCTET STRING":
            value.value = bytes(body)
        else:  # NULL
            if body:
                raise DecodeError(
                    f"NULL field {fld.path!r} must have length 0, got {len(body)}",
                    offset=body_start,
                    code="null_nonzero_length",
                )
            value.value = None
            value.null = True
        value.body_end = reader.offset
        value.end = reader.offset

    # For an implicitly-tagged field the complete encoding is the source.
    # Explicit callers prepend the wrapper range themselves.
    value.source_ranges.append(("encoding", start, value.end))
    return value


def _decode_children(
    reader: Reader,
    fields: tuple,
    *,
    body_end: int,
    indefinite: bool,
    path: str,
) -> list[Value]:
    """Decode the direct children of a constructed value."""
    saved_limit = reader.limit
    # For indefinite layers body_end is the enclosing limit, so EOC handling
    # consumes the terminator before the limit is hit.
    reader.limit = body_end
    values: list[Value] = []
    pos = 0
    closed = False
    try:
        while True:
            if reader.at_end():
                break
            if reader.peek(2) == b"\x00\x00":
                if not indefinite:
                    raise BerError(
                        "unexpected end-of-contents octets inside a definite-length value",
                        offset=reader.offset,
                        code="unexpected_eoc",
                    )
                reader.read(2, context="end-of-contents")
                closed = True
                break
            if pos >= len(fields):
                trailing = parse_header(reader)
                raise DecodeError(
                    f"unknown field with tag {trailing.tag} in {path or 'root'} "
                    f"after {len(fields)} declared field(s)",
                    offset=trailing.offset,
                    code="unknown_field",
                )
            fld = fields[pos]
            probe = Reader(reader.data, reader.pos, reader.base, reader.limit)
            child_header = parse_header(probe)
            if child_header.tag != fld.wire_tag:
                if fld.optional:
                    pos += 1
                    continue
                raise DecodeError(
                    f"field {fld.path!r} expected tag {fld.wire_tag}, "
                    f"found {child_header.tag}",
                    offset=child_header.offset,
                    code="tag_mismatch",
                )
            reader.pos = probe.pos
            child = _decode_field(reader, fld, child_header)
            values.append(child)
            pos += 1
    finally:
        reader.limit = saved_limit

    if indefinite and not closed:
        raise TruncatedError(
            "indefinite-length value is missing its end-of-contents octets",
            offset=reader.offset,
        )
    for fld in fields[pos:]:
        if not fld.optional:
            raise DecodeError(
                f"required field {fld.path!r} is missing",
                offset=reader.offset,
                code="missing_field",
            )
    return values


def _decode_field(reader: Reader, fld, header: Header) -> Value:
    """Decode a field, unwrapping an explicit layer when declared."""
    if fld.mode != "explicit":
        return _decode_value(reader, fld, header)

    _require_constructed(header, f"explicit field {fld.path!r}")
    wrapper_end, wrapper_indefinite = _enter(reader, header, f"explicit wrapper {fld.path!r}")
    saved_limit = reader.limit
    # An indefinite wrapper shares its enclosing limit; the inner value and the
    # EOC are consumed before it is reached.
    reader.limit = saved_limit if wrapper_indefinite else wrapper_end
    try:
        if reader.at_end():
            raise DecodeError(
                f"explicit field {fld.path!r} wraps no value",
                offset=reader.offset,
                code="explicit_empty",
            )
        inner_header = parse_header(reader)
        assert fld.inner_tag is not None
        if inner_header.tag != fld.inner_tag:
            raise DecodeError(
                f"explicit field {fld.path!r} expected inner tag {fld.inner_tag}, "
                f"found {inner_header.tag}",
                offset=inner_header.offset,
                code="explicit_inner_tag_mismatch",
            )
        value = _decode_value(reader, fld, inner_header)
        if wrapper_indefinite:
            if reader.peek(2) != b"\x00\x00":
                raise DecodeError(
                    f"explicit field {fld.path!r} must wrap exactly one value",
                    offset=reader.offset,
                    code="explicit_extra_value",
                )
            reader.read(2, context="explicit end-of-contents")
        elif not reader.at_end():
            raise DecodeError(
                f"explicit field {fld.path!r} must wrap exactly one value; "
                f"{reader.remaining()} trailing byte(s)",
                offset=reader.offset,
                code="explicit_extra_value",
            )
    finally:
        reader.limit = saved_limit
    # ``value`` currently carries the inner value's ranges; the explicit
    # wrapper adds its own enclosing range and records the inner one clearly.
    inner_ranges = value.source_ranges
    value.source_ranges = [("wrapper", header.offset, reader.offset)]
    value.source_ranges.extend(
        ("inner", s, e) for _, s, e in inner_ranges if _ == "encoding"
    )
    value.source_ranges.extend(
        r for r in inner_ranges if r[0] != "encoding"
    )
    value.start = header.offset
    value.end = reader.offset
    return value


def _decode_integer(body: bytes, *, offset: int) -> int:
    if not body:
        raise BerError(
            "INTEGER body must contain at least one octet",
            offset=offset,
            code="invalid_integer",
        )
    if len(body) > 1:
        if body[0] == 0x00 and body[1] & 0x80 == 0:
            raise BerError(
                "INTEGER has a redundant leading 0x00 octet",
                offset=offset,
                code="non_minimal_integer",
            )
        if body[0] == 0xFF and body[1] & 0x80:
            raise BerError(
                "INTEGER has a redundant leading 0xFF octet",
                offset=offset,
                code="non_minimal_integer",
            )
    return int.from_bytes(body, "big", signed=True)


def _encode_integer(value: int) -> bytes:
    """Shortest two's-complement big-endian body for ``value``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise EncodeError(
            f"INTEGER value must be an int, got {type(value).__name__!r}",
            code="type_error",
        )
    if value == 0:
        return b"\x00"
    if value > 0:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return b"\x00" + body if body[0] & 0x80 else body
    length = 1
    while not (-(1 << (8 * length - 1)) <= value < (1 << (8 * length - 1))):
        length += 1
    body = value.to_bytes(length, "big", signed=True)
    while length > 1 and body[0] == 0xFF and body[1] & 0x80:
        body = body[1:]
        length -= 1
    return body


# ---------------------------------------------------------------------------
# Encoder (used by the compile service's schema product checks)

def _normalize(values: Mapping[str, Any]) -> dict:
    """Expand flat dotted keys into nested mappings.

    ``{"sub.x": 5}`` and ``{"sub": {"x": 5}}`` normalise identically.
    """
    root: dict = {}
    for key, value in values.items():
        parts = str(key).split(".")
        cur = root
        for part in parts[:-1]:
            nxt = cur.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[part] = nxt
            cur = nxt
        leaf = parts[-1]
        if isinstance(value, Mapping):
            existing = cur.get(leaf)
            base = dict(existing) if isinstance(existing, Mapping) else {}
            base.update(value)
            cur[leaf] = base
        else:
            cur[leaf] = value
    return root


def _collect_sequence(
    fields: tuple[Field, ...],
    scope: Mapping[str, Any],
    prefix: str,
    out: list[tuple[Field, bytes]],
) -> None:
    for fld in fields:
        key = f"{prefix}.{fld.name}" if prefix else fld.name
        present = fld.name in scope
        val = scope.get(fld.name)
        if not present or (val is None and fld.base_type not in ("NULL", "SEQUENCE")):
            if fld.optional:
                continue
            if fld.base_type == "NULL":
                val = None
            else:
                raise EncodeError(
                    f"missing required field {key!r}", code="missing_field"
                )
        if fld.base_type == "SEQUENCE":
            if not isinstance(val, Mapping):
                raise EncodeError(
                    f"SEQUENCE field {key!r} requires a mapping of subfields, "
                    f"got {type(val).__name__!r}",
                    code="type_error",
                )
            nested: list[tuple[Field, bytes]] = []
            _collect_sequence(fld.fields, _normalize(val), key, nested)
            out.append((fld, _encode_layers(nested)))
        elif fld.base_type == "NULL":
            out.append((fld, b""))
        elif fld.base_type == "INTEGER":
            body = val if isinstance(val, (bytes, bytearray)) else _encode_integer(val)
            out.append((fld, bytes(body)))
        else:
            if not isinstance(val, (bytes, bytearray)):
                raise EncodeError(
                    f"OCTET STRING field {key!r} requires bytes, "
                    f"got {type(val).__name__!r}",
                    code="type_error",
                )
            out.append((fld, bytes(val)))


def _encode_layers(items: list[tuple[Field, bytes]], *, indefinite: bool = False) -> bytes:
    chunks: list[bytes] = []
    for fld, body in items:
        inner_tag = (
            Tag("universal", True, 16)
            if fld.base_type == "SEQUENCE"
            else _universal_tag_for(fld.base_type)
        )
        if fld.mode == "implicit":
            chunks.append(_tlv(fld.wire_tag, body, indefinite=indefinite and fld.base_type == "SEQUENCE"))
        else:
            inner = _tlv(inner_tag, body, indefinite=indefinite and fld.base_type == "SEQUENCE")
            chunks.append(_tlv(fld.wire_tag, inner, indefinite=indefinite))
    return b"".join(chunks)


def encode_record(values: Mapping[str, Any], product: Product) -> bytes:
    """Encode a record from nested mappings or flat dotted field paths.

    Absent keys mark optional fields absent.  ``None`` for a NULL field means
    present-and-null; for other types it means absent.
    """
    items: list[tuple[Field, bytes]] = []
    _collect_sequence(product.fields, _normalize(values), "", items)
    return _tlv(product.root_tag, _encode_layers(items))


def encode_record_indefinite(values: Mapping[str, Any], product: Product) -> bytes:
    """Encode every constructed layer (root, SEQUENCEs, explicit wrappers) with
    indefinite length.  Primitive values stay in definite short/long form."""
    items: list[tuple[Field, bytes]] = []
    _collect_sequence(product.fields, _normalize(values), "", items)
    return _tlv(product.root_tag, _encode_layers(items, indefinite=True), indefinite=True)


def _universal_tag_for(base_type: str) -> Tag:
    from .schema import UNIVERSAL_TAGS

    return UNIVERSAL_TAGS[base_type]


def _tlv(tag: Tag, body: bytes, *, indefinite: bool = False) -> bytes:
    from .ber import encode_length, encode_tag

    ident = encode_tag(tag.cls, tag.constructed, tag.number)
    if indefinite:
        if not tag.constructed:
            raise EncodeError("indefinite encoding requires a constructed tag")
        return ident + b"\x80" + body + b"\x00\x00"
    return ident + encode_length(len(body)) + body
