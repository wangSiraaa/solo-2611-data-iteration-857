"""Independent byte-level builder for test fixtures and the demo source.

This module deliberately shares *no* code with :mod:`telber.ber`: it builds TLV
octets by hand so the library decoder is validated against an independent
implementation, not against itself.
"""

from __future__ import annotations

from typing import Iterable


def _tag_octets(cls: str, constructed: bool, number: int) -> bytes:
    cls_bits = {"universal": 0, "application": 1, "context": 2, "private": 3}[cls]
    first = (cls_bits << 6) | (0x20 if constructed else 0)
    if number < 31:
        return bytes([first | number])
    groups = []
    n = number
    while n:
        groups.append(n & 0x7F)
        n >>= 7
    groups.reverse()
    out = bytearray([first | 0x1F])
    for g in groups:
        out.append(g)
    out[-1] &= 0x7F
    for i in range(len(out) - 2, 0, -1):
        out[i] |= 0x80
    return bytes(out)


def _len_octets(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: bytes, body: bytes, *, indefinite: bool = False) -> bytes:
    if indefinite:
        return tag + b"\x80" + body + b"\x00\x00"
    return tag + _len_octets(len(body)) + body


def tag(cls: str, constructed: bool, number: int) -> bytes:
    return _tag_octets(cls, constructed, number)


def seq(body: bytes, *, indefinite: bool = False, cls: str = "universal", number: int = 16) -> bytes:
    return tlv(tag(cls, True, number), body, indefinite=indefinite)


def int_body(value: int) -> bytes:
    """Minimal two's-complement big-endian INTEGER body."""
    if value == 0:
        return b"\x00"
    if value > 0:
        out = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return b"\x00" + out if out[0] & 0x80 else out
    width = 1
    while not (-(1 << (8 * width - 1)) <= value < (1 << (8 * width - 1))):
        width += 1
    out = value.to_bytes(width, "big", signed=True)
    if width > 1 and out[0] == 0xFF and out[1] & 0x80:
        out = out[1:]
    return out


def integer(value: int, *, cls: str = "universal", number: int = 2) -> bytes:
    return tlv(_tag_octets(cls, False, number), int_body(value))


def octets(value: bytes, *, cls: str = "universal", number: int = 4) -> bytes:
    return tlv(_tag_octets(cls, False, number), value)


def null(*, cls: str = "universal", number: int = 5) -> bytes:
    return _tag_octets(cls, False, number) + b"\x00"


def raw_tlv(identifier: bytes, body: bytes, *, indefinite: bool = False) -> bytes:
    return tlv(identifier, body, indefinite=indefinite)


def explicit(outer: bytes, inner: bytes, *, indefinite: bool = False) -> bytes:
    return tlv(outer, inner, indefinite=indefinite)


def concat(parts: Iterable[bytes]) -> bytes:
    return b"".join(parts)
