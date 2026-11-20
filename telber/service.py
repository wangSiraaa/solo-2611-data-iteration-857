"""The compile service: schema products, record checking and encoding.

This module is the public seam between the "compiler" and the "ingestion
repository".  It has no database dependency, so it can be run (and its
artifacts published) independently of any import.

A :class:`SchemaProduct` is a compiled, immutable directory.  ``artifact()``
emits the canonical JSON product descriptor (the published schema product);
:func:`load_artifact` restores it.  Products are content-addressed, so a
revision is always a *new* product with a new id; existing imports keep their
own compiled product untouched.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .codec import Record, decode_record, encode_record
from .errors import TelberError
from .schema import Product, compile_product


@dataclass(frozen=True)
class CheckResult:
    """Result of checking a given legal record against a product."""

    record: Record
    fields: dict[str, dict]
    integers: dict[str, int]
    octets: dict[str, bytes]
    nulls: dict[str, bool]
    presence: dict[str, bool]

    def as_dict(self) -> dict:
        out = {}
        for path, value in self.record.value_map().items():
            out[path] = {
                "type": value.type,
                "present": value.present,
                "null": value.null,
                "value": (
                    value.value.hex()
                    if isinstance(value.value, (bytes, bytearray))
                    else value.value
                ),
                "start": value.start,
                "end": value.end,
                "source_ranges": [list(r) for r in value.source_ranges],
            }
        return {
            "record": {"start": self.record.start, "end": self.record.end},
            "fields": out,
        }


class CompileService:
    """Stateless facade over the compiled-directory implementation."""

    def compile(self, schema: Mapping[str, Any] | str | bytes) -> Product:
        return compile_product(schema)

    # -- publish ----------------------------------------------------------
    def artifact(self, product: Product) -> str:
        """Canonical published product descriptor."""
        return json.dumps(product.as_dict(), sort_keys=True, indent=2) + "\n"

    def load_artifact(self, text: str | bytes) -> Product:
        """Rebuild the compiled product from a published artifact.

        The artifact embeds the canonical source schema; this validates the
        artifact was not edited (the digest must still match).
        """
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TelberError(f"artifact is not valid JSON: {exc}", code="invalid_artifact") from exc
        if not isinstance(obj, dict) or "product_id" not in obj:
            raise TelberError("artifact is missing product_id", code="invalid_artifact")
        schema = obj.get("schema_document")
        if not isinstance(schema, dict):
            raise TelberError(
                "artifact is missing its schema_document", code="invalid_artifact"
            )
        product = compile_product(schema)
        if product.product_id != obj["product_id"]:
            raise TelberError(
                "artifact content does not match its product id; the descriptor "
                "was edited after compilation",
                code="artifact_digest_mismatch",
            )
        return product

    # -- check / encode ----------------------------------------------------
    def decode(self, product: Product, data: bytes, *, base: int = 0) -> Record:
        return decode_record(data, product, base=base)

    def check(self, product: Product, data: bytes, *, base: int = 0) -> CheckResult:
        record = decode_record(data, product, base=base)
        integers: dict[str, int] = {}
        octets: dict[str, bytes] = {}
        nulls: dict[str, bool] = {}
        presence: dict[str, bool] = {}
        for path, value in record.value_map().items():
            presence[path] = True
            if value.type == "INTEGER":
                integers[path] = value.value
            elif value.type == "OCTET STRING":
                octets[path] = value.value
            elif value.type == "NULL":
                nulls[path] = True
        return CheckResult(
            record=record,
            fields=record.value_map(),
            integers=integers,
            octets=octets,
            nulls=nulls,
            presence=presence,
        )

    def encode(self, product: Product, values: Mapping[str, Any]) -> bytes:
        return encode_record(values, product)

    def encode_indefinite(self, product: Product, values: Mapping[str, Any]) -> bytes:
        from .codec import encode_record_indefinite

        return encode_record_indefinite(values, product)

    def roundtrip(self, product: Product, values: Mapping[str, Any]) -> CheckResult:
        """Encode and re-check.  The decoded record must preserve presence and
        INTEGER / OCTET STRING / NULL typing."""
        data = encode_record(values, product)
        return self.check(product, data)
