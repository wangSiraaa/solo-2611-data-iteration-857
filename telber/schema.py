"""Compile the JSON record directory into an immutable matching product.

Schema shape (a deliberately small subset of ASN.1):

.. code-block:: json

    {
      "schema": "telemetry.record",
      "version": 3,
      "root": {
        "name": "TelemetryRecord",
        "tag": {"class": "universal", "number": 16},
        "type": "SEQUENCE",
        "fields": [
          {"name": "id",   "tag": {"class": "context", "number": 0},
           "mode": "implicit", "type": "INTEGER"},
          {"name": "note", "tag": {"class": "context", "number": 1},
           "mode": "explicit", "type": "OCTET STRING", "optional": true},
          {"name": "sub",  "tag": {"class": "application", "number": 7},
           "mode": "implicit", "type": "SEQUENCE", "fields": [ ... ]}
        ]
      }
    }

The root is a constructed value whose body is a SEQUENCE of fields.  A field
declares an ordered name, a tag class/number, an explicit-vs-implicit mode, a
base type and whether it is optional.  ``constructed`` is *derived* from the
mode and base type, never supplied, so the same tag can never be quietly
interpreted both ways.

Compilation is strict:

* unknown keys are rejected (catches typos that would otherwise silently
  change the meaning of a product),
* tags are unique within a SEQUENCE and optional runs are checked for
  non-deterministic same-tag matches,
* nesting is bounded, and every field is turned into a pre-computed wire tag
  and (for explicit fields) the expected inner universal tag.

The result is immutable and content-addressed; publishing a revised schema
creates a different product and therefore a different import.  Existing
imports keep the product they were bound to.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .ber import (
    CLASS_CODES,
    MAX_TAG_NUMBER,
    Tag,
    UNIVERSAL_INTEGER,
    UNIVERSAL_NULL,
    UNIVERSAL_OCTET_STRING,
    UNIVERSAL_SEQUENCE,
)
from .errors import SchemaError

BASE_TYPES = ("INTEGER", "OCTET STRING", "NULL", "SEQUENCE")
MODES = ("explicit", "implicit")
MAX_DEPTH = 64
MAX_FIELDS_PER_SEQUENCE = 4096

UNIVERSAL_TAGS = {
    "INTEGER": Tag("universal", False, UNIVERSAL_INTEGER),
    "OCTET STRING": Tag("universal", False, UNIVERSAL_OCTET_STRING),
    "NULL": Tag("universal", False, UNIVERSAL_NULL),
    "SEQUENCE": Tag("universal", True, UNIVERSAL_SEQUENCE),
}

_SCHEMA_KEYS = {"schema", "version", "root", "description"}
_ROOT_KEYS = {"name", "tag", "type", "fields", "description"}
_FIELD_KEYS = {"name", "tag", "mode", "type", "optional", "fields", "description"}
_TAG_KEYS = {"class", "number"}


@dataclass(frozen=True)
class Field:
    """A compiled field with a pre-computed wire tag."""

    ordinal: int
    name: str
    path: str
    depth: int
    class_name: str
    number: int
    mode: str
    base_type: str
    optional: bool
    wire_tag: Tag
    inner_tag: Tag | None
    fields: tuple["Field", ...] = ()

    def as_dict(self) -> dict:
        out = {
            "ordinal": self.ordinal,
            "name": self.name,
            "path": self.path,
            "depth": self.depth,
            "tag": {"class": self.class_name, "number": self.number},
            "mode": self.mode,
            "type": self.base_type,
            "optional": self.optional,
            "wire_tag": self.wire_tag.as_dict(),
        }
        if self.fields:
            out["fields"] = [f.as_dict() for f in self.fields]
        return out


@dataclass(frozen=True)
class Product:
    schema_name: str
    version: int
    canonical_json: str
    digest: str
    root_name: str
    root_tag: Tag
    fields: tuple[Field, ...]

    @property
    def product_id(self) -> str:
        return self.digest

    def schema_dict(self) -> dict:
        return json.loads(self.canonical_json)

    def field_paths(self) -> list[str]:
        out: list[str] = []

        def walk(fields: Iterable[Field]) -> None:
            for f in fields:
                out.append(f.path)
                if f.fields:
                    walk(f.fields)

        walk(self.fields)
        return out

    def flattened_fields(self) -> list[Field]:
        out: list[Field] = []

        def walk(fields: Iterable[Field]) -> None:
            for f in fields:
                out.append(f)
                if f.fields:
                    walk(f.fields)

        walk(self.fields)
        return out

    def match_table(self) -> dict[str, list[dict]]:
        """The compiled prediction table.

        For every SEQUENCE scope (root and every nested SEQUENCE) this lists,
        in declaration order, the pre-computed wire tag, the mode and whether the
        field is optional.  Decoding is driven by these entries: an optional is
        present iff the next header's tag equals its ``wire_tag``; a nested
        SEQUENCE's body boundary comes from its own length (or its EOC); and a
        mismatch reports the next required entry's ``wire_tag`` at the child's
        absolute offset.
        """
        table: dict[str, list[dict]] = {}

        def walk(fields: tuple[Field, ...], path: str, depth: int) -> None:
            entries = []
            for f in fields:
                entries.append(
                    {
                        "ordinal": f.ordinal,
                        "name": f.name,
                        "wire_tag": [
                            f.wire_tag.cls,
                            f.wire_tag.constructed,
                            f.wire_tag.number,
                        ],
                        "mode": f.mode,
                        "type": f.base_type,
                        "optional": f.optional,
                        "inner_tag": (
                            None
                            if f.inner_tag is None
                            else [f.inner_tag.cls, f.inner_tag.constructed, f.inner_tag.number]
                        ),
                    }
                )
            key = path or "$root"
            table[key] = entries
            for f in fields:
                if f.fields:
                    walk(f.fields, f.path, depth + 1)

        walk(self.fields, "", 0)
        return table

    def as_dict(self) -> dict:
        return {
            "product_id": self.product_id,
            "schema": self.schema_name,
            "version": self.version,
            # The canonical source schema is embedded so the artifact can be
            # recompiled verbatim; the digest pins both together.
            "schema_document": json.loads(self.canonical_json),
            "root": {
                "name": self.root_name,
                "tag": {"class": self.root_tag.cls, "number": self.root_tag.number},
                "type": "SEQUENCE",
                "fields": [f.as_dict() for f in self.fields],
            },
        }


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _check_keys(obj: Mapping[str, Any], allowed: set[str], where: str) -> None:
    """Reject unknown keys; required keys are checked separately for clarity."""
    unknown = sorted(set(obj) - allowed - {"description"})
    if unknown:
        raise SchemaError(
            f"{where}: unknown key(s) {', '.join(unknown)}",
            code="unknown_schema_key",
        )


def _parse_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise SchemaError(f"{where} must be a boolean", code="invalid_schema")
    return value


def _parse_tag(obj: Any, where: str) -> tuple[str, int]:
    if not isinstance(obj, dict):
        raise SchemaError(f"{where} must be an object with class/number", code="invalid_schema")
    unknown = sorted(set(obj) - _TAG_KEYS)
    if unknown:
        raise SchemaError(
            f"{where}: unknown tag key(s) {', '.join(unknown)}; "
            "constructed is derived from mode/type",
            code="unknown_schema_key",
        )
    cls = obj.get("class")
    number = obj.get("number")
    if cls not in CLASS_CODES:
        raise SchemaError(
            f"{where}.class must be one of {', '.join(CLASS_CODES)}",
            code="bad_tag_class",
        )
    if isinstance(number, bool) or not isinstance(number, int):
        raise SchemaError(f"{where}.number must be an integer", code="bad_tag_number")
    if number < 0 or number > MAX_TAG_NUMBER:
        raise SchemaError(
            f"{where}.number must be between 0 and {MAX_TAG_NUMBER}",
            code="bad_tag_number",
        )
    return cls, number


def _compile_fields(
    raw_fields: Any,
    *,
    parent_path: str,
    depth: int,
    sibling_names: set[str],
) -> tuple[Field, ...]:
    if not isinstance(raw_fields, list):
        raise SchemaError(f"{parent_path or 'root'}.fields must be an array", code="invalid_schema")
    if len(raw_fields) > MAX_FIELDS_PER_SEQUENCE:
        raise SchemaError(
            f"{parent_path or 'root'}: {len(raw_fields)} fields exceeds "
            f"the supported maximum {MAX_FIELDS_PER_SEQUENCE}",
            code="too_many_fields",
        )
    compiled: list[Field] = []
    for ordinal, raw in enumerate(raw_fields):
        where = f"{parent_path or 'root'}.fields[{ordinal}]"
        if not isinstance(raw, dict):
            raise SchemaError(f"{where} must be an object", code="invalid_schema")
        _check_keys(raw, _FIELD_KEYS, where)
        for required_key in ("name", "tag", "mode", "type"):
            if required_key not in raw:
                raise SchemaError(f"{where}: missing required key {required_key!r}", code="invalid_schema")
        name = raw["name"]
        if not isinstance(name, str) or not name:
            raise SchemaError(f"{where}.name must be a non-empty string", code="invalid_schema")
        if name in sibling_names:
            raise SchemaError(
                f"{where}: duplicate field name {name!r} within one SEQUENCE",
                code="duplicate_field_name",
            )
        sibling_names.add(name)
        mode = raw["mode"]
        if mode not in MODES:
            raise SchemaError(f"{where}.mode must be 'explicit' or 'implicit'", code="invalid_schema")
        base_type = raw["type"]
        if base_type not in BASE_TYPES:
            raise SchemaError(
                f"{where}.type must be one of {', '.join(BASE_TYPES)}",
                code="invalid_schema",
            )
        optional = _parse_bool(raw.get("optional", False), f"{where}.optional")
        cls, number = _parse_tag(raw["tag"], f"{where}.tag")
        path = f"{parent_path}.{name}" if parent_path else name

        nested: tuple[Field, ...] = ()
        if base_type == "SEQUENCE":
            if "fields" not in raw:
                raise SchemaError(
                    f"{where}: a SEQUENCE field must declare its fields",
                    code="invalid_schema",
                )
            if depth + 1 > MAX_DEPTH:
                raise SchemaError(
                    f"{where}: nesting depth exceeds supported maximum {MAX_DEPTH}",
                    code="too_deep",
                )
            nested = _compile_fields(
                raw["fields"],
                parent_path=path,
                depth=depth + 1,
                sibling_names=set(),
            )
        elif "fields" in raw:
            raise SchemaError(
                f"{where}: only SEQUENCE fields may declare nested fields",
                code="invalid_schema",
            )

        # An explicit field carries a constructed wrapper regardless of its base
        # type; an implicit SEQUENCE keeps the constructed bit, everything else
        # stays primitive.
        constructed = base_type == "SEQUENCE" or mode == "explicit"
        wire_tag = Tag(cls, constructed, number)
        inner_tag = UNIVERSAL_TAGS[base_type] if mode == "explicit" else None
        compiled.append(
            Field(
                ordinal=ordinal,
                name=name,
                path=path,
                depth=depth,
                class_name=cls,
                number=number,
                mode=mode,
                base_type=base_type,
                optional=optional,
                wire_tag=wire_tag,
                inner_tag=inner_tag,
                fields=nested,
            )
        )
    _check_ambiguity(compiled, parent_path or "root")
    return tuple(compiled)


def _check_ambiguity(fields: list[Field], where: str) -> None:
    # Any repeated wire tag within one SEQUENCE is undecidable: with optionals
    # the matcher could skip the earlier field and consume the later one in its
    # place (and even without optionals, field identity would be arbitrary).
    # Rejecting all repeats is therefore both the strongest and the simplest
    # rule; a run of adjacent optional fields must carry distinct tags.
    seen: dict[Tag, Field] = {}
    for f in fields:
        previous = seen.get(f.wire_tag)
        if previous is not None:
            if previous.optional or f.optional:
                raise SchemaError(
                    f"{where}: optional fields {previous.path!r} and {f.path!r} "
                    f"share wire tag {f.wire_tag}; presence and identity would be "
                    "undecidable at decode time",
                    code="ambiguous_optionals",
                )
            raise SchemaError(
                f"{where}: fields {previous.path!r} and {f.path!r} share wire tag "
                f"{f.wire_tag}",
                code="duplicate_field_tag",
            )
        seen[f.wire_tag] = f


def compile_product(schema: Mapping[str, Any] | str | bytes) -> Product:
    if isinstance(schema, (str, bytes, bytearray)):
        try:
            schema = json.loads(schema)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"schema is not valid JSON: {exc}", code="invalid_json") from exc
    if not isinstance(schema, dict):
        raise SchemaError("schema must be a JSON object", code="invalid_schema")
    _check_keys(schema, _SCHEMA_KEYS, "schema")
    for key in ("schema", "version", "root"):
        if key not in schema:
            raise SchemaError(f"schema: missing required key {key!r}", code="invalid_schema")
    schema_name = schema["schema"]
    if not isinstance(schema_name, str) or not schema_name:
        raise SchemaError("schema.schema must be a non-empty string", code="invalid_schema")
    version = schema["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise SchemaError("schema.version must be a positive integer", code="invalid_schema")
    root = schema["root"]
    if not isinstance(root, dict):
        raise SchemaError("schema.root must be an object", code="invalid_schema")
    _check_keys(root, _ROOT_KEYS, "schema.root")
    for key in ("name", "tag", "type", "fields"):
        if key not in root:
            raise SchemaError(f"schema.root: missing required key {key!r}", code="invalid_schema")
    root_name = root["name"]
    if not isinstance(root_name, str) or not root_name:
        raise SchemaError("schema.root.name must be a non-empty string", code="invalid_schema")
    if root["type"] != "SEQUENCE":
        raise SchemaError("schema.root.type must be 'SEQUENCE'", code="invalid_schema")
    cls, number = _parse_tag(root["tag"], "schema.root.tag")
    root_tag = Tag(cls, True, number)
    fields = _compile_fields(
        root["fields"],
        parent_path="",
        depth=0,
        sibling_names=set(),
    )

    canonical = canonical_json(schema)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return Product(
        schema_name=schema_name,
        version=version,
        canonical_json=canonical,
        digest=digest,
        root_name=root_name,
        root_tag=root_tag,
        fields=fields,
    )


def load_product(path: str) -> Product:
    with open(path, "r", encoding="utf-8") as fh:
        return compile_product(fh.read())
