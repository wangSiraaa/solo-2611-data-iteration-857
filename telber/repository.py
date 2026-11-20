"""SQLite-backed schema product registry and telemetry fact repository.

The registry
------------

A *product* is a compiled schema directory, identified by the SHA-256 of its
canonical JSON.  Publishing a revised schema produces a new product id; an
import is bound to exactly one product id at creation and can never be
rebound.  Re-publishing identical bytes is idempotent; re-using a
``(schema, version)`` pair for different content is rejected, so historical
field meanings can never drift underneath an existing import.

The repository
--------------

An import reads the *actual original byte stream* through
:class:`telber.stream.RecordScanner` and writes, per record:

* ``records`` — ordinal, absolute start/end offset, record status;
* ``fields`` — one row per declared field path (including absent optionals,
  with ``present=0``), its type, presence, null flag, decoded scalar value and
  the absolute offsets of its complete encoding and value body;
* ``field_source_ranges`` — the byte ranges backing the value, role-tagged
  (``wrapper`` for an explicit wrapper, ``body`` for the value octets).

On the first top-level error the import stops.  Records already committed stay
queryable; the import becomes ``partial`` and records the error code, message,
absolute offset and the start offset of the failing record.  A partial import
cannot be published.  The scanner never searches for a later plausible tag to
resume.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Mapping

from .codec import decode_record, encode_record
from .errors import (
    ImportStateError,
    ProductRevisionError,
    TelberError,
)
from .schema import Product, compile_product
from .stream import DEFAULT_BLOCK_SIZE, DEFAULT_MAX_BODY, DEFAULT_MAX_RECORD, RecordScanner

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS products (
    product_id     TEXT PRIMARY KEY,
    schema_name    TEXT NOT NULL,
    version        INTEGER NOT NULL,
    canonical_json TEXT NOT NULL,
    root_tag       TEXT NOT NULL,
    created_at     REAL NOT NULL,
    UNIQUE (schema_name, version)
);

CREATE TABLE IF NOT EXISTS imports (
    import_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id       TEXT NOT NULL REFERENCES products(product_id),
    source_name      TEXT,
    source_size      INTEGER,
    block_size       INTEGER NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('running','partial','complete','failed')),
    created_at       REAL NOT NULL,
    finished_at      REAL,
    record_count     INTEGER NOT NULL DEFAULT 0,
    byte_count       INTEGER NOT NULL DEFAULT 0,
    error_code       TEXT,
    error_message    TEXT,
    error_offset     INTEGER,
    error_record_start INTEGER
);

CREATE TABLE IF NOT EXISTS records (
    record_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id    INTEGER NOT NULL REFERENCES imports(import_id),
    ordinal      INTEGER NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset   INTEGER NOT NULL,
    length       INTEGER NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('complete')),
    UNIQUE (import_id, ordinal)
);

CREATE TABLE IF NOT EXISTS fields (
    field_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id      INTEGER NOT NULL REFERENCES imports(import_id),
    record_id      INTEGER NOT NULL REFERENCES records(record_id),
    parent_field_id INTEGER REFERENCES fields(field_id),
    path           TEXT NOT NULL,
    parent_path    TEXT NOT NULL,
    field_name     TEXT NOT NULL,
    ordinal        INTEGER NOT NULL,
    seq            INTEGER NOT NULL,
    type           TEXT NOT NULL,
    mode           TEXT NOT NULL,
    present        INTEGER NOT NULL CHECK (present IN (0,1)),
    is_null        INTEGER NOT NULL CHECK (is_null IN (0,1)),
    tagged_class   TEXT NOT NULL,
    tag_number     INTEGER NOT NULL,
    int_value      INTEGER,
    bytes_value    BLOB,
    start_offset   INTEGER,
    end_offset     INTEGER,
    body_start     INTEGER,
    body_end       INTEGER,
    UNIQUE (record_id, path)
);

CREATE TABLE IF NOT EXISTS field_source_ranges (
    range_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    field_id   INTEGER NOT NULL REFERENCES fields(field_id),
    import_id  INTEGER NOT NULL REFERENCES imports(import_id),
    record_id  INTEGER NOT NULL REFERENCES records(record_id),
    seq        INTEGER NOT NULL,
    role       TEXT NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_records_import ON records(import_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_fields_record ON fields(record_id);
CREATE INDEX IF NOT EXISTS idx_fields_path ON fields(import_id, path);
CREATE INDEX IF NOT EXISTS idx_ranges_record ON field_source_ranges(record_id, seq);

CREATE VIEW IF NOT EXISTS field_relation AS
SELECT
    f.import_id,
    r.ordinal     AS record_ordinal,
    r.start_offset AS record_start,
    f.path,
    f.type,
    f.mode,
    f.present,
    f.is_null,
    f.int_value,
    f.bytes_value,
    f.start_offset,
    f.end_offset,
    f.body_start,
    f.body_end
FROM fields f JOIN records r ON r.record_id = f.record_id;
"""


def _connect(db_path: str | os.PathLike[str]) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA_SQL)
    return conn


def _root_tag_text(product: Product) -> str:
    return json.dumps(product.root_tag.as_dict(), sort_keys=True)


@dataclass(frozen=True)
class ImportInfo:
    import_id: int
    product_id: str
    status: str
    record_count: int
    byte_count: int
    error_code: str | None
    error_offset: int | None
    error_record_start: int | None

    def as_dict(self) -> dict:
        return {
            "import_id": self.import_id,
            "product_id": self.product_id,
            "status": self.status,
            "record_count": self.record_count,
            "byte_count": self.byte_count,
            "error_code": self.error_code,
            "error_offset": self.error_offset,
            "error_record_start": self.error_record_start,
        }


class Repository:
    """Schema product registry plus import fact repository."""

    def __init__(self, db_path: str | os.PathLike[str] = ":memory:") -> None:
        self.db_path = db_path
        self.conn = _connect(db_path)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Repository":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- products ---------------------------------------------------------
    def publish_product(self, schema: Mapping[str, Any] | str | bytes) -> Product:
        product = compile_product(schema)
        row = self.conn.execute(
            "SELECT product_id, canonical_json FROM products "
            "WHERE schema_name = ? AND version = ?",
            (product.schema_name, product.version),
        ).fetchone()
        if row is not None:
            if row["product_id"] == product.product_id:
                return product  # idempotent republish of identical content
            raise ProductRevisionError(
                f"product {product.schema_name!r} version {product.version} already "
                f"exists with different content ({row['product_id'][:12]}...); "
                "bump the schema version to revise it",
                code="product_revision_conflict",
            )
        self.conn.execute(
            "INSERT INTO products(product_id, schema_name, version, canonical_json, "
            "root_tag, created_at) VALUES (?,?,?,?,?,?)",
            (
                product.product_id,
                product.schema_name,
                product.version,
                product.canonical_json,
                _root_tag_text(product),
                time.time(),
            ),
        )
        self.conn.commit()
        return product

    def get_product(self, product_id: str) -> Product:
        row = self.conn.execute(
            "SELECT canonical_json FROM products WHERE product_id = ?", (product_id,)
        ).fetchone()
        if row is None:
            raise TelberError(
                f"unknown product id {product_id!r}", code="unknown_product"
            )
        return compile_product(row["canonical_json"])

    def list_products(self) -> list[dict]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT product_id, schema_name, version, root_tag, created_at "
                "FROM products ORDER BY schema_name, version"
            )
        ]

    # -- imports ----------------------------------------------------------
    def create_import(
        self,
        product: Product | str,
        *,
        source_name: str | None = None,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> int:
        product_id = product if isinstance(product, str) else product.product_id
        # Validate that the product is actually registered; refusing here makes
        # "bind an import to a known product" an explicit precondition.
        exists = self.conn.execute(
            "SELECT 1 FROM products WHERE product_id = ?", (product_id,)
        ).fetchone()
        if exists is None:
            raise TelberError(
                f"cannot bind import to unknown product {product_id!r}; "
                "publish the schema product first",
                code="unknown_product",
            )
        cur = self.conn.execute(
            "INSERT INTO imports(product_id, source_name, block_size, status, created_at) "
            "VALUES (?,?,?,?,?)",
            (product_id, source_name, block_size, "running", time.time()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def ingest_stream(
        self,
        import_id: int,
        fp: BinaryIO,
        *,
        source_size: int | None = None,
        block_size: int | None = None,
        max_record: int = DEFAULT_MAX_RECORD,
        max_body: int = DEFAULT_MAX_BODY,
    ) -> ImportInfo:
        row = self._import_row(import_id)
        if row["status"] != "running":
            raise ImportStateError(
                f"import {import_id} is {row['status']}, not running",
                code="import_not_running",
            )
        product = self.get_product(row["product_id"])
        bs = block_size if block_size is not None else row["block_size"]
        if bs != row["block_size"]:
            self.conn.execute(
                "UPDATE imports SET block_size = ? WHERE import_id = ?", (bs, import_id)
            )
            self.conn.commit()
        if source_size is not None:
            self.conn.execute(
                "UPDATE imports SET source_size = ? WHERE import_id = ?",
                (source_size, import_id),
            )
            self.conn.commit()

        scanner = RecordScanner(
            fp, product, block_size=bs, max_record=max_record, max_body=max_body
        )
        ordinal = 0
        byte_count = 0
        current_start = 0
        try:
            for stream_record in scanner.records():
                current_start = stream_record.start
                try:
                    record = decode_record(stream_record.data, product, base=stream_record.start)
                except TelberError as exc:
                    exc.with_record_start(stream_record.start)
                    raise
                self._store_record(import_id, ordinal, stream_record.start, record, product)
                ordinal += 1
                byte_count += len(stream_record.data)
                # Commit each complete record so a later failure leaves exactly
                # the verified prefix behind.
                self.conn.commit()
        except TelberError as exc:
            # Drop the failed record's pending inserts; every earlier record was
            # committed individually, so the completed prefix survives.
            self.conn.rollback()
            if exc.record_start is None:
                exc.with_record_start(current_start)
            completed = self.conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(length), 0) AS total "
                "FROM records WHERE import_id = ?",
                (import_id,),
            ).fetchone()
            record_count = int(completed["n"])
            byte_count = int(completed["total"])
            self.conn.execute(
                "UPDATE imports SET status='partial', finished_at=?, error_code=?, "
                "error_message=?, error_offset=?, error_record_start=?, "
                "record_count=?, byte_count=? WHERE import_id=?",
                (
                    time.time(),
                    exc.code,
                    exc.message,
                    exc.offset,
                    exc.record_start,
                    record_count,
                    byte_count,
                    import_id,
                ),
            )
            self.conn.commit()
            info = self._info(import_id)
            raise _IngestFailure(info, exc) from exc
        except BaseException:
            self.conn.rollback()
            raise

        self.conn.execute(
            "UPDATE imports SET status='complete', finished_at=?, record_count=?, "
            "byte_count=? WHERE import_id=?",
            (time.time(), ordinal, byte_count, import_id),
        )
        self.conn.commit()
        return self._info(import_id)

    def ingest_bytes(
        self, import_id: int, data: bytes, *, block_size: int | None = None, **kwargs
    ) -> ImportInfo:
        import io

        return self.ingest_stream(
            import_id,
            io.BytesIO(data),
            source_size=len(data),
            block_size=block_size,
            **kwargs,
        )

    def ingest_file(
        self,
        import_id: int,
        path: str | os.PathLike[str],
        *,
        block_size: int | None = None,
        **kwargs,
    ) -> ImportInfo:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            return self.ingest_stream(
                import_id, fh, source_size=size, block_size=block_size, **kwargs
            )

    def _import_row(self, import_id: int) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM imports WHERE import_id = ?", (import_id,)
        ).fetchone()
        if row is None:
            raise TelberError(f"unknown import {import_id!r}", code="unknown_import")
        return row

    def _info(self, import_id: int) -> ImportInfo:
        r = self._import_row(import_id)
        return ImportInfo(
            import_id=r["import_id"],
            product_id=r["product_id"],
            status=r["status"],
            record_count=r["record_count"],
            byte_count=r["byte_count"],
            error_code=r["error_code"],
            error_offset=r["error_offset"],
            error_record_start=r["error_record_start"],
        )

    def import_info(self, import_id: int) -> ImportInfo:
        return self._info(import_id)

    def publish_import(self, import_id: int) -> ImportInfo:
        info = self._info(import_id)
        if info.status != "complete":
            raise ImportStateError(
                f"import {import_id} is {info.status}; only a complete import can be "
                "published as whole-stream complete",
                code="import_not_complete",
            )
        return info

    def _store_field(
        self,
        *,
        import_id: int,
        record_id: int,
        parent_id: int | None,
        fld,
        value,
        seq: int,
    ) -> int:
        present = value is not None
        cur = self.conn.execute(
            "INSERT INTO fields(import_id, record_id, parent_field_id, path, parent_path, "
            "field_name, ordinal, seq, type, mode, present, is_null, tagged_class, "
            "tag_number, int_value, bytes_value, start_offset, end_offset, body_start, "
            "body_end) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                import_id,
                record_id,
                parent_id,
                fld.path,
                fld.path.rsplit(".", 1)[0] if "." in fld.path else "",
                fld.name,
                fld.ordinal,
                seq,
                fld.base_type,
                fld.mode,
                1 if present else 0,
                1 if (present and value.null) else 0,
                fld.class_name,
                fld.number,
                value.value if (present and fld.base_type == "INTEGER") else None,
                value.value if (present and fld.base_type == "OCTET STRING") else None,
                value.start if present else None,
                value.end if present else None,
                # NULL and SEQUENCE have no scalar value octets: their body
                # range is not a byte range of interest, so it is left NULL.
                None
                if (not present or fld.base_type in ("NULL", "SEQUENCE"))
                else value.body_start,
                None
                if (not present or fld.base_type in ("NULL", "SEQUENCE"))
                else value.body_end,
            ),
        )
        field_id = int(cur.lastrowid)
        if present:
            for range_seq, (role, rs, re_) in enumerate(value.source_ranges):
                self.conn.execute(
                    "INSERT INTO field_source_ranges(field_id, import_id, record_id, "
                    "seq, role, start_offset, end_offset) VALUES (?,?,?,?,?,?,?)",
                    (field_id, import_id, record_id, range_seq, role, rs, re_),
                )
        return field_id

    def _store_record(
        self, import_id: int, ordinal: int, start: int, record, product: Product
    ) -> None:
        end = record.end
        cur = self.conn.execute(
            "INSERT INTO records(import_id, ordinal, start_offset, end_offset, length, status) "
            "VALUES (?,?,?,?,?, 'complete')",
            (import_id, ordinal, start, end, end - start),
        )
        record_id = int(cur.lastrowid)
        decoded = record.value_map()

        def emit(fields: tuple, parent_id: int | None) -> None:
            for seq, fld in enumerate(fields):
                v = decoded.get(fld.path)
                field_id = self._store_field(
                    import_id=import_id,
                    record_id=record_id,
                    parent_id=parent_id,
                    fld=fld,
                    value=v,
                    seq=seq,
                )
                emit(fld.fields, field_id)

        emit(product.fields, None)

    # -- queries ----------------------------------------------------------
    def records(self, import_id: int) -> list[dict]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT record_id, ordinal, start_offset, end_offset, length, status "
                "FROM records WHERE import_id = ? ORDER BY ordinal",
                (import_id,),
            )
        ]

    def relation_rows(
        self, import_id: int, *, present_only: bool = False
    ) -> list[dict]:
        sql = (
            "SELECT record_ordinal, record_start, path, type, mode, present, is_null, "
            "int_value, bytes_value, start_offset, end_offset, body_start, body_end "
            "FROM field_relation WHERE import_id = ?"
        )
        params: list[Any] = [import_id]
        if present_only:
            sql += " AND present = 1"
        sql += " ORDER BY record_ordinal, path"
        out = []
        for r in self.conn.execute(sql, params):
            d = dict(r)
            if d["bytes_value"] is not None:
                d["bytes_value"] = bytes(d["bytes_value"])
            out.append(d)
        return out

    def source_ranges(
        self, import_id: int, record_ordinal: int | None = None
    ) -> list[dict]:
        sql = (
            "SELECT r.ordinal AS record_ordinal, f.path, s.seq, s.role, "
            "s.start_offset, s.end_offset "
            "FROM field_source_ranges s "
            "JOIN fields f ON f.field_id = s.field_id "
            "JOIN records r ON r.record_id = s.record_id "
            "WHERE s.import_id = ?"
        )
        params: list[Any] = [import_id]
        if record_ordinal is not None:
            sql += " AND r.ordinal = ?"
            params.append(record_ordinal)
        sql += " ORDER BY r.ordinal, f.path, s.seq"
        return [dict(r) for r in self.conn.execute(sql, params)]

    def field_presence(self, import_id: int) -> dict[int, dict[str, bool]]:
        out: dict[int, dict[str, bool]] = {}
        for r in self.conn.execute(
            "SELECT r.ordinal, f.path, f.present FROM fields f "
            "JOIN records r ON r.record_id = f.record_id "
            "WHERE f.import_id = ?",
            (import_id,),
        ):
            out.setdefault(r["ordinal"], {})[r["path"]] = bool(r["present"])
        return out

    # -- convenience ------------------------------------------------------
    def schema_product_for(self, schema: Mapping[str, Any] | str | bytes) -> Product:
        return self.publish_product(schema)

    def encode(self, product_id: str, values: Mapping[str, Any]) -> bytes:
        return encode_record(values, self.get_product(product_id))


class _IngestFailure(TelberError):
    """Raised by :meth:`Repository.ingest_stream` after recording a partial import.

    The partial prefix remains committed and queryable; ``info`` describes the
    stopped import and the original error is available as ``__cause__``.
    """

    code = "ingest_partial"

    def __init__(self, info: ImportInfo, cause: TelberError) -> None:
        super().__init__(
            cause.message,
            offset=cause.offset,
            record_start=cause.record_start,
            code=cause.code,
        )
        self.info = info
        self.cause = cause

    def as_dict(self) -> dict:
        d = super().as_dict()
        d["import"] = self.info.as_dict()
        return d
