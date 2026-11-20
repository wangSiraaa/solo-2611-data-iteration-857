"""telber — a bounded BER-subset type directory, codec and telemetry repository.

Modules
-------
``ber``         tag/length wire primitives with minimal-encoding enforcement
``schema``      JSON schema directory compiler (immutable, content-addressed product)
``codec``       record decoder/encoder with absolute byte provenance
``stream``      bounded streaming record delimitation over the original octets
``repository``  SQLite product registry + per-record field/relation fact store
``errors``      error hierarchy carrying absolute offsets

See ``README.md`` for the exact supported encoding subset and the design rules.
"""

from .ber import Tag
from .codec import Record, Value, decode_record, encode_record, encode_record_indefinite
from .errors import (
    BerError,
    DecodeError,
    EncodeError,
    ImportStateError,
    ProductRevisionError,
    SchemaError,
    TelberError,
    TruncatedError,
)
from .repository import ImportInfo, Repository
from .schema import Field, Product, compile_product
from .stream import RecordScanner, StreamRecord, scan_records

__all__ = [
    "Tag",
    "Field",
    "Product",
    "compile_product",
    "Record",
    "Value",
    "decode_record",
    "encode_record",
    "encode_record_indefinite",
    "RecordScanner",
    "StreamRecord",
    "scan_records",
    "Repository",
    "ImportInfo",
    "TelberError",
    "BerError",
    "TruncatedError",
    "DecodeError",
    "SchemaError",
    "EncodeError",
    "ProductRevisionError",
    "ImportStateError",
]
