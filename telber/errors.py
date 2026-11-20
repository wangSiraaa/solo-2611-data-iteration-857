"""Error types shared by the BER subset codec and the ingestion repository.

Every wire-level error carries the absolute byte offset at which the problem was
detected.  The repository additionally records the start offset of the
top-level record being parsed.  There is deliberately no resynchronisation
machinery: the caller stops at the first error.
"""

from __future__ import annotations


class TelberError(Exception):
    """Base class for all errors raised by this package."""

    code = "telber_error"

    def __init__(
        self,
        message: str,
        *,
        offset: int | None = None,
        record_start: int | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.offset = offset
        self.record_start = record_start
        if code is not None:
            self.code = code

    def with_record_start(self, record_start: int) -> "TelberError":
        if self.record_start is None:
            self.record_start = record_start
        return self

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        where = ""
        if self.offset is not None:
            where += f" at offset {self.offset}"
        if self.record_start is not None:
            where += f" (record starts at {self.record_start})"
        return f"{self.code}{where}: {self.message}"

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "offset": self.offset,
            "record_start": self.record_start,
        }


class BerError(TelberError):
    """Malformed or non-minimal BER-subset encoding."""

    code = "ber_error"


class TruncatedError(BerError):
    """The stream ended before a complete value was available."""

    code = "truncated"


class DecodeError(TelberError):
    """A syntactically valid TLV does not match the compiled schema."""

    code = "decode_error"


class SchemaError(TelberError):
    """The JSON schema cannot be compiled into a deterministic directory."""

    code = "schema_error"


class EncodeError(TelberError):
    """An input record cannot be encoded with the compiled schema."""

    code = "encode_error"


class ProductRevisionError(TelberError):
    """A published product revision would change immutable history."""

    code = "product_revision_error"


class ImportStateError(TelberError):
    """An import cannot be mutated in the requested way."""

    code = "import_state_error"
