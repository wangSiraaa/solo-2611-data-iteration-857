# telber — BER-subset telemetry directory, codec and fact repository

A Python 3.11 implementation of a *finite* BER-style type directory and
telemetry fact repository. This is a deliberately bounded subset, not a
general ASN.1 toolkit.

The motivating failures this fixes:

* **`00 00` inside a primitive body is data, not end-of-message.** The earlier
  ingestion treated every `00 00` as a record terminator and truncated legal
  binary fields. Here `00 00` terminates only an indefinite-length constructed
  layer, and only when it sits at that layer's child boundary.
* **Long tags and implicit tags were mapped to the wrong field.** Tags are
  decoded with class + constructed bit + base-128 number, and the schema
  compiler pre-computes each field's exact wire tag (including the constructed
  bit that explicit wrapping adds), so a long tag or an implicit tag can never
  be silently matched to the wrong field.

## Supported wire subset

* **Identifier octets**: class (`universal`/`application`/`context`/`private`),
  constructed bit, tag number in short form (`0..30`) and base-128 long form
  (`31..2^63-1`). Long-form tags must be minimal: no leading `0x80` padding and
  no long form for a number that fits the short form.
* **Length octets**: short form (`0..127`), long form with 1..4 octets, and
  indefinite form `0x80` for constructed values only. Long-form lengths must be
  minimal (no leading zero, short form used whenever it fits).
* **Base types**: `INTEGER` (shortest two's-complement big-endian body),
  `OCTET STRING`, `NULL` (length must be 0), and `SEQUENCE`.
* **End-of-contents**: `00 00` closes an indefinite constructed layer only. A
  definite-length layer is bounded by its declared length and is never ended
  early by `00 00`; bytes inside a primitive body are never inspected for EOC.
* Records are a stream of consecutive top-level TLVs; each record is decoded
  whole, and trailing bytes after a record are an error rather than silently
  folded into the next record.

Anything outside this subset (other universal types, indefinite primitive
strings, non-minimal encodings) is rejected with an absolute byte offset.

## Schema directory

The directory is JSON with a small, strict shape (`schemas/telemetry_v1.json`):

```json
{
  "schema": "telemetry.record",
  "version": 1,
  "root": {
    "name": "TelemetryRecord",
    "tag": {"class": "universal", "number": 16},
    "type": "SEQUENCE",
    "fields": [
      {"name": "station_id", "tag": {"class": "context", "number": 0},
       "mode": "implicit", "type": "INTEGER"},
      {"name": "note", "tag": {"class": "context", "number": 2},
       "mode": "explicit", "type": "NULL", "optional": true},
      {"name": "sensor", "tag": {"class": "application", "number": 1000},
       "mode": "implicit", "type": "SEQUENCE", "fields": [ ... ]}
    ]
  }
}
```

Each field declares an ordered name, a tag class/number, `explicit` or
`implicit`, a base type and `optional`. `constructed` is **derived**, never
declared: an explicit field is always a constructed wrapper; an implicit
`SEQUENCE` keeps the constructed bit; all other implicit fields are primitive.
This removes the class of bug where the same tag is read both ways.

Compilation is strict and deterministic:

* unknown keys, unsupported types, duplicate field names, duplicate wire tags
  and over-deep nesting are rejected;
* **ambiguous optionals are rejected at compile time**: if any two fields in
  one SEQUENCE share a wire tag (in particular a run of adjacent optionals
  followed by a field repeating an earlier optional's tag), presence/identity
  would be undecidable at decode time, so the schema does not compile. The
  decoder never "picks the first plausible" match;
* the result is an immutable, content-addressed `Product` (SHA-256 of the
  canonical schema). Publishing a revision is a *new* product id; existing
  imports keep the product they were bound to.

Matching semantics: fields are matched in declaration order against the next
header. An optional field is present iff the next header's wire tag equals its
pre-computed wire tag; otherwise it is skipped. A required field whose tag does
not match is an error at that header's offset — it is not skipped in search of a
later match. An explicit field must contain exactly one complete value with the
declared universal inner tag. An implicit field's body is interpreted as the
declared base type.

## Modules

| module | responsibility |
| --- | --- |
| `telber/ber.py` | tag/length parsing with minimality and EOC rules |
| `telber/schema.py` | strict schema compiler, ambiguity checks, match table |
| `telber/codec.py` | record decoder/encoder with absolute byte provenance |
| `telber/stream.py` | bounded streaming delimitation over the original octets |
| `telber/repository.py` | SQLite product registry + per-record fact relation store |
| `telber/service.py` | independent compile service: artifact, check, encode |
| `telber/build.py` | independent byte builder used only by tests/demo |
| `telber/demo.py`, `telber/cli.py` | demo and command-line entry points |

Two source modules carry the core: `schema.py` + `codec.py` compile and
interpret the directory, and `stream.py` + `repository.py` produce the streaming
relation table. The compiled prediction table (`Product.match_table()`) drives
optional presence decisions, nested boundaries and error offsets.

## Bounds

* nesting depth 32+ supported (compile and stream both bounded; default cap 64)
* 100 fields per SEQUENCE (cap 4096)
* 100 MiB streams processed with bounded memory (one record + read buffer)
* records up to 1 MiB by default (`max_record`, raise for larger)
* primitive bodies buffered up to 2 MiB (`max_body`); larger bodies are rejected
  before copy

The block size is I/O granularity only and never changes offsets or results.

## Fact repository

`Repository` binds each import to one product id at creation. Ingest walks the
original stream and writes, per record:

* `records` — ordinal, absolute start/end, length;
* `fields` — one row per declared field path (absent optionals have
  `present=0`), type, mode, presence, null flag, decoded INTEGER/OCTET STRING,
  and absolute offsets of the complete encoding and value body;
* `field_source_ranges` — role-tagged byte ranges (`encoding` for an implicit
  field's full TLV, `wrapper`/`inner` for an explicit field, and the primitive
  body range).

On the first top-level error the import stops. Completed records stay
committed as a **partial** import with the error code, absolute offset and the
failing record's start offset. A partial import cannot be published as
whole-stream complete. There is no resynchronisation: the scanner never scans
forward for a plausible tag.

## Running

```bash
python3 -m telber.demo                 # end-to-end demo, prints relation table
python3 -m telber.demo --with-truncation
python3 tools/demo.py --out out/       # writes product.json, telemetry.bin, DB, relation.json
python3 -m telber.cli compile schemas/telemetry_v1.json -o product.json
python3 -m telber.cli check product.json record.bin
python3 -m telber.cli encode product.json values.json -o record.bin   # {"$hex": "00ff"} for bytes
python3 -m telber.cli ingest product.json telemetry.bin --db facts.sqlite
python3 -m telber.cli report facts.sqlite --import-id 1 --relation
```

## Tests

```bash
python3 -m pytest tests -q
TELBER_FULL_SCALE=1 python3 -m pytest tests/test_scale.py -q   # 100 MiB stream
```

Coverage highlights (`tests/`):

* `test_ber_wire.py` — base-128 long tags, minimal tag/length, indefinite
  primitive rejection;
* `test_schema.py` — ambiguity rejection, unknown keys, depth/field limits,
  product revision identity;
* `test_codec.py` — independently built records: negative integer boundaries,
  `00 00` inside primitive and definite constructed bodies, optional-vs-null,
  explicit multi-value rejection, implicit interpretation, source ranges;
* `test_stream.py` — block-size invariance (1..4096), truncation prefix
  stability, bounded memory, EOC at the correct level, no resync;
* `test_repository.py` — relation rows, byte provenance slices, partial imports,
  product-revision binding, persistence;
* `test_service.py` — artifact recompilation, presence/type preservation for
  definite and indefinite encodings;
* `test_demo_truth.py` — checks the demo's relation table against an
  independently derived presence map and byte ranges;
* `test_scale.py` — depth 32, 100 MiB stream, 2 MiB body cap (opt-in).
