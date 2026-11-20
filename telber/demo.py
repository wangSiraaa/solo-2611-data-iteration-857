#!/usr/bin/env python3
"""End-to-end demo: compile a schema product, build a real byte stream with an
independent byte builder, ingest it, and print the record/field relation table.

Run from the repository root::

    python3 -m telber.demo            # in-memory, prints a report
    python3 tools/demo.py --out DIR   # writes DB + schema artifact + stream

The demo deliberately constructs its source octets with :mod:`telber.build`
(no shared code with the codec), including:

* a base-128 long tag (application 300 and application 1000, private tags),
* negative INTEGER boundaries (-1, -128, -129, -8388608, minimum widths),
* OCTET STRING bodies containing ``00 00``,
* a mix of definite and indefinite constructed layers,
* runs of adjacent optional fields,
* an explicit field wrapping a SEQUENCE (multi-level explicit),
* and, in ``--with-truncation`` mode, a truncated tail that yields a partial
  import with an absolute error offset.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from telber import build as B  # noqa: E402
from telber.errors import TelberError  # noqa: E402
from telber.repository import Repository  # noqa: E402
from telber.service import CompileService  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "telemetry_v1.json"


def record_bytes(
    *,
    station_id,
    observed_at,
    kind,
    flags=None,
    note_present=False,
    raw=None,
    label=None,
    quality=None,
    calibration=None,
    indefinite_outer=False,
    indefinite_sensor=False,
):
    """Assemble one top-level record from the schema's fields, by hand."""
    body = B.integer(station_id, cls="context", number=0)
    if flags is not None:
        body += B.octets(flags, cls="context", number=1)
    body += B.integer(observed_at, cls="application", number=300)
    if note_present:
        # explicit NULL: context [2] constructed wrapper around universal NULL
        body += B.explicit(B.tag("context", True, 2), B.null())
    if raw is not None:
        body += B.explicit(B.tag("context", True, 3), B.octets(raw))

    sensor = B.integer(kind, cls="private", number=0)
    if label is not None:
        sensor += B.octets(label, cls="private", number=1)
    if quality is not None:
        sensor += B.explicit(B.tag("private", True, 2), B.integer(quality))
    if calibration is not None:
        offset, valid = calibration
        cal = B.integer(offset, cls="context", number=10)
        if valid:
            cal += B.null(cls="context", number=11)
        # explicit wrapper: private [3] constructed, inner universal SEQUENCE
        sensor += B.explicit(
            B.tag("private", True, 3),
            B.seq(cal, cls="universal", number=16),
        )
    sensor_layer = B.tlv(
        B.tag("application", True, 1000),
        sensor,
        indefinite=indefinite_sensor,
    )
    body += sensor_layer
    return B.tlv(
        B.tag("universal", True, 16),
        body,
        indefinite=indefinite_outer,
    )


def generate_stream() -> tuple[bytes, list[dict]]:
    """A mixed stream plus the expected presence map for each record."""
    fixtures = [
        dict(
            station_id=-1,
            observed_at=0,
            kind=0,
            flags=b"\x00\x00",
            note_present=True,
            raw=b"\x00\x00\xff\x00",
            label=b"\x00\x00",
            quality=-128,
            calibration=(-1, True),
        ),
        dict(
            station_id=-128,
            observed_at=-129,
            kind=1,
            note_present=False,
            raw=b"\x00\x00",
            indefinite_outer=True,
        ),
        dict(
            station_id=-8388608,
            observed_at=300,
            kind=2,
            flags=b"\x00\x00\x00",
            raw=b"\x00\x00",
            label=b"",
            quality=-129,
            calibration=(-8388608, False),
            indefinite_outer=True,
            indefinite_sensor=True,
        ),
        dict(
            station_id=0,
            observed_at=127,
            kind=-1,
            note_present=True,
            label=b"\x00\x00\x00\x00",
            calibration=(0, True),
        ),
    ]
    parts = [record_bytes(**f) for f in fixtures]
    expected = []
    for f in fixtures:
        expected.append(
            {
                "station_id": True,
                "flags": f.get("flags") is not None,
                "observed_at": True,
                "note": f.get("note_present", False),
                "raw": f.get("raw") is not None,
                "sensor": True,
                "sensor.kind": True,
                "sensor.label": f.get("label") is not None,
                "sensor.quality": f.get("quality") is not None,
                "sensor.calibration": f.get("calibration") is not None,
                "sensor.calibration.offset": f.get("calibration") is not None,
                "sensor.calibration.valid": bool(
                    f.get("calibration") and f["calibration"][1]
                ),
            }
        )
    return b"".join(parts), expected


def run(out: Path | None = None, with_truncation: bool = False) -> dict:
    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    service = CompileService()
    product = service.compile(schema_text)
    stream, expected = generate_stream()
    if with_truncation:
        stream = stream + stream[: len(stream) // 3]

    db_path = ":memory:" if out is None else str(out / "telemetry.sqlite")
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "product.json").write_text(service.artifact(product), encoding="utf-8")
        (out / "telemetry.bin").write_bytes(stream)

    report: dict = {
        "product_id": product.product_id,
        "schema": product.schema_name,
        "schema_version": product.version,
        "stream_bytes": len(stream),
        "records": [],
        "match_table": product.match_table(),
    }

    with Repository(db_path) as repo:
        repo.publish_product(schema_text)
        import_id = repo.create_import(
            product.product_id, source_name="demo/telemetry.bin"
        )
        try:
            info = repo.ingest_bytes(import_id, stream, block_size=7)
            report["import"] = info.as_dict()
        except TelberError as exc:
            report["import"] = exc.as_dict()
            report["error"] = {
                "code": exc.code,
                "offset": exc.offset,
                "record_start": exc.record_start,
            }
            info = exc.info  # type: ignore[attr-defined]

        records = repo.records(import_id)
        relation = repo.relation_rows(import_id)
        ranges = repo.source_ranges(import_id)
        report["record_count"] = len(records)
        report["records"] = records
        report["relation"] = relation
        report["source_ranges"] = ranges
        if out is not None:
            (out / "relation.json").write_text(
                json.dumps(
                    {"records": records, "relation": relation, "ranges": ranges},
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )

    if not with_truncation:
        presence = {}
        for row in report["relation"]:
            presence.setdefault(row["record_ordinal"], {})[row["path"]] = bool(
                row["present"]
            )
        report["presence"] = presence
        report["expected_presence"] = expected
        report["presence_matches"] = presence == {
            i: exp for i, exp in enumerate(expected)
        }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=None, help="write artifacts here")
    parser.add_argument(
        "--with-truncation",
        action="store_true",
        help="append a truncated record to demonstrate a partial import",
    )
    args = parser.parse_args(argv)
    report = run(args.out, args.with_truncation)
    printable = {
        k: v
        for k, v in report.items()
        if k not in ("relation", "source_ranges", "match_table", "records")
    }
    print(json.dumps(printable, indent=2, default=str))
    print("\nmatch table (wire tags per SEQUENCE scope):")
    print(json.dumps(report["match_table"], indent=2))
    print("\nfirst 12 relation rows:")
    for row in report["relation"][:12]:
        print(json.dumps(row, default=str))
    print("\nfirst 12 source ranges:")
    for row in report["source_ranges"][:12]:
        print(json.dumps(row, default=str))
    if "presence_matches" in report:
        print("\npresence matches independent expectation:", report["presence_matches"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
