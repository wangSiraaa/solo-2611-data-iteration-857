"""End-to-end demo truth checks: presence, byte provenance, relation types.

The demo builds its source octets with the independent builder.  These tests
re-derive the expected presence map and byte ranges from those same octets and
assert the repository's relation table agrees, at several block sizes.
"""

from __future__ import annotations

import io

import pytest

from telber.demo import SCHEMA_PATH, generate_stream
from telber.repository import Repository
from telber.schema import compile_product
from telber.stream import scan_records


@pytest.fixture(scope="module")
def product():
    return compile_product(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_demo_stream_presence_truth(product, tmp_path):
    stream, expected = generate_stream()
    with Repository(tmp_path / "demo.sqlite") as repo:
        repo.publish_product(SCHEMA_PATH.read_text(encoding="utf-8"))
        import_id = repo.create_import(repo.list_products()[0]["product_id"])
        info = repo.ingest_bytes(import_id, stream, block_size=3)
        assert info.status == "complete"
        assert info.record_count == len(expected)
        presence = repo.field_presence(import_id)
        assert presence == {i: exp for i, exp in enumerate(expected)}


def test_demo_stream_slices_back_to_original_bytes(product, tmp_path):
    stream, _ = generate_stream()
    with Repository(tmp_path / "demo.sqlite") as repo:
        repo.publish_product(SCHEMA_PATH.read_text(encoding="utf-8"))
        import_id = repo.create_import(repo.list_products()[0]["product_id"])
        repo.ingest_bytes(import_id, stream, block_size=1)
        # every relation row's byte range must be inside its record and non-empty
        records = {r["ordinal"]: r for r in repo.records(import_id)}
        for row in repo.relation_rows(import_id):
            if not row["present"]:
                continue
            rec = records[row["record_ordinal"]]
            assert rec["start_offset"] <= row["start_offset"] <= row["end_offset"] <= rec["end_offset"]
            assert row["start_offset"] < row["end_offset"]
        # each integer's body decodes to its recorded value
        for row in repo.relation_rows(import_id):
            if row["present"] and row["type"] == "INTEGER":
                body = stream[row["body_start"] : row["body_end"]]
                assert int.from_bytes(body, "big", signed=True) == row["int_value"]
            if row["present"] and row["type"] == "OCTET STRING":
                body = stream[row["body_start"] : row["body_end"]]
                assert body == row["bytes_value"]


def test_demo_relation_types_are_correct(product, tmp_path):
    stream, expected = generate_stream()
    with Repository(tmp_path / "demo.sqlite") as repo:
        repo.publish_product(SCHEMA_PATH.read_text(encoding="utf-8"))
        import_id = repo.create_import(repo.list_products()[0]["product_id"])
        repo.ingest_bytes(import_id, stream, block_size=9)
        types = {r["path"]: (r["type"], r["mode"]) for r in repo.relation_rows(import_id)}
        assert types["station_id"] == ("INTEGER", "implicit")
        assert types["flags"] == ("OCTET STRING", "implicit")
        assert types["note"] == ("NULL", "explicit")
        assert types["raw"] == ("OCTET STRING", "explicit")
        assert types["sensor"] == ("SEQUENCE", "implicit")
        assert types["sensor.calibration"] == ("SEQUENCE", "explicit")
        assert types["sensor.calibration.valid"] == ("NULL", "implicit")


def test_demo_block_size_invariance(product):
    stream, _ = generate_stream()
    reference = None
    for block in (1, 2, 3, 5, 8, 21, 512):
        got = [
            (r.start, r.end, r.data)
            for r in scan_records(io.BytesIO(stream), product, block_size=block)
        ]
        if reference is None:
            reference = got
        assert got == reference, f"block size {block} changed the result"


def test_demo_truncated_variant_is_partial(product, tmp_path):
    stream, expected = generate_stream()
    truncated = stream + stream[: len(stream) // 3]
    from telber.errors import TelberError

    with Repository(tmp_path / "demo.sqlite") as repo:
        repo.publish_product(SCHEMA_PATH.read_text(encoding="utf-8"))
        import_id = repo.create_import(repo.list_products()[0]["product_id"])
        with pytest.raises(TelberError) as exc:
            repo.ingest_bytes(import_id, truncated, block_size=4)
        info = repo.import_info(import_id)
        assert info.status == "partial"
        assert info.record_count == len(expected) + 1  # 4 + 1 complete of the appended copy
        assert exc.value.offset == len(truncated)
        assert exc.value.record_start >= len(stream)
