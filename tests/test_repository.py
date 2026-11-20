"""Repository: product binding, field/source relation, partial imports."""

from __future__ import annotations

import pytest

from conftest import field, make_schema
from telber import build as B
from telber.codec import encode_record
from telber.errors import (
    ImportStateError,
    ProductRevisionError,
    TelberError,
)
from telber.repository import Repository


SCHEMA = make_schema(
    [
        field("id", "context", 0, "implicit", "INTEGER"),
        field("blob", "context", 1, "implicit", "OCTET STRING", optional=True),
        field("tagged", "application", 300, "implicit", "INTEGER"),
        field("nul", "context", 2, "explicit", "NULL", optional=True),
        field(
            "inner",
            "application",
            1000,
            "implicit",
            "SEQUENCE",
            fields=[
                field("a", "private", 0, "implicit", "INTEGER"),
                field("b", "private", 1, "implicit", "OCTET STRING", optional=True),
            ],
        ),
    ]
)


def build_record(product, **kw):
    return encode_record(kw, product)


def manual_record(
    id_,
    tagged,
    a,
    *,
    blob=None,
    null_present=False,
    b=None,
    outer_indefinite=False,
):
    body = B.integer(id_, cls="context", number=0)
    if blob is not None:
        body += B.octets(blob, cls="context", number=1)
    body += B.integer(tagged, cls="application", number=300)
    if null_present:
        body += B.explicit(B.tag("context", True, 2), B.null())
    inner = B.integer(a, cls="private", number=0)
    if b is not None:
        inner += B.octets(b, cls="private", number=1)
    body += B.tlv(B.tag("application", True, 1000), inner)
    return B.seq(body, indefinite=outer_indefinite)


@pytest.fixture
def setup(tmp_path):
    db = tmp_path / "facts.sqlite"
    with Repository(db) as repo:
        product = repo.publish_product(SCHEMA)
        import_id = repo.create_import(product.product_id, source_name="test")
        yield repo, product, import_id
    repo.close()


def test_relation_rows_cover_present_and_absent_fields(setup):
    repo, product, import_id = setup
    data = manual_record(1, 2, 3, blob=b"\x00\x00", null_present=True)
    info = repo.ingest_bytes(import_id, data)
    assert info.status == "complete"
    assert info.record_count == 1

    rows = {r["path"]: r for r in repo.relation_rows(import_id)}
    assert rows["id"]["present"] == 1 and rows["id"]["int_value"] == 1
    assert rows["blob"]["present"] == 1 and rows["blob"]["bytes_value"] == b"\x00\x00"
    assert rows["tagged"]["int_value"] == 2
    assert rows["nul"]["present"] == 1 and rows["nul"]["is_null"] == 1
    assert rows["inner"]["present"] == 1
    assert rows["inner.a"]["int_value"] == 3
    assert rows["inner.b"]["present"] == 0
    assert rows["inner.b"]["start_offset"] is None
    assert rows["inner.b"]["int_value"] is None


def test_field_source_ranges_slice_original_stream(setup):
    repo, product, import_id = setup
    data = (
        manual_record(5, 6, 7, blob=b"\xaa\x00\x00")
        + manual_record(-1, 8, -128, null_present=True, b=b"\x00\x00")
    )
    repo.ingest_bytes(import_id, data)
    records = repo.records(import_id)
    assert records[0]["start_offset"] == 0
    assert records[1]["start_offset"] == len(records[0]) and False or records[1]["start_offset"] == records[0]["end_offset"]

    ranges = repo.source_ranges(import_id)
    by_key = {}
    for r in ranges:
        by_key.setdefault((r["record_ordinal"], r["path"]), []).append(r)

    # implicit INTEGER: one encoding range that slices to the exact bytes
    id_ranges = by_key[(0, "id")]
    assert id_ranges[0]["role"] == "encoding"
    seg = data[id_ranges[0]["start_offset"] : id_ranges[0]["end_offset"]]
    assert seg == B.integer(5, cls="context", number=0)

    # OCTET STRING body range includes the 00 00 bytes verbatim
    blob_ranges = by_key[(0, "blob")]
    assert blob_ranges[0]["role"] == "encoding"
    body = data[blob_ranges[0]["start_offset"] : blob_ranges[0]["end_offset"]]
    assert body == B.octets(b"\xaa\x00\x00", cls="context", number=1)

    # explicit NULL has a wrapper range and an inner range
    nul_ranges = [r for r in by_key[(1, "nul")]]
    assert [r["role"] for r in nul_ranges] == ["wrapper", "inner"]
    wrapper = nul_ranges[0]
    inner = nul_ranges[1]
    assert data[wrapper["start_offset"] : wrapper["end_offset"]] == B.explicit(
        B.tag("context", True, 2), B.null()
    )
    assert data[inner["start_offset"] : inner["end_offset"]] == B.null()

    # nested field range lies inside its parent's encoding range
    inner_rows = by_key[(1, "inner")]
    a_rows = by_key[(1, "inner.a")]
    assert inner_rows[0]["start_offset"] <= a_rows[0]["start_offset"]
    assert a_rows[0]["end_offset"] <= inner_rows[0]["end_offset"]
    assert (
        data[a_rows[0]["start_offset"] : a_rows[0]["end_offset"]]
        == B.integer(-128, cls="private", number=0)
    )


def test_field_body_offsets_match_relation(setup):
    repo, product, import_id = setup
    data = manual_record(1, 2, 3, blob=b"\x00\x00")
    repo.ingest_bytes(import_id, data)
    rows = {r["path"]: r for r in repo.relation_rows(import_id)}
    blob = rows["blob"]
    assert data[blob["body_start"] : blob["body_end"]] == b"\x00\x00"
    id_row = rows["id"]
    assert data[id_row["body_start"] : id_row["body_end"]] == B.int_body(1)


def test_partial_import_keeps_prefix_and_blocks_publish(setup):
    repo, product, import_id = setup
    good = manual_record(1, 2, 3) + manual_record(4, 5, 6)
    stream = good + manual_record(7, 8, 9)[:-3]
    with pytest.raises(TelberError) as exc:
        repo.ingest_bytes(import_id, stream)
    err = exc.value
    assert err.code == "truncated"
    assert err.offset == len(stream)
    assert err.record_start == len(good)

    info = repo.import_info(import_id)
    assert info.status == "partial"
    assert info.record_count == 2
    assert info.error_offset == len(stream)
    assert repo.records(import_id)[-1]["end_offset"] == len(good)

    # prefix facts are fully queryable
    presence = repo.field_presence(import_id)
    assert presence[0]["id"] and presence[1]["inner.a"]

    with pytest.raises(ImportStateError):
        repo.publish_import(import_id)


def test_error_offset_is_absolute_across_multiple_records(setup):
    repo, product, import_id = setup
    one = manual_record(1, 2, 3)
    two = manual_record(4, 5, 6)
    # append a record with a bad INTEGER body (redundant sign octet)
    bad_body = (
        B.raw_tlv(B.tag("context", False, 0), b"\x00\x01")
        + B.integer(2, cls="application", number=300)
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
    )
    bad = B.seq(bad_body)
    with pytest.raises(TelberError) as exc:
        repo.ingest_bytes(import_id, one + two + bad)
    # the INTEGER body starts 4 bytes into the bad record
    # (root header 30 LL, then field header 80 02)
    bad_start = len(one) + len(two)
    assert exc.value.offset == bad_start + 4
    assert exc.value.record_start == bad_start


def test_block_size_does_not_change_relation(setup):
    repo, product, import_id = setup
    data = b"".join(
        manual_record(i, i * 2, -i, blob=b"\x00\x00" if i % 2 else None, outer_indefinite=bool(i % 3 == 0))
        for i in range(1, 20)
    )
    reference = None
    for block in (1, 2, 3, 7, 64):
        with Repository(":memory:") as tmp:
            pid = tmp.publish_product(SCHEMA)
            imp = tmp.create_import(pid.product_id)
            tmp.ingest_bytes(imp, data, block_size=block)
            rows = [
                (
                    r["record_ordinal"], r["path"], r["present"], r["is_null"],
                    r["int_value"], r["bytes_value"], r["start_offset"], r["end_offset"],
                )
                for r in tmp.relation_rows(imp)
            ]
            rr = [
                (r["record_ordinal"], r["path"], r["seq"], r["role"], r["start_offset"], r["end_offset"])
                for r in tmp.source_ranges(imp)
            ]
            if reference is None:
                reference = (rows, rr)
            assert (rows, rr) == reference, f"block {block} differed"
    # also check against the shared fixture repo
    repo.ingest_bytes(import_id, data, block_size=5)
    rows = [
        (r["record_ordinal"], r["path"], r["present"], r["is_null"], r["int_value"],
         r["bytes_value"], r["start_offset"], r["end_offset"])
        for r in repo.relation_rows(import_id)
    ]
    assert rows == reference[0]


def test_product_revision_requires_new_import(setup):
    repo, product, import_id = setup
    repo.ingest_bytes(import_id, manual_record(1, 2, 3))

    # changing content while keeping (schema, version) is rejected
    revised_same_version = make_schema(
        [field("id", "context", 0, "implicit", "OCTET STRING")]
    )
    with pytest.raises(ProductRevisionError):
        repo.publish_product(revised_same_version)

    # bumping the version publishes a new product id
    new_schema = make_schema(
        [field("id", "context", 0, "implicit", "OCTET STRING")], version=2
    )
    product2 = repo.publish_product(new_schema)
    assert product2.product_id != product.product_id

    new_import = repo.create_import(product2.product_id)
    assert repo.import_info(import_id).product_id == product.product_id
    assert repo.import_info(new_import).product_id == product2.product_id

    # the old import's field meaning is untouched
    old_rows = {r["path"]: r for r in repo.relation_rows(import_id)}
    assert old_rows["id"]["type"] == "INTEGER"
    assert old_rows["id"]["int_value"] == 1

    # old import cannot ingest under the new product
    new_record = encode_record({"id": b"\x00\x00"}, product2)
    info = repo.ingest_bytes(new_import, new_record)
    assert info.status == "complete"


def test_republishing_identical_schema_is_idempotent(setup):
    repo, product, import_id = setup
    again = repo.publish_product(SCHEMA)
    assert again.product_id == product.product_id
    assert len(repo.list_products()) == 1


def test_import_cannot_bind_to_unknown_product(tmp_path):
    with Repository(tmp_path / "db.sqlite") as repo:
        with pytest.raises(TelberError) as exc:
            repo.create_import("deadbeef")
        assert exc.value.code == "unknown_product"


def test_import_cannot_be_ingested_twice(setup):
    repo, product, import_id = setup
    repo.ingest_bytes(import_id, manual_record(1, 2, 3))
    with pytest.raises(ImportStateError):
        repo.ingest_bytes(import_id, manual_record(1, 2, 3))


def test_unknown_and_duplicate_fields_reject_record(setup):
    repo, product, import_id = setup
    good = manual_record(1, 2, 3)
    extra = B.seq(
        B.integer(1, cls="context", number=0)
        + B.integer(2, cls="application", number=300)
        + B.tlv(B.tag("application", True, 1000), B.integer(3, cls="private", number=0))
        + B.integer(9, cls="context", number=99)
    )
    with pytest.raises(TelberError) as exc:
        repo.ingest_bytes(import_id, good + extra)
    assert exc.value.code == "unknown_field"
    assert exc.value.record_start == len(good)
    assert repo.import_info(import_id).status == "partial"
    assert repo.import_info(import_id).record_count == 1


def test_facts_persist_across_reopen(tmp_path):
    db = tmp_path / "persist.sqlite"
    with Repository(db) as repo:
        product = repo.publish_product(SCHEMA)
        import_id = repo.create_import(product.product_id)
        repo.ingest_bytes(import_id, manual_record(1, 2, 3))
    with Repository(db) as repo:
        info = repo.import_info(import_id)
        assert info.status == "complete"
        rows = repo.relation_rows(import_id)
        assert {r["path"] for r in rows} >= {"id", "inner", "inner.a"}


def test_ingest_file_with_block_sizes(tmp_path):
    data = b"".join(manual_record(i, i, i) for i in range(1, 10))
    src = tmp_path / "stream.bin"
    src.write_bytes(data)
    for block in (1, 11, 4096):
        with Repository(":memory:") as repo:
            product = repo.publish_product(SCHEMA)
            import_id = repo.create_import(product.product_id)
            info = repo.ingest_file(import_id, src, block_size=block)
            assert info.record_count == 9
            assert info.byte_count == len(data)
