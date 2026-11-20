"""Command-line access to the bowling pipeline.

    python3 -m bowling.cli ingest lane.bin --db lane.sqlite
    python3 -m bowling.cli physical lane.sqlite -o physical.json
    python3 -m bowling.cli replay physical.json referee.json [-o score.json]
    python3 -m bowling.cli demo [out_dir]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import demo as _demo
from .physical import physical_record_from_repository
from .replay import replay
from .schema import load_schema


def _cmd_ingest(args) -> int:
    from telber.repository import Repository

    stream = Path(args.lane_bin).read_bytes()
    with Repository(args.db) as repo:
        product = repo.publish_product(load_schema())
        import_id = repo.create_import(product.product_id, source_name=args.lane_bin)
        info = repo.ingest_bytes(import_id, stream)
    print(json.dumps(info.as_dict(), indent=2))
    return 0 if info.status == "complete" else 2


def _cmd_physical(args) -> int:
    from telber.repository import Repository

    with Repository(args.db) as repo:
        ids = [
            r["import_id"]
            for r in repo.conn.execute("SELECT import_id FROM imports ORDER BY import_id")
        ]
        import_id = args.import_id if args.import_id is not None else ids[-1]
        record = physical_record_from_repository(repo, import_id)
    text = json.dumps(record, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"physical record -> {args.out}")
    else:
        print(text)
    return 0


def _cmd_replay(args) -> int:
    physical = json.loads(Path(args.physical).read_text(encoding="utf-8"))
    sheet = json.loads(Path(args.referee).read_text(encoding="utf-8"))
    report = replay(physical, sheet)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"score report -> {args.out}")
    else:
        print(text)
    return 0


def _cmd_demo(args) -> int:
    summaries = _demo.run(Path(args.out))
    print(json.dumps(summaries, indent=2, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bowling", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="ingest a lane event stream into a repository")
    p.add_argument("lane_bin")
    p.add_argument("--db", required=True)
    p.set_defaults(func=_cmd_ingest)

    p = sub.add_parser("physical", help="derive the per-throw physical record")
    p.add_argument("db")
    p.add_argument("--import-id", type=int, default=None)
    p.add_argument("-o", "--out")
    p.set_defaults(func=_cmd_physical)

    p = sub.add_parser("replay", help="replay a referee sheet against the physical record")
    p.add_argument("physical")
    p.add_argument("referee")
    p.add_argument("-o", "--out")
    p.set_defaults(func=_cmd_replay)

    p = sub.add_parser("demo", help="run all demo scenarios")
    p.add_argument("out", nargs="?", default="data/bowling")
    p.set_defaults(func=_cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
