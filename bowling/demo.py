"""End-to-end bowling demo: lane log -> repository -> physical record -> replay.

For every scenario the demo

1. builds a real TLV byte stream with the lane-side builder (``lane.bin``),
2. ingests it into a fresh SQLite fact repository (``lane.sqlite``),
3. **reopens** that repository and derives the per-throw physical record
   (``physical.json``) — the record other programs read,
4. replays one or more separately kept referee sheets against the reopened
   physical record and writes the ten-frame score reports (``score_*.json``).

Scenarios
---------
``abc``         full rack, throw A downs all ten; re-rack; B downs 1-3; C
                downs 4-7.  Replayed twice from the reopened record: all
                normal -> frame 1 = 17; A judged dead -> frame 1 = 7.
``abc_c45``     same log except C's evidence and actual falls are pins 4,5
                only; original referee sheet -> frame 1 = 15.
``full_game``   a complete ten-frame game (strikes, spares, tenth-frame
                extra balls), status ``complete``, total 183.
``foul``        a foul with re-spot, a dead ball with restoration, and an
                unclosed strike bonus at the end of the log.
``missing_obs`` one probe misses pin 10, leaving a position undecidable;
                the dependent frame is marked pending verification while
                frame 1 stays confirmable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from telber.repository import Repository  # noqa: E402

from bowling.lane import LaneSimulator  # noqa: E402
from bowling.physical import physical_record_from_repository  # noqa: E402
from bowling.replay import replay  # noqa: E402
from bowling.schema import load_schema  # noqa: E402

ALL = list(range(1, 11))


# ---------------------------------------------------------------------------
# scenario builders: each returns (stream_bytes, {sheet_name: referee_sheet})


def build_abc() -> tuple[bytes, dict]:
    sim = LaneSimulator(lane=1)
    sim.rack_full(reason=0)  # file starts from a full rack
    sim.throw(1, down=ALL)  # A: all ten down
    sim.rack_full(reason=1)  # fresh full rack after the strike
    sim.throw(2, down=[1, 2, 3])  # B
    sim.throw(3, down=[4, 5, 6, 7])  # C, continuation deck
    sheets = {
        "normal": _sheet("player-1, all normal", [(1, "normal"), (2, "normal"), (3, "normal")]),
        "a_dead": _sheet("player-1, A judged dead", [(1, "dead"), (2, "normal"), (3, "normal")]),
    }
    return sim.stream(), sheets


def build_abc_c45() -> tuple[bytes, dict]:
    sim = LaneSimulator(lane=1)
    sim.rack_full(reason=0)
    sim.throw(1, down=ALL)
    sim.rack_full(reason=1)
    sim.throw(2, down=[1, 2, 3])
    sim.throw(3, down=[4, 5])  # C: only 4 and 5 fall, evidence agrees
    sheets = {
        "normal": _sheet("player-1, all normal", [(1, "normal"), (2, "normal"), (3, "normal")]),
    }
    return sim.stream(), sheets


def build_full_game() -> tuple[bytes, dict]:
    sim = LaneSimulator(lane=1)
    sim.rack_full(reason=0)
    sim.throw(1, down=[1, 2, 3, 4, 5, 6, 7])  # F1 b1 = 7
    sim.throw(2, down=[8, 9])  # F1 b2 = 2
    sim.rack_full()
    # F2 strike, final state probed in two overlapping fragments that
    # cross-check each other (positions 5 and 6 are covered by both).
    sim.throw(3, down=ALL, obs=[([1, 2, 3, 4, 5, 6], True), ([5, 6, 7, 8, 9, 10], True)])
    sim.rack_full()
    sim.throw(4, down=[1, 3, 5, 7, 9])  # F3 b1 = 5
    sim.throw(5, down=[2, 4, 6, 8, 10])  # F3 b2 = spare
    sim.rack_full()
    sim.throw(6, down=ALL)  # F4 strike
    sim.rack_full()
    sim.throw(7, down=ALL)  # F5 strike
    sim.rack_full()
    sim.throw(8, down=[1, 2, 3])  # F6 b1 = 3
    sim.throw(9, down=[4, 5, 6, 7, 8, 9])  # F6 b2 = 6
    sim.rack_full()
    sim.throw(10, down=[1, 2, 3, 4])  # F7 b1 = 4
    sim.throw(11, down=[5, 6, 7, 8])  # F7 b2 = 4
    sim.rack_full()
    sim.throw(12, down=[1, 2, 3, 4, 5, 6, 7, 8, 9])  # F8 b1 = 9
    sim.throw(13, down=[10])  # F8 b2 = spare
    sim.rack_full()
    sim.throw(14, down=ALL)  # F9 strike
    sim.rack_full()
    sim.throw(15, down=ALL)  # F10 b1 strike
    sim.rack_full()
    sim.throw(16, down=ALL)  # F10 b2 strike
    sim.rack_full()
    sim.throw(17, down=[1, 2, 3, 4, 5])  # F10 b3 = 5
    sheets = {
        "normal": _sheet(
            "player-1, full game",
            [(i, "normal") for i in range(1, 18)],
        ),
    }
    return sim.stream(), sheets


def build_foul() -> tuple[bytes, dict]:
    sim = LaneSimulator(lane=1)
    sim.rack_full(reason=0)
    sim.throw(1, down=[1, 2, 3, 4])  # F1 b1 = 4
    sim.throw(2, down=[5, 6])  # F1 b2: FOUL — 5,6 physically fall, scores 0
    sim.rack_full()  # 5,6 re-spotted; fresh rack for frame 2
    sim.throw(3, down=ALL)  # F2 b1: strike
    sim.rack_full()
    sim.throw(4, down=[1, 2])  # F3 b1 = 2
    sim.throw(5, down=[3, 4])  # F3 b2 = 2
    sim.rack_full()
    sim.throw(6, down=[1])  # DEAD ball — pin 1 physically falls, restored
    sim.rack_full(reason=2)  # restoration after the dead ball
    sim.throw(7, down=ALL)  # F4 b1: strike
    sim.rack_full()
    sim.throw(8, down=[1, 2, 3])  # F5 b1 = 3; log ends, strike bonus unclosed
    sheets = {
        "referee": _sheet(
            "player-1, foul+dead",
            [
                (1, "normal"),
                (2, "foul"),
                (3, "normal"),
                (4, "normal"),
                (5, "normal"),
                (6, "dead"),
                (7, "normal"),
                (8, "normal"),
            ],
        ),
    }
    return sim.stream(), sheets


def build_missing_obs() -> tuple[bytes, dict]:
    sim = LaneSimulator(lane=1)
    sim.rack_full(reason=0)
    sim.throw(1, down=[1, 2, 3, 4, 5, 6, 7])  # F1 b1 = 7
    sim.throw(2, down=[8, 9])  # F1 b2 = 2 (pin 10 left)
    sim.rack_full()
    # F2 b1: the final probe covers positions 1..9 only — pin 10 is never
    # observed, so it stays undecidable even though the next rack shows it.
    sim.throw(3, down=[1, 2, 3, 4, 5, 6], obs=[([1, 2, 3, 4, 5, 6, 7, 8, 9], True)])
    sim.throw(4, down=[7, 8])  # F2 b2 on the actual continuation deck
    sheets = {
        "normal": _sheet(
            "player-1, missing observation",
            [(1, "normal"), (2, "normal"), (3, "normal"), (4, "normal")],
        ),
    }
    return sim.stream(), sheets


def _sheet(description: str, calls: list[tuple[int, str]]) -> dict:
    return {
        "player": "player-1",
        "description": description,
        "calls": [{"throw_seq": seq, "call": call} for seq, call in calls],
    }


SCENARIOS = {
    "abc": build_abc,
    "abc_c45": build_abc_c45,
    "full_game": build_full_game,
    "foul": build_foul,
    "missing_obs": build_missing_obs,
}


# ---------------------------------------------------------------------------
# pipeline


def run_scenario(name: str, out_root: Path) -> dict:
    stream, sheets = SCENARIOS[name]()
    out_dir = out_root / name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "lane.bin").write_bytes(stream)

    schema = load_schema()
    db_path = out_dir / "lane.sqlite"
    if db_path.exists():
        db_path.unlink()
    with Repository(db_path) as repo:
        product = repo.publish_product(schema)
        import_id = repo.create_import(product.product_id, source_name=f"{name}/lane.bin")
        info = repo.ingest_bytes(import_id, stream)
        assert info.status == "complete", info

    # Reopen the repository: the physical record is derived from the stored
    # facts, not from anything kept in memory.
    with Repository(db_path) as repo:
        physical = physical_record_from_repository(repo, import_id)
    (out_dir / "physical.json").write_text(
        json.dumps(physical, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    scores = {}
    for sheet_name, sheet in sheets.items():
        (out_dir / f"referee_{sheet_name}.json").write_text(
            json.dumps(sheet, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        report = replay(physical, sheet)
        (out_dir / f"score_{sheet_name}.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        scores[sheet_name] = report
    return {
        "scenario": name,
        "stream_bytes": len(stream),
        "records": physical["import"]["record_count"],
        "throws": len(physical["throws"]),
        "sheets": {
            k: {
                "status": r["status"],
                "frame1": r["frames"][0]["score"],
                "total": r["total"],
                "confirmed_frames": r["confirmed_frames"],
                "pending_verification_frames": r["pending_verification_frames"],
                "unclosed_bonus_frames": r["unclosed_bonus_frames"],
                "conflicts": [c["code"] for c in r["conflicts"]],
            }
            for k, r in scores.items()
        },
    }


def run(out_root: Path) -> list[dict]:
    out_root.mkdir(parents=True, exist_ok=True)
    return [run_scenario(name, out_root) for name in SCENARIOS]


def main() -> int:
    out_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/bowling")
    summaries = run(out_root)
    print(json.dumps(summaries, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
