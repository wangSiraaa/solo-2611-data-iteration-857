"""Bowling lane log + referee replay: end-to-end over the telber repository."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telber.repository import Repository  # noqa: E402

from bowling.demo import SCENARIOS  # noqa: E402
from bowling.lane import LaneSimulator  # noqa: E402
from bowling.physical import physical_record_from_repository  # noqa: E402
from bowling.replay import replay  # noqa: E402
from bowling.schema import load_schema  # noqa: E402

ALL = list(range(1, 11))


def make_physical(tmp_path, stream: bytes):
    """Ingest a lane stream, reopen the repository, derive the record."""
    db = tmp_path / "lane.sqlite"
    schema = load_schema()
    with Repository(db) as repo:
        product = repo.publish_product(schema)
        import_id = repo.create_import(product.product_id, source_name="test")
        info = repo.ingest_bytes(import_id, stream)
        assert info.status == "complete"
    with Repository(db) as repo:
        return physical_record_from_repository(repo, import_id)


def sheet(*calls):
    return {
        "player": "player-1",
        "calls": [{"throw_seq": s, "call": c} for s, c in calls],
    }


def scenario(name):
    return SCENARIOS[name]()


# -- the three required judgements -----------------------------------------


def test_abc_all_normal_frame1_17(tmp_path):
    stream, sheets = scenario("abc")
    physical = make_physical(tmp_path, stream)
    report = replay(physical, sheets["normal"])
    assert report["frames"][0]["status"] == "confirmed"
    assert report["frames"][0]["score"] == 17  # 10 + 3 + 4
    assert report["frames"][1]["score"] == 7  # B 3 + C 4
    assert report["status"] == "in_progress"  # only two frames bowled
    assert report["conflicts"] == []


def test_abc_dead_ball_frame1_7(tmp_path):
    stream, sheets = scenario("abc")
    physical = make_physical(tmp_path, stream)
    report = replay(physical, sheets["a_dead"])
    # A is dead: no slot, no bonus; B and C become frame 1's two balls
    assert report["frames"][0]["score"] == 7
    assert report["frames"][0]["balls"] == [
        {"throw_seq": 2, "call": "normal", "pins": 3, "uncertain": False},
        {"throw_seq": 3, "call": "normal", "pins": 4, "uncertain": False},
    ]
    assert report["dead_throws"] == [1]
    assert report["conflicts"] == []
    # the rack after the dead ball was restored to full before B
    checks = {c["throw_seq"]: c for c in report["rack_checks"]}
    assert checks[2]["ok"] and checks[3]["ok"]


def test_abc_c45_frame1_15(tmp_path):
    stream, sheets = scenario("abc_c45")
    physical = make_physical(tmp_path, stream)
    report = replay(physical, sheets["normal"])
    assert report["frames"][0]["score"] == 15  # 10 + 3 + 2
    assert report["frames"][1]["score"] == 5


def test_reopened_repository_replays_both_sheets(tmp_path):
    """The same reopened physical record serves two referee sheets."""
    stream, sheets = scenario("abc")
    physical = make_physical(tmp_path, stream)
    assert replay(physical, sheets["normal"])["frames"][0]["score"] == 17
    assert replay(physical, sheets["a_dead"])["frames"][0]["score"] == 7


# -- full game ---------------------------------------------------------------


def test_full_game_complete_183(tmp_path):
    stream, sheets = scenario("full_game")
    physical = make_physical(tmp_path, stream)
    report = replay(physical, sheets["normal"])
    assert report["status"] == "complete"
    assert report["total"] == 183
    scores = [f["score"] for f in report["frames"]]
    assert scores == [9, 20, 20, 23, 19, 9, 8, 20, 30, 25]
    cumulative = [f["cumulative"] for f in report["frames"]]
    assert cumulative == [9, 29, 49, 72, 91, 100, 108, 128, 158, 183]
    # tenth frame took exactly three balls, all counted in frame 10 only
    assert [b["throw_seq"] for b in report["frames"][9]["balls"]] == [15, 16, 17]
    assert report["frames"][9]["bonus_from"] == []
    # fragmented final probes cross-checked the F2 strike
    t3 = physical["throws"][2]
    assert t3["observations"][0]["final"] and t3["observations"][1]["final"]
    assert t3["fall_count"] == 10 and t3["undetermined"] == []


# -- foul re-spot and dead-ball restore ---------------------------------------


def test_foul_and_dead_rack_rules(tmp_path):
    stream, sheets = scenario("foul")
    physical = make_physical(tmp_path, stream)
    report = replay(physical, sheets["referee"])
    assert report["status"] == "in_progress"
    assert report["conflicts"] == []
    frames = report["frames"]
    assert frames[0]["score"] == 4  # 4 + foul(0)
    assert frames[0]["balls"][1]["call"] == "foul"
    assert frames[1]["score"] == 14  # strike + 2 + 2
    assert frames[2]["score"] == 4
    assert frames[3]["status"] == "open_bonus"  # strike, only one bonus ball seen
    assert report["unclosed_bonus_frames"] == [4]
    assert report["dead_throws"] == [6]
    # every rack followed the rules: re-spot after the foul, restore after
    # the dead ball, fresh full racks after strikes
    assert all(c["ok"] for c in report["rack_checks"])


# -- missing observation -------------------------------------------------------


def test_missing_observation_marks_dependent_frame(tmp_path):
    stream, sheets = scenario("missing_obs")
    physical = make_physical(tmp_path, stream)
    t3 = physical["throws"][2]
    assert t3["confirmed_down"] == [1, 2, 3, 4, 5, 6]
    assert t3["confirmed_standing"] == [7, 8, 9]
    assert t3["undetermined"] == [10]
    report = replay(physical, sheets["normal"])
    assert report["status"] == "in_progress"
    assert report["verification_pending"]
    assert report["frames"][0]["status"] == "confirmed"
    assert report["frames"][0]["score"] == 9
    assert report["frames"][1]["status"] == "pending_verification"
    assert report["confirmed_frames"] == [1]
    assert report["pending_verification_frames"] == [2]
    # the next rack shows pin 10 but that is never back-filled as evidence
    t3_after = physical["throws"][2]
    assert t3_after["undetermined"] == [10]
    check4 = [c for c in report["rack_checks"] if c["throw_seq"] == 4][0]
    assert check4["unverifiable"] == [10]


def test_later_full_rack_does_not_complete_evidence(tmp_path):
    """A throw with no probes at all stays undecided; the following full
    re-rack must not turn it into a strike."""
    sim = LaneSimulator()
    sim.rack_full(reason=0)
    sim.throw(1, down=ALL, obs=[], settle=False)  # no observation, no settle
    sim.rack_full()
    sim.throw(2, down=[1])
    physical = make_physical(tmp_path, sim.stream())
    t1 = physical["throws"][0]
    assert t1["fall_count"] == 0
    assert t1["undetermined"] == ALL
    report = replay(physical, sheet((1, "normal"), (2, "normal")))
    # could be a strike -> frame structure undecidable, game waits
    assert report["status"] == "in_progress"
    assert report["verification_pending"]
    assert report["frames"][0]["status"] == "pending_verification"
    assert report["unassignable_throws"] == [2]


# -- contradictions ------------------------------------------------------------


def test_restanding_pin_is_a_conflict(tmp_path):
    from bowling.lane import observe_event, settle_event, throw_event

    sim = LaneSimulator()
    sim.rack_full(reason=0)
    sim._emit(throw_event(2, 1, [1] * 10, 1))
    # obs 1 sees pin 1 down, obs 2 sees it standing again: impossible
    sim._emit(observe_event(3, 1, 1, [1, 1] + [0] * 8, [0, 1] + [0] * 8, 1))
    sim._emit(observe_event(4, 1, 2, [1, 1] + [0] * 8, [1, 1] + [0] * 8, 1))
    sim._emit(settle_event(5, 1, [2], 1))
    physical = make_physical(tmp_path, sim.stream())
    t1 = physical["throws"][0]
    codes = {c["code"] for c in t1["contradictions"]}
    assert "pin_restanding" in codes
    report = replay(physical, sheet((1, "normal")))
    assert report["status"] == "conflict"
    assert any(c["code"] == "pin_restanding" for c in report["conflicts"])


def test_final_fragments_disagree(tmp_path):
    from bowling.lane import observe_event, settle_event, throw_event

    sim = LaneSimulator()
    sim.rack_full(reason=0)
    sim._emit(throw_event(2, 1, [1] * 10, 1))
    # two final fragments overlap on pin 5 and disagree
    sim._emit(observe_event(3, 1, 1, [1] * 5 + [0] * 5, [0, 0, 0, 0, 0] + [0] * 5, 1))
    sim._emit(observe_event(4, 1, 2, [0] * 4 + [1] * 6, [0] * 4 + [1] + [0] * 5, 1))
    sim._emit(settle_event(5, 1, [1, 2], 1))
    physical = make_physical(tmp_path, sim.stream())
    codes = {c["code"] for c in physical["throws"][0]["contradictions"]}
    assert "final_observations_disagree" in codes
    report = replay(physical, sheet((1, "normal")))
    assert report["status"] == "conflict"


def test_extra_throw_after_complete_game(tmp_path):
    stream, sheets = scenario("full_game")
    physical = make_physical(tmp_path, stream)
    # append an eighteenth judged throw to the physical record
    extra = dict(physical["throws"][-1])
    extra["throw_seq"] = 18
    physical["throws"].append(extra)
    calls = list(sheets["normal"]["calls"]) + [{"throw_seq": 18, "call": "normal"}]
    report = replay(physical, {"player": "player-1", "calls": calls})
    assert report["status"] == "conflict"
    assert report["extra_throws"] == [18]
    assert any(c["code"] == "extra_throw" for c in report["conflicts"])


def test_rack_mismatch_is_a_conflict(tmp_path):
    sim = LaneSimulator()
    sim.rack_full(reason=0)
    sim.throw(1, down=[1, 2, 3])  # leaves 4..10
    # second ball must start on the remaining deck, but starts full instead
    sim.rack_full()
    sim.throw(2, down=[1])
    physical = make_physical(tmp_path, sim.stream())
    report = replay(physical, sheet((1, "normal"), (2, "normal")))
    assert report["status"] == "conflict"
    assert any(c["code"] == "rack_mismatch" for c in report["conflicts"])


def test_sheet_referencing_unknown_throw(tmp_path):
    stream, sheets = scenario("abc")
    physical = make_physical(tmp_path, stream)
    bad = sheet((1, "normal"), (2, "normal"), (3, "normal"), (9, "normal"))
    report = replay(physical, bad)
    assert report["status"] == "conflict"
    assert any(c["code"] == "sheet_unknown_throw" for c in report["conflicts"])


def test_multiple_players_rejected(tmp_path):
    stream, sheets = scenario("abc")
    physical = make_physical(tmp_path, stream)
    bad = dict(sheets["normal"])
    bad["players"] = ["a", "b"]
    report = replay(physical, bad)
    assert report["status"] == "conflict"
    assert any(c["code"] == "multiple_players" for c in report["conflicts"])


def test_uncalled_throw_leaves_game_in_progress(tmp_path):
    stream, sheets = scenario("abc")
    physical = make_physical(tmp_path, stream)
    report = replay(physical, sheet((1, "normal"), (2, "normal")))
    assert report["status"] == "in_progress"
    assert report["uncalled_throws"] == [3]


def test_dead_ball_grants_no_bonus_and_foul_scores_zero(tmp_path):
    """Strike, then a dead ball (skipped), a foul (0, but a scoring ball),
    then 5: frame 1 = 10 + 0 + 5."""
    sim = LaneSimulator()
    sim.rack_full(reason=0)
    sim.throw(1, down=ALL)          # strike
    sim.rack_full()
    sim.throw(2, down=[1, 2])       # dead ball: pins restored afterwards
    sim.rack_full(reason=2)
    sim.throw(3, down=[1, 2, 3])    # foul: occupies a ball, scores 0
    sim.rack_full(reason=2)         # re-spot after the foul
    sim.throw(4, down=[1, 2, 3, 4, 5])  # 5
    physical = make_physical(tmp_path, sim.stream())
    report = replay(
        physical,
        sheet((1, "normal"), (2, "dead"), (3, "foul"), (4, "normal")),
    )
    assert report["conflicts"] == []
    f1 = report["frames"][0]
    assert f1["score"] == 15
    assert f1["bonus_from"] == [3, 4]  # the dead throw 2 grants nothing
    # frame 2 consists of the foul (0) and the 5: an open frame of 5
    assert report["frames"][1]["balls"][0]["call"] == "foul"
    assert report["frames"][1]["status"] == "confirmed"
    assert report["frames"][1]["score"] == 5


# -- repository behaviour ------------------------------------------------------


def test_physical_record_persists_across_reopen(tmp_path):
    stream, _ = scenario("abc")
    db = tmp_path / "lane.sqlite"
    schema = load_schema()
    with Repository(db) as repo:
        product = repo.publish_product(schema)
        import_id = repo.create_import(product.product_id)
        repo.ingest_bytes(import_id, stream)
        first = physical_record_from_repository(repo, import_id)
    with Repository(db) as repo:
        second = physical_record_from_repository(repo, import_id)
    assert first == second


def test_old_and_new_formats_coexist(tmp_path):
    """The telemetry v1 format stays importable and queryable alongside."""
    from telber import build as B
    from telber.demo import generate_stream

    db = tmp_path / "mixed.sqlite"
    telemetry_schema = __import__("json").loads(
        open(__import__("pathlib").Path(__file__).parent.parent / "schemas" / "telemetry_v1.json").read()
    )
    with Repository(db) as repo:
        p_old = repo.publish_product(telemetry_schema)
        p_new = repo.publish_product(load_schema())
        assert p_old.product_id != p_new.product_id
        old_stream, expected = generate_stream()
        imp_old = repo.create_import(p_old.product_id)
        repo.ingest_bytes(imp_old, old_stream)
        new_stream, _ = scenario("abc")
        imp_new = repo.create_import(p_new.product_id)
        repo.ingest_bytes(imp_new, new_stream)
        # old format still queryable
        rows = repo.relation_rows(imp_old)
        assert {r["path"] for r in rows} >= {"station_id", "sensor.kind"}
        # new format yields the physical record
        physical = physical_record_from_repository(repo, imp_new)
        assert [t["throw_seq"] for t in physical["throws"]] == [1, 2, 3]


def test_event_offsets_point_into_original_stream(tmp_path):
    stream, _ = scenario("abc")
    physical = make_physical(tmp_path, stream)
    t1 = physical["throws"][0]
    start = t1["start_source"]["start_offset"]
    end = t1["start_source"]["end_offset"]
    # the throw_start record's bytes sit at the recorded absolute offsets
    assert stream[start:start+1] == b"\x30"  # SEQUENCE tag opens the record
    assert start < end <= len(stream)
    obs_src = t1["positions"][0]["source"]
    assert obs_src["obs_seq"] == 1
    assert stream[obs_src["start_offset"]:obs_src["start_offset"]+1] == b"\x30"
