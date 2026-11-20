"""Match replay: physical record + referee sheet -> ten-frame scoring.

The referee sheet is kept apart from the lane log and maps physical throw
numbers to calls:

* ``normal`` — scores the confirmed fall count;
* ``foul``   — occupies one ball, scores zero, pins are re-spotted afterwards;
* ``dead``   — occupies no slot, grants no bonus to the previous frame, and
               the deck is restored before the next throw.

Scoring is the ten-frame game: frames 1-9 score strike = 10 + next two
scoring balls, spare = 10 + next one, otherwise the sum of two balls; the
tenth frame adds its extra balls to itself only.  A normal throw with
undetermined positions marks every frame that depends on it as
``pending_verification``; frames that do not are reported as confirmable.

Match status is one of ``complete`` (normal end), ``in_progress`` (still
running or awaiting verification/judgement) or ``conflict`` (physical
evidence clash, rack-rule mismatch, extra throws, sheet errors).
"""

from __future__ import annotations

CALLS = ("normal", "foul", "dead")

STATUS_COMPLETE = "complete"
STATUS_IN_PROGRESS = "in_progress"
STATUS_CONFLICT = "conflict"


def _maybe_strike(t: dict) -> bool:
    """True when the throw could physically be a strike but is not confirmed."""
    return (
        t["fall_count"] < 10
        and not t["confirmed_standing"]
        and bool(t["undetermined"])
    )


def _remaining_after(t: dict) -> list[int | None]:
    """Deck expected after a normal throw: 0 down, 1 standing, None unknown."""
    down = set(t["confirmed_down"])
    standing = set(t["confirmed_standing"])
    out: list[int | None] = []
    for pin in range(1, 11):
        if t["start_pins"][pin - 1] == 0:
            out.append(0)
        elif pin in down:
            out.append(0)
        elif pin in standing:
            out.append(1)
        else:
            out.append(None)
    return out


def replay(physical: dict, sheet: dict) -> dict:
    throws = sorted(physical["throws"], key=lambda t: t["throw_seq"])
    throw_by_seq = {t["throw_seq"]: t for t in throws}
    conflicts: list[dict] = []
    notes: list[str] = [physical.get("evidence_rule", "")]

    # ---- referee sheet validation --------------------------------------
    player = sheet.get("player")
    players = sheet.get("players")
    if players is not None:
        if not isinstance(players, list) or len(players) != 1:
            conflicts.append(
                {"code": "multiple_players", "message": "match record accepts only one player"}
            )
        elif player is None:
            player = players[0]
    calls: dict[int, str] = {}
    for c in sheet.get("calls", []):
        seq, call = c.get("throw_seq"), c.get("call")
        if call not in CALLS:
            conflicts.append(
                {"code": "bad_call", "message": f"throw {seq}: unknown call {call!r}"}
            )
            continue
        if seq in calls:
            conflicts.append(
                {"code": "duplicate_call", "message": f"throw {seq} judged twice"}
            )
            continue
        calls[seq] = call
    for seq in sorted(calls):
        if seq not in throw_by_seq:
            conflicts.append(
                {
                    "code": "sheet_unknown_throw",
                    "message": f"referee sheet judges throw {seq} which is not in the lane log",
                }
            )

    # ---- physical contradictions surface per throw ----------------------
    for t in throws:
        for c in t["contradictions"]:
            conflicts.append({"throw_seq": t["throw_seq"], **c})
    for issue in physical.get("log_issues", []):
        conflicts.append(issue)
    for orphan in physical.get("orphan_events", []):
        conflicts.append(orphan)

    # ---- throws -> scoring balls ----------------------------------------
    balls: list[dict] = []
    uncalled: list[int] = []
    dead_throws: list[int] = []
    for t in throws:
        call = calls.get(t["throw_seq"])
        if call is None:
            uncalled.append(t["throw_seq"])
            break
        if call == "dead":
            dead_throws.append(t["throw_seq"])
            continue
        if call == "foul":
            balls.append(
                {
                    "throw_seq": t["throw_seq"],
                    "call": "foul",
                    "pins": 0,
                    "uncertain": False,
                    "maybe_strike": False,
                    "unknown_count": 0,
                    "throw": t,
                }
            )
        else:
            balls.append(
                {
                    "throw_seq": t["throw_seq"],
                    "call": "normal",
                    "pins": t["fall_count"],
                    "uncertain": bool(t["undetermined"]),
                    "maybe_strike": _maybe_strike(t),
                    "unknown_count": len(t["undetermined"]),
                    "throw": t,
                }
            )

    # ---- assign balls to frames ------------------------------------------
    frames = [
        {
            "index": i,
            "balls": [],
            "structure_uncertain": False,
            "spare_uncertain": False,
        }
        for i in range(10)
    ]
    assignment: dict[int, tuple[int, int]] = {}
    fi = 0
    bi = 0
    walk_stopped = False
    while bi < len(balls) and fi < 10:
        b = balls[bi]
        fr = frames[fi]
        fr["balls"].append(b)
        assignment[b["throw_seq"]] = (fi, 0)
        bi += 1
        if fi < 9:
            if b["pins"] == 10:
                fi += 1
                continue
            if b["maybe_strike"]:
                fr["structure_uncertain"] = True
                walk_stopped = True
                break
            if bi < len(balls):
                b2 = balls[bi]
                fr["balls"].append(b2)
                assignment[b2["throw_seq"]] = (fi, 1)
                bi += 1
            fi += 1
        else:
            if b["pins"] == 10 or b["maybe_strike"]:
                if b["maybe_strike"]:
                    fr["structure_uncertain"] = True
                for k in (1, 2):
                    if bi < len(balls):
                        bb = balls[bi]
                        fr["balls"].append(bb)
                        assignment[bb["throw_seq"]] = (fi, k)
                        bi += 1
            else:
                if bi < len(balls):
                    b2 = balls[bi]
                    fr["balls"].append(b2)
                    assignment[b2["throw_seq"]] = (fi, 1)
                    bi += 1
                    total = b["pins"] + b2["pins"]
                    possible = total + b["unknown_count"] + b2["unknown_count"]
                    if total == 10 and not (b["uncertain"] or b2["uncertain"]):
                        if bi < len(balls):
                            b3 = balls[bi]
                            fr["balls"].append(b3)
                            assignment[b3["throw_seq"]] = (fi, 2)
                            bi += 1
                    elif total < 10 <= possible:
                        fr["spare_uncertain"] = True
                        if bi < len(balls):
                            b3 = balls[bi]
                            fr["balls"].append(b3)
                            assignment[b3["throw_seq"]] = (fi, 2)
                            bi += 1
            fi += 1
    leftover = balls[bi:]
    unassignable = [b["throw_seq"] for b in leftover] if walk_stopped else []

    # ---- score frames ------------------------------------------------------
    ball_seq = [b for fr in frames for b in fr["balls"]]
    for i, fr in enumerate(frames):
        own = fr["balls"]
        if not own:
            fr.update(status="not_started", score=None, depends_on=[], bonus_from=[])
            continue
        bonus: list[dict] = []
        needed_bonus = 0
        if i < 9:
            expected_own = 1 if own[0]["pins"] == 10 else 2
            if own[0]["pins"] == 10:
                needed_bonus = 2
                at = ball_seq.index(own[-1])
                bonus = ball_seq[at + 1 : at + 3]
            elif len(own) == 2:
                s = own[0]["pins"] + own[1]["pins"]
                poss = s + own[0]["unknown_count"] + own[1]["unknown_count"]
                if s == 10 and not (own[0]["uncertain"] or own[1]["uncertain"]):
                    needed_bonus = 1
                    at = ball_seq.index(own[-1])
                    bonus = ball_seq[at + 1 : at + 2]
                elif s < 10 <= poss:
                    fr["spare_uncertain"] = True
        else:
            first = own[0]
            if first["pins"] == 10 or first["maybe_strike"]:
                expected_own = 3
            elif len(own) >= 2:
                s = first["pins"] + own[1]["pins"]
                poss = s + first["unknown_count"] + own[1]["unknown_count"]
                expected_own = 3 if (s == 10 or (s < 10 <= poss)) else 2
            else:
                expected_own = 2
        depended = own + bonus
        fr["depends_on"] = [b["throw_seq"] for b in depended]
        fr["bonus_from"] = [b["throw_seq"] for b in bonus]
        if fr["structure_uncertain"] or fr["spare_uncertain"]:
            status, score = "pending_verification", None
        elif any(b["uncertain"] for b in depended):
            status, score = "pending_verification", None
        elif len(own) < expected_own:
            status, score = "incomplete", None
        elif len(bonus) < needed_bonus:
            status, score = "open_bonus", None
        else:
            status = "confirmed"
            score = sum(b["pins"] for b in depended)
        fr.update(status=status, score=score)

    cumulative = 0
    for fr in frames:
        if fr.get("status") == "confirmed":
            cumulative += fr["score"]
            fr["cumulative"] = cumulative
        else:
            fr["cumulative"] = None

    # ---- rack rule checks ---------------------------------------------------
    rack_checks, extra_throws = _check_racks(
        throws, calls, frames, assignment, conflicts, notes
    )

    # ---- match status ---------------------------------------------------------
    if leftover and not walk_stopped:
        # balls past the tenth frame are reported by the rack pass as extra
        pass
    for seq in extra_throws:
        conflicts.append(
            {
                "code": "extra_throw",
                "message": f"throw {seq} was delivered after the game was complete",
                "throw_seq": seq,
            }
        )
    verification_pending = any(
        fr.get("status") == "pending_verification" for fr in frames
    )
    if conflicts:
        status = STATUS_CONFLICT
    elif all(fr.get("status") == "confirmed" for fr in frames):
        status = STATUS_COMPLETE
    else:
        status = STATUS_IN_PROGRESS

    out_frames = []
    for fr in frames:
        out_frames.append(
            {
                "frame": fr["index"] + 1,
                "balls": [
                    {
                        "throw_seq": b["throw_seq"],
                        "call": b["call"],
                        "pins": b["pins"],
                        "uncertain": b["uncertain"],
                    }
                    for b in fr["balls"]
                ],
                "status": fr.get("status", "not_started"),
                "score": fr.get("score"),
                "cumulative": fr.get("cumulative"),
                "depends_on": fr.get("depends_on", []),
                "bonus_from": fr.get("bonus_from", []),
            }
        )
    return {
        "player": player,
        "status": status,
        "verification_pending": verification_pending,
        "frames": out_frames,
        "confirmed_frames": [f["frame"] for f in out_frames if f["status"] == "confirmed"],
        "pending_verification_frames": [
            f["frame"] for f in out_frames if f["status"] == "pending_verification"
        ],
        "unclosed_bonus_frames": [f["frame"] for f in out_frames if f["status"] == "open_bonus"],
        "total": out_frames[-1]["cumulative"] if status == STATUS_COMPLETE else None,
        "dead_throws": dead_throws,
        "uncalled_throws": uncalled,
        "extra_throws": extra_throws,
        "unassignable_throws": unassignable,
        "rack_checks": rack_checks,
        "conflicts": conflicts,
        "notes": [n for n in notes if n],
    }


def _check_racks(throws, calls, frames, assignment, conflicts, notes):
    """Check each throw's starting deck against the rule-required deck.

    Covers fresh full racks after strikes and at frame starts, continuation
    decks for second balls, re-spotting after fouls and restoration after
    dead balls.  Positions the previous throw left undetermined cannot be
    verified; the actual rack there is noted but never back-filled as
    evidence for that earlier throw.
    """
    checks = []
    extra_throws: list[int] = []
    expected: list[int | None] = [1] * 10
    game_over = False
    for t in throws:
        seq = t["throw_seq"]
        if game_over:
            extra_throws.append(seq)
            continue
        actual = t["start_pins"]
        mismatches = []
        unverifiable = []
        for i in range(10):
            if expected[i] is None:
                unverifiable.append(i + 1)
            elif actual[i] != expected[i]:
                mismatches.append({"pin": i + 1, "expected": expected[i], "actual": actual[i]})
        checks.append(
            {
                "throw_seq": seq,
                "ok": not mismatches,
                "mismatches": mismatches,
                "unverifiable": unverifiable,
            }
        )
        if mismatches:
            conflicts.append(
                {
                    "code": "rack_mismatch",
                    "message": f"throw {seq} starts on {actual}, rule requires {expected}",
                    "throw_seq": seq,
                    "pins": [m["pin"] for m in mismatches],
                }
            )
        if unverifiable:
            notes.append(
                f"throw {seq}: deck positions {unverifiable} not verifiable from the "
                "previous throw's evidence; the actual rack there is noted but not "
                "used to complete that throw's evidence"
            )
        call = calls.get(seq)
        if call is None:
            break
        pos = assignment.get(seq)
        if call != "dead" and pos is None:
            notes.append(
                f"throw {seq}: frame assignment undecidable (earlier throw's "
                "evidence incomplete); rack checks stop here"
            )
            break
        if call == "dead":
            expected = list(actual)  # deck restored to the pre-throw state
            continue
        if call == "foul":
            fi, ball_no = pos
            if fi is not None and fi < 9 and ball_no == 1:
                expected = [1] * 10  # frame closed by the foul; fresh rack next
            elif fi == 9 and ball_no == 1:
                first = frames[9]["balls"][0]
                if first["pins"] == 10:
                    expected = list(actual)  # re-spot; ball 3 still to come
                else:
                    game_over = True  # foul closed an open tenth frame
            elif fi == 9 and ball_no == 2:
                game_over = True
            else:
                expected = list(actual)  # re-spot to the pre-foul deck
            continue
        # normal throw
        fi, ball_no = pos
        strike_state = (
            "yes" if t["fall_count"] == 10 else ("maybe" if _maybe_strike(t) else "no")
        )
        if fi < 9:
            if ball_no == 0:
                if strike_state == "yes":
                    expected = [1] * 10
                elif strike_state == "maybe":
                    expected = [None] * 10
                else:
                    expected = _remaining_after(t)
            else:
                expected = [1] * 10
        else:
            if ball_no == 0:
                if strike_state == "yes":
                    expected = [1] * 10
                elif strike_state == "maybe":
                    expected = [None] * 10
                else:
                    expected = _remaining_after(t)
            elif ball_no == 1:
                first = frames[9]["balls"][0]["throw"]
                if first["fall_count"] == 10:
                    if strike_state == "yes":
                        expected = [1] * 10
                    elif strike_state == "maybe":
                        expected = [None] * 10
                    else:
                        expected = _remaining_after(t)
                elif _maybe_strike(first):
                    expected = [None] * 10
                else:
                    s = first["fall_count"] + t["fall_count"]
                    poss = s + len(first["undetermined"]) + len(t["undetermined"])
                    if s == 10 and not (first["undetermined"] or t["undetermined"]):
                        expected = [1] * 10  # spare: fresh rack for ball 3
                    elif s < 10 <= poss:
                        expected = [None] * 10
                    else:
                        game_over = True
            else:
                game_over = True
    return checks, extra_throws
