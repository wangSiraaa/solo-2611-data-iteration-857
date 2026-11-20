"""Per-throw physical record built from the telber fact repository.

Reads the imported lane event stream back out of the SQLite fact store and
decides, for every physical throw and every one of the ten fixed starting
positions, one of:

* ``down``      — confirmed fallen: some probe saw the position down.  A pin
                  that fell cannot stand back up within one throw, so any
                  sighting of it down is decisive.
* ``standing``  — confirmed standing: a probe *declared final by the
                  settlement record* saw the position up at the stable state.
* ``unknown``   — cannot be decided: never probed, or probed standing only
                  before settlement (it may have fallen afterwards).
* ``empty``     — the position was empty when the throw started; it never
                  counts as a fallen pin.

Contradictions are reported per throw, never smoothed over:

* a pin seen down and later seen standing again (it cannot re-stand);
* two final probes disagreeing on an overlapping position;
* any probe after a final probe disagreeing with the final state;
* a settlement declaring an unknown observation id;
* observations or settlements for a throw that never started;
* a throw start whose deck differs from the rack record immediately before it.

Rack records are kept as their own actual deck-setup records.  They are never
used as evidence for a throw's outcome: a later full re-rack cannot silently
complete the previous throw's evidence.
"""

from __future__ import annotations

from .lane import KIND_NAMES, KIND_OBSERVE, KIND_RACK, KIND_SETTLE, KIND_THROW

PINS = tuple(range(1, 11))


def events_from_repository(repo, import_id: int) -> list[dict]:
    """Reconstruct ordered lane events from the stored relation rows."""
    records = {r["ordinal"]: r for r in repo.records(import_id)}
    by_record: dict[int, dict[str, dict]] = {}
    for row in repo.relation_rows(import_id):
        if row["present"]:
            by_record.setdefault(row["record_ordinal"], {})[row["path"]] = row
    events = []
    for ordinal in sorted(by_record):
        fields = by_record[ordinal]
        rec = records[ordinal]
        ev = {
            "record_ordinal": ordinal,
            "start_offset": rec["start_offset"],
            "end_offset": rec["end_offset"],
            "event_seq": fields["event_seq"]["int_value"],
            "kind": fields["kind"]["int_value"],
            "lane": fields["lane"]["int_value"] if "lane" in fields else None,
        }
        kind = ev["kind"]
        if kind == KIND_RACK:
            ev["pins"] = list(fields["rack.pins"]["bytes_value"])
            ev["reason"] = fields["rack.reason"]["int_value"] if "rack.reason" in fields else None
        elif kind == KIND_THROW:
            ev["throw_seq"] = fields["throw.throw_seq"]["int_value"]
            ev["pins"] = list(fields["throw.pins"]["bytes_value"])
        elif kind == KIND_OBSERVE:
            ev["throw_seq"] = fields["observe.throw_seq"]["int_value"]
            ev["obs_seq"] = fields["observe.obs_seq"]["int_value"]
            ev["mask"] = list(fields["observe.mask"]["bytes_value"])
            ev["standing"] = list(fields["observe.standing"]["bytes_value"])
        elif kind == KIND_SETTLE:
            ev["throw_seq"] = fields["settle.throw_seq"]["int_value"]
            ev["final_obs"] = list(fields["settle.final_obs"]["bytes_value"])
        events.append(ev)
    return events


def _source(ev: dict) -> dict:
    return {
        "record_ordinal": ev["record_ordinal"],
        "start_offset": ev["start_offset"],
        "end_offset": ev["end_offset"],
    }


def _check_deck(name: str, pins: list[int], ev: dict, issues: list[dict]) -> None:
    if len(pins) != 10 or any(p not in (0, 1) for p in pins):
        issues.append(
            {
                "code": "bad_deck",
                "message": f"{name} must be ten 0/1 positions, got {pins!r}",
                "source": _source(ev),
            }
        )


def build_physical_record(events: list[dict], *, product_id: str, import_info: dict) -> dict:
    """Reduce ordered lane events to the per-throw physical record."""
    throws: dict[int, dict] = {}
    throw_order: list[int] = []
    racks: list[dict] = []
    orphans: list[dict] = []
    log_issues: list[dict] = []
    prev_seq = 0
    prev_rack: dict | None = None

    for ev in events:
        if ev["event_seq"] <= prev_seq:
            log_issues.append(
                {
                    "code": "event_seq_not_increasing",
                    "message": f"event_seq {ev['event_seq']} follows {prev_seq}",
                    "source": _source(ev),
                }
            )
        prev_seq = ev["event_seq"]
        kind = ev["kind"]
        if kind not in KIND_NAMES:
            log_issues.append(
                {"code": "unknown_kind", "message": f"unknown event kind {kind}", "source": _source(ev)}
            )
            prev_rack = None
            continue

        if kind == KIND_RACK:
            _check_deck("rack.pins", ev["pins"], ev, log_issues)
            racks.append(
                {"pins": ev["pins"], "reason": ev["reason"], "source": _source(ev)}
            )
            prev_rack = ev
            continue

        if kind == KIND_THROW:
            seq = ev["throw_seq"]
            _check_deck("throw.pins", ev["pins"], ev, log_issues)
            if seq in throws:
                log_issues.append(
                    {
                        "code": "duplicate_throw",
                        "message": f"throw_seq {seq} started twice",
                        "source": _source(ev),
                    }
                )
            else:
                if prev_rack is not None and prev_rack["pins"] != ev["pins"]:
                    log_issues.append(
                        {
                            "code": "throw_start_rack_mismatch",
                            "message": (
                                f"throw {seq} starts on {ev['pins']} but the rack record "
                                f"immediately before shows {prev_rack['pins']}"
                            ),
                            "throw_seq": seq,
                            "source": _source(ev),
                        }
                    )
                throws[seq] = {
                    "throw_seq": seq,
                    "start_pins": ev["pins"],
                    "start_source": _source(ev),
                    "observations": [],
                    "obs_by_seq": {},
                    "final_ids": [],
                    "settle_sources": [],
                    "contradictions": [],
                }
                throw_order.append(seq)
            prev_rack = None
            continue

        # observe / settle need a started throw
        seq = ev["throw_seq"]
        target = throws.get(seq)
        if target is None:
            orphans.append(
                {
                    "code": "event_for_unknown_throw",
                    "message": f"{KIND_NAMES[kind]} references throw_seq {seq} which never started",
                    "throw_seq": seq,
                    "source": _source(ev),
                }
            )
            prev_rack = None
            continue
        if kind == KIND_OBSERVE:
            _check_deck("observe.mask", ev["mask"], ev, target["contradictions"])
            _check_deck("observe.standing", ev["standing"], ev, target["contradictions"])
            if ev["obs_seq"] in target["obs_by_seq"]:
                target["contradictions"].append(
                    {
                        "code": "duplicate_observation",
                        "message": f"obs_seq {ev['obs_seq']} repeated for throw {seq}",
                        "source": _source(ev),
                    }
                )
            else:
                obs = {
                    "obs_seq": ev["obs_seq"],
                    "mask": ev["mask"],
                    "standing": ev["standing"],
                    "final": False,
                    "source": _source(ev),
                }
                target["observations"].append(obs)
                target["obs_by_seq"][ev["obs_seq"]] = obs
        else:  # KIND_SETTLE
            target["final_ids"].extend(ev["final_obs"])
            target["settle_sources"].append(_source(ev))
        prev_rack = None

    out_throws = [_finalize_throw(throws[seq]) for seq in throw_order]
    return {
        "schema": "bowling.lane.event",
        "product_id": product_id,
        "import": import_info,
        "throws": out_throws,
        "racks": racks,
        "orphan_events": orphans,
        "log_issues": log_issues,
        "evidence_rule": (
            "per-throw outcomes come only from that throw's observe/settle "
            "records; rack records are actual deck setups and are never used "
            "as throw evidence"
        ),
    }


def _finalize_throw(t: dict) -> dict:
    obs_list = t["observations"]
    obs_by_seq = t["obs_by_seq"]
    final_ids: set[int] = set()
    for fid in t["final_ids"]:
        if fid not in obs_by_seq:
            t["contradictions"].append(
                {
                    "code": "settle_unknown_observation",
                    "message": f"settlement declares obs_seq {fid} final, but throw "
                    f"{t['throw_seq']} has no such observation",
                    "throw_seq": t["throw_seq"],
                    "sources": t["settle_sources"],
                }
            )
        else:
            final_ids.add(fid)
    for obs in obs_list:
        obs["final"] = obs["obs_seq"] in final_ids

    positions = []
    confirmed_down: list[int] = []
    confirmed_standing: list[int] = []
    undetermined: list[int] = []
    for pin in PINS:
        i = pin - 1
        if t["start_pins"][i] == 0:
            positions.append({"pin": pin, "started": 0, "state": "empty", "source": None, "note": None})
            continue
        sightings = []  # (order, value 1=standing/0=down, obs)
        for order, obs in enumerate(obs_list):
            if len(obs["mask"]) == 10 and len(obs["standing"]) == 10 and obs["mask"][i] == 1:
                sightings.append((order, obs["standing"][i], obs))
        # contradiction: pin re-stands after being seen down
        seen_down_at = None
        for order, value, obs in sightings:
            if value == 0 and seen_down_at is None:
                seen_down_at = obs
            elif value == 1 and seen_down_at is not None:
                t["contradictions"].append(
                    {
                        "code": "pin_restanding",
                        "message": f"pin {pin} of throw {t['throw_seq']} seen down by obs "
                        f"{seen_down_at['obs_seq']} then standing again by obs {obs['obs_seq']}",
                        "throw_seq": t["throw_seq"],
                        "pins": [pin],
                        "sources": [_source_ref(seen_down_at), _source_ref(obs)],
                    }
                )
        finals = [(o, v, ob) for o, v, ob in sightings if ob["final"]]
        # contradiction: final probes disagree where they overlap
        for a in range(len(finals)):
            for b in range(a + 1, len(finals)):
                if finals[a][1] != finals[b][1]:
                    t["contradictions"].append(
                        {
                            "code": "final_observations_disagree",
                            "message": f"final observations {finals[a][2]['obs_seq']} and "
                            f"{finals[b][2]['obs_seq']} disagree on pin {pin} of throw {t['throw_seq']}",
                            "throw_seq": t["throw_seq"],
                            "pins": [pin],
                            "sources": [_source_ref(finals[a][2]), _source_ref(finals[b][2])],
                        }
                    )
        # contradiction: a probe after a final probe disagrees with the final state
        for order, value, obs in sightings:
            for forder, fvalue, fobs in finals:
                if order > forder and value != fvalue:
                    t["contradictions"].append(
                        {
                            "code": "post_final_observation_disagrees",
                            "message": f"obs {obs['obs_seq']} of throw {t['throw_seq']} reports pin "
                            f"{pin} after final obs {fobs['obs_seq']} with a different state",
                            "throw_seq": t["throw_seq"],
                            "pins": [pin],
                            "sources": [_source_ref(fobs), _source_ref(obs)],
                        }
                    )
        downs = [(o, ob) for o, v, ob in sightings if v == 0]
        final_ups = [(o, ob) for o, v, ob in finals if v == 1]
        if downs:
            state, source, note = "down", _source_ref(downs[0][1]), None
            confirmed_down.append(pin)
        elif final_ups:
            state, source, note = "standing", _source_ref(final_ups[0][1]), None
            confirmed_standing.append(pin)
        elif sightings:
            state, source, note = (
                "unknown",
                _source_ref(sightings[-1][2]),
                "seen standing but not covered by any final observation",
            )
            undetermined.append(pin)
        else:
            state, source, note = "unknown", None, "never observed"
            undetermined.append(pin)
        positions.append({"pin": pin, "started": 1, "state": state, "source": source, "note": note})

    return {
        "throw_seq": t["throw_seq"],
        "start_pins": t["start_pins"],
        "start_source": t["start_source"],
        "observations": [
            {
                "obs_seq": o["obs_seq"],
                "mask": o["mask"],
                "standing": o["standing"],
                "final": o["final"],
                "source": o["source"],
            }
            for o in obs_list
        ],
        "settled": bool(final_ids),
        "positions": positions,
        "confirmed_down": confirmed_down,
        "confirmed_standing": confirmed_standing,
        "undetermined": undetermined,
        "fall_count": len(confirmed_down),
        "contradictions": t["contradictions"],
    }


def _source_ref(obs: dict) -> dict:
    return {"obs_seq": obs["obs_seq"], **obs["source"]}


def physical_record_from_repository(repo, import_id: int) -> dict:
    """Build the physical record from an open repository."""
    info = repo.import_info(import_id)
    events = events_from_repository(repo, import_id)
    return build_physical_record(
        events,
        product_id=info.product_id,
        import_info=info.as_dict(),
    )
