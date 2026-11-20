"""Lane-side event stream builder.

This is the *producer* side of the lane: it assembles ``bowling.lane.event``
records from mechanical facts (deck setups, throw starts, quiet-moment probes,
settlement declarations) and serialises them with :mod:`telber.build`, the
independent byte builder — the lane does not share code with the decoder that
will later read its log.

Positions are always 1-based pin numbers 1..10.  A deck is a list of ten
0/1 integers (1 = pin standing on that position).
"""

from __future__ import annotations

from telber import build as B

KIND_RACK = 1
KIND_THROW = 2
KIND_OBSERVE = 3
KIND_SETTLE = 4

KIND_NAMES = {
    KIND_RACK: "rack",
    KIND_THROW: "throw_start",
    KIND_OBSERVE: "observe",
    KIND_SETTLE: "settle",
}

REASON_INITIAL = 0
REASON_RERACK = 1
REASON_RESPOT = 2
REASON_REMOVE = 3

FULL_DECK = [1] * 10


def _event(event_seq: int, kind: int, lane: int | None, payload: bytes) -> bytes:
    body = B.integer(event_seq, cls="context", number=0)
    body += B.integer(kind, cls="context", number=1)
    if lane is not None:
        body += B.integer(lane, cls="context", number=2)
    body += payload
    return B.seq(body)


def rack_event(event_seq: int, pins: list[int], reason: int | None, lane: int | None = 1) -> bytes:
    inner = B.octets(bytes(pins), cls="context", number=0)
    if reason is not None:
        inner += B.integer(reason, cls="context", number=1)
    payload = B.explicit(B.tag("context", True, 3), B.seq(inner))
    return _event(event_seq, KIND_RACK, lane, payload)


def throw_event(event_seq: int, throw_seq: int, pins: list[int], lane: int | None = 1) -> bytes:
    inner = B.integer(throw_seq, cls="context", number=0)
    inner += B.octets(bytes(pins), cls="context", number=1)
    payload = B.explicit(B.tag("context", True, 4), B.seq(inner))
    return _event(event_seq, KIND_THROW, lane, payload)


def observe_event(
    event_seq: int,
    throw_seq: int,
    obs_seq: int,
    mask: list[int],
    standing: list[int],
    lane: int | None = 1,
) -> bytes:
    inner = B.integer(throw_seq, cls="context", number=0)
    inner += B.integer(obs_seq, cls="context", number=1)
    inner += B.octets(bytes(mask), cls="context", number=2)
    inner += B.octets(bytes(standing), cls="context", number=3)
    payload = B.explicit(B.tag("context", True, 5), B.seq(inner))
    return _event(event_seq, KIND_OBSERVE, lane, payload)


def settle_event(event_seq: int, throw_seq: int, final_obs: list[int], lane: int | None = 1) -> bytes:
    inner = B.integer(throw_seq, cls="context", number=0)
    inner += B.octets(bytes(final_obs), cls="context", number=1)
    payload = B.explicit(B.tag("context", True, 6), B.seq(inner))
    return _event(event_seq, KIND_SETTLE, lane, payload)


class LaneSimulator:
    """Scriptable ten-pin lane.

    Tracks the actual deck, emits the four event records in log order and
    applies real falls to the deck.  Observation plans describe, per probe,
    which positions were looked at and whether the probe is part of the
    final stable-state coverage declared by the settlement record.
    """

    def __init__(self, lane: int = 1) -> None:
        self.lane = lane
        self.event_seq = 0
        self.deck: list[int] | None = None
        self.parts: list[bytes] = []

    def _emit(self, record: bytes) -> None:
        self.event_seq += 1
        self.parts.append(record)

    # -- deck setups ------------------------------------------------------
    def rack(self, pins: list[int], reason: int = REASON_RERACK) -> None:
        assert len(pins) == 10 and all(p in (0, 1) for p in pins)
        self.deck = list(pins)
        self._emit(rack_event(self.event_seq + 1, self.deck, reason, self.lane))

    def rack_full(self, reason: int = REASON_RERACK) -> None:
        self.rack(FULL_DECK, reason)

    # -- throws -------------------------------------------------------------
    def throw(
        self,
        throw_seq: int,
        down: list[int] | tuple[int, ...] = (),
        obs: list[tuple[list[int], bool]] | None = None,
        settle: bool = True,
    ) -> None:
        """Emit one throw.

        ``down``    positions (1..10) that actually fall on this throw.
        ``obs``     probe plan: list of ``(positions_looked_at, is_final)``.
                    Defaults to one final full-deck probe.  Probes flagged
                    final are listed by the settlement record; others are
                    earlier quiet moments only.
        ``settle``  emit the settlement record (skipped only to model a
                    missing settlement).
        """
        assert self.deck is not None, "throw before any rack"
        for p in down:
            assert 1 <= p <= 10 and self.deck[p - 1] == 1, f"pin {p} not standing"
        self._emit(throw_event(self.event_seq + 1, throw_seq, self.deck, self.lane))
        after = list(self.deck)
        for p in down:
            after[p - 1] = 0
        if obs is None:
            obs = [(list(range(1, 11)), True)]
        final_ids: list[int] = []
        for obs_seq, (positions, is_final) in enumerate(obs, start=1):
            mask = [1 if (i + 1) in positions else 0 for i in range(10)]
            standing = [after[i] if mask[i] else 0 for i in range(10)]
            self._emit(
                observe_event(self.event_seq + 1, throw_seq, obs_seq, mask, standing, self.lane)
            )
            if is_final:
                final_ids.append(obs_seq)
        if settle:
            self._emit(settle_event(self.event_seq + 1, throw_seq, final_ids, self.lane))
        self.deck = after

    # -- serialisation ------------------------------------------------------
    def stream(self) -> bytes:
        return b"".join(self.parts)
