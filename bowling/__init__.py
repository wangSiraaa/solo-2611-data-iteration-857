"""bowling — ten-pin lane mechanical log and referee-sheet replay on telber.

Layers
------
``schema``    loads the ``bowling.lane.event`` TLV directory (schemas/bowling_lane_v1.json)
``lane``      lane-side event stream builder (independent byte construction)
``physical``  repository -> per-throw physical record (confirmed down/standing/
              undetermined pin positions with sources and contradictions)
``replay``    physical record + referee sheet -> ten-frame confirmed scores,
              unclosed bonuses, positions needing verification, match status

The physical record is the only bridge between the lane log and scoring:
rack records are never used as throw evidence, so a later full re-rack can
never silently complete an earlier throw's evidence.
"""

from .schema import BOWLING_SCHEMA_PATH, load_schema

__all__ = ["BOWLING_SCHEMA_PATH", "load_schema"]
