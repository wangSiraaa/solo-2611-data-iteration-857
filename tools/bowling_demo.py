#!/usr/bin/env python3
"""Entry point for the bowling lane demo; see :mod:`bowling.demo`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bowling.demo import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
