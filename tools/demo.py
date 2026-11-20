#!/usr/bin/env python3
"""Entry point kept at tools/demo.py for discoverability.

Equivalent to ``python3 -m telber.demo``; see :mod:`telber.demo`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from telber.demo import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
