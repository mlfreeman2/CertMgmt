#!/usr/bin/env python3
"""Compatibility launcher for the packaged driver CLI."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from certmgmt.compat import main

raise SystemExit(main('driver-truenas-scale.py'))
