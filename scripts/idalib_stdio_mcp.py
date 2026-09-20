"""Compatibility launcher for the private worker."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
runpy.run_module("ida_assistant.idalib_worker", run_name="__main__")
