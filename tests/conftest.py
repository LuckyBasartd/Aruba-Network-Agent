"""
Shared pytest configuration.

Adds the repo root to sys.path so test modules can `from aruba_agent
import ...` without an editable install. Tests run from a fresh
checkout this way: `pytest tests/` and nothing else.
"""

from __future__ import annotations

import pathlib
import sys


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
