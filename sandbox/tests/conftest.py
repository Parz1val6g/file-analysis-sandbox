"""Shared test configuration for sandbox engine tests.

Auto-detects the C binary (sandbox_engine.exe on Windows,
sandbox_engine on Unix) and falls back to the Python engine.
"""

import os
import sys

# Determine the sandbox directory
SANDBOX_DIR = os.path.join(os.path.dirname(__file__), "..")
ENGINE_PY = os.path.join(SANDBOX_DIR, "engine.py")

# Detect C binary
if sys.platform == "win32":
    ENGINE_C = os.path.join(SANDBOX_DIR, "sandbox_engine.exe")
else:
    ENGINE_C = os.path.join(SANDBOX_DIR, "sandbox_engine")

# Use C binary if it exists, otherwise fall back to Python
ENGINE_PATH = ENGINE_C if os.path.isfile(ENGINE_C) else ENGINE_PY

FIXTURES_DIR = os.path.join(SANDBOX_DIR, "fixtures")
