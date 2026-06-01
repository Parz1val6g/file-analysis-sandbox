#!/usr/bin/env python3
"""Sandbox File Analysis & Ephemeral Execution Engine.

Usage:
    python engine.py <file_path>

The engine processes an untrusted input file through three air-gapped
security layers and prints a deterministic JSON result to stdout.
All diagnostic output goes to stderr.
"""

import json
import os
import sys
import traceback

# Ensure the sandbox package is importable from any CWD
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from layers.layer1_magic import validate as layer1_validate
from layers.layer2_clamav import scan as layer2_scan
from layers.layer3_sandbox import execute as layer3_execute


def emit(result: dict) -> None:
    """Write the final JSON result to stdout and exit.

    This is the ONLY function allowed to write to stdout.
    """
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()


def run_pipeline(file_path: str) -> None:
    """Execute the three-layer security pipeline.

    Stops at the first non-clean result (infected or error).
    """
    abs_path = os.path.abspath(file_path)

    # --- Layer 1: Magic Bytes & Hex Validation ---
    import sys as _sys
    print("[engine] Layer 1: Magic byte validation...", file=_sys.stderr)
    l1 = layer1_validate(abs_path)
    if l1.status != "clean":
        print("[engine] Layer 1 FAILED: {}".format(l1.reason), file=_sys.stderr)
        emit(l1.to_dict())
        sys.exit(1)
    print("[engine] Layer 1 PASSED (extension: {})".format(l1.declared_extension), file=_sys.stderr)

    # --- Layer 2: ClamAV Antivirus Scan ---
    print("[engine] Layer 2: ClamAV scan...", file=_sys.stderr)
    l2 = layer2_scan(abs_path)
    if l2.status == "infected":
        print("[engine] Layer 2 FAILED (infected): {}".format(l2.reason), file=_sys.stderr)
        emit(l2.to_dict())
        sys.exit(1)
    if l2.status == "error":
        print("[engine] Layer 2 ERROR: {}".format(l2.reason), file=_sys.stderr)
        emit(l2.to_dict())
        sys.exit(1)
    print("[engine] Layer 2 PASSED", file=_sys.stderr)

    # --- Layer 3: Ephemeral Sandbox Execution ---
    print("[engine] Layer 3: Sandbox execution...", file=_sys.stderr)
    l3 = layer3_execute(abs_path)
    if l3.status == "clean":
        print("[engine] Layer 3 PASSED — file is clean", file=_sys.stderr)
        emit(l3.to_dict())
    else:
        print("[engine] Layer 3 ERROR: {}".format(l3.reason), file=_sys.stderr)
        emit(l3.to_dict())
        sys.exit(1)


def main() -> None:
    """CLI entry point with global panic handler.

    Every code path MUST produce valid JSON on stdout. Crashes are caught
    and serialized into the error schema so the calling application never
    receives broken output.
    """
    try:
        if len(sys.argv) != 2:
            emit({"status": "error", "reason": "Usage: engine.py <file_path>"})
            sys.exit(1)

        file_path = sys.argv[1]

        if not os.path.exists(file_path):
            emit({"status": "error", "reason": "File not found: {}".format(file_path)})
            sys.exit(1)

        if not os.path.isfile(file_path):
            emit({"status": "error", "reason": "Path is not a regular file: {}".format(file_path)})
            sys.exit(1)

        run_pipeline(file_path)

    except Exception as exc:
        # Global panic handler — guarantee valid JSON regardless of failure
        emit({
            "status": "error",
            "reason": "Engine internal error: {}".format(exc),
        })
        if os.environ.get("SANDBOX_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
