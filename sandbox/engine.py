#!/usr/bin/env python3
"""Sandbox File Analysis & Ephemeral Execution Engine.

Usage:
    python engine.py <file_path>

The engine processes an untrusted input file through three air-gapped
security layers and prints a deterministic JSON result to stdout.
All diagnostic, debug, and container output is forcibly redirected to stderr
or isolated log files. Nothing but the final JSON contract reaches stdout.
"""

import contextlib
import io
import json
import os
import sys
import traceback

# Ensure the sandbox package is importable from any CWD
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from validation import validate_input
from cleanup import install_cleanup, create_temp_file, register_cleanup_path, unregister_cleanup_path
from layers.layer1_magic import validate as layer1_validate
from layers.layer2_clamav import scan as layer2_scan
from layers.layer3_sandbox import execute as layer3_execute
from config import LOG_DIR


# Capture the real stdout before we potentially replace it.
# emit() MUST write to THIS reference, never to sys.stdout
_REAL_STDOUT = sys.stdout


def emit(result: dict) -> None:
    """Write the final JSON result to the real stdout.

    This is the ONLY function allowed to write to stdout. It bypasses
    any stdout redirection that may be in effect during pipeline execution.
    """
    _REAL_STDOUT.write(json.dumps(result, separators=(",", ":")))
    _REAL_STDOUT.write("\n")
    _REAL_STDOUT.flush()


@contextlib.contextmanager
def _isolated_stdout():
    """Context manager that forcibly redirects sys.stdout to devnull.

    Ensures that no code path during pipeline execution accidentally
    leaks diagnostic output to stdout. Only emit() can reach real stdout
    because it holds a captured reference.
    """
    old_stdout = sys.stdout
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
        yield
    finally:
        sys.stdout.close()
        sys.stdout = old_stdout


def run_pipeline(file_path: str) -> None:
    """Execute the three-layer security pipeline inside isolated stdout context.

    Stops at the first non-clean result (infected or error).
    All diagnostic logging goes to stderr.
    """
    abs_path = os.path.abspath(file_path)

    # --- Layer 1: Magic Bytes & Hex Validation ---
    print("[engine] Layer 1: Magic byte validation...", file=sys.stderr)
    l1 = layer1_validate(abs_path)
    if l1.status != "clean":
        print("[engine] Layer 1 FAILED: {}".format(l1.reason), file=sys.stderr)
        emit(l1.to_dict())
        sys.exit(1)
    print("[engine] Layer 1 PASSED (extension: {})".format(l1.declared_extension), file=sys.stderr)

    # --- Layer 2: ClamAV Antivirus Scan ---
    print("[engine] Layer 2: ClamAV scan...", file=sys.stderr)
    l2 = layer2_scan(abs_path)
    if l2.status == "infected":
        print("[engine] Layer 2 FAILED (infected): {}".format(l2.reason), file=sys.stderr)
        emit(l2.to_dict())
        sys.exit(1)
    if l2.status == "error":
        print("[engine] Layer 2 ERROR: {}".format(l2.reason), file=sys.stderr)
        emit(l2.to_dict())
        sys.exit(1)
    print("[engine] Layer 2 PASSED", file=sys.stderr)

    # --- Layer 3: Ephemeral Sandbox Execution ---
    print("[engine] Layer 3: Sandbox execution...", file=sys.stderr)
    l3 = layer3_execute(abs_path)
    if l3.status == "clean":
        print("[engine] Layer 3 PASSED — file is clean", file=sys.stderr)
        emit(l3.to_dict())
    else:
        print("[engine] Layer 3 ERROR: {}".format(l3.reason), file=sys.stderr)
        emit(l3.to_dict())
        sys.exit(1)


def main() -> None:
    """CLI entry point with global panic handler.

    Every code path MUST produce valid JSON on stdout. Crashes are caught
    and serialized into the error schema so the calling application never
    receives broken output.
    """
    # --- Install cleanup hooks before anything else ---
    install_cleanup()

    try:
        # --- Argument validation ---
        if len(sys.argv) != 2:
            emit({"status": "error", "reason": "Usage: engine.py <file_path>"})
            sys.exit(1)

        file_path = sys.argv[1]

        # --- Host-side input validation (size, perms, traversal) ---
        validation_error = validate_input(file_path)
        if validation_error is not None:
            emit(validation_error)
            sys.exit(1)

        # --- Run the pipeline with stdout isolation ---
        with _isolated_stdout():
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
