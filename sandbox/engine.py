#!/usr/bin/env python3
"""Sandbox File Analysis & Ephemeral Execution Engine.

Usage:
    python engine.py <file_path>

The engine processes an untrusted input file through three air-gapped
security layers and prints a deterministic JSON result to stdout.
ALL diagnostic, debug, and container output is forcibly routed to stderr.
The real stdout file descriptor is captured at startup and ONLY the final
JSON contract is written to it — nothing else.
"""

import json
import os
import sys
import traceback

# Ensure the sandbox package is importable from any CWD
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from validation import validate_input
from cleanup import install_cleanup
from layers.layer1_magic import validate as layer1_validate
from layers.layer2_clamav import scan as layer2_scan
from layers.layer3_sandbox import execute as layer3_execute


# Capture the OS-level stdout file descriptor BEFORE any redirection.
# This is the ONLY reference allowed to write final JSON to stdout.
# sys.__stdout__ is the original stdout at process start — it survives
# any sys.stdout reassignment.
_REAL_STDOUT = sys.__stdout__


def _redirect_stdout_to_devnull() -> None:
    """Permanently redirect sys.stdout to /dev/null for this process.

    After this call, print() without an explicit file= argument
    writes to the void. Only _REAL_STDOUT (sys.__stdout__) can reach
    the parent application's stdout.
    """
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
    except (OSError, IOError):
        pass


def emit(result: dict) -> None:
    """Write the final JSON result to the OS-level stdout.

    This is the ONLY function that writes to real stdout. It uses
    the captured __stdout__ reference, which survives all sys.stdout
    reassignments.
    """
    try:
        _REAL_STDOUT.write(json.dumps(result, separators=(",", ":")))
        _REAL_STDOUT.write("\n")
        _REAL_STDOUT.flush()
    except (OSError, IOError, ValueError):
        pass


def _log(msg: str) -> None:
    """Write a diagnostic message to stderr. Safe to call at any time."""
    try:
        sys.stderr.write("[engine] {}\n".format(msg))
        sys.stderr.flush()
    except (OSError, IOError):
        pass


def run_pipeline(file_path: str) -> None:
    """Execute the three-layer security pipeline.

    - Layer 1 failure (infected/error) halts immediately.
    - Layer 2 failure (ClamAV error/unavailable) is gracefully bypassed
      with a flag in the final metadata.
    - Layer 2 infected result halts immediately.
    - Layer 3 runs regardless of Layer 2 outcome.
    """
    abs_path = os.path.abspath(file_path)
    clamav_skipped = False
    clamav_skip_reason = ""

    # --- Layer 1: Magic Bytes & Hex Validation ---
    _log("Layer 1: Magic byte validation...")
    l1 = layer1_validate(abs_path)
    if l1.status != "clean":
        _log("Layer 1 FAILED: {}".format(l1.reason))
        emit(l1.to_dict())
        sys.exit(1)
    _log("Layer 1 PASSED (extension: {})".format(l1.declared_extension))

    # --- Layer 2: ClamAV Antivirus Scan ---
    _log("Layer 2: ClamAV scan...")
    l2 = layer2_scan(abs_path)
    if l2.status == "infected":
        _log("Layer 2 FAILED (infected): {}".format(l2.reason))
        emit(l2.to_dict())
        sys.exit(1)
    if l2.status == "error":
        # Graceful degradation: ClamAV unavailable or failed,
        # log the warning and continue to Layer 3.
        _log("Layer 2 BYPASSED: {}".format(l2.reason))
        clamav_skipped = True
        clamav_skip_reason = l2.reason
    else:
        _log("Layer 2 PASSED")

    # --- Layer 3: Ephemeral Sandbox Execution ---
    _log("Layer 3: Sandbox execution...")
    l3 = layer3_execute(abs_path)
    if l3.status == "clean":
        _log("Layer 3 PASSED — file is clean")

        # If ClamAV was bypassed, annotate the metadata
        if clamav_skipped:
            l3.metadata["clamav_skipped"] = True
            l3.metadata["clamav_skip_reason"] = clamav_skip_reason

        emit(l3.to_dict())
    else:
        _log("Layer 3 ERROR: {}".format(l3.reason))
        emit(l3.to_dict())
        sys.exit(1)


def main() -> None:
    """CLI entry point with global panic handler and stdout isolation.

    Every code path MUST produce valid JSON to the real stdout.
    Crashes are caught and serialized into the error schema so the
    calling application never receives broken output.
    """
    # --- Install cleanup hooks before anything else ---
    install_cleanup()

    # --- Permanently redirect sys.stdout to devnull ---
    # From this point forward, print() goes nowhere unless explicitly
    # directed to sys.stderr or to _REAL_STDOUT via emit().
    _redirect_stdout_to_devnull()

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

        # --- Run the pipeline ---
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
