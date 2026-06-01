"""Host-side input validation for the sandbox file analysis engine.

Validates file existence, size caps, read permissions, and prevents
path traversal attacks before any security layer is invoked.
"""

import os
import stat

from config import MAX_FILE_SIZE_BYTES


def validate_input(file_path: str) -> dict | None:
    """Validate the input file before pipeline execution.

    Returns None if the file passes all checks.
    Returns an error dict (suitable for direct emit) if validation fails.
    """
    # --- Resolve to absolute real path to prevent symlink/traversal attacks ---
    try:
        abs_path = os.path.realpath(os.path.abspath(file_path))
    except (OSError, ValueError) as exc:
        return {"status": "error", "reason": "Path resolution failed: {}".format(exc)}

    # --- Basic existence checks ---
    if not os.path.exists(abs_path):
        return {"status": "error", "reason": "File not found: {}".format(abs_path)}

    if not os.path.isfile(abs_path):
        return {"status": "error", "reason": "Path is not a regular file: {}".format(abs_path)}

    # --- Size cap (anti-DoS: reject zip bombs and excessively large files) ---
    try:
        file_size = os.path.getsize(abs_path)
    except OSError as exc:
        return {"status": "error", "reason": "Cannot determine file size: {}".format(exc)}

    if file_size > MAX_FILE_SIZE_BYTES:
        max_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        actual_mb = file_size / (1024 * 1024)
        return {
            "status": "error",
            "reason": "File too large: {:.1f} MB exceeds maximum allowed size of {} MB".format(
                actual_mb, max_mb
            ),
        }

    if file_size == 0:
        return {"status": "error", "reason": "File is empty (0 bytes) — nothing to analyze"}

    # --- Read permission check ---
    if not os.access(abs_path, os.R_OK):
        return {"status": "error", "reason": "Permission denied: cannot read file"}

    # --- Path traversal prevention ---
    # Convert to normalized absolute path and verify no directory escapes
    norm = os.path.normpath(abs_path)
    if ".." in norm.split(os.sep):
        return {"status": "error", "reason": "Path traversal detected in file path"}

    return None
