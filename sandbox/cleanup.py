"""Host-side cleanup logic for the sandbox file analysis engine.

Ensures temporary sandbox assets are wiped on completion, failure,
or interrupt signals. Registers atexit handlers and signal hooks.
"""

import atexit
import os
import shutil
import signal
import sys
import tempfile

from config import LOG_DIR


# Registry of paths to clean up on exit
_cleanup_paths = set()
_cleanup_registered = False


def register_cleanup_path(path: str) -> None:
    """Register a file or directory path to be cleaned up on process exit."""
    _cleanup_paths.add(os.path.abspath(path))


def unregister_cleanup_path(path: str) -> None:
    """Remove a path from the cleanup registry (if it was cleaned up manually)."""
    _cleanup_paths.discard(os.path.abspath(path))


def _do_cleanup() -> None:
    """Execute all registered cleanup operations silently.

    Failures during cleanup are suppressed — we do not want cleanup
    errors to interfere with the engine's JSON output contract.
    """
    for path in list(_cleanup_paths):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            elif os.path.isfile(path):
                os.unlink(path)
        except (OSError, IOError):
            pass
    _cleanup_paths.clear()


def _signal_handler(signum: int, _frame) -> None:
    """Handle interrupt signals by emitting error JSON and cleaning up.

    SIGINT  (2)  — Ctrl+C
    SIGTERM (15) — kill command
    """
    signal_names = {
        signal.SIGINT: "SIGINT",
        signal.SIGTERM: "SIGTERM",
    }
    name = signal_names.get(signum, "SIGNAL-{}".format(signum))

    # Emit error JSON to stdout before the process dies
    sys.stdout.write('{"status":"error","reason":"Engine interrupted by {}"}\n'.format(name))
    sys.stdout.flush()

    _do_cleanup()
    sys.exit(1)


def install_signal_handlers() -> None:
    """Install signal handlers for graceful shutdown on SIGINT/SIGTERM.

    Only installs handlers on platforms that support them (Unix).
    On Windows, signal handling is limited but atexit still works.
    """
    if hasattr(signal, "SIGINT"):
        try:
            signal.signal(signal.SIGINT, _signal_handler)
        except (ValueError, OSError):
            pass

    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, _signal_handler)
        except (ValueError, OSError):
            pass


def install_cleanup() -> None:
    """Install the global cleanup hooks (atexit + signal handlers).

    Safe to call multiple times — only installs once.
    """
    global _cleanup_registered
    if _cleanup_registered:
        return
    _cleanup_registered = True

    atexit.register(_do_cleanup)
    install_signal_handlers()


def create_temp_dir(prefix: str = "sandbox_") -> str:
    """Create a temporary directory that will be auto-cleaned on exit.

    Returns the path to the created directory.
    """
    install_cleanup()
    tmp_dir = tempfile.mkdtemp(prefix=prefix)
    register_cleanup_path(tmp_dir)
    return tmp_dir


def create_temp_file(suffix: str = ".tmp", prefix: str = "sandbox_") -> str:
    """Create a temporary file that will be auto-cleaned on exit.

    Returns the path to the created file. The caller is responsible
    for writing content and closing the file.
    """
    install_cleanup()
    fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.close(fd)  # We just want the path; caller opens it
    register_cleanup_path(tmp_path)
    return tmp_path
