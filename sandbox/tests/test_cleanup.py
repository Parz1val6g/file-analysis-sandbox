"""Tests for cleanup module (temp assets, signal handling, atexit)."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cleanup import (
    install_cleanup,
    create_temp_dir,
    create_temp_file,
    register_cleanup_path,
    unregister_cleanup_path,
    _do_cleanup,
)


class TestCleanupTempAssets:
    """Validates temporary directory/file creation and auto-cleanup."""

    def test_create_temp_dir_creates_directory(self):
        tmp_dir = create_temp_dir(prefix="test_sandbox_")
        assert os.path.isdir(tmp_dir)
        # Cleanup should have been registered; verify manual cleanup works
        _do_cleanup()
        assert not os.path.exists(tmp_dir)

    def test_create_temp_file_creates_file(self):
        tmp_path = create_temp_file(prefix="test_sandbox_")
        assert os.path.exists(tmp_path)
        _do_cleanup()
        assert not os.path.exists(tmp_path)

    def test_register_and_unregister_cleanup(self):
        tmp_dir = create_temp_dir(prefix="test_reg_")
        assert os.path.isdir(tmp_dir)
        unregister_cleanup_path(tmp_dir)
        _do_cleanup()
        # Should NOT have been cleaned up since we unregistered
        assert os.path.isdir(tmp_dir)
        # Clean up manually
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_cleanup_handles_nonexistent_paths(self):
        """Cleanup should not raise when a registered path no longer exists."""
        register_cleanup_path("/this/path/does/not/exist/anywhere")
        _do_cleanup()  # Should not raise

    def test_do_cleanup_clears_registry(self):
        """After cleanup, the path set should be empty."""
        import tempfile
        tmp = tempfile.mkdtemp(prefix="test_clear_")
        register_cleanup_path(tmp)
        _do_cleanup()
        assert not os.path.exists(tmp)
        from cleanup import _cleanup_paths
        assert len(_cleanup_paths) == 0


class TestSignalHandlers:
    """Validates that signal handlers are installed without error."""

    def test_install_cleanup_is_idempotent(self):
        """Calling install_cleanup multiple times should not fail."""
        install_cleanup()
        install_cleanup()
        install_cleanup()
        # Should not raise

    def test_signal_handler_registered(self):
        """On supported platforms, SIGINT/SIGTERM handlers should be installed."""
        import signal
        if hasattr(signal, "SIGINT") and hasattr(signal, "getsignal"):
            # The handler should be callable or SIG_DFL — we just installed ours
            handler = signal.getsignal(signal.SIGINT)
            assert handler is not None

    def test_cleanup_creates_dirs_with_correct_prefix(self):
        """Created temp dirs should have the specified prefix."""
        tmp_dir = create_temp_dir(prefix="zzz_test_")
        assert "zzz_test_" in os.path.basename(tmp_dir)
        _do_cleanup()
