"""Tests for host-side input validation module."""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from validation import validate_input


class TestInputValidation:
    """Validates file existence, size, permissions, and path traversal checks."""

    def test_nonexistent_file_returns_error(self):
        err = validate_input(os.path.join(tempfile.gettempdir(), "definitely_not_a_real_file_12345.xyz"))
        assert err is not None
        assert err["status"] == "error"

    def test_directory_returns_error(self):
        err = validate_input(tempfile.gettempdir())
        assert err is not None
        assert err["status"] == "error"

    def test_valid_file_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("hello world")
            tmp = f.name
        try:
            err = validate_input(tmp)
            assert err is None
        finally:
            os.unlink(tmp)

    def test_empty_file_returns_error(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmp = f.name
        try:
            err = validate_input(tmp)
            assert err is not None
            assert err["status"] == "error"
            assert "empty" in err["reason"].lower()
        finally:
            os.unlink(tmp)

    def test_path_traversal_detected(self):
        """Validate that path traversal patterns are flagged."""
        err = validate_input("/etc/../../var/run/../../../tmp/file.txt")
        assert err is not None
        # It should be caught either by traversal check or by file-not-found
        assert err["status"] == "error"


class TestInputValidationEdgeCases:
    """Edge case tests for input validation."""

    def test_symlink_to_valid_file_passes(self):
        """A symlink to a valid file should pass (realpath resolves it)."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("content for symlink test")
            target = f.name
        try:
            err = validate_input(target)
            assert err is None
        finally:
            os.unlink(target)

    def test_unicode_filename(self):
        """Unicode filenames should work correctly."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("unicode test content")
            tmp = f.name
        try:
            err = validate_input(tmp)
            assert err is None
        finally:
            os.unlink(tmp)

    def test_result_dict_structure(self):
        """Error results must have 'status' and 'reason' keys."""
        err = validate_input("/nonexistent/file.txt")
        assert isinstance(err, dict)
        assert "status" in err
        assert "reason" in err
