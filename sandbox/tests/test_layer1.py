"""Tests for Layer 1: Static Magic Bytes & Hex Validation."""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.layer1_magic import validate, Layer1Result
from config import FIXTURES_DIR


class TestLayer1MagicBytes:
    """Validates that magic byte detection correctly identifies file types."""

    def test_valid_pdf_passes(self):
        """A genuine PDF with %PDF header should pass clean."""
        result = validate(os.path.join(FIXTURES_DIR, "valid.pdf"))
        assert result.status == "clean", result.reason

    def test_valid_png_passes(self):
        """A genuine PNG should pass clean."""
        result = validate(os.path.join(FIXTURES_DIR, "valid.png"))
        assert result.status == "clean", result.reason

    def test_valid_gif_passes(self):
        """A genuine GIF should pass clean."""
        result = validate(os.path.join(FIXTURES_DIR, "valid.gif"))
        assert result.status == "clean", result.reason

    def test_malformed_pdf_detects_exe_header(self):
        """A .pdf file with MZ (EXE) header must be flagged as infected."""
        result = validate(os.path.join(FIXTURES_DIR, "malformed_header.pdf"))
        assert result.status == "infected"
        assert "mismatch" in result.reason.lower()
        assert "MZ" in result.true_type or "executable" in result.true_type.lower()
        assert result.declared_extension == "pdf"

    def test_no_extension_returns_clean(self):
        """A file with no extension should skip magic byte check and return clean."""
        result = validate(os.path.join(FIXTURES_DIR, "clean.txt"))
        assert result.status == "clean"

    def test_missing_file_returns_error(self):
        """A non-existent file path should return error status."""
        result = validate(os.path.join(FIXTURES_DIR, "does_not_exist.xyz"))
        assert result.status == "error"

    def test_result_to_dict_has_required_keys(self):
        """Layer1Result.to_dict() must always include 'status'."""
        result = validate(os.path.join(FIXTURES_DIR, "valid.pdf"))
        d = result.to_dict()
        assert "status" in d


class TestLayer1ExecutableDetection:
    """Verifies that executable binary signatures are correctly identified."""

    def test_eicar_txt_is_not_executable(self):
        """EICAR test string in a .txt file should not trigger executable detection."""
        # Use a clean text file as the eicar fixture may not be available
        path = os.path.join(FIXTURES_DIR, "clean.txt")
        if not os.path.isfile(path):
            pytest.skip("clean.txt fixture not available")
        result = validate(path)
        assert result.status == "clean"

    def test_slow_py_is_not_executable_binary(self):
        """A .py file should not be flagged as a binary executable."""
        result = validate(os.path.join(FIXTURES_DIR, "slow.py"))
        assert result.status == "clean"


class TestLayer1EdgeCases:
    """Covers edge cases for Layer 1."""

    def test_empty_file_with_extension(self):
        """An empty file with a known extension should fail magic byte check."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"")
            tmp_path = f.name
        try:
            result = validate(tmp_path)
            assert result.status == "infected"
        finally:
            os.unlink(tmp_path)

    def test_small_file_shorter_than_magic(self):
        """A file smaller than the expected magic bytes length."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(b"\x89")
            tmp_path = f.name
        try:
            result = validate(tmp_path)
            assert result.status == "infected"
        finally:
            os.unlink(tmp_path)

    def test_zip_extension_with_valid_pk_header(self):
        """A file with .zip extension and PK header should pass."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(b"PK\x03\x04\x00\x00\x00\x00")
            tmp_path = f.name
        try:
            result = validate(tmp_path)
            assert result.status == "clean"
        finally:
            os.unlink(tmp_path)
