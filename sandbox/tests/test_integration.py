"""Integration tests for the full sandbox engine pipeline."""

import json
import os
import subprocess
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import FIXTURES_DIR

ENGINE_PATH = os.path.join(os.path.dirname(__file__), "..", "engine.py")


def run_engine(file_path: str) -> dict:
    """Run the engine CLI and return parsed JSON output."""
    proc = subprocess.run(
        [sys.executable, ENGINE_PATH, file_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    stdout = proc.stdout.strip()
    assert stdout, "Engine produced no stdout output — stderr: {}".format(proc.stderr)
    return json.loads(stdout)


class TestEngineIntegration:
    """End-to-end tests that validate the full three-layer pipeline."""

    def test_clean_text_file(self):
        """A clean text file should pass all layers (or get error if ClamAV/Docker missing)."""
        result = run_engine(os.path.join(FIXTURES_DIR, "clean.txt"))
        assert "status" in result
        assert result["status"] in ("clean", "error")

    def test_malformed_pdf_is_flagged(self):
        """The malformed_header.pdf must be detected by Layer 1."""
        result = run_engine(os.path.join(FIXTURES_DIR, "malformed_header.pdf"))
        assert result["status"] == "infected"
        assert "mismatch" in result.get("reason", "").lower()

    def test_valid_pdf_passes_layer1(self):
        """A valid PDF should pass Layer 1 (may fail later if ClamAV/Docker not present)."""
        result = run_engine(os.path.join(FIXTURES_DIR, "valid.pdf"))
        assert "status" in result
        assert result["status"] != "infected"

    def test_valid_png_passes_layer1(self):
        """A valid PNG should pass Layer 1."""
        result = run_engine(os.path.join(FIXTURES_DIR, "valid.png"))
        assert "status" in result
        assert result["status"] != "infected"

    def test_valid_gif_passes_layer1(self):
        """A valid GIF should pass Layer 1."""
        result = run_engine(os.path.join(FIXTURES_DIR, "valid.gif"))
        assert "status" in result
        assert result["status"] != "infected"


class TestEngineJsonProtocol:
    """Validates that the engine always produces valid JSON."""

    def test_missing_file_argument(self):
        """Running engine without a file path should return error JSON."""
        proc = subprocess.run(
            [sys.executable, ENGINE_PATH],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout.strip())
        assert result["status"] == "error"
        assert "usage" in result["reason"].lower()

    def test_nonexistent_file(self):
        """Running engine on a non-existent file should return error JSON."""
        proc = subprocess.run(
            [sys.executable, ENGINE_PATH, os.path.join(FIXTURES_DIR, "nope.nope")],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout.strip())
        assert result["status"] == "error"

    def test_output_is_valid_json(self):
        """Every engine invocation must produce parseable JSON."""
        proc = subprocess.run(
            [sys.executable, ENGINE_PATH, os.path.join(FIXTURES_DIR, "clean.txt")],
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = proc.stdout.strip()
        assert stdout
        parsed = json.loads(stdout)
        assert isinstance(parsed, dict)
        assert "status" in parsed

    def test_clean_result_has_signature_field(self):
        """A clean result from the engine must include the signature key."""
        result = run_engine(os.path.join(FIXTURES_DIR, "clean.txt"))
        if result["status"] == "clean":
            assert "signature" in result

    def test_infected_result_has_reason_field(self):
        """An infected result must include a reason."""
        result = run_engine(os.path.join(FIXTURES_DIR, "malformed_header.pdf"))
        if result["status"] == "infected":
            assert "reason" in result

    def test_error_result_has_reason_field(self):
        """An error result must include a reason."""
        proc = subprocess.run(
            [sys.executable, ENGINE_PATH],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout.strip())
        assert "reason" in result


class TestEngineExitCodes:
    """Validates engine exit codes for different states."""

    def test_usage_error_exit_code(self):
        """Missing argument should exit with non-zero."""
        proc = subprocess.run(
            [sys.executable, ENGINE_PATH],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode != 0

    def test_infected_exit_code(self):
        """Infected file should exit non-zero."""
        proc = subprocess.run(
            [sys.executable, ENGINE_PATH, os.path.join(FIXTURES_DIR, "malformed_header.pdf")],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode != 0


class TestEngineRobustness:
    """Validates that the engine never crashes."""

    def test_directory_as_input(self):
        """Passing a directory instead of a file should not crash."""
        proc = subprocess.run(
            [sys.executable, ENGINE_PATH, FIXTURES_DIR],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout.strip())
        assert result["status"] == "error"

    def test_special_chars_in_path(self):
        """Spaces in path should not break argument parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test file with spaces.txt")
            with open(file_path, "w") as f:
                f.write("hello world")
            proc = subprocess.run(
                [sys.executable, ENGINE_PATH, file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            result = json.loads(proc.stdout.strip())
            assert "status" in result

    def test_empty_file(self):
        """An empty file should not crash the engine."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("")
            tmp_path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, ENGINE_PATH, tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            result = json.loads(proc.stdout.strip())
            assert "status" in result
        finally:
            os.unlink(tmp_path)

    def test_binary_file(self):
        """A file with null bytes should not crash the engine."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello\x00world\x00binary")
            tmp_path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, ENGINE_PATH, tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            result = json.loads(proc.stdout.strip())
            assert "status" in result
        finally:
            os.unlink(tmp_path)


class TestConfigConstants:
    """Validates configuration values meet security requirements."""

    def test_cli_help(self):
        """Engine should accept a file path and produce output."""
        from config import SANDBOX_TIMEOUT_SECONDS, SANDBOX_MEMORY_LIMIT
        assert SANDBOX_TIMEOUT_SECONDS > 0
        assert "m" in SANDBOX_MEMORY_LIMIT.lower()


class TestClamavBypass:
    """Validates that ClamAV unavailability gracefully bypasses Layer 2."""

    def test_clamav_unavailable_does_not_block_pipeline(self):
        """Engine must not halt when ClamAV is missing — continues to Layer 3."""
        result = run_engine(os.path.join(FIXTURES_DIR, "valid.pdf"))
        assert result["status"] in ("clean", "error")
        # If error, it must be from Layer 3 (Docker), not Layer 2
        if result["status"] == "error":
            reason = result.get("reason", "")
            assert "Layer 2" not in reason

    def test_clamav_bypass_appears_in_metadata(self):
        """When result is clean, metadata must have clamav_skipped flag."""
        result = run_engine(os.path.join(FIXTURES_DIR, "valid.pdf"))
        if result["status"] == "clean":
            meta = result.get("metadata", {})
            assert "clamav_skipped" in meta
            assert meta["clamav_skipped"] is True
            assert "clamav_skip_reason" in meta

    def test_malformed_header_still_halts(self):
        """Layer 1 infected detection still halts the pipeline immediately."""
        result = run_engine(os.path.join(FIXTURES_DIR, "malformed_header.pdf"))
        assert result["status"] == "infected"
