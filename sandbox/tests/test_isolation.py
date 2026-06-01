"""Tests for stdout isolation in the engine."""

import io
import os
import sys
import json
import subprocess
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestStdoutIsolation:
    """Validates that the engine never leaks diagnostic output to stdout."""

    def test_engine_stdout_is_strict_json(self):
        """Every stdout line from the engine must be parseable JSON."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "clean.txt")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = proc.stdout.strip()
        assert stdout, "Engine produced empty stdout"
        result = json.loads(stdout)
        assert "status" in result

    def test_engine_stdout_does_not_contain_debug_prefix(self):
        """stdout must NOT contain '[engine]' log prefix lines."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "clean.txt")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert "[engine]" not in proc.stdout

    def test_debug_logs_go_to_stderr(self):
        """Diagnostic messages should appear in stderr, not stdout."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "clean.txt")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert "Layer 1" in proc.stderr
        assert "Layer 2" in proc.stderr

    def test_engine_exits_with_valid_json_on_invalid_input(self):
        """Even on bad input, stdout must be valid JSON."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        proc = subprocess.run(
            [sys.executable, engine_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout.strip())
        assert result["status"] == "error"

    def test_real_stdout_capture_exists(self):
        """Verify the stdout isolation mechanism is defined in engine.py."""
        engine_src = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        with open(engine_src, "r", encoding="utf-8") as fh:
            content = fh.read()
        assert "_REAL_STDOUT" in content
        assert "_redirect_stdout_to_devnull" in content
        assert "sys.__stdout__" in content

    def test_stdout_is_single_json_line(self):
        """stdout must be exactly one line — the JSON object."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "clean.txt")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        assert len(lines) == 1, "stdout must be exactly one line, got: {}".format(lines)
        json.loads(lines[0])  # Must be parseable

    def test_stdout_no_layer_prefix(self):
        """stdout must not contain '[engine] Layer' debug log lines."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "clean.txt")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Debug log lines have format "[engine] Layer N: ..."
        assert "[engine]" not in proc.stdout
        # Verify the stdout line is valid JSON only
        for line in proc.stdout.splitlines():
            if line.strip():
                json.loads(line.strip())


class TestClamavGracefulBypass:
    """Validates that ClamAV unavailability bypasses Layer 2 gracefully."""

    def test_clamav_missing_does_not_halt_engine(self):
        """When ClamAV is not installed, the engine must continue to Layer 3."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "valid.pdf")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        result = json.loads(proc.stdout.strip())
        # Should NOT be an error about ClamAV — engine continues past it
        if result["status"] == "clean":
            # Metadata must contain the clamav_skipped flag
            assert "metadata" in result
            assert result["metadata"].get("clamav_skipped") is True
            assert "clamav_skip_reason" in result["metadata"]
        elif result["status"] == "error":
            # If error, it should be from Layer 3 (Docker), not Layer 2 (ClamAV)
            reason = result.get("reason", "")
            assert "Layer 2" not in reason

    def test_infected_file_still_halts_at_layer1(self):
        """An infected file (malformed header) should still halt at Layer 1."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "malformed_header.pdf")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout.strip())
        assert result["status"] == "infected"

    def test_clamav_bypass_logged_in_stderr(self):
        """stderr must contain a 'BYPASSED' message when ClamAV is skipped."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "valid.pdf")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert "BYPASSED" in proc.stderr

    def test_clamav_bypass_metadata_structure(self):
        """When ClamAV is bypassed and result is clean, metadata must have skip info."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        fixture = os.path.join(os.path.dirname(__file__), "..", "fixtures", "valid.pdf")
        proc = subprocess.run(
            [sys.executable, engine_path, fixture],
            capture_output=True,
            text=True,
            timeout=30,
        )
        result = json.loads(proc.stdout.strip())
        if result["status"] == "clean":
            meta = result.get("metadata", {})
            assert "clamav_skipped" in meta
            assert isinstance(meta["clamav_skipped"], bool)
            assert isinstance(meta["clamav_skip_reason"], str)
