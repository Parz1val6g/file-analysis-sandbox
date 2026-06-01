"""Tests for stdout isolation in the engine."""

import io
import os
import sys
import json
import subprocess
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestStdoutIsolation:
    """Validates that the engine never leaks diagnostic output to stdout."""

    def test_engine_stdout_is_strict_json(self):
        """Every stdout line from the engine must be parseable JSON."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        proc = subprocess.run(
            [sys.executable, engine_path, os.path.join(
                os.path.dirname(__file__), "..", "fixtures", "clean.txt"
            )],
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = proc.stdout.strip()
        assert stdout, "Engine produced empty stdout"
        # Must be valid JSON
        result = json.loads(stdout)
        assert "status" in result

    def test_engine_stdout_does_not_contain_debug_prefix(self):
        """stdout must NOT contain '[engine]' log prefix lines."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        proc = subprocess.run(
            [sys.executable, engine_path, os.path.join(
                os.path.dirname(__file__), "..", "fixtures", "clean.txt"
            )],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Debug logs go to stderr, not stdout
        assert "[engine]" not in proc.stdout

    def test_debug_logs_go_to_stderr(self):
        """Diagnostic messages should appear in stderr, not stdout."""
        engine_path = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        proc = subprocess.run(
            [sys.executable, engine_path, os.path.join(
                os.path.dirname(__file__), "..", "fixtures", "clean.txt"
            )],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # stderr should contain the layer status messages
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

    def test_isolated_stdout_context_manager_exists(self):
        """Verify the _isolated_stdout context manager is defined in engine.py."""
        engine_src = os.path.join(os.path.dirname(__file__), "..", "engine.py")
        with open(engine_src, "r", encoding="utf-8") as fh:
            content = fh.read()
        assert "_isolated_stdout" in content
        assert "contextlib.contextmanager" in content
        assert "_REAL_STDOUT" in content
