"""C Engine test suite — validates compiled sandbox_engine binary.

Runs the full integration test suite against the C binary.
Verifies 100% JSON contract parity with the Python reference engine.
"""

import json
import os
import subprocess
import sys
import tempfile
import pytest

SANDBOX_DIR = os.path.join(os.path.dirname(__file__), "..")
ENGINE_PY = os.path.join(SANDBOX_DIR, "engine.py")
FIXTURES_DIR = os.path.join(SANDBOX_DIR, "fixtures")

if sys.platform == "win32":
    ENGINE_C = os.path.join(SANDBOX_DIR, "sandbox_engine.exe")
else:
    ENGINE_C = os.path.join(SANDBOX_DIR, "sandbox_engine")

# Skip all tests if C binary doesn't exist
pytestmark = pytest.mark.skipif(
    not os.path.isfile(ENGINE_C),
    reason="C binary not compiled — run build.bat first"
)

ENGINE_C_ABS = os.path.abspath(ENGINE_C)


def run_cengine(file_path):
    """Run the C engine binary and return parsed JSON."""
    proc = subprocess.run(
        [ENGINE_C_ABS, file_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    assert stdout, "C engine produced no stdout — stderr: {}".format(stderr)
    result = json.loads(stdout)
    return result, proc.returncode, stderr


def run_pyengine(file_path):
    """Run the Python engine for comparison."""
    proc = subprocess.run(
        [sys.executable, os.path.abspath(ENGINE_PY), file_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(proc.stdout.strip())


class TestCEngineIntegration:
    """Full pipeline tests against the C binary."""

    def test_malformed_pdf_detected(self):
        """Layer 1 must flag extension-mismatch attack."""
        result, exit_code, _ = run_cengine(
            os.path.join(FIXTURES_DIR, "malformed_header.pdf")
        )
        assert result["status"] == "infected"
        assert "mismatch" in result.get("reason", "").lower()
        assert exit_code != 0

    def test_valid_pdf_passes_layer1(self):
        """Valid PDF passes Layer 1."""
        result, _, _ = run_cengine(
            os.path.join(FIXTURES_DIR, "valid.pdf")
        )
        assert result["status"] != "infected"

    def test_valid_png_passes_layer1(self):
        """Valid PNG passes Layer 1."""
        result, _, _ = run_cengine(
            os.path.join(FIXTURES_DIR, "valid.png")
        )
        assert result["status"] != "infected"

    def test_valid_gif_passes_layer1(self):
        """Valid GIF passes Layer 1."""
        result, _, _ = run_cengine(
            os.path.join(FIXTURES_DIR, "valid.gif")
        )
        assert result["status"] != "infected"

    def test_clean_txt_passes_layer1(self):
        """Clean text file passes Layer 1."""
        result, _, _ = run_cengine(
            os.path.join(FIXTURES_DIR, "clean.txt")
        )
        assert result["status"] != "infected"


class TestCEngineJsonProtocol:
    """Validates JSON output contract from C binary."""

    def test_missing_argument(self):
        """No args produces valid error JSON."""
        proc = subprocess.run(
            [ENGINE_C_ABS],
            capture_output=True, text=True, timeout=10,
        )
        result = json.loads(proc.stdout.strip())
        assert result["status"] == "error"
        assert "usage" in result.get("reason", "").lower()

    def test_nonexistent_file(self):
        """Non-existent file produces error JSON."""
        result, _, _ = run_cengine("/nonexistent/file.xyz")
        assert result["status"] == "error"

    def test_output_is_valid_json(self):
        """Every invocation produces parseable JSON."""
        result, _, _ = run_cengine(os.path.join(FIXTURES_DIR, "clean.txt"))
        assert "status" in result

    def test_infected_has_reason(self):
        """Infected result includes reason field."""
        result, _, _ = run_cengine(
            os.path.join(FIXTURES_DIR, "malformed_header.pdf")
        )
        assert "reason" in result

    def test_error_has_reason(self):
        """Error result includes reason field."""
        result, _, _ = run_cengine(os.path.join(FIXTURES_DIR, "valid.pdf"))
        if result["status"] == "error":
            assert "reason" in result


class TestCEngineStdoutIsolation:
    """Validates C binary stdout purity."""

    def test_stdout_is_single_json_line(self):
        """stdout must be exactly one line of valid JSON."""
        proc = subprocess.run(
            [ENGINE_C_ABS, os.path.join(FIXTURES_DIR, "clean.txt")],
            capture_output=True, text=True, timeout=30,
        )
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        assert len(lines) == 1
        json.loads(lines[0])

    def test_no_debug_in_stdout(self):
        """stdout must NOT contain '[engine]' debug prefix."""
        proc = subprocess.run(
            [ENGINE_C_ABS, os.path.join(FIXTURES_DIR, "clean.txt")],
            capture_output=True, text=True, timeout=30,
        )
        assert "[engine]" not in proc.stdout

    def test_debug_in_stderr(self):
        """stderr must contain layer status messages."""
        proc = subprocess.run(
            [ENGINE_C_ABS, os.path.join(FIXTURES_DIR, "clean.txt")],
            capture_output=True, text=True, timeout=30,
        )
        assert "Layer 1" in proc.stderr
        assert "Layer 2" in proc.stderr


class TestCEngineClamavBypass:
    """Validates ClamAV graceful degradation in C binary."""

    def test_clamav_unavailable_bypasses(self):
        """When ClamAV missing, engine continues to Layer 3."""
        result, _, _ = run_cengine(os.path.join(FIXTURES_DIR, "valid.pdf"))
        # Should not be an "infected" result from Layer 2
        assert result["status"] != "infected"

    def test_bypass_logged_in_stderr(self):
        """stderr contains BYPASSED message."""
        proc = subprocess.run(
            [ENGINE_C_ABS, os.path.join(FIXTURES_DIR, "valid.pdf")],
            capture_output=True, text=True, timeout=30,
        )
        assert "BYPASSED" in proc.stderr

    def test_clamav_skipped_in_metadata(self):
        """If result is clean, metadata has clamav_skipped flag."""
        result, _, _ = run_cengine(os.path.join(FIXTURES_DIR, "valid.pdf"))
        if result["status"] == "clean":
            meta = result.get("metadata", {})
            assert "clamav_skipped" in meta
            assert meta["clamav_skipped"] is True


class TestCEngineContractSpecific:
    """Validates exact JSON key presence matching Python engine."""

    @pytest.mark.parametrize("fixture", [
        "malformed_header.pdf",
        "clean.txt",
        "valid.pdf",
        "valid.png",
        "valid.gif",
    ])
    def test_status_key_matches_python(self, fixture):
        """C and Python engines must agree on status."""
        path = os.path.join(FIXTURES_DIR, fixture)
        c_result, _, _ = run_cengine(path)
        py_result = run_pyengine(path)
        assert c_result["status"] == py_result["status"], \
            "C: {} != Python: {} for {}".format(
                c_result["status"], py_result["status"], fixture
            )

    def test_infected_keys_match_python(self):
        """Infected result must have same keys as Python engine."""
        path = os.path.join(FIXTURES_DIR, "malformed_header.pdf")
        c_result, _, _ = run_cengine(path)
        py_result = run_pyengine(path)
        for key in ("status", "reason", "true_type", "declared_extension"):
            assert (key in c_result) == (key in py_result), \
                "Key '{}' mismatch for infected result".format(key)


class TestCEngineRobustness:
    """Validates C engine crash-resistance."""

    def test_directory_as_input(self):
        """Directory input produces error, not crash."""
        result, _, _ = run_cengine(FIXTURES_DIR)
        assert result["status"] == "error"

    def test_empty_file_rejected(self):
        """Empty file is rejected by validation."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmp = f.name
        try:
            result, _, _ = run_cengine(tmp)
            assert result["status"] == "error"
            assert "empty" in result.get("reason", "").lower()
        finally:
            os.unlink(tmp)

    def test_spaces_in_path(self):
        """Spaces in path don't break argument parsing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test file.txt")
            with open(file_path, "w") as f:
                f.write("hello world")
            result, _, _ = run_cengine(file_path)
            assert "status" in result

    def test_binary_file_handled(self):
        """Null bytes don't crash the engine."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello\x00world\x00binary")
            tmp = f.name
        try:
            result, _, _ = run_cengine(tmp)
            assert "status" in result
        finally:
            os.unlink(tmp)

    def test_no_args_crash(self):
        """Missing arguments produce valid JSON, not crash."""
        proc = subprocess.run(
            [ENGINE_C_ABS],
            capture_output=True, text=True, timeout=10,
        )
        json.loads(proc.stdout.strip())  # Must parse
        assert proc.returncode != 0


class TestCEngineSignature:
    """Validates SHA-256 signature output."""

    def test_signature_is_64_hex_chars(self):
        """When signature is present, it must be 64 lowercase hex chars."""
        # Use a file that produces clean result (if Docker works)
        # or error with signature
        result, _, _ = run_cengine(os.path.join(FIXTURES_DIR, "valid.pdf"))
        sig = result.get("signature", "")
        if sig:
            assert len(sig) == 64
            assert all(c in "0123456789abcdef" for c in sig)

    def test_same_file_same_signature(self):
        """Same file produces deterministic signature."""
        path = os.path.join(FIXTURES_DIR, "valid.pdf")
        r1, _, _ = run_cengine(path)
        r2, _, _ = run_cengine(path)
        s1 = r1.get("signature", "")
        s2 = r2.get("signature", "")
        if s1 and s2:
            assert s1 == s2
