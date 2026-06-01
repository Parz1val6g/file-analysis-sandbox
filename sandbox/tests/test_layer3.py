"""Tests for Layer 3: Ephemeral Docker Sandbox Execution Engine."""

import json
import os
import sys
import subprocess
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.layer3_sandbox import (
    execute,
    Layer3Result,
    _sha256_file,
    _docker_available,
    _windows_to_docker_path,
)
from config import FIXTURES_DIR, SANDBOX_DOCKER_FLAGS


class TestLayer3Result:
    """Validates Layer3Result serialization."""

    def test_clean_result_has_signature_and_metadata(self):
        r = Layer3Result(
            status="clean",
            signature="abc123",
            metadata={"extracted_text": "hello world"},
        )
        d = r.to_dict()
        assert d["status"] == "clean"
        assert d["signature"] == "abc123"
        assert d["metadata"]["extracted_text"] == "hello world"

    def test_error_result_has_reason(self):
        r = Layer3Result(status="error", reason="Something broke")
        d = r.to_dict()
        assert d["status"] == "error"
        assert d["reason"] == "Something broke"

    def test_infected_result_excludes_metadata(self):
        r = Layer3Result(
            status="infected",
            reason="Malware found",
            signature="badhash",
            metadata={"should_not_appear": True},
        )
        d = r.to_dict()
        assert "metadata" not in d
        assert d["reason"] == "Malware found"


class TestLayer3Docker:
    """Validates Docker availability detection and path conversion."""

    def test_docker_available_detection(self):
        """_docker_available should return bool, never raise."""
        result = _docker_available()
        assert isinstance(result, bool)

    def test_sha256_consistent(self):
        """SHA-256 hash should be deterministic for the same file."""
        path = os.path.join(FIXTURES_DIR, "clean.txt")
        h1 = _sha256_file(path)
        h2 = _sha256_file(path)
        assert h1 == h2
        assert len(h1) == 64
        assert all(c in "0123456789abcdef" for c in h1)

    def test_sha256_different_for_different_files(self):
        """Different files should produce different hashes."""
        path1 = os.path.join(FIXTURES_DIR, "clean.txt")
        path2 = os.path.join(FIXTURES_DIR, "valid.pdf")
        if not os.path.isfile(path1) or not os.path.isfile(path2):
            pytest.skip("Required fixtures not available")
        h1 = _sha256_file(path1)
        h2 = _sha256_file(path2)
        assert h1 != h2

    def test_windows_path_conversion(self):
        """Windows path conversion should produce valid Docker volume paths."""
        result = _windows_to_docker_path("C:\\Users\\test\\file.txt")
        assert "\\" not in result
        assert result.startswith("/")
        assert "file.txt" in result

    def test_windows_path_conversion_lowercase_drive(self):
        """Drive letter should be lowercased."""
        result = _windows_to_docker_path("D:\\Data\\stuff.pdf")
        assert result.startswith("/d/")


class TestLayer3Execution:
    """Validates sandbox execution behavior with Docker present/absent."""

    def test_execute_nonexistent_file(self):
        """Executing on a non-existent file should return error."""
        result = execute(os.path.join(FIXTURES_DIR, "no_such_file.xyz"))
        assert result.status == "error"

    def test_execute_valid_file_returns_result(self):
        """Executing on a valid file returns a result dict."""
        result = execute(os.path.join(FIXTURES_DIR, "clean.txt"))
        assert result.status in ("clean", "error")
        # If Docker is available and image builds, we get clean
        # If Docker is unavailable, we get error — both are valid

    def test_metadata_excluded_on_error(self):
        """Error results should not include metadata."""
        r = Layer3Result(status="error", reason="fail", metadata={"a": 1})
        d = r.to_dict()
        assert "metadata" not in d


class TestLayer3CodeStructure:
    """Validates that the code has the required security constraints."""

    def test_docker_flags_include_rm(self):
        """Container must use --rm for auto-destruction."""
        from config import SANDBOX_DOCKER_FLAGS
        assert "--rm" in SANDBOX_DOCKER_FLAGS

    def test_docker_flags_include_network_none(self):
        """Container must be network air-gapped."""
        from config import SANDBOX_DOCKER_FLAGS
        assert "--network" in SANDBOX_DOCKER_FLAGS
        flags = " ".join(SANDBOX_DOCKER_FLAGS)
        assert "none" in flags

    def test_docker_flags_include_read_only(self):
        """Container must use read-only root filesystem."""
        from config import SANDBOX_DOCKER_FLAGS
        assert "--read-only" in SANDBOX_DOCKER_FLAGS

    def test_docker_flags_include_cap_drop_all(self):
        """Container must drop all Linux capabilities."""
        flags_str = " ".join(SANDBOX_DOCKER_FLAGS)
        assert "--cap-drop=ALL" in flags_str

    def test_memory_limit_is_256m(self):
        """Container must enforce 256 MB memory limit."""
        from config import SANDBOX_MEMORY_LIMIT
        assert SANDBOX_MEMORY_LIMIT == "256m"

    def test_cpu_limit_is_half_core(self):
        """Container must enforce 0.5 CPU limit."""
        from config import SANDBOX_CPU_LIMIT
        assert SANDBOX_CPU_LIMIT == "0.5"

    def test_timeout_is_8_seconds(self):
        """Container must enforce 8 second timeout."""
        from config import SANDBOX_TIMEOUT_SECONDS
        assert SANDBOX_TIMEOUT_SECONDS == 8
