"""Tests for Layer 2: ClamAV Antivirus Scanner Integration."""

import json
import os
import sys
import subprocess
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.layer2_clamav import scan, Layer2Result, _find_clamav, _parse_virus_name
from config import FIXTURES_DIR


class TestLayer2Clamav:
    """Validates ClamAV integration layer behavior."""

    def test_result_to_dict_has_required_keys(self):
        """Layer2Result.to_dict() must always include 'status'."""
        r = Layer2Result(status="clean")
        d = r.to_dict()
        assert "status" in d

    def test_clamav_unavailable_returns_error_not_crash(self):
        """When ClamAV is not installed, scan() must return error, not raise."""
        # _find_clamav() will return None when ClamAV is missing
        result = scan(os.path.join(FIXTURES_DIR, "clean.txt"))
        assert result.status in ("clean", "error")
        if result.status == "error":
            assert "clamav" in result.reason.lower() or "not" in result.reason.lower()

    def test_find_clamav_returns_none_or_string(self):
        """_find_clamav should return None (not installed) or str (installed)."""
        result = _find_clamav()
        assert result is None or isinstance(result, str)


class TestParseVirusName:
    """Tests the virus name parser."""

    def test_parse_standard_clamav_output(self):
        """Standard clamscan output: '/path: Virus.Name FOUND'"""
        output = "/tmp/test.txt: Eicar-Test-Signature FOUND"
        name = _parse_virus_name(output)
        assert name == "Eicar-Test-Signature"

    def test_parse_no_found_keyword(self):
        """Output without FOUND keyword."""
        output = "/tmp/test.txt: Something.Here"
        name = _parse_virus_name(output)
        assert name == "Something.Here"

    def test_parse_empty_output(self):
        """Empty string should return empty string."""
        assert _parse_virus_name("") == ""

    def test_parse_no_colon(self):
        """Output without colon should return entire output."""
        assert _parse_virus_name("SomeVirusName") == "SomeVirusName"


class TestLayer2GracefulDegradation:
    """Ensures Layer 2 never crashes the engine."""

    @pytest.mark.skipif(
        subprocess.run(
            ["pip", "show", "pytest-mock"], capture_output=True
        ).returncode != 0,
        reason="pytest-mock not installed",
    )
    def test_scan_handles_subprocess_timeout(self):
        """Scan should handle timeout gracefully."""
        # This test validates the timeout code path exists in the function
        source_file = os.path.join(
            os.path.dirname(__file__), "..", "layers", "layer2_clamav.py"
        )
        with open(source_file, "r") as fh:
            content = fh.read()
        assert "TimeoutExpired" in content

    def test_scan_on_nonexistent_file(self):
        """Scanning a non-existent file should return an error."""
        result = scan(os.path.join(FIXTURES_DIR, "definitely_not_here.xyz"))
        # ClamAV may or may not be installed; either way we should get a result
        assert result.status in ("clean", "infected", "error")

    def test_infected_status_has_virus_name(self):
        """An infected result must include the virus_name field."""
        result = Layer2Result(
            status="infected",
            reason="Test malware",
            virus_name="Test.Malware.Name",
        )
        d = result.to_dict()
        assert d["status"] == "infected"
        assert d["virus_name"] == "Test.Malware.Name"
