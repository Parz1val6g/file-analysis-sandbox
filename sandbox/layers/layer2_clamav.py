"""Layer 2: Static Antivirus Scan via ClamAV.

Interfaces with a locally installed ClamAV daemon (clamdscan) or standalone
scanner (clamscan). Gracefully handles the case where ClamAV is unavailable.
"""

import json
import os
import subprocess
import sys
import tempfile
from typing import Optional

from config import CLAMAV_COMMANDS, CLAMAV_TIMEOUT_SECONDS


class Layer2Result:
    __slots__ = ("status", "reason", "virus_name", "raw_output")

    def __init__(self, status: str, reason: str = "", virus_name: str = "", raw_output: str = ""):
        self.status = status
        self.reason = reason
        self.virus_name = virus_name
        self.raw_output = raw_output

    def to_dict(self) -> dict:
        d = {"status": self.status}
        if self.reason:
            d["reason"] = self.reason
        if self.virus_name:
            d["virus_name"] = self.virus_name
        if os.environ.get("SANDBOX_DEBUG"):
            d["clamav_raw"] = self.raw_output
        return d


def _find_clamav() -> Optional[str]:
    """Locate an available ClamAV binary on the system PATH."""
    for cmd in CLAMAV_COMMANDS:
        try:
            result = subprocess.run(
                [cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def scan(file_path: str) -> Layer2Result:
    """Scan a file using ClamAV.

    Returns Layer2Result with status 'clean', 'infected', or 'error'.
    """
    clamav_bin = _find_clamav()

    if not clamav_bin:
        return Layer2Result(
            status="error",
            reason="Layer 2: ClamAV is not installed or not reachable on this system",
        )

    abs_path = os.path.abspath(file_path)

    try:
        proc = subprocess.run(
            [clamav_bin, "--no-summary", "--stdout", abs_path],
            capture_output=True,
            text=True,
            timeout=CLAMAV_TIMEOUT_SECONDS,
        )

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        # clamdscan/clamscan exit codes:
        #   0 = clean
        #   1 = virus found
        #   2 = error
        if proc.returncode == 0:
            return Layer2Result(
                status="clean",
                raw_output=stdout if stdout else stderr,
            )

        if proc.returncode == 1:
            # Virus found — extract the virus name from output
            virus_name = _parse_virus_name(stdout)
            return Layer2Result(
                status="infected",
                reason="Layer 2: Malware detected — {}".format(virus_name or "Unknown threat"),
                virus_name=virus_name or "Unknown.Threat",
                raw_output=stdout,
            )

        # returncode == 2 or other: error
        return Layer2Result(
            status="error",
            reason="Layer 2: ClamAV scan error (exit code {}): {}".format(
                proc.returncode, stderr or stdout or "unknown error"
            ),
            raw_output=stderr,
        )

    except subprocess.TimeoutExpired:
        return Layer2Result(
            status="error",
            reason="Layer 2: ClamAV scan timed out after {} seconds".format(CLAMAV_TIMEOUT_SECONDS),
        )
    except Exception as exc:
        return Layer2Result(
            status="error",
            reason="Layer 2: Unexpected error during ClamAV scan: {}".format(exc),
        )


def _parse_virus_name(output: str) -> str:
    """Extract the virus/malware name from ClamAV output.

    Typical format: /path/to/file: Virus.Name.Here FOUND
    """
    if ":" in output:
        after_path = output.split(":", 1)[1].strip()
        if "FOUND" in after_path:
            return after_path.replace("FOUND", "").strip()
        return after_path
    return output.strip()


def main():
    """Standalone CLI entry for Layer 2."""
    if len(sys.argv) != 2:
        print(json.dumps({"status": "error", "reason": "Usage: layer2_clamav.py <file_path>"}))
        sys.exit(1)
    result = scan(sys.argv[1])
    print(json.dumps(result.to_dict()))
    sys.exit(0 if result.status == "clean" else 1)


if __name__ == "__main__":
    main()
