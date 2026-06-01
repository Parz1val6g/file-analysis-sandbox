"""Layer 3: Ephemeral Docker Sandbox Execution Engine.

Spawns a heavily restricted, air-gapped Docker container to safely extract
data from untrusted files. The container is auto-destroyed after use.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from typing import Optional

from config import (
    SANDBOX_IMAGE_NAME,
    SANDBOX_DOCKERFILE,
    SANDBOX_TIMEOUT_SECONDS,
    SANDBOX_MEMORY_LIMIT,
    SANDBOX_CPU_LIMIT,
    SANDBOX_DOCKER_FLAGS,
    SANDBOX_CONTAINER_MOUNT_POINT,
)


class Layer3Result:
    __slots__ = ("status", "reason", "signature", "metadata")

    def __init__(self, status: str, reason: str = "", signature: str = "", metadata: Optional[dict] = None):
        self.status = status
        self.reason = reason
        self.signature = signature
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        d = {"status": self.status}
        if self.signature:
            d["signature"] = self.signature
        if self.reason and self.status != "clean":
            d["reason"] = self.reason
        if self.metadata and self.status == "clean":
            d["metadata"] = self.metadata
        return d


def _sha256_file(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _docker_available() -> bool:
    """Check if Docker is installed and the daemon is reachable."""
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _build_sandbox_image() -> Optional[str]:
    """Build the sandbox Docker image. Returns None on failure."""
    if not os.path.isfile(SANDBOX_DOCKERFILE):
        return "Dockerfile not found at {}".format(SANDBOX_DOCKERFILE)

    try:
        proc = subprocess.run(
            ["docker", "build", "-t", SANDBOX_IMAGE_NAME, "-f", SANDBOX_DOCKERFILE,
             os.path.dirname(SANDBOX_DOCKERFILE)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            return "docker build failed: {}".format(proc.stderr.strip())
        return None
    except subprocess.TimeoutExpired:
        return "docker build timed out"
    except Exception as exc:
        return "docker build error: {}".format(exc)


def _windows_to_docker_path(windows_path: str) -> str:
    r"""Convert a Windows path to a Docker-compatible volume mount path.

    Docker Desktop on Windows expects paths in the format:
        C:\\Users\\foo\\bar  ->  //c/Users/foo/bar
    or keeps them as C:/Users/foo/bar depending on config.
    We try the forward-slash form first, which Docker Desktop accepts.
    """
    abs_path = os.path.abspath(windows_path)
    # Replace backslashes with forward slashes
    docker_path = abs_path.replace("\\", "/")
    # Ensure drive letter is lowercase for WSL-style
    if len(docker_path) >= 2 and docker_path[1] == ":":
        docker_path = "/" + docker_path[0].lower() + docker_path[2:]
    return docker_path


def execute(file_path: str) -> Layer3Result:
    """Execute the sandbox pipeline for a given file.

    Builds the sandbox image if needed, then runs the ephemeral container
    with strict isolation flags. Returns a Layer3Result.
    """
    if not _docker_available():
        return Layer3Result(
            status="error",
            reason="Layer 3: Docker is not available or daemon is not reachable",
        )

    abs_file_path = os.path.abspath(file_path)
    if not os.path.isfile(abs_file_path):
        return Layer3Result(
            status="error",
            reason="Layer 3: Input file not found: {}".format(abs_file_path),
        )

    # Build the sandbox image if it doesn't already exist
    build_err = _build_sandbox_image()
    if build_err:
        return Layer3Result(
            status="error",
            reason="Layer 3: Cannot build sandbox image — {}".format(build_err),
        )

    file_hash = _sha256_file(abs_file_path)

    # Convert paths for Docker volume mount
    docker_src_path = _windows_to_docker_path(abs_file_path)
    volume_mount = "{}:{}".format(docker_src_path, SANDBOX_CONTAINER_MOUNT_POINT)

    # Build the docker run command
    cmd = ["docker", "run"] + SANDBOX_DOCKER_FLAGS + [
        "-v", volume_mount,
        SANDBOX_IMAGE_NAME,
        SANDBOX_CONTAINER_MOUNT_POINT,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SANDBOX_TIMEOUT_SECONDS + 2,  # extra buffer beyond container timeout
        )

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        if proc.returncode == 0:
            metadata = {}
            if stdout:
                try:
                    metadata = json.loads(stdout)
                except json.JSONDecodeError:
                    metadata = {"extracted_text": stdout[:10000]}

            return Layer3Result(
                status="clean",
                signature=file_hash,
                metadata=metadata,
            )

        # Non-zero exit: container likely hit a timeout or error
        return Layer3Result(
            status="error",
            reason="Layer 3: Sandbox container exited with code {} — {}".format(
                proc.returncode, stderr or stdout or "no output"
            ),
            signature=file_hash,
        )

    except subprocess.TimeoutExpired:
        return Layer3Result(
            status="error",
            reason="Layer 3: Sandbox execution timed out after {} seconds".format(SANDBOX_TIMEOUT_SECONDS),
            signature=file_hash,
        )
    except Exception as exc:
        return Layer3Result(
            status="error",
            reason="Layer 3: Unexpected error during sandbox execution: {}".format(exc),
            signature=file_hash,
        )


def main():
    """Standalone CLI entry for Layer 3."""
    if len(sys.argv) != 2:
        print(json.dumps({"status": "error", "reason": "Usage: layer3_sandbox.py <file_path>"}))
        sys.exit(1)
    result = execute(sys.argv[1])
    print(json.dumps(result.to_dict()))
    sys.exit(0 if result.status == "clean" else 1)


if __name__ == "__main__":
    main()
