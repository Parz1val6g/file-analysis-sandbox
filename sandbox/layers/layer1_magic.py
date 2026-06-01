"""Layer 1: Static Magic Bytes & Hex Signature Validation.

Reads raw header bytes and validates true file type against declared extension.
Detects extension-mismatch attacks (e.g., .pdf masking an executable).
"""

import os
import json
import sys
from typing import Optional

from config import MAGIC_BYTES, EXECUTABLE_SIGNATURES, EXECUTABLE_EXTENSIONS


class Layer1Result:
    __slots__ = ("status", "reason", "true_type", "declared_extension")

    def __init__(self, status: str, reason: str = "", true_type: str = "", declared_extension: str = ""):
        self.status = status
        self.reason = reason
        self.true_type = true_type
        self.declared_extension = declared_extension

    def to_dict(self) -> dict:
        d = {"status": self.status}
        if self.reason:
            d["reason"] = self.reason
        if self.true_type:
            d["true_type"] = self.true_type
        if self.declared_extension:
            d["declared_extension"] = self.declared_extension
        return d


def _get_extension(file_path: str) -> str:
    """Extract lowercase file extension without the dot."""
    _, ext = os.path.splitext(file_path)
    return ext.lstrip(".").lower()


def _read_header(file_path: str, max_bytes: int = 16) -> bytes:
    """Read the first N bytes of a file for signature analysis."""
    with open(file_path, "rb") as fh:
        return fh.read(max_bytes)


def _check_executable(header: bytes) -> Optional[str]:
    """Return the executable type label if header matches a known binary signature."""
    for signature, label in EXECUTABLE_SIGNATURES.items():
        if header.startswith(signature):
            return label
    return None


def validate(file_path: str) -> Layer1Result:
    """Run Layer 1 validation on the given file.

    Returns a Layer1Result with status 'clean', 'infected', or 'error'.
    """
    ext = _get_extension(file_path)

    if not ext:
        return Layer1Result(status="clean", reason="No extension to validate; skipping magic byte check")

    try:
        header = _read_header(file_path)
    except (OSError, IOError) as exc:
        return Layer1Result(
            status="error",
            reason="Layer 1: Cannot read file for hex analysis: {}".format(exc),
        )

    # Check if the file matches a known executable signature
    exec_type = _check_executable(header)

    if exec_type and ext not in EXECUTABLE_EXTENSIONS:
        # The file has executable magic bytes but a non-executable extension.
        # This is an extension-mismatch attack.
        return Layer1Result(
            status="infected",
            reason="Layer 1: Extension mismatch attack detected — file has '{}' extension but "
                   "binary header matches {}".format(ext, exec_type),
            true_type=exec_type,
            declared_extension=ext,
        )

    # Check declared extension matches known magic bytes
    expected = MAGIC_BYTES.get(ext)
    if expected:
        expected_bytes = expected["bytes"]
        offset = expected["offset"]
        actual = header[offset:offset + len(expected_bytes)]

        if actual != expected_bytes:
            return Layer1Result(
                status="infected",
                reason="Layer 1: Magic byte mismatch — expected {} ({}) for '.{}' but got {}".format(
                    expected["label"], expected_bytes.hex(), ext, actual.hex()
                ),
                true_type="unknown (magic bytes: {})".format(actual.hex()),
                declared_extension=ext,
            )

    return Layer1Result(status="clean", declared_extension=ext)


def main():
    """Standalone CLI entry for Layer 1."""
    if len(sys.argv) != 2:
        print(json.dumps({"status": "error", "reason": "Usage: layer1_magic.py <file_path>"}))
        sys.exit(1)
    result = validate(sys.argv[1])
    print(json.dumps(result.to_dict()))
    sys.exit(0 if result.status == "clean" else 1)


if __name__ == "__main__":
    main()
