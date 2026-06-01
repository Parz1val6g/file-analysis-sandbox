#!/usr/bin/env python3
"""Sandbox file extractor — runs INSIDE the ephemeral Docker container.

Receives a single file path as argument, attempts to detect the file type
and extract text content. Prints a JSON object with metadata to stdout.
"""

import json
import os
import subprocess
import sys
import hashlib
import traceback


def sha256(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def detect_mime(path: str) -> str:
    """Detect the MIME type of a file using the `file` command."""
    try:
        proc = subprocess.run(
            ["file", "--mime-type", "-b", path],
            capture_output=True, text=True, timeout=5,
        )
        return proc.stdout.strip()
    except Exception:
        return "unknown"


def extract_text(path: str) -> str:
    """Try to extract readable text from the file based on its MIME type."""
    mime = detect_mime(path)

    if mime == "application/pdf":
        try:
            proc = subprocess.run(
                ["pdftotext", "-layout", path, "-"],
                capture_output=True, text=True, timeout=5,
            )
            return proc.stdout.strip()
        except Exception:
            pass
    elif mime.startswith("image/"):
        try:
            proc = subprocess.run(
                ["tesseract", path, "stdout", "-l", "eng"],
                capture_output=True, text=True, timeout=10,
            )
            return proc.stdout.strip()
        except Exception:
            pass

    # Fallback: try reading as UTF-8 text
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(20000)
            return content
    except Exception:
        pass

    # Last resort: read raw bytes as hex preview
    try:
        with open(path, "rb") as fh:
            raw = fh.read(256)
            return raw.hex()
    except Exception:
        return ""


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: extractor.py <file_path>"}))
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(json.dumps({"error": "Input file not found"}))
        sys.exit(1)

    try:
        file_hash = sha256(file_path)
        mime_type = detect_mime(file_path)
        extracted = extract_text(file_path)

        result = {
            "sha256": file_hash,
            "mime_type": mime_type,
            "file_size_bytes": os.path.getsize(file_path),
            "extracted_text": extracted[:50000],
        }

        print(json.dumps(result))
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
