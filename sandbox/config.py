"""Zero-dependency configuration constants for the sandbox file analysis engine."""

import os

# --- Workspace paths ---
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.join(ROOT_DIR, "fixtures")
DOCKER_DIR = os.path.join(ROOT_DIR, "docker")
LOG_DIR = os.path.join(ROOT_DIR, "logs")

# --- Layer 1: Magic byte signatures ---
# Maps lowercase file extension to expected header bytes + offset
MAGIC_BYTES = {
    "pdf":  {"bytes": b"%PDF",          "offset": 0, "label": "PDF Document"},
    "png":  {"bytes": b"\x89PNG\r\n\x1a\n", "offset": 0, "label": "PNG Image"},
    "jpg":  {"bytes": b"\xff\xd8\xff",  "offset": 0, "label": "JPEG Image"},
    "jpeg": {"bytes": b"\xff\xd8\xff",  "offset": 0, "label": "JPEG Image"},
    "gif":  {"bytes": b"GIF8",          "offset": 0, "label": "GIF Image"},
    "zip":  {"bytes": b"PK\x03\x04",    "offset": 0, "label": "ZIP Archive"},
    "docx": {"bytes": b"PK\x03\x04",    "offset": 0, "label": "Office Open XML Document"},
    "xlsx": {"bytes": b"PK\x03\x04",    "offset": 0, "label": "Office Open XML Spreadsheet"},
    "pptx": {"bytes": b"PK\x03\x04",    "offset": 0, "label": "Office Open XML Presentation"},
    "bz2":  {"bytes": b"BZh",           "offset": 0, "label": "Bzip2 Archive"},
    "gz":   {"bytes": b"\x1f\x8b",      "offset": 0, "label": "Gzip Archive"},
    "7z":   {"bytes": b"7z\xbc\xaf'\x1c", "offset": 0, "label": "7-Zip Archive"},
    "rar":  {"bytes": b"Rar!\x1a\x07",  "offset": 0, "label": "RAR Archive"},
    "mp3":  {"bytes": b"\xff\xfb",      "offset": 0, "label": "MP3 Audio"},
    "mp4":  {"bytes": b"...ftyp",        "offset": 4, "label": "MP4 Video"},
    "ogg":  {"bytes": b"OggS",          "offset": 0, "label": "OGG Media"},
    "wav":  {"bytes": b"RIFF",          "offset": 0, "label": "WAV Audio"},
    "flac": {"bytes": b"fLaC",          "offset": 0, "label": "FLAC Audio"},
    "sqlite": {"bytes": b"SQLite format 3\x00", "offset": 0, "label": "SQLite Database"},
}

# Signatures that indicate an executable binary (high-risk)
EXECUTABLE_SIGNATURES = {
    b"MZ":            "Windows/DOS Executable (PE/COFF)",
    b"\x7fELF":       "Unix/Linux ELF Binary",
    b"\xca\xfe\xba\xbe": "macOS Mach-O Fat Binary",
    b"\xce\xfa\xed\xfe": "macOS Mach-O 32-bit",
    b"\xcf\xfa\xed\xfe": "macOS Mach-O 64-bit",
    b"\xfe\xed\xfa\xce": "macOS Mach-O 32-bit (reverse)",
    b"\xfe\xed\xfa\xcf": "macOS Mach-O 64-bit (reverse)",
}

# Extensions that are explicitly allowed for executable binaries
EXECUTABLE_EXTENSIONS = {"exe", "dll", "sys", "elf", "bin", "so", "o", "a", "dylib", "com", "msi"}

# --- Layer 2: ClamAV ---
# Try clamdscan (daemon) first, fall back to clamscan (standalone)
CLAMAV_COMMANDS = ["clamdscan", "clamscan"]
CLAMAV_TIMEOUT_SECONDS = 30
# Standard EICAR test string for malware testing
EICAR_STRING = (
    r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)

# --- Layer 3: Docker Sandbox ---
SANDBOX_IMAGE_NAME = "sandbox-extractor:latest"
SANDBOX_DOCKERFILE = os.path.join(DOCKER_DIR, "Dockerfile.sandbox")
SANDBOX_TIMEOUT_SECONDS = 8
SANDBOX_MEMORY_LIMIT = "256m"
SANDBOX_CPU_LIMIT = "0.5"
SANDBOX_CONTAINER_MOUNT_POINT = "/sandbox/input_file:ro"

# --- Docker command flags used to build the sandbox invocation ---
SANDBOX_DOCKER_FLAGS = [
    "--rm",                    # Auto-destroy container on exit
    "--network", "none",       # Air-gapped: no network access
    "--read-only",             # Read-only root filesystem
    "--cap-drop=ALL",          # Drop all Linux capabilities
    "--memory={}".format(SANDBOX_MEMORY_LIMIT),
    "--cpus={}".format(SANDBOX_CPU_LIMIT),
]
