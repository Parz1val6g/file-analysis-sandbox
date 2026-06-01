# Sandbox File Analysis & Ephemeral Execution Engine

A production-ready, zero-dependency, standalone engine that processes untrusted
files through three air-gapped security layers. Operates purely via CLI invocation
— no persistent background services required.

## Quick Start

```bash
# Install test dependencies (engine itself has zero runtime deps)
pip install pytest

# Run the engine against a file
python sandbox/engine.py /path/to/suspicious/file.pdf

# Run the test suite
python -m pytest sandbox/tests/ -v
```

## CLI Signature

```
python sandbox/engine.py <file_path>
```

| Exit Code | Meaning |
|-----------|---------|
| `0` | File is clean (all layers passed) |
| `1` | Infected/error detected, or usage error |

## JSON Contract Schema

The engine writes **exactly one JSON object** to stdout. Nothing else.

### Clean Result
```json
{"status":"clean","signature":"<sha256_hex>","metadata":{...}}
```

### Infected Result
```json
{"status":"infected","reason":"<detection details>","true_type":"<actual type>","declared_extension":"<ext>"}
```

### Error Result
```json
{"status":"error","reason":"<human-readable error description>"}
```

## Architecture

### Three Security Layers (air-gapped pipeline)

| Layer | Name | Protection |
|-------|------|------------|
| 1 | Static Magic Bytes | Validates hex signature against declared extension. Blocks `.pdf` files with `.exe` (MZ) headers. |
| 2 | ClamAV Scan | Interfaces with `clamdscan`/`clamscan` for known malware signatures. Gracefully degrades if ClamAV is unavailable. |
| 3 | Ephemeral Docker Sandbox | Runs file extraction inside an air-gapped, capability-dropped, read-only container with CPU/memory limits and an 8-second timeout. |

### Layer 3 Docker Isolation Rules

- `--rm` — Container auto-destroys on termination
- `--network none` — Completely air-gapped (no internet, no LAN)
- `--read-only` — Read-only root filesystem
- `--cap-drop=ALL` — All Linux capabilities dropped
- `--memory=256m` — Hard 256 MB memory limit (anti-Zip-Bomb)
- `--cpus=0.5` — Half a CPU core max
- **8-second timeout** — Container is killed if extraction hangs
- **Single file mount** — Only the target file is mounted (read-only); zero host visibility

### Host-Side Input Validation

Before any security layer runs:
- **Size cap**: 500 MB default (override via `SANDBOX_MAX_FILE_SIZE` env var)
- **Read permission** check
- **Empty file** rejection
- **Path traversal** detection (`../` escapes)
- **Symlink resolution** via `os.path.realpath`

### Stdout Isolation

All diagnostic output, container logs, and debug messages are **forcibly redirected**
to stderr or isolated log files. Only the final JSON contract reaches stdout.

### Cleanup & Signal Handling

- `atexit` handlers auto-wipe all temporary assets
- `SIGINT` (Ctrl+C) and `SIGTERM` (kill) are caught — a valid error JSON is emitted
  before exit
- Cleanup registry allows modules to register files/dirs for automatic cleanup

## Directory Structure

```
sandbox/
├── engine.py              # CLI entry point (orchestrates pipeline)
├── config.py              # Magic byte dicts, security constants
├── validation.py          # Host-side input validation
├── cleanup.py             # Temp asset cleanup + signal handlers
├── layers/
│   ├── layer1_magic.py    # Static hex/magic byte validation
│   ├── layer2_clamav.py   # ClamAV integration
│   └── layer3_sandbox.py  # Docker sandbox execution
├── docker/
│   ├── Dockerfile.sandbox # Minimal Alpine extractor image
│   └── extractor.py       # Internal extractor (runs inside container)
├── fixtures/
│   ├── clean.txt          # Clean text file
│   ├── valid.pdf/png/gif  # Valid file fixtures
│   ├── malformed_header.pdf  # .pdf with MZ header (Layer 1 test)
│   └── slow.py            # 30s sleep script (Layer 3 timeout test)
└── tests/
    ├── test_layer1.py     # 11 tests — magic bytes, executable detection
    ├── test_layer2.py     # 9 tests — ClamAV, virus parsing, graceful failure
    ├── test_layer3.py     # 17 tests — Docker isolation, SHA-256, security flags
    ├── test_integration.py # 18 tests — full pipeline, JSON protocol, robustness
    ├── test_validation.py # Host-side input validation tests
    ├── test_cleanup.py    # Cleanup & signal handler tests
    └── test_isolation.py  # Stdout isolation verification
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SANDBOX_MAX_FILE_SIZE` | `524288000` (500 MB) | Maximum input file size in bytes |
| `SANDBOX_DEBUG` | unset | Set to any value to enable traceback output on errors |

## Host Permission Notes

| Requirement | Reason |
|-------------|--------|
| Docker daemon access | Layer 3 sandbox execution (must be running) |
| ClamAV (optional) | Layer 2 virus scanning (engine works without it) |
| Read access to target file | Self-explanatory |
| No network required | Layer 3 is air-gapped; ClamAV is local |

## Embedding in a Monolithic App

The engine is designed to be invoked as a subprocess from any web framework:

```python
# Example: embedding in Flask/FastAPI/Django
import subprocess
import json

def analyze_upload(file_path: str) -> dict:
    proc = subprocess.run(
        ["python", "sandbox/engine.py", file_path],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return json.loads(proc.stdout)
```

The calling application only needs to parse the single-line JSON from stdout.

## Test Suite

```bash
python -m pytest sandbox/tests/ -v
```

Tests cover: Layer 1 (magic bytes, executable detection, edge cases), Layer 2
(virus name parsing, ClamAV unavailable, graceful degradation), Layer 3
(Docker isolation flags, SHA-256 hashing, path conversion, security constraints),
full integration pipeline, JSON protocol compliance, exit codes, input validation,
cleanup lifecycle, and stdout isolation.

## Supported File Type Detection (Layer 1)

PDF, PNG, JPEG, GIF, ZIP, DOCX, XLSX, PPTX, BZ2, GZ, 7Z, RAR, MP3, MP4, OGG,
WAV, FLAC, SQLite. Executable binaries (EXE/DLL, ELF, Mach-O) masquerading under
non-executable extensions are flagged as infected.

## License

Internal tool — no license.
