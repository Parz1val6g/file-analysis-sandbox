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

## Testing the System

### Prerequisites

```bash
pip install pytest
```

The engine itself has **zero runtime dependencies** (stdlib-only). `pytest` is
only needed to run the test suite.

---

### Run All Tests

```bash
cd file-analysis-sandbox
python -m pytest sandbox/tests/ -v
```

Expected: **87 passed, 1 skipped** (the skipped test is an optional `pytest-mock` check).

---

### Test by Module

Each test file targets a specific subsystem so you can isolate failures quickly:

```bash
# Layer 1: Magic byte validation — 11 tests
python -m pytest sandbox/tests/test_layer1.py -v

# Layer 2: ClamAV integration — 9 tests (1 skipped)
python -m pytest sandbox/tests/test_layer2.py -v

# Layer 3: Docker sandbox engine — 17 tests
python -m pytest sandbox/tests/test_layer3.py -v

# Full pipeline integration — 21 tests
python -m pytest sandbox/tests/test_integration.py -v

# Stdout isolation & ClamAV bypass — 12 tests
python -m pytest sandbox/tests/test_isolation.py -v

# Host-side input validation — 8 tests
python -m pytest sandbox/tests/test_validation.py -v

# Cleanup & signal handling — 8 tests
python -m pytest sandbox/tests/test_cleanup.py -v
```

---

### Manual Smoke Tests

Verify the engine works from the command line. The first line printed is **stdout**
(the JSON contract). Everything after `[engine]` is **stderr** (diagnostics).

#### 1. Clean file passes all layers

```bash
python sandbox/engine.py sandbox/fixtures/clean.txt
```

Pulls clean.txt through magic bytes, ClamAV, and Docker. If ClamAV or Docker are
missing, the engine gracefully degrades (Layer 2 bypassed, Layer 3 reports error).

#### 2. Malformed PDF is detected (extension-mismatch attack)

```bash
python sandbox/engine.py sandbox/fixtures/malformed_header.pdf
```

A `.pdf` file with an `MZ` (Windows EXE) header. Layer 1 immediately flags it:

```json
{"status":"infected","reason":"Layer 1: Extension mismatch attack detected...","true_type":"Windows/DOS Executable (PE/COFF)","declared_extension":"pdf"}
```

#### 3. Valid file types pass Layer 1

```bash
python sandbox/engine.py sandbox/fixtures/valid.pdf
python sandbox/engine.py sandbox/fixtures/valid.png
python sandbox/engine.py sandbox/fixtures/valid.gif
```

All pass Layer 1 with status `clean` (or `error` if Docker is unavailable).

#### 4. Verify stdout is pure JSON (no debug pollution)

```bash
python sandbox/engine.py sandbox/fixtures/clean.txt > stdout.txt 2> stderr.txt
cat stdout.txt          # Exactly one JSON line — nothing else
cat stderr.txt          # All [engine] Layer N: ... diagnostics live here
```

#### 5. Verify ClamAV bypass (graceful degradation)

When ClamAV is not installed, Layer 2 is bypassed and the engine continues to
Layer 3. The bypass is logged to stderr and annotated in the output metadata:

```bash
python sandbox/engine.py sandbox/fixtures/valid.pdf 2>stderr.txt
```

In stderr you will see: `[engine] Layer 2 BYPASSED: ...`

If Layer 3 succeeds, stdout includes:
```json
{"status":"clean","signature":"...","metadata":{"clamav_skipped":true,"clamav_skip_reason":"...",...}}
```

#### 6. Empty file rejected

```bash
touch /tmp/empty.txt
python sandbox/engine.py /tmp/empty.txt
```

```json
{"status":"error","reason":"File is empty (0 bytes) — nothing to analyze"}
```

#### 7. Size cap enforced

```bash
# Create a 600 MB dummy file (adjust MAX_FILE_SIZE via env var to test smaller caps)
python sandbox/engine.py /path/to/oversized.bin
```

```json
{"status":"error","reason":"File too large: ... MB exceeds maximum allowed size of 500 MB"}
```

---

### Test Fixtures

The `sandbox/fixtures/` directory contains pre-built test files for each attack
vector:

| Fixture | Purpose | Layer |
|---------|---------|-------|
| `clean.txt` | Harmless text content | Passes all layers |
| `valid.pdf` | Minimal valid PDF with `%PDF` header | Passes Layer 1 |
| `valid.png` | Minimal valid PNG with `\x89PNG` header | Passes Layer 1 |
| `valid.gif` | Minimal valid GIF with `GIF89a` header | Passes Layer 1 |
| `malformed_header.pdf` | `.pdf` extension with `MZ` (EXE) header | **Caught by Layer 1** |
| `slow.py` | Python script that sleeps 30 seconds | **Caught by Layer 3 timeout** |

---

### What Each Test Module Covers

| Test File | Tests | Validates |
|-----------|-------|-----------|
| `test_layer1.py` | 11 | Magic byte dictionaries, executable signature detection, extension-mismatch attack, empty/small files, missing files |
| `test_layer2.py` | 9 | ClamAV binary discovery, virus name parsing, unavailable ClamAV returns error, infected result structure, graceful degradation |
| `test_layer3.py` | 17 | Docker availability detection, SHA-256 consistency, Windows-to-Docker path conversion, Docker flag enforcement (`--rm`, `--network none`, `--read-only`, `--cap-drop=ALL`, memory/CPU limits, timeout) |
| `test_integration.py` | 21 | End-to-end three-layer pipeline, JSON protocol schema, exit codes (0=clean, 1=infected/error), robustness (directory input, spaces in path, empty/binary files), ClamAV bypass integration |
| `test_isolation.py` | 12 | Stdout contains only JSON, no `[engine]` debug prefix, debug goes to stderr, single-line stdout, ClamAV bypass metadata structure |
| `test_validation.py` | 8 | File existence, size caps, empty rejection, directory rejection, read permissions, path traversal detection, symlink handling, unicode paths |
| `test_cleanup.py` | 8 | Temp directory/file auto-cleanup, register/unregister paths, signal handler installation, idempotent cleanup hooks |

## Supported File Type Detection (Layer 1)

PDF, PNG, JPEG, GIF, ZIP, DOCX, XLSX, PPTX, BZ2, GZ, 7Z, RAR, MP3, MP4, OGG,
WAV, FLAC, SQLite. Executable binaries (EXE/DLL, ELF, Mach-O) masquerading under
non-executable extensions are flagged as infected.

## License

Internal tool — no license.
