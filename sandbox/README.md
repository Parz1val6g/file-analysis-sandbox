# Sandbox File Analysis Engine (C)

Zero-dependency production engine that processes untrusted files through
three air-gapped security layers. Written in **pure C99** — no external
libraries beyond `libc` and the OS system call interface.

## Quick Start

```bash
# Windows (one-click)
.\build.bat

# Unix
cd sandbox && make

# Run
sandbox\sandbox_engine.exe path\to\file.pdf        # Windows
./sandbox/sandbox_engine path/to/file.pdf           # Unix

# Test
sandbox\test_runner.exe                             # Windows
cd sandbox && ./test_runner                         # Unix
```

## Build Requirements

| Platform | Compiler | Notes |
|----------|----------|-------|
| Windows | TCC 0.9.27+ | Auto-downloaded by `build.bat` |
| Linux | GCC or Clang | `make` uses `cc` by default |
| macOS | GCC or Clang | `make CC=clang` |

## CLI Contract

```
sandbox_engine <file_path>
```

| Exit | Meaning |
|------|---------|
| 0 | File clean (all layers passed) |
| 1 | Infected or error |

### JSON Output (stdout — exactly one line)

**Clean:**
```json
{"status":"clean","signature":"<sha256_hex>","metadata":{...}}
```

**Infected:**
```json
{"status":"infected","reason":"<details>","true_type":"<type>","declared_extension":"<ext>"}
```

**Error:**
```json
{"status":"error","reason":"<message>"}
```

All diagnostics go to **stderr** — never stdout.

## Architecture

```
sandbox/
├── src/
│   ├── engine.c           # CLI entry + 3-layer pipeline
│   ├── sha256.c/h         # FIPS 180-4 SHA-256 (pure C, zero-deps)
│   ├── json_builder.c/h   # Safe JSON builder with escaping
│   ├── subprocess.c/h     # CreateProcess + pipes (no shell, no system())
│   ├── validation.c/h     # Input validation (size 500MB, perms, traversal)
│   ├── layer1_magic.c/h   # Magic byte detection (17 formats)
│   ├── layer2_clamav.c/h  # ClamAV subprocess scanner
│   └── layer3_sandbox.c/h # Docker sandbox (all isolation flags)
├── docker/
│   ├── Dockerfile.sandbox # Multi-stage C extractor image
│   └── extractor.c        # Internal extractor (compiled in-container)
├── tests/
│   └── test_runner.c      # Comprehensive C test suite
├── fixtures/              # Test vectors
├── Makefile
└── README.md
```

## Three Security Layers

| Layer | Protection |
|-------|-----------|
| 1 — Magic Bytes | Validates hex signature. Blocks `.pdf` with `.exe` headers. |
| 2 — ClamAV | Spawns `clamscan` via `CreateProcess`. Bypasses gracefully if unavailable. |
| 3 — Docker Sandbox | Air-gapped `--network none`, `--read-only`, `--cap-drop=ALL`, 256MB/0.5CPU limit, 8s timeout. |

## Zero-Dependency Guarantee

| Component | Implementation |
|-----------|---------------|
| SHA-256 | 120 lines of pure C bitwise ops (FIPS 180-4) |
| JSON Builder | Self-growing buffer, `\uXXXX` escaping |
| Subprocess | `CreateProcessW` (Windows) / `fork+exec` (Unix) — never `system()` |
| Bounded functions | `snprintf`, `strncmp`, `memmove` exclusively |
| Memory | Every `malloc` paired with `free` |

## Docker Sandbox (Layer 3)

The Docker image is built via multi-stage `Dockerfile.sandbox`:
- **Stage 1:** Alpine + `build-base` compiles `extractor.c` into a static binary
- **Stage 2:** Minimal Alpine with `file`, `pdftotext`, `tesseract` + the compiled binary

Container isolation:
- `--rm` — auto-destroy on exit
- `--network none` — air-gapped
- `--read-only` — read-only rootfs
- `--cap-drop=ALL` — no capabilities
- `--memory=256m` — anti-zip-bomb
- `--cpus=0.5` — CPU cap
- 8-second `WaitForSingleObject` timeout

## Test Suite

The C test runner covers all three layers plus edge cases:

```bash
sandbox\test_runner.exe
```

| Area | Tests |
|------|-------|
| Layer 1 — Magic bytes | 7 (malformed PDF, valid formats, no extension, empty) |
| JSON Protocol | 4 (missing arg, nonexistent, reason key, status key) |
| Stdout Isolation | 2 (single line, no debug prefix) |
| ClamAV Bypass | 2 (not infected, metadata flag) |
| Robustness | 3 (directory input, binary file, empty file) |
| Contract | 3 (signature, hex format, infected keys) |

## Supported File Types (Layer 1)

PDF, PNG, JPEG, GIF, ZIP, DOCX, BZ2, GZ, 7Z, RAR, MP3, MP4, OGG,
WAV, FLAC, SQLite. Executables (EXE/DLL, ELF, Mach-O) with non-executable
extensions are flagged as infected.
