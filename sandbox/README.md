# Sandbox File Analysis Engine (C)

Zero-dependency production engine that processes untrusted files through
three air-gapped security layers. Written in **pure C99** — no external
libraries beyond `libc` and the OS system call interface.

Builds to a single static binary ~30KB. Invoked via CLI, communicates
through stdout JSON. No daemons, no sockets, no persistent state.

## Server Deployment (Linux)

### 1. Install prerequisites

```bash
# Compiler
apt-get install -y gcc make           # Debian/Ubuntu
yum install -y gcc make               # RHEL/CentOS

# Docker (Layer 3 — sandbox execution)
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# ClamAV (Layer 2 — optional but recommended)
apt-get install -y clamav clamav-daemon
freshclam                              # update virus definitions
systemctl enable --now clamav-daemon
```

### 2. Build

```bash
git clone https://github.com/Parz1val6g/file-analysis-sandbox.git
cd file-analysis-sandbox/sandbox
make          # release build (-O3 -flto -march=x86-64 -mtune=generic)
```

The binary lands at `./sandbox_engine`. Copy it anywhere:

```bash
cp sandbox_engine /usr/local/bin/
chmod 755 /usr/local/bin/sandbox_engine
```

### 3. Build the Docker sandbox image (first time only)

```bash
docker build -t sandbox-extractor:latest -f docker/Dockerfile.sandbox docker/
```

The engine caches this — it runs `docker image inspect` before every
invocation and skips the build if the image already exists.

### 4. Verify

```bash
sandbox_engine --version                   # sandbox_engine v1.0.0
make test                                  # 21 unit tests
make chaos                                 # 10 stress tests (100 concurrent)
```

### 5. Invoke from your application

```bash
sandbox_engine /path/to/user/upload.pdf
```

Output (stdout — exactly one line):
```json
{"status":"clean","signature":"a1b2c3...","metadata":{"mime_type":"application/pdf","extracted_text":"..."}}
```

Exit code `0` = clean, `1` = infected/error. All diagnostics go to stderr.

## Integration Patterns

### Python (Flask / FastAPI / Django)

```python
import subprocess, json

ENGINE = "/usr/local/bin/sandbox_engine"

def analyze(file_path: str) -> dict:
    proc = subprocess.run([ENGINE, file_path],
        capture_output=True, text=True, timeout=30)
    return json.loads(proc.stdout)

@app.post("/upload")
def upload(file: UploadFile):
    tmp = f"/tmp/upload_{uuid4()}"
    file.save(tmp)
    result = analyze(tmp)
    os.unlink(tmp)
    if result["status"] == "infected":
        raise HTTPException(400, result.get("reason"))
    return result
```

### Node.js (Express)

```javascript
const { spawn } = require("child_process");
const ENGINE = "/usr/local/bin/sandbox_engine";

function analyze(filePath) {
  return new Promise((resolve, reject) => {
    const proc = spawn(ENGINE, [filePath], { timeout: 30000 });
    let stdout = "";
    proc.stdout.on("data", d => stdout += d);
    proc.on("close", code => {
      try { resolve(JSON.parse(stdout.trim())); }
      catch(e) { reject(e); }
    });
  });
}
```

### PHP

```php
function analyze(string $path): array {
    $cmd = sprintf("/usr/local/bin/sandbox_engine %s 2>/dev/null", escapeshellarg($path));
    exec($cmd, $output, $exit);
    return json_decode(implode("", $output), true);
}
```

### Go

```go
func Analyze(path string) (map[string]interface{}, error) {
    cmd := exec.Command("/usr/local/bin/sandbox_engine", path)
    cmd.Stderr = nil
    out, err := cmd.Output()
    if err != nil { return nil, err }
    var result map[string]interface{}
    json.Unmarshal(out, &result)
    return result, nil
}
```

## Systemd Service (optional wrapper)

If you want a simple HTTP wrapper around the engine:

```ini
# /etc/systemd/system/sandbox-api.service
[Unit]
Description=Sandbox File Analysis API
After=docker.service

[Service]
ExecStart=/usr/local/bin/sandbox-api
Restart=always
RestartSec=5
LimitNOFILE=65536
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

## JSON Contract

| Status | Fields | Exit |
|--------|--------|------|
| `clean` | `status`, `signature`, `metadata` | 0 |
| `infected` | `status`, `reason`, `true_type`, `declared_extension` | 1 |
| `error` | `status`, `reason` | 1 |

When ClamAV is unavailable, a `clean` result includes:
```json
{"metadata": {"clamav_skipped": true, "clamav_skip_reason": "..."}}
```

## Three Security Layers

| # | Layer | What it catches |
|---|-------|----------------|
| 1 | Magic Bytes | Extension mismatch (`.pdf` with EXE header), corrupted headers |
| 2 | ClamAV | Known malware signatures, macros, trojans |
| 3 | Docker Sandbox | Extracts text in air-gapped container (`--network none`, `--read-only`, `--cap-drop=ALL`, 256MB/0.5CPU limit, 8s timeout) |

Layer 2 bypasses gracefully if ClamAV is not installed.
Layer 3 fails gracefully if Docker is not running.

## Docker Sandbox Isolation

```bash
docker run \
  --rm \                    # auto-destroy after exit
  --network none \          # completely air-gapped
  --read-only \             # immutable root filesystem
  --cap-drop=ALL \          # zero Linux capabilities
  --memory=256m \           # anti-zip-bomb
  --memory-swap=256m \      # no swap abuse
  --cpus=0.5 \              # half a core max
  -v /host/file:/sandbox/input_file:ro \  # single file, read-only
  sandbox-extractor:latest /sandbox/input_file
```

Container is killed by `TerminateProcess` / `SIGKILL` at exactly 8 seconds
if the extraction hangs.

## Host-Side Validation

Before any layer runs, the engine validates:
- File exists and is a regular file
- Size <= 500 MB (override with `SANDBOX_MAX_FILE_SIZE` env var)
- Read permission check
- Empty file rejection
- Path traversal prevention

## Test Suite

```bash
make test       # 21 unit tests — layers, JSON protocol, isolation, robustness
make chaos      # 10 stress tests — 100 concurrent, fuzzing, signals, integrity
make test-asan  # both suites under AddressSanitizer + UBSan (GCC/Clang only)
```

| Suite | Tests | Coverage |
|-------|-------|----------|
| Unit (`test_runner`) | 21 | Layer 1/2/3, JSON contract, stdout isolation, ClamAV bypass, robustness, signatures |
| Chaos (`chaos_runner`) | 10 | 100 concurrent processes, random binary fuzzing, null-poisoned headers, PATH_MAX paths, zero-byte files, signal interruption, timeout enforcement, JSON integrity under load |

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Binary size | ~30 KB (static) |
| Startup time | < 1 ms |
| Memory baseline | < 2 MB |
| Layer 1 (magic bytes) | < 1 ms |
| Layer 2 (ClamAV) | 1-30s (depends on file size + daemon) |
| Layer 3 (Docker) | 2-8s (container spin-up + extraction) |
| Concurrent throughput | 100 parallel invocations in < 5s |

## Supported File Types (Layer 1)

PDF, PNG, JPEG, GIF, ZIP, DOCX, XLSX, PPTX, BZ2, GZ, 7Z, RAR, MP3,
MP4, OGG, WAV, FLAC, SQLite. Executables (EXE/DLL, ELF, Mach-O) with
non-executable extensions are flagged as infected.

## Production Hardening Notes

- **Binary deployment:** Copy the single `sandbox_engine` binary — no shared libraries needed.
- **User context:** Run as a dedicated unprivileged user (`sandbox`). Grant Docker socket access via group membership.
- **Rate limiting:** Wrap invocations in your application layer. The engine itself is stateless.
- **Logging:** stderr output can be piped to `logger` or journald. Add `2>&1 | logger -t sandbox` to your invocation.
- **File cleanup:** The engine does not delete the input file. Your application must clean up uploads.
- **SELinux/AppArmor:** No special profiles needed — the dangerous work happens inside the Docker container.
- **Signal handling:** Ctrl+C / SIGTERM / SIGINT produce valid JSON `{"status":"error","reason":"Interrupted"}` before exit.

## Zero-Dependency Guarantee

| Component | Implementation |
|-----------|---------------|
| SHA-256 | FIPS 180-4 — 64-round fully unrolled, pure C bitwise ops |
| JSON Builder | Self-growing buffer, `\uXXXX` escaping |
| Subprocess | `fork+execve` (Unix) / `CreateProcessW` (Windows) — never `system()` |
| Bounded functions | `snprintf`, `strncmp`, `memmove` exclusively |
| Memory | Every `malloc` paired with `free`; ASAN-clean at 100 concurrent load |

## Build Requirements

| Platform | Compiler | Flags |
|----------|----------|-------|
| Linux | GCC 9+ or Clang 12+ | `-O3 -flto -march=x86-64 -mtune=generic` |
| macOS | GCC or Clang | `make CC=clang` |
| Windows | TCC 0.9.27+ | Auto-downloaded by `build.bat` |
